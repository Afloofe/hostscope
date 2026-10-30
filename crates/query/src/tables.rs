use std::collections::BTreeMap;
use std::fs;

use crate::{Cell, Row, Table, TableRows};

fn row(pairs: Vec<(&str, Cell)>) -> Row {
    pairs.into_iter().map(|(k, v)| (k.to_string(), v)).collect::<BTreeMap<_, _>>()
}

fn text(v: Option<String>) -> Cell {
    v.map_or(Cell::Null, Cell::Text)
}

pub struct Processes;

impl Table for Processes {
    fn name(&self) -> &'static str {
        "processes"
    }
    fn columns(&self) -> &'static [&'static str] {
        &["pid", "ppid", "uid", "exe", "cmdline", "comm", "state", "deleted"]
    }
    fn describe(&self) -> &'static str {
        "every process in /proc, with the path of its image and whether that image has been \
         unlinked"
    }
    fn rows(&self) -> TableRows {
        let mut out = TableRows::default();
        let (Ok(dir), Some(proc_dev)) = (fs::read_dir("/proc"), proc_dev()) else {
            out.gaps.push("/proc could not be read at all".into());
            return out;
        };
        let mut unreadable_exe = 0_usize;
        let mut seen = 0_usize;

        let mut cut_cmdline: Vec<i64> = Vec::new();
        let mut foreign: Vec<i64> = Vec::new();
        let mut over_budget: Vec<i64> = Vec::new();
        let mut budget = MAX_PROCESS_TEXT_BYTES;
        for e in dir.flatten() {
            let Some(pid) = e.file_name().to_str().and_then(|n| n.parse::<i64>().ok()) else {
                continue;
            };
            seen += 1;
            let base = e.path();
            let mut refused = false;
            let mut read = |name: &str, cap: u64| match read_pid_file(&base.join(name), proc_dev, cap) {
                Ok(got) => Some(got),
                Err(e) => {
                    refused |= e.kind() == std::io::ErrorKind::InvalidInput;
                    None
                }
            };

            let mut oversized = false;
            let stat = match read("stat", MAX_STAT_BYTES) {
                Some((b, false)) => Some(String::from_utf8_lossy(&b).into_owned()),
                Some((_, true)) => {
                    oversized = true;
                    None
                }
                None => None,
            };
            let (ppid, state, comm) = stat.as_deref().map_or((None, None, None), stat_fields);

            let uid = read("status", MAX_STAT_BYTES).and_then(|(b, _)| {
                let s = String::from_utf8_lossy(&b);
                s.lines()
                    .find_map(|l| l.strip_prefix("Uid:"))
                    .and_then(|v| v.split_whitespace().next()?.parse::<i64>().ok())
            });
            let link = fs::read_link(base.join("exe")).ok();
            let had_link = link.is_some();
            let raw = link.map(|p| p.to_string_lossy().into_owned());

            let deleted = i64::from(raw.as_deref().is_some_and(|p| p.ends_with(" (deleted)")));
            let exe = raw.map(|p| p.trim_end_matches(" (deleted)").to_string());

            let cmdline = read("cmdline", MAX_CMDLINE_BYTES).map(|(b, cut)| {
                if cut {
                    cut_cmdline.push(pid);
                }
                argv_text(&b)
            });
            if refused || oversized {
                foreign.push(pid);
            }

            let kernel_thread = !had_link && cmdline.as_deref().is_none_or(str::is_empty);
            if !had_link && !kernel_thread {
                unreadable_exe += 1;
            }
            let ([exe, cmdline], over) = within_budget(&mut budget, [exe, cmdline]);
            if over {
                over_budget.push(pid);
            }

            out.rows.push(row(vec![
                ("pid", Cell::Int(pid)),
                ("ppid", ppid.map_or(Cell::Null, Cell::Int)),
                ("uid", uid.map_or(Cell::Null, Cell::Int)),
                ("exe", text(exe)),
                ("cmdline", text(cmdline)),
                ("comm", text(comm)),
                ("state", text(state)),
                ("deleted", Cell::Int(deleted)),
            ]));
        }
        if unreadable_exe > 0 {
            out.gaps.push(format!(
                "{unreadable_exe} userland process(es) would not show their image path — an \
                 unprivileged run cannot read another user's /proc/<pid>/exe. A query on `exe` \
                 has not been answered for those rows. Kernel threads are NOT counted here: \
                 they have no image by design, and reporting them as a gap would make every \
                 complete sweep on every host look partial"
            ));
        }
        out.gaps.extend(process_gaps(&cut_cmdline, &foreign, &over_budget, seen));
        out
    }
}

const MAX_CMDLINE_BYTES: u64 = 8 * 1024;

const MAX_STAT_BYTES: u64 = 64 * 1024;

const MAX_PROCESS_TEXT_BYTES: u64 = 32 * 1024 * 1024;

#[cfg(unix)]
const NOT_PROCFS: &str = "not a regular file on the /proc mount — something is mounted over this \
     process's entry, and it is not read";

#[cfg(unix)]
fn proc_dev() -> Option<u64> {
    use std::os::unix::fs::MetadataExt as _;
    fs::metadata("/proc").ok().map(|m| m.dev())
}

#[cfg(not(unix))]
fn proc_dev() -> Option<u64> {
    Some(0)
}

fn read_pid_file(path: &std::path::Path, proc_dev: u64, cap: u64) -> std::io::Result<(Vec<u8>, bool)> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
        let before = procs_own(path, proc_dev)?;
        let f = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK | libc::O_NOCTTY)
            .open(path)?;
        let after = f.metadata()?;
        if !after.is_file() || (after.dev(), after.ino()) != (before.dev(), before.ino()) {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, NOT_PROCFS));
        }
        read_bounded(f, cap)
    }
    #[cfg(not(unix))]
    {
        let _ = proc_dev;
        read_bounded(fs::File::open(path)?, cap)
    }
}

#[cfg(unix)]
fn procs_own(path: &std::path::Path, proc_dev: u64) -> std::io::Result<fs::Metadata> {
    use std::os::unix::fs::MetadataExt as _;
    let md = fs::metadata(path)?;
    if md.is_file() && md.dev() == proc_dev {
        Ok(md)
    } else {
        Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, NOT_PROCFS))
    }
}

fn is_procs_own(path: &std::path::Path, proc_dev: u64) -> bool {
    #[cfg(unix)]
    {
        procs_own(path, proc_dev).is_ok()
    }
    #[cfg(not(unix))]
    {
        let _ = (path, proc_dev);
        true
    }
}

fn stat_fields(s: &str) -> (Option<i64>, Option<String>, Option<String>) {
    let close = s.rfind(')');
    let comm = close
        .and_then(|c| s.find('(').and_then(|o| s.get(o + 1..c)))
        .map(str::to_string);
    let rest: Vec<&str> = close
        .and_then(|c| s.get(c + 1..))
        .map(|r| r.split_whitespace().collect())
        .unwrap_or_default();
    (
        rest.get(1).and_then(|v| v.parse::<i64>().ok()),
        rest.first().map(|v| (*v).to_string()),
        comm,
    )
}

fn argv_text(raw: &[u8]) -> String {
    raw.split(|c| *c == 0)
        .filter(|s| !s.is_empty())
        .map(String::from_utf8_lossy)
        .collect::<Vec<_>>()
        .join(" ")
}

fn within_budget<const N: usize>(budget: &mut u64, cells: [Option<String>; N]) -> ([Option<String>; N], bool) {
    let mut over = false;
    let kept = cells.map(|cell| {
        let text = cell?;
        let cost = text.len() as u64;
        if cost <= *budget {
            *budget -= cost;
            Some(text)
        } else {
            *budget = 0;
            over = true;
            None
        }
    });
    (kept, over)
}

fn process_gaps(cut_cmdline: &[i64], foreign: &[i64], over_budget: &[i64], seen: usize) -> Vec<String> {
    let pids = |list: &[i64]| {
        let shown: Vec<String> = list.iter().take(10).map(i64::to_string).collect();
        let more = list.len() - shown.len();
        format!("pid {}{}", shown.join(", "), if more > 0 { format!(" and {more} more") } else { String::new() })
    };
    let mut gaps = Vec::new();
    if !cut_cmdline.is_empty() {
        gaps.push(format!(
            "{} of {seen} process(es) have a command line longer than the {} KiB a row keeps, and \
             `cmdline` holds only its start — {}. A query on what follows has not been answered \
             for those rows",
            cut_cmdline.len(),
            MAX_CMDLINE_BYTES / 1024,
            pids(cut_cmdline)
        ));
    }
    if !foreign.is_empty() {
        gaps.push(format!(
            "{} of {seen} process(es) have a /proc file that is not what the kernel prints there \
             — something is mounted over it — and it was not read, so their rows are missing what \
             it holds — {}. A query on those columns has not been answered for those rows, and \
             a mount over a process's entry is itself worth a look",
            foreign.len(),
            pids(foreign)
        ));
    }
    if let Some(first) = over_budget.first() {
        gaps.push(format!(
            "the table holds at most {} MiB of `exe` and `cmdline` text and reached it at pid \
             {first}: from there on {} of {seen} process(es) have them NULL — not read into the \
             table, not empty. A query on either has not been answered for those rows",
            MAX_PROCESS_TEXT_BYTES / (1024 * 1024),
            over_budget.len()
        ));
    }
    gaps
}

pub struct Users;

impl Table for Users {
    fn name(&self) -> &'static str {
        "users"
    }
    fn columns(&self) -> &'static [&'static str] {
        &["name", "uid", "gid", "home", "shell"]
    }
    fn describe(&self) -> &'static str {
        "local accounts as /etc/passwd lists them"
    }
    fn rows(&self) -> TableRows {
        let mut out = TableRows::default();
        let Ok(text_) = fs::read_to_string("/etc/passwd") else {
            out.gaps.push("/etc/passwd could not be read".into());
            return out;
        };
        for line in text_.lines() {
            let f: Vec<&str> = line.split(':').collect();
            if f.len() < 7 {
                continue;
            }
            out.rows.push(row(vec![
                ("name", Cell::Text(f[0].to_string())),
                ("uid", f[2].parse().map_or(Cell::Null, Cell::Int)),
                ("gid", f[3].parse().map_or(Cell::Null, Cell::Int)),
                ("home", Cell::Text(f[5].to_string())),
                ("shell", Cell::Text(f[6].to_string())),
            ]));
        }
        out
    }
}

pub struct KernelModules;

impl Table for KernelModules {
    fn name(&self) -> &'static str {
        "kernel_modules"
    }
    fn columns(&self) -> &'static [&'static str] {
        &["name", "size", "used_by_count", "state", "unsigned"]
    }
    fn describe(&self) -> &'static str {
        "loaded kernel modules, and which of them the kernel recorded as unsigned"
    }
    fn rows(&self) -> TableRows {
        let mut out = TableRows::default();

        let Ok(text_) = read_kernel_text("/proc/modules") else {
            out.gaps.push("/proc/modules could not be read".into());
            return out;
        };
        module_rows(&text_, &mut out);
        out
    }
}

fn module_rows(text_: &str, out: &mut TableRows) {
    let mut untainted_unknown: Vec<String> = Vec::new();
    for line in text_.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        let [name, size, used_by, _, state, ..] = f.as_slice() else {
            continue;
        };

        let unsigned = unsigned_cell(fs::read_to_string(format!("/sys/module/{name}/taint")));
        if unsigned == Cell::Null {
            untainted_unknown.push((*name).to_string());
        }
        out.rows.push(row(vec![
            ("name", Cell::Text((*name).to_string())),
            ("size", size.parse().map_or(Cell::Null, Cell::Int)),
            ("used_by_count", used_by.parse().map_or(Cell::Null, Cell::Int)),
            ("state", Cell::Text((*state).to_string())),
            ("unsigned", unsigned),
        ]));
    }
    if !untainted_unknown.is_empty() {
        out.gaps.push(format!(
            "the taint of {} module(s) could not be read, so whether they are signed is \
             unknown (unsigned is NULL, not 0): {}",
            untainted_unknown.len(),
            untainted_unknown.join(", ")
        ));
    }
}

fn unsigned_cell(taint: std::io::Result<String>) -> Cell {
    match taint {
        Ok(t) => Cell::Int(i64::from(t.contains('E'))),
        Err(_) => Cell::Null,
    }
}

pub struct ListeningPorts;

impl Table for ListeningPorts {
    fn name(&self) -> &'static str {
        "listening_ports"
    }
    fn columns(&self) -> &'static [&'static str] {
        &["protocol", "port", "address", "inode"]
    }
    fn describe(&self) -> &'static str {
        "sockets in LISTEN, and bound UDP, from /proc/net. `address` is dotted IPv4 or RFC 5952 \
         IPv6, and a dual-stack listener on every interface is `::`, not `0.0.0.0`"
    }
    fn rows(&self) -> TableRows {
        let mut out = TableRows::default();
        for (proto, path, listen_only) in [
            ("tcp", "/proc/net/tcp", true),
            ("tcp6", "/proc/net/tcp6", true),
            ("udp", "/proc/net/udp", false),
            ("udp6", "/proc/net/udp6", false),
        ] {
            let text_ = match fs::read_to_string(path) {
                Ok(t) => t,
                Err(e) => {
                    out.gaps.extend(unread_gap(path, &e));
                    continue;
                }
            };
            socket_rows(proto, &text_, listen_only, &mut out.rows);
        }
        out
    }
}

fn unread_gap(path: &str, e: &std::io::Error) -> Option<String> {
    if path.ends_with('6') && e.kind() == std::io::ErrorKind::NotFound {
        return None;
    }
    Some(format!("{path} could not be read"))
}

fn decode_address(hex: &str) -> Option<String> {
    let word = |i: usize| -> Option<[u8; 4]> {
        let w = hex.get(i * 8..i * 8 + 8)?;
        Some(u32::from_str_radix(w, 16).ok()?.to_le_bytes())
    };
    match hex.len() {
        8 => Some(std::net::Ipv4Addr::from(word(0)?).to_string()),
        32 => {
            let mut octets = [0_u8; 16];
            for (i, chunk) in octets.as_chunks_mut::<4>().0.iter_mut().enumerate() {
                *chunk = word(i)?;
            }
            let v6 = std::net::Ipv6Addr::from(octets);
            Some(v6.to_ipv4_mapped().map_or_else(|| v6.to_string(), |v4| v4.to_string()))
        }
        _ => None,
    }
}

fn socket_rows(proto: &str, text_: &str, listen_only: bool, rows: &mut Vec<Row>) {
    for line in text_.lines().skip(1) {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 10 {
            continue;
        }

        let Some((addr, port_hex)) = f[1].rsplit_once(':') else { continue };
        if listen_only && f[3] != "0A" {
            continue;
        }
        let Ok(port) = i64::from_str_radix(port_hex, 16) else { continue };
        rows.push(row(vec![
            ("protocol", Cell::Text(proto.to_string())),
            ("port", Cell::Int(port)),
            ("address", text(decode_address(addr))),
            ("inode", f[9].parse().map_or(Cell::Null, Cell::Int)),
        ]));
    }
}

pub struct MemoryRegions;

impl Table for MemoryRegions {
    fn name(&self) -> &'static str {
        "memory_regions"
    }
    fn columns(&self) -> &'static [&'static str] {
        &[
            "pid", "comm", "start", "end", "perms", "path", "executable", "writable",
            "anonymous", "pseudo",
        ]
    }
    fn describe(&self) -> &'static str {
        "every mapping in every readable process, with executable-and-anonymous broken out — \
         the shape of code that was never loaded from a file"
    }
    fn rows(&self) -> TableRows {
        let mut out = TableRows::default();
        let (Ok(dir), Some(proc_dev)) = (fs::read_dir("/proc"), proc_dev()) else {
            out.gaps.push("/proc could not be read at all".into());
            return out;
        };
        let mut refused = 0_usize;
        let mut cut = Vec::new();
        let mut seen = 0_usize;
        let mut filled_in: Option<i64> = None;
        let mut left_out = 0_usize;
        for e in dir.flatten() {
            let Some(pid) = e.file_name().to_str().and_then(|n| n.parse::<i64>().ok()) else {
                continue;
            };
            seen += 1;

            if out.rows.len() >= MAX_REGION_ROWS {
                left_out += 1;
                continue;
            }
            let base = e.path();

            let comm = || {
                read_pid_file(&base.join("comm"), proc_dev, MAX_STAT_BYTES)
                    .ok()
                    .map(|(c, _)| String::from_utf8_lossy(&c).trim().to_string())
            };

            if !is_procs_own(&base.join("maps"), proc_dev) {
                refused += 1;
                continue;
            }
            match process_regions(pid, comm, &base.join("maps"), MAX_MAPS_BYTES, MAX_REGION_ROWS, &mut out.rows) {
                MapRead::Whole => {}
                MapRead::Cut => cut.push(pid),
                MapRead::Full => filled_in = Some(pid),
                MapRead::Refused => refused += 1,
            }
        }
        out.gaps.extend(cut_maps_gap(&cut, seen, MAX_MAPS_BYTES));
        out.gaps.extend(full_table_gap(filled_in, left_out, seen, MAX_REGION_ROWS));
        if refused > 0 {
            out.gaps.push(format!(
                "{refused} of {seen} process(es) would not show their maps — an unprivileged \
                 run cannot read another user's, and one that exits mid-walk has none to show. \
                 Anything mapped in those processes is outside this result, including anything \
                 injected into them"
            ));
        }
        out
    }
}

pub const MAX_MAPS_BYTES: u64 = 64 * 1024 * 1024;

const MAX_REGION_ROWS: usize = 262_144;

#[derive(Debug, PartialEq, Eq)]
enum MapRead {
    Whole,

    Cut,

    Full,
    Refused,
}

fn process_regions(
    pid: i64,
    comm: impl FnOnce() -> Option<String>,
    maps: &std::path::Path,
    cap: u64,
    max_rows: usize,
    rows: &mut Vec<Row>,
) -> MapRead {
    let Ok((text, truncated)) = read_kernel_text_capped(maps, cap) else {
        return MapRead::Refused;
    };
    if !region_rows(pid, comm().as_deref(), &text, max_rows, rows) {
        return MapRead::Full;
    }
    if truncated {
        MapRead::Cut
    } else {
        MapRead::Whole
    }
}

fn cut_maps_gap(cut: &[i64], seen: usize, cap: u64) -> Option<String> {
    if cut.is_empty() {
        return None;
    }
    let pids: Vec<String> = cut.iter().take(10).map(i64::to_string).collect();
    let more = if cut.len() > pids.len() { format!(" and {} more", cut.len() - pids.len()) } else { String::new() };
    Some(format!(
        "{} of {seen} process(es) have a map over the {} MiB read cap and are in this result \
         only in part — pid {}{more}. A region mapped past the cap, injected or not, is not \
         here, and a map that size is itself anomalous",
        cut.len(),
        cap / (1024 * 1024),
        pids.join(", ")
    ))
}

fn full_table_gap(filled_in: Option<i64>, left_out: usize, seen: usize, max_rows: usize) -> Option<String> {
    if filled_in.is_none() && left_out == 0 {
        return None;
    }
    let at = filled_in.map_or_else(String::new, |pid| format!(" part way through pid {pid}'s map,"));
    Some(format!(
        "the table holds at most {max_rows} rows and reached it{at} with {left_out} of {seen} \
         process(es) not read at all. A region past that point, injected or not, is not \
         here; read a process's map whole with `grep -E ' ..x[ps] ' /proc/<pid>/maps`"
    ))
}

pub fn read_kernel_text_capped(path: impl AsRef<std::path::Path>, cap: u64) -> std::io::Result<(String, bool)> {
    let (mut buf, truncated) = read_bounded(fs::File::open(path)?, cap)?;
    if truncated {
        let whole = buf.iter().rposition(|b| *b == b'\n').map_or(0, |i| i + 1);
        buf.truncate(whole);
    }
    let text = String::from_utf8(buf).unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned());
    Ok((text, truncated))
}

fn read_bounded(mut r: impl std::io::Read, cap: u64) -> std::io::Result<(Vec<u8>, bool)> {
    let limit = usize::try_from(cap).unwrap_or(usize::MAX).saturating_add(1);
    let mut buf: Vec<u8> = Vec::new();
    let mut chunk = [0_u8; 64 * 1024];
    while buf.len() < limit {
        let want = chunk.len().min(limit - buf.len());
        let Some(into) = chunk.get_mut(..want) else { break };
        let n = match r.read(into) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        let Some(got) = chunk.get(..n) else { break };
        if buf.capacity() - buf.len() < n {
            buf.reserve_exact(buf.capacity().max(n).min(limit - buf.len()));
        }
        buf.extend_from_slice(got);
    }
    let truncated = buf.len() as u64 > cap;
    buf.truncate(usize::try_from(cap).unwrap_or(usize::MAX));
    Ok((buf, truncated))
}

fn read_kernel_text(path: impl AsRef<std::path::Path>) -> std::io::Result<String> {
    fs::read(path).map(|b| String::from_utf8_lossy(&b).into_owned())
}

const KERNEL_MAPPINGS: &[&str] =
    &["[vdso]", "[vvar]", "[vvar_vclock]", "[vsyscall]", "[uprobes]", "[sigpage]", "[vectors]"];

fn region_rows(pid: i64, comm: Option<&str>, maps: &str, max_rows: usize, rows: &mut Vec<Row>) -> bool {
    for line in maps.lines() {

        let f: Vec<&str> = line.splitn(6, char::is_whitespace).collect();
        if f.len() < 5 {
            continue;
        }
        let Some((start, end)) = f[0].split_once('-') else { continue };
        let perms = f[1];
        let path = f.get(5).map(|p| p.trim().to_string()).filter(|p| !p.is_empty());

        let pseudo = path.as_deref().is_some_and(|p| KERNEL_MAPPINGS.contains(&p));
        let anonymous = i64::from(!pseudo && path.as_deref().is_none_or(|p| p.starts_with('[')));
        let pseudo = i64::from(pseudo);
        if rows.len() >= max_rows {
            return false;
        }
        rows.push(row(vec![
            ("pid", Cell::Int(pid)),
            ("comm", text(comm.map(str::to_string))),
            ("start", Cell::Text(start.to_string())),
            ("end", Cell::Text(end.to_string())),
            ("perms", Cell::Text(perms.to_string())),
            ("path", text(path)),
            ("executable", i64::from(perms.contains('x')).into()),
            ("writable", i64::from(perms.contains('w')).into()),
            ("anonymous", Cell::Int(anonymous)),
            ("pseudo", Cell::Int(pseudo)),
        ]));
    }
    true
}

impl From<i64> for Cell {
    fn from(v: i64) -> Cell {
        Cell::Int(v)
    }
}

pub fn all_with_memory() -> Vec<Box<dyn Table>> {
    vec![
        Box::new(Processes),
        Box::new(Users),
        Box::new(KernelModules),
        Box::new(ListeningPorts),
        Box::new(MemoryRegions),
    ]
}

pub fn all() -> Vec<Box<dyn Table>> {
    vec![
        Box::new(Processes),
        Box::new(Users),
        Box::new(KernelModules),
        Box::new(ListeningPorts),
    ]
}
