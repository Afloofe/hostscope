use std::collections::BTreeMap;
use std::fs;

use crate::triage::{rank, Finding, Severity};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Identity {

    pub hostname: String,

    pub kernel: String,

    pub distro: String,

    pub uptime_secs: u64,

    pub boot_epoch: u64,

    pub mem_total_kb: u64,

    pub mem_available_kb: u64,

    pub processes: usize,

    pub modules: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Socket {

    pub proto: &'static str,

    pub local: String,

    pub port: u16,

    pub remote: String,

    pub remote_port: u16,

    pub state: &'static str,

    pub uid: u32,

    pub inode: u64,

    pub pid: Option<u32>,

    pub comm: Option<String>,

    pub exe: Option<String>,

    pub exe_replaced: bool,

    pub netns: Option<String>,

    pub also_held_by: Vec<String>,
}

impl Socket {

    pub fn listening(&self) -> bool {
        self.state == "LISTEN"
    }

    pub fn world_reachable(&self) -> bool {
        self.listening() && !is_loopback(&self.local) && self.netns.is_none()
    }

    pub fn listening_elsewhere(&self) -> bool {
        self.listening() && !is_loopback(&self.local) && self.netns.is_some()
    }

    pub fn established_offhost(&self) -> bool {
        self.state == "ESTABLISHED" && !self.remote.is_empty() && !is_loopback(&self.remote)
    }

    pub fn connecting_offhost(&self) -> bool {
        self.state == "SYN_SENT" && !self.remote.is_empty() && !is_loopback(&self.remote)
    }
}

const RAW_SHELL_TOOLS: &[&str] = &[
    "bash", "sh", "dash", "zsh", "ash", "hush", "msh", "ksh", "csh", "tcsh", "fish", "busybox",
    "nc", "ncat", "netcat", "socat", "telnet",
];

const MULTI_CALL: &[&str] = &["busybox"];

const MULTI_CALL_SHELL_SERVERS: &[&str] = &["telnetd"];

fn is_interpreter(name: &str) -> bool {
    ["python", "perl", "ruby", "php", "openssl", "lua"].iter().any(|p| name.starts_with(p))
}

const SUSPECT_EXE_DIRS: &[&str] = &["/tmp/", "/var/tmp/", "/dev/shm/", "/run/shm/", "/run/user/"];

fn exe_basename(exe: &str) -> &str {
    exe.trim_end_matches(" (deleted)").rsplit('/').next().unwrap_or(exe)
}

fn c2_class(comm: Option<&str>, exe: Option<&str>, exe_replaced: bool) -> Option<(Severity, String)> {
    let comm = comm.filter(|c| !c.is_empty());
    let multi_call = exe.map(exe_basename).filter(|n| MULTI_CALL.contains(n));
    let exe_name = exe.map(exe_basename).filter(|n| !(MULTI_CALL.contains(n) && comm.is_some()));
    let names = [comm, exe_name];
    for name in names.into_iter().flatten() {
        if RAW_SHELL_TOOLS.contains(&name) {
            return Some((Severity::Critical, format!("owned by `{name}`, a shell or raw network tool")));
        }
    }
    if let (Some(bin), Some(applet)) = (multi_call, comm.filter(|c| MULTI_CALL_SHELL_SERVERS.contains(c))) {
        return Some((Severity::Critical, format!("owned by {bin}'s `{applet}`, which serves a shell")));
    }
    if let Some(reason) = dropper(exe, exe_replaced) {
        return Some((Severity::Critical, reason));
    }
    for name in names.into_iter().flatten() {
        if is_interpreter(name) {
            return Some((Severity::Warn, format!("owned by `{name}`, a scripting interpreter")));
        }
    }
    None
}

fn dropper(exe: Option<&str>, exe_replaced: bool) -> Option<String> {
    let e = exe?;
    if let Some(dir) = SUSPECT_EXE_DIRS.iter().find(|d| e.starts_with(**d)) {
        return Some(format!("its executable runs from {dir}, a world-writable path"));
    }
    if e.ends_with("(deleted)") && !exe_replaced {
        return Some("its executable has been deleted from disk while still running".to_string());
    }
    None
}

fn is_loopback(addr: &str) -> bool {

    addr.starts_with("127.") || addr == "::1"
}

#[derive(Debug, Clone, Default)]
pub struct Report {

    pub identity: Identity,

    pub sockets: Vec<Socket>,

    pub findings: Vec<Finding>,

    pub mapped_any: bool,

    pub unmapped_processes: usize,

    pub unread_tables: Vec<String>,

    pub other_namespaces: usize,
}

impl Report {

    pub fn listeners(&self) -> impl Iterator<Item = &Socket> {
        self.sockets.iter().filter(|s| s.listening() && s.netns.is_none())
    }

    pub fn unread_here(&self) -> Vec<String> {
        self.unread_tables.iter().filter(|t| t.starts_with("/proc/net/")).cloned().collect()
    }

    pub fn count_at_least(&self, sev: Severity) -> usize {
        self.findings.iter().filter(|f| f.severity >= sev).count()
    }
}

fn first_line(path: &str) -> String {
    crate::saferead::read_kernel_text(path)
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

fn distro() -> String {
    let Some(text) = crate::saferead::read_scan_target(std::path::Path::new("/etc/os-release"))
    else {
        return String::new();
    };
    text.lines()
        .find_map(|l| l.strip_prefix("PRETTY_NAME="))
        .map(|v| v.trim().trim_matches('"').to_string())
        .unwrap_or_default()
}

fn meminfo(key: &str) -> u64 {
    let Ok(text) = crate::saferead::read_kernel_text("/proc/meminfo") else {
        return 0;
    };
    text.lines()
        .find_map(|l| l.strip_prefix(key))
        .and_then(|v| v.trim().trim_end_matches(" kB").trim().parse().ok())
        .unwrap_or(0)
}

fn tcp_state(code: u8) -> &'static str {
    match code {
        0x01 => "ESTABLISHED",
        0x02 => "SYN_SENT",
        0x03 => "SYN_RECV",
        0x04 => "FIN_WAIT1",
        0x05 => "FIN_WAIT2",
        0x06 => "TIME_WAIT",
        0x07 => "CLOSE",
        0x08 => "CLOSE_WAIT",
        0x09 => "LAST_ACK",
        0x0A => "LISTEN",
        0x0B => "CLOSING",
        _ => "UNKNOWN",
    }
}

pub fn parse_addr(field: &str) -> Option<(String, u16)> {
    let (addr, port) = field.split_once(':')?;
    let port = u16::from_str_radix(port, 16).ok()?;

    match addr.len() {
        8 => {
            let v = u32::from_str_radix(addr, 16).ok()?;
            let b = v.to_le_bytes();
            Some((format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3]), port))
        }
        32 => {

            let mut octets = [0u8; 16];
            for w in 0..4 {
                let start = w * 8;
                let word = addr.get(start..start + 8)?;
                let v = u32::from_str_radix(word, 16).ok()?;
                let b = v.to_le_bytes();
                for (i, byte) in b.iter().enumerate() {
                    *octets.get_mut(w * 4 + i)? = *byte;
                }
            }

            if octets.get(..12) == Some(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff]) {
                let b = octets.get(12..16)?;
                return Some((
                    format!("{}.{}.{}.{}", b.first()?, b.get(1)?, b.get(2)?, b.get(3)?),
                    port,
                ));
            }
            let groups: Vec<u16> = octets
                .chunks(2)
                .filter_map(|c| Some(u16::from_be_bytes([*c.first()?, *c.get(1)?])))
                .collect();
            Some((compress_v6(&groups), port))
        }
        _ => None,
    }
}

fn compress_v6(groups: &[u16]) -> String {

    let (mut best_start, mut best_len) = (0usize, 0usize);
    let (mut cur_start, mut cur_len) = (0usize, 0usize);
    for (i, g) in groups.iter().enumerate() {
        if *g == 0 {
            if cur_len == 0 {
                cur_start = i;
            }
            cur_len += 1;
            if cur_len > best_len {
                best_start = cur_start;
                best_len = cur_len;
            }
        } else {
            cur_len = 0;
        }
    }

    if best_len < 2 {
        return groups.iter().map(|g| format!("{g:x}")).collect::<Vec<_>>().join(":");
    }
    let head: Vec<String> = groups
        .iter()
        .take(best_start)
        .map(|g| format!("{g:x}"))
        .collect();
    let tail: Vec<String> = groups
        .iter()
        .skip(best_start + best_len)
        .map(|g| format!("{g:x}"))
        .collect();
    format!("{}::{}", head.join(":"), tail.join(":"))
}

fn parse_socket_line(proto: &'static str, line: &str) -> Option<Socket> {
    let mut f = line.split_whitespace();
    let _sl = f.next()?;
    let (local, port) = parse_addr(f.next()?)?;
    let (remote, rport) = parse_addr(f.next()?)?;
    let state = tcp_state(u8::from_str_radix(f.next()?, 16).ok()?);
    let _tx_rx = f.next()?;
    let _tr = f.next()?;
    let _retrnsmt = f.next()?;
    let uid = f.next()?.parse().ok()?;
    let _timeout = f.next()?;
    let inode = f.next()?.parse().ok()?;

    let state = if proto.starts_with("udp") {
        if remote == "0.0.0.0" || remote == "::" { "LISTEN" } else { "ESTABLISHED" }
    } else {
        state
    };

    Some(Socket {
        proto,
        local,
        port,
        remote_port: if state == "LISTEN" { 0 } else { rport },
        remote: if state == "LISTEN" { String::new() } else { remote },
        state,
        uid,
        inode,
        pid: None,
        comm: None,
        exe: None,
        exe_replaced: false,
        netns: None,
        also_held_by: Vec::new(),
    })
}

struct SocketOwner {

    pid: u32,

    comm: String,

    exe: Option<String>,

    exe_replaced: bool,

    on_stdio: bool,
}

fn judged_holder(holders: &[SocketOwner]) -> Option<&SocketOwner> {
    let first = holders.iter().min_by_key(|h| h.pid)?;
    let grade = |h: &SocketOwner| {
        c2_class(Some(h.comm.as_str()), h.exe.as_deref(), h.exe_replaced).map(|(sev, _)| sev)
    };
    let worse = holders
        .iter()
        .filter(|h| h.on_stdio && grade(h) > grade(first))
        .max_by_key(|h| (grade(h), std::cmp::Reverse(h.pid)));
    Some(worse.unwrap_or(first))
}

fn inode_owners() -> (BTreeMap<u64, Vec<SocketOwner>>, usize) {
    let mut out: BTreeMap<u64, Vec<SocketOwner>> = BTreeMap::new();

    let mut refused = 0usize;
    let Ok(dir) = fs::read_dir("/proc") else {

        return (out, usize::MAX);
    };
    for entry in dir.flatten() {
        let Some(pid) = entry.file_name().to_str().and_then(|n| n.parse::<u32>().ok()) else {
            continue;
        };
        let fds = match fs::read_dir(format!("/proc/{pid}/fd")) {
            Ok(fds) => fds,

            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => {
                refused += 1;
                continue;
            }
        };

        let comm = crate::saferead::read_pid_text(format!("/proc/{pid}/comm"))
            .map(|s| s.trim().to_string())
            .unwrap_or_default();
        let exe = fs::read_link(format!("/proc/{pid}/exe"))
            .ok()
            .map(|p| p.display().to_string());

        let replaced = crate::hooked::exe_path_refilled(pid, exe.as_deref());

        let mut held: BTreeMap<u64, bool> = BTreeMap::new();
        for fd in fds.flatten() {
            let Ok(target) = fs::read_link(fd.path()) else { continue };
            let t = target.to_string_lossy();
            let Some(rest) = t.strip_prefix("socket:[") else { continue };
            let Some(num) = rest.strip_suffix(']') else { continue };
            if let Ok(inode) = num.parse::<u64>() {
                let stdio = matches!(fd.file_name().to_str(), Some("0" | "1" | "2"));
                *held.entry(inode).or_default() |= stdio;
            }
        }
        for (inode, on_stdio) in held {
            out.entry(inode).or_default().push(SocketOwner {
                pid,
                comm: comm.clone(),
                exe: exe.clone(),
                exe_replaced: replaced,
                on_stdio,
            });
        }
    }
    (out, refused)
}

fn unowned_listener_findings(sockets: &[Socket], unmapped_processes: usize) -> Vec<Finding> {
    if unmapped_processes != 0 {
        return Vec::new();
    }
    sockets
        .iter()
        .filter(|s| s.listening() && s.pid.is_none())
        .map(|s| {
            let ns = s.netns.as_ref().map(|n| format!(" in network namespace {n}")).unwrap_or_default();
            Finding::flag(
                Severity::Warn,
                "socket-ownership",
                format!("{}/{} on {}{ns}", s.proto, s.port, s.local),
                "listening, and no process on this host holds it".to_string(),
                "every process's file descriptors were readable on this run, so the missing \
                 owner is not a permissions artefact: nothing in /proc claims this port. A \
                 process hidden from /proc looks exactly like this from userspace. It is a \
                 lead and not a verdict — the kernel's own listeners (nfsd, lockd) hold no \
                 file descriptor either, and a process that exited between reading \
                 /proc/net and walking /proc/*/fd leaves the same gap, so re-run and see \
                 whether it persists"
                    .to_string(),
            )
        })
        .collect()
}

const TABLES: [(&str, &str); 4] = [("tcp", "tcp"), ("tcp6", "tcp6"), ("udp", "udp"), ("udp6", "udp6")];

pub(crate) fn other_netns() -> BTreeMap<String, Vec<(u32, u32)>> {
    let (Ok(ours), Ok(dir)) = (fs::read_link("/proc/self/ns/net"), fs::read_dir("/proc")) else {
        return BTreeMap::new();
    };
    let mut tasks = Vec::new();
    for entry in dir.flatten() {
        let Some(pid) = entry.file_name().to_str().and_then(|n| n.parse::<u32>().ok()) else {
            continue;
        };
        let Ok(threads) = fs::read_dir(format!("/proc/{pid}/task")) else { continue };
        for t in threads.flatten() {
            let Some(tid) = t.file_name().to_str().and_then(|n| n.parse::<u32>().ok()) else {
                continue;
            };
            if let Ok(ns) = fs::read_link(format!("/proc/{pid}/task/{tid}/ns/net")) {
                tasks.push((pid, tid, ns));
            }
        }
    }
    netns_by_task(&ours, tasks)
}

fn netns_by_task(
    ours: &std::path::Path,
    tasks: impl IntoIterator<Item = (u32, u32, std::path::PathBuf)>,
) -> BTreeMap<String, Vec<(u32, u32)>> {
    let mut out: BTreeMap<String, Vec<(u32, u32)>> = BTreeMap::new();
    for (pid, tid, ns) in tasks {
        if ns != ours {
            out.entry(ns.display().to_string()).or_default().push((pid, tid));
        }
    }
    out
}

fn task_table(pid: u32, tid: u32, table: &str) -> std::io::Result<String> {
    crate::saferead::read_kernel_text(format!("/proc/{pid}/task/{tid}/net/{table}"))
}

fn read_from_any<T: Copy>(
    tasks: &[T],
    read: impl Fn(T) -> std::io::Result<String>,
) -> std::io::Result<Option<String>> {
    let mut refused = None;
    for &task in tasks {
        match read(task) {
            Ok(t) => return Ok(Some(t)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => refused = Some(e),
        }
    }
    refused.map_or(Ok(None), Err)
}

type FlowEnd<'a> = (&'a str, &'a str, u16, &'a str, u16);

type FlowEnds<'a> = BTreeMap<FlowEnd<'a>, Vec<Option<&'a str>>>;

fn flow_ends(sockets: &[Socket]) -> FlowEnds<'_> {
    let mut out = FlowEnds::new();
    for s in sockets.iter().filter(|s| s.state == "ESTABLISHED" && !s.remote.is_empty()) {
        let end = (s.proto.trim_end_matches('6'), s.local.as_str(), s.port, s.remote.as_str(), s.remote_port);
        out.entry(end).or_default().push(s.netns.as_deref());
    }
    out
}

fn container_traffic(s: &Socket, ends: &FlowEnds<'_>) -> bool {
    let own_end = (s.proto.trim_end_matches('6'), s.local.as_str(), s.port, s.remote.as_str(), s.remote_port);
    let other_end = (s.proto.trim_end_matches('6'), s.remote.as_str(), s.remote_port, s.local.as_str(), s.port);
    match (ends.get(&own_end).map(Vec::as_slice), ends.get(&other_end).map(Vec::as_slice)) {
        (Some([_]), Some([peer_ns])) => s.netns.is_some() || peer_ns.is_some(),
        _ => false,
    }
}

fn c2_candidate(s: &Socket, ends: &FlowEnds<'_>) -> bool {
    let damning = || {
        matches!(c2_class(s.comm.as_deref(), s.exe.as_deref(), s.exe_replaced), Some((Severity::Critical, _)))
    };
    s.world_reachable()
        || (s.established_offhost() && (!container_traffic(s, ends) || damning()))
        || s.connecting_offhost()
        || s.listening_elsewhere()
}

fn c2_finding(s: &Socket, who: &str, locus: String) -> Option<Finding> {
    let (severity, reason) = c2_class(s.comm.as_deref(), s.exe.as_deref(), s.exe_replaced)?;
    let exe = s.exe.as_deref().unwrap_or("unknown");

    let attempt = s.state == "SYN_SENT";
    let severity = if attempt && dropper(s.exe.as_deref(), s.exe_replaced).is_none() {
        Severity::Note
    } else {
        severity
    };

    if severity == Severity::Warn && s.listening_elsewhere() {
        return Some(Finding::flag(
            Severity::Note,
            "c2",
            locus,
            format!("{who} — {exe}"),
            format!(
                "{reason}, listening inside another network namespace. That is usually a \
                 container's app server, reachable from off the host only where a port is \
                 published. Confirm it is the service the container runs"
            ),
        ));
    }

    let shape = if s.listening() {
        "a bind shell or backdoor listener"
    } else if attempt {
        "an outbound connection nothing has answered: a beacon or reverse shell retrying \
         a C2 that is down or blocked"
    } else {
        "a reverse shell or outbound C2 channel"
    };
    let graded = if attempt && severity == Severity::Note {
        ". A Note while it waits, because a port probe of a host that is down looks the \
         same; once it connects it is judged as the connection it is"
    } else {
        ""
    };
    let also = match s.also_held_by.len() {
        0 => String::new(),
        n if n <= 4 => format!("; also held by {}", s.also_held_by.join(", ")),
        n => format!(
            "; also held by {} and {} more",
            s.also_held_by.iter().take(4).cloned().collect::<Vec<_>>().join(", "),
            n - 4
        ),
    };
    Some(Finding::flag(
        severity,
        "c2",
        locus,
        format!("{who} — {exe}{also}"),
        format!(
            "{reason}; on this socket that is {shape}. Confirm the process and where the \
             connection goes before trusting the host{graded}"
        ),
    ))
}

pub fn report() -> Report {
    let mut r = Report::default();

    r.identity.hostname = first_line("/proc/sys/kernel/hostname");
    r.identity.kernel = first_line("/proc/sys/kernel/osrelease");
    r.identity.distro = distro();
    r.identity.uptime_secs = crate::saferead::read_kernel_text("/proc/uptime")
        .ok()
        .and_then(|s| s.split('.').next().and_then(|v| v.parse().ok()))
        .unwrap_or(0);
    r.identity.boot_epoch = crate::saferead::read_kernel_text("/proc/stat")
        .ok()
        .and_then(|s| {
            s.lines()
                .find_map(|l| l.strip_prefix("btime "))
                .and_then(|v| v.trim().parse().ok())
        })
        .unwrap_or(0);
    r.identity.mem_total_kb = meminfo("MemTotal:");
    r.identity.mem_available_kb = meminfo("MemAvailable:");
    r.identity.processes = fs::read_dir("/proc")
        .map(|d| {
            d.flatten()
                .filter(|e| e.file_name().to_str().is_some_and(|n| n.parse::<u32>().is_ok()))
                .count()
        })
        .unwrap_or(0);
    r.identity.modules = crate::saferead::read_kernel_text("/proc/modules")
        .map(|s| s.lines().count())
        .unwrap_or(0);

    let (owners, fd_refused) = inode_owners();
    r.unmapped_processes = fd_refused;
    let add_rows = |r: &mut Report, proto: &'static str, text: &str, netns: Option<&str>| {
        for line in text.lines().skip(1) {
            let Some(mut s) = parse_socket_line(proto, line) else { continue };
            let holders = owners.get(&s.inode).map_or(&[][..], Vec::as_slice);
            if let Some(owner) = judged_holder(holders) {
                s.pid = Some(owner.pid);
                s.comm = Some(owner.comm.clone());
                s.exe = owner.exe.clone();
                s.exe_replaced = owner.exe_replaced;
                s.also_held_by = holders
                    .iter()
                    .filter(|h| h.pid != owner.pid)
                    .map(|h| format!("{} (pid {})", h.comm, h.pid))
                    .collect();
                r.mapped_any = true;
            }
            s.netns = netns.map(str::to_string);
            r.sockets.push(s);
        }
    };
    for (proto, table) in TABLES {
        match crate::saferead::read_kernel_text(format!("/proc/net/{table}")) {
            Ok(t) => add_rows(&mut r, proto, &t, None),

            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => r.unread_tables.push(format!("/proc/net/{table} ({e})")),
        }
    }

    let others = other_netns();
    r.other_namespaces = others.len();
    for (ns, tasks) in &others {
        for (proto, table) in TABLES {
            match read_from_any(tasks, |(pid, tid)| task_table(pid, tid, table)) {
                Ok(Some(t)) => add_rows(&mut r, proto, &t, Some(ns)),
                Ok(None) => {}
                Err(e) => r.unread_tables.push(format!("{table} in network namespace {ns} ({e})")),
            }
        }
    }

    r.sockets.sort_by(|a, b| {
        b.listening()
            .cmp(&a.listening())
            .then_with(|| a.port.cmp(&b.port))
            .then_with(|| a.proto.cmp(b.proto))
    });

    for t in &r.unread_tables {
        r.findings.push(Finding {
            severity: Severity::Warn,
            subject: "socket table".into(),
            locus: t.clone(),
            what: "could not be read — the sockets in it are not in this report".into(),
            why: "the port list below is not the host's port list: everything this table \
                  held is missing from it, and a missing bind shell looks the same as no \
                  bind shell. These files are world-readable on an ordinary host, so a \
                  refusal here is itself worth explaining — a hooked read of /proc/net is \
                  how an implant hides its own listener"
                .into(),
        });
    }

    let mut exposed: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let unowned = if r.unmapped_processes == 0 {

        "NO process on this host holds this socket"
    } else {
        "owner unknown — needs root to map"
    };
    let ends = flow_ends(&r.sockets);
    for s in r.sockets.iter().filter(|s| c2_candidate(s, &ends)) {
        let who = match (&s.comm, s.pid) {
            (Some(c), Some(p)) => format!("{c} (pid {p})"),
            _ => unowned.to_string(),
        };
        let mut locus = if s.listening() {
            format!("{}/{} on {}", s.proto, s.port, s.local)
        } else {
            format!("{}/{} -> {}", s.proto, s.port, s.remote)
        };
        if let Some(ns) = &s.netns {
            locus.push_str(&format!(" in network namespace {ns}"));
        }

        match c2_finding(s, &who, locus) {
            Some(f) => r.findings.push(f),

            None if s.world_reachable() && s.listening() => {
                exposed
                    .entry(who)
                    .or_default()
                    .push(format!("{}/{}", s.proto, s.port));
            }
            None => {}
        }
    }

    for (who, mut ports) in exposed {
        ports.sort();
        ports.dedup();
        let shown: Vec<&str> = ports.iter().take(6).map(String::as_str).collect();
        let more = ports.len().saturating_sub(shown.len());
        let tail = if more > 0 { format!(" (+{more} more)") } else { String::new() };
        r.findings.push(Finding::flag(
            Severity::Note,
            "listening",
            who,
            format!("answers from off this host on {}{tail}", shown.join(", ")),
            "inventory, not a verdict: a server is supposed to listen. It is here so the set \
             of things reachable from outside is one list a responder can read, and so that a \
             port nobody can account for stands out against the ones they can",
        ));
    }

    r.findings.extend(unowned_listener_findings(&r.sockets, r.unmapped_processes));

    if !r.mapped_any && !r.sockets.is_empty() {
        r.findings.push(Finding::flag(
            Severity::Warn,
            "socket-ownership",
            "/proc/*/fd",
            "no socket could be matched to a process",
            "a process's file descriptors are readable only by its owner and root, so \
             this list has ports without owners. Re-run as root; until then the absence \
             of an owner says nothing about the socket",
        ));
    }

    rank(&mut r.findings);
    r
}
