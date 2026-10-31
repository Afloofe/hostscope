use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

use crate::triage::{rank, Finding, Severity};

const UNEXPECTED_LIB_DIRS: &[&str] =
    &["/tmp/", "/var/tmp/", "/dev/shm/", "/run/user/", "/home/", "/root/"];

pub(crate) const MAX_NAMES_LISTED: usize = 32;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Process {

    pub pid: u32,

    pub comm: String,

    pub cmdline: String,

    pub tracer: Option<u32>,

    pub ld_preload: Option<String>,

    pub ld_audit: Option<String>,

    pub env_readable: bool,

    pub kernel_thread: bool,

    pub exe_deleted: bool,

    pub exe_replaced: bool,

    pub exe: Option<String>,

    pub runs_our_image: bool,

    pub maps_readable: bool,

    pub maps_truncated: bool,

    pub unexpected_libs: Vec<String>,

    pub unexpected_libs_total: usize,

    pub anon_exec: usize,

    pub memfd_exec: usize,

    pub memfd_names: Vec<String>,

    pub memfd_names_total: usize,

    pub mounted_over: Vec<&'static str>,

    pub ppid: u32,

    pub uid: Option<u32>,

    pub embedded_image: bool,

    pub daemon_script: Option<String>,

    pub ffi: FfiMaps,

    pub kernel_helper: bool,

    pub ffi_vouched: Option<String>,
}

impl Process {

    fn interesting(&self) -> bool {
        self.tracer.is_some()
            || self.ld_preload.is_some()
            || self.ld_audit.is_some()
            || self.exe_deleted
            || !self.unexpected_libs.is_empty()
            || self.memfd_exec > 0
            || self.maps_truncated
            || !self.mounted_over.is_empty()
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FfiMaps {

    pub exec: usize,

    pub exec_max: u64,

    pub exec_total: u64,

    pub odd: bool,

    pub library: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct Report {

    pub processes: Vec<Process>,

    pub findings: Vec<Finding>,

    pub examined: usize,

    pub unreadable: usize,

    pub env_unreadable: usize,

    pub maps_unreadable: usize,

    pub maps_capped: usize,

    pub vanished: usize,

    pub anon_exec_total: usize,

    pub mounted_over: usize,
}

impl Report {

    fn account(&mut self, p: &Process) {
        self.anon_exec_total += p.anon_exec;
        if !p.mounted_over.is_empty() {
            self.mounted_over += 1;
        }
        if !p.env_readable && !p.kernel_thread {
            self.env_unreadable += 1;
        }
        if p.maps_truncated {
            self.maps_capped += 1;
        } else if !p.maps_readable && !p.kernel_thread {
            self.maps_unreadable += 1;
        }
    }

    fn tally(&mut self, read: Option<&Process>, gone: bool) {
        if gone {
            self.vanished += 1;
            self.anon_exec_total += read.map_or(0, |p| p.anon_exec);
            return;
        }
        self.examined += 1;
        match read {
            Some(p) => self.account(p),
            None => self.unreadable += 1,
        }
    }

    pub fn count_at_least(&self, sev: Severity) -> usize {
        self.findings.iter().filter(|f| f.severity >= sev).count()
    }
}

fn tracer_of(status: &str) -> Option<u32> {
    status
        .lines()
        .find_map(|l| l.strip_prefix("TracerPid:"))
        .and_then(|v| v.trim().parse::<u32>().ok())
        .filter(|p| *p != 0)
}

fn is_kernel_thread(stat: &str) -> bool {
    const PF_KTHREAD: u64 = 0x0020_0000;
    stat.rsplit_once(')')
        .and_then(|(_, rest)| rest.split_whitespace().nth(6))
        .and_then(|f| f.parse::<u64>().ok())
        .is_some_and(|flags| flags & PF_KTHREAD != 0)
}

fn ppid_of(stat: &str) -> Option<u32> {
    stat.rsplit_once(')')
        .and_then(|(_, rest)| rest.split_whitespace().nth(1))
        .and_then(|f| f.parse().ok())
}

fn uid_of(status: &str) -> Option<u32> {
    status
        .lines()
        .find_map(|l| l.strip_prefix("Uid:"))
        .and_then(|v| v.split_whitespace().next()?.parse().ok())
}

fn is_kernel_thread_pid(pid: u32) -> bool {
    pid > 0
        && crate::saferead::read_pid_text(format!("/proc/{pid}/stat")).is_ok_and(|s| is_kernel_thread(&s))
}

pub fn env_var(environ: &[u8], key: &str) -> Option<String> {
    let mut prefix = key.as_bytes().to_vec();
    prefix.push(b'=');
    environ
        .rsplit(|b| *b == 0)
        .find_map(|kv| kv.strip_prefix(prefix.as_slice()))
        .map(|v| String::from_utf8_lossy(v).into_owned())
}

pub fn parse_map_line(line: &str) -> Option<(bool, Option<&str>)> {
    map_entry(line).map(|m| (m.perms.contains('x'), m.path))
}

struct MapEntry<'a> {

    len: u64,

    perms: &'a str,

    dev: &'a str,

    path: Option<&'a str>,
}

fn map_entry(line: &str) -> Option<MapEntry<'_>> {
    let mut fields = line.splitn(6, char::is_whitespace).filter(|f| !f.is_empty());
    let range = fields.next()?;
    let perms = fields.next()?;
    let _offset = fields.next();
    let dev = fields.next().unwrap_or_default();
    let _inode = fields.next();
    let path = fields.next().map(str::trim).filter(|p| !p.is_empty());
    let len = range
        .split_once('-')
        .and_then(|(a, b)| u64::from_str_radix(b, 16).ok()?.checked_sub(u64::from_str_radix(a, 16).ok()?))
        .unwrap_or(0);
    Some(MapEntry { len, perms, dev, path })
}

const LIBFFI_MEMFD: &str = "/memfd:libffi (deleted)";

#[derive(Debug, Default, PartialEq, Eq)]
struct MappedCode {
    unexpected_libs: Vec<String>,
    unexpected_libs_total: usize,
    anon_exec: usize,
    memfd_exec: usize,
    memfd_names: Vec<String>,
    memfd_names_total: usize,

    image_mapped: usize,
    image_on_disk: bool,

    other_files: usize,

    ffi: FfiMaps,
}

impl MappedCode {

    fn embedded_image(&self) -> bool {
        self.other_files == 0 && self.image_mapped > 0 && !self.image_on_disk && self.anon_exec == 0
    }

    fn shape(&mut self, m: &MapEntry<'_>, own_image: bool) {
        let Some(path) = m.path.filter(|p| !p.starts_with('[')) else { return };
        if own_image {
            self.image_mapped += 1;
            self.image_on_disk |= m.dev.split(':').next() != Some("00");
            return;
        }
        if c_runtime(path) {
            return;
        }
        self.other_files += 1;
        let executable = m.perms.contains('x');
        if path == LIBFFI_MEMFD {
            self.ffi.odd |= m.perms.ends_with('p') || (executable && m.perms.contains('w'));
            if executable {
                self.ffi.exec += 1;
                self.ffi.exec_max = self.ffi.exec_max.max(m.len);
                self.ffi.exec_total = self.ffi.exec_total.saturating_add(m.len);
            }
        } else if self.ffi.library.is_none()
            && path.starts_with('/')
            && path.rsplit('/').next().is_some_and(|n| n.starts_with("libffi.so"))
        {
            self.ffi.library = Some(path.to_string());
        }
    }
}

fn c_runtime(path: &str) -> bool {
    let path = path.strip_suffix(" (deleted)").unwrap_or(path);
    let Some((dir, name)) = path.rsplit_once('/') else { return false };
    let runtime = name == "libc.so.6"
        || (name.starts_with("libc-2.") && name.ends_with(".so"))
        || name.starts_with("ld-linux")
        || (name.starts_with("ld-2.") && name.ends_with(".so"))
        || name.starts_with("ld64.so.");
    let system = ["/lib", "/lib64", "/usr/lib", "/usr/lib64"].contains(&dir)
        || dir.rsplit_once('/').is_some_and(|(up, arch)| {
            ["/lib", "/usr/lib"].contains(&up) && arch.contains("-linux-") && !arch.contains('.')
        });
    runtime && system
}

fn mapped_code(maps: &str, exe: Option<&str>) -> MappedCode {
    let mut code = MappedCode::default();
    let mut seen_memfds: HashSet<&str> = HashSet::new();
    let mut seen_libs: HashSet<&str> = HashSet::new();

    let is_own_image = |p: &str| exe.is_some_and(|e| e == p || e.trim_end_matches(" (deleted)") == p);
    for line in maps.lines() {
        let Some(m) = map_entry(line) else { continue };
        code.shape(&m, m.path.is_some_and(is_own_image));
        let (executable, path) = (m.perms.contains('x'), m.path);
        if !executable {
            continue;
        }
        match path {
            None => code.anon_exec += 1,

            Some(p) if p.starts_with("/memfd:") || p.starts_with("memfd:") => {
                if !is_own_image(p) {
                    code.memfd_exec += 1;
                    if seen_memfds.insert(p) {
                        code.memfd_names_total += 1;
                        if code.memfd_names.len() < MAX_NAMES_LISTED {
                            code.memfd_names.push(p.to_string());
                        }
                    }
                }
            }
            Some(p) if p.starts_with('[') => {}
            Some(p) => {
                if !is_own_image(p)
                    && UNEXPECTED_LIB_DIRS.iter().any(|d| p.starts_with(*d))
                    && seen_libs.insert(p)
                {
                    code.unexpected_libs_total += 1;
                    if code.unexpected_libs.len() < MAX_NAMES_LISTED {
                        code.unexpected_libs.push(p.to_string());
                    }
                }
            }
        }
    }
    code
}

pub(crate) fn shares_our_mount_ns(base: &Path) -> bool {
    match (
        fs::read_link("/proc/self/ns/mnt"),
        fs::read_link(base.join("ns/mnt")),
    ) {
        (Ok(ours), Ok(theirs)) => ours == theirs,
        _ => false,
    }
}

pub(crate) fn exe_path_refilled(pid: u32, exe: Option<&str>) -> bool {
    let base = PathBuf::from(format!("/proc/{pid}"));
    exe_path_refilled_under(&base.join("root"), shares_our_mount_ns(&base), exe)
}

pub(crate) fn exe_path_refilled_under(root: &Path, same_ns: bool, exe: Option<&str>) -> bool {
    let Some(path) = exe.and_then(|e| e.strip_suffix(" (deleted)")) else {
        return false;
    };

    let theirs = path
        .strip_prefix('/')
        .filter(|rel| !rel.is_empty())
        .is_some_and(|rel| fs::symlink_metadata(root.join(rel)).is_ok());
    let ours = same_ns && path.starts_with('/') && Path::new(path).exists();
    theirs || ours
}

fn env_coverage_finding(
    examined: usize,
    env_unreadable: usize,
    elevated: bool,
) -> Option<Finding> {
    if env_unreadable == 0 {
        return None;
    }
    let looked = examined.saturating_sub(env_unreadable);
    Some(Finding::flag(
        Severity::Note,
        "preload coverage",
        format!("{looked}/{examined} processes"),
        format!(
            "the LD_PRELOAD and LD_AUDIT checks could read the environment of {looked} of \
             {examined} process(es); {env_unreadable} refused"
        ),
        format!(
            "an environment that could not be read is not an environment without LD_PRELOAD \
             in it — /proc/<pid>/environ is readable only by the process owner and root. {}",
            refused_because(elevated)
        ),
    ))
}

fn maps_coverage_finding(
    examined: usize,
    maps_unreadable: usize,
    maps_capped: usize,
    elevated: bool,
) -> Option<Finding> {
    if maps_unreadable == 0 && maps_capped == 0 {
        return None;
    }
    let looked = examined.saturating_sub(maps_unreadable).saturating_sub(maps_capped);
    let mut what = format!(
        "the unexpected-library, anonymous-code and memfd checks could read the whole memory \
         map of {looked} of {examined} process(es)"
    );
    let mut why = Vec::new();
    if maps_unreadable > 0 {
        what.push_str(&format!("; {maps_unreadable} refused"));
        why.push(format!(
            "a map that could not be read is not a map with nothing injected in it — \
             /proc/<pid>/maps is readable only by a process allowed to trace the target. {}",
            refused_because(elevated)
        ));
    }
    if maps_capped > 0 {
        what.push_str(&format!(
            "; {maps_capped} over the {} MiB read cap were examined only in part",
            crate::saferead::MAX_MAPS_BYTES / (1024 * 1024)
        ));
        why.push(
            "a mapping past the cap was not looked at, and no privilege reaches it: each such \
             process is named in its own oversized-map finding"
                .to_string(),
        );
    }
    Some(Finding::flag(
        Severity::Note,
        "mapped-code coverage",
        format!("{looked}/{examined} processes"),
        what,
        why.join(". "),
    ))
}

fn oversized_map_finding(p: &Process) -> Option<Finding> {
    if !p.maps_truncated {
        return None;
    }
    let cap = crate::saferead::MAX_MAPS_BYTES / (1024 * 1024);
    Some(Finding::flag(
        Severity::Warn,
        "oversized-map",
        format!("pid {} ({})", p.pid, p.comm),
        format!(
            "its memory map is over the {cap} MiB read cap, so only the first {cap} MiB went \
             through the unexpected-library, anonymous-code and memfd checks"
        ),
        format!(
            "{cap} MiB is 262,144 mappings at 256 bytes a line, the largest map count any \
             mainstream software asks the kernel for. A map past it is the process's own \
             doing, and a library mapped above the part read was not examined — padding the \
             map is a way to put one there. Identify the process; `wc -l /proc/{}/maps` \
             gives the count",
            p.pid
        ),
    ))
}

fn refused_because(elevated: bool) -> &'static str {
    if elevated {
        "This sweep ran as root and was refused anyway, so re-running will not reach these. \
         Among the causes: a process part way through exiting, or whose first thread has \
         exited while the rest run, has no address space left to read, and a security \
         module's ptrace rule can refuse even root"
    } else {
        "An unprivileged sweep covers only this user's own processes. Re-run elevated to \
         check the rest"
    }
}

fn mapped_code_findings(p: &Process, findings: &mut Vec<Finding>) {
    let pid = p.pid;
    for lib in &p.unexpected_libs {
        findings.push(Finding::flag(
            Severity::Warn,
            "unexpected-library",
            format!("pid {pid} ({})", p.comm),
            format!("maps executable code from {lib}"),
            "no packaged library lives there. Either this is a developer build or \
             something placed code where a normal load path does not reach",
        ));
    }
    let unlisted = p.unexpected_libs_total.saturating_sub(p.unexpected_libs.len());
    if unlisted > 0 {
        findings.push(Finding::flag(
            Severity::Warn,
            "unexpected-library",
            format!("pid {pid} ({})", p.comm),
            format!(
                "maps executable code from {} distinct files where no packaged library \
                 lives; the first {} are listed, {unlisted} more are not",
                p.unexpected_libs_total,
                p.unexpected_libs.len()
            ),
            format!(
                "no build tree or injection maps that many; the count is the process's own \
                 doing, and is why the list stops. `grep -E ' ..x[ps] ' /proc/{pid}/maps` lists \
                 every executable mapping"
            ),
        ));
    }
    if let (true, Some(vouched)) = (p.memfd_exec > 0, &p.ffi_vouched) {
        findings.push(Finding::flag(
            Severity::Note,
            "memfd-execution",
            format!("pid {pid} ({})", p.comm),
            format!(
                "{} executable mapping(s) of {LIBFFI_MEMFD}, {} bytes in all: libffi's closure trampolines",
                p.memfd_exec, p.ffi.exec_total
            ),
            format!(
                "where SELinux is enabled libffi never maps memory writable and executable at once: it writes each \
                 closure through one shared mapping of a memfd it names libffi and runs it through a second, \
                 read-only one. That is the shape here — every mapping of it shared, none writable and executable, \
                 none private as a loaded binary's are, a few pages in all — and {vouched}. A memfd by any other \
                 name, a private or larger mapping of this one, or a program the package manager does not vouch \
                 for is the Warn"
            ),
        ));
    } else if p.memfd_exec > 0 {
        let unlisted = p.memfd_names_total.saturating_sub(p.memfd_names.len());
        let more = if unlisted > 0 {
            format!(", and {unlisted} more distinct name(s) not listed")
        } else {
            String::new()
        };
        findings.push(Finding::flag(
            Severity::Warn,
            "memfd-execution",
            format!("pid {pid} ({})", p.comm),
            format!(
                "{} executable mapping(s) backed by an anonymous file: {}{more}",
                p.memfd_exec,
                p.memfd_names.join(", ")
            ),
            "a memfd has no path on disk, which is how a payload runs without ever \
             being written to the filesystem. A JIT that double-maps its code through \
             one (.NET's `doublemapper`) has the same shape; the name is the creator's \
             choice, so identify the process before trusting it",
        ));
    }
}

fn read_maps_or(path: &Path, cap: u64, exe: Option<&str>) -> std::io::Result<(bool, MappedCode)> {
    let (maps, truncated) = crate::saferead::read_kernel_text_capped(path, cap)?;
    Ok((truncated, mapped_code(&maps, exe)))
}

fn noting<T>(over: &mut Vec<&'static str>, name: &'static str, r: std::io::Result<T>) -> Option<T> {
    match r {
        Ok(v) => Some(v),
        Err(e) => {
            if e.kind() == std::io::ErrorKind::InvalidInput {
                over.push(name);
            }
            None
        }
    }
}

fn read_process(pid: u32) -> Option<Process> {
    use crate::saferead::{read_pid_text, read_proc, MAX_PROC_BYTES};
    let base = PathBuf::from(format!("/proc/{pid}"));
    let mut over: Vec<&'static str> = Vec::new();

    let status = match read_pid_text(base.join("status")) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::InvalidInput => {
            over.push("status");
            String::new()
        }
        Err(_) => return None,
    };
    let stat = noting(&mut over, "stat", read_pid_text(base.join("stat")));
    let kernel_thread = stat.as_deref().is_some_and(is_kernel_thread);
    let ppid = stat.as_deref().and_then(ppid_of).unwrap_or(0);

    let comm = noting(&mut over, "comm", read_pid_text(base.join("comm")))
        .map(|s| s.trim().to_string())
        .unwrap_or_default();

    let argv = noting(&mut over, "cmdline", read_proc(&base.join("cmdline"), MAX_PROC_BYTES));
    let cmdline = argv
        .as_ref()
        .map(|(b, _)| {
            let text = String::from_utf8_lossy(b).replace('\0', " ").trim().to_string();
            crate::procfs::keep_ends(text, crate::procfs::MAX_CMDLINE_KEPT).0
        })
        .unwrap_or_default();

    let environ = noting(&mut over, "environ", read_proc(&base.join("environ"), MAX_PROC_BYTES));
    let env_readable = environ.as_ref().is_some_and(|(_, truncated)| !truncated);
    let environ = environ.map(|(e, _)| e).unwrap_or_default();
    let ld_preload = env_var(&environ, "LD_PRELOAD");
    let ld_audit = env_var(&environ, "LD_AUDIT");

    let link = fs::read_link(base.join("exe")).ok();
    let exe = link.as_ref().map(|p| p.display().to_string());

    let exe_deleted = exe.as_deref().is_some_and(|e| e.ends_with(" (deleted)"))
        || (shares_our_mount_ns(&base) && link.as_ref().is_some_and(|p| !p.exists()));

    let exe_replaced = exe_deleted && exe_path_refilled(pid, exe.as_deref());

    let maps = noting(
        &mut over,
        "maps",
        read_maps_or(&base.join("maps"), crate::saferead::MAX_MAPS_BYTES, exe.as_deref()),
    );
    let (maps_readable, maps_truncated, code) = match maps {
        Some((truncated, code)) => (!truncated, truncated, code),
        None => (false, false, MappedCode::default()),
    };
    let embedded_image = maps_readable && code.embedded_image();

    let daemon_script = match (&argv, exe.as_deref()) {
        (Some((raw, false)), Some(exe)) if env_readable => python_daemon_script(exe, raw, &environ),
        _ => None,
    };

    Some(Process {
        pid,
        comm,
        cmdline,
        tracer: tracer_of(&status),
        ld_preload,
        ld_audit,
        env_readable,
        kernel_thread,
        exe_deleted,
        exe_replaced,
        exe,
        runs_our_image: false,
        maps_readable,
        maps_truncated,
        unexpected_libs: code.unexpected_libs,
        unexpected_libs_total: code.unexpected_libs_total,
        anon_exec: code.anon_exec,
        memfd_exec: code.memfd_exec,
        memfd_names: code.memfd_names,
        memfd_names_total: code.memfd_names_total,
        mounted_over: over,
        ppid,
        uid: uid_of(&status),
        embedded_image,
        daemon_script,
        ffi: code.ffi,
        kernel_helper: false,
        ffi_vouched: None,
    })
}

const BPFILTER_UMH: &str = "bpfilter_umh";

fn kernel_helper_facts(p: &Process, parent_is_kernel_thread: bool) -> bool {
    p.comm == BPFILTER_UMH
        && p.exe.as_deref() == Some("/bpfilter_umh")
        && p.exe_deleted
        && !p.exe_replaced
        && !p.kernel_thread
        && parent_is_kernel_thread
        && p.uid == Some(0)
        && p.tracer.is_none()
        && p.env_readable
        && p.ld_preload.is_none()
        && p.ld_audit.is_none()
        && p.embedded_image
        && p.memfd_exec == 0
        && p.unexpected_libs_total == 0
        && p.mounted_over.is_empty()
}

fn helper_findings(processes: &mut [Process], helpers: &[u32]) -> Vec<Finding> {
    let unique = helpers.len() == 1;
    processes
        .iter_mut()
        .filter(|p| helpers.contains(&p.pid))
        .filter_map(|p| {
            p.kernel_helper = unique;
            exe_finding(p)
        })
        .collect()
}

const MAX_FFI_MAPPING: u64 = 256 * 1024;

const MAX_FFI_TOTAL: u64 = 1024 * 1024;

fn ffi_shaped(p: &Process) -> bool {
    p.memfd_exec > 0
        && p.memfd_names_total == 1
        && p.memfd_names.first().map(String::as_str) == Some(LIBFFI_MEMFD)
        && p.maps_readable
        && !p.ffi.odd
        && p.ffi.exec == p.memfd_exec
        && p.ffi.exec_max <= MAX_FFI_MAPPING
        && p.ffi.exec_total <= MAX_FFI_TOTAL
        && p.ffi.library.is_some()
        && !p.exe_deleted
        && p.exe.as_deref().is_some_and(|e| e.starts_with('/'))
        && p.tracer.is_none()
        && p.ld_preload.is_none()
        && p.ld_audit.is_none()
        && p.mounted_over.is_empty()
}

fn interpreter_like(exe: &str) -> bool {
    const RUNTIMES: &[&str] = &["python", "perl", "ruby", "php", "node", "gjs", "java", "lua", "tclsh"];
    let name = exe.rsplit('/').next().unwrap_or(exe);
    crate::watchdog::is_interpreter(exe) || RUNTIMES.iter().any(|r| name.contains(r))
}

fn is_running_image(pid: u32, exe: &str) -> bool {
    use std::os::unix::fs::MetadataExt as _;
    match (fs::metadata(format!("/proc/{pid}/exe")), fs::metadata(exe)) {
        (Ok(running), Ok(here)) => (running.dev(), running.ino()) == (here.dev(), here.ino()),
        _ => false,
    }
}

fn is_loader(exe: &str) -> bool {
    let name = exe.rsplit('/').next().unwrap_or(exe);
    name.starts_with("ld-") || name.starts_with("ld.so") || name.starts_with("ld64.so")
}

const DAEMON_DIRS: &[&str] = &["/usr/sbin/", "/sbin/", "/usr/libexec/"];

const PYTHON_PLAIN_FLAGS: &str = "bBdEIOqsSu";

const PYTHON_INERT_VARS: &[&str] = &[
    "PYTHONUNBUFFERED",
    "PYTHONDONTWRITEBYTECODE",
    "PYTHONIOENCODING",
    "PYTHONHASHSEED",
    "PYTHONUTF8",
    "PYTHONCOERCECLOCALE",
    "PYTHONNOUSERSITE",
    "PYTHONFAULTHANDLER",
];

fn python_daemon_script(exe: &str, argv: &[u8], environ: &[u8]) -> Option<String> {
    python_daemon_script_with(exe, argv, environ, &|p| fs::canonicalize(p).ok()?.to_str().map(str::to_string))
}

fn python_daemon_script_with(
    exe: &str,
    argv: &[u8],
    environ: &[u8],
    resolve: &dyn Fn(&str) -> Option<String>,
) -> Option<String> {
    let name = exe.rsplit('/').next()?;
    if !matches!(name.trim_end_matches(|c: char| c.is_ascii_digit() || c == '.'), "python" | "platform-python") {
        return None;
    }
    let mut words = argv.split(|b| *b == 0).map(|w| std::str::from_utf8(w).ok());
    let argv0 = words.next()??;
    if !argv0.starts_with('/') || resolve(argv0).as_deref() != Some(exe) {
        return None;
    }
    let mut flags = String::new();
    let script = loop {
        let w = words.next()??;
        if w.is_empty() || w.chars().any(char::is_whitespace) {
            return None;
        }
        match w.strip_prefix('-') {
            Some(f) if !f.is_empty() && f.chars().all(|c| PYTHON_PLAIN_FLAGS.contains(c)) => flags.push_str(f),
            Some(_) => return None,
            None => break w,
        }
    };
    if !(flags.contains('s') || flags.contains('I')) {
        return None;
    }
    let in_daemon_dir = |p: &str| DAEMON_DIRS.iter().any(|d| p.starts_with(d));
    if !in_daemon_dir(script) || !in_daemon_dir(&resolve(script)?) {
        return None;
    }
    let steered = environ.split(|b| *b == 0).any(|kv| {
        kv.starts_with(b"PYTHON")
            && !PYTHON_INERT_VARS.iter().any(|v| kv.strip_prefix(v.as_bytes()).is_some_and(|r| r.starts_with(b"=")))
    });
    if steered && !(flags.contains('E') || flags.contains('I')) {
        return None;
    }
    Some(script.to_string())
}

struct Vouch {
    manager: Option<crate::pkg::Manager>,
    verified: BTreeMap<String, Option<Vec<PathBuf>>>,
}

impl Vouch {
    fn new() -> Self {
        Vouch { manager: crate::pkg::manager(), verified: BTreeMap::new() }
    }

    fn of(&mut self, path: &str) -> Option<String> {
        self.manager.as_ref()?.vouches(Path::new(path), &mut self.verified)
    }

    fn kind(&self) -> &'static str {
        self.manager.as_ref().map_or("the package manager", |m| m.kind.name())
    }
}

fn ffi_vouched(p: &Process, vouch: &mut Vouch) -> Option<String> {
    if !ffi_shaped(p) {
        return None;
    }
    let exe = p.exe.as_deref()?;

    if !is_running_image(p.pid, exe) {
        return None;
    }
    let runs = if interpreter_like(exe) {
        let script = p.daemon_script.as_deref()?;
        let exe_pkg = vouch.of(exe)?;
        let script_pkg = vouch.of(script)?;
        format!("{exe} ({exe_pkg}) running {script} ({script_pkg})")
    } else if is_loader(exe) {
        return None;
    } else {
        let exe_pkg = vouch.of(exe)?;
        format!("{exe} ({exe_pkg})")
    };
    let lib = p.ffi.library.as_deref()?;
    let lib_pkg = vouch.of(lib)?;
    Some(format!(
        "the program is {runs}, and the trampolines' library {lib} ({lib_pkg}), each verified unmodified by {}",
        vouch.kind()
    ))
}

fn mounted_over_finding(listed: &[String], total: usize) -> Option<Finding> {
    if total == 0 {
        return None;
    }
    let more = total.saturating_sub(listed.len());
    let more = if more > 0 { format!("; and {more} more not listed") } else { String::new() };
    Some(Finding::flag(
        Severity::Warn,
        "proc-mount",
        format!("{total} process(es)"),
        format!(
            "something is mounted over a file the kernel serves for them, so it was neither opened nor read: {}{more}",
            listed.join("; ")
        ),
        "nothing ordinary mounts over a process's /proc entry. It is how a process's tracer, name or command line \
         is forged and how one is hidden from ps, and a named pipe or /dev/zero there once hung this sweep and the \
         console with it. What was not read is a gap for that process. `grep /proc/PID /proc/self/mountinfo` names \
         the mount, and unmounting it gives the kernel's file back",
    ))
}

fn exe_finding(p: &Process) -> Option<Finding> {
    let pid = p.pid;
    if p.exe_deleted && p.exe_replaced {

        Some(Finding::flag(
            Severity::Note,
            "deleted-executable",
            format!("pid {pid} ({})", p.comm),
            format!(
                "running an older copy of {} — the file was replaced while it ran",
                p.exe.as_deref().unwrap_or_default().trim_end_matches(" (deleted)")
            ),
            "a package upgrade replaces the file underneath every process still running \
             the old inode, which is exactly this. The path is occupied again, so the \
             binary on disk can be verified by the package manager and the process only \
             needs restarting to pick it up. An implant unlinks and leaves nothing behind, \
             which is the Critical above",
        ))
    } else if p.exe_deleted && p.runs_our_image {
        Some(Finding::flag(
            Severity::Note,
            "deleted-executable",
            format!("pid {pid} ({})", p.comm),
            format!(
                "running this agent's own image from a sealed memfd: {}",
                p.exe.as_deref().unwrap_or_default()
            ),
            "a HEMOSTAT sentinel starts, and relaunches the agent, with fexecve on a sealed \
             memfd, so the link reads as deleted. This image is byte-identical to the binary \
             running this sweep — compared by content, because the memfd's name is its \
             creator's choice. A sweep by a different HEMOSTAT build cannot match it, and \
             reports the Critical instead",
        ))
    } else if p.exe_deleted && p.kernel_helper {
        Some(Finding::flag(
            Severity::Note,
            "deleted-executable",
            format!("pid {pid} ({})", p.comm),
            format!(
                "the kernel's own bpfilter helper, running the image the bpfilter module embeds: {}",
                p.exe.as_deref().unwrap_or_default()
            ),
            format!(
                "the bpfilter module writes its helper into a tmpfs it mounts for itself and starts it, so the \
                 exe link names a file no mount reaches, which reads as deleted. Recognised on facts a shell \
                 cannot set: its parent, pid {}, is a kernel thread; it runs as root with nothing preloaded and no \
                 tracer; its whole map is that one image, on a filesystem with no disk under it, and at most the \
                 host's C library and loader; and it is the only process that shows all of that. Anything else \
                 named {BPFILTER_UMH}, or a second one, is the Critical. `rmmod bpfilter` stops it where nothing \
                 uses it",
                p.ppid
            ),
        ))
    } else if p.exe_deleted {
        Some(Finding::flag(
            Severity::Critical,
            "deleted-executable",
            format!("pid {pid} ({})", p.comm),
            format!("running from a deleted file: {}", p.exe.clone().unwrap_or_default()),
            "the program is running and nothing is left at its path, so there is nothing \
             on disk to examine or hash. Copy-exec-unlink is the standard way to run \
             without leaving an artefact",
        ))
    } else {
        None
    }
}

fn exited(pid: u32, own_proc: bool) -> bool {
    let Ok(pid) = libc::pid_t::try_from(pid) else { return false };
    if !own_proc || pid <= 0 {
        return false;
    }

    let rc = unsafe { libc::kill(pid, 0) };
    rc == -1 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH)
}

fn proc_is_ours() -> bool {
    fs::read_link("/proc/self")
        .ok()
        .and_then(|l| l.to_str().and_then(|s| s.parse::<u32>().ok()))
        == Some(std::process::id())
}

pub fn report() -> Report {
    let mut r = Report::default();
    let Ok(dir) = fs::read_dir("/proc") else {
        return r;
    };

    let mut pids: Vec<u32> = dir
        .flatten()
        .filter_map(|e| e.file_name().to_str().and_then(|n| n.parse::<u32>().ok()))
        .collect();
    pids.sort_unstable();

    let mut preload_groups: BTreeMap<String, Vec<u32>> = BTreeMap::new();

    let mut our_image: Option<Option<(u64, [u8; 32])>> = None;

    let mut vouch: Option<Vouch> = None;

    let mut helpers: Vec<u32> = Vec::new();

    let (mut mounted_listed, mut mounted_total): (Vec<String>, usize) = (Vec::new(), 0);

    let mut cmdline_budget = crate::procfs::MAX_WALK_CMDLINE_BYTES;

    let own_proc = proc_is_ours();
    for pid in pids {
        let read = read_process(pid);
        let whole = read
            .as_ref()
            .is_some_and(|p| p.kernel_thread || (p.env_readable && p.maps_readable));
        r.tally(read.as_ref(), !whole && exited(pid, own_proc));
        let Some(mut p) = read else {
            continue;
        };
        if p.exe_deleted && p.exe.as_deref().is_some_and(|e| e.starts_with("/memfd:")) {
            let ours = our_image
                .get_or_insert_with(|| crate::saferead::image_id(Path::new("/proc/self/exe")));
            p.runs_our_image = ours
                .as_ref()
                .is_some_and(|o| crate::saferead::is_image(Path::new(&format!("/proc/{pid}/exe")), o));
        }

        let helper = p.exe_deleted
            && p.comm == BPFILTER_UMH
            && kernel_helper_facts(&p, is_kernel_thread_pid(p.ppid));
        if ffi_shaped(&p) {
            p.ffi_vouched = ffi_vouched(&p, vouch.get_or_insert_with(Vouch::new));
        }
        if !p.mounted_over.is_empty() {
            mounted_total += 1;
            if mounted_listed.len() < MAX_NAMES_LISTED {
                mounted_listed.push(format!("pid {pid} ({}): {}", p.comm, p.mounted_over.join(", ")));
            }
        }

        if let Some(lib) = &p.ld_preload {
            preload_groups.entry(lib.clone()).or_default().push(pid);
        }
        if let Some(lib) = &p.ld_audit {
            r.findings.push(Finding::flag(
                Severity::Critical,
                "ld-audit",
                format!("pid {pid} ({})", p.comm),
                format!("LD_AUDIT={lib}"),
                "the audit interface hooks the dynamic linker itself, earlier and more \
                 completely than LD_PRELOAD, and almost nothing uses it legitimately",
            ));
        }
        if helper {
            helpers.push(pid);
        } else {
            r.findings.extend(exe_finding(&p));
        }
        r.findings.extend(oversized_map_finding(&p));
        if let Some(t) = p.tracer {
            r.findings.push(Finding::flag(
                Severity::Warn,
                "ptrace",
                format!("pid {pid} ({})", p.comm),
                format!("is being traced by pid {t}"),
                "ptrace gives the tracer full control of this process's memory and \
                 registers. A debugger looks identical to an injector; identify the \
                 tracer",
            ));
        }
        mapped_code_findings(&p, &mut r.findings);

        if p.interesting() {
            crate::procfs::charge_cmdline(&mut cmdline_budget, &mut p.cmdline);
            r.processes.push(p);
        }
    }

    r.findings.extend(helper_findings(&mut r.processes, &helpers));
    r.findings.extend(mounted_over_finding(&mounted_listed, mounted_total));

    for (lib, pids) in preload_groups {
        let sample: Vec<String> = pids.iter().take(6).map(u32::to_string).collect();
        r.findings.push(Finding::flag(
            Severity::Warn,
            "ld-preload",
            format!("{} process(es): {}", pids.len(), sample.join(", ")),
            format!("LD_PRELOAD={lib}"),
            "a library forced into a process intercepts libc for it. Some sandboxed \
             desktop applications do this legitimately; on a server it is how a userland \
             rootkit stays resident. Identify the library",
        ));
    }

    let elevated = crate::kernposture::euid() == Some(0);
    if let Some(f) = env_coverage_finding(r.examined, r.env_unreadable, elevated) {
        r.findings.push(f);
    }
    if let Some(f) = maps_coverage_finding(r.examined, r.maps_unreadable, r.maps_capped, elevated) {
        r.findings.push(f);
    }

    rank(&mut r.findings);
    r
}
