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
    }
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
}

impl Report {

    fn account(&mut self, p: &Process) {
        self.anon_exec_total += p.anon_exec;
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

pub fn env_var(environ: &[u8], key: &str) -> Option<String> {
    let mut prefix = key.as_bytes().to_vec();
    prefix.push(b'=');
    environ
        .rsplit(|b| *b == 0)
        .find_map(|kv| kv.strip_prefix(prefix.as_slice()))
        .map(|v| String::from_utf8_lossy(v).into_owned())
}

pub fn parse_map_line(line: &str) -> Option<(bool, Option<&str>)> {
    let mut fields = line.splitn(6, char::is_whitespace).filter(|f| !f.is_empty());
    let _addr = fields.next()?;
    let perms = fields.next()?;
    let executable = perms.contains('x');
    let path = fields.nth(3).map(str::trim).filter(|p| !p.is_empty());
    Some((executable, path))
}

#[derive(Debug, Default, PartialEq, Eq)]
struct MappedCode {
    unexpected_libs: Vec<String>,
    unexpected_libs_total: usize,
    anon_exec: usize,
    memfd_exec: usize,
    memfd_names: Vec<String>,
    memfd_names_total: usize,
}

fn mapped_code(maps: &str, exe: Option<&str>) -> MappedCode {
    let mut code = MappedCode::default();
    let mut seen_memfds: HashSet<&str> = HashSet::new();
    let mut seen_libs: HashSet<&str> = HashSet::new();
    for line in maps.lines() {
        let Some((executable, path)) = parse_map_line(line) else { continue };
        if !executable {
            continue;
        }

        let is_own_image = |p: &str| {
            exe.is_some_and(|e| e == p || e.trim_end_matches(" (deleted)") == p)
        };
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
    if p.memfd_exec > 0 {
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

fn read_maps(path: &Path, cap: u64, exe: Option<&str>) -> (bool, bool, MappedCode) {
    match crate::saferead::read_kernel_text_capped(path, cap) {
        Ok((maps, truncated)) => (!truncated, truncated, mapped_code(&maps, exe)),
        Err(_) => (false, false, MappedCode::default()),
    }
}

fn read_process(pid: u32) -> Option<Process> {
    let base = PathBuf::from(format!("/proc/{pid}"));

    let status = crate::saferead::read_kernel_text(base.join("status")).ok()?;
    let kernel_thread = crate::saferead::read_kernel_text(base.join("stat"))
        .is_ok_and(|stat| is_kernel_thread(&stat));

    let comm = crate::saferead::read_kernel_text(base.join("comm"))
        .map(|s| s.trim().to_string())
        .unwrap_or_default();

    let cmdline = crate::saferead::read_proc(&base.join("cmdline"), crate::saferead::MAX_PROC_BYTES)
        .map(|(b, _)| {
            String::from_utf8_lossy(&b)
                .replace('\0', " ")
                .trim()
                .to_string()
        })
        .unwrap_or_default();

    let environ = crate::saferead::read_proc(&base.join("environ"), crate::saferead::MAX_PROC_BYTES).ok();
    let env_readable = environ.as_ref().is_some_and(|(_, truncated)| !truncated);
    let environ = environ.map(|(e, _)| e).unwrap_or_default();
    let ld_preload = env_var(&environ, "LD_PRELOAD");
    let ld_audit = env_var(&environ, "LD_AUDIT");

    let link = fs::read_link(base.join("exe")).ok();
    let exe = link.as_ref().map(|p| p.display().to_string());

    let exe_deleted = exe.as_deref().is_some_and(|e| e.ends_with(" (deleted)"))
        || (shares_our_mount_ns(&base) && link.as_ref().is_some_and(|p| !p.exists()));

    let exe_replaced = exe_deleted && exe_path_refilled(pid, exe.as_deref());

    let (maps_readable, maps_truncated, code) =
        read_maps(&base.join("maps"), crate::saferead::MAX_MAPS_BYTES, exe.as_deref());

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
    })
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
        r.findings.extend(exe_finding(&p));
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
            r.processes.push(p);
        }
    }

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
