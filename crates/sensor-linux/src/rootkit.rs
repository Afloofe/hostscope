use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

const GOOFKIT_MAGIC: &str = "E1e37";

const GOOFKIT_HIDE_SIG: i32 = 62;

const GOOFKIT_ESC_SIG: i32 = 63;

fn goofkit_magic() -> String {
    std::env::var("HEMOSTAT_GOOFKIT_MAGIC")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| GOOFKIT_MAGIC.to_string())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {

    pub severity: Severity,

    pub subject: String,

    pub what: String,

    pub why: String,
}

pub use hs_core::severity::Severity;

#[derive(Debug, Clone, Default)]
pub struct Report {

    pub findings: Vec<Finding>,

    pub hidden_pids: Vec<u32>,

    pub cross_view_ran: bool,

    pub goofkit_getdents_hook: Option<bool>,

    pub did_not_run: Vec<String>,
}

pub(crate) fn pids_via_readdir() -> Option<BTreeSet<u32>> {
    let mut out = BTreeSet::new();
    for entry in fs::read_dir("/proc").ok()? {
        let entry = entry.ok()?;
        if let Some(pid) = entry.file_name().to_str().and_then(|n| n.parse::<u32>().ok()) {
            out.insert(pid);
        }
    }
    Some(out)
}

fn pid_max() -> u32 {
    crate::saferead::read_kernel_text("/proc/sys/kernel/pid_max")
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(32768)
}

fn is_hidden_leader_candidate(pid: u32) -> bool {

    let Ok(status) = crate::saferead::read_pid_text(format!("/proc/{pid}/status")) else {

        return false;
    };
    status
        .lines()
        .find_map(|l| l.strip_prefix("Tgid:"))
        .and_then(|v| v.trim().parse::<u32>().ok())
        == Some(pid)
}

fn hidden_pids(listed: &BTreeSet<u32>, cap: u32) -> Vec<u32> {
    let mut hidden = Vec::new();
    for pid in 1..=cap {
        if listed.contains(&pid) {
            continue;
        }

        if is_hidden_leader_candidate(pid) {
            hidden.push(pid);
        }
    }
    hidden
}

fn parse_preload(text: &str) -> Vec<String> {

    text.lines()
        .map(|line| line.split('#').next().unwrap_or("").trim())
        .flat_map(|body| body.split_whitespace())
        .filter(|tok| !tok.is_empty())
        .map(str::to_string)
        .collect()
}

fn preload_in_environ(environ: &[u8]) -> Option<String> {
    crate::hooked::env_var(environ, "LD_PRELOAD")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GoofkitProbe {

    Clean,

    HookDetected,

    CouldNotRun,
}

fn goofkit_probe_verdict(by_stat: bool, listed: Option<bool>) -> GoofkitProbe {
    match (by_stat, listed) {
        (true, Some(false)) => GoofkitProbe::HookDetected,
        (_, None) => GoofkitProbe::CouldNotRun,
        _ => GoofkitProbe::Clean,
    }
}

fn run_goofkit_probe(magic: &str) -> GoofkitProbe {
    use std::io::Write as _;

    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let name = format!("{magic}-hemostat-probe-{}-{nonce}", std::process::id());

    for dir in [std::env::temp_dir(), PathBuf::from("/dev/shm")] {
        let path = dir.join(&name);
        let Ok(mut f) = fs::File::create(&path) else {
            continue;
        };
        let _ = f.write_all(b"hemostat goofkit getdents probe\n");
        drop(f);

        let by_stat = fs::symlink_metadata(&path).is_ok();

        let listed = dir_lists_name(&dir, &name);

        let _ = fs::remove_file(&path);
        return goofkit_probe_verdict(by_stat, listed);
    }
    GoofkitProbe::CouldNotRun
}

fn dir_lists_name(dir: &Path, name: &str) -> Option<bool> {
    let rd = fs::read_dir(dir).ok()?;
    Some(rd.flatten().any(|e| e.file_name().to_string_lossy() == name))
}

fn goofkit_finding(outcome: GoofkitProbe, magic: &str) -> Finding {

    let src = if magic == GOOFKIT_MAGIC { "published" } else { "operator-supplied" };
    match outcome {
        GoofkitProbe::HookDetected => Finding {
            severity: Severity::Critical,
            subject: "goofkit getdents hook".into(),
            what: format!(
                "a file whose name contains goofkit's magic string {magic:?} was \
                 created and confirmed present by stat, then filtered out of a directory read"
            ),
            why: format!(
                "goofkit (RITRedteam) hooks getdents inline and hides any entry whose name \
                 contains its magic string ({src}: {magic:?}, strstr); an entry present to stat \
                 but absent from the listing is that hook executing. Its control channel is \
                 `kill -{GOOFKIT_HIDE_SIG} <pid>` to toggle a process's hidden flag and `kill \
                 -{GOOFKIT_ESC_SIG} <pid>` to escalate to root. It patches syscall prologues, \
                 not the syscall table, so a table-integrity check will not see it — this \
                 probe does"
            ),
        },
        GoofkitProbe::Clean => Finding {
            severity: Severity::Note,
            subject: "goofkit getdents probe".into(),
            what: format!(
                "a file named with goofkit's magic string ({src}: {magic:?}) was created and \
                 appeared normally in a directory read"
            ),
            why: format!(
                "the getdents hook goofkit keys on {magic:?} is not loaded — but this is a \
                 signature test, and the string came from a source the operator flagged as \
                 possibly poisoned, so treat a clean result as weaker than the method-based \
                 process cross-view above. If a captured sample uses a different string, set \
                 $HEMOSTAT_GOOFKIT_MAGIC and re-run. A process hidden by `kill \
                 -{GOOFKIT_HIDE_SIG}` is still caught by the cross-view regardless"
            ),
        },
        GoofkitProbe::CouldNotRun => Finding {
            severity: Severity::Warn,
            subject: "goofkit getdents probe".into(),
            what: "no writable directory (tried the temp dir and /dev/shm), so the \
                   magic-string probe did not run"
                .into(),
            why: "the active probe creates one short-lived file to see whether a getdents \
                  hook hides it; without a writable directory it cannot, and a probe that did \
                  not run is not a clean result"
                .into(),
        },
    }
}

pub fn report() -> Report {
    let mut findings = Vec::new();
    let mut did_not_run = Vec::new();

    check_ld_so_preload(&mut findings);
    check_ld_preload_env(&mut findings);
    let (hidden, cross_view_ran) = check_hidden_processes(&mut findings);
    let goofkit_getdents_hook = check_goofkit_probe(&mut findings);
    if goofkit_getdents_hook.is_none() {
        did_not_run.push("goofkit getdents probe: no writable directory".to_string());
    }
    did_not_run.extend(check_service_hooking(&mut findings));
    did_not_run.extend(check_kernel_text(&mut findings));
    did_not_run.extend(check_ftrace_hooks(&mut findings));
    did_not_run.extend(check_hidden_modules(&mut findings));
    did_not_run.extend(check_kprobe_hooks(&mut findings));
    did_not_run.extend(check_userland_cross_views(&mut findings));
    did_not_run.extend(check_ebpf_programs(&mut findings));

    findings.sort_by_key(|f| std::cmp::Reverse(f.severity));
    Report { findings, hidden_pids: hidden, cross_view_ran, goofkit_getdents_hook, did_not_run }
}

fn check_ld_so_preload(findings: &mut Vec<Finding>) {

    let path = std::path::Path::new("/etc/ld.so.preload");

    if fs::symlink_metadata(path).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound) {
        return;
    }
    let Some((text, truncated)) = crate::saferead::read_scan_target_bounded(path) else {
        findings.push(Finding {
            severity: Severity::Warn,
            subject: "/etc/ld.so.preload".into(),
            what: "exists and could not be read".into(),
            why: "a global preload in it would be invisible to this check. It is normally absent \
                  on a server; one that is present and unreadable is worth a look by hand"
                .into(),
        });
        return;
    };
    if truncated {
        findings.push(Finding {
            severity: Severity::Warn,
            subject: "/etc/ld.so.preload".into(),
            what: "read only in part — it is larger than the read cap".into(),
            why: "entries past the cap were not examined; no legitimate preload file is this size"
                .into(),
        });
    }
    {
        for lib in parse_preload(&text) {
            findings.push(Finding {
                severity: Severity::Critical,
                subject: "/etc/ld.so.preload".into(),
                what: format!("forces every dynamically-linked process to load {lib}"),
                why: "a global LD_PRELOAD is the install point for a userland rootkit \
                      (the IRSeC red team's `Father` lives here); it is normally absent on \
                      a server, so any entry is presumed hostile until explained".into(),
            });
        }
    }
}

fn check_ld_preload_env(findings: &mut Vec<Finding>) {
    if let Ok(dir) = fs::read_dir("/proc") {
        let mut by_lib: BTreeMap<String, Vec<u32>> = BTreeMap::new();

        let (mut examined, mut unread, mut partial) = (0usize, 0usize, 0usize);
        for entry in dir.flatten() {
            let Some(pid) = entry.file_name().to_str().and_then(|n| n.parse::<u32>().ok()) else {
                continue;
            };
            examined += 1;
            match crate::saferead::read_proc(
                std::path::Path::new(&format!("/proc/{pid}/environ")),
                crate::saferead::MAX_PROC_BYTES,
            ) {
                Ok((environ, truncated)) => {
                    partial += usize::from(truncated);
                    if let Some(lib) = preload_in_environ(&environ) {
                        by_lib.entry(lib).or_default().push(pid);
                    }
                }

                Err(e) if e.kind() == std::io::ErrorKind::NotFound => examined -= 1,
                Err(_) => unread += 1,
            }
        }
        if unread + partial > 0 {
            findings.push(Finding {
                severity: Severity::Note,
                subject: "LD_PRELOAD environ coverage".into(),
                what: format!(
                    "read the environment of {} of {examined} process(es); {unread} refused, \
                     {partial} larger than the read cap and examined only in part",
                    examined.saturating_sub(unread)
                ),
                why: "an environment that could not be read is not one without LD_PRELOAD in it. \
                      /proc/<pid>/environ is readable only by the owner and root, so re-run \
                      elevated to check the rest"
                    .into(),
            });
        }
        for (lib, pids) in by_lib {
            let sample = pids.iter().take(8).map(u32::to_string).collect::<Vec<_>>().join(", ");
            let more = if pids.len() > 8 {
                format!(" (+{} more)", pids.len() - 8)
            } else {
                String::new()
            };
            findings.push(Finding {
                severity: Severity::Warn,
                subject: format!("LD_PRELOAD {lib}"),
                what: format!(
                    "forced into {} live process(es): {sample}{more}",
                    pids.len()
                ),
                why: "a lead, not a verdict: some sandboxed desktop apps preload legitimately, \
                      but on a server LD_PRELOAD in a live process is how a userland rootkit \
                      (e.g. the red team's `Father`) stays resident — run the library down"
                    .into(),
            });
        }
    }
}

fn check_hidden_processes(findings: &mut Vec<Finding>) -> (Vec<u32>, bool) {
    let mut hidden = Vec::new();
    let cross_view_ran = if let Some(before) = pids_via_readdir() {

        let cap = pid_max().min(500_000);
        let found = hidden_pids(&before, cap);

        let after = pids_via_readdir().unwrap_or_default();
        hidden = found
            .into_iter()
            .filter(|pid| !after.contains(pid))

            .filter(|pid| is_hidden_leader_candidate(*pid))
            .collect();
        if hidden.is_empty() {
            findings.push(Finding {
                severity: Severity::Note,
                subject: "process cross-view".into(),
                what: format!(
                    "no PID up to {cap} answered stat while hidden from the /proc listing"
                ),
                why: "the userspace check for a getdents-hiding kernel rootkit found nothing; \
                      it cannot see a process hidden from stat as well, which needs the kernel \
                      module".into(),
            });
        } else {
            findings.push(Finding {
                severity: Severity::Critical,
                subject: "process cross-view".into(),
                what: format!(
                    "{} PID(s) present via stat but hidden from the /proc listing: {}",
                    hidden.len(),
                    hidden.iter().take(12).map(u32::to_string).collect::<Vec<_>>().join(", ")
                ),
                why: "the /proc directory read and a direct stat disagree, which is what a \
                      kernel rootkit hooking getdents produces (the red team's `goofkit`); a \
                      process the kernel is actively hiding is running".into(),
            });
        }
        true
    } else {
        findings.push(Finding {
            severity: Severity::Warn,
            subject: "process cross-view".into(),
            what: "/proc could not be listed, so the hidden-process check did not run".into(),
            why: "without /proc this reader cannot compare views; is /proc mounted?".into(),
        });
        false
    };
    (hidden, cross_view_ran)
}

fn check_goofkit_probe(findings: &mut Vec<Finding>) -> Option<bool> {
    let magic = goofkit_magic();
    let goofkit = run_goofkit_probe(&magic);
    findings.push(goofkit_finding(goofkit, &magic));
    match goofkit {
        GoofkitProbe::HookDetected => Some(true),
        GoofkitProbe::Clean => Some(false),
        GoofkitProbe::CouldNotRun => None,
    }
}

fn check_service_hooking(findings: &mut Vec<Finding>) -> Option<String> {
    let mut unreadable_services: Vec<String> = Vec::new();
    let mut cut_services: Vec<String> = Vec::new();
    for (pid, name) in service_pids(&["sshd", "systemd", "cron", "crond", "auditd", "dbus-daemon"]) {
        let Some(mapped) = injected_libraries(pid) else {
            unreadable_services.push(format!("{name} (pid {pid})"));
            continue;
        };
        if mapped.truncated {
            cut_services.push(format!("{name} (pid {pid})"));
        }
        service_findings(&name, pid, mapped, findings);
    }

    if !unreadable_services.is_empty() {
        findings.push(Finding {
            severity: Severity::Note,
            subject: "service hooking".into(),
            what: format!(
                "the memory maps of {} could NOT be read, so {} not checked for injected \
                 libraries",
                unreadable_services.join(", "),
                if unreadable_services.len() == 1 { "it was" } else { "they were" }
            ),
            why: "reading another process's map needs privilege it did not have here. This is \
                  the check that catches a userland rootkit inside a live service, so a clean \
                  result from this sweep says nothing about the services listed — re-run as \
                  root"
                .into(),
        });
    }
    cut_services_gap(&cut_services)
}

fn service_findings(name: &str, pid: u32, mapped: Mapped, findings: &mut Vec<Finding>) {
    if mapped.truncated {
        findings.push(oversized_service_map(name, pid));
    }
    let listed = mapped.libs.len();
    for lib in mapped.libs {
        findings.push(Finding {
            severity: Severity::Critical,
            subject: format!("{name} (pid {pid})"),
            what: format!("has {lib} mapped executable — outside any package path"),
            why: "a library loaded into a live service from a world-writable or non-package location is how a userland rootkit hooks that service from inside it; trusted services are exactly where an attacker wants to be".into(),
        });
    }

    let unlisted = mapped.total.saturating_sub(listed);
    if unlisted > 0 {
        findings.push(Finding {
            severity: Severity::Critical,
            subject: format!("{name} (pid {pid})"),
            what: format!(
                "has {} distinct files mapped executable outside any package path; the first \
                 {listed} are listed, {unlisted} more are not",
                mapped.total
            ),
            why: format!(
                "every one is a library in a live service from outside a package path, and no \
                 service maps that many. `grep -E ' ..x[ps] ' /proc/{pid}/maps` lists every \
                 executable mapping"
            ),
        });
    }
}

fn cut_services_gap(cut: &[String]) -> Option<String> {
    if cut.is_empty() {
        return None;
    }
    Some(format!(
        "service hooking: the memory map of {} is over the {} MiB read cap and was checked \
         for injected libraries only in part",
        cut.join(", "),
        crate::saferead::MAX_MAPS_BYTES / (1024 * 1024)
    ))
}

fn oversized_service_map(name: &str, pid: u32) -> Finding {
    let cap = crate::saferead::MAX_MAPS_BYTES / (1024 * 1024);
    Finding {
        severity: Severity::Warn,
        subject: format!("{name} (pid {pid})"),
        what: format!(
            "memory map is over the {cap} MiB read cap, so it was checked for injected \
             libraries only in part"
        ),
        why: format!(
            "{cap} MiB is 262,144 mappings at 256 bytes a line, far past anything this service \
             maps; a library mapped beyond the part read was not examined, and padding the map \
             is a way to put one there. Look by hand: `grep -E ' ..x[ps] ' /proc/{pid}/maps` \
             lists every executable mapping"
        ),
    }
}

fn check_kernel_text(findings: &mut Vec<Finding>) -> Option<String> {
    let kt = crate::syscallhook::report();
    if kt.available {
        let had = kt.findings.len();
        findings.extend(kt.findings);
        if had == 0 {
            findings.push(Finding {
                severity: Severity::Note,
                subject: "kernel-text integrity".into(),
                what: format!(
                    "{} syscall prologues and {} syscall-table entries read from /proc/kcore \
                     show no inline hook or table redirection",
                    kt.functions_checked, kt.table_entries_checked
                ),
                why: "read at the kernel's own level, so unlike every check above it needs no \
                      magic string and is not blinded by a rootkit that also hooks stat — but it \
                      sees only direct text patching (the goofkit class), not ftrace/BPF hooks"
                    .into(),
            });
        }
    } else {
        let why = kt.reason.unwrap_or_else(|| "unavailable".into());
        findings.push(Finding {
            severity: Severity::Note,
            subject: "kernel-text integrity".into(),
            what: "the kernel-text scan did not run".into(),
            why: why.clone(),
        });
        return Some(format!("kernel-text scan: {why}"));
    }
    None
}

fn check_ftrace_hooks(findings: &mut Vec<Finding>) -> Option<String> {
    let ft = crate::ftracehook::report();
    if ft.available {
        let had = ft.findings.len();
        findings.extend(ft.findings);
        if had == 0 {
            findings.push(Finding {
                severity: Severity::Note,
                subject: "ftrace hooks".into(),
                what: format!(
                    "{} function(s) currently ftrace-traced, {} of them watched syscalls, none \
                     dispatching into a module or outside kernel text",
                    ft.traced_functions, ft.watched_traced
                ),
                why: "the companion to the inline scan: an ftrace-based syscall hook leaves the \
                      prologue clean, so it is caught here or not at all — it was not found"
                    .into(),
            });
        }
    } else {
        let why = ft.reason.unwrap_or_else(|| "unavailable".into());
        findings.push(Finding {
            severity: Severity::Note,
            subject: "ftrace hooks".into(),
            what: "the ftrace-hook scan did not run".into(),
            why: why.clone(),
        });
        return Some(format!("ftrace-hook scan: {why}"));
    }
    None
}

fn check_hidden_modules(findings: &mut Vec<Finding>) -> Option<String> {
    let km = crate::kmod::report();
    if km.available {
        let had = km.findings.len();
        findings.extend(km.findings);
        if had == 0 {
            findings.push(Finding {
                severity: Severity::Note,
                subject: "module cross-view".into(),
                what: format!(
                    "{} modules in /proc/modules reconcile with {} in /sys/module and {} \
                     kallsyms-tagged; none is hidden",
                    km.proc_count, km.sysfs_count, km.tagged_count
                ),
                why: "a module present in /sys/module or the kallsyms tags but missing from \
                      /proc/modules would be one that unlinked itself from lsmod; none was. A \
                      module hidden from all three needs the kcore module-list walk"
                    .into(),
            });
        }
    } else {
        let why = km.reason.unwrap_or_else(|| "unavailable".into());
        findings.push(Finding {
            severity: Severity::Note,
            subject: "module cross-view".into(),
            what: "the module cross-view did not run".into(),
            why: why.clone(),
        });
        return Some(format!("module cross-view: {why}"));
    }
    None
}

fn check_kprobe_hooks(findings: &mut Vec<Finding>) -> Option<String> {
    let kpr = crate::kprobe::report();
    if kpr.available {
        let had = kpr.findings.len();
        findings.extend(kpr.findings);
        if had == 0 {
            findings.push(Finding {
                severity: Severity::Note,
                subject: "kprobe enumeration".into(),
                what: format!(
                    "{} kprobe(s)/kretprobe(s) registered; none sits on a syscall entry point, \
                     kallsyms_lookup_name, a filldir/seq_show hiding callback, an LSM security_* \
                     hook or an ip_rcv backdoor path",
                    kpr.kprobe_count
                ),
                why: "the kernel's kprobe registry was read and no probe lands on a symbol a \
                      rootkit hooks via kprobes — the register_kprobe-based hook the kernel-text \
                      and ftrace scans cannot see was not found. A rootkit already resident could \
                      hide its own kprobe from this list, which needs HEMOSTAT's kernel module to \
                      rule out"
                    .into(),
            });
        }
    } else {
        let why = kpr.reason.unwrap_or_else(|| "unavailable".into());
        findings.push(Finding {
            severity: Severity::Note,
            subject: "kprobe enumeration".into(),
            what: "the kprobe enumeration did not run".into(),
            why: why.clone(),
        });
        return Some(format!("kprobe enumeration: {why}"));
    }
    None
}

fn check_userland_cross_views(findings: &mut Vec<Finding>) -> Option<String> {
    let cv = crate::crossview::report();
    if cv.available {
        let had = cv.findings.len();
        findings.extend(cv.findings);
        if had == 0 {
            findings.push(Finding {
                severity: Severity::Note,
                subject: "userland cross-views".into(),
                what: format!(
                    "no raw/AF_PACKET socket and no io_uring holder; the kernel's thread count \
                     ({}) matched the {} task(s) a /proc walk enumerated",
                    cv.loadavg_total.map_or_else(|| "?".into(), |t| t.to_string()),
                    cv.tasks_seen
                ),
                why: "the cheap /proc cross-views found no hidden-task gap, no off-syscall I/O \
                      channel, and no unenumerated socket family — seams the tcp/udp socket view \
                      and the process cross-view do not cover; a kernel that also lies to these \
                      /proc files would need the kernel-level view".into(),
            });
        }
    } else {
        let why = cv.reason.unwrap_or_else(|| "unavailable".into());
        findings.push(Finding {
            severity: Severity::Note,
            subject: "userland cross-views".into(),
            what: "the userland cross-views did not run".into(),
            why: why.clone(),
        });
        return Some(format!("userland cross-views: {why}"));
    }
    None
}

fn check_ebpf_programs(findings: &mut Vec<Finding>) -> Option<String> {
    let bp = crate::bpfprog::report();

    findings.extend(bp.findings);

    if !bp.available {
        Some(format!("eBPF program census: {}", bp.reason.unwrap_or_else(|| "unavailable".into())))
    } else if bp.census_incomplete {
        Some("eBPF program census: refused part-way or short of what the kernel named, so it \
              is a floor, not a list"
            .into())
    } else {
        None
    }
}

fn service_pids(names: &[&str]) -> Vec<(u32, String)> {
    let mut out = Vec::new();
    let Ok(dir) = std::fs::read_dir("/proc") else { return out };
    for entry in dir.flatten() {
        let Some(pid) = entry.file_name().to_str().and_then(|n| n.parse::<u32>().ok()) else {
            continue;
        };
        if let Ok(comm) = crate::saferead::read_pid_text(format!("/proc/{pid}/comm")) {
            let comm = comm.trim();
            if let Some(name) = names.iter().find(|n| **n == comm) {
                out.push((pid, (*name).to_string()));
            }
        }
    }
    out
}

const TRUSTED_LIB_DIRS: &[&str] = &[
    "/lib/", "/lib64/", "/usr/lib/", "/usr/lib64/", "/usr/local/lib/",

    "/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/",
];

fn map_path(line: &str) -> Option<(&str, bool)> {
    let mut rest = line;
    for _ in 0..5 {
        rest = rest.trim_start();
        let end = rest.find(char::is_whitespace)?;
        rest = rest.get(end..)?;
    }
    let path = rest.trim();
    if !path.starts_with('/') {
        return None;
    }
    match path.strip_suffix(" (deleted)") {
        Some(p) => Some((p, true)),
        None => Some((path, false)),
    }
}

fn injected_libraries(pid: u32) -> Option<Mapped> {
    injected_libraries_at(Path::new(&format!("/proc/{pid}/maps")), crate::saferead::MAX_MAPS_BYTES)
}

#[derive(Debug, Default, PartialEq, Eq)]
struct Mapped {

    libs: Vec<String>,

    total: usize,

    truncated: bool,
}

fn injected_libraries_at(maps: &Path, cap: u64) -> Option<Mapped> {

    let (maps, truncated) = crate::saferead::read_kernel_text_capped(maps, cap).ok()?;
    let mut hits = Vec::new();
    let mut seen = HashSet::new();
    let mut total = 0;
    for line in maps.lines() {
        let Some(perms) = line.split_whitespace().nth(1) else { continue };
        if !perms.contains('x') {
            continue;
        }
        let Some((path, deleted)) = map_path(line) else {
            continue;
        };
        let trusted = TRUSTED_LIB_DIRS.iter().any(|d| path.starts_with(d));
        if !trusted {

            if seen.insert((path, deleted)) {
                total += 1;
                if hits.len() < crate::hooked::MAX_NAMES_LISTED {
                    hits.push(if deleted { format!("{path} (deleted from disk)") } else { path.to_string() });
                }
            }
        }
    }
    Some(Mapped { libs: hits, total, truncated })
}
