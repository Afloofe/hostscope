use std::fs;
use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};

use crate::rootkit::{Finding, Severity};

const BPF_PROG_GET_NEXT_ID: i32 = 11;
const BPF_PROG_GET_FD_BY_ID: i32 = 13;
const BPF_OBJ_GET_INFO_BY_FD: i32 = 15;

mod prog_type {
    pub(crate) const SOCKET_FILTER: u32 = 1;
    pub(crate) const KPROBE: u32 = 2;
    pub(crate) const SCHED_CLS: u32 = 3;
    pub(crate) const SCHED_ACT: u32 = 4;
    pub(crate) const TRACEPOINT: u32 = 5;
    pub(crate) const XDP: u32 = 6;
    pub(crate) const PERF_EVENT: u32 = 7;
    pub(crate) const CGROUP_SKB: u32 = 8;
    pub(crate) const CGROUP_SOCK: u32 = 9;
    pub(crate) const SOCK_OPS: u32 = 13;
    pub(crate) const SK_SKB: u32 = 14;
    pub(crate) const CGROUP_DEVICE: u32 = 15;
    pub(crate) const SK_MSG: u32 = 16;
    pub(crate) const RAW_TRACEPOINT: u32 = 17;
    pub(crate) const CGROUP_SOCK_ADDR: u32 = 18;
    pub(crate) const RAW_TRACEPOINT_WRITABLE: u32 = 24;
    pub(crate) const CGROUP_SOCKOPT: u32 = 25;
    pub(crate) const TRACING: u32 = 26;
    pub(crate) const STRUCT_OPS: u32 = 27;
    pub(crate) const EXT: u32 = 28;
    pub(crate) const LSM: u32 = 29;
    pub(crate) const SK_LOOKUP: u32 = 30;
    pub(crate) const SYSCALL: u32 = 31;
    pub(crate) const NETFILTER: u32 = 32;
}

fn prog_type_name(t: u32) -> &'static str {
    use prog_type::*;
    match t {
        0 => "unspec",
        SOCKET_FILTER => "socket_filter",
        KPROBE => "kprobe",
        SCHED_CLS => "sched_cls",
        SCHED_ACT => "sched_act",
        TRACEPOINT => "tracepoint",
        XDP => "xdp",
        PERF_EVENT => "perf_event",
        CGROUP_SKB => "cgroup_skb",
        CGROUP_SOCK => "cgroup_sock",
        10 => "lwt_in",
        11 => "lwt_out",
        12 => "lwt_xmit",
        SOCK_OPS => "sock_ops",
        SK_SKB => "sk_skb",
        CGROUP_DEVICE => "cgroup_device",
        SK_MSG => "sk_msg",
        RAW_TRACEPOINT => "raw_tracepoint",
        CGROUP_SOCK_ADDR => "cgroup_sock_addr",
        19 => "lwt_seg6local",
        20 => "lirc_mode2",
        21 => "sk_reuseport",
        22 => "flow_dissector",
        23 => "cgroup_sysctl",
        RAW_TRACEPOINT_WRITABLE => "raw_tracepoint.w",
        CGROUP_SOCKOPT => "cgroup_sockopt",
        TRACING => "tracing",
        STRUCT_OPS => "struct_ops",
        EXT => "ext",
        LSM => "lsm",
        SK_LOOKUP => "sk_lookup",
        SYSCALL => "syscall",
        NETFILTER => "netfilter",
        _ => "other",
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Class {

    Interception,

    Lsm,

    Network,

    Other,
}

fn classify(t: u32) -> Class {
    use prog_type::*;
    match t {
        LSM => Class::Lsm,
        KPROBE | TRACEPOINT | RAW_TRACEPOINT | RAW_TRACEPOINT_WRITABLE | TRACING | EXT
        | PERF_EVENT => Class::Interception,
        SOCKET_FILTER | SCHED_CLS | SCHED_ACT | XDP | SOCK_OPS | SK_SKB | SK_MSG
        | FLOW_DISSECTOR_ALIAS | SK_LOOKUP | NETFILTER | CGROUP_SKB | CGROUP_SOCK
        | CGROUP_SOCK_ADDR => Class::Network,
        _ => Class::Other,
    }
}

const FLOW_DISSECTOR_ALIAS: u32 = 22;

const SYSTEMD_LSM_PROGRAMS: &[&str] = &["restrict_filesy"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProgSummary {

    pub id: u32,

    pub prog_type: u32,

    pub name: String,

    pub created_by_uid: u32,

    pub held_by_init: bool,

    pub selfprotect_holder: Option<u32>,
}

#[derive(Debug, Clone, Default)]
pub struct Report {

    pub findings: Vec<Finding>,

    pub available: bool,

    pub reason: Option<String>,

    pub program_count: usize,

    pub interception_count: usize,

    pub lsm_count: usize,

    pub nonroot_count: usize,

    pub census_incomplete: bool,

    pub pins: Vec<String>,
}

fn census(programs: &[ProgSummary]) -> String {
    use std::collections::BTreeMap;
    let mut counts: BTreeMap<&'static str, usize> = BTreeMap::new();
    for p in programs {
        *counts.entry(prog_type_name(p.prog_type)).or_default() += 1;
    }
    counts
        .into_iter()
        .map(|(name, n)| format!("{n} {name}"))
        .collect::<Vec<_>>()
        .join(", ")
}

fn assess(programs: &[ProgSummary]) -> Vec<Finding> {
    let mut findings = Vec::new();

    findings.push(Finding {
        severity: Severity::Note,
        subject: "eBPF program census".into(),
        what: if programs.is_empty() {
            "no eBPF programs are loaded".into()
        } else {
            format!("{} eBPF program(s) loaded: {}", programs.len(), census(programs))
        },
        why: "the kernel's own program registry, read as `bpftool prog list` reads it. eBPF is \
              used heavily by legitimate software (systemd, containers, bpftrace, security \
              agents), so this census is context, not an alarm — the elevated findings below \
              pick out the classes worth running down"
            .into(),
    });

    let lsm_all: Vec<&ProgSummary> =
        programs.iter().filter(|p| classify(p.prog_type) == Class::Lsm).collect();
    let held_systemd = |p: &ProgSummary| p.held_by_init && SYSTEMD_LSM_PROGRAMS.contains(&p.name.as_str());
    let mut held_copies: std::collections::BTreeMap<&str, usize> = Default::default();
    for p in lsm_all.iter().filter(|p| held_systemd(p)) {
        *held_copies.entry(p.name.as_str()).or_default() += 1;
    }
    let (systemd, lsm): (Vec<&ProgSummary>, Vec<&ProgSummary>) = lsm_all
        .iter()
        .partition(|p| held_systemd(p) && held_copies.get(p.name.as_str()) == Some(&1));
    if !systemd.is_empty() {
        findings.push(Finding {
            severity: Severity::Note,
            subject: "BPF-LSM program(s) held by systemd".into(),
            what: format!(
                "{} BPF-LSM program(s) loaded and held by PID 1: {}",
                systemd.len(),
                name_list(&systemd)
            ),
            why: "systemd attaches `restrict_filesystems` (RestrictFileSystems=) at startup \
                  whenever bpf is an active LSM, whether or not any unit uses it, and PID 1 holds \
                  it for as long as it runs. That is attribution, not proof — a unit's file \
                  descriptor store can also hand PID 1 a descriptor — so a second copy of this \
                  name, held or not, or one PID 1 does not hold, is still the Warn"
                .into(),
        });
    }

    let (agent, lsm): (Vec<&ProgSummary>, Vec<&ProgSummary>) = lsm
        .into_iter()
        .partition(|p| p.name == crate::selfprotect::PROG_NAME && p.selfprotect_holder.is_some());
    if !agent.is_empty() {
        let mut held = agent
            .iter()
            .take(10)
            .map(|p| format!("id {} ({}) in pid {}", p.id, p.name, p.selfprotect_holder.unwrap_or_default()))
            .collect::<Vec<_>>()
            .join(", ");
        if agent.len() > 10 {
            held.push_str(&format!(", +{} more", agent.len() - 10));
        }
        findings.push(Finding {
            severity: Severity::Note,
            subject: "BPF-LSM program(s) held by `selfprotect --arm`".into(),
            what: format!(
                "{} BPF-LSM program(s) held by this agent's own `selfprotect --arm`: {held}",
                agent.len()
            ),
            why: "`selfprotect --arm` attaches `hemostat_deny`, a task_kill deny over its own \
                  pid, and holds it for as long as it runs. Attributed only to a process whose \
                  image is byte-identical to the binary running this sweep, started as \
                  `selfprotect --arm`, and holding one copy: a descriptor carried across exec \
                  into another verb, or a second copy beside its own, is still the Warn, and so \
                  is a deny armed by a different HEMOSTAT build. If you did not arm it, \
                  `kill -USR1 <pid>` lifts it"
                .into(),
        });
    }
    if !lsm.is_empty() {
        let mut why = String::from(
            "a BPF program of type lsm hooks the kernel's security_* checks — the primitive \
             an eBPF rootkit uses to grant privilege or hide access decisions. It is rare on \
             a general-purpose host (Ubuntu does not enable BPF-LSM by default). If no eBPF \
             security agent is deployed here, treat this as hostile until explained; pull it \
             with `bpftool prog dump xlated id <id>`",
        );
        if lsm.iter().any(|p| SYSTEMD_LSM_PROGRAMS.contains(&p.name.as_str())) {
            why.push_str(
                ". A program named like systemd's `restrict_filesy` is listed here because PID 1 \
                 does not hold it, or holds more than one copy of the name — systemd holds \
                 exactly one, so at most one of them is systemd's",
            );
        }
        if lsm.iter().any(|p| p.name == crate::selfprotect::PROG_NAME) {
            why.push_str(
                ". A `hemostat_deny` is listed here because no `selfprotect --arm` running this \
                 exact build holds it as its only copy — one armed by a different HEMOSTAT \
                 build reads this way too",
            );
        }
        findings.push(Finding {
            severity: Severity::Warn,
            subject: "BPF-LSM program(s)".into(),
            what: format!(
                "{} BPF-LSM program(s) loaded: {}",
                lsm.len(),
                name_list(&lsm)
            ),
            why,
        });
    }

    let intercept: Vec<&ProgSummary> =
        programs.iter().filter(|p| classify(p.prog_type) == Class::Interception).collect();
    if !intercept.is_empty() {
        findings.push(Finding {
            severity: Severity::Warn,
            subject: "eBPF interception-class program(s)".into(),
            what: format!(
                "{} program(s) that hook a syscall or kernel function: {}",
                intercept.len(),
                name_list(&intercept)
            ),
            why: "kprobe/tracepoint/fentry(tracing)/freplace(ext) programs run on a kernel \
                  function or syscall and can, with bpf_override_return, change its result — the \
                  method for hiding a file from getdents or denying a read from kernel context, \
                  leaving no module in lsmod. Observability tools (bpftrace, bcc, falco) load \
                  these legitimately, so reconcile each against a known tool; an unaccounted one \
                  on a server is the finding. Dump with `bpftool prog dump xlated id <id>`"
                .into(),
        });
    }

    let nonroot: Vec<&ProgSummary> = programs.iter().filter(|p| p.created_by_uid != 0).collect();
    if !nonroot.is_empty() {
        let mut sample = nonroot
            .iter()
            .take(8)
            .map(|p| format!("id {} ({}, uid {})", p.id, prog_type_name(p.prog_type), p.created_by_uid))
            .collect::<Vec<_>>()
            .join("; ");
        if nonroot.len() > 8 {
            sample.push_str(&format!("; +{} more", nonroot.len() - 8));
        }
        findings.push(Finding {
            severity: Severity::Warn,
            subject: "eBPF program loaded by a non-root uid".into(),
            what: format!("{} program(s) with a non-root created_by_uid: {sample}", nonroot.len()),
            why: "unprivileged BPF is disabled by default on modern kernels, so a program whose \
                  loader was not root is unusual — either unprivileged BPF has been enabled \
                  (an attack surface) or the program was loaded by a service running as that uid. \
                  Confirm the owning software"
                .into(),
        });
    }

    findings.sort_by_key(|f| std::cmp::Reverse(f.severity));
    findings
}

fn name_list(progs: &[&ProgSummary]) -> String {
    let mut s = progs
        .iter()
        .take(10)
        .map(|p| {
            if p.name.is_empty() {
                format!("id {} (unnamed)", p.id)
            } else {
                format!("id {} ({})", p.id, p.name)
            }
        })
        .collect::<Vec<_>>()
        .join(", ");
    if progs.len() > 10 {
        s.push_str(&format!(", +{} more", progs.len() - 10));
    }
    s
}

#[repr(C)]
#[derive(Default)]
struct GetIdAttr {
    id: u32,
    next_id: u32,
    open_flags: u32,
}

#[repr(C)]
#[derive(Default)]
struct ObjGetInfoAttr {
    bpf_fd: u32,
    info_len: u32,
    info: u64,
}

#[repr(C)]
#[derive(Default, Clone, Copy)]
struct BpfProgInfo {
    prog_type: u32,
    id: u32,
    tag: [u8; 8],
    jited_prog_len: u32,
    xlated_prog_len: u32,
    jited_prog_insns: u64,
    xlated_prog_insns: u64,
    load_time: u64,
    created_by_uid: u32,
    nr_map_ids: u32,
    map_ids: u64,
    name: [u8; 16],
    ifindex: u32,
    gpl_compatible_bits: u32,
}

const _: () = {
    assert!(core::mem::offset_of!(BpfProgInfo, id) == 4);
    assert!(core::mem::offset_of!(BpfProgInfo, tag) == 8);
    assert!(core::mem::offset_of!(BpfProgInfo, jited_prog_insns) == 24);
    assert!(core::mem::offset_of!(BpfProgInfo, xlated_prog_insns) == 32);
    assert!(core::mem::offset_of!(BpfProgInfo, load_time) == 40);
    assert!(core::mem::offset_of!(BpfProgInfo, created_by_uid) == 48);
    assert!(core::mem::offset_of!(BpfProgInfo, map_ids) == 56);
    assert!(core::mem::offset_of!(BpfProgInfo, name) == 64);
    assert!(core::mem::offset_of!(BpfProgInfo, ifindex) == 80);

    assert!(core::mem::size_of::<BpfProgInfo>() == 88);
};

unsafe fn bpf(cmd: i32, attr: *mut core::ffi::c_void, size: u32) -> i64 {

    unsafe { libc::syscall(libc::SYS_bpf, cmd, attr, size) }
}

fn last_errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn summarise(id: u32) -> Result<ProgSummary, i32> {
    let mut get = GetIdAttr { id, ..Default::default() };

    let fd = unsafe {
        bpf(
            BPF_PROG_GET_FD_BY_ID,
            std::ptr::addr_of_mut!(get).cast(),
            core::mem::size_of::<GetIdAttr>() as u32,
        )
    };
    if fd < 0 {
        return Err(last_errno());
    }

    let fd = unsafe { OwnedFd::from_raw_fd(fd as i32) };

    let mut info = BpfProgInfo::default();
    let mut attr = ObjGetInfoAttr {
        bpf_fd: fd.as_raw_fd() as u32,
        info_len: core::mem::size_of::<BpfProgInfo>() as u32,
        info: std::ptr::addr_of_mut!(info) as u64,
    };

    let rc = unsafe {
        bpf(
            BPF_OBJ_GET_INFO_BY_FD,
            std::ptr::addr_of_mut!(attr).cast(),
            core::mem::size_of::<ObjGetInfoAttr>() as u32,
        )
    };
    if rc < 0 {
        return Err(last_errno());
    }

    Ok(ProgSummary {
        id: info.id,
        prog_type: info.prog_type,
        name: cstr16(&info.name),
        created_by_uid: info.created_by_uid,
        held_by_init: false,
        selfprotect_holder: None,
    })
}

fn fdinfo_prog_id(text: &str) -> Option<u32> {
    text.lines()
        .find_map(|l| l.strip_prefix("prog_id:"))
        .and_then(|v| v.trim().parse().ok())
}

fn held_by(pid: u32) -> std::collections::BTreeSet<u32> {
    let Ok(rd) = fs::read_dir(format!("/proc/{pid}/fdinfo")) else {
        return Default::default();
    };
    rd.flatten()
        .filter_map(|e| e.file_name().to_str().map(str::to_owned))
        .filter_map(|fd| fs::read_to_string(format!("/proc/{pid}/fdinfo/{fd}")).ok())
        .filter_map(|t| fdinfo_prog_id(&t))
        .collect()
}

fn held_by_selfprotect(
    deny_ids: &std::collections::BTreeSet<u32>,
) -> std::collections::BTreeMap<u32, u32> {
    use std::path::Path;
    let mut out = std::collections::BTreeMap::new();
    let Some(ours) = crate::saferead::image_id(Path::new("/proc/self/exe")) else {
        return out;
    };
    let Ok(dir) = fs::read_dir("/proc") else {
        return out;
    };
    for e in dir.flatten() {
        let Some(pid) = e.file_name().to_str().and_then(|n| n.parse::<u32>().ok()) else {
            continue;
        };
        let exe = format!("/proc/{pid}/exe");
        if !fs::metadata(&exe).is_ok_and(|m| m.len() == ours.0) {
            continue;
        }
        let Some(id) = sole_deny(&held_by(pid), deny_ids) else {
            continue;
        };
        let argv = crate::saferead::read_proc(
            Path::new(&format!("/proc/{pid}/cmdline")),
            crate::saferead::MAX_PROC_BYTES,
        );
        if !argv.is_ok_and(|(b, truncated)| !truncated && selfprotect_argv(&b)) {
            continue;
        }
        if crate::saferead::is_image(Path::new(&exe), &ours) {
            out.insert(id, pid);
        }
    }
    out
}

fn sole_deny(
    held: &std::collections::BTreeSet<u32>,
    deny_ids: &std::collections::BTreeSet<u32>,
) -> Option<u32> {
    let mut both = held.intersection(deny_ids);
    match (both.next(), both.next()) {
        (Some(id), None) => Some(*id),
        _ => None,
    }
}

fn selfprotect_argv(cmdline: &[u8]) -> bool {
    let args: Vec<&[u8]> =
        cmdline.strip_suffix(b"\0").unwrap_or(cmdline).split(|b| *b == 0).skip(1).collect();
    args.iter().find(|a| !a.starts_with(b"--")).is_some_and(|v| *v == b"selfprotect")
        && args.iter().any(|a| *a == b"--arm")
}

fn cstr16(bytes: &[u8; 16]) -> String {
    let end = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

struct Walk {
    programs: Vec<ProgSummary>,

    truncated: bool,

    ids_seen: usize,

    vanished: usize,
}

impl Walk {

    fn named(&self) -> usize {
        self.ids_seen.saturating_sub(self.vanished)
    }

    fn undescribed(&self) -> usize {
        self.named().saturating_sub(self.programs.len())
    }

    fn incomplete(&self) -> bool {
        self.truncated || self.undescribed() > 0
    }
}

fn next_prog_id(after: u32) -> Result<u32, i32> {
    let mut get = GetIdAttr { id: after, ..Default::default() };

    let rc = unsafe {
        bpf(
            BPF_PROG_GET_NEXT_ID,
            std::ptr::addr_of_mut!(get).cast(),
            core::mem::size_of::<GetIdAttr>() as u32,
        )
    };
    if rc < 0 {
        Err(last_errno())
    } else {
        Ok(get.next_id)
    }
}

fn gone(answer: Result<u32, i32>, id: u32) -> bool {
    match answer {
        Ok(next) => next != id,
        Err(e) => e == libc::ENOENT,
    }
}

fn walk_programs() -> Result<Walk, i32> {
    walk_with(next_prog_id, summarise)
}

fn walk_with(
    mut next: impl FnMut(u32) -> Result<u32, i32>,
    mut describe: impl FnMut(u32) -> Result<ProgSummary, i32>,
) -> Result<Walk, i32> {
    let mut walk = Walk { programs: Vec::new(), truncated: false, ids_seen: 0, vanished: 0 };
    let mut cur = 0u32;
    for _ in 0..1_000_000 {
        let prev = cur;
        match next(cur) {

            Err(libc::ENOENT) => return Ok(walk),

            Err(e) if cur == 0 => return Err(e),

            Err(_) => {
                walk.truncated = true;
                return Ok(walk);
            }
            Ok(next) => cur = next,
        }
        walk.ids_seen += 1;
        match describe(cur) {
            Ok(s) => walk.programs.push(s),
            Err(libc::ENOENT) if gone(next(prev), cur) => walk.vanished += 1,

            Err(_) => {}
        }
    }
    Ok(walk)
}

fn attribute(walk: &mut Walk) {
    let lsm = |p: &ProgSummary| classify(p.prog_type) == Class::Lsm;
    if !walk.programs.iter().any(lsm) {
        return;
    }
    let init = held_by(1);
    let deny_ids: std::collections::BTreeSet<u32> = walk
        .programs
        .iter()
        .filter(|p| lsm(p) && p.name == crate::selfprotect::PROG_NAME)
        .map(|p| p.id)
        .collect();

    let agent = if deny_ids.is_empty() { Default::default() } else { held_by_selfprotect(&deny_ids) };
    for p in &mut walk.programs {
        p.held_by_init = init.contains(&p.id);
        p.selfprotect_holder = agent.get(&p.id).copied();
    }
}

fn walk_findings(walk: &Walk) -> Vec<Finding> {
    let mut findings = assess(&walk.programs);

    let named = walk.named();
    let undescribed = walk.undescribed();
    if undescribed > 0 {
        findings.push(Finding {
            severity: Severity::Warn,
            subject: "bpf-progs".into(),
            what: format!(
                "the kernel named {named} loaded program(s) and {undescribed} of them could not \
                 be described"
            ),
            why: "an id the walk returned is a program that exists; failing to read its \
                  info does not make it absent. Treat the census below as a FLOOR and \
                  not a list — an eBPF implant is exactly the thing that would be \
                  missing from it, and this sensor is the only one in the tree that \
                  looks for one"
                .into(),
        });
    }
    if walk.truncated {

        findings.push(Finding {
            severity: Severity::Note,
            subject: "eBPF program walk incomplete".into(),
            what: format!(
                "the walk was refused part-way; {} program(s) were enumerated before it \
                 stopped",
                walk.programs.len()
            ),
            why: "the counts and classifications above cover only what was reached. A \
                  program loaded after the refusal point is absent from them, so this \
                  is a floor rather than a census — re-run as root"
                .into(),
        });
    }
    findings.sort_by_key(|f| std::cmp::Reverse(f.severity));
    findings
}

fn bpffs_pins() -> (Vec<String>, Vec<String>) {
    fn walk(dir: &std::path::Path, depth: usize, out: &mut Vec<String>, gaps: &mut Vec<String>) {
        if depth > 8 {
            gaps.push(format!("{} (deeper than 8 levels, not entered)", dir.display()));
            return;
        }
        if out.len() >= 256 {
            return;
        }
        let rd = match fs::read_dir(dir) {
            Ok(rd) => rd,

            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return,
            Err(e) => {
                gaps.push(format!("{} ({e})", dir.display()));
                return;
            }
        };
        for entry in rd.flatten() {
            let path = entry.path();
            match entry.file_type() {
                Ok(ft) if ft.is_dir() => walk(&path, depth + 1, out, gaps),
                Ok(_) => out.push(path.to_string_lossy().into_owned()),
                Err(e) => gaps.push(format!("{} ({e})", path.display())),
            }
            if out.len() >= 256 {
                gaps.push("the walk stopped at 256 pins; more may exist".into());
                return;
            }
        }
    }
    let (mut out, mut gaps) = (Vec::new(), Vec::new());
    walk(std::path::Path::new("/sys/fs/bpf"), 0, &mut out, &mut gaps);
    gaps.dedup();
    (out, gaps)
}

fn pin_coverage(gaps: &[String]) -> Option<Finding> {
    if gaps.is_empty() {
        return None;
    }
    Some(Finding {
        severity: Severity::Note,
        subject: "bpffs pin coverage".into(),
        what: format!("the pin walk did not cover all of /sys/fs/bpf: {}", gaps.join("; ")),
        why: "a pin behind any of these was not listed, so the absence of an unexpected pin \
              above is not a clean result for those parts"
            .into(),
    })
}

pub fn report() -> Report {
    let mut report = Report::default();

    match walk_programs() {
        Ok(mut walk) => {
            attribute(&mut walk);
            let programs = &walk.programs;
            report.available = true;
            report.program_count = programs.len();
            report.interception_count =
                programs.iter().filter(|p| classify(p.prog_type) == Class::Interception).count();
            report.lsm_count = programs.iter().filter(|p| classify(p.prog_type) == Class::Lsm).count();
            report.nonroot_count = programs.iter().filter(|p| p.created_by_uid != 0).count();
            report.census_incomplete = walk.incomplete();
            report.findings = walk_findings(&walk);
        }
        Err(errno) => {
            report.reason = Some(if errno == libc::EPERM {
                "bpf(BPF_PROG_GET_NEXT_ID) refused (EPERM): the program walk needs CAP_SYS_ADMIN — \
                 re-run as root"
                    .into()
            } else if errno == libc::ENOSYS {
                "bpf(2) is not available on this kernel".into()
            } else {
                format!("bpf(BPF_PROG_GET_NEXT_ID) failed with errno {errno}")
            });
        }
    }

    let (pins, pin_gaps) = bpffs_pins();
    report.pins = pins;
    report.findings.extend(pin_coverage(&pin_gaps));
    if !report.pins.is_empty() {
        let sample = report.pins.iter().take(12).cloned().collect::<Vec<_>>().join(", ");
        let more = if report.pins.len() > 12 {
            format!(" (+{} more)", report.pins.len() - 12)
        } else {
            String::new()
        };
        report.findings.push(Finding {
            severity: Severity::Note,
            subject: "bpffs pins".into(),
            what: format!("{} object(s) pinned under /sys/fs/bpf: {sample}{more}", report.pins.len()),
            why: "a pin keeps a BPF program or map alive after the process that loaded it exits — \
                  the way an eBPF implant persists without a kernel module or a unit file. systemd \
                  and Cilium pin legitimately (e.g. /sys/fs/bpf/cilium), so reconcile each path \
                  against known software; an unexpected pin is worth dumping"
                .into(),
        });
    }

    if let Ok(v) = fs::read_to_string("/proc/sys/kernel/unprivileged_bpf_disabled") {
        if v.trim() == "0" {
            report.findings.push(Finding {
                severity: Severity::Note,
                subject: "unprivileged BPF permitted".into(),
                what: "kernel.unprivileged_bpf_disabled = 0".into(),
                why: "unprivileged users can load BPF programs on this host, which widens the \
                      attack surface for a local privilege-escalation via a verifier bug. Setting \
                      it to 1 (or 2) is the common hardening; not itself an indicator of compromise"
                    .into(),
            });
        }
    }

    if !report.available {

        report.findings.push(Finding {
            severity: Severity::Note,
            subject: "eBPF program scan".into(),
            what: "the eBPF program scan did not run".into(),
            why: report
                .reason
                .clone()
                .unwrap_or_else(|| "unavailable".into()),
        });
    }

    report.findings.sort_by_key(|f| std::cmp::Reverse(f.severity));
    report
}
