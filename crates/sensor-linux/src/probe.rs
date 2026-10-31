use crate::SensorError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Tier {

    L1,

    L2,

    L3,

    L4,
}

impl Tier {

    pub const fn can_deny(self) -> bool {
        matches!(self, Tier::L1 | Tier::L2)
    }

    pub const fn label(self) -> &'static str {
        match self {
            Tier::L1 => "L1",
            Tier::L2 => "L2",
            Tier::L3 => "L3",
            Tier::L4 => "L4",
        }
    }

    pub const fn describe(self) -> &'static str {
        match self {
            Tier::L1 => "BPF LSM: the kernel permits a synchronous deny on exec, open, connect, \
                         signal, ptrace",
            Tier::L2 => "fanotify: the kernel permits blocking file access; no signal or ptrace \
                         deny",
            Tier::L3 => "audit multicast: observe only",
            Tier::L4 => "procfs: observe only, coarse",
        }
    }
}

pub const BUILT_DENY: &str = "signals to the agent itself (BPF-LSM task_kill), and only while \
     `selfprotect --arm` holds it; no exec, open, connect or ptrace deny is built, and nothing \
     denies through fanotify";

impl core::fmt::Display for Tier {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.label())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {

    pub check: &'static str,

    pub ok: bool,

    pub detail: String,
}

impl Finding {
    fn new(check: &'static str, ok: bool, detail: impl Into<String>) -> Self {
        Self {
            check,
            ok,
            detail: detail.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum L1Availability {

    Active,

    NeedsReboot {

        current: Option<String>,

        suggested: String,
    },

    NotInKernel,

    Unknown,
}

impl L1Availability {

    pub fn remediation(&self) -> Option<String> {
        match self {
            L1Availability::Active => None,
            L1Availability::NeedsReboot { current, suggested } => Some(format!(
                "This kernel supports the BPF LSM (CONFIG_BPF_LSM=y) but `bpf` is not in the\n\
                 active list{}, so enforcement is capped below L1.\n\n\
                 To enable it, add this to the kernel command line and reboot:\n\
                 \n    lsm={suggested}\n\n\
                 GRUB: add it to GRUB_CMDLINE_LINUX in /etc/default/grub, then run\n\
                 update-grub (Debian/Ubuntu) or grub2-mkconfig -o /boot/grub2/grub.cfg (RHEL).\n\n\
                 HEMOSTAT does not edit the boot line itself: a host that does not come back\n\
                 up is a worse outcome than a lower enforcement tier.",
                match current {
                    Some(c) => format!(" (currently lsm={c})"),
                    None => " (no lsm= parameter is set, so the built-in default applies)".to_string(),
                }
            )),
            L1Availability::NotInKernel => Some(
                "This kernel was not built with CONFIG_BPF_LSM, so no boot-line change will\n\
                 enable L1. Reaching it requires a different kernel."
                    .to_string(),
            ),
            L1Availability::Unknown => Some(
                "The kernel configuration could not be read (no /proc/config.gz and no\n\
                 /boot/config-<release>), so it is not possible to tell whether the BPF LSM is\n\
                 compiled in but inactive, or absent entirely. Reported conservatively."
                    .to_string(),
            ),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LsmBootLine {

    Default,

    Complete,

    Narrowed {

        dropped: Vec<String>,
    },

    Unknown,
}

impl LsmBootLine {

    pub fn warning(&self) -> Option<String> {
        match self {
            LsmBootLine::Default | LsmBootLine::Complete => None,
            LsmBootLine::Narrowed { dropped } => Some(format!(
                "The boot line's lsm= list excludes {} that this kernel's CONFIG_LSM\n\
                 enables. Compare it against the active list above: most excluded modules\n\
                 will be absent from it, though a few — `capability` and `lockdown` — \n\
                 register irrespective of lsm= and will still appear. What is stated here\n\
                 is what the boot line excluded, not what failed to load.\n\n\
                 This does not change the tier, which is measured separately. But if this\n\
                 list was set in order to reach L1, it was set too narrowly: extend the\n\
                 kernel's list rather than replacing it, and reboot.",
                dropped.join(", ")
            )),
            LsmBootLine::Unknown => Some(
                "An lsm= list is in force but the kernel configuration could not be read,\n\
                 so whether it excludes modules the kernel would otherwise enable is\n\
                 undetermined. Reported rather than assumed clean."
                    .to_string(),
            ),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TierReport {

    pub host_supports: Tier,

    pub process_can: Tier,

    pub provisional: bool,

    pub capabilities_known: bool,

    pub l1: L1Availability,

    pub lsm_boot_line: LsmBootLine,

    pub trial: Option<crate::trial::TrialAttach>,

    pub findings: Vec<Finding>,
}

impl TierReport {

    pub fn effective(&self) -> Tier {

        self.host_supports.max(self.process_can)
    }

    pub fn limited_by_privilege(&self) -> bool {
        self.process_can > self.host_supports
    }
}

fn kernel_config() -> Option<String> {
    let release = crate::saferead::read_kernel_text("/proc/sys/kernel/osrelease").ok()?;
    crate::saferead::read_scan_target(std::path::Path::new(&format!(
        "/boot/config-{}",
        release.trim()
    )))
}

fn suggested_lsm(config_default: Option<&str>, current: Option<&str>) -> String {
    let mut out: Vec<&str> = Vec::new();
    for list in [config_default, current].into_iter().flatten() {
        for m in list.split(',').map(str::trim).filter(|m| !m.is_empty()) {
            if !out.contains(&m) {
                out.push(m);
            }
        }
    }

    if out.is_empty() {

        return "landlock,lockdown,yama,integrity,bpf".to_string();
    }
    if !out.contains(&"bpf") {
        out.push("bpf");
    }
    out.join(",")
}

fn lsm_boot_line(cmdline: Option<&str>, config: Option<&str>) -> LsmBootLine {
    let Some(cmdline) = cmdline else {
        return LsmBootLine::Default;
    };
    let Some(default) = config
        .and_then(|c| c.lines().find_map(|l| l.trim().strip_prefix("CONFIG_LSM=")))
        .map(|v| v.trim().trim_matches('"'))
    else {
        return LsmBootLine::Unknown;
    };

    let in_force: Vec<&str> = cmdline.split(',').map(str::trim).filter(|s| !s.is_empty()).collect();
    let dropped: Vec<String> = default
        .split(',')
        .map(str::trim)
        .filter(|m| !m.is_empty() && !in_force.contains(m))
        .map(str::to_string)
        .collect();

    if dropped.is_empty() {
        LsmBootLine::Complete
    } else {
        LsmBootLine::Narrowed { dropped }
    }
}

fn cmdline_lsm() -> Option<String> {
    crate::saferead::read_kernel_text("/proc/cmdline")
        .ok()
        .and_then(|c| crate::kernposture::boot_param(&c, "lsm").map(str::to_string))
}

fn audit_available(config: Option<&str>, cmdline: Option<&str>) -> Option<bool> {
    if cmdline.is_some_and(|c| c.split_whitespace().any(|p| p == "audit=0")) {
        return Some(false);
    }
    config.map(|c| c.lines().any(|l| l.trim() == "CONFIG_AUDIT=y"))
}

fn precondition_tier(
    (maj, min): (u32, u32),
    bpf_lsm_ready: bool,
    fanotify: Option<bool>,
    audit: Option<bool>,
) -> Tier {
    let multicast_kernel = maj > 3 || (maj == 3 && min >= 16);
    if (maj > 5 || (maj == 5 && min >= 7)) && bpf_lsm_ready {
        Tier::L1
    } else if fanotify.unwrap_or(maj >= 5) {
        Tier::L2
    } else if multicast_kernel && audit.unwrap_or(true) {
        Tier::L3
    } else {
        Tier::L4
    }
}

fn kernel_version() -> Result<(u32, u32), SensorError> {
    let s = crate::saferead::read_kernel_text("/proc/sys/kernel/osrelease")
        .map_err(|e| SensorError::Probe("cannot read /proc/sys/kernel/osrelease", e.to_string()))?;
    let mut parts = s.trim().split(['.', '-', '+']);
    let major = parts.next().and_then(|v| v.parse().ok()).unwrap_or(0);
    let minor = parts.next().and_then(|v| v.parse().ok()).unwrap_or(0);
    Ok((major, minor))
}

fn cap_effective() -> Option<u64> {
    crate::saferead::read_pid_text("/proc/self/status").ok().and_then(|s| {
        s.lines()
            .find_map(|l| l.strip_prefix("CapEff:"))
            .and_then(|v| u64::from_str_radix(v.trim(), 16).ok())
    })
}

const CAP_SYS_ADMIN: u32 = 21;
const CAP_AUDIT_READ: u32 = 37;
const CAP_BPF: u32 = 39;

const fn has_cap(caps: Option<u64>, bit: u32) -> Option<bool> {
    match caps {
        Some(c) => Some(c & (1u64 << bit) != 0),
        None => None,
    }
}

pub fn probe() -> TierReport {
    let mut findings = Vec::new();

    let (maj, min) = kernel_version().unwrap_or((0, 0));
    findings.push(Finding::new(
        "kernel version",
        maj > 5 || (maj == 5 && min >= 7),
        format!("{maj}.{min} (BPF LSM needs >= 5.7)"),
    ));

    let btf = std::path::Path::new("/sys/kernel/btf/vmlinux").exists();
    findings.push(Finding::new(
        "BTF for CO-RE",
        btf,
        if btf {
            "/sys/kernel/btf/vmlinux present".to_string()
        } else {
            "absent; an embedded BTFHub blob would be required".to_string()
        },
    ));

    let lsm_raw = crate::saferead::read_kernel_text("/sys/kernel/security/lsm").unwrap_or_default();
    let lsm_list: Vec<&str> = lsm_raw.trim().split(',').filter(|s| !s.is_empty()).collect();
    let bpf_lsm = lsm_list.contains(&"bpf");
    findings.push(Finding::new(
        "bpf in the active LSM list",
        bpf_lsm,
        if lsm_raw.trim().is_empty() {
            "/sys/kernel/security/lsm unreadable (securityfs not mounted?)".to_string()
        } else {
            format!("active: {}", lsm_list.join(", "))
        },
    ));

    let fan = crate::trial::trial_fanotify();
    let fanotify_host = match &fan {
        crate::trial::FanotifyTrial::Available => Some(true),
        crate::trial::FanotifyTrial::Refused { errno: libc::EPERM, .. } => None,
        crate::trial::FanotifyTrial::Refused { .. } => Some(false),
    };
    findings.push(Finding::new(
        "fanotify permission events",
        fan.ok(),
        match fanotify_host {
            None => format!("{} — not permitted to this process, so the host is judged by kernel {maj}.{min}", fan.detail()),
            _ => fan.detail(),
        },
    ));

    let caps = cap_effective();
    let caps_known = caps.is_some();
    let detail = match caps {
        Some(c) => format!("CapEff=0x{c:016x}"),
        None => "UNDETERMINED: /proc/self/status unreadable (is /proc mounted?)".to_string(),
    };

    let cap_bpf = matches!(has_cap(caps, CAP_BPF), Some(true))
        || matches!(has_cap(caps, CAP_SYS_ADMIN), Some(true));
    let cap_admin = matches!(has_cap(caps, CAP_SYS_ADMIN), Some(true));
    let cap_audit = matches!(has_cap(caps, CAP_AUDIT_READ), Some(true)) || cap_admin;

    findings.push(Finding::new("CAP_BPF or CAP_SYS_ADMIN", cap_bpf, detail));
    findings.push(Finding::new(
        "CAP_SYS_ADMIN",
        cap_admin,
        if caps_known { "for fanotify permission mode" } else { "undetermined" },
    ));
    findings.push(Finding::new(
        "CAP_AUDIT_READ",
        cap_audit,
        if caps_known { "for audit multicast" } else { "undetermined" },
    ));

    let cfg = kernel_config();
    let audit_host =
        audit_available(cfg.as_deref(), crate::saferead::read_kernel_text("/proc/cmdline").ok().as_deref());
    findings.push(Finding::new(
        "kernel audit available",
        audit_host != Some(false),
        match audit_host {
            Some(true) => "CONFIG_AUDIT=y and not disabled on the boot line".to_string(),
            Some(false) => "audit is compiled out or disabled with audit=0".to_string(),
            None => format!("kernel config unreadable, so judged by kernel {maj}.{min}"),
        },
    ));
    let l1 = if bpf_lsm {
        L1Availability::Active
    } else {
        match &cfg {
            None => L1Availability::Unknown,
            Some(c) if c.lines().any(|l| l.trim() == "CONFIG_BPF_LSM=y") => {
                let current = cmdline_lsm();
                let config_default = c
                    .lines()
                    .find_map(|l| l.trim().strip_prefix("CONFIG_LSM="))
                    .map(|v| v.trim_matches('"').to_string());
                let suggested =
                    suggested_lsm(config_default.as_deref(), current.as_deref());
                L1Availability::NeedsReboot { current, suggested }
            }
            Some(_) => L1Availability::NotInKernel,
        }
    };

    let lsm_boot_line = lsm_boot_line(cmdline_lsm().as_deref(), cfg.as_deref());
    findings.push(Finding::new(
        "boot line keeps the kernel's LSM set",
        !matches!(lsm_boot_line, LsmBootLine::Narrowed { .. }),
        match &lsm_boot_line {
            LsmBootLine::Default => "no lsm= parameter; the built-in default is in force".to_string(),
            LsmBootLine::Complete => "lsm= names everything CONFIG_LSM does".to_string(),
            LsmBootLine::Narrowed { dropped } => {
                format!("lsm= excludes {}, which CONFIG_LSM enables", dropped.join(", "))
            }
            LsmBootLine::Unknown => "lsm= is set but CONFIG_LSM is unreadable".to_string(),
        },
    ));

    findings.push(Finding::new(
        "BPF LSM reachable by reboot",
        matches!(l1, L1Availability::Active | L1Availability::NeedsReboot { .. }),
        match &l1 {
            L1Availability::Active => "already active".to_string(),
            L1Availability::NeedsReboot { .. } => {
                "CONFIG_BPF_LSM=y but inactive — a boot-line change would enable it".to_string()
            }
            L1Availability::NotInKernel => "CONFIG_BPF_LSM not set in this kernel".to_string(),
            L1Availability::Unknown => "kernel config unreadable".to_string(),
        },
    ));

    let trial = crate::trial::trial_attach();
    findings.push(Finding::new(
        "trial attach of a no-op LSM program",
        trial.ok(),
        trial.detail(),
    ));

    let by_precondition = precondition_tier((maj, min), btf && bpf_lsm, fanotify_host, audit_host);

    let refused_for_privilege = matches!(
        trial,
        crate::trial::TrialAttach::Refused { errno: libc::EPERM, .. }
    );

    let host_supports = match &trial {

        crate::trial::TrialAttach::Refused { .. } if !refused_for_privilege => {
            by_precondition.max(Tier::L2)
        }
        _ => by_precondition,
    };

    let process_can = if cap_bpf && host_supports == Tier::L1 {
        Tier::L1
    } else if cap_admin {
        Tier::L2
    } else if cap_audit {
        Tier::L3
    } else {
        Tier::L4
    };

    let process_can = if refused_for_privilege {
        process_can.max(Tier::L2)
    } else {
        process_can
    };

    TierReport {
        host_supports,
        process_can,

        provisional: false,

        capabilities_known: caps_known,
        l1,
        lsm_boot_line,
        trial: Some(trial),
        findings,
    }
}
