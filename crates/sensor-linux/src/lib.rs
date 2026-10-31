#![allow(unsafe_code)]
#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(not(target_arch = "x86_64"))]
compile_error!(
    "hemostat-sensor-linux is x86-64 only. `syscallhook` matches literal x86-64 \
     instruction bytes and would report a clean host on any other architecture, and \
     `ebpf_sensor::drain` relies on x86-64 load/load ordering and would need a \
     per-record Acquire on `len`. Both fail silently, which is why this refuses to \
     build rather than warning."
);

use core::fmt;

pub mod adjoin;
pub mod accounts;
pub mod audit;
pub mod btf;
pub mod fanotify;
pub mod firewall;
pub mod flowexport;
pub mod hooked;
pub mod hooks;
pub mod overview;
pub mod enablement;
pub mod persist;
pub mod pkg;
pub mod services;
pub mod probe;
pub mod rootkit;
pub mod syscallhook;
pub mod ftracehook;
pub mod kmod;
pub mod screencap;

pub(crate) mod bpfabi;
pub mod selfprotect;
pub mod selfsandbox;
pub mod triage;
pub mod trial;
pub mod procfs;

pub mod saferead;

pub mod safewrite;

pub mod kprobe;
pub mod kptrhooks;
pub mod sysmap;
pub mod suid;
pub mod inventory;
pub mod crossview;
pub mod ebpf_sensor;
pub mod sigpipe;

pub mod rng;
pub mod bpfprog;
pub mod kernposture;
pub mod kwalk;

pub mod kground;
pub mod watchdog;
pub mod sshd;
pub mod netnarrow;
pub mod netpolicy;
pub mod sysctlpolicy;
pub mod trust;
pub mod nftables;
pub mod snapshot;
pub mod vendor;
pub mod volume;

pub mod gui_fb;

pub mod gui_x11;

pub use probe::{probe, Finding, L1Availability, LsmBootLine, Tier, TierReport};
pub use accounts::{report as account_report, Account, Report as AccountReport, Severity};
pub use hooks::{report as hook_report, HookReport, HookState};
pub use firewall::{report as firewall_report, Backend, Report as FirewallReport};
pub use rootkit::{report as rootkit_report, Report as RootkitReport};
pub use crossview::{report as crossview_report, Report as CrossViewReport};
pub use audit::{report as audit_report, Report as AuditReport};
pub use kernposture::{report as kernposture_report, Report as KernPostureReport};
pub use kwalk::{report as kwalk_report, Report as KwalkReport};
pub use kground::{report as kground_report, Report as KgroundReport};
pub use bpfprog::{report as bpfprog_report, ProgSummary, Report as BpfProgReport};
pub use syscallhook::{report as syscall_hook_report, Report as SyscallHookReport};
pub use ftracehook::{report as ftrace_hook_report, Report as FtraceHookReport};
pub use kmod::{report as kmod_report, Report as KmodReport};
pub use persist::{report as persist_report, Report as PersistReport, CATALOGUE as PERSIST_CATALOGUE};
pub use hooked::{report as hooked_report, Process as HookedProcess, Report as HookedReport};
pub use overview::{report as overview_report, Identity, Report as OverviewReport, Socket};
pub use triage::{Coverage, Finding as TriageFinding, Severity as TriageSeverity};
pub use screencap::{report as screencap_report, Report as ScreenCaptureReport, Vector as CaptureVector};
pub use selfprotect::{arm as arm_deny, arm_resident as arm_deny_resident, trial as deny_trial, Armed, ArmError, ArmStage, Trial as DenyTrial, Verdict as DenyVerdict};
pub use trial::{trial_attach, trial_fanotify, FanStage, FanotifyTrial, Stage, TrialAttach};
pub use procfs::{walk, ProcSnapshot};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SensorError {

    Probe(&'static str, String),
}

impl fmt::Display for SensorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SensorError::Probe(what, detail) => write!(f, "probe failed: {what}: {detail}"),
        }
    }
}

impl std::error::Error for SensorError {}
