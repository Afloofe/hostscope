#![forbid(unsafe_code)]

use hemostat_buildinfo::{ActionClass, ModuleDescriptor, ModuleId, Status};

pub mod noop;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Provider {

    Mandatory,

    Module(ModuleId),
}

pub const fn provider_for(class: ActionClass) -> Provider {
    match class {

        ActionClass::Isolate => Provider::Module(ModuleId::EnfNetEgress),
        ActionClass::ProcBlock => Provider::Module(ModuleId::EnfNetEgress),
        ActionClass::DestBlock => Provider::Module(ModuleId::EnfNetEgress),
        ActionClass::IsolateInbound => Provider::Module(ModuleId::EnfNetIngress),

        ActionClass::Kill => Provider::Module(ModuleId::EnfProc),
        ActionClass::Suspend => Provider::Module(ModuleId::EnfProc),

        ActionClass::SessionKill => Provider::Module(ModuleId::EnfAccount),

        ActionClass::TicketPurge => Provider::Module(ModuleId::EnfAccount),
        ActionClass::AccountDisable => Provider::Module(ModuleId::EnfAccount),
        ActionClass::CredRotate => Provider::Module(ModuleId::EnfAccount),
        ActionClass::GroupDrop => Provider::Module(ModuleId::EnfAccount),

        ActionClass::ExecBlock => Provider::Module(ModuleId::EnfExec),
        ActionClass::PersistenceNeutralize => Provider::Module(ModuleId::EnfPersistence),

        ActionClass::Quarantine => Provider::Module(ModuleId::EnfFile),

        ActionClass::Harden => Provider::Module(ModuleId::HardenNoReboot),
        ActionClass::Deception => Provider::Module(ModuleId::Deceive),
        ActionClass::SidecarInstall => Provider::Module(ModuleId::Sidecar),

        ActionClass::Collect => Provider::Module(ModuleId::Collect),
        ActionClass::Acquire => Provider::Module(ModuleId::Acquire),

        ActionClass::Allowlist => Provider::Mandatory,
        ActionClass::Lift => Provider::Mandatory,
        ActionClass::Uninstall => Provider::Mandatory,

        ActionClass::PerimeterBlock => Provider::Module(ModuleId::EnfPerimeter),
        ActionClass::PerimeterStateKill => Provider::Module(ModuleId::EnfPerimeterKill),

        ActionClass::ServiceStart => Provider::Module(ModuleId::EnfPersistence),
    }
}

pub const fn is_built(id: ModuleId) -> bool {
    match id {
        ModuleId::SensorEtw => cfg!(feature = "mod-sensor-etw"),
        ModuleId::SensorEvtlog => cfg!(feature = "mod-sensor-evtlog"),
        ModuleId::SensorUsn => cfg!(feature = "mod-sensor-usn"),
        ModuleId::SensorSysmon => cfg!(feature = "mod-sensor-sysmon"),
        ModuleId::SensorWmi => cfg!(feature = "mod-sensor-wmi"),
        ModuleId::SensorEbpf => cfg!(feature = "mod-sensor-ebpf"),
        ModuleId::SensorFanotify => cfg!(feature = "mod-sensor-fanotify"),
        ModuleId::SensorAudit => cfg!(feature = "mod-sensor-audit"),
        ModuleId::DetectSigma => cfg!(feature = "mod-detect-sigma"),
        ModuleId::Correlation => cfg!(feature = "mod-correlation"),
        ModuleId::ScanYara => cfg!(feature = "mod-scan-yara"),
        ModuleId::Query => cfg!(feature = "mod-query"),
        ModuleId::QueryMemory => cfg!(feature = "mod-query-memory"),
        ModuleId::EnfNetEgress => cfg!(feature = "mod-enf-net-egress"),
        ModuleId::EnfNetIngress => cfg!(feature = "mod-enf-net-ingress"),
        ModuleId::EnfProc => cfg!(feature = "mod-enf-proc"),
        ModuleId::EnfAccount => cfg!(feature = "mod-enf-account"),
        ModuleId::EnfExec => cfg!(feature = "mod-enf-exec"),
        ModuleId::EnfPersistence => cfg!(feature = "mod-enf-persistence"),
        ModuleId::EnfFile => cfg!(feature = "mod-enf-file"),
        ModuleId::EnfPerimeter => cfg!(feature = "mod-enf-perimeter"),
        ModuleId::EnfPerimeterKill => cfg!(feature = "mod-enf-perimeter-kill"),
        ModuleId::HardenNoReboot => cfg!(feature = "mod-harden-noreboot"),
        ModuleId::HardenReboot => cfg!(feature = "mod-harden-reboot"),
        ModuleId::Deceive => cfg!(feature = "mod-deceive"),
        ModuleId::Sidecar => cfg!(feature = "mod-sidecar"),
        ModuleId::Collect => cfg!(feature = "mod-collect"),
        ModuleId::Acquire => cfg!(feature = "mod-acquire"),
        ModuleId::Tui => cfg!(feature = "mod-tui"),
        ModuleId::Remote => cfg!(feature = "mod-remote"),
        ModuleId::Collector => cfg!(feature = "mod-collector"),
        ModuleId::ExportStix => cfg!(feature = "mod-export-stix"),
        ModuleId::ExportMisp => cfg!(feature = "mod-export-misp"),
        ModuleId::ExportJsonl => cfg!(feature = "mod-export-jsonl"),
        ModuleId::ExportReport => cfg!(feature = "mod-export-report"),
        ModuleId::VerifyEmbedded => cfg!(feature = "mod-verify-embedded"),
        ModuleId::Tamper => cfg!(feature = "mod-tamper"),
        ModuleId::SelfprotectLsm => cfg!(feature = "mod-selfprotect-lsm"),
        ModuleId::Selfsandbox => cfg!(feature = "mod-selfsandbox"),
        ModuleId::OnBoxKey => cfg!(feature = "mod-on-box-key"),
        ModuleId::DriverTier => cfg!(feature = "driver-tier"),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetOs {

    Linux,

    Windows,

    FreeBsd,
}

impl TargetOs {

    pub const THIS: TargetOs = if cfg!(target_os = "windows") {
        TargetOs::Windows
    } else if cfg!(target_os = "freebsd") {
        TargetOs::FreeBsd
    } else {
        TargetOs::Linux
    };
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Executor {

    Reachable,

    Unreachable,

    Unimplemented,

    NotInVariant,

    NotOnThisOs,
}

impl Executor {

    pub const fn token(self) -> &'static str {
        match self {
            Executor::Reachable => "yes",
            Executor::Unreachable => "built, unreachable",
            Executor::Unimplemented => "not implemented",
            Executor::NotInVariant => "not in this build",
            Executor::NotOnThisOs => "not on this OS",
        }
    }
}

impl core::fmt::Display for Executor {

    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.pad(self.token())
    }
}

pub const fn executor_for(class: ActionClass) -> Executor {

    let built = executor_given(action_build_status(class), wiring_for(class));
    routed_given(class, built, is_built(ModuleId::EnfNetIngress))
}

const fn routed_given(class: ActionClass, built: Executor, inbound_built: bool) -> Executor {
    if matches!(class, ActionClass::Isolate) && matches!(built, Executor::Reachable) && !inbound_built {
        return Executor::Unreachable;
    }
    built
}

const fn executor_given(status: Status, wiring: Executor) -> Executor {
    if matches!(status, Status::NotBuilt) {
        return Executor::NotInVariant;
    }
    wiring
}

pub const fn wiring_for(class: ActionClass) -> Executor {
    wiring_on(TargetOs::THIS, class)
}

pub const fn wiring_on(os: TargetOs, class: ActionClass) -> Executor {
    match os {
        TargetOs::Linux => linux_wiring(class),
        TargetOs::Windows => windows_wiring(class),
        TargetOs::FreeBsd => freebsd_wiring(class),
    }
}

const fn freebsd_wiring(class: ActionClass) -> Executor {
    match class {
        ActionClass::PerimeterBlock | ActionClass::PerimeterStateKill => Executor::Reachable,

        ActionClass::Collect => Executor::Reachable,
        _ => Executor::NotOnThisOs,
    }
}

const fn windows_wiring(class: ActionClass) -> Executor {
    match class {

        ActionClass::Harden => Executor::Reachable,

        ActionClass::Collect => Executor::Reachable,

        ActionClass::Kill | ActionClass::Quarantine => Executor::Reachable,

        ActionClass::PersistenceNeutralize => Executor::Reachable,

        ActionClass::AccountDisable => Executor::Reachable,

        ActionClass::IsolateInbound => Executor::Reachable,

        ActionClass::ServiceStart => Executor::Reachable,
        _ => Executor::NotOnThisOs,
    }
}

const fn linux_wiring(class: ActionClass) -> Executor {
    match class {

        ActionClass::PersistenceNeutralize => Executor::Reachable,

        ActionClass::Lift => Executor::Reachable,

        ActionClass::Kill | ActionClass::Suspend | ActionClass::Quarantine => {
            Executor::Reachable
        }

        ActionClass::IsolateInbound => Executor::Reachable,

        ActionClass::Isolate => Executor::Reachable,

        ActionClass::ProcBlock | ActionClass::DestBlock => Executor::Reachable,

        ActionClass::AccountDisable | ActionClass::Harden => Executor::Reachable,

        ActionClass::SessionKill
        | ActionClass::TicketPurge
        | ActionClass::CredRotate
        | ActionClass::GroupDrop => Executor::Reachable,

        ActionClass::ExecBlock => Executor::Reachable,

        ActionClass::Collect => Executor::Reachable,

        ActionClass::Acquire => Executor::Reachable,

        ActionClass::Deception => Executor::Reachable,

        ActionClass::SidecarInstall => Executor::Reachable,

        ActionClass::Allowlist | ActionClass::Uninstall => Executor::Reachable,

        ActionClass::ServiceStart => Executor::Reachable,

        ActionClass::PerimeterBlock | ActionClass::PerimeterStateKill => Executor::NotOnThisOs,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Implementation {

    Registered(&'static str),

    Declared,

    NotOnThisOs,
}

impl Implementation {

    pub const fn token(self) -> &'static str {
        match self {
            Implementation::Registered(_) => "implemented",
            Implementation::Declared => "declared only",
            Implementation::NotOnThisOs => "not on this OS",
        }
    }
}

pub fn implementation_for(id: ModuleId) -> Implementation {
    implementation_on(TargetOs::THIS, id)
}

pub fn implementation_on(os: TargetOs, id: ModuleId) -> Implementation {
    use Implementation::Registered as R;
    match (os, id) {

        (TargetOs::Windows, ModuleId::HardenNoReboot) => R("cli/src/remedy.rs::apply_remedy (WDigest)"),
        (TargetOs::Windows, ModuleId::HardenReboot) => {
            R("cli/src/remedy.rs::apply_remedy (driver blocklist)")
        }

        (TargetOs::Windows, ModuleId::EnfProc) => R("cli/src/win_respond.rs::kill"),
        (TargetOs::Windows, ModuleId::EnfFile) => R("cli/src/win_respond.rs::quarantine"),
        (TargetOs::Windows, ModuleId::EnfAccount) => R("cli/src/win_accounts.rs::disable"),
        (TargetOs::Windows, ModuleId::EnfPersistence) => {
            R("cli/src/win_respond.rs + win_wmi.rs + win_binvault.rs + win_restore.rs")
        }
        (TargetOs::Windows, ModuleId::EnfNetIngress) => R("cli/src/win_firewall.rs::allow"),

        (TargetOs::Linux | TargetOs::Windows, ModuleId::EnfPerimeter | ModuleId::EnfPerimeterKill) => {
            Implementation::NotOnThisOs
        }
        _ => match registered(id) {
            R(path) if !linked_on(os, path) => Implementation::NotOnThisOs,
            imp => imp,
        },
    }
}

fn linked_on(os: TargetOs, path: &str) -> bool {
    let krate = path.strip_prefix("crates/").unwrap_or(path);
    match os {
        TargetOs::Linux => !krate.starts_with("sensor-win/"),
        TargetOs::Windows => {
            !(krate.starts_with("sensor-linux/") || krate.starts_with("enforce-linux/"))
        }

        TargetOs::FreeBsd => {
            !(krate.starts_with("sensor-linux/")
                || krate.starts_with("enforce-linux/")
                || krate.starts_with("sensor-win/"))
        }
    }
}

const fn registered(id: ModuleId) -> Implementation {
    use Implementation::Registered as R;
    match id {

        ModuleId::SensorEbpf => R("sensor-linux/src/ebpf_sensor.rs"),

        ModuleId::SensorEtw => R("sensor-win/src/etw"),

        ModuleId::SensorWmi => R("sensor-win/src/wmi.rs"),

        ModuleId::EnfNetIngress => R("sensor-linux/src/netpolicy.rs"),

        ModuleId::EnfNetEgress => R("sensor-linux/src/netpolicy.rs::egress + netnarrow.rs"),
        ModuleId::ExportJsonl
        | ModuleId::ExportStix
        | ModuleId::ExportMisp
        | ModuleId::ExportReport => R("crates/export"),

        ModuleId::EnfAccount => R("enforce-linux/src/account.rs"),

        ModuleId::Acquire => R("enforce-linux/src/acquire.rs"),

        ModuleId::Deceive => R("enforce-linux/src/deceive.rs"),

        ModuleId::Selfsandbox => R("sensor-linux/src/selfsandbox.rs"),

        ModuleId::Sidecar => R("enforce-linux/src/sidecar.rs"),

        ModuleId::Remote => R("crates/remote"),

        ModuleId::EnfExec => R("enforce-linux/src/exec.rs"),

        ModuleId::HardenNoReboot => R("sensor-linux/src/sysctlpolicy.rs + sshd.rs"),

        ModuleId::HardenReboot => R("enforce-linux/src/bootparam.rs"),

        ModuleId::SensorFanotify => R("sensor-linux/src/fanotify.rs"),

        ModuleId::SensorAudit => R("sensor-linux/src/audit.rs"),

        ModuleId::SensorEvtlog => R("sensor-win/src/evtlog.rs"),

        ModuleId::DetectSigma => R("crates/detect"),

        ModuleId::Correlation => R("detect/src/correlate.rs"),

        ModuleId::Query => R("crates/query"),

        ModuleId::QueryMemory => R("query/src/tables.rs::MemoryRegions"),

        ModuleId::SensorUsn => R("sensor-win/src/usn.rs"),

        ModuleId::SensorSysmon => R("sensor-win/src/sysmon.rs"),

        ModuleId::Tamper => R("sensor-linux/src/selfprotect.rs"),

        ModuleId::EnfPersistence => R("enforce-linux/src/persistence.rs"),

        ModuleId::EnfProc => R("enforce-linux/src/lib.rs::apply_process"),

        ModuleId::EnfFile => R("enforce-linux/src/lib.rs::apply_move_out"),

        ModuleId::Tui => R("crates/tui + gui"),

        ModuleId::Collect => R("crates/evfmt"),

        ModuleId::VerifyEmbedded => R("crates/evfmt/src/store.rs"),

        ModuleId::SelfprotectLsm => R("sensor-linux/src/selfprotect.rs"),

        ModuleId::ScanYara => R("crates/scan"),

        ModuleId::EnfPerimeter => R("enforce-pf/src/apply.rs"),

        ModuleId::EnfPerimeterKill => R("enforce-pf/src/statekill.rs"),

        _ => Implementation::Declared,
    }
}

pub fn reachable_action_count() -> usize {
    ActionClass::ALL
        .iter()
        .filter(|c| matches!(executor_for(**c), Executor::Reachable))
        .count()
}

pub const fn action_build_status(class: ActionClass) -> Status {
    match provider_for(class) {
        Provider::Mandatory => Status::Full,
        Provider::Module(id) => {
            if is_built(id) {
                Status::Full
            } else {
                Status::NotBuilt
            }
        }
    }
}

pub fn refusal_message(class: ActionClass, variant: &str) -> String {
    format!("{}: {} in variant {}", class, Status::NotBuilt, variant)
}

pub fn module_refusal(id: ModuleId, variant: &str) -> String {
    format!("{}: {} in variant {}", id.feature(), Status::NotBuilt, variant)
}

pub const MODULES: &[ModuleDescriptor] = &[
    d(ModuleId::SensorEtw),
    d(ModuleId::SensorEvtlog),
    d(ModuleId::SensorUsn),
    d(ModuleId::SensorSysmon),
    d(ModuleId::SensorWmi),
    d(ModuleId::SensorEbpf),
    d(ModuleId::SensorFanotify),
    d(ModuleId::SensorAudit),
    d(ModuleId::DetectSigma),
    d(ModuleId::Correlation),
    d(ModuleId::ScanYara),
    d(ModuleId::Query),
    d(ModuleId::QueryMemory),
    d(ModuleId::EnfNetEgress),
    d(ModuleId::EnfNetIngress),
    d(ModuleId::EnfProc),
    d(ModuleId::EnfAccount),
    d(ModuleId::EnfExec),
    d(ModuleId::EnfPersistence),
    d(ModuleId::EnfFile),
    d(ModuleId::EnfPerimeter),
    d(ModuleId::EnfPerimeterKill),
    d(ModuleId::HardenNoReboot),
    d(ModuleId::HardenReboot),
    d(ModuleId::Deceive),
    d(ModuleId::Sidecar),
    d(ModuleId::Collect),
    d(ModuleId::Acquire),
    d(ModuleId::Tui),
    d(ModuleId::Remote),
    d(ModuleId::Collector),
    d(ModuleId::ExportStix),
    d(ModuleId::ExportMisp),
    d(ModuleId::ExportJsonl),
    d(ModuleId::ExportReport),
    d(ModuleId::VerifyEmbedded),
    d(ModuleId::Tamper),
    d(ModuleId::SelfprotectLsm),
    d(ModuleId::Selfsandbox),
    d(ModuleId::OnBoxKey),
    d(ModuleId::DriverTier),
];

const fn d(id: ModuleId) -> ModuleDescriptor {
    ModuleDescriptor {
        id,
        status: if is_built(id) {
            Status::Full
        } else {
            Status::NotBuilt
        },
        provides_actions: actions_of(id),
    }
}

const fn actions_of(id: ModuleId) -> &'static [ActionClass] {
    match id {
        ModuleId::EnfNetEgress => &[
            ActionClass::Isolate,
            ActionClass::ProcBlock,
            ActionClass::DestBlock,
        ],
        ModuleId::EnfNetIngress => &[ActionClass::IsolateInbound],
        ModuleId::EnfProc => &[ActionClass::Kill, ActionClass::Suspend],
        ModuleId::EnfAccount => &[
            ActionClass::SessionKill,
            ActionClass::TicketPurge,
            ActionClass::AccountDisable,
            ActionClass::CredRotate,
            ActionClass::GroupDrop,
        ],
        ModuleId::EnfExec => &[ActionClass::ExecBlock],
        ModuleId::EnfPersistence => &[ActionClass::PersistenceNeutralize, ActionClass::ServiceStart],
        ModuleId::EnfFile => &[ActionClass::Quarantine],
        ModuleId::EnfPerimeter => &[ActionClass::PerimeterBlock],
        ModuleId::EnfPerimeterKill => &[ActionClass::PerimeterStateKill],
        ModuleId::HardenNoReboot => &[ActionClass::Harden],
        ModuleId::Deceive => &[ActionClass::Deception],
        ModuleId::Sidecar => &[ActionClass::SidecarInstall],
        ModuleId::Collect => &[ActionClass::Collect],
        ModuleId::Acquire => &[ActionClass::Acquire],

        _ => &[],
    }
}
