#![forbid(unsafe_code)]

use core::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Status {

    Full,

    Partial,

    DetectOnly,

    NotInV1,

    NotBuilt,
}

impl Status {

    pub const fn token(self) -> &'static str {
        match self {
            Status::Full => "FULL",
            Status::Partial => "PARTIAL",
            Status::DetectOnly => "DETECT-ONLY",
            Status::NotInV1 => "NOT-IN-V1",
            Status::NotBuilt => "NOT-BUILT",
        }
    }
}

impl fmt::Display for Status {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad(self.token())
    }
}

#[allow(missing_docs)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ActionClass {

    Isolate,
    IsolateInbound,
    ProcBlock,
    DestBlock,

    Kill,
    Suspend,
    SessionKill,

    TicketPurge,
    AccountDisable,
    CredRotate,
    GroupDrop,

    ExecBlock,
    PersistenceNeutralize,

    Quarantine,

    Harden,
    Allowlist,
    Deception,
    SidecarInstall,

    Collect,
    Acquire,

    Lift,
    Uninstall,

    PerimeterBlock,
    PerimeterStateKill,

    ServiceStart,
}

impl ActionClass {

    pub const ALL: [ActionClass; 25] = [
        ActionClass::Isolate,
        ActionClass::IsolateInbound,
        ActionClass::ProcBlock,
        ActionClass::DestBlock,
        ActionClass::Kill,
        ActionClass::Suspend,
        ActionClass::SessionKill,
        ActionClass::TicketPurge,
        ActionClass::AccountDisable,
        ActionClass::CredRotate,
        ActionClass::GroupDrop,
        ActionClass::ExecBlock,
        ActionClass::PersistenceNeutralize,
        ActionClass::Quarantine,
        ActionClass::Harden,
        ActionClass::Allowlist,
        ActionClass::Deception,
        ActionClass::SidecarInstall,
        ActionClass::Collect,
        ActionClass::Acquire,
        ActionClass::Lift,
        ActionClass::Uninstall,
        ActionClass::PerimeterBlock,
        ActionClass::PerimeterStateKill,
        ActionClass::ServiceStart,
    ];

    pub const fn name(self) -> &'static str {
        match self {
            ActionClass::Isolate => "Isolate",
            ActionClass::IsolateInbound => "IsolateInbound",
            ActionClass::ProcBlock => "ProcBlock",
            ActionClass::DestBlock => "DestBlock",
            ActionClass::Kill => "Kill",
            ActionClass::Suspend => "Suspend",
            ActionClass::SessionKill => "SessionKill",
            ActionClass::TicketPurge => "TicketPurge",
            ActionClass::AccountDisable => "AccountDisable",
            ActionClass::CredRotate => "CredRotate",
            ActionClass::GroupDrop => "GroupDrop",
            ActionClass::ExecBlock => "ExecBlock",
            ActionClass::PersistenceNeutralize => "PersistenceNeutralize",
            ActionClass::Quarantine => "Quarantine",
            ActionClass::Harden => "Harden",
            ActionClass::Allowlist => "Allowlist",
            ActionClass::Deception => "Deception",
            ActionClass::SidecarInstall => "SidecarInstall",
            ActionClass::Collect => "Collect",
            ActionClass::Acquire => "Acquire",
            ActionClass::Lift => "Lift",
            ActionClass::Uninstall => "Uninstall",
            ActionClass::PerimeterBlock => "PerimeterBlock",
            ActionClass::PerimeterStateKill => "PerimeterStateKill",
            ActionClass::ServiceStart => "ServiceStart",
        }
    }

    pub const fn is_mandatory(self) -> bool {
        match self {
            ActionClass::Allowlist | ActionClass::Lift | ActionClass::Uninstall => true,
            ActionClass::Isolate
            | ActionClass::IsolateInbound
            | ActionClass::ProcBlock
            | ActionClass::DestBlock
            | ActionClass::Kill
            | ActionClass::Suspend
            | ActionClass::SessionKill
            | ActionClass::TicketPurge
            | ActionClass::AccountDisable
            | ActionClass::CredRotate
            | ActionClass::GroupDrop
            | ActionClass::ExecBlock
            | ActionClass::PersistenceNeutralize
            | ActionClass::Quarantine
            | ActionClass::Harden
            | ActionClass::Deception
            | ActionClass::SidecarInstall
            | ActionClass::Collect
            | ActionClass::Acquire
            | ActionClass::PerimeterBlock
            | ActionClass::PerimeterStateKill
            | ActionClass::ServiceStart => false,
        }
    }
}

impl fmt::Display for ActionClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad(self.name())
    }
}

#[allow(missing_docs)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ModuleId {

    SensorEtw,
    SensorEvtlog,
    SensorUsn,
    SensorSysmon,
    SensorWmi,
    SensorEbpf,
    SensorFanotify,
    SensorAudit,

    DetectSigma,
    Correlation,
    ScanYara,
    Query,
    QueryMemory,

    EnfNetEgress,
    EnfNetIngress,
    EnfProc,
    EnfAccount,
    EnfExec,
    EnfPersistence,
    EnfFile,

    EnfPerimeter,
    EnfPerimeterKill,

    HardenNoReboot,
    HardenReboot,
    Deceive,
    Sidecar,
    Collect,
    Acquire,

    Tui,
    Remote,
    Collector,
    ExportStix,
    ExportMisp,
    ExportJsonl,
    ExportReport,
    VerifyEmbedded,

    Tamper,
    SelfprotectLsm,
    Selfsandbox,
    OnBoxKey,
    DriverTier,
}

impl ModuleId {

    pub const fn feature(self) -> &'static str {
        match self {
            ModuleId::SensorEtw => "mod-sensor-etw",
            ModuleId::SensorEvtlog => "mod-sensor-evtlog",
            ModuleId::SensorUsn => "mod-sensor-usn",
            ModuleId::SensorSysmon => "mod-sensor-sysmon",
            ModuleId::SensorWmi => "mod-sensor-wmi",
            ModuleId::SensorEbpf => "mod-sensor-ebpf",
            ModuleId::SensorFanotify => "mod-sensor-fanotify",
            ModuleId::SensorAudit => "mod-sensor-audit",
            ModuleId::DetectSigma => "mod-detect-sigma",
            ModuleId::Correlation => "mod-correlation",
            ModuleId::ScanYara => "mod-scan-yara",
            ModuleId::Query => "mod-query",
            ModuleId::QueryMemory => "mod-query-memory",
            ModuleId::EnfNetEgress => "mod-enf-net-egress",
            ModuleId::EnfNetIngress => "mod-enf-net-ingress",
            ModuleId::EnfProc => "mod-enf-proc",
            ModuleId::EnfAccount => "mod-enf-account",
            ModuleId::EnfExec => "mod-enf-exec",
            ModuleId::EnfPersistence => "mod-enf-persistence",
            ModuleId::EnfFile => "mod-enf-file",
            ModuleId::EnfPerimeter => "mod-enf-perimeter",
            ModuleId::EnfPerimeterKill => "mod-enf-perimeter-kill",
            ModuleId::HardenNoReboot => "mod-harden-noreboot",
            ModuleId::HardenReboot => "mod-harden-reboot",
            ModuleId::Deceive => "mod-deceive",
            ModuleId::Sidecar => "mod-sidecar",
            ModuleId::Collect => "mod-collect",
            ModuleId::Acquire => "mod-acquire",
            ModuleId::Tui => "mod-tui",
            ModuleId::Remote => "mod-remote",
            ModuleId::Collector => "mod-collector",
            ModuleId::ExportStix => "mod-export-stix",
            ModuleId::ExportMisp => "mod-export-misp",
            ModuleId::ExportJsonl => "mod-export-jsonl",
            ModuleId::ExportReport => "mod-export-report",
            ModuleId::VerifyEmbedded => "mod-verify-embedded",
            ModuleId::Tamper => "mod-tamper",
            ModuleId::SelfprotectLsm => "mod-selfprotect-lsm",
            ModuleId::Selfsandbox => "mod-selfsandbox",
            ModuleId::OnBoxKey => "mod-on-box-key",
            ModuleId::DriverTier => "driver-tier",
        }
    }
}

impl fmt::Display for ModuleId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad(self.feature())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModuleDescriptor {

    pub id: ModuleId,

    pub status: Status,

    pub provides_actions: &'static [ActionClass],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuildManifest {

    pub manifest_ver: u16,

    pub variant: &'static str,

    pub modules: &'static [ModuleDescriptor],

    pub toolchain: &'static str,

    pub source_date_epoch: u64,

    pub source_rev: &'static str,

    pub source_dirty: bool,
}

impl BuildManifest {

    pub fn is_built(&self, id: ModuleId) -> bool {
        self.modules
            .iter()
            .any(|m| m.id == id && m.status != Status::NotBuilt)
    }

    pub fn action_status(&self, class: ActionClass) -> Status {
        if class.is_mandatory() {
            return Status::Full;
        }
        for m in self.modules {
            if m.provides_actions.contains(&class) {
                return m.status;
            }
        }
        Status::NotBuilt
    }

    pub fn built(&self) -> impl Iterator<Item = &ModuleDescriptor> {
        self.modules.iter().filter(|m| m.status != Status::NotBuilt)
    }

    pub fn to_json(&self) -> String {
        let mut s = String::with_capacity(2048);
        s.push('{');
        push_kv_num(&mut s, "manifest_ver", self.manifest_ver as u64);
        s.push(',');
        push_kv_str(&mut s, "variant", self.variant);
        s.push(',');
        push_kv_str(&mut s, "toolchain", self.toolchain);
        s.push(',');
        push_kv_num(&mut s, "source_date_epoch", self.source_date_epoch);
        s.push(',');
        push_kv_str(&mut s, "source_rev", self.source_rev);
        s.push(',');
        s.push_str("\"source_dirty\":");
        s.push_str(if self.source_dirty { "true" } else { "false" });
        s.push(',');
        s.push_str("\"modules\":[");
        for (i, m) in self.modules.iter().enumerate() {
            if i > 0 {
                s.push(',');
            }
            s.push('{');
            push_kv_str(&mut s, "id", m.id.feature());
            s.push(',');
            push_kv_str(&mut s, "status", m.status.token());
            s.push(',');
            s.push_str("\"provides_actions\":[");
            for (j, a) in m.provides_actions.iter().enumerate() {
                if j > 0 {
                    s.push(',');
                }
                push_json_str(&mut s, a.name());
            }
            s.push_str("]}");
        }
        s.push_str("]}");
        s
    }
}

fn push_kv_str(s: &mut String, k: &str, v: &str) {
    push_json_str(s, k);
    s.push(':');
    push_json_str(s, v);
}

fn push_kv_num(s: &mut String, k: &str, v: u64) {
    push_json_str(s, k);
    s.push(':');
    s.push_str(&v.to_string());
}

fn push_json_str(s: &mut String, v: &str) {
    s.push('"');
    for c in v.chars() {
        match c {
            '"' => s.push_str("\\\""),
            '\\' => s.push_str("\\\\"),
            '\n' => s.push_str("\\n"),
            '\r' => s.push_str("\\r"),
            '\t' => s.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                s.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => s.push(c),
        }
    }
    s.push('"');
}
