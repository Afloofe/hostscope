use std::path::PathBuf;

use crate::action::RemovalAction;

#[derive(Debug, Clone)]
pub struct ApplyOptions {

    pub armed: bool,

    pub vault_dir: PathBuf,
}

pub const DEFAULT_VAULT: &str = "/var/lib/hemostat/quarantine";

impl Default for ApplyOptions {
    fn default() -> Self {
        ApplyOptions { armed: false, vault_dir: PathBuf::from(DEFAULT_VAULT) }
    }
}

impl ApplyOptions {

    pub fn dry_run() -> Self {
        ApplyOptions::default()
    }

    pub fn armed() -> Self {
        ApplyOptions { armed: true, ..ApplyOptions::default() }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {

    pub summary: String,

    pub detail: String,

    pub undo: String,

    pub reversible: bool,

    pub prefer_instead: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtectReason {

    InitProcess,

    KernelThread,

    UnreadableTarget,

    ServiceListener,

    OperatorSession,

    HostNetwork,

    ScoredService(String),

    AgentSelf,

    UnitEnablement,

    IncompleteListenerMap,

    OperatorDeclared,

    OutOfScopeAccount,

    DeclarationsUnreadable,

    InfrastructureProcess,

    InfrastructureHost,
}

pub(crate) fn override_hint(reason: &ProtectReason, unit: &str) -> String {
    match reason {
        ProtectReason::ServiceListener => format!(
            "\n        If you have checked {unit} and it is not a service this host is scored \
             on, clear it by name: --allow-listener {unit}"
        ),
        ProtectReason::ScoredService(service) => {
            format!("\n        the packet's scored service on this box: {service} (`{unit}` runs it)")
        }
        _ => String::new(),
    }
}

impl ProtectReason {

    pub fn describe(&self) -> &'static str {
        match self {
            ProtectReason::InitProcess => "it is PID 1 or PID 2 (init / kthreadd)",
            ProtectReason::KernelThread => {
                "it is a kernel thread (no /proc/<pid>/exe and no command line)"
            }
            ProtectReason::UnreadableTarget => {
                "/proc/<pid> could not be read well enough to say what it is — it may have \
                 exited, or belong to another user. This is 'could not look', not 'it is \
                 harmless': re-run as root, or re-scan and try again"
            }
            ProtectReason::ServiceListener => {
                "it owns a listening socket — a scored service must never be killed, \
                 suspended, or masked"
            }
            ProtectReason::OperatorSession => {
                "it is part of the operator's own SSH session chain, or the ssh/sshd unit — \
                 acting on it would cut the responder off the host"
            }
            ProtectReason::HostNetwork => {
                "it is one of the units that bring the host's network up (networking, \
                 systemd-networkd, NetworkManager, network, systemd-resolved, wicked, ifup@), or \
                 its unit file or a drop-in of it — stopping, disabling or masking it, or moving \
                 the file away, takes the host off the network, and every scored service and \
                 remote session with it. No flag or declaration clears this: if it must change, a \
                 person changes it by hand, from a console that does not need the network"
            }
            ProtectReason::ScoredService(_) => {
                "it runs the packet's scored service on this box, or it is a file of a unit that \
                 does (HEMOSTAT_GOLDEN is set, and the packet gives this box's role — its \
                 hostname, or HEMOSTAT_ROLE — that service). Stopping, disabling or masking it, \
                 moving the file away, or killing or blocking what it runs takes the service \
                 down, and while it is down no listening socket is there to protect it. No flag \
                 or declaration clears this: fix it by hand and keep the service up — restore a \
                 tampered unit from its package (`rpm -V` or `dpkg -V` shows what differs), or \
                 take an added drop-in or line out — and `services --restore --arm` brings the \
                 service back if it is down"
            }
            ProtectReason::AgentSelf => "it is HEMOSTAT itself",
            ProtectReason::UnitEnablement => {
                "it is a systemd enablement symlink — removing it disables the unit it points \
                 at (getty, NetworkManager, logind, local-fs mounts live here) rather than \
                 removing persistence. Stopping the unit already clears its enablement"
            }
            ProtectReason::OperatorDeclared => {
                "the operator declared it off-limits for this host — `--protect`, or a line \
                 in /etc/hemostat/protect or /etc/hemostat/critical"
            }
            ProtectReason::OutOfScopeAccount => {
                "it is an account HEMOSTAT never changes on any host: the white team's own \
                 login (whiteteam keeps its access at all times) or one of the DataDog \
                 agent's (dd-agent, ddagentuser, datadog), which are out of scope. No flag or \
                 declaration clears this — if it really must change, a person changes it by \
                 hand"
            }
            ProtectReason::InfrastructureProcess => {
                "it is an HA daemon, a backup agent or an EDR (design §11.9.2). Killing a \
                 corosync or keepalived gets the node fenced or fails its resources over; \
                 killing the EDR mid-incident is almost always wrong. Suspend it instead"
            }
            ProtectReason::InfrastructureHost => {
                "this host runs a cluster daemon, and a kill here needs dual control (design \
                 §11.9.2), which this build does not have. A node whose process tree changes \
                 under a heartbeat can be fenced by its peers. Suspend instead"
            }
            ProtectReason::DeclarationsUnreadable => {
                "/etc/hemostat/protect exists and could not be read, so what this host was \
                 declared to keep is not known. Treating that as `nothing is protected` is how \
                 a break-glass account or a scored service gets removed by a run that was told \
                 not to — re-run with access to the file"
            }
            ProtectReason::IncompleteListenerMap => {
                "the listening-socket map could not be read, so this unit cannot be shown not \
                 to be a scored service — re-run as root before arming"
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RefuseCause {

    Protected(ProtectReason),

    FrozenTargetMismatch {

        expected: String,

        found: String,
    },

    InvalidTarget(String),

    UnverifiedProtectSet,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {

    pub action: String,

    pub cause: RefuseCause,

    pub message: String,

    pub suggested_alternative: Option<RemovalAction>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UndoKind {

    Nothing,

    RestoreBootParams {

        vault: PathBuf,

        original: PathBuf,

        generator: String,

        output: PathBuf,
    },

    RemoveCanary {

        path: PathBuf,
    },

    RemoveNftAllow {

        family: String,

        table: String,

        chain: String,

        comment: String,
    },

    UnmountExecBlock {

        path: PathBuf,
    },

    RejoinGroup {

        user: String,

        group: String,
    },

    RestorePasswordAge {

        user: String,

        last_change: String,
    },

    ResumeProcess {

        pid: u32,

        start_time: u64,
    },

    UnmaskService {

        unit: String,

        was_active: Option<bool>,
    },

    RestoreServiceState {

        unit: String,

        was_enabled: Option<bool>,

        was_active: Option<bool>,
    },

    RestoreFile {

        vault: PathBuf,

        original: PathBuf,

        moved: bool,
    },

    RestoreUnit {

        vault: PathBuf,

        original: PathBuf,

        unit: String,
    },

    RestoreMode {

        path: PathBuf,

        mode: u32,
    },

    UnlockAccount {

        user: String,

        shell: Option<String>,

        was_locked: Option<bool>,
    },

    RemoveCreatedFile {

        vault: PathBuf,

        original: PathBuf,
    },

    RestoreSysctl {

        was: Vec<(String, String)>,
    },

    RestoreStripped {

        vault: PathBuf,

        original: PathBuf,

        line_no: usize,

        line_sha256: String,

        before: String,

        after: String,

        mode: u32,

        uid: u32,

        gid: u32,
    },

    RestoreAnchor {

        vault: PathBuf,

        original: PathBuf,

        cert_sha256: String,

        before: String,

        after: String,

        mode: u32,

        uid: u32,

        gid: u32,

        rebuild: String,

        bundle_before: String,
    },

    Irreversible {

        note: String,
    },
}

impl UndoKind {

    pub const fn token(&self) -> &'static str {
        match self {
            UndoKind::ResumeProcess { .. } => "resume-process",
            UndoKind::UnmaskService { .. } => "unmask-service",
            UndoKind::RestoreServiceState { .. } => "restore-service-state",
            UndoKind::RestoreFile { .. } => "restore-file",
            UndoKind::RestoreUnit { .. } => "restore-unit",
            UndoKind::RestoreMode { .. } => "restore-mode",
            UndoKind::UnlockAccount { .. } => "unlock-account",
            UndoKind::RemoveCreatedFile { .. } => "remove-created-file",
            UndoKind::RestoreSysctl { .. } => "restore-sysctl",
            UndoKind::Irreversible { .. } => "irreversible",
            UndoKind::Nothing => "nothing",
            UndoKind::UnmountExecBlock { .. } => "unmount-exec-block",
            UndoKind::RemoveCanary { .. } => "remove-canary",
            UndoKind::RemoveNftAllow { .. } => "remove-nft-allow",
            UndoKind::RestoreBootParams { .. } => "restore-boot-params",
            UndoKind::RejoinGroup { .. } => "rejoin-group",
            UndoKind::RestorePasswordAge { .. } => "restore-password-age",
            UndoKind::RestoreStripped { .. } => "restore-stripped",
            UndoKind::RestoreAnchor { .. } => "restore-anchor",
        }
    }

    pub const ALL_TOKENS: [&'static str; 18] = [
        "resume-process",
        "unmask-service",
        "restore-file",
        "restore-unit",
        "restore-mode",
        "unlock-account",
        "remove-created-file",
        "restore-sysctl",
        "irreversible",
        "nothing",
        "rejoin-group",
        "restore-password-age",
        "unmount-exec-block",
        "restore-boot-params",
        "remove-canary",
        "remove-nft-allow",
        "restore-stripped",
        "restore-anchor",
    ];
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UndoRecord {

    pub did: String,

    pub undo: UndoKind,

    pub reversible: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Failure {

    pub action: String,

    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {

    Planned(Plan),

    Applied(UndoRecord),

    Refused(Refusal),

    Failed(Failure),
}
