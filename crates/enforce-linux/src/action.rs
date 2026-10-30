use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PersistKind {

    Cron,

    SystemdUnit,

    ShellInit,

    Other(String),
}

impl PersistKind {
    pub(crate) fn label(&self) -> String {
        match self {
            PersistKind::Cron => "cron persistence".into(),
            PersistKind::SystemdUnit => "systemd-unit persistence".into(),
            PersistKind::ShellInit => "shell-init persistence".into(),
            PersistKind::Other(s) => format!("{s} persistence"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModuleSighting {

    Sysfs,

    KernelListOnly,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RemovalAction {

    KillProcess {

        pid: u32,

        start_time: u64,

        exe: Option<String>,
    },

    SuspendProcess {

        pid: u32,

        start_time: u64,

        exe: Option<String>,
    },

    UnloadModule {

        name: String,

        seen: ModuleSighting,
    },

    MaskService {

        unit: String,
    },

    StartService {

        unit: String,
    },

    AllowInboundPort {

        port: u16,
    },

    StopAndRemoveUnit {

        unit: String,

        path: PathBuf,
    },

    DisablePersistence {

        path: PathBuf,

        kind: PersistKind,
    },

    QuarantineFile {

        path: PathBuf,
    },

    RemoveLdPreload {

        path: PathBuf,

        entry: Option<String>,
    },

    StripLine {

        path: PathBuf,

        line: crate::strip::LineRef,

        authority: crate::strip::StripAuthority,
    },

    RemoveAnchor {

        path: PathBuf,

        anchor: crate::anchor::AnchorRef,
    },

    RestoreKnownGood {

        path: PathBuf,

        content: Vec<u8>,

        want_sha256: String,

        label: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProcVerb {
    Kill,
    Suspend,
}
