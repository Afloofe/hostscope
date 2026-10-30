use crate::identity::Origin;
use crate::lane::Lane;
use crate::time::Stamp;
use core::fmt;

pub const MAX_FIELD_BYTES: usize = 8 * 1024;

pub const CUT_MARK: &str = "\u{2026}";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FieldName(&'static str);

impl FieldName {

    pub const fn new(name: &'static str) -> Self {
        Self(name)
    }

    pub const fn as_str(self) -> &'static str {
        self.0
    }
}

impl fmt::Display for FieldName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

pub mod fields {
    use super::FieldName;

    pub const IMAGE: FieldName = FieldName::new("Image");

    pub const COMMAND_LINE: FieldName = FieldName::new("CommandLine");

    pub const USER: FieldName = FieldName::new("User");

    pub const PROCESS_ID: FieldName = FieldName::new("ProcessId");

    pub const PARENT_PROCESS_ID: FieldName = FieldName::new("ParentProcessId");

    pub const PARENT_IMAGE: FieldName = FieldName::new("ParentImage");

    pub const PARENT_COMMAND_LINE: FieldName = FieldName::new("ParentCommandLine");

    pub const INTEGRITY_LEVEL: FieldName = FieldName::new("IntegrityLevel");

    pub const ALL: &[FieldName] = &[
        IMAGE,
        COMMAND_LINE,
        USER,
        PROCESS_ID,
        PARENT_PROCESS_ID,
        PARENT_IMAGE,
        PARENT_COMMAND_LINE,
        INTEGRITY_LEVEL,
    ];

    pub const PROCFS: &[FieldName] = &[IMAGE, COMMAND_LINE, USER, PROCESS_ID, PARENT_PROCESS_ID];

    pub const WINDOWS_PROCESS: &[FieldName] = &[
        IMAGE,
        COMMAND_LINE,
        USER,
        PROCESS_ID,
        PARENT_PROCESS_ID,
        PARENT_IMAGE,
        PARENT_COMMAND_LINE,
        INTEGRITY_LEVEL,
    ];

    pub const HERE: &[FieldName] = if cfg!(target_os = "windows") { WINDOWS_PROCESS } else { PROCFS };

    #[must_use]
    pub fn is_known(name: &str) -> bool {
        HERE.iter().any(|f| f.as_str().eq_ignore_ascii_case(name))
    }

    pub const DESTINATION_IP: FieldName = FieldName::new("DestinationIp");

    pub const DESTINATION_PORT: FieldName = FieldName::new("DestinationPort");

    pub const TARGET_FILENAME: FieldName = FieldName::new("TargetFilename");

    pub const TARGET_OBJECT: FieldName = FieldName::new("TargetObject");
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FieldValue {

    Str(String),

    U64(u64),

    I64(i64),

    Bool(bool),
}

impl fmt::Display for FieldValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FieldValue::Str(s) => f.write_str(s),
            FieldValue::U64(v) => write!(f, "{v}"),
            FieldValue::I64(v) => write!(f, "{v}"),
            FieldValue::Bool(v) => write!(f, "{v}"),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FieldMap {
    entries: Vec<(FieldName, FieldValue)>,
    truncated: bool,
}

impl FieldMap {

    pub const fn new() -> Self {
        Self {
            entries: Vec::new(),
            truncated: false,
        }
    }

    pub fn insert(&mut self, name: FieldName, value: FieldValue) {
        let value = match value {
            FieldValue::Str(s) if s.len() > MAX_FIELD_BYTES => {
                self.truncated = true;
                FieldValue::Str(head_and_tail(&s))
            }
            other => other,
        };
        match self.entries.iter_mut().find(|(n, _)| *n == name) {
            Some(slot) => slot.1 = value,
            None => self.entries.push((name, value)),
        }
    }

    pub fn get(&self, name: FieldName) -> Option<&FieldValue> {
        self.entries
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, v)| v)
    }

    pub const fn truncated(&self) -> bool {
        self.truncated
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = &(FieldName, FieldValue)> {
        self.entries.iter()
    }
}

fn head_and_tail(s: &str) -> String {
    let room = MAX_FIELD_BYTES - CUT_MARK.len();
    let mut head = room / 2;
    while head > 0 && !s.is_char_boundary(head) {
        head -= 1;
    }

    let mut tail = s.len().saturating_sub(room - head);
    while tail < s.len() && !s.is_char_boundary(tail) {
        tail += 1;
    }
    let mut out = String::with_capacity(MAX_FIELD_BYTES);
    out.push_str(s.get(..head).unwrap_or_default());
    out.push_str(CUT_MARK);
    out.push_str(s.get(tail..).unwrap_or_default());
    out
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Provenance {

    EtwKernel,

    Sysmon(u16),

    EventLog(u16),

    Ebpf,

    Audit,

    Procfs,

    Agent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EventKind {

    ProcessCreate,

    ProcessExit,

    ImageLoad,

    NetworkConnect,

    DnsQuery,

    FileWrite,

    FileDelete,

    RegistrySet,

    Logon,

    Tamper,

    AgentAction,
}

impl EventKind {

    pub const fn logsource_category(self) -> &'static str {
        match self {
            EventKind::ProcessCreate => "process_creation",
            EventKind::ProcessExit => "process_termination",
            EventKind::ImageLoad => "image_load",
            EventKind::NetworkConnect => "network_connection",
            EventKind::DnsQuery => "dns_query",
            EventKind::FileWrite => "file_event",
            EventKind::FileDelete => "file_delete",
            EventKind::RegistrySet => "registry_set",
            EventKind::Logon => "authentication",

            EventKind::Tamper => "hemostat_tamper",
            EventKind::AgentAction => "hemostat_action",
        }
    }

    pub const fn default_lane(self) -> Lane {
        match self {
            EventKind::Tamper | EventKind::AgentAction => Lane::P0,
            _ => Lane::P2,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Event {

    pub seq: u64,

    pub stamp: Stamp,

    pub origin: Origin,

    pub lane: Lane,

    pub kind: EventKind,

    pub provenance: Provenance,

    pub fields: FieldMap,
}

impl Event {

    pub const fn truncated(&self) -> bool {
        self.fields.truncated()
    }

    pub const fn logsource_category(&self) -> &'static str {
        self.kind.logsource_category()
    }
}
