use hs_core::Trust;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flag {

    On,

    Off,

    Unreadable,
}

impl Flag {

    pub fn token(self) -> &'static str {
        match self {
            Flag::On => "on",
            Flag::Off => "off",
            Flag::Unreadable => "unreadable",
        }
    }

    pub fn from_dword(reading: Reading, zero_is: Flag, absent_is: Flag) -> Flag {
        match reading {
            Reading::Unreadable => Flag::Unreadable,
            Reading::Absent => absent_is,
            Reading::Value(0) => zero_is,
            Reading::Value(_) => match zero_is {
                Flag::On => Flag::Off,
                _ => Flag::On,
            },
        }
    }

    pub fn from_enum(reading: Reading, on: &[u32], off: &[u32], absent_is: Flag) -> Flag {
        match reading {
            Reading::Unreadable => Flag::Unreadable,
            Reading::Absent => absent_is,
            Reading::Value(v) if on.contains(&v) => Flag::On,
            Reading::Value(v) if off.contains(&v) => Flag::Off,
            Reading::Value(_) => Flag::Unreadable,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reading {

    Value(u32),

    Absent,

    Unreadable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Integrity {

    Unknown,

    Low,

    Medium,

    High,

    System,
}

impl Integrity {

    pub fn token(self) -> &'static str {
        match self {
            Integrity::Unknown => "unknown",
            Integrity::Low => "low",
            Integrity::Medium => "medium",
            Integrity::High => "high",
            Integrity::System => "system",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Facts {

    pub integrity: Integrity,

    pub elevated: Flag,

    pub se_debug: Flag,

    pub se_load_driver: Flag,

    pub se_backup: Flag,

    pub se_security: Flag,

    pub secure_boot: Flag,

    pub vbs: Flag,

    pub defender_rtp_observed: bool,

    pub hvci: Flag,

    pub driver_blocklist: Flag,

    pub driver_blocklist_basis: Option<String>,

    pub lsa_ppl: Flag,

    pub wdigest_plaintext: Flag,

    pub defender_rtp: Flag,

    pub defender_tamper: Flag,

    pub notes: Vec<String>,
}

impl Facts {

    pub fn unreadable(&self) -> Vec<&'static str> {
        [
            ("elevated", self.elevated),
            ("SeDebugPrivilege", self.se_debug),
            ("SeLoadDriverPrivilege", self.se_load_driver),
            ("SeBackupPrivilege", self.se_backup),
            ("SeSecurityPrivilege", self.se_security),
            ("Secure Boot", self.secure_boot),
            ("VBS", self.vbs),
            ("HVCI", self.hvci),
            ("vulnerable-driver blocklist", self.driver_blocklist),
            ("LSA protected process", self.lsa_ppl),
            ("WDigest plaintext caching", self.wdigest_plaintext),
            ("Defender real-time protection", self.defender_rtp),
            ("Defender tamper protection", self.defender_tamper),
        ]
        .into_iter()
        .filter(|(_, f)| matches!(f, Flag::Unreadable))
        .map(|(name, _)| name)
        .collect()
    }
}

pub const BLOCKLIST_DEFAULT_ON_BUILD: u32 = 22_621;

pub fn infer_blocklist(build: Option<u32>, hvci: Flag) -> (Flag, Option<String>) {
    const NO_VALUE: &str = "INFERRED, not read: VulnerableDriverBlocklistEnable is absent and \
                            Windows reports the policy's state nowhere this can read";
    match (hvci, build) {
        (Flag::On, _) => (
            Flag::On,
            Some(format!("{NO_VALUE}; HVCI is on, and Windows enforces the blocklist whenever it is")),
        ),
        (_, Some(b)) if b >= BLOCKLIST_DEFAULT_ON_BUILD => (
            Flag::On,
            Some(format!(
                "{NO_VALUE}; build {b} enforces it by default (Windows 11 22H2, build \
                 {BLOCKLIST_DEFAULT_ON_BUILD}, and later)"
            )),
        ),
        (Flag::Off, Some(b)) => (
            Flag::Off,
            Some(format!(
                "{NO_VALUE}; build {b} predates default enforcement (build \
                 {BLOCKLIST_DEFAULT_ON_BUILD}) and HVCI is off, and before that build Windows \
                 enforces it only with HVCI, Smart App Control or S mode"
            )),
        ),
        _ => (Flag::Unreadable, None),
    }
}

impl Default for Facts {
    fn default() -> Self {
        Facts {
            integrity: Integrity::Unknown,
            elevated: Flag::Unreadable,
            se_debug: Flag::Unreadable,
            se_load_driver: Flag::Unreadable,
            se_backup: Flag::Unreadable,
            se_security: Flag::Unreadable,
            secure_boot: Flag::Unreadable,
            vbs: Flag::Unreadable,
            defender_rtp_observed: false,
            hvci: Flag::Unreadable,
            driver_blocklist: Flag::Unreadable,
            driver_blocklist_basis: None,
            lsa_ppl: Flag::Unreadable,
            wdigest_plaintext: Flag::Unreadable,
            defender_rtp: Flag::Unreadable,
            defender_tamper: Flag::Unreadable,
            notes: Vec::new(),
        }
    }
}

impl Facts {

    pub fn trust(&self) -> Trust {
        Trust::Syscall
    }
}
