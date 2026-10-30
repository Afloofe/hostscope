mod bounds;
mod catalogue;
mod judge;
#[cfg(target_os = "windows")]
mod read;
mod shapes;
mod task;

pub use catalogue::CATALOGUE;
pub use judge::{
    assemble, assemble_with, defender_driver_path, judge, judge_entry, judge_winrm, judge_with,
    lower_defender_driver, ImageEvidence,
};
pub use shapes::{loud_arguments, names_interpreter, under_writable};
pub use task::{decode_task, task_commands};

use crate::posture::Finding;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Category {

    Logon,

    Service,

    Scheduled,

    Injection,

    Boot,
}

impl Category {

    pub const fn token(self) -> &'static str {
        match self {
            Category::Logon => "logon",
            Category::Service => "service",
            Category::Scheduled => "scheduled",
            Category::Injection => "injection",
            Category::Boot => "boot",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Coverage {

    Clean,

    Populated,

    Partial,

    Unreadable,

    NotPresent,
}

impl Coverage {

    pub const fn token(self) -> &'static str {
        match self {
            Coverage::Clean => "clean",
            Coverage::Populated => "populated",
            Coverage::Partial => "partial",
            Coverage::Unreadable => "unreadable",
            Coverage::NotPresent => "not-present",
        }
    }

    pub const fn established(self) -> bool {
        !matches!(self, Coverage::Unreadable | Coverage::Partial)
    }

    pub const fn of(found: usize, refused: usize, present: bool) -> Self {
        if !present {
            Coverage::NotPresent
        } else if refused > 0 && found == 0 {
            Coverage::Unreadable
        } else if refused > 0 {
            Coverage::Partial
        } else if found == 0 {
            Coverage::Clean
        } else {
            Coverage::Populated
        }
    }
}

#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
pub(super) fn multi_strings(data: &[u16]) -> Vec<String> {
    let members: Vec<String> = data
        .split(|c| *c == 0)
        .filter(|m| !m.is_empty())
        .map(String::from_utf16_lossy)
        .collect();
    if members.is_empty() {
        vec![String::new()]
    } else {
        members
    }
}

#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
pub(super) fn is_user_hive(name: &str) -> bool {
    !name.to_ascii_lowercase().ends_with("_classes")
}

#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
pub(super) fn key_refusal(locus: &str, rc: u32) -> Option<String> {
    (rc != crate::reg::ABSENT).then(|| format!("{locus} (error {rc})"))
}

#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
pub(super) fn dir_refusal(locus: &str, e: &std::io::Error) -> Option<String> {
    (e.kind() != std::io::ErrorKind::NotFound).then(|| format!("{locus}: {e}"))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {

    pub mechanism: &'static str,

    pub category: Category,

    pub locus: String,

    pub name: String,

    pub command: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observation {

    pub id: &'static str,

    pub name: &'static str,

    pub category: Category,

    pub coverage: Coverage,

    pub entries: usize,

    pub refused: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Report {

    pub observations: Vec<Observation>,

    pub entries: Vec<Entry>,

    pub findings: Vec<Finding>,

    pub established: usize,

    pub total: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Probe {

    KeyValues(&'static str),

    NamedValues(&'static str, &'static [&'static str]),

    SubkeyValue(&'static str, &'static str),

    UserValues(&'static str, &'static [&'static str]),

    TaskFiles(&'static str),

    Directory(&'static str),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Mechanism {

    pub id: &'static str,

    pub name: &'static str,

    pub category: Category,

    pub probe: Probe,
}

#[cfg(not(target_os = "windows"))]
pub fn report() -> Report {
    let observations = CATALOGUE
        .iter()
        .map(|m| Observation {
            id: m.id,
            name: m.name,
            category: m.category,
            coverage: Coverage::Unreadable,
            entries: 0,
            refused: vec!["this binary was not built for Windows".into()],
        })
        .collect();
    assemble(Vec::new(), observations)
}

#[cfg(target_os = "windows")]
pub fn report() -> Report {
    let mut entries = Vec::new();
    let mut observations = Vec::new();
    for m in CATALOGUE {
        let (found, refused, present) = read::mechanism(m);
        let coverage = Coverage::of(found.len(), refused.len(), present);
        observations.push(Observation {
            id: m.id,
            name: m.name,
            category: m.category,
            coverage,
            entries: found.len(),
            refused,
        });
        entries.extend(found);
    }
    let images = defender_images(&entries);
    assemble_with(entries, observations, &images)
}

#[cfg(target_os = "windows")]
fn defender_images(entries: &[Entry]) -> std::collections::BTreeMap<String, ImageEvidence> {
    let mut out = std::collections::BTreeMap::new();
    let Ok(program_data) = std::env::var("ProgramData") else { return out };
    let root = format!(r"{}\Microsoft\Windows Defender", program_data.trim_end_matches('\\'));
    for e in entries.iter().filter(|e| e.mechanism == "services") {
        let Some(path) = defender_driver_path(&e.command, &root) else { continue };
        let (trust, signer) = crate::authenticode::verify_signer(&path);

        let (mut admits, mut unread) = (false, false);
        let mut at = Some(std::path::Path::new(&path));
        while let Some(p) = at {
            let s = p.to_string_lossy();
            match crate::acl::dacl_of_read(&s) {
                Ok(aces) => admits |= crate::acl::grants_unprivileged_write(&aces),
                Err(_) => unread = true,
            }
            if s.len() <= root.len() {
                break;
            }
            at = p.parent();
        }
        let writable = if admits { Some(true) } else if unread { None } else { Some(false) };
        let signed = trust.is_valid();
        out.insert(e.locus.clone(), ImageEvidence { path, signed, signer: signed.then_some(signer).flatten(), writable });
    }
    out
}
