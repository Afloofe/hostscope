use std::collections::BTreeMap;
use std::path::Path;

use crate::triage::{Coverage, Finding, Severity};

mod catalogue;
mod dialects;
mod places;
mod shapes;
mod sweep;
mod walk;

pub use catalogue::CATALOGUE;
pub use places::suspicious_location;
pub use shapes::{suspicion, tmpfiles_suspicion};
pub use sweep::report;

use walk::home_dirs;

pub(crate) use walk::boot_time;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Category {

    Boot,

    Service,

    Scheduled,

    Login,

    Linker,

    Kernel,

    Auth,

    Event,

    Package,
}

impl Category {

    pub fn token(self) -> &'static str {
        match self {
            Category::Boot => "boot",
            Category::Service => "service",
            Category::Scheduled => "scheduled",
            Category::Login => "login",
            Category::Linker => "linker",
            Category::Kernel => "kernel",
            Category::Auth => "auth",
            Category::Event => "event",
            Category::Package => "package",
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum Probe {

    FilesIn(&'static [&'static str]),

    Files(&'static [&'static str]),

    TreeUnder(&'static [&'static str]),

    PerUser(&'static [&'static str]),
}

#[derive(Debug, Clone, Copy)]
pub struct Mechanism {

    pub id: &'static str,

    pub name: &'static str,

    pub category: Category,

    pub why: &'static str,
    probe: Probe,
}

impl Mechanism {

    pub fn entry_is_its_own_file(&self, path: &Path) -> bool {
        match self.probe {
            Probe::Files(list) => !list.iter().any(|f| Path::new(f) == path),
            Probe::FilesIn(_) | Probe::TreeUnder(_) => true,

            Probe::PerUser(rels) => !rels.iter().any(|r| path.ends_with(r)),
        }
    }
}

pub fn watched_directories() -> Vec<std::path::PathBuf> {
    use std::path::PathBuf;
    let mut out: Vec<PathBuf> = Vec::new();

    let homes = home_dirs();
    for m in CATALOGUE {
        match m.probe {
            Probe::FilesIn(dirs) | Probe::TreeUnder(dirs) => {
                out.extend(dirs.iter().map(PathBuf::from));
            }

            Probe::PerUser(rels) => {
                for (_, home) in &homes {
                    for rel in rels {
                        let p = home.join(rel);
                        if p.is_dir() {
                            out.push(p);
                        } else if let Some(parent) = p.parent() {
                            if parent != home.as_path() && parent.is_dir() {
                                out.push(parent.to_path_buf());
                            }
                        }
                    }
                }
            }

            Probe::Files(_) => {}
        }
    }
    out.sort();
    out.dedup();
    out
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

#[derive(Debug, Clone, Default)]
pub struct Report {

    pub observations: Vec<Observation>,

    pub findings: Vec<Finding>,

    pub established: usize,

    pub total: usize,
}

impl Report {

    pub fn count_at_least(&self, sev: Severity) -> usize {
        self.findings.iter().filter(|f| f.severity >= sev).count()
    }
}

pub fn by_category(r: &Report) -> BTreeMap<Category, Vec<&Observation>> {
    let mut out: BTreeMap<Category, Vec<&Observation>> = BTreeMap::new();
    for o in &r.observations {
        out.entry(o.category).or_default().push(o);
    }
    out
}
