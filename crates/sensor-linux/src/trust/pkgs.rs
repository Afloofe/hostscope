use std::cell::RefCell;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

pub trait Packages {

    fn judge(&self, path: &Path, bytes: &[u8]) -> Option<(String, Option<bool>)>;

    fn name(&self) -> Option<&'static str>;
}

const KEEP: &[&str] = &[
    "/usr/share/ca-certificates/",
    "/usr/local/share/ca-certificates/",
    "/etc/ssl/",
    "/etc/ca-certificates",
    "/usr/share/pki/",
    "/etc/pki/",
];

#[derive(Debug, Clone, Default)]
pub struct Dpkg {
    files: BTreeMap<String, (String, String)>,
}

impl Dpkg {

    pub fn read(root: &Path) -> Option<Dpkg> {
        let info = root.join("var/lib/dpkg/info");
        let rd = std::fs::read_dir(&info).ok()?;
        let mut d = Dpkg::default();
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            let Some(pkg) = name.strip_suffix(".md5sums") else { continue };
            let pkg = pkg.split(':').next().unwrap_or(pkg).to_string();
            let Some(text) = crate::saferead::read_scan_target(&e.path()) else { continue };
            d.add_md5sums(&pkg, &text);
        }
        if let Some(status) = crate::saferead::read_scan_target(&root.join("var/lib/dpkg/status")) {
            d.add_conffiles(&status);
        }
        Some(d)
    }

    pub fn add_md5sums(&mut self, pkg: &str, text: &str) {
        for line in text.lines() {
            let Some((md5, rel)) = line.split_once(char::is_whitespace) else { continue };
            let path = format!("/{}", rel.trim().trim_start_matches('/'));
            if md5.len() == 32 && KEEP.iter().any(|k| path.starts_with(k)) {
                self.files.insert(path, (pkg.to_string(), md5.to_ascii_lowercase()));
            }
        }
    }

    pub fn add_conffiles(&mut self, status: &str) {
        for stanza in status.split("\n\n") {
            let mut pkg = None;
            let mut in_conf = false;
            let mut conf: Vec<(String, String)> = Vec::new();
            for l in stanza.lines() {
                if let Some(p) = l.strip_prefix("Package: ") {
                    pkg = Some(p.trim().to_string());
                    in_conf = false;
                } else if l.starts_with("Conffiles:") {
                    in_conf = true;
                } else if in_conf && l.starts_with(' ') {
                    let mut f = l.split_whitespace();
                    if let (Some(p), Some(m)) = (f.next(), f.next()) {
                        if m.len() == 32 && KEEP.iter().any(|k| p.starts_with(k)) {
                            conf.push((p.to_string(), m.to_ascii_lowercase()));
                        }
                    }
                } else {
                    in_conf = false;
                }
            }
            if let Some(p) = pkg {
                for (path, md5) in conf {
                    self.files.entry(path).or_insert((p.clone(), md5));
                }
            }
        }
    }
}

impl Packages for Dpkg {
    fn judge(&self, path: &Path, bytes: &[u8]) -> Option<(String, Option<bool>)> {
        let (pkg, md5) = self.files.get(path.to_str()?)?;
        Some((pkg.clone(), Some(crate::inventory::md5_hex(bytes) == *md5)))
    }

    fn name(&self) -> Option<&'static str> {
        Some("dpkg")
    }
}

pub enum System {

    Dpkg(Dpkg),

    Tool(crate::pkg::Manager, RefCell<BTreeMap<String, Vec<PathBuf>>>),

    None,
}

impl System {

    pub fn detect(root: &Path) -> System {
        if let Some(d) = Dpkg::read(root) {
            return System::Dpkg(d);
        }
        if root == Path::new("/") {
            if let Some(m) = crate::pkg::manager() {
                return System::Tool(m, RefCell::new(BTreeMap::new()));
            }
        }
        System::None
    }
}

impl Packages for System {
    fn judge(&self, path: &Path, bytes: &[u8]) -> Option<(String, Option<bool>)> {
        match self {
            System::Dpkg(d) => d.judge(path, bytes),
            System::Tool(m, cache) => {
                let pkg = m.owner(path)?;
                let mut c = cache.borrow_mut();
                let drifted = c.entry(pkg.clone()).or_insert_with(|| m.drift(&pkg).into_iter().map(|d| d.path).collect());
                let differs = drifted.iter().any(|p| p == path);
                Some((pkg, Some(!differs)))
            }
            System::None => None,
        }
    }

    fn name(&self) -> Option<&'static str> {
        match self {
            System::Dpkg(_) => Some("dpkg"),
            System::Tool(m, _) => Some(m.kind.name()),
            System::None => None,
        }
    }
}
