use std::collections::{BTreeMap, BTreeSet};
use std::fs;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ModuleProtectReason {

    MountedFilesystem(String),

    StorageDriver(String),

    NetworkDriver(String),

    DependedOn(Vec<String>),

    OperatorDeclared,
}

impl ModuleProtectReason {

    pub fn describe(&self) -> String {
        match self {
            Self::MountedFilesystem(at) => format!(
                "it is the filesystem driver for a live mount at `{at}`. Unloading it does not \
                 fail, it makes this host unable to read that filesystem"
            ),
            Self::StorageDriver(dev) => format!(
                "it is the storage driver beneath `{dev}`. The disk stops answering and the \
                 host does not come back without a power cycle"
            ),
            Self::NetworkDriver(iface) => format!(
                "it drives `{iface}`, which carries a route. An unreachable host is a lost \
                 host, and you are probably arriving over it"
            ),
            Self::DependedOn(by) => format!(
                "{} loaded module(s) depend on it ({}). The kernel would refuse with EBUSY; \
                 this says which",
                by.len(),
                by.join(", ")
            ),
            Self::OperatorDeclared => {
                "the operator declared it in /etc/hemostat/protect".to_string()
            }
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct ModuleProtectSet {

    pub filesystems: BTreeMap<String, String>,

    pub storage: BTreeMap<String, String>,

    pub network: BTreeMap<String, String>,

    pub depended_on: BTreeMap<String, Vec<String>>,

    pub complete: bool,
}

impl ModuleProtectSet {

    pub fn reason(&self, name: &str) -> Option<ModuleProtectReason> {
        if let Some(at) = self.filesystems.get(name) {
            return Some(ModuleProtectReason::MountedFilesystem(at.clone()));
        }
        if let Some(dev) = self.storage.get(name) {
            return Some(ModuleProtectReason::StorageDriver(dev.clone()));
        }
        if let Some(iface) = self.network.get(name) {
            return Some(ModuleProtectReason::NetworkDriver(iface.clone()));
        }
        if let Some(by) = self.depended_on.get(name) {
            if !by.is_empty() {
                return Some(ModuleProtectReason::DependedOn(by.clone()));
            }
        }
        None
    }

    pub fn gather() -> Self {
        let mut s = Self { complete: true, ..Self::default() };

        match hemostat_sensor_linux::saferead::read_kernel_text("/proc/mounts") {
            Ok(t) => s.filesystems = filesystems_from_mounts(&t),
            Err(_) => s.complete = false,
        }
        match hemostat_sensor_linux::saferead::read_kernel_text("/proc/modules") {
            Ok(t) => s.depended_on = dependents_from_modules(&t),
            Err(_) => s.complete = false,
        }
        match storage_drivers() {
            Some(m) => s.storage = m,
            None => s.complete = false,
        }
        match fs::read_to_string("/proc/net/route") {
            Ok(t) => s.network = network_drivers(&routed_interfaces(&t)),
            Err(_) => s.complete = false,
        }
        s
    }
}

pub fn filesystems_from_mounts(text: &str) -> BTreeMap<String, String> {
    const PSEUDO: &[&str] = &[
        "proc", "sysfs", "devtmpfs", "devpts", "tmpfs", "cgroup", "cgroup2", "securityfs",
        "pstore", "bpf", "debugfs", "tracefs", "configfs", "fusectl", "hugetlbfs", "mqueue",
        "ramfs", "binfmt_misc", "autofs", "efivarfs", "rpc_pipefs", "selinuxfs",
    ];
    let mut out = BTreeMap::new();
    for line in text.lines() {
        let mut f = line.split_whitespace();
        let (Some(_src), Some(at), Some(fstype)) = (f.next(), f.next(), f.next()) else {
            continue;
        };
        if PSEUDO.contains(&fstype) {
            continue;
        }

        if at == "/" || !out.contains_key(fstype) {
            out.insert(fstype.to_string(), at.to_string());
        }
    }
    out
}

pub fn dependents_from_modules(text: &str) -> BTreeMap<String, Vec<String>> {
    let mut out = BTreeMap::new();
    for line in text.lines() {
        let mut f = line.split_whitespace();
        let (Some(name), Some(_size), Some(_refs), Some(used_by)) =
            (f.next(), f.next(), f.next(), f.next())
        else {
            continue;
        };
        if used_by == "-" {
            out.insert(name.to_string(), Vec::new());
            continue;
        }
        let deps: Vec<String> = used_by
            .split(',')
            .map(str::trim)
            .filter(|d| !d.is_empty())
            .map(str::to_string)
            .collect();
        out.insert(name.to_string(), deps);
    }
    out
}

pub fn routed_interfaces(text: &str) -> BTreeSet<String> {
    text.lines()
        .skip(1)
        .filter_map(|l| l.split_whitespace().next())
        .filter(|i| !i.is_empty() && *i != "lo")
        .map(str::to_string)
        .collect()
}

fn network_drivers(ifaces: &BTreeSet<String>) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for i in ifaces {
        let link = format!("/sys/class/net/{i}/device/driver");
        if let Ok(p) = fs::read_link(&link) {
            if let Some(d) = p.file_name().and_then(|s| s.to_str()) {
                out.insert(d.to_string(), i.clone());
            }
        }
    }
    out
}

fn storage_drivers() -> Option<BTreeMap<String, String>> {
    storage_drivers_under(std::path::Path::new("/sys"))
}

pub(crate) fn storage_drivers_under(sys: &std::path::Path) -> Option<BTreeMap<String, String>> {
    let entries = fs::read_dir(sys.join("block")).ok()?;
    let devices = fs::canonicalize(sys.join("devices")).ok()?;
    let mut out = BTreeMap::new();
    for e in entries.flatten() {
        let dev = e.file_name().to_string_lossy().into_owned();
        let Ok(real) = fs::canonicalize(e.path()) else { continue };
        for anc in real.ancestors().take_while(|a| a.starts_with(&devices) && *a != devices) {
            let Ok(driver) = fs::read_link(anc.join("driver")) else { continue };
            let module = fs::read_link(anc.join("driver/module")).ok();
            for name in std::iter::once(driver).chain(module) {
                if let Some(n) = name.file_name().and_then(|s| s.to_str()) {
                    out.insert(n.to_string(), dev.clone());
                }
            }
        }
    }
    Some(out)
}
