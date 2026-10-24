use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use crate::outcome::ProtectReason;
use crate::paths::{read_declared_protections, read_declared_users};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetKind {

    Userland,

    KernelThread,

    Unreadable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcId {

    pub start_time: u64,

    pub exe: Option<String>,
}

pub(crate) fn identity_matches(expected: &ProcId, current: Option<&ProcId>) -> bool {
    let Some(cur) = current else {
        return false;
    };
    if cur.start_time != expected.start_time {
        return false;
    }
    match (&expected.exe, &cur.exe) {
        (Some(a), Some(b)) => a == b,
        _ => true,
    }
}

pub(crate) fn read_proc_id(pid: u32) -> Option<ProcId> {
    let snap = hemostat_sensor_linux::procfs::read_process(pid)?;
    Some(ProcId { start_time: snap.starttime_ticks, exe: snap.exe })
}

#[derive(Debug, Clone, Default)]
pub struct ProtectSet {

    pub infra_role: Option<String>,

    pub listener_pids: BTreeSet<u32>,

    pub session_pids: BTreeSet<u32>,

    pub session_units: BTreeSet<String>,

    pub listener_units: BTreeSet<String>,

    pub declared_protected: BTreeSet<String>,

    pub modules: crate::modprotect::ModuleProtectSet,

    pub protected_users: BTreeSet<String>,

    pub declarations_unreadable: bool,

    pub allow_listener_units: BTreeSet<String>,

    pub agent_pid: u32,

    pub listener_map_complete: bool,
}

impl ProtectSet {

    pub fn holds_user(&self, user: &str) -> bool {
        self.protected_users.contains(user)
    }

    pub fn gather() -> ProtectSet {
        let infra_role = infrastructure_role();
        let agent_pid = std::process::id();
        let modules = crate::modprotect::ModuleProtectSet::gather();
        let inodes = listener_inodes_all();
        let (listener_pids, complete) = pids_owning_inodes(&inodes);
        let session_pids = session_chain(agent_pid);
        let mut session_units = units_in_cgroup(
            &fs::read_to_string("/proc/self/cgroup").unwrap_or_default(),
        );

        for u in ["ssh.service", "sshd.service", "ssh.socket", "sshd.socket"] {
            session_units.insert(u.to_string());
        }

        let mut listener_units = BTreeSet::new();
        for pid in &listener_pids {
            let cg = fs::read_to_string(format!("/proc/{pid}/cgroup")).unwrap_or_default();
            listener_units.extend(units_in_cgroup(&cg));
        }
        ProtectSet {
            infra_role,
            declarations_unreadable: crate::paths::declarations_unreadable(),
            protected_users: read_declared_users(),
            listener_pids,
            session_pids,
            session_units,
            listener_units,
            modules,
            declared_protected: read_declared_protections(),
            allow_listener_units: BTreeSet::new(),
            agent_pid,
            listener_map_complete: complete,
        }
    }

    #[must_use]
    pub fn declaring_protected(mut self, entries: impl IntoIterator<Item = String>) -> ProtectSet {
        self.declared_protected.extend(entries);
        self
    }

    #[must_use]
    pub fn declaring_protected_users(mut self, users: impl IntoIterator<Item = String>) -> Self {
        self.protected_users.extend(users);
        self
    }

    pub(crate) fn declared_reason(&self, subject: &str) -> Option<ProtectReason> {
        if self.declared(subject) {
            Some(ProtectReason::OperatorDeclared)
        } else if self.declarations_unreadable {
            Some(ProtectReason::DeclarationsUnreadable)
        } else {
            None
        }
    }

    pub fn user_reason(&self, user: &str) -> Option<ProtectReason> {
        if self.holds_user(user) {
            Some(ProtectReason::OperatorDeclared)
        } else if self.declarations_unreadable {
            Some(ProtectReason::DeclarationsUnreadable)
        } else {
            None
        }
    }

    pub(crate) fn declared(&self, subject: &str) -> bool {
        self.declared_protected.iter().any(|d| {
            d == subject
                || (d.starts_with('/')
                    && subject.starts_with(d.as_str())
                    && (d.ends_with('/') || subject[d.len()..].starts_with('/')))
        })
    }

    #[must_use]
    pub fn allowing_listeners(mut self, units: impl IntoIterator<Item = String>) -> ProtectSet {
        self.allow_listener_units.extend(units);
        self
    }

    pub(crate) fn process_reason(&self, pid: u32, kind: TargetKind) -> Option<ProtectReason> {
        if pid == 1 || pid == 2 {
            return Some(ProtectReason::InitProcess);
        }
        if pid == self.agent_pid {
            return Some(ProtectReason::AgentSelf);
        }
        if self.session_pids.contains(&pid) {
            return Some(ProtectReason::OperatorSession);
        }
        if self.listener_pids.contains(&pid) {
            return Some(ProtectReason::ServiceListener);
        }
        match kind {
            TargetKind::Userland => None,
            TargetKind::KernelThread => Some(ProtectReason::KernelThread),
            TargetKind::Unreadable => Some(ProtectReason::UnreadableTarget),
        }
    }

    pub(crate) fn declared_process_reason(
        &self,
        exe: Option<&str>,
        unit: Option<&str>,
    ) -> Option<ProtectReason> {
        if exe.is_some_and(|e| self.declared(e)) || unit.is_some_and(|u| self.declared(u)) {
            return Some(ProtectReason::OperatorDeclared);
        }
        self.declarations_unreadable.then_some(ProtectReason::DeclarationsUnreadable)
    }

    pub(crate) fn infrastructure_kill_reason(&self, name: Option<&str>) -> Option<ProtectReason> {
        if name.is_some_and(is_infrastructure_process) {
            return Some(ProtectReason::InfrastructureProcess);
        }
        self.infra_role.as_ref().map(|_| ProtectReason::InfrastructureHost)
    }

    pub(crate) fn unit_reason(&self, unit: &str) -> Option<ProtectReason> {
        if unit_is_ssh(unit) || self.session_units.contains(unit) {
            return Some(ProtectReason::OperatorSession);
        }

        if let Some(r) = self.declared_reason(unit) {
            return Some(r);
        }
        if self.listener_units.contains(unit) && !self.allow_listener_units.contains(unit) {
            return Some(ProtectReason::ServiceListener);
        }

        if !self.listener_map_complete {
            return Some(ProtectReason::IncompleteListenerMap);
        }
        None
    }

    pub fn path_reason(&self, path: &Path) -> Option<ProtectReason> {
        let s = path.to_string_lossy();
        if let Some(r) = self.declared_reason(&s) {
            return Some(r);
        }

        if let Some(resolved) = crate::paths::canonical_parent(path) {
            if self.declared(&resolved.to_string_lossy()) {
                return Some(ProtectReason::OperatorDeclared);
            }
        }

        if s.contains(".wants/") || s.contains(".requires/") {
            return Some(ProtectReason::UnitEnablement);
        }

        if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
            if s.contains("/systemd/") {
                if let Some(r) = self.unit_reason(name) {
                    return Some(r);
                }
            }
        }

        if s.contains("/systemd/") {
            for anc in path.ancestors().skip(1) {
                let Some(dir) = anc.file_name().and_then(|n| n.to_str()) else { continue };
                let Some(unit) = dir.strip_suffix(".d") else { continue };
                if let Some(r) = self.unit_reason(unit) {
                    return Some(r);
                }
            }
        }
        None
    }
}

pub(crate) fn unit_is_ssh(unit: &str) -> bool {
    let base = unit
        .strip_suffix(".service")
        .or_else(|| unit.strip_suffix(".socket"))
        .unwrap_or(unit);
    matches!(base, "ssh" | "sshd")
}

pub(crate) fn session_chain(start: u32) -> BTreeSet<u32> {
    let mut chain = BTreeSet::new();
    let mut pid = start;
    for _ in 0..256 {
        if pid == 0 || !chain.insert(pid) {
            break;
        }
        match hemostat_sensor_linux::procfs::read_process(pid) {
            Some(snap) if snap.ppid != pid => pid = snap.ppid,
            _ => break,
        }
    }
    chain
}

pub(crate) fn units_in_cgroup(text: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for line in text.lines() {

        let Some(path) = line.rsplit(':').next() else { continue };
        for comp in path.split('/') {
            if comp.ends_with(".service") || comp.ends_with(".scope") {
                out.insert(comp.to_string());
            }
        }
    }
    out
}

pub(crate) const TCP_LISTEN: u8 = 0x0A;

pub(crate) const UDP_BOUND: u8 = 0x07;

pub(crate) fn listening_inodes(text: &str, want: &[u8]) -> BTreeSet<u64> {
    let mut out = BTreeSet::new();
    for line in text.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 10 {
            continue;
        }
        let Ok(state) = u8::from_str_radix(f[3], 16) else { continue };
        if !want.contains(&state) {
            continue;
        }

        let port_nonzero = f[1].rsplit(':').next().is_some_and(|p| p != "0000" && !p.is_empty());
        if !port_nonzero {
            continue;
        }
        if let Ok(inode) = f[9].parse::<u64>() {
            if inode != 0 {
                out.insert(inode);
            }
        }
    }
    out
}

const LISTENER_TABLES: [(&str, u8); 4] =
    [("tcp", TCP_LISTEN), ("tcp6", TCP_LISTEN), ("udp", UDP_BOUND), ("udp6", UDP_BOUND)];

pub(crate) fn listener_inodes_all() -> BTreeSet<u64> {
    let mut out = BTreeSet::new();

    for (t, want) in LISTENER_TABLES {
        let path = format!("/proc/net/{t}");
        if let Ok(text) = fs::read_to_string(path) {
            out.extend(listening_inodes(&text, &[want]));
        }
    }
    let pids = fs::read_dir("/proc")
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| e.file_name().to_str()?.parse::<u32>().ok());
    out.extend(listener_inodes_across(
        fs::read_link("/proc/self/ns/net").ok(),
        pids,
        |pid| fs::read_link(format!("/proc/{pid}/ns/net")).ok(),
        |pid, t| fs::read_to_string(format!("/proc/{pid}/net/{t}")).ok(),
    ));
    out
}

pub(crate) fn listener_inodes_across<N: Ord>(
    already: Option<N>,
    pids: impl IntoIterator<Item = u32>,
    netns_of: impl Fn(u32) -> Option<N>,
    table: impl Fn(u32, &str) -> Option<String>,
) -> BTreeSet<u64> {
    let mut read: BTreeSet<N> = already.into_iter().collect();
    let mut out = BTreeSet::new();
    for pid in pids {
        let Some(ns) = netns_of(pid) else { continue };
        if read.contains(&ns) {
            continue;
        }
        let Some(tcp) = table(pid, "tcp") else { continue };
        out.extend(listening_inodes(&tcp, &[TCP_LISTEN]));

        for (t, want) in LISTENER_TABLES.iter().skip(1) {
            if let Some(text) = table(pid, t) {
                out.extend(listening_inodes(&text, &[*want]));
            }
        }
        read.insert(ns);
    }
    out
}

pub(crate) fn socket_inode(link_target: &str) -> Option<u64> {
    link_target
        .strip_prefix("socket:[")
        .and_then(|s| s.strip_suffix(']'))
        .and_then(|n| n.parse().ok())
}

pub(crate) fn pids_owning_inodes(inodes: &BTreeSet<u64>) -> (BTreeSet<u32>, bool) {
    let mut owners = BTreeSet::new();
    if inodes.is_empty() {

        return (owners, fs::read_dir("/proc").is_ok());
    }
    let Ok(dir) = fs::read_dir("/proc") else {
        return (owners, false);
    };
    for entry in dir.flatten() {
        let Some(pid) = entry.file_name().to_str().and_then(|n| n.parse::<u32>().ok()) else {
            continue;
        };
        let Ok(fds) = fs::read_dir(format!("/proc/{pid}/fd")) else {
            continue;
        };
        for fd in fds.flatten() {
            if let Ok(target) = fs::read_link(fd.path()) {
                if let Some(inode) = socket_inode(&target.to_string_lossy()) {
                    if inodes.contains(&inode) {
                        owners.insert(pid);
                        break;
                    }
                }
            }
        }
    }
    (owners, true)
}

pub(crate) fn remove_preload_entry(text: &str, entry: &str) -> (String, bool) {
    let mut kept: Vec<&str> = Vec::new();
    let mut removed = false;
    for line in text.lines() {
        let body = line.split('#').next().unwrap_or("").trim();
        if body == entry {
            removed = true;
            continue;
        }
        kept.push(line);
    }
    let mut out = kept.join("\n");
    if !out.is_empty() {
        out.push('\n');
    }
    (out, removed)
}

pub(crate) const INFRASTRUCTURE_PROCESSES: &[&str] = &[

    "corosync",
    "pacemakerd",
    "pacemaker-contr",
    "pacemaker-contro",
    "pacemaker-fence",
    "pacemaker-fenced",
    "keepalived",

    "bacula-fd",
    "bareos-fd",
    "amandad",
    "veeamservice",
    "dsmcad",

    "falcon-sensor",
    "wdavdaemon",
    "cbagentd",
    "s1-agent",
    "elastic-endpoint",
];

const CLUSTER_DAEMONS: &[&str] = &["corosync", "pacemakerd", "keepalived"];

pub(crate) fn is_infrastructure_process(name: &str) -> bool {
    let base = name.rsplit('/').next().unwrap_or(name);
    INFRASTRUCTURE_PROCESSES.contains(&base)
}

pub fn infrastructure_role() -> Option<String> {
    let dir = fs::read_dir("/proc").ok()?;
    for e in dir.flatten() {
        let name = e.file_name();
        let Some(pid) = name.to_str().filter(|n| n.bytes().all(|b| b.is_ascii_digit())) else {
            continue;
        };
        let comm = hemostat_sensor_linux::saferead::read_scan_target(std::path::Path::new(&format!(
            "/proc/{pid}/comm"
        )))
        .unwrap_or_default();
        let comm = comm.trim();
        if CLUSTER_DAEMONS.contains(&comm) {
            return Some(comm.to_string());
        }
    }
    None
}
