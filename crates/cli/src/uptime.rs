#![allow(dead_code)]

use std::collections::BTreeSet;

use crate::golden::{self, ScoredService};
#[cfg(target_os = "linux")]
use crate::service_health::Health;

pub(crate) struct Restart {
    pub svc: &'static ScoredService,
    pub unit: String,
}

#[cfg(target_os = "linux")]
pub(crate) fn plan_restarts(health: &[Health], known: &BTreeSet<String>) -> Vec<Restart> {
    health
        .iter()
        .filter(|h| h.up == Some(false))
        .filter_map(|h| {
            golden::pick_unit(golden::units_for(h.svc.probe), known)
                .map(|u| Restart { svc: h.svc, unit: u.to_string() })
        })
        .collect()
}

#[cfg(target_os = "linux")]
pub(crate) fn known_service_units() -> BTreeSet<String> {
    use std::process::Command;

    let Some(systemctl) = ["/usr/bin/systemctl", "/bin/systemctl", "/usr/sbin/systemctl"]
        .into_iter()
        .map(std::path::PathBuf::from)
        .find(|p| p.exists())
    else {
        return BTreeSet::new();
    };
    let out = Command::new(&systemctl)
        .env_clear()
        .env("LC_ALL", "C")
        .args(["list-unit-files", "--type=service", "--no-legend", "--no-pager", "--plain"])
        .output();
    match out {
        Ok(o) if o.status.success() => parse_unit_files(&String::from_utf8_lossy(&o.stdout)),
        _ => BTreeSet::new(),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UnitState {

    Active,

    Activating,

    Inactive,

    Unknown,
}

pub(crate) fn parse_is_active(stdout: &str) -> UnitState {
    match stdout.lines().next().map(str::trim) {
        Some("active" | "reloading" | "refreshing") => UnitState::Active,
        Some("activating") => UnitState::Activating,
        Some("inactive" | "failed" | "deactivating") => UnitState::Inactive,
        _ => UnitState::Unknown,
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn unit_state(unit: &str) -> UnitState {
    let Some(systemctl) = ["/usr/bin/systemctl", "/bin/systemctl", "/usr/sbin/systemctl"]
        .into_iter()
        .map(std::path::PathBuf::from)
        .find(|p| p.exists())
    else {
        return UnitState::Unknown;
    };
    match std::process::Command::new(&systemctl).env_clear().env("LC_ALL", "C").args(["is-active", unit]).output() {
        Ok(o) => parse_is_active(&String::from_utf8_lossy(&o.stdout)),
        Err(_) => UnitState::Unknown,
    }
}

pub(crate) fn already_running(state: UnitState) -> Option<&'static str> {
    match state {
        UnitState::Active => Some("the unit is running"),
        UnitState::Activating => Some("the unit is still starting"),
        UnitState::Inactive | UnitState::Unknown => None,
    }
}

pub(crate) fn port_closed_hint(probe: golden::Probe) -> &'static str {
    match probe {
        golden::Probe::Ssh => "check ListenAddress in sshd_config (a localhost-only bind counts as down)",
        golden::Probe::Ftp => "check listen / listen_address in the FTP server's config",
        golden::Probe::Irc => {
            "the compose project may be down while Docker runs: `services --compose-up --arm` recreates it"
        }
        golden::Probe::MariaDb => "check bind-address and skip-networking in the MariaDB config",
        _ => "check what the service is bound to",
    }
}

pub(crate) const PORT_WAIT_SECS: u32 = 15;

pub(crate) fn poll_until_up(tries: u32, mut probe: impl FnMut() -> Option<bool>, mut pause: impl FnMut()) -> Option<bool> {
    let mut last = None;
    for n in 0..tries {
        last = probe();
        if last == Some(true) {
            return last;
        }
        if n.saturating_add(1) < tries {
            pause();
        }
    }
    last
}

#[cfg(target_os = "linux")]
pub(crate) fn await_port(svc: &ScoredService) -> Option<bool> {
    poll_until_up(
        PORT_WAIT_SECS,
        || {
            let r = crate::service_health::from_overview(&hemostat_sensor_linux::overview::report());
            if r.not_checked.is_some() {
                return None;
            }
            r.services.iter().find(|h| h.svc.service == svc.service && h.svc.host == svc.host).and_then(|h| h.up)
        },
        || std::thread::sleep(std::time::Duration::from_secs(1)),
    )
}

pub(crate) fn parse_unit_files(stdout: &str) -> BTreeSet<String> {
    let mut set = BTreeSet::new();
    for name in stdout.lines().filter_map(|l| l.split_whitespace().next()) {
        if let Some(bare) = name.strip_suffix(".service") {
            if bare.ends_with('@') {
                continue;
            }
            set.insert(name.to_string());
            set.insert(bare.to_string());
        }
    }
    set
}

pub(crate) const MAX_CONSECUTIVE_FAILURES: u32 = 3;

#[derive(Default)]
pub(crate) struct Governor {
    consecutive_failures: std::collections::BTreeMap<String, u32>,
}

impl Governor {

    pub(crate) fn should_attempt(&self, unit: &str) -> bool {
        self.consecutive_failures.get(unit).copied().unwrap_or(0) < MAX_CONSECUTIVE_FAILURES
    }

    pub(crate) fn record(&mut self, unit: &str, succeeded: bool) {
        if succeeded {
            self.consecutive_failures.remove(unit);
        } else {
            *self.consecutive_failures.entry(unit.to_string()).or_default() += 1;
        }
    }

    pub(crate) fn backed_off(&self, unit: &str) -> bool {
        !self.should_attempt(unit)
    }

    pub(crate) fn seen_up(&mut self, unit: &str) {
        self.consecutive_failures.remove(unit);
    }
}
