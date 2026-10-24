#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Init {

    Systemd,

    Runit,

    Other(String),

    Unknown,
}

impl Init {

    pub fn token(&self) -> String {
        match self {
            Init::Systemd => "systemd".into(),
            Init::Runit => "runit".into(),
            Init::Other(n) => format!("other:{n}"),
            Init::Unknown => "unknown".into(),
        }
    }

    pub const fn is_systemd(&self) -> bool {
        matches!(self, Init::Systemd)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Supervision {

    pub pid1: Init,

    pub runit: bool,
}

impl Supervision {

    pub fn token(&self) -> String {
        match (&self.pid1, self.runit) {
            (Init::Runit, _) => "runit".into(),
            (p, true) => format!("{} + runit", p.token()),
            (p, false) => p.token(),
        }
    }

    pub const fn has_runit(&self) -> bool {
        self.runit || matches!(self.pid1, Init::Runit)
    }

    pub const fn is_systemd(&self) -> bool {
        self.pid1.is_systemd()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mechanism {

    ForkedChild,

    TransientUnit,

    UnitRestart,

    RunitService,

    RunitSupervised,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Resurrection {

    Normal,

    Partial,

    Unavailable,
}

impl Resurrection {

    pub const fn of(n_effective: usize) -> Self {
        match n_effective {
            0 => Resurrection::Unavailable,
            1 => Resurrection::Partial,
            _ => Resurrection::Normal,
        }
    }

    pub const fn token(self) -> &'static str {
        match self {
            Resurrection::Normal => "normal",
            Resurrection::Partial => "PARTIAL",
            Resurrection::Unavailable => "unavailable",
        }
    }

    pub const fn p0(self) -> Option<&'static str> {
        match self {
            Resurrection::Normal => None,
            Resurrection::Partial => Some(
                "P0: resurrection is PARTIAL — one mechanism, so a single removal leaves \
                 nothing to put the agent back",
            ),
            Resurrection::Unavailable => Some(
                "P0: resurrection is unavailable — nothing will put the agent back if it is \
                 killed. It still senses, records and contains",
            ),
        }
    }
}

impl Mechanism {

    pub const ALL: [Mechanism; 5] = [
        Mechanism::ForkedChild,
        Mechanism::TransientUnit,
        Mechanism::UnitRestart,
        Mechanism::RunitService,
        Mechanism::RunitSupervised,
    ];

    pub const fn token(self) -> &'static str {
        match self {
            Mechanism::ForkedChild => "forked-child",
            Mechanism::TransientUnit => "transient-unit",
            Mechanism::UnitRestart => "unit-restart",
            Mechanism::RunitService => "runit-service",
            Mechanism::RunitSupervised => "runit-supervised",
        }
    }

    pub const fn needs_a_live_sentinel(self) -> bool {
        match self {
            Mechanism::ForkedChild | Mechanism::TransientUnit | Mechanism::RunitSupervised => true,
            Mechanism::UnitRestart | Mechanism::RunitService => false,
        }
    }

    pub const fn survives_agent_cgroup_kill(self) -> bool {
        match self {
            Mechanism::ForkedChild => false,
            Mechanism::TransientUnit
            | Mechanism::UnitRestart
            | Mechanism::RunitService
            | Mechanism::RunitSupervised => true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Availability {

    pub mechanism: Mechanism,

    pub usable: bool,

    pub reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diversity {

    pub mechanisms: Vec<Availability>,

    pub init: Supervision,
}

impl Diversity {

    pub fn usable(&self) -> usize {
        self.mechanisms.iter().filter(|m| m.usable).count()
    }

    pub fn autonomous(&self) -> usize {
        self.mechanisms
            .iter()
            .filter(|m| m.usable && !m.mechanism.needs_a_live_sentinel())
            .count()
    }

    pub fn survive_cgroup_kill(&self) -> usize {
        self.mechanisms
            .iter()
            .filter(|m| m.usable && m.mechanism.survives_agent_cgroup_kill())
            .count()
    }

    pub fn summary(&self) -> String {
        let usable = self.usable();
        if usable == 0 {
            return "no launch mechanism is usable on this host: nothing will put the agent back \
                    if it dies"
                .into();
        }
        format!(
            "{usable} of {} route(s) usable under {}; {} survive a cgroup kill, {} need no live \
             watcher",
            self.mechanisms.len(),
            self.init.token(),
            self.survive_cgroup_kill(),
            self.autonomous()
        )
    }
}

#[cfg(target_os = "linux")]
pub fn init_system() -> Supervision {

    let comm = std::fs::read_to_string("/proc/1/comm").ok().map(|c| c.trim().to_string());
    judge_supervision(comm.as_deref(), process_named("runsvdir"))
}

pub fn judge_supervision(pid1_comm: Option<&str>, runsvdir_running: bool) -> Supervision {
    let pid1 = match pid1_comm.map(str::trim) {
        Some("systemd") => Init::Systemd,
        Some("runit" | "runit-init") => Init::Runit,
        Some("") | None => Init::Unknown,
        Some(other) => Init::Other(other.to_string()),
    };
    Supervision { pid1, runit: runsvdir_running }
}

#[cfg(target_os = "linux")]
fn process_named(name: &str) -> bool {
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return false;
    };
    for e in entries.flatten() {
        let Some(pid) = e.file_name().to_str().and_then(|n| n.parse::<u32>().ok()) else {
            continue;
        };
        if std::fs::read_to_string(format!("/proc/{pid}/comm"))
            .map(|c| c.trim() == name)
            .unwrap_or(false)
        {
            return true;
        }
    }
    false
}

#[cfg(target_os = "linux")]
fn first_existing(names: &[&str]) -> Option<String> {
    names.iter().find(|p| std::path::Path::new(p).exists()).map(|p| (*p).to_string())
}

#[cfg(target_os = "linux")]
pub fn runit_service_dir() -> Option<String> {
    first_existing(RUNIT_SERVICE_DIRS)
}

pub const RUNIT_SERVICE_DIRS: &[&str] = &[
    "/etc/service",
    "/run/runit/service",
    "/var/service",
    "/service",
    "/etc/runit/runsvdir/current",
];

#[cfg(target_os = "linux")]
pub fn probe(service: &str) -> Diversity {
    let init = init_system();
    let mut out = Vec::new();

    out.push(match crate::image::Sealed::new(b"\x7fELF-probe") {
        Ok(img) if img.sealed() => {
            Availability { mechanism: Mechanism::ForkedChild, usable: true, reason: None }
        }
        Ok(_) => Availability {
            mechanism: Mechanism::ForkedChild,
            usable: false,
            reason: Some(
                "a memfd was created but would not seal, so a relaunch could not be trusted to \
                 execute the image that was verified"
                    .into(),
            ),
        },
        Err(e) => Availability { mechanism: Mechanism::ForkedChild, usable: false, reason: Some(e) },
    });

    let not_systemd = || {
        format!(
            "systemd is not in charge here (pid 1 is {}), so this route does not exist",
            init.pid1.token()
        )
    };
    let systemd_run = first_existing(&["/usr/bin/systemd-run", "/bin/systemd-run"]);
    let systemctl = first_existing(&["/usr/bin/systemctl", "/bin/systemctl"]);

    out.push(if !init.is_systemd() {
        Availability {
            mechanism: Mechanism::TransientUnit,
            usable: false,
            reason: Some(not_systemd()),
        }
    } else if systemd_run.is_some() {
        Availability { mechanism: Mechanism::TransientUnit, usable: true, reason: None }
    } else {
        Availability {
            mechanism: Mechanism::TransientUnit,
            usable: false,
            reason: Some("systemd-run was not found".into()),
        }
    });

    out.push(if init.is_systemd() {
        probe_unit_restart(systemctl.as_deref(), service)
    } else {
        Availability {
            mechanism: Mechanism::UnitRestart,
            usable: false,
            reason: Some(not_systemd()),
        }
    });

    let sv = first_existing(&["/usr/bin/sv", "/bin/sv", "/sbin/sv"]);
    let svdir = runit_service_dir();
    let no_runit = || {
        "no runit supervision was found on this host: neither runit as pid 1 nor a running \
         runsvdir"
            .to_string()
    };

    out.push(if !init.has_runit() {
        Availability { mechanism: Mechanism::RunitService, usable: false, reason: Some(no_runit()) }
    } else {
        probe_runit_service(sv.as_deref(), service)
    });

    out.push(if !init.has_runit() {
        Availability {
            mechanism: Mechanism::RunitSupervised,
            usable: false,
            reason: Some(no_runit()),
        }
    } else {
        match (&sv, &svdir) {
            (Some(_), Some(_)) => {
                Availability { mechanism: Mechanism::RunitSupervised, usable: true, reason: None }
            }
            (None, _) => Availability {
                mechanism: Mechanism::RunitSupervised,
                usable: false,
                reason: Some("the sv(8) control program was not found".into()),
            },
            (_, None) => Availability {
                mechanism: Mechanism::RunitSupervised,
                usable: false,
                reason: Some(
                    "runit is supervising but its service scan directory could not be found in \
                     any of the usual places (/etc/service, /var/service, /service)"
                        .into(),
                ),
            },
        }
    });

    Diversity { mechanisms: out, init }
}

#[cfg(target_os = "linux")]
fn probe_unit_restart(systemctl: Option<&str>, unit: &str) -> Availability {
    let no = |r: &str| Availability {
        mechanism: Mechanism::UnitRestart,
        usable: false,
        reason: Some(r.to_string()),
    };
    let Some(sc) = systemctl else {
        return no("systemctl was not found");
    };
    if unit.trim().is_empty() {
        return no(
            "this agent is not running under a named unit, so there is no unit for systemd to \
             restart. Set $HEMOSTAT_UNIT if it is.",
        );
    }
    match std::process::Command::new(sc)
        .args(["show", "-p", "Restart", "--value", unit])
        .output()
    {
        Ok(o) => judge_restart(String::from_utf8_lossy(&o.stdout).trim()),
        Err(e) => Availability {
            mechanism: Mechanism::UnitRestart,
            usable: false,
            reason: Some(format!("could not ask systemd about the unit: {e}")),
        },
    }
}

#[cfg(target_os = "linux")]
fn probe_runit_service(sv: Option<&str>, service: &str) -> Availability {
    let no = |r: &str| Availability {
        mechanism: Mechanism::RunitService,
        usable: false,
        reason: Some(r.to_string()),
    };
    let Some(sv) = sv else {
        return no("the sv(8) control program was not found");
    };
    if service.trim().is_empty() {
        return no(
            "this agent is not running under a named runit service, so there is nothing for \
             runsv to restart. Set $HEMOSTAT_UNIT if it is.",
        );
    }
    match std::process::Command::new(sv).args(["status", service]).output() {
        Ok(o) => {

            let text = if o.status.success() {
                String::from_utf8_lossy(&o.stdout).trim().to_string()
            } else {
                let e = String::from_utf8_lossy(&o.stderr).trim().to_string();
                if e.is_empty() {
                    String::from_utf8_lossy(&o.stdout).trim().to_string()
                } else {
                    e
                }
            };
            judge_sv_status(&text)
        }
        Err(e) => Availability {
            mechanism: Mechanism::RunitService,
            usable: false,
            reason: Some(format!("could not ask runit about the service: {e}")),
        },
    }
}

#[cfg(target_os = "linux")]
fn judge_restart(value: &str) -> Availability {
    match value {

        "always" | "on-failure" | "on-abnormal" | "on-abort" => {
            Availability { mechanism: Mechanism::UnitRestart, usable: true, reason: None }
        }
        "" => Availability {
            mechanism: Mechanism::UnitRestart,
            usable: false,
            reason: Some(
                "systemd reported no Restart= for this unit — the unit may not exist under that \
                 name"
                    .into(),
            ),
        },
        other => Availability {
            mechanism: Mechanism::UnitRestart,
            usable: false,
            reason: Some(format!(
                "the unit has Restart={other}, which does not bring back an agent that was \
                 killed: a SIGKILL is not a clean exit and not a watchdog timeout"
            )),
        },
    }
}

fn judge_sv_status(text: &str) -> Availability {
    let ok = || Availability { mechanism: Mechanism::RunitService, usable: true, reason: None };
    let no = |r: String| Availability {
        mechanism: Mechanism::RunitService,
        usable: false,
        reason: Some(r),
    };
    let line = text.lines().next().unwrap_or("").trim();

    if line.is_empty() {
        return no("runit returned nothing about this service, so it could not be confirmed \
                   supervised"
            .into());
    }

    if line.starts_with("fail:") || line.starts_with("warning:") {
        return no(format!(
            "runit is not supervising this service, so nothing would restart the agent: {line}"
        ));
    }
    if line.starts_with("run:") {

        if line.contains("want down") {
            return no(format!(
                "the service is running but has been told to stop ({line}), so runsv will not \
                 restart it when it exits"
            ));
        }
        return ok();
    }
    if line.starts_with("down:") {

        if line.contains("normally up") {
            return no(format!(
                "the service is stopped ({line}) — `sv up` restores it. runit will not start it \
                 on its own: \"normally up\" describes boot, not what runsv intends now"
            ));
        }
        return no(format!(
            "the service is down and runit is configured to keep it down ({line}) — removing \
             the service's `down` file and `sv up` is what makes this a route"
        ));
    }
    no(format!("runit's answer was not recognised, so it could not be confirmed: {line}"))
}
