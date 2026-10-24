use super::catalog::{Lane, Provider};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Stats {

    pub events: u64,

    pub unattributed: u64,

    pub events_lost: u32,

    pub buffers_lost: u32,

    pub providers_failed: Vec<String>,

    pub providers_enabled: Vec<String>,

    pub delivered: Vec<u64>,
}

impl Stats {

    pub fn summary(&self) -> String {
        if self.providers_enabled.is_empty() {
            return "no provider enabled, so nothing was being watched — this is a gap, not a \
                    quiet host"
                .into();
        }
        let lost = if self.events_lost > 0 || self.buffers_lost > 0 {
            format!(
                "; the OS dropped {} event(s) and {} buffer(s), so this is a partial view",
                self.events_lost, self.buffers_lost
            )
        } else {
            String::new()
        };
        if self.events == 0 {
            return format!(
                "{} provider(s) enabled but NO events arrived. On a live host that is itself a \
                 finding: either nothing happened in the window, or the session is enabled and \
                 silent{lost}",
                self.providers_enabled.len()
            );
        }
        let others = if self.unattributed > 0 {
            format!(" (and {} record(s) from no enabled provider, not counted)", self.unattributed)
        } else {
            String::new()
        };

        if self.delivered.len() != self.providers_enabled.len() {
            return format!(
                "{} event(s) across {} enabled provider(s), not attributed to any one of \
                 them{others}{lost}",
                self.events,
                self.providers_enabled.len()
            );
        }
        let heard = self.delivered.iter().filter(|n| **n > 0).count();
        let each = self
            .providers_enabled
            .iter()
            .zip(&self.delivered)
            .map(|(p, n)| {
                if *n > 0 {
                    format!("{p}: {n}")
                } else {
                    format!("{p}: 0 — not on this host, or quiet in this window")
                }
            })
            .collect::<Vec<_>>()
            .join("; ");
        format!(
            "{} event(s) from {heard} of {} enabled provider(s){others} — {each}{lost}",
            self.events,
            self.providers_enabled.len()
        )
    }
}

pub fn session_name(lane: Lane) -> &'static str {
    match lane {
        Lane::P0 => "hemostat-p0",
        Lane::P1 => "hemostat-p1",
        Lane::P2 => "hemostat-p2",

        Lane::EventLog => "hemostat-eventlog-not-a-session",
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Buffers {

    pub size_kb: u32,

    pub minimum: u32,

    pub maximum: u32,

    pub flush_secs: u32,
}

pub fn buffers_for(lane: Lane, cpus: u32) -> Buffers {
    let cpus = cpus.clamp(1, 64);
    match lane {
        Lane::P0 => Buffers { size_kb: 8, minimum: cpus * 2, maximum: cpus * 4, flush_secs: 1 },
        Lane::P1 => Buffers { size_kb: 32, minimum: cpus * 2, maximum: cpus * 8, flush_secs: 2 },
        Lane::P2 => Buffers { size_kb: 64, minimum: cpus * 4, maximum: cpus * 16, flush_secs: 5 },
        Lane::EventLog => Buffers { size_kb: 0, minimum: 0, maximum: 0, flush_secs: 0 },
    }
}

pub fn enable_failure(p: &Provider, win_error: u32) -> String {
    let hint = match win_error {

        5 => " (access denied — this needs SYSTEM or an administrator with SeDebugPrivilege)",

        87 => " (invalid parameter — usually a malformed GUID or an unsupported keyword mask)",

        1168 => " (not registered on this Windows build)",

        1450 => " (no system resources — the host may already be at its ETW session limit)",
        _ => "",
    };
    format!(
        "{} did not enable: error {win_error}{hint}. Everything it would have carried — {} — is \
         absent from this run.",
        p.name, p.buys
    )
}
