#![allow(dead_code)]

use std::collections::BTreeSet;

use hemostat_sensor_linux::firewall::Reach;
use hemostat_sensor_linux::netpolicy::{Proto, Surface};

use crate::golden::ScoredService;

pub(crate) struct Health {
    pub svc: &'static ScoredService,

    pub up: Option<bool>,
}

pub(crate) fn health_of(mine: &[&'static ScoredService], listening: &BTreeSet<u16>, blind: bool) -> Vec<Health> {
    mine.iter()
        .map(|&s| {
            let up = match s.port {
                None => None,
                Some(_) if blind => None,
                Some(p) => Some(listening.contains(&p)),
            };
            Health { svc: s, up }
        })
        .collect()
}

pub(crate) struct HealthReport {

    pub services: Vec<Health>,

    pub not_checked: Option<String>,

    pub role: Option<crate::golden::Role>,
}

pub(crate) fn tcp_listening(surf: &Surface) -> BTreeSet<u16> {
    surf.services.iter().filter(|(proto, _, _)| *proto == Proto::Tcp).map(|(_, p, _)| *p).collect()
}

pub(crate) fn assess(golden_on: bool, host: Option<&str>, role_override: Option<&str>, surf: &Surface) -> HealthReport {
    if !golden_on {
        return HealthReport {
            services: Vec::new(),
            not_checked: Some("the IRSeC golden baseline is off (HEMOSTAT_GOLDEN), so there is no scored roster".into()),
            role: None,
        };
    }
    let role = match crate::golden::resolve_role(host, role_override) {
        Ok(r) => r,
        Err(gap) => return HealthReport { services: Vec::new(), not_checked: Some(gap), role: None },
    };
    let mine = crate::golden::services_of_role(role.name);
    let blind = !surf.unread.is_empty();
    let not_checked = blind.then(|| {
        format!(
            "the socket table could not be read ({}), so no scored service can be called up or down",
            surf.unread.join(", ")
        )
    });
    HealthReport { services: health_of(&mine, &tcp_listening(surf), blind), not_checked, role: Some(role) }
}

pub(crate) fn from_overview(ov: &hemostat_sensor_linux::overview::Report) -> HealthReport {

    let surf = hemostat_sensor_linux::netpolicy::survey_from(ov);
    let role_override = crate::golden::role_override();
    assess(crate::golden::active(), Some(ov.identity.hostname.as_str()), role_override.as_deref(), &surf)
}

pub(crate) fn reach_rows(
    health: &HealthReport,
    reach: impl Fn(u16) -> Reach,
) -> Vec<(&'static ScoredService, Reach)> {
    if health.not_checked.is_some() {
        return Vec::new();
    }
    health
        .services
        .iter()
        .filter(|h| h.up == Some(true))
        .filter_map(|h| {
            let port = h.svc.port?;
            match reach(port) {
                Reach::Open => None,
                r => Some((h.svc, r)),
            }
        })
        .collect()
}

pub(crate) fn firewall_reach(
    health: &HealthReport,
    fw: &hemostat_sensor_linux::FirewallReport,
) -> Vec<(&'static ScoredService, Reach)> {
    reach_rows(health, |port| fw.tcp_reach(port))
}
