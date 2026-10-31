#![allow(dead_code)]

use std::collections::BTreeSet;

#[cfg(target_os = "linux")]
use hemostat_sensor_linux::Account;

pub(crate) const LEGIT_USERS: &[&str] = &[

    "principal", "sportingdir", "chiefeng", "strategist",

    "pitcrew", "mechanic", "analyst", "driver", "tireman", "fuelman",

    "scrutineer", "techdirector", "crewchief", "firecrew",

    "jackcrew", "garagecrew", "celebrity", "pitlaner", "reserve", "gunners",
];

pub(crate) const HARD_PROTECT: &[&str] = hs_core::accounts::HARD_PROTECT;

pub(crate) fn is_legit(name: &str) -> bool {
    LEGIT_USERS.iter().any(|u| u.eq_ignore_ascii_case(name))
}

pub(crate) fn is_protected(name: &str) -> bool {
    hs_core::accounts::is_hard_protected(name)
}

pub(crate) const UID_MIN: u32 = 1000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UserClass {

    Allowed,

    Protected,

    System,

    Rogue,
}

pub(crate) fn classify(name: &str, uid: u32, can_login: bool) -> UserClass {
    if HARD_PROTECT.contains(&name) {
        return UserClass::Protected;
    }
    if !can_login || uid < UID_MIN {
        return UserClass::System;
    }
    if LEGIT_USERS.contains(&name) {
        return UserClass::Allowed;
    }
    UserClass::Rogue
}

#[cfg(target_os = "linux")]
pub(crate) fn rogue_users(accounts: &[Account]) -> Vec<&Account> {
    accounts.iter().filter(|a| classify(&a.name, a.uid, a.can_login()) == UserClass::Rogue).collect()
}

pub(crate) fn active() -> bool {
    std::env::var_os("HEMOSTAT_GOLDEN").is_some_and(|v| !v.is_empty())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Probe {
    Ssh,
    Ftp,
    Irc,
    MariaDb,
    Icmp,
    Telnet,
    Smb,
    Iis,
    WinRm,
    AdDns,

    Firewall,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct ScoredService {
    pub host: &'static str,
    pub os: &'static str,
    pub service: &'static str,
    pub probe: Probe,
    pub port: Option<u16>,
}

pub(crate) const SCORED_SERVICES: &[ScoredService] = &[
    ScoredService { host: "pitlane", os: "Debian 12", service: "SSH", probe: Probe::Ssh, port: Some(22) },
    ScoredService { host: "garage", os: "Ubuntu 22.04", service: "FTP", probe: Probe::Ftp, port: Some(21) },
    ScoredService { host: "grandstand", os: "Ubuntu 24.04", service: "IRC (Docker Compose)", probe: Probe::Irc, port: Some(6667) },
    ScoredService { host: "scrutineering", os: "Rocky 9", service: "MariaDB", probe: Probe::MariaDb, port: Some(3306) },
    ScoredService { host: "safetycar", os: "Windows 10", service: "ICMP", probe: Probe::Icmp, port: None },
    ScoredService { host: "safetycar", os: "Windows 10", service: "Telnet", probe: Probe::Telnet, port: Some(23) },
    ScoredService { host: "barrier", os: "pfSense 2.7.2", service: "routing/firewall", probe: Probe::Firewall, port: None },
    ScoredService { host: "pitwall", os: "Windows Server 2025", service: "AD/DNS", probe: Probe::AdDns, port: None },
    ScoredService { host: "teamradio", os: "Windows 11", service: "WinRM", probe: Probe::WinRm, port: Some(5985) },
    ScoredService { host: "transporters", os: "Windows Server 2022", service: "SMB", probe: Probe::Smb, port: Some(445) },
    ScoredService { host: "stewards", os: "Windows 10", service: "IIS", probe: Probe::Iis, port: Some(80) },
];

pub(crate) fn roles() -> Vec<&'static str> {
    let mut out: Vec<&'static str> = Vec::new();
    for s in SCORED_SERVICES {
        if !out.contains(&s.host) {
            out.push(s.host);
        }
    }
    out
}

pub(crate) const ROLE_ENV: &str = "HEMOSTAT_ROLE";

pub(crate) fn role_of_hostname(hostname: &str) -> Option<&'static str> {
    let label = hostname.trim().split('.').next().unwrap_or_default();
    if label.is_empty() {
        return None;
    }
    let roles = roles();
    if let Some(r) = roles.iter().find(|r| r.eq_ignore_ascii_case(label)) {
        return Some(r);
    }
    let mut parts = label.split(['-', '_']).filter_map(|p| roles.iter().find(|r| r.eq_ignore_ascii_case(p)));
    match (parts.next(), parts.next()) {
        (Some(r), None) => Some(r),
        _ => None,
    }
}

pub(crate) fn services_of_role(role: &str) -> Vec<&'static ScoredService> {
    SCORED_SERVICES.iter().filter(|s| s.host.eq_ignore_ascii_case(role)).collect()
}

pub(crate) fn services_for_host(hostname: &str) -> Vec<&'static ScoredService> {
    role_of_hostname(hostname).map(services_of_role).unwrap_or_default()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Role {
    pub name: &'static str,

    pub from_override: bool,
}

pub(crate) fn resolve_role(hostname: Option<&str>, role_override: Option<&str>) -> Result<Role, String> {
    let roles = roles();
    let named = roles.join(", ");
    if let Some(want) = role_override.map(str::trim).filter(|v| !v.is_empty()) {
        return match roles.iter().find(|r| r.eq_ignore_ascii_case(want)) {
            Some(r) => Ok(Role { name: r, from_override: true }),
            None => Err(format!(
                "{ROLE_ENV}=`{want}` is not one of the packet's roles ({named}): set it to one of them, \
                 or unset it to go by the hostname"
            )),
        };
    }
    let Some(host) = hostname.map(str::trim).filter(|h| !h.is_empty()) else {
        return Err(format!(
            "the hostname could not be read, so which scored services this box owns is not known. \
             Set {ROLE_ENV}=<role> to name it (one of {named})"
        ));
    };
    match role_of_hostname(host) {
        Some(r) => Ok(Role { name: r, from_override: false }),
        None => Err(format!(
            "hostname `{host}` is not one of the packet's roles ({named}), and its first label does \
             not name exactly one of them in its `-`/`_` parts: the box was renamed, or the packet \
             does not score it. Set {ROLE_ENV}=<role> to name this box's role outright"
        )),
    }
}

pub(crate) fn role_override() -> Option<String> {
    std::env::var_os(ROLE_ENV).map(|v| v.to_string_lossy().into_owned())
}

pub(crate) fn this_role(hostname: Option<&str>) -> Result<Role, String> {
    resolve_role(hostname, role_override().as_deref())
}

pub(crate) fn services_for_box(hostname: &str) -> Vec<&'static ScoredService> {
    this_role(Some(hostname)).map(|r| services_of_role(r.name)).unwrap_or_default()
}

pub(crate) fn role_said(role: &Role) -> String {
    let from = if role.from_override { ROLE_ENV } else { "the hostname" };
    format!("role `{}` (from {from})", role.name)
}

#[cfg(any(target_os = "linux", target_os = "windows"))]
pub(crate) fn role_json(role: Option<&Role>) -> String {
    role.map_or_else(String::new, |r| {
        let from = if r.from_override { ROLE_ENV } else { "hostname" };
        format!(",\"role\":{},\"role_from\":{}", crate::render::json_str(r.name), crate::render::json_str(from))
    })
}

pub(crate) fn units_for(probe: Probe) -> &'static [&'static str] {
    match probe {
        Probe::Ssh => &["ssh", "sshd"],
        Probe::Ftp => &["vsftpd", "pure-ftpd", "proftpd"],
        Probe::MariaDb => &["mariadb", "mysqld", "mysql"],
        Probe::Irc => &["docker", "containerd"],
        Probe::Icmp
        | Probe::Telnet
        | Probe::Smb
        | Probe::Iis
        | Probe::WinRm
        | Probe::AdDns
        | Probe::Firewall => &[],
    }
}

pub(crate) fn win_service_for(probe: Probe) -> Option<&'static str> {
    win_services_for(probe).first().copied()
}

pub(crate) fn win_services_for(probe: Probe) -> &'static [&'static str] {
    match probe {
        Probe::WinRm => &["WinRM"],
        Probe::Smb => &["LanmanServer"],
        Probe::Iis => &["W3SVC"],
        Probe::Telnet => &["TlntSvr"],
        Probe::AdDns => &["NTDS", "DNS"],
        Probe::Ssh | Probe::Ftp | Probe::Irc | Probe::MariaDb | Probe::Icmp | Probe::Firewall => &[],
    }
}

pub(crate) fn pick_unit<'a>(candidates: &[&'a str], known: &BTreeSet<String>) -> Option<&'a str> {
    candidates
        .iter()
        .copied()
        .find(|c| known.contains(*c) || known.contains(&format!("{c}.service")))
}

pub(crate) fn scored_units_of_role(role: &str) -> Vec<(String, &'static str)> {
    let mut out: Vec<(String, &'static str)> = Vec::new();
    for s in services_of_role(role) {
        for name in units_for(s.probe) {
            for unit in [format!("{name}.service"), format!("{name}.socket")] {
                if !out.iter().any(|(u, _)| *u == unit) {
                    out.push((unit, s.service));
                }
            }
        }
    }
    out
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ScoredHold {
    pub role: Role,
    pub units: Vec<(String, &'static str)>,
}

pub(crate) fn scored_hold(
    golden_on: bool,
    hostname: Option<&str>,
    role_override: Option<&str>,
) -> Option<Result<ScoredHold, String>> {
    golden_on.then(|| {
        resolve_role(hostname, role_override).map(|role| ScoredHold { role, units: scored_units_of_role(role.name) })
    })
}

pub(crate) fn hold_line(hold: &Result<ScoredHold, String>, held: &std::collections::BTreeMap<String, String>) -> String {
    let h = match hold {
        Ok(h) => h,
        Err(why) => {
            return format!("HEMOSTAT_GOLDEN is set, but no scored service is held back on this box: {why}")
        }
    };
    let mut by_service: std::collections::BTreeMap<&str, Vec<&str>> = std::collections::BTreeMap::new();
    for (unit, service) in held {
        by_service.entry(service.as_str()).or_default().push(unit.as_str());
    }
    if by_service.is_empty() {
        return format!(
            "HEMOSTAT_GOLDEN is set and this box is {}, which has no scored service a systemd unit \
             runs: nothing is held back",
            role_said(&h.role)
        );
    }
    let services: Vec<String> =
        by_service.iter().map(|(service, units)| format!("{service} ({})", units.join(", "))).collect();
    format!(
        "the packet's scored service on this box, {}: {} — never masked, stopped, disabled or \
         moved, and nothing it runs is killed or blocked, while it is down too",
        role_said(&h.role),
        services.join("; ")
    )
}

#[cfg(target_os = "linux")]
pub(crate) fn scored_hold_here() -> Option<Result<ScoredHold, String>> {
    if !active() {
        return None;
    }
    let host = hemostat_sensor_linux::saferead::read_scan_target(std::path::Path::new("/proc/sys/kernel/hostname"));
    scored_hold(true, host.as_deref(), role_override().as_deref())
}

#[cfg(target_os = "linux")]
pub(crate) fn scored_units_here() -> Vec<(String, String)> {
    match scored_hold_here() {
        Some(Ok(hold)) => hold.units.into_iter().map(|(unit, service)| (unit, service.to_string())).collect(),
        _ => Vec::new(),
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn scored_hold_by_name() -> hemostat_enforce_linux::ProtectSet {
    hemostat_enforce_linux::ProtectSet {
        scored_units: scored_units_here().into_iter().collect(),
        ..hemostat_enforce_linux::ProtectSet::default()
    }
}

pub(crate) const TEAM_ENV: &str = "HEMOSTAT_TEAM";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ScopeRange {
    Lan,
    Cloud,
}

#[cfg(target_os = "linux")]
pub(crate) const INFRA_EXCEPTIONS: &[(&str, u16)] = &[("10.64.250.228", 9000)];

const NETBIRD_EGRESS_OCTET: u8 = 99;

#[cfg(target_os = "linux")]
pub(crate) fn netbird_egress(team: u8) -> String {
    format!("10.{team}.1.{NETBIRD_EGRESS_OCTET}")
}

const PACKET_HOSTS: &[(ScopeRange, u8, &str, &str)] = &[
    (ScopeRange::Lan, 1, "pitwall", "your team's AD/DNS box, a scored service"),
    (ScopeRange::Lan, 2, "teamradio", "your team's WinRM box, a scored service"),
    (ScopeRange::Lan, 3, "safetycar", "your team's ICMP and Telnet box, a scored service"),
    (ScopeRange::Lan, 4, "pitlane", "your team's SSH box, a scored service"),
    (ScopeRange::Lan, 5, "garage", "your team's FTP box, a scored service"),
    (ScopeRange::Lan, 6, "grandstand", "your team's IRC box, a scored service"),
    (
        ScopeRange::Lan,
        NETBIRD_EGRESS_OCTET,
        "the NetBird egress",
        "out of scope in the packet (v2): do not modify, disable, or block this host or its traffic",
    ),
    (ScopeRange::Lan, 254, "barrier", "your team's pfSense router, which every scored check crosses"),
    (ScopeRange::Cloud, 1, "transporters", "your team's SMB box, a scored service"),
    (ScopeRange::Cloud, 2, "stewards", "your team's IIS box, a scored service"),
    (ScopeRange::Cloud, 3, "scrutineering", "your team's MariaDB box, a scored service"),
    (ScopeRange::Cloud, 4, "timing", "the Wazuh logging box, which is out of scope (rule 14): barrier to timing on port 514 must stay open"),
];

pub(crate) fn teams_of(own: &[std::net::IpAddr]) -> BTreeSet<u8> {
    own.iter()
        .filter_map(|a| match a {
            std::net::IpAddr::V4(v) => match v.octets() {
                [10, x, 1, _] | [192, 168, x, _] => Some(x),
                _ => None,
            },
            std::net::IpAddr::V6(_) => None,
        })
        .collect()
}

pub(crate) fn team(env: Option<&str>, own: &[std::net::IpAddr]) -> Result<u8, String> {
    if let Some(v) = env.map(str::trim).filter(|v| !v.is_empty()) {
        return v
            .parse::<u8>()
            .ok()
            .filter(|n| *n > 0)
            .ok_or_else(|| format!("${TEAM_ENV} is {v:?}, not a team number (1 to 255)"));
    }
    let teams = teams_of(own);
    let mut it = teams.iter();
    match (it.next(), it.next()) {
        (Some(t), None) => Ok(*t),
        (None, _) => Err(format!(
            "this host has no address in a packet range (10.x.1.0/24 or 192.168.x.0/24), so its \
             team number is not known: set {TEAM_ENV}=<your team number>"
        )),
        (Some(_), Some(_)) => Err(format!(
            "this host's addresses name more than one team ({}): set {TEAM_ENV}=<your team number>",
            teams.iter().map(u8::to_string).collect::<Vec<_>>().join(", ")
        )),
    }
}

pub(crate) fn block_scope_refusal(target: &hs_core::cidr::Cidr, team: Result<u8, String>) -> Option<String> {
    let t = match team {
        Ok(t) => t,
        Err(why) => {
            return Some(format!(
                "{why}. With HEMOSTAT_GOLDEN set a block is held to your team's in-scope ranges \
                 (packet rules 14 and 15)"
            ))
        }
    };
    let std::net::IpAddr::V4(a) = target.addr() else {
        return Some(format!(
            "{target} is IPv6; only 10.{t}.1.0/24 and 192.168.{t}.0/24 are in scope (packet rule \
             14), and an out-of-scope address may not be blocked (rule 15)"
        ));
    };
    if target.prefix() != 32 {
        return Some(format!("{target} is a range; the packet allows blocks of single addresses only (rule 15)"));
    }
    let (range, last) = match a.octets() {
        [10, x, 1, last] if x == t => (ScopeRange::Lan, last),
        [192, 168, x, last] if x == t => (ScopeRange::Cloud, last),
        _ => {
            return Some(format!(
                "{a} is outside your team's in-scope ranges 10.{t}.1.0/24 and 192.168.{t}.0/24, \
                 so it is out of scope: the packet forbids blocking it (rules 14 and 15). The \
                 scoring engine is out there too"
            ))
        }
    };
    if last == 0 || last == 255 {
        return Some(format!("{a} is the range's network or broadcast address, not a host"));
    }
    PACKET_HOSTS
        .iter()
        .find(|(r, o, ..)| *r == range && *o == last)
        .map(|(_, _, host, what)| format!("{a} is {host}, {what}; it is not blocked with HEMOSTAT_GOLDEN set"))
}

#[cfg(target_os = "linux")]
pub(crate) fn own_addrs() -> Vec<std::net::IpAddr> {
    hemostat_sensor_linux::saferead::read_text(std::path::Path::new("/proc/net/fib_trie"))
        .map(|t| hemostat_sensor_linux::flowexport::fib_trie_locals(&t))
        .unwrap_or_default()
}

#[cfg(target_os = "freebsd")]
pub(crate) fn own_addrs_of(config: &hemostat_sensor_freebsd::configxml::Config) -> Vec<std::net::IpAddr> {
    config
        .root()
        .child("interfaces")
        .map(|ifs| ifs.children.iter().filter_map(|i| i.text_at("ipaddr")?.trim().parse().ok()).collect())
        .unwrap_or_default()
}

pub(crate) fn block_scope_here(target: &hs_core::cidr::Cidr, own: &[std::net::IpAddr]) -> Option<String> {
    if !active() {
        return None;
    }
    block_scope_refusal(target, team(std::env::var(TEAM_ENV).ok().as_deref(), own))
}
