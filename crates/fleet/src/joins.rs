use std::any::Any;
use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::rc::Rc;

use sha2::{Digest as _, Sha256};

use crate::held::HeldFinding;
use crate::queue::{Evidence, Sev};
use crate::rejudge::Rejudge;
use crate::hex;

pub const MARGIN_S: u64 = 5;

pub const ASSUMED_SKEW_S: u64 = 60;

pub const SESSION_SLACK_NS: i64 = 30 * 60 * 1_000_000_000;

pub const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

const NS: i64 = 1_000_000_000;

pub type Pos = (u64, usize);

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Entity {

    Digest(String),

    Key(String),

    Command(String),

    Destination(String),
}

impl Entity {

    pub fn kind(&self) -> &'static str {
        match self {
            Entity::Digest(_) => "file sha256",
            Entity::Key(_) => "ssh key",
            Entity::Command(_) => "crontab line",
            Entity::Destination(_) => "destination",
        }
    }

    pub fn value(&self) -> &str {
        match self {
            Entity::Digest(v) | Entity::Key(v) | Entity::Command(v) | Entity::Destination(v) => v,
        }
    }

    pub fn short(&self) -> String {
        let v = self.value();
        let cut: String = match self {
            Entity::Digest(d) => d.chars().take(16).collect(),
            _ => v.chars().take(80).collect(),
        };
        format!("{} {cut}", self.kind())
    }
}

#[derive(Clone)]
pub enum FlowSide {

    Firewall(Rc<dyn Any>),

    Host(Rc<dyn Any>),
}

impl std::fmt::Debug for FlowSide {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            FlowSide::Firewall(_) => "Firewall(..)",
            FlowSide::Host(_) => "Host(..)",
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Conn {

    pub local: String,

    pub remote: IpAddr,

    pub port: u16,

    pub owner: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Presence {

    pub entity: Entity,

    pub at: String,
}

#[derive(Debug, Clone, Default)]
pub struct Facts {

    pub taken_ns: Option<i64>,

    pub hostname: String,

    pub addrs: Vec<IpAddr>,

    pub conns: Vec<Conn>,

    pub present: Vec<Presence>,

    pub flow: Option<FlowSide>,
}

#[derive(Debug, Clone)]
pub struct FlowAsk<'a> {

    pub offset_s: i64,

    pub skew_s: u64,

    pub elsewhere: &'a BTreeSet<IpAddr>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum FlowGrade {

    Contradiction,

    Unknown,

    Agreement,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowRow {

    pub grade: FlowGrade,

    pub flow: String,

    pub basis: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub struct FlowReport {

    pub host_on_fw: Vec<String>,

    pub flows: Vec<FlowRow>,

    pub unknowns: Vec<String>,

    pub clock: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ran {

    AllBut(BTreeSet<String>),

    One(String, Vec<String>),

    Nothing,
}

impl Ran {

    pub fn saw(&self, source: &str, subject: &str) -> bool {
        match self {
            Ran::AllBut(g) => !g.contains("*") && !g.contains(source),
            Ran::One(s, gaps) => s == source && (gaps.is_empty() || !subject.is_empty() && !gaps.iter().any(|g| g.contains(subject))),
            Ran::Nothing => false,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Found {

    pub id: String,

    pub source: String,

    pub subject: String,

    pub sev: Sev,

    pub entities: Vec<Entity>,

    pub text: String,
}

impl Found {

    pub fn of(id: &str, source: &str, subject: &str, fs: &[&HeldFinding]) -> Found {
        let mut e: BTreeSet<Entity> = BTreeSet::new();
        let mut text = String::new();
        for f in fs {
            e.extend(entities_of(f));
            text.push_str(&f.locus);
            text.push('\n');
            text.push_str(&f.what);
            text.push('\n');
        }
        Found {
            id: id.to_string(),
            source: source.to_string(),
            subject: subject.to_string(),
            sev: fs.iter().map(|f| f.severity).max().unwrap_or(Sev::Note),
            entities: e.into_iter().collect(),
            text,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Seen {

    pub pos: Pos,

    pub run: u64,

    pub host: [u8; 32],

    pub genesis: [u8; 32],

    pub at_ns: i64,

    pub taken_ns: i64,

    pub records: u64,

    pub facts: Facts,

    pub found: Vec<Found>,

    pub ran: Ran,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Measured {

    pub offset_ns: i64,

    pub spread_ns: i64,
}

#[derive(Debug, Clone, Default)]
pub struct HostInfo {

    pub label: String,

    pub clock: Option<Measured>,

    pub enrolled_ns: Option<i64>,

    pub beacon: Option<String>,

    pub gaps: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct Raise {

    pub pos: Pos,

    pub run: u64,

    pub host: [u8; 32],

    pub source: &'static str,

    pub subject: String,

    pub sev: Sev,

    pub store: String,

    pub at_ns: i64,

    pub evidence: Vec<Evidence>,

    pub basis: Vec<String>,
}

impl Raise {

    pub fn digest(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        for e in &self.evidence {
            for p in [&e.severity, &e.locus, &e.what, &e.why] {
                h.update(p.as_bytes());
                h.update([0x1f]);
            }
        }
        h.finalize().into()
    }
}

#[derive(Debug, Clone)]
pub struct Member {

    pub host: [u8; 32],

    pub label: String,

    pub flagged: Vec<(String, Sev)>,

    pub present: Vec<String>,

    pub spread: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Cluster {

    pub entity: Entity,

    pub severity: Sev,

    pub members: Vec<Member>,
}

#[derive(Debug, Clone)]
pub struct Chain {

    pub from: [u8; 32],

    pub to: [u8; 32],

    pub port: u16,

    pub service: &'static str,

    pub alert: String,

    pub raised: Vec<String>,

    pub window: String,
}

#[derive(Debug, Clone)]
pub struct FlowPair {

    pub fw: [u8; 32],

    pub host: [u8; 32],

    pub fw_store: [u8; 32],

    pub host_store: [u8; 32],

    pub counts: (usize, usize, usize),

    pub clock: String,

    pub recognised: Vec<String>,

    pub unknowns: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct Coverage {

    pub host: [u8; 32],

    pub label: String,

    pub status: &'static str,

    pub lines: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub struct Joins {

    pub flows: Vec<FlowPair>,

    pub clusters: Vec<Cluster>,

    pub chains: Vec<Chain>,

    pub coverage: Vec<Coverage>,

    pub notes: Vec<String>,
}

#[derive(Debug, Default)]
pub struct Joined {

    pub raises: Vec<Raise>,

    pub joins: Joins,
}

fn short(b: &[u8; 32]) -> String {
    hex(b).chars().take(16).collect()
}

fn label(info: &BTreeMap<[u8; 32], HostInfo>, h: &[u8; 32]) -> String {
    match info.get(h).map(|i| i.label.as_str()).filter(|l| !l.is_empty()) {
        Some(l) => format!("{l} ({})", hex(h).chars().take(8).collect::<String>()),
        None => format!("host {}", hex(h).chars().take(12).collect::<String>()),
    }
}

fn store_line(s: &Seen, what: &str) -> String {
    format!(
        "{what}: store {} from host {} (records 1..{} of every stream; arrived {}, ledger run {}; taken {} by the host's clock)",
        hex(&s.genesis),
        short(&s.host),
        s.records,
        crate::utc(s.at_ns),
        s.run,
        crate::utc(s.taken_ns)
    )
}

pub fn run(seen: &[Seen], info: &BTreeMap<[u8; 32], HostInfo>, judge: &dyn Rejudge) -> Joined {
    let mut out = Joined::default();
    j1(seen, info, judge, &mut out);
    j2(seen, info, &mut out);
    j3(seen, info, &mut out);
    j4(seen, info, &mut out);
    out
}

fn flow_clock(info: &BTreeMap<[u8; 32], HostInfo>, fw: &[u8; 32], host: &[u8; 32]) -> (i64, u64, String) {
    let c = |h: &[u8; 32]| info.get(h).and_then(|i| i.clock);
    match (c(fw), c(host)) {
        (Some(f), Some(h)) => {
            let off = h.offset_ns - f.offset_ns;
            let spread = u64::try_from(f.spread_ns.saturating_add(h.spread_ns).max(0)).unwrap_or(0);
            let skew = spread.div_ceil(1_000_000_000) + MARGIN_S;
            (
                off,
                skew,
                format!(
                    "measured: box − host = {} from both agents' heartbeats (collector − host {}, collector − box {}); bound ±{skew} s (their spreads plus {MARGIN_S} s)",
                    crate::heartbeat::secs(off),
                    crate::heartbeat::secs(h.offset_ns),
                    crate::heartbeat::secs(f.offset_ns)
                ),
            )
        }
        (f, h) => {
            let who: Vec<String> = [(fw, f.is_none(), "the firewall"), (host, h.is_none(), "the host")]
                .iter()
                .filter(|(_, missing, _)| *missing)
                .map(|(id, _, role)| format!("{role} ({})", label(info, id)))
                .collect();
            (
                0,
                ASSUMED_SKEW_S,
                format!(
                    "NOT MEASURED: {} sends no heartbeats, so the two clocks are compared as they read, with S11's assumed bound of ±{ASSUMED_SKEW_S} s; the agreed flows still check it",
                    who.join(" and ")
                ),
            )
        }
    }
}

fn pairings<'a>(exports: &[(&'a Seen, &'a Rc<dyn Any>)], h: &[u8; 32], offset_ns: i64, f: &Seen) -> Vec<(&'a Seen, &'a Rc<dyn Any>)> {
    let mut cand: Vec<(&Seen, &Rc<dyn Any>)> =
        exports.iter().filter(|(e, _)| e.host == *h && e.taken_ns.saturating_add(offset_ns) <= f.taken_ns).copied().collect();
    cand.sort_by_key(|(e, _)| e.pos);
    let mut out: Vec<(&Seen, &Rc<dyn Any>)> = Vec::new();
    let mut best: Option<(&Seen, &Rc<dyn Any>)> = None;
    for c in cand {
        let better = best.is_none_or(|b| c.0.taken_ns > b.0.taken_ns);
        if c.0.pos <= f.pos {
            if better {
                best = Some(c);
            }
            continue;
        }
        if out.is_empty() {
            out.extend(best);
        }
        if better {
            best = Some(c);
            out.push(c);
        }
    }
    if out.is_empty() {
        out.extend(best);
    }
    out
}

fn j1(seen: &[Seen], info: &BTreeMap<[u8; 32], HostInfo>, judge: &dyn Rejudge, out: &mut Joined) {
    let fws: Vec<(&Seen, &Rc<dyn Any>)> = seen
        .iter()
        .filter_map(|s| match &s.facts.flow {
            Some(FlowSide::Firewall(d)) => Some((s, d)),
            _ => None,
        })
        .collect();
    let exports: Vec<(&Seen, &Rc<dyn Any>)> = seen
        .iter()
        .filter_map(|s| match &s.facts.flow {
            Some(FlowSide::Host(d)) => Some((s, d)),
            _ => None,
        })
        .collect();
    let hosts: BTreeSet<[u8; 32]> = exports.iter().map(|(s, _)| s.host).collect();
    let mut no_prior = 0usize;
    for (f, fdata) in &fws {
        for h in hosts.iter().filter(|h| **h != f.host) {
            let (offset_ns, skew_s, said) = flow_clock(info, &f.host, h);
            let pairs = pairings(&exports, h, offset_ns, f);
            if pairs.is_empty() {
                no_prior += 1;
                continue;
            }
            for (e, edata) in pairs {
                let pos = f.pos.max(e.pos);

                let mut latest: BTreeMap<[u8; 32], &Seen> = BTreeMap::new();
                for (o, _) in exports.iter().filter(|(o, _)| o.host != *h && o.host != f.host && o.pos <= pos) {
                    let slot = latest.entry(o.host).or_insert(o);
                    if o.pos > slot.pos {
                        *slot = o;
                    }
                }
                let elsewhere: BTreeSet<IpAddr> = latest.values().flat_map(|o| o.facts.addrs.iter().copied()).collect();
                let ask = FlowAsk { offset_s: offset_ns.div_euclid(NS), skew_s, elsewhere: &elsewhere };
                let Some(r) = judge.flow(fdata.as_ref(), edata.as_ref(), &ask) else { continue };
                if r.host_on_fw.is_empty() {
                    continue;
                }
                let count = |g: FlowGrade| r.flows.iter().filter(|x| x.grade == g).count();
                let basis = vec![
                    store_line(f, "the firewall's capture"),
                    store_line(e, "the host's flow export"),
                    format!("clocks: {said}"),
                    format!("the evidence's own check: {}", r.clock),
                    format!("the host on the firewall: {}", r.host_on_fw.join("; ")),
                ];
                for row in r.flows.iter().filter(|x| x.grade == FlowGrade::Contradiction) {
                    let mut rest = row.basis.iter().skip(1).cloned().collect::<Vec<_>>();
                    rest.push(format!("firewall {} · clocks {said}", label(info, &f.host)));
                    out.raises.push(Raise {
                        pos,
                        run: f.run.max(e.run),
                        host: *h,
                        source: "flow",
                        subject: row.flow.clone(),
                        sev: Sev::Critical,
                        store: format!("j1 {}+{}", short(&f.genesis), short(&e.genesis)),
                        at_ns: f.at_ns.max(e.at_ns),
                        evidence: vec![Evidence {
                            severity: "CONTRADICTION".to_string(),
                            locus: row.flow.clone(),
                            what: row.basis.first().cloned().unwrap_or_default(),
                            why: rest.join(" | "),
                        }],
                        basis: basis.clone(),
                    });
                }
                out.joins.flows.push(FlowPair {
                    fw: f.host,
                    host: *h,
                    fw_store: f.genesis,
                    host_store: e.genesis,
                    counts: (count(FlowGrade::Contradiction), count(FlowGrade::Agreement), count(FlowGrade::Unknown)),
                    clock: said.clone(),
                    recognised: r.host_on_fw.clone(),
                    unknowns: r.unknowns.clone(),
                });
            }
        }
    }
    if no_prior > 0 {
        out.joins.notes.push(format!(
            "J1: {no_prior} firewall capture × host pair(s) not joined: the host had no flow export taken before the capture, \
             and a flow can be shown alive across a sweep only by a capture after it"
        ));
    }
}

pub fn entities_of(f: &HeldFinding) -> Vec<Entity> {
    let mut out: BTreeSet<Entity> = BTreeSet::new();
    for d in &f.files {
        if d.vouched.is_none() && d.sha256 != EMPTY_SHA256 {
            out.insert(Entity::Digest(d.sha256.clone()));
        }
    }
    for t in [&f.subject, &f.locus, &f.what, &f.why] {
        out.extend(key_fingerprints(t).into_iter().map(Entity::Key));
    }
    if f.source == "persistence" {
        if let Some(c) = cron_command(&f.subject, &f.what) {
            out.insert(Entity::Command(c));
        }
    }
    out.extend(destinations(&f.locus).into_iter().map(Entity::Destination));
    out.into_iter().collect()
}

pub fn key_fingerprints(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(i) = rest.find("SHA256:") {
        let after = rest.get(i + 7..).unwrap_or_default();
        let fp: String = after.chars().take_while(|c| c.is_ascii_alphanumeric() || *c == '+' || *c == '/').collect();
        if fp.len() == 43 {
            out.push(format!("SHA256:{fp}"));
        }
        rest = after;
    }
    out
}

pub fn cron_command(mechanism: &str, line: &str) -> Option<String> {
    if !mechanism.starts_with("cron-") || mechanism == "cron-periodic" {
        return None;
    }
    let words: Vec<&str> = line.split_whitespace().collect();
    let first = words.first()?;
    let schedule = if first.starts_with('@') {
        1
    } else {
        let field = |w: &str| {
            w.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '*' | '/' | ',' | '-'))
                && w.chars().any(|c| c.is_ascii_digit() || c == '*')
        };
        if words.len() < 6 || !words.iter().take(5).all(|w| field(w)) {
            return None;
        }
        5
    };
    let user = usize::from(matches!(mechanism, "cron-system" | "cron-d"));
    let cmd = words.get(schedule + user..)?.join(" ");
    (cmd.len() >= 4).then_some(cmd)
}

pub fn destinations(locus: &str) -> Vec<String> {
    let mut out = Vec::new();
    for part in locus.split("->").skip(1) {
        let Some(tok) = part.split_whitespace().next() else { continue };
        let host = if let Some(v6) = tok.strip_prefix('[') {
            v6.split(']').next().unwrap_or_default()
        } else {
            tok.rsplit_once(':').map_or(tok, |(h, _)| h)
        };
        let Ok(a) = host.parse::<IpAddr>() else { continue };
        let local = match a {
            IpAddr::V4(v) => v.is_loopback() || v.is_unspecified() || v.is_link_local() || v.is_multicast() || v.is_broadcast(),
            IpAddr::V6(v) => v.is_loopback() || v.is_unspecified() || v.is_multicast() || (v.segments()[0] & 0xffc0) == 0xfe80,
        };
        if !local {
            out.push(a.to_string());
        }
    }
    out
}

fn j2(seen: &[Seen], info: &BTreeMap<[u8; 32], HostInfo>, out: &mut Joined) {

    type Flag = BTreeMap<[u8; 32], BTreeMap<String, (Sev, Pos, String)>>;
    type Recorded<'a> = BTreeMap<[u8; 32], Vec<(Pos, &'a Seen, String)>>;
    let mut flagged: BTreeMap<Entity, Flag> = BTreeMap::new();
    let mut present: BTreeMap<Entity, Recorded<'_>> = BTreeMap::new();
    for s in seen {
        for f in &s.found {
            for e in &f.entities {
                let what = format!("[{}] {} · {}", f.sev.token(), f.source, f.subject);
                let slot = flagged.entry(e.clone()).or_default().entry(s.host).or_default().entry(f.id.clone()).or_insert((f.sev, s.pos, what));
                slot.0 = slot.0.max(f.sev);
            }
        }
        for p in &s.facts.present {
            present.entry(p.entity.clone()).or_default().entry(s.host).or_default().push((s.pos, s, p.at.clone()));
        }
    }
    for (e, by_host) in &flagged {

        let anchors: Vec<([u8; 32], &String, Sev, Pos, &String)> = by_host
            .iter()
            .flat_map(|(h, ids)| ids.iter().filter(|(_, v)| v.0 >= Sev::Warn).map(move |(id, v)| (*h, id, v.0, v.1, &v.2)))
            .collect();
        if anchors.is_empty() {
            continue;
        }
        let pres = present.get(e);
        let mut hosts: BTreeSet<[u8; 32]> = by_host.keys().copied().collect();
        if let Some(p) = pres {
            hosts.extend(p.keys().copied());
        }
        if hosts.len() < 2 {
            continue;
        }
        let severity = anchors.iter().map(|a| a.2).max().unwrap_or(Sev::Warn);
        let mut members = Vec::new();
        for h in &hosts {
            let flags: Vec<(String, Sev)> =
                by_host.get(h).map(|ids| ids.iter().map(|(id, v)| (id.clone(), v.0)).collect()).unwrap_or_default();
            let mut at: Vec<String> = pres.and_then(|p| p.get(h)).map(|v| v.iter().map(|(_, _, a)| a.clone()).collect()).unwrap_or_default();
            at.sort();
            at.dedup();

            let own_first = by_host.get(h).and_then(|ids| ids.values().map(|v| v.1).min());
            let others: Vec<&([u8; 32], &String, Sev, Pos, &String)> = anchors.iter().filter(|a| a.0 != *h).collect();
            let first = others.iter().min_by_key(|a| a.3);
            let entries: Vec<&(Pos, &Seen, String)> = match (pres.and_then(|p| p.get(h)), first) {
                (Some(v), Some(first)) => v.iter().filter(|(p, _, _)| own_first.is_none_or(|o| (*p).max(first.3) < o)).collect(),
                _ => Vec::new(),
            };
            let spread = (!entries.is_empty()).then(|| crate::queue::alert_id(h, "spread", &e.short()));
            members.push(Member { host: *h, label: label(info, h), flagged: flags.clone(), present: at, spread });
            let Some(first) = first else { continue };
            let sev = others.iter().map(|a| a.2).max().unwrap_or(Sev::Warn).min(Sev::Warn);
            let flagged_by: Vec<String> = others.iter().map(|a| format!("{} {}", label(info, &a.0), a.4)).collect();
            for (pos, s, at) in entries {
                let pos = (*pos).max(first.3);
                out.raises.push(Raise {
                    pos,
                    run: s.run.max(first.3 .0),
                    host: *h,
                    source: "spread",
                    subject: e.short(),
                    sev,
                    store: hex(&s.genesis),
                    at_ns: s.at_ns,
                    evidence: vec![Evidence {
                        severity: sev.token().to_string(),
                        locus: at.clone(),
                        what: format!("the {} {} is recorded here, and another host flagged it: {}", e.kind(), e.value(), flagged_by.join("; ")),
                        why: "the same thing on two hosts is one intrusion in two places, or one legitimate thing a sweep \
                              misread twice. Nothing on this host flagged it, so how it runs here was not judged: look \
                              before trusting the host. The other host's alert stays its own"
                            .to_string(),
                    }],
                    basis: vec![
                        store_line(s, "where it is recorded"),
                        format!("anchored by {} on {}", first.1, label(info, &first.0)),
                        format!("cluster: {} host(s) share the {}", hosts.len(), e.kind()),
                    ],
                });
            }
        }
        out.joins.clusters.push(Cluster { entity: e.clone(), severity, members });
    }
    out.joins.clusters.sort_by(|a, b| b.severity.cmp(&a.severity).then(b.members.len().cmp(&a.members.len())).then(a.entity.cmp(&b.entity)));
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {

    Key,

    Account,

    Persistence,
}

pub fn service(port: u16) -> Option<(&'static str, &'static [Class])> {
    const ALL: &[Class] = &[Class::Key, Class::Account, Class::Persistence];
    const LOGIN: &[Class] = &[Class::Account, Class::Persistence];
    Some(match port {
        22 => ("ssh", ALL),
        23 => ("telnet", LOGIN),
        3389 => ("rdp", LOGIN),
        5985 | 5986 => ("winrm", LOGIN),
        139 | 445 => ("smb", LOGIN),
        135 => ("rpc", &[Class::Persistence]),
        5900 => ("vnc", LOGIN),
        _ => return None,
    })
}

pub fn class_of(f: &Found) -> Option<Class> {
    let t = format!("{}\n{}", f.subject, f.text).to_ascii_lowercase();
    if t.contains("authorized_keys") || t.contains("authorizedkeys") || t.contains("sha256:") && t.contains("key") {
        return Some(Class::Key);
    }
    match f.source.as_str() {
        "accounts" => Some(Class::Account),
        "persistence" | "systemd" => Some(Class::Persistence),

        "drift" if f.subject.starts_with("user") || f.subject.starts_with("group") || f.subject.starts_with("system/user") => {
            Some(Class::Account)
        }
        "drift" => Some(Class::Persistence),
        _ => None,
    }
}

fn j3(seen: &[Seen], info: &BTreeMap<[u8; 32], HostInfo>, out: &mut Joined) {

    let mut latest: BTreeMap<[u8; 32], &Seen> = BTreeMap::new();
    for s in seen.iter().filter(|s| !s.facts.addrs.is_empty()) {
        let slot = latest.entry(s.host).or_insert(s);
        if s.pos > slot.pos {
            *slot = s;
        }
    }
    let mut owner: BTreeMap<IpAddr, BTreeSet<[u8; 32]>> = BTreeMap::new();
    for (h, s) in &latest {
        for a in &s.facts.addrs {
            owner.entry(*a).or_default().insert(*h);
        }
    }
    let mut not_new = BTreeSet::new();
    let mut twice = BTreeSet::new();
    for a in seen {
        for c in &a.facts.conns {
            let Some((svc, classes)) = service(c.port) else { continue };
            let Some(owners) = owner.get(&c.remote) else { continue };
            if owners.len() > 1 {
                twice.insert(c.remote);
                continue;
            }
            let Some(b) = owners.iter().next().copied().filter(|b| *b != a.host) else { continue };

            let mut firsts: BTreeMap<&str, (&Seen, &Found)> = BTreeMap::new();
            for s in seen.iter().filter(|s| s.host == b) {
                for f in &s.found {
                    firsts.entry(f.id.as_str()).or_insert((s, f));
                }
            }
            for (id, (s1, f)) in firsts {
                if f.sev < Sev::Warn || !class_of(f).is_some_and(|k| classes.contains(&k)) {
                    continue;
                }
                let s0 = seen
                    .iter()
                    .filter(|s| s.host == b && s.pos < s1.pos && s.ran.saw(&f.source, &f.subject) && !s.found.iter().any(|g| g.id == id))
                    .max_by_key(|s| s.pos);
                let Some(s0) = s0 else {
                    not_new.insert(id.to_string());
                    continue;
                };
                let (ca, cb) = (info.get(&a.host).and_then(|i| i.clock), info.get(&b).and_then(|i| i.clock));
                let off = |m: Option<Measured>| m.map_or(0, |m| m.offset_ns);
                let ta = a.taken_ns.saturating_add(off(ca));
                let (t0, t1) = (s0.taken_ns.saturating_add(off(cb)), s1.taken_ns.saturating_add(off(cb)));
                let (bound, bound_text) = match (ca, cb) {
                    (Some(x), Some(y)) => {
                        let b = x.spread_ns.saturating_add(y.spread_ns).saturating_add(i64::try_from(MARGIN_S).unwrap_or(0) * NS);
                        (b, format!("clock bound ±{} (both hosts' measured spreads plus {MARGIN_S} s), on the collector's clock", crate::heartbeat::secs(b).trim_start_matches('+')))
                    }
                    _ => {
                        let who: Vec<String> = [(a.host, ca.is_none()), (b, cb.is_none())]
                            .iter()
                            .filter(|(_, m)| *m)
                            .map(|(h, _)| label(info, h))
                            .collect();
                        (
                            0,
                            format!(
                                "clock bound UNKNOWN: {} sends no heartbeats, so its clock is not measured and the times are its own, uncorrected",
                                who.join(" and ")
                            ),
                        )
                    }
                };
                let lo = t0.saturating_sub(bound).saturating_sub(SESSION_SLACK_NS);
                let hi = t1.saturating_add(bound).saturating_add(SESSION_SLACK_NS);
                if ta < lo || ta > hi {
                    continue;
                }
                let window = format!(
                    "B's change window ({} .. {}], A's socket seen {}; {bound_text}; a session may be seen up to {} either side",
                    crate::utc(t0),
                    crate::utc(t1),
                    crate::utc(ta),
                    crate::span(SESSION_SLACK_NS)
                );
                let pos = a.pos.max(s1.pos);
                let basis = vec![
                    store_line(a, "A's flow export, holding the socket"),
                    store_line(s0, "B's last store where the sweep ran, could see it, and did not show it"),
                    store_line(s1, "B's first store showing it"),
                    window.clone(),
                ];
                let socket = format!("{} -> {}:{} ({svc}), held by {}", c.local, c.remote, c.port, if c.owner.is_empty() { "no owner found" } else { &c.owner });
                let why = "a session from one host to another's remote-access service, and on the far end a new key, \
                           account or persistence that service can leave, in the same window: the shape of lateral \
                           movement, and also of an administrator at work. A lead on both hosts; B's own alert keeps \
                           its grade";
                let mut raised = Vec::new();
                for (on, subject, what) in [
                    (a.host, format!("to {}:{} · {} · {}", label(info, &b), c.port, f.source, f.subject), format!("this host held {socket}, and {} shows [{}] {} · {} first in its store {}", label(info, &b), f.sev.token(), f.source, f.subject, short(&s1.genesis))),
                    (b, format!("from {} :{} · {} · {}", label(info, &a.host), c.port, f.source, f.subject), format!("{} held {socket}, and this host's alert [{}] {} · {} first shows in its store {}", label(info, &a.host), f.sev.token(), f.source, f.subject, short(&s1.genesis))),
                ] {
                    raised.push(crate::queue::alert_id(&on, "lateral", &subject));
                    out.raises.push(Raise {
                        pos,
                        run: a.run.max(s1.run),
                        host: on,
                        source: "lateral",
                        subject,
                        sev: Sev::Warn,
                        store: format!("j3 {}+{}", short(&a.genesis), short(&s1.genesis)),
                        at_ns: a.at_ns.max(s1.at_ns),
                        evidence: vec![Evidence { severity: Sev::Warn.token().to_string(), locus: socket.clone(), what, why: format!("{why}. {window}") }],
                        basis: basis.clone(),
                    });
                }
                out.joins.chains.push(Chain { from: a.host, to: b, port: c.port, service: svc, alert: id.to_string(), raised, window });
            }
        }
    }

    let mut seen_chain = BTreeSet::new();
    out.joins.chains.retain(|c| seen_chain.insert((c.from, c.to, c.port, c.alert.clone())));
    if !not_new.is_empty() {
        out.joins.notes.push(format!(
            "J3: {} alert(s) on a host a socket reached were there from that host's first store in which the sweep could see them, so \
             none is shown new and no chain is drawn from it",
            not_new.len()
        ));
    }
    if !twice.is_empty() {
        out.joins.notes.push(format!(
            "J3: {} address(es) are held by two hosts, so a socket to them reaches no one host: {}",
            twice.len(),
            twice.iter().map(IpAddr::to_string).collect::<Vec<_>>().join(", ")
        ));
    }
}

fn j4(seen: &[Seen], info: &BTreeMap<[u8; 32], HostInfo>, out: &mut Joined) {
    let any_fw = seen.iter().any(|s| matches!(s.facts.flow, Some(FlowSide::Firewall(_))));
    for (h, i) in info {
        let stores = seen.iter().filter(|s| s.host == *h).count();
        let exports = seen.iter().filter(|s| s.host == *h && matches!(s.facts.flow, Some(FlowSide::Host(_)))).count();
        let is_fw = seen.iter().any(|s| s.host == *h && matches!(s.facts.flow, Some(FlowSide::Firewall(_))));
        let mut lines = Vec::new();
        let mut status = "ok";
        if stores == 0 && i.beacon.is_none() {
            status = "never heard from";
            lines.push(match i.enrolled_ns {
                Some(t) => format!("enrolled {} and nothing since: no store, no heartbeat", crate::utc(t)),
                None => "no store and no heartbeat".to_string(),
            });
        }
        if i.beacon.as_deref() == Some("silent") {
            status = if status == "ok" { "silent" } else { status };
            lines.push("its heartbeats stopped: see its agent-silent alert".to_string());
        }
        if !i.gaps.is_empty() {
            status = if status == "ok" { "gaps" } else { status };
            lines.push(format!("sweeps with gaps in its latest store: {}", i.gaps.join(", ")));
        }
        if stores > 0 && !is_fw {
            if exports == 0 {
                lines.push("no flow export (`overview --export`) from it: J1 and J3 cannot see its connections".to_string());
            } else if any_fw && !out.joins.flows.iter().any(|p| p.host == *h) {
                lines.push("its flow exports are in no firewall capture taken after them: no J1 pair".to_string());
            }
            if status == "ok" && !lines.is_empty() {
                status = "blind to joins";
            }
        }
        if i.beacon.is_none() && stores > 0 {
            lines.push("no heartbeat: its clock is not measured, so a join compares its times uncorrected".to_string());
        }
        out.joins.coverage.push(Coverage { host: *h, label: label(info, h), status, lines });
    }
    let rank = |s: &str| match s {
        "never heard from" => 0,
        "silent" => 1,
        "gaps" => 2,
        "blind to joins" => 3,
        _ => 4,
    };
    out.joins.coverage.sort_by(|a, b| rank(a.status).cmp(&rank(b.status)).then(a.label.cmp(&b.label)));
}
