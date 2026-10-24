use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use hemostat_evcrypto::secret::Secret32;
use sha2::{Digest, Sha256};

use crate::held::{read_held, HeldFinding, HeldGap, HeldStore, Readable};
use crate::rejudge::{NoRejudge, Outcome, Rejudge};
use crate::ingest::Layout;
use crate::json::{self, Value};
use crate::{hex, js};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Sev {

    Info,

    Note,

    Warn,

    Critical,
}

impl Sev {

    pub fn token(self) -> &'static str {
        match self {
            Sev::Info => "info",
            Sev::Note => "note",
            Sev::Warn => "WARN",
            Sev::Critical => "CRITICAL",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Resolution {

    TruePositive,

    FalsePositive,

    Benign,
}

impl Resolution {

    pub fn name(self) -> &'static str {
        match self {
            Resolution::TruePositive => "true-positive",
            Resolution::FalsePositive => "false-positive",
            Resolution::Benign => "benign",
        }
    }

    pub fn parse(s: &str) -> Option<Resolution> {
        match s {
            "true-positive" | "tp" | "t" => Some(Resolution::TruePositive),
            "false-positive" | "fp" | "f" => Some(Resolution::FalsePositive),
            "benign" | "b" => Some(Resolution::Benign),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {

    New,

    Acked,

    Investigating,

    Resolved(Resolution),

    Reopened,
}

impl State {

    pub fn name(self) -> String {
        match self {
            State::New => "new".to_string(),
            State::Acked => "acked".to_string(),
            State::Investigating => "investigating".to_string(),
            State::Resolved(r) => format!("resolved:{}", r.name()),
            State::Reopened => "reopened".to_string(),
        }
    }

    pub fn parse(s: &str) -> Option<State> {
        Some(match s {
            "new" => State::New,
            "acked" => State::Acked,
            "investigating" => State::Investigating,
            "reopened" => State::Reopened,
            r => State::Resolved(Resolution::parse(r.strip_prefix("resolved:")?)?),
        })
    }

    pub fn is_resolved(self) -> bool {
        matches!(self, State::Resolved(_))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {

    Ack,

    Investigate,

    Resolve(Resolution),

    Note,
}

impl Action {

    pub fn name(&self) -> &'static str {
        match self {
            Action::Ack => "ack",
            Action::Investigate => "investigate",
            Action::Resolve(_) => "resolve",
            Action::Note => "note",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Actor {

    pub uid: u32,

    pub name: String,
}

impl Actor {

    pub fn label(&self) -> String {
        format!("uid={}({})", self.uid, self.name)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {

    Finding,

    Collector,

    Join,
}

#[derive(Debug, Clone)]
pub struct Sighting {

    pub store: String,

    pub seqs: Vec<u64>,

    pub at_ns: i64,

    pub severity: Sev,

    pub digest: [u8; 32],

    pub ledger_run: u64,
}

#[derive(Debug, Clone)]
pub struct Event {

    pub at_ns: i64,

    pub actor: String,

    pub session: String,

    pub action: String,

    pub from: String,

    pub to: String,

    pub reason: String,

    pub ledger_run: u64,

    pub owner_matches: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Evidence {

    pub severity: String,

    pub locus: String,

    pub what: String,

    pub why: String,
}

#[derive(Debug, Clone)]
pub struct Alert {

    pub id: String,

    pub host: [u8; 32],

    pub source: String,

    pub subject: String,

    pub origin: Origin,

    pub first_ns: i64,

    pub last_ns: i64,

    pub sightings: Vec<Sighting>,

    pub max_sev: Sev,

    pub cur_sev: Sev,

    pub state: State,

    pub owner: Option<String>,

    pub history: Vec<Event>,

    pub evidence: Vec<Evidence>,

    pub absent_from_latest: bool,

    pub judged_here: Option<String>,

    pub basis: Vec<String>,
    resolved_basis: Option<([u8; 32], Sev)>,
}

pub fn alert_id(host: &[u8; 32], source: &str, subject: &str) -> String {
    let mut h = Sha256::new();
    h.update(host);
    h.update([0x1f]);
    h.update(source.as_bytes());
    h.update([0x1f]);
    h.update(subject.as_bytes());
    let d: [u8; 32] = h.finalize().into();
    hex(d.get(..8).unwrap_or_default())
}

impl Alert {
    fn new(host: [u8; 32], source: &str, subject: &str, origin: Origin, s: Sighting) -> Alert {
        Alert {
            id: alert_id(&host, source, subject),
            host,
            source: source.to_string(),
            subject: subject.to_string(),
            origin,
            first_ns: s.at_ns,
            last_ns: s.at_ns,
            max_sev: s.severity,
            cur_sev: s.severity,
            sightings: vec![s],
            state: State::New,
            owner: None,
            history: Vec::new(),
            evidence: Vec::new(),
            absent_from_latest: false,
            judged_here: None,
            basis: Vec::new(),
            resolved_basis: None,
        }
    }

    fn sight(&mut self, s: Sighting) {
        self.last_ns = self.last_ns.max(s.at_ns);
        self.cur_sev = s.severity;
        self.max_sev = self.max_sev.max(s.severity);
        if let (State::Resolved(_), Some((digest, sev))) = (self.state, self.resolved_basis) {
            let why = if s.severity > sev {
                Some(format!("seen again graded {}, above the {} it had when it was resolved", s.severity.token(), sev.token()))
            } else if s.digest != digest {
                Some("seen again with different evidence from what was resolved".to_string())
            } else {
                None
            };
            if let Some(reason) = why {
                self.history.push(Event {
                    at_ns: s.at_ns,
                    actor: "ingest".to_string(),
                    session: String::new(),
                    action: "reopen".to_string(),
                    from: self.state.name(),
                    to: State::Reopened.name(),
                    reason,
                    ledger_run: s.ledger_run,
                    owner_matches: true,
                });
                self.state = State::Reopened;
                self.resolved_basis = None;
            }
        }

        let finding = self.origin != Origin::Collector;
        match self.sightings.last_mut() {
            Some(last) if finding && last.store == s.store => *last = s,
            _ => self.sightings.push(s),
        }
    }

    pub fn check(&self, action: &Action, actor: &Actor, reason: &str) -> Result<State, String> {
        let reason_needed = matches!(action, Action::Resolve(_) | Action::Note);
        if reason_needed && reason.trim().is_empty() {
            return Err(format!("{} needs a reason: it is what the ledger keeps of the judgement", action.name()));
        }
        if self.state.is_resolved() && !matches!(action, Action::Note) {
            return Err(format!(
                "the alert is {}; only ingest reopens it, when it is seen again with new evidence or a higher \
                 grade. A note can still be added",
                self.state.name()
            ));
        }
        Ok(match action {
            Action::Ack => {
                if self.state == State::Acked && self.owner.as_deref() == Some(actor.label().as_str()) {
                    return Err("you already own it".to_string());
                }
                State::Acked
            }
            Action::Investigate => {
                if self.state == State::Investigating && self.owner.as_deref() == Some(actor.label().as_str()) {
                    return Err("you are already investigating it".to_string());
                }
                State::Investigating
            }
            Action::Resolve(r) => State::Resolved(*r),
            Action::Note => self.state,
        })
    }

    fn apply(&mut self, action: &Action, to: State, ev: Event) {
        match action {
            Action::Ack | Action::Investigate => self.owner = Some(ev.actor.clone()),
            Action::Resolve(_) => {
                self.resolved_basis = self.sightings.last().map(|s| (s.digest, self.max_sev));
            }
            Action::Note => {}
        }
        self.state = to;
        self.history.push(ev);
    }

    pub fn latest(&self) -> Option<&Sighting> {
        self.sightings.last()
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Beacon {

    pub agent: String,

    pub state: String,

    pub as_of_ns: i64,

    pub last_ns: i64,

    pub run: String,

    pub seq: u64,

    pub received: u64,

    pub missing: u64,

    pub restarts: u64,

    pub stale: u64,

    pub offset_ns: Option<i64>,

    pub spread_ns: Option<i64>,

    pub window: u64,

    pub jumps: u64,
}

#[derive(Debug, Clone, Default)]
pub struct Host {

    pub host: [u8; 32],

    pub label: String,

    pub last_heard_ns: i64,

    pub last_store: Option<[u8; 32]>,

    pub pin: String,

    pub variant: String,

    pub version: String,

    pub seal: Option<[u8; 32]>,

    pub stores: usize,

    pub gaps: Vec<crate::held::HeldGap>,

    pub readable: String,

    pub beacon: Option<Beacon>,

    pub carried: Vec<CarriedKind>,
    gap_history: Vec<BTreeSet<String>>,
    store_set: BTreeSet<[u8; 32]>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CarriedKind {

    pub kind: String,

    pub what: String,

    pub stores: usize,

    pub raised: bool,
}

pub const NO_COLLECT: &str = "no `collect` store held: its sealed stores carry raw input, not findings";

pub const JUDGED_HERE: &str = "raw input, judged here";

#[derive(Debug, Clone, Default)]
pub struct Queue {

    pub alerts: Vec<Alert>,

    pub hosts: Vec<Host>,

    pub ledger_runs: u64,

    pub anomalies: Vec<String>,

    pub inventory_rows: u64,

    pub joins: crate::joins::Joins,
}

impl Queue {

    pub fn find(&self, id: &str) -> Result<&Alert, String> {
        let id = id.trim().to_ascii_lowercase();
        if id.len() < 4 {
            return Err("give at least four characters of the alert id".to_string());
        }
        let hits: Vec<&Alert> = self.alerts.iter().filter(|a| a.id.starts_with(&id)).collect();
        match hits.as_slice() {
            [a] => Ok(a),
            [] => Err(format!("no alert {}", crate::shown(&id))),
            _ => Err(format!("{} alerts start with {}; give more of the id", hits.len(), crate::shown(&id))),
        }
    }

    pub fn count_at_least(&self, at_least: Sev) -> usize {
        self.alerts.iter().filter(|a| a.max_sev >= at_least).count()
    }

    pub fn joins_of(&self, a: &Alert) -> Vec<String> {
        let mut v = Vec::new();
        for c in &self.joins.clusters {
            let mine = c.members.iter().any(|m| m.flagged.iter().any(|(id, _)| *id == a.id) || m.spread.as_deref() == Some(a.id.as_str()));
            if mine {
                v.push(format!(
                    "J2 cluster: the {} {} on {} host(s): {}",
                    c.entity.kind(),
                    c.entity.value(),
                    c.members.len(),
                    c.members.iter().map(|m| m.label.clone()).collect::<Vec<_>>().join(", ")
                ));
            }
        }
        for c in &self.joins.chains {
            if c.alert == a.id || c.raised.contains(&a.id) {
                v.push(format!("J3 chain: {} -> {} on {} ({}); {}", hex(&c.from).get(..12).unwrap_or(""), hex(&c.to).get(..12).unwrap_or(""), c.port, c.service, c.window));
            }
        }
        v
    }
}

pub fn triage_record(
    alert: &Alert,
    action: &Action,
    to: State,
    reason: &str,
    actor: &Actor,
    session: &str,
    at_ns: i64,
) -> String {
    let resolution = match action {
        Action::Resolve(r) => js(r.name()),
        _ => "null".to_string(),
    };
    format!(
        "{{\"kind\":\"triage\",\"alert\":{},\"host\":\"{}\",\"source\":{},\"subject\":{},\"action\":{},\
         \"resolution\":{resolution},\"from\":{},\"to\":{},\"reason\":{},\"actor\":{},\"uid\":{},\"session\":{},\
         \"at_ns\":{at_ns}}}",
        js(&alert.id),
        hex(&alert.host),
        js(&alert.source),
        js(&alert.subject),
        js(action.name()),
        js(&alert.state.name()),
        js(&to.name()),
        js(reason),
        js(&actor.label()),
        actor.uid,
        js(session),
    )
}

fn kept_host(kept: &str) -> Option<[u8; 32]> {
    let parts: Vec<&str> = kept.split('/').collect();
    match parts.as_slice() {
        ["hosts", h, g] if hex32(g).is_some() => hex32(h),
        _ => None,
    }
}

fn hex32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, o) in out.iter_mut().enumerate() {
        *o = u8::from_str_radix(s.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

fn run_owner(dir: &Path) -> Option<u32> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        std::fs::symlink_metadata(dir).ok().map(|m| m.uid())
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
        None
    }
}

struct Where {
    store: String,
    at_ns: i64,
    run: u64,
}

struct Fold<'a> {
    layout: &'a Layout,
    read_key: Option<&'a Secret32>,
    rejudge: &'a dyn Rejudge,

    accepted: BTreeMap<[u8; 32], Vec<std::path::PathBuf>>,
    alerts: Vec<Alert>,
    index: BTreeMap<String, usize>,
    hosts: BTreeMap<[u8; 32], Host>,
    anomalies: Vec<String>,
    inventory_rows: u64,

    pos: crate::joins::Pos,

    seen: Vec<crate::joins::Seen>,

    deferred: Vec<Deferred>,

    enrolled: BTreeMap<[u8; 32], (String, i64)>,
}

struct Deferred {
    pos: crate::joins::Pos,
    rec: Value,
    run: u64,
    owner: Option<u32>,
}

impl Fold<'_> {
    fn new<'a>(layout: &'a Layout, read_key: Option<&'a Secret32>, rejudge: &'a dyn Rejudge, accepted: BTreeMap<[u8; 32], Vec<std::path::PathBuf>>) -> Fold<'a> {
        Fold {
            layout,
            read_key,
            rejudge,
            accepted,
            alerts: Vec::new(),
            index: BTreeMap::new(),
            hosts: BTreeMap::new(),
            anomalies: Vec::new(),
            inventory_rows: 0,
            pos: (0, 0),
            seen: Vec::new(),
            deferred: Vec::new(),
            enrolled: BTreeMap::new(),
        }
    }

    fn raise(&mut self, host: [u8; 32], source: &str, subject: &str, origin: Origin, s: Sighting, ev: Vec<Evidence>) {
        let id = alert_id(&host, source, subject);
        match self.index.get(&id) {
            Some(&i) => {
                if let Some(a) = self.alerts.get_mut(i) {
                    a.sight(s);
                    a.evidence = ev;
                }
            }
            None => {
                let mut a = Alert::new(host, source, subject, origin, s);
                a.evidence = ev;
                self.index.insert(id, self.alerts.len());
                self.alerts.push(a);
            }
        }
    }

    fn collector_alert(&mut self, host: [u8; 32], subject: &str, sev: Sev, at: Where, why: &str) {
        let digest: [u8; 32] = Sha256::digest(why.as_bytes()).into();
        let s = Sighting { store: at.store, seqs: vec![], at_ns: at.at_ns, severity: sev, digest, ledger_run: at.run };
        let ev = vec![Evidence { severity: sev.token().to_string(), locus: String::new(), what: why.to_string(), why: String::new() }];
        self.raise(host, "collector", subject, Origin::Collector, s, ev);
    }

    fn ingest(&mut self, rec: &Value, run: u64) {
        let at_ns = rec.get("received_ns").and_then(Value::as_i64).unwrap_or(0);
        let host = hex32(rec.str_of("host")).unwrap_or([0; 32]);
        match rec.str_of("verdict") {
            "accepted" => {}
            "rejected" => {

                let reason = rec.str_of("reason");
                let subject = format!("parcel-rejected:{}", rec.str_of("sha256"));
                let store = rec.str_of("kept").to_string();
                self.collector_alert(host, &subject, Sev::Warn, Where { store, at_ns, run }, reason);
                return;
            }
            _ => return,
        }
        let kept = rec.str_of("kept");
        if kept_host(kept).is_none() {
            self.anomalies.push(format!("ledger run {run}: an accepted ingest names {}, which ingest does not write", crate::shown(kept)));
            return;
        }
        let dir = self.layout.base().join(kept);
        let genesis = rec.str_of("genesis").to_string();
        let held = match read_held(&dir, self.read_key) {
            Ok(h) => h,
            Err(why) => {
                let what = format!(
                    "the store at {kept} was accepted in ledger run {run} and does not verify now: {why}. The \
                     collector's own copy changed"
                );
                self.collector_alert(host, &format!("held-store-changed:{genesis}"), Sev::Critical, Where { store: genesis.clone(), at_ns, run }, &what);
                return;
            }
        };
        let pin = rec.str_of("pin").to_string();
        let records = rec.get("records").and_then(Value::as_u64).unwrap_or(0);
        self.store(held, &genesis, at_ns, run, pin, records);
    }

    fn store(&mut self, held: HeldStore, genesis: &str, at_ns: i64, run: u64, pin: String, records: u64) {
        let facts = self.rejudge.facts(&held);
        let seen = crate::joins::Seen {
            pos: self.pos,
            run,
            host: held.host,
            genesis: held.genesis,
            at_ns,
            taken_ns: facts.taken_ns.unwrap_or(held.created_wall_ns),
            records,
            facts,
            found: Vec::new(),
            ran: crate::joins::Ran::Nothing,
        };
        let (found, ran) = self.store_alerts(held, genesis, at_ns, run, pin);
        self.seen.push(crate::joins::Seen { found, ran, ..seen });
    }

    fn store_alerts(&mut self, held: HeldStore, genesis: &str, at_ns: i64, run: u64, pin: String) -> (Vec<crate::joins::Found>, crate::joins::Ran) {
        use crate::joins::Ran;
        let host = held.host;
        let is_collect = held.shape == crate::check::StoreShape::Collect;
        let gap_set: BTreeSet<String> = held.gaps.iter().map(|g| g.source.clone()).collect();
        let mut lost: Vec<String> = Vec::new();
        {
            let h = self.hosts.entry(host).or_insert_with(|| Host { host, ..Host::default() });
            h.store_set.insert(held.genesis);
            h.stores = h.store_set.len();
            if at_ns >= h.last_heard_ns {
                h.last_heard_ns = at_ns;
                h.last_store = Some(held.genesis);
                h.pin = pin;
                h.seal = Some(held.seal);
            }
            if is_collect {

                for s in &gap_set {
                    if h.gap_history.iter().any(|earlier| !earlier.contains(s) && !earlier.contains("*")) {
                        lost.push(s.clone());
                    }
                }
                h.gap_history.push(gap_set.clone());
                h.gaps = held.gaps.clone();
                h.variant = held.variant.clone();
                h.version = held.version.clone();
                h.readable = match &held.readable {
                    Readable::Yes => "yes".to_string(),
                    Readable::NotACollection => "not a collection".to_string(),
                    Readable::No(why) => format!("NO — {why}"),
                };
            } else if h.readable.is_empty() {

                h.readable = NO_COLLECT.to_string();
            }
        }
        for s in lost {
            let what = format!("the {s} sweep ran in an earlier store from this host and did not run fully in this one");
            self.collector_alert(host, &format!("coverage-lost:{s}"), Sev::Warn, Where { store: genesis.to_string(), at_ns, run }, &what);
        }
        if !is_collect {
            return self.raw_input(&held, genesis, at_ns, run);
        }
        if let Readable::No(why) = &held.readable {
            let what = format!("the findings of {genesis} cannot be read: {why}");
            self.collector_alert(host, "findings-unreadable", Sev::Warn, Where { store: genesis.to_string(), at_ns, run }, &what);
            for a in self.alerts.iter_mut().filter(|a| a.host == host) {
                a.absent_from_latest = false;
            }
            return (Vec::new(), Ran::Nothing);
        }
        if !held.unparsed.is_empty() {
            let what = format!(
                "{} evidence record(s) of {genesis} decrypted and are not findings the collector can parse (seq {})",
                held.unparsed.len(),
                held.unparsed.iter().take(10).map(u64::to_string).collect::<Vec<_>>().join(", ")
            );
            self.collector_alert(host, "records-unparsed", Sev::Warn, Where { store: genesis.to_string(), at_ns, run }, &what);
        }
        let found = self.sightings(host, &held.findings, Where { store: genesis.to_string(), at_ns, run }, None);
        let present: BTreeSet<&str> = found.iter().map(|f| f.id.as_str()).collect();
        let full_run = !gap_set.contains("*");

        for a in self.alerts.iter_mut().filter(|a| a.host == host && a.origin == Origin::Finding && a.judged_here.is_none()) {
            a.absent_from_latest = !present.contains(a.id.as_str()) && full_run && !gap_set.contains(&a.source);
        }
        (found, Ran::AllBut(gap_set))
    }

    fn sightings(&mut self, host: [u8; 32], findings: &[HeldFinding], at: Where, judged: Option<&str>) -> Vec<crate::joins::Found> {

        let mut by: BTreeMap<(String, String), Vec<&HeldFinding>> = BTreeMap::new();
        for f in findings {
            if f.severity == Sev::Info {
                self.inventory_rows += 1;
                continue;
            }
            by.entry((f.source.clone(), f.subject.clone())).or_default().push(f);
        }
        let mut found = Vec::new();
        for ((source, subject), fs) in &by {
            found.push(crate::joins::Found::of(&alert_id(&host, source, subject), source, subject, fs));
            let mut digests: Vec<[u8; 32]> = fs.iter().map(|f| f.digest).collect();
            digests.sort_unstable();
            let mut h = Sha256::new();
            for d in &digests {
                h.update(d);
            }
            let s = Sighting {
                store: at.store.clone(),

                seqs: if judged.is_some() { Vec::new() } else { fs.iter().map(|f| f.seq).collect() },
                at_ns: at.at_ns,
                severity: fs.iter().map(|f| f.severity).max().unwrap_or(Sev::Warn),
                digest: h.finalize().into(),
                ledger_run: at.run,
            };
            let ev = fs
                .iter()
                .map(|f| Evidence { severity: f.severity_raw.clone(), locus: f.locus.clone(), what: f.what.clone(), why: f.why.clone() })
                .collect();
            self.raise(host, source, subject, Origin::Finding, s, ev);
            if let Some(i) = self.index.get(&alert_id(&host, source, subject)).copied() {
                if let Some(a) = self.alerts.get_mut(i) {
                    a.judged_here = judged.map(str::to_string);
                }
            }
        }
        found
    }

    fn raw_input(&mut self, held: &HeldStore, genesis: &str, at_ns: i64, run: u64) -> (Vec<crate::joins::Found>, crate::joins::Ran) {
        use crate::joins::Ran;
        let host = held.host;
        let dirs = self.accepted.get(&host).cloned().unwrap_or_default();
        let peers = move |seal: &[u8; 32]| -> Option<HeldStore> {
            dirs.iter().find_map(|d| {
                let h = hemostat_evfmt::read_store_header(d).ok()?;
                if hemostat_evcrypto::seal::decode_seal_pubkey(&h.variable_tail)? != *seal {
                    return None;
                }
                read_held(d, None).ok().filter(|p| p.host == host)
            })
        };
        let at = || Where { store: genesis.to_string(), at_ns, run };
        match self.rejudge.rejudge(held, &peers) {
            Outcome::Carried { kind, what } => {
                self.carried(host, &kind, &what, false);
                (Vec::new(), Ran::Nothing)
            }
            Outcome::Unjudged { sweep, why } => {
                let what = format!("the {sweep} store {genesis} holds raw input the collector did not judge: {why}");
                self.collector_alert(host, &format!("not-rejudged:{}", crate::shown(&sweep)), Sev::Warn, at(), &what);
                self.carried(host, &sweep, &why, true);
                (Vec::new(), Ran::Nothing)
            }
            Outcome::Judged(r) => {
                let found = self.sightings(host, &r.findings, at(), Some(&r.basis));
                let present: BTreeSet<&str> = found.iter().map(|f| f.id.as_str()).collect();
                let sweep = r.sweep.clone();
                if let Some(h) = self.hosts.get_mut(&host) {
                    h.gaps.retain(|g| g.source != sweep);
                    h.gaps.extend(r.gaps.iter().map(|g| HeldGap { source: sweep.clone(), reason: g.clone(), partial: true }));
                    if h.readable.is_empty() || h.readable == "not a collection" || h.readable == NO_COLLECT {
                        h.readable = JUDGED_HERE.to_string();
                    }
                }

                let whole = r.gaps.is_empty();
                for a in self.alerts.iter_mut().filter(|a| a.host == host && a.origin == Origin::Finding && a.source == sweep) {
                    a.absent_from_latest = whole && !present.contains(a.id.as_str());
                }
                (found, Ran::One(sweep, r.gaps.clone()))
            }
        }
    }

    fn carried(&mut self, host: [u8; 32], kind: &str, what: &str, raised: bool) {
        let h = self.hosts.entry(host).or_insert_with(|| Host { host, ..Host::default() });
        let kind = crate::shown(kind);
        match h.carried.iter_mut().find(|c| c.kind == kind) {
            Some(c) => {
                c.stores += 1;
                c.what = what.to_string();
                c.raised |= raised;
            }
            None => h.carried.push(CarriedKind { kind, what: what.to_string(), stores: 1, raised }),
        }
    }

    fn heartbeat(&mut self, rec: &Value) {
        let Some(host) = hex32(rec.str_of("host")) else {
            self.anomalies.push("a heartbeat record that names no host".to_string());
            return;
        };
        let n = |k: &str| rec.get(k).and_then(Value::as_u64).unwrap_or(0);
        let i = |k: &str| rec.get(k).and_then(Value::as_i64);
        let b = Beacon {
            agent: rec.str_of("agent").to_string(),
            state: rec.str_of("state").to_string(),
            as_of_ns: i("at_ns").unwrap_or(0),
            last_ns: i("last_ns").unwrap_or(0),
            run: rec.str_of("run").to_string(),
            seq: n("seq"),
            received: n("received"),
            missing: n("missing"),
            restarts: n("restarts"),
            stale: n("stale"),
            offset_ns: i("offset_ns"),
            spread_ns: i("spread_ns"),
            window: n("window"),
            jumps: n("jumps"),
        };

        let h = self.hosts.entry(host).or_insert_with(|| Host { host, ..Host::default() });
        h.beacon = Some(b);
    }

    fn recorded_alert(&mut self, rec: &Value, run: u64) {
        let kind = rec.str_of("alert");
        if kind.is_empty() {
            self.anomalies.push(format!("ledger run {run}: an alert record that names no alert"));
            return;
        }
        let host = hex32(rec.str_of("host")).unwrap_or([0; 32]);
        let genesis = rec.str_of("genesis");
        let about = [genesis, rec.str_of("source"), rec.str_of("from"), rec.str_of("parcel_sha256"), rec.str_of("conn")]
            .into_iter()
            .find(|v| !v.is_empty())
            .unwrap_or("?");
        let store = if !genesis.is_empty() {
            genesis.to_string()
        } else if !rec.str_of("parcel_sha256").is_empty() {
            format!("rejected/{}", rec.str_of("parcel_sha256"))
        } else {
            format!("spool/{}", rec.str_of("conn"))
        };
        let at_ns = rec.get("at_ns").and_then(Value::as_i64).unwrap_or(0);
        let sev = crate::held::parse_sev(rec.str_of("severity")).max(Sev::Warn);
        let why = rec.str_of("why").to_string();
        self.collector_alert(host, &format!("{kind}:{}", crate::shown(about)), sev, Where { store, at_ns, run }, &why);
    }

    fn join(&mut self) -> crate::joins::Joins {
        use crate::joins::{HostInfo, Measured};
        let mut info: BTreeMap<[u8; 32], HostInfo> = BTreeMap::new();
        for (h, (label, at)) in &self.enrolled {
            info.insert(*h, HostInfo { label: label.clone(), enrolled_ns: Some(*at), ..HostInfo::default() });
        }
        for s in &self.seen {
            let i = info.entry(s.host).or_default();
            if i.label.is_empty() && !s.facts.hostname.is_empty() {
                i.label = s.facts.hostname.clone();
            }
        }
        for (h, host) in &mut self.hosts {
            let i = info.entry(*h).or_default();
            if let Some(b) = &host.beacon {
                i.beacon = Some(b.state.clone());
                if let (Some(o), Some(s)) = (b.offset_ns, b.spread_ns) {
                    i.clock = Some(Measured { offset_ns: o, spread_ns: s });
                }
            }
            i.gaps = host.gaps.iter().map(|g| g.source.clone()).collect();
            i.gaps.dedup();
            host.label = i.label.clone();
        }
        let joined = crate::joins::run(&self.seen, &info, self.rejudge);
        enum Ev {
            Raise(crate::joins::Raise),
            Triage(Deferred),
        }
        let mut events: Vec<(crate::joins::Pos, Ev)> = joined.raises.into_iter().map(|r| (r.pos, Ev::Raise(r))).collect();
        events.extend(std::mem::take(&mut self.deferred).into_iter().map(|d| (d.pos, Ev::Triage(d))));

        events.sort_by_key(|(p, e)| (*p, matches!(e, Ev::Triage(_))));
        for (_, e) in events {
            match e {
                Ev::Raise(r) => {
                    let s = Sighting { store: r.store.clone(), seqs: Vec::new(), at_ns: r.at_ns, severity: r.sev, digest: r.digest(), ledger_run: r.run };
                    let (host, source, subject, basis) = (r.host, r.source, r.subject.clone(), r.basis.clone());
                    self.raise(host, source, &subject, Origin::Join, s, r.evidence);
                    if let Some(a) = self.index.get(&alert_id(&host, source, &subject)).copied().and_then(|i| self.alerts.get_mut(i)) {
                        a.basis = basis;
                    }
                }
                Ev::Triage(d) => self.triage(&d.rec, d.run, d.owner),
            }
        }
        joined.joins
    }

    fn triage(&mut self, rec: &Value, run: u64, owner: Option<u32>) {
        let id = rec.str_of("alert");
        let Some(&i) = self.index.get(id) else {
            self.anomalies.push(format!("ledger run {run}: a triage record names alert {}, which no ingest or join raised", crate::shown(id)));
            return;
        };
        let action = match (rec.str_of("action"), Resolution::parse(rec.str_of("resolution"))) {
            ("ack", _) => Action::Ack,
            ("investigate", _) => Action::Investigate,
            ("note", _) => Action::Note,
            ("resolve", Some(r)) => Action::Resolve(r),
            (other, _) => {
                self.anomalies.push(format!("ledger run {run}: a triage record with action {}", crate::shown(other)));
                return;
            }
        };
        let uid = rec.get("uid").and_then(Value::as_u64).and_then(|u| u32::try_from(u).ok());
        let actor_label = rec.str_of("actor").to_string();
        let owner_matches = uid.is_some() && owner.is_some() && uid == owner;
        if !owner_matches {
            self.anomalies.push(format!(
                "ledger run {run}: a triage record names {} (uid {}), and the run directory is owned by uid {}",
                crate::shown(&actor_label),
                uid.map_or("?".to_string(), |u| u.to_string()),
                owner.map_or("?".to_string(), |u| u.to_string())
            ));
        }
        let Some(a) = self.alerts.get_mut(i) else { return };
        let reason = rec.str_of("reason");
        let recorded_from = rec.str_of("from");
        let to = State::parse(rec.str_of("to"));

        let name = actor_label.trim_start_matches("uid=").split('(').nth(1).unwrap_or("").trim_end_matches(')');
        let actor = Actor { uid: uid.unwrap_or(u32::MAX), name: name.to_string() };
        let checked = a.check(&action, &actor, reason);
        let state_before = a.state.name();
        match (checked, to) {
            (Ok(want), Some(to)) if want == to && recorded_from == state_before => {
                let ev = Event {
                    at_ns: rec.get("at_ns").and_then(Value::as_i64).unwrap_or(0),
                    actor: actor_label,
                    session: rec.str_of("session").to_string(),
                    action: action.name().to_string(),
                    from: state_before,
                    to: to.name(),
                    reason: reason.to_string(),
                    ledger_run: run,
                    owner_matches,
                };
                a.apply(&action, to, ev);
            }
            (checked, _) => {
                let why = checked.err().unwrap_or_else(|| {
                    format!("it records {} -> {}, and the alert was {state_before}", crate::shown(recorded_from), crate::shown(rec.str_of("to")))
                });
                self.anomalies.push(format!("ledger run {run}: a {} on alert {} does not replay: {why}", action.name(), a.id));
            }
        }
    }
}

pub fn fold(layout: &Layout, read_key: Option<&Secret32>) -> Result<Queue, String> {
    fold_with(layout, read_key, &NoRejudge)
}

pub fn fold_with(layout: &Layout, read_key: Option<&Secret32>, rejudge: &dyn Rejudge) -> Result<Queue, String> {
    let ledger_dir = layout.ledger();
    if std::fs::symlink_metadata(ledger_dir.join(crate::ledger::KEY_FILE)).is_err() {
        return Ok(Queue::default());
    }
    let pk = crate::ledger::ledger_public_key(&ledger_dir)?;
    let runs = crate::ledger::audit(&ledger_dir, &pk)?;

    let mut accepted: BTreeMap<[u8; 32], Vec<std::path::PathBuf>> = BTreeMap::new();
    for r in &runs {
        for raw in r.records.iter().skip(2) {
            let Some(v) = std::str::from_utf8(raw).ok().and_then(|t| json::parse(t).ok()) else { continue };
            if v.str_of("kind") == "ingest" && v.str_of("verdict") == "accepted" {
                if let Some(host) = kept_host(v.str_of("kept")) {
                    accepted.entry(host).or_default().push(layout.base().join(v.str_of("kept")));
                }
            }
        }
    }
    let mut f = Fold::new(layout, read_key, rejudge, accepted);
    for r in &runs {
        let run = r.summary.run;
        if !r.summary.sealed {
            f.anomalies.push(format!(
                "ledger run {run} is not sealed (a crash, or it is being written): its records after the last seal \
                 are read, and no key vouches for them"
            ));
        }
        let owner = run_owner(&ledger_dir.join(format!("{run:010}")));
        for (idx, raw) in r.records.iter().enumerate().skip(2) {
            f.pos = (run, idx);
            let Ok(v) = std::str::from_utf8(raw).map_err(|_| ()).and_then(|t| json::parse(t).map_err(|_| ())) else {
                f.anomalies.push(format!("ledger run {run}: a record that is not JSON"));
                continue;
            };
            match v.str_of("kind") {
                "ingest" => f.ingest(&v, run),
                "alert" => {
                    f.recorded_alert(&v, run);
                    if !v.str_of("link").is_empty() {
                        f.heartbeat(&v);
                    }
                }
                "heartbeat" => f.heartbeat(&v),
                "enroll" => {
                    if let Some(h) = hex32(v.str_of("host")) {
                        f.enrolled.insert(h, (v.str_of("label").to_string(), v.get("enrolled_ns").and_then(Value::as_i64).unwrap_or(0)));
                    }
                }
                "triage" if !f.index.contains_key(v.str_of("alert")) => f.deferred.push(Deferred { pos: f.pos, rec: v, run, owner }),
                "triage" => f.triage(&v, run, owner),
                _ => {}
            }
        }
    }
    let joins = f.join();
    let mut alerts = f.alerts;
    alerts.sort_by(|a, b| b.max_sev.cmp(&a.max_sev).then(a.first_ns.cmp(&b.first_ns)).then(a.id.cmp(&b.id)));
    Ok(Queue {
        alerts,
        hosts: f.hosts.into_values().collect(),
        ledger_runs: runs.len() as u64,
        anomalies: f.anomalies,
        inventory_rows: f.inventory_rows,
        joins,
    })
}

#[derive(Debug, Clone)]
pub struct Transition<'a> {

    pub id: &'a str,

    pub action: Action,

    pub reason: &'a str,

    pub actor: &'a Actor,

    pub session: &'a str,

    pub via: &'a str,
}

#[derive(Debug, Clone)]
pub struct Recorded {

    pub id: String,

    pub from: State,

    pub to: State,

    pub run: u64,
}

pub fn transition(
    layout: &Layout,
    read_key: Option<&Secret32>,
    rejudge: &dyn Rejudge,
    ids: &crate::ledger::LedgerIds,
    entropy: &mut dyn FnMut() -> std::io::Result<[u8; 32]>,
    t: &Transition<'_>,
) -> Result<Recorded, String> {
    if t.reason.len() > 2000 {
        return Err("the reason is over 2000 bytes; the ledger keeps a judgement, not a report".to_string());
    }
    let _lock = layout.lock()?;
    let q = fold_with(layout, read_key, rejudge)?;
    let alert = q.find(t.id)?;
    let to = alert.check(&t.action, t.actor, t.reason)?;
    let from = alert.state;
    let mut ledger = crate::ledger::Ledger::open(&layout.ledger(), ids, entropy)?;
    let run = ledger.run();
    let verb = format!("queue {}", t.action.name());
    let written = ledger
        .append(&crate::ledger::run_record(&verb, &t.actor.label(), t.via))
        .and_then(|()| ledger.append(&triage_record(alert, &t.action, to, t.reason, t.actor, t.session, crate::now_ns())));
    let closed = ledger.close();
    written?;
    closed?;
    Ok(Recorded { id: alert.id.clone(), from, to, run })
}

pub fn suggestion(a: &Alert) -> (String, String) {
    let host = hex(&a.host);
    let ticket = |class: &str| {
        format!("hemostat ticket --op action --class {class} --engagement <ENG> --host {host} --ttl 15m --out ticket.cbor  (sign it off-host)")
    };
    match a.source.as_str() {
        "accounts" => (
            "hemostat accounts   (on the host; account changes are a manual call in the host's TUI)".to_string(),
            ticket("AccountDisable"),
        ),
        "persistence" | "systemd" => ("hemostat persistence".to_string(), ticket("PersistenceNeutralize")),
        "overview" | "injected" => ("hemostat overview".to_string(), ticket("Kill")),
        "sshd" => ("hemostat sshd".to_string(), ticket("Harden")),
        "sysctl" => ("hemostat sysctl".to_string(), ticket("Harden")),

        "trust" => (
            "hemostat trust   (on the host; on Linux `hemostat remediate --anchors` offers a removal for a person to arm)".to_string(),
            ticket("PersistenceNeutralize"),
        ),
        "watchdog" => ("hemostat watchdog --watch 10".to_string(), ticket("Kill")),
        "suid" | "inventory" => ("hemostat suid".to_string(), ticket("Quarantine")),
        "rootkit" | "kwalk" | "sysmap" | "kptr-hooks" | "kernel-posture" => ("hemostat rootkit".to_string(), ticket("Acquire")),

        "vendor" => (
            "hemostat vendor --manifest <the signed pfSense manifest>   (on the firewall, over ssh from the jump host)".to_string(),
            "none the agent carries: restore the file from the vendor's image by hand".to_string(),
        ),
        "drift" => (
            "hemostat drift   (on the firewall, with $HEMOSTAT_SNAPSHOT_PUBKEY pinned)".to_string(),
            "none the agent carries: a config change is a human's, in the pfSense GUI".to_string(),
        ),
        "fw-flows" => ("hemostat fw flows   (on the firewall)".to_string(), ticket("PerimeterBlock")),

        "fw-rules" => (
            "hemostat fw rules   (on the firewall)".to_string(),
            "none the agent carries: a rule change is a human's, in the pfSense GUI".to_string(),
        ),

        "flow" => (
            "hemostat overview --export on the host, then hemostat fw flows on the firewall after it, and ship both: \
             the join is read again from the pair"
                .to_string(),
            ticket("PerimeterBlock"),
        ),
        "spread" => (
            "hemostat persistence and hemostat overview   (on this host: what runs the thing the other host flagged)".to_string(),
            ticket("Acquire"),
        ),
        "lateral" => (
            "hemostat accounts and hemostat persistence on the host the session reached; hemostat overview on the one it \
             came from"
                .to_string(),
            ticket("AccountDisable"),
        ),
        "collector" => (
            "nothing on the host: this is the collector's own alert; see its evidence and the ledger".to_string(),
            "none".to_string(),
        ),
        other => (format!("hemostat {other}"), ticket("<class>")),
    }
}
