#![cfg_attr(not(feature = "mod-collector"), allow(dead_code))]

use std::cell::{OnceCell, RefCell};
use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::rc::Rc;

use hemostat_evcrypto::manifest::meta::VerifiedMeta;
use hemostat_evcrypto::manifest::Verified;
use hemostat_fleet::held::{HeldFinding, HeldStore};
use hemostat_fleet::queue::Sev;
use hemostat_fleet::joins::{Conn, Entity, Facts, FlowAsk, FlowGrade, FlowReport, FlowRow, FlowSide, Presence, EMPTY_SHA256};
use hemostat_fleet::rejudge::{finding, Outcome, Peers, Rejudge, Rejudged};
use hemostat_evcrypto::manifest::Manifest;
use hemostat_sensor_freebsd::evidence::Evidence;
use hemostat_sensor_freebsd::{accounts, drift, grade, persist, pfrules, posture, telemetry, verdict};
use hemostat_sensor_linux::flowexport::HostFlows;
use hs_core::severity::Severity;

use crate::render::hex32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Kind {

    Vendor,

    Snapshot,

    Drift,

    Telemetry,

    Accounts,

    Persistence,

    FwRules,

    Posture,

    Trust,

    Carried(String, String),

    Unknown(Option<String>),
}

const SNAPSHOT_WHAT: &str = "the firewall's arrival snapshot of config.xml: the baseline a drift store is judged \
                             against, not judged on its own";
const WINDOWS_WHAT: &str = "a Windows host's arrival snapshot: the baseline that host's own `drift` compares the \
                            live state with; it holds no finding, and the live state is not in it";
const LINUX_WHAT: &str = "a Linux host's arrival snapshot (`snapshot`): the baseline that host's own `drift` \
                          compares the live state with; it holds no finding, and the live state is not in it";
const HOSTFLOWS_WHAT: &str = "a Linux host's socket export (`overview --export`): raw input to the cross-host flow \
                              join (S11, RFC-003 F8), which judges it with a firewall store, not alone";

const WINDOWS_KIND: &[u8] = b"windows-host";

const HOSTFLOWS_SCOPE: &[u8] = b"hostflows/";

fn is_linux_snapshot(records: &[Vec<u8>]) -> bool {
    records.first().is_some_and(|r| r.len() == 17 && r.first() == Some(&b's'))
        && records.get(1).and_then(|r| r.strip_prefix(b"v")).is_some_and(|v| !v.is_empty() && v.iter().all(u8::is_ascii_digit))
}

fn named(raw: &[u8]) -> String {
    hemostat_fleet::shown(&String::from_utf8_lossy(raw.get(..64).unwrap_or(raw)))
}

pub(crate) fn kind_of(records: &[Vec<u8>]) -> Kind {
    if let Some(scope) = records.first().and_then(|r| r.strip_prefix(b"V")) {
        return if scope.starts_with(b"telemetry/") {
            Kind::Telemetry
        } else if scope.starts_with(b"posture/") {
            Kind::Posture
        } else if scope.starts_with(HOSTFLOWS_SCOPE) {
            Kind::Carried(named(scope), HOSTFLOWS_WHAT.to_string())
        } else {
            Kind::Unknown(Some(named(scope)))
        };
    }
    let Some(k) = records.iter().take(4).find_map(|r| r.strip_prefix(b"k")) else {

        if is_linux_snapshot(records) {
            return Kind::Carried("linux-host".to_string(), LINUX_WHAT.to_string());
        }
        return Kind::Unknown(None);
    };
    match k {
        _ if k == grade::STORE_KIND.as_bytes() => Kind::Vendor,
        _ if k == drift::KIND.as_bytes() => Kind::Snapshot,
        _ if k == crate::freebsd_drift::DRIFT_KIND.as_bytes() => Kind::Drift,
        _ if k == crate::freebsd_sweeps::ACCOUNTS.as_bytes() => Kind::Accounts,
        _ if k == crate::freebsd_sweeps::PERSISTENCE.as_bytes() => Kind::Persistence,
        _ if k == crate::freebsd_sweeps::TRUST.as_bytes() => Kind::Trust,
        _ if k == pfrules::KIND.as_bytes() => Kind::FwRules,
        _ if k == WINDOWS_KIND => Kind::Carried(named(k), WINDOWS_WHAT.to_string()),
        _ => {
            let rec = [b"k".as_slice(), k].concat();
            match crate::evidence::sealed_kind(&[rec.as_slice()]) {

                Some(what) => Kind::Carried(named(k), what.split_whitespace().collect::<Vec<_>>().join(" ")),
                None => Kind::Unknown(Some(named(k))),
            }
        }
    }
}

fn sev(s: Severity) -> Sev {
    match s {
        Severity::Critical => Sev::Critical,
        Severity::Warn => Sev::Warn,
        Severity::Note => Sev::Note,
    }
}

fn short(b: &[u8; 32]) -> String {
    hex32(b).chars().take(16).collect()
}

pub(crate) fn judge_vendor(records: &[Vec<u8>], m: &Verified, meta: &VerifiedMeta, label: &str) -> Outcome {
    match grade::judge_records(records.iter().map(Vec::as_slice), m, meta) {
        Ok(r) => Outcome::Judged(Rejudged {
            sweep: "vendor".to_string(),
            findings: r
                .findings
                .iter()
                .enumerate()
                .map(|(i, f)| finding(i, "vendor", sev(f.severity), &f.path, &f.what, &f.detail))
                .collect(),
            basis: format!(
                "{label} and its sidecar: {} entries walked, {} vendor files absent, {} unlisted elsewhere",
                r.walked, r.absent, r.unlisted
            ),
            gaps: r.gaps,
        }),
        Err(why) => Outcome::Unjudged { sweep: "vendor".to_string(), why },
    }
}

pub(crate) fn judge_drift(records: &[Vec<u8>], peers: Peers<'_>) -> Outcome {
    let unjudged = |why: String| Outcome::Unjudged { sweep: "drift".to_string(), why };
    let Some(a) = records.iter().find_map(|r| r.strip_prefix(b"a")).and_then(|a| <[u8; 32]>::try_from(a).ok()) else {
        return unjudged("the drift store names no arrival snapshot".to_string());
    };
    let Some(base) = peers(&a) else {
        return unjudged(format!(
            "the arrival snapshot it is compared with (seal key {}) is not held here from this host. Carry the \
             box's snapshot store too",
            hex32(&a)
        ));
    };
    let arrival = match crate::freebsd_drift::decode_snapshot(&base.records) {
        Ok(x) => x,
        Err(e) => return unjudged(format!("the store with seal key {} is not its arrival snapshot: {e}", short(&a))),
    };
    let now = match crate::freebsd_drift::decode_drift(records, &a) {
        Ok(n) => n,
        Err(e) => return unjudged(e),
    };
    let j = drift::judge_raw(&arrival.raw, &now, &arrival.salt);
    let mut gaps = arrival.gaps;
    gaps.extend(j.gaps);
    Outcome::Judged(Rejudged {
        sweep: "drift".to_string(),
        findings: j
            .findings
            .iter()
            .enumerate()
            .map(|(i, f)| finding(i, "drift", sev(f.severity), &f.subject, &f.what, &f.why))
            .collect(),
        gaps,
        basis: format!(
            "the arrival snapshot {} (seal key {}): config.xml {} then, {} now",
            short(&base.genesis),
            short(&a),
            short(&drift::raw_digest(&arrival.raw)),
            short(&drift::raw_digest(&now))
        ),
    })
}

pub(crate) fn judge_evidence(ev: &telemetry::Evidence, label: &str) -> Outcome {
    use telemetry::filterlog::proto;
    let mut findings: Vec<HeldFinding> = Vec::new();
    let mut push = |s: Sev, subject: String, what: &str, why: &str| {
        let n = findings.len();
        findings.push(finding(n, "fw-flows", s, &subject, what, why));
    };
    let own = verdict::box_owned(ev);
    for f in own.flows.iter().filter(|f| f.standing == verdict::Standing::Contradiction) {
        let subject = format!("box-owned {} {} {} {}", proto::name(f.proto), f.local, if f.inbound { "<-" } else { "->" }, f.peer);
        push(Sev::Critical, subject, &format!("CONTRADICTION: {}", f.state), &f.basis);
    }
    for s in &ev.suspect {
        push(
            Sev::Warn,
            "telemetry-suspect".to_string(),
            s,
            "what a tool that failed verification reported cannot be shown to be the box's; the vendor sweep judges the tool",
        );
    }
    for c in verdict::identity_conflicts(ev) {
        let addr = c.split(": the ").next().unwrap_or(&c).to_string();
        push(Sev::Note, format!("lease-neighbour {addr}"), &c, "a lease and a neighbour entry are what a host claimed");
    }
    let mut gaps = ev.gaps.clone();
    gaps.extend(own.limits.iter().filter(|l| l.contains("not read")).cloned());
    Outcome::Judged(Rejudged {
        sweep: "fw-flows".to_string(),
        findings,
        gaps,
        basis: format!(
            "{label}: each logging tool's digest, then pf's {} state(s) against the box's own sockets ({} with an end on it)",
            ev.states.as_ref().map_or(0, Vec::len),
            own.flows.len()
        ),
    })
}

fn evidence_findings(sweep: &str, j: &hemostat_sensor_freebsd::evidence::Judged) -> Vec<HeldFinding> {
    j.findings.iter().enumerate().map(|(i, f)| finding(i, sweep, sev(f.severity), &f.subject, &f.what, &f.why)).collect()
}

fn evidence_of(records: &[Vec<u8>], sweep: &str) -> Result<Evidence, Outcome> {
    Evidence::from_records(records.iter().map(Vec::as_slice)).map_err(|e| Outcome::Unjudged {
        sweep: sweep.to_string(),
        why: format!("the store does not decode as the box's {sweep} evidence ({e}), so nothing in it was judged"),
    })
}

pub(crate) fn judge_accounts(records: &[Vec<u8>], opts: &accounts::Opts) -> Outcome {
    let ev = match evidence_of(records, "accounts") {
        Ok(e) => e,
        Err(o) => return o,
    };
    let j = accounts::judge(&ev, opts);
    let keys = if opts.operator_keys.is_empty() {
        "no operator key enrolled on this collector (`queue --operator-key`, $HEMOSTAT_OPERATOR_KEY): the store does \
         not carry the keys the box was told, so the responder's own key, where a key file holds it and config.xml \
         does not, is Critical here and was a Note on the box"
            .to_string()
    } else {
        format!(
            "{} operator key(s) enrolled on this collector, each a Note where a key file holds it; the store does not \
             carry the keys the box was told",
            opts.operator_keys.len()
        )
    };
    Outcome::Judged(Rejudged {
        sweep: "accounts".to_string(),
        findings: evidence_findings("accounts", &j),
        gaps: j.gaps,
        basis: format!(
            "the sealed evidence: {} path(s) read, against the config.xml in it; {keys}. A password-free grant is \
             Critical whatever is enrolled",
            ev.obs.len()
        ),
    })
}

pub(crate) fn judge_persistence(records: &[Vec<u8>], man: Result<(&Manifest, &str), &str>) -> Outcome {
    let ev = match evidence_of(records, "persistence") {
        Ok(e) => e,
        Err(o) => return o,
    };
    let mut j = persist::judge(&ev, man.ok().map(|(m, _)| m));
    let against = match man {
        Ok((_, label)) => format!("{label}; the store does not name the manifest the box held"),
        Err(why) => {
            j.gaps.push(format!("the collector judged it with no manifest: {why}"));
            "no signed manifest on this collector: the config-backed checks only".to_string()
        }
    };
    Outcome::Judged(Rejudged {
        sweep: "persistence".to_string(),
        findings: evidence_findings("persistence", &j),
        gaps: j.gaps,
        basis: format!(
            "the sealed evidence: {} path(s) read and {} tool run(s), against the config.xml in it and {against}",
            ev.obs.len(),
            ev.tools.len()
        ),
    })
}

pub(crate) fn judge_trust(records: &[Vec<u8>], man: Result<(&Manifest, &str), &str>) -> Outcome {
    let ev = match evidence_of(records, "trust") {
        Ok(e) => e,
        Err(o) => return o,
    };
    let j = hemostat_sensor_freebsd::trust::judge(&ev, man.ok().map(|(m, _)| m));
    let against = match man {
        Ok((_, label)) => label.to_string(),
        Err(why) => format!("no signed manifest on this collector ({why}), so the base system's anchors were taken as shipped"),
    };
    Outcome::Judged(Rejudged {
        sweep: "trust".to_string(),
        findings: evidence_findings("trust", &j),
        gaps: j.gaps,
        basis: format!("the sealed evidence: {} path(s) read, against the config.xml in it and {against}", ev.obs.len()),
    })
}

pub(crate) fn judge_fw_rules(records: &[Vec<u8>]) -> Outcome {
    let c = match pfrules::from_records(records.iter().map(Vec::as_slice)) {
        Ok(c) => c,
        Err(why) => return Outcome::Unjudged { sweep: "fw-rules".to_string(), why },
    };
    let j = pfrules::judge(&c);
    let s = &j.summary;
    Outcome::Judged(Rejudged {
        sweep: "fw-rules".to_string(),
        findings: j
            .findings
            .iter()
            .enumerate()
            .map(|(i, f)| finding(i, "fw-rules", sev(f.severity), &f.subject, &f.what, &f.why))
            .collect(),
        basis: format!(
            "the sealed pfctl listings and files ({} source(s)): {} deciding filter rule(s), {} traced to config.xml, \
             {} anchor(s), {} table(s). The box also re-checks its confirmed blocks against the containment \
             journals on its own disk, which are not in the store: a lost block is the box's to report",
            c.sources.len(),
            s.filter_rules,
            s.from_config,
            s.anchors.len(),
            s.tables
        ),
        gaps: j.gaps,
    })
}

pub(crate) fn judge_posture(records: &[Vec<u8>], m: &Manifest, label: &str) -> Outcome {
    let raw = match posture::Raw::from_records(records.iter().map(Vec::as_slice)) {
        Ok(r) => r,
        Err(why) => return Outcome::Unjudged { sweep: "posture".to_string(), why },
    };
    let rep = posture::judge(&raw, m);
    drop(raw);
    let findings = rep
        .findings
        .iter()
        .enumerate()
        .map(|(i, f)| {
            let pids = if f.pids.is_empty() {
                String::new()
            } else {
                format!(" [pid {}]", f.pids.iter().map(u32::to_string).collect::<Vec<_>>().join(" "))
            };
            let subject = format!("{} {}", f.subject.label(), f.what);
            finding(i, "posture", sev(f.severity), &subject, &format!("{}{pids}", f.what), &f.why)
        })
        .collect();
    Outcome::Judged(Rejudged {
        sweep: "posture".to_string(),
        findings,
        basis: format!(
            "{label}; the store does not name the manifest the box held: {} process(es), {} image(s) ({} vendor), {} \
             listener(s), {} kld(s), the agent's own pid not judged",
            rep.processes, rep.images, rep.vendor_images, rep.listeners, rep.klds
        ),
        gaps: rep.gaps,
    })
}

fn routable(a: &IpAddr) -> bool {
    match a {
        IpAddr::V4(v) => !(v.is_loopback() || v.is_link_local() || v.is_unspecified() || v.is_multicast() || v.is_broadcast()),
        IpAddr::V6(v) => !(v.is_loopback() || v.is_unspecified() || v.is_multicast() || (v.segments()[0] & 0xffc0) == 0xfe80),
    }
}

pub(crate) fn snapshot_presence(records: &[Vec<u8>]) -> Vec<Presence> {
    let host_snapshot = records.first().is_some_and(|r| r.len() == 17 && r.first() == Some(&b's'))
        && records.get(1).is_some_and(|r| r.first() == Some(&b'v'));
    if !host_snapshot {
        return Vec::new();
    }
    let mut out = Vec::new();
    for r in records {
        let Some(rest) = r.strip_prefix(b"i") else { continue };
        let Some(nul) = rest.iter().position(|b| *b == 0) else { continue };
        let key = String::from_utf8_lossy(rest.get(..nul).unwrap_or_default()).into_owned();
        let value = String::from_utf8_lossy(rest.get(nul + 1..).unwrap_or_default());
        if let Some(d) = value.strip_prefix("sha256:") {
            let d = d.trim().to_ascii_lowercase();
            if d.len() == 64 && d.bytes().all(|b| b.is_ascii_hexdigit()) && d != EMPTY_SHA256 {
                out.push(Presence { entity: Entity::Digest(d), at: key.clone() });
            }
        }
        if key.ends_with("/authorized_keys") || key.ends_with("/authorized_keys2") {
            if let Some(text) = value.strip_prefix("text:") {
                for k in hemostat_sensor_freebsd::accounts::parse_authorized_keys(text).0 {
                    if let Some(fp) = k.fingerprint() {
                        out.push(Presence { entity: Entity::Key(fp), at: key.clone() });
                    }
                }
            }
        }
    }
    out
}

pub(crate) fn host_facts(h: HostFlows) -> Facts {
    let conns = h
        .sockets
        .iter()
        .filter(|s| s.proto == "tcp" && s.state == "ESTABLISHED")
        .filter_map(|s| {
            let r = s.remote.map(hemostat_sensor_linux::flowexport::unmap).filter(routable)?;
            Some(Conn { local: format!("{}:{}", s.local, s.lport), remote: r, port: s.rport, owner: s.owner.clone().unwrap_or_default() })
        })
        .collect();
    Facts {
        taken_ns: i64::try_from(h.now).ok().and_then(|n| n.checked_mul(1_000_000_000)),
        hostname: h.hostname.clone(),
        addrs: h.addrs.iter().map(|a| hemostat_sensor_linux::flowexport::unmap(*a)).filter(routable).collect(),
        conns,
        present: Vec::new(),
        flow: Some(FlowSide::Host(Rc::new(h))),
    }
}

pub(crate) fn flow_report(r: &crate::collector::Report) -> FlowReport {
    use crate::collector::Grade;
    let c = &r.clock;
    let clock = match (c.unmeasured.as_deref(), c.floor) {

        (Some(why), _) => format!("the clocks are NOT MEASURED: {why}. No CONTRADICTION is called"),
        (None, Some(f)) if c.violated() => format!("the agreed flows put box − host at {f:+} s or more, OVER THE ±{} s bound: no CONTRADICTION is called", c.skew),
        (None, Some(f)) => format!("the agreed flows put box − host at {f:+} s or more, within the ±{} s bound", c.skew),
        (None, None) => format!("no agreed TCP flow to check the ±{} s bound with", c.skew),
    };
    FlowReport {
        host_on_fw: r.host_on_fw.clone(),
        flows: r
            .flows
            .iter()
            .map(|f| FlowRow {
                grade: match f.grade {
                    Grade::Contradiction => FlowGrade::Contradiction,
                    Grade::Unknown => FlowGrade::Unknown,
                    Grade::Agreement => FlowGrade::Agreement,
                },
                flow: f.flow.clone(),
                basis: f.basis.clone(),
            })
            .collect(),
        unknowns: r.unknowns.clone(),
        clock,
    }
}

struct Loaded {
    manifest: Verified,
    meta: Result<VerifiedMeta, String>,
    label: String,
}

pub(crate) struct FirewallJudge {
    path: Option<PathBuf>,
    loaded: OnceCell<Result<Loaded, String>>,
    accounts: accounts::Opts,

    captures: RefCell<BTreeMap<[u8; 32], Rc<telemetry::Evidence>>>,
}

impl FirewallJudge {

    pub(crate) fn new(base: &Path, flag: Option<&str>, operator_keys: Vec<String>) -> FirewallJudge {
        let path = flag
            .map(PathBuf::from)
            .or_else(|| std::env::var(crate::vendor_manifest::MANIFEST_ENV).ok().filter(|v| !v.is_empty()).map(PathBuf::from))
            .or_else(|| {
                let dir = base.join("manifests");
                let mut tsv: Vec<PathBuf> = std::fs::read_dir(&dir)
                    .ok()?
                    .flatten()
                    .map(|e| e.path())
                    .filter(|p| p.extension().is_some_and(|x| x == "tsv"))
                    .collect();
                tsv.sort();
                (tsv.len() == 1).then(|| tsv.remove(0))
            });
        FirewallJudge { path, loaded: OnceCell::new(), accounts: accounts::Opts { operator_keys }, captures: RefCell::new(BTreeMap::new()) }
    }

    fn capture(&self, store: &HeldStore, m: &Verified) -> Result<Rc<telemetry::Evidence>, String> {
        if let Some(ev) = self.captures.borrow().get(&store.genesis) {
            return Ok(Rc::clone(ev));
        }
        let raw = telemetry::Raw::from_records(store.records.iter().map(Vec::as_slice))?;
        let ev = Rc::new(telemetry::judge(&raw, m));
        self.captures.borrow_mut().insert(store.genesis, Rc::clone(&ev));
        Ok(ev)
    }

    fn load(&self) -> &Result<Loaded, String> {
        self.loaded.get_or_init(|| {
            let path = self.path.as_ref().ok_or_else(|| {
                "the collector holds no signed manifest to judge it against: put the pair (and its sidecar) under \
                 <engagement>/manifests/, or pass --manifest PATH, with the key in $HEMOSTAT_MANIFEST_PUBKEY"
                    .to_string()
            })?;
            let p = path.to_str().ok_or("the manifest path is not UTF-8")?;
            let open = |q: &Path| hemostat_sensor_linux::saferead::open_regular(q, "not a regular file");
            let manifest = crate::vendor_manifest::load_in_place(Some(p), &open)?
                .ok_or("no manifest was named")?;
            let meta_path = crate::vendor_manifest::meta_path_for(p, None);
            let meta = crate::vendor_manifest::load_meta_in_place(&meta_path, &manifest, &open);
            let label = format!(
                "the signed {} manifest ({} paths, sha256 {})",
                manifest.release,
                manifest.paths(),
                short(manifest.body_sha256())
            );
            Ok(Loaded { manifest, meta, label })
        })
    }
}

impl Rejudge for FirewallJudge {
    fn rejudge(&self, store: &HeldStore, peers: Peers<'_>) -> Outcome {
        let records = &store.records;
        match kind_of(records) {
            Kind::Snapshot => Outcome::Carried { kind: drift::KIND.to_string(), what: SNAPSHOT_WHAT.to_string() },
            Kind::Carried(kind, what) => Outcome::Carried { kind, what },
            Kind::Unknown(None) => Outcome::Unjudged {
                sweep: "unnamed".to_string(),
                why: "a sealed store that names no kind, which no HEMOSTAT writer makes: what it holds is judged \
                      nowhere in this queue. Find out what wrote it"
                    .to_string(),
            },
            Kind::Unknown(Some(kind)) => Outcome::Unjudged {
                why: format!(
                    "this collector does not know a sealed store of kind {kind}. If it is a sweep from a newer agent \
                     build, the raw input it sealed is judged nowhere in this queue: judge it with a collector of \
                     the same release, or read the box's own output"
                ),
                sweep: kind,
            },
            Kind::Drift => judge_drift(records, peers),
            Kind::Accounts => judge_accounts(records, &self.accounts),
            Kind::FwRules => judge_fw_rules(records),
            Kind::Persistence => match self.load() {
                Ok(l) => judge_persistence(records, Ok((l.manifest.manifest(), &l.label))),
                Err(why) => judge_persistence(records, Err(why)),
            },
            Kind::Trust => match self.load() {
                Ok(l) => judge_trust(records, Ok((l.manifest.manifest(), &l.label))),
                Err(why) => judge_trust(records, Err(why)),
            },
            Kind::Posture => match self.load() {
                Err(why) => Outcome::Unjudged { sweep: "posture".to_string(), why: why.clone() },
                Ok(l) => judge_posture(records, l.manifest.manifest(), &l.label),
            },
            Kind::Vendor => match self.load() {
                Err(why) => Outcome::Unjudged { sweep: "vendor".to_string(), why: why.clone() },
                Ok(Loaded { meta: Err(why), .. }) => Outcome::Unjudged {
                    sweep: "vendor".to_string(),
                    why: format!("{why}: the sidecar says where each digest came from, and without it nothing is graded"),
                },
                Ok(Loaded { manifest, meta: Ok(meta), label }) => judge_vendor(records, manifest, meta, label),
            },
            Kind::Telemetry => match self.load() {
                Err(why) => Outcome::Unjudged { sweep: "fw-flows".to_string(), why: why.clone() },
                Ok(l) => match self.capture(store, &l.manifest) {
                    Ok(ev) => judge_evidence(&ev, &l.label),
                    Err(why) => Outcome::Unjudged { sweep: "fw-flows".to_string(), why },
                },
            },
        }
    }

    fn facts(&self, store: &HeldStore) -> Facts {
        if store.shape != hemostat_fleet::check::StoreShape::SealedCustody {
            return Facts::default();
        }
        match kind_of(&store.records) {
            Kind::Telemetry => {

                let Ok(l) = self.load() else { return Facts::default() };
                let Ok(ev) = self.capture(store, &l.manifest) else { return Facts::default() };
                Facts {
                    taken_ns: i64::try_from(ev.now).ok().and_then(|n| n.checked_mul(1_000_000_000)),
                    addrs: verdict::own_addresses(&ev).into_iter().filter(routable).collect(),
                    flow: Some(FlowSide::Firewall(ev)),
                    ..Facts::default()
                }
            }

            Kind::Carried(k, _) if k.as_bytes().starts_with(HOSTFLOWS_SCOPE) => {
                match HostFlows::from_records(store.records.iter().map(Vec::as_slice)) {
                    Ok(h) => host_facts(h),
                    Err(_) => Facts::default(),
                }
            }

            Kind::Carried(..) | Kind::Unknown(_) => Facts { present: snapshot_presence(&store.records), ..Facts::default() },
            _ => Facts::default(),
        }
    }

    fn flow(&self, fw: &dyn std::any::Any, host: &dyn std::any::Any, ask: &FlowAsk<'_>) -> Option<FlowReport> {
        let ev = fw.downcast_ref::<telemetry::Evidence>()?;
        let h = host.downcast_ref::<HostFlows>()?;
        let elsewhere: BTreeSet<IpAddr> = ask.elsewhere.iter().copied().collect();
        Some(flow_report(&crate::collector::correlate(ev, h, ask.skew_s, ask.offset_s, &elsewhere)))
    }
}
