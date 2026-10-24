#![cfg_attr(all(target_os = "linux", not(test)), allow(dead_code, unused_imports))]

use std::collections::BTreeMap;

use hemostat_sensor_freebsd::configxml::{self, Revision};
use hemostat_sensor_freebsd::drift::{self, Finding};

use crate::render::{h, hex32, jesc};
use crate::{EXIT_OK, EXIT_PARTIAL};

#[cfg_attr(not(target_os = "freebsd"), allow(dead_code))]
pub(crate) const DEFAULT_STORE: &str = "/root/hemostat/snapshot";

pub(crate) const PIN_ENV: &str = "HEMOSTAT_SNAPSHOT_PUBKEY";

pub(crate) const DRIFT_KIND: &str = "pfsense-config-drift";

pub(crate) use crate::sealed::{open, seal, Ids};

pub(crate) fn snapshot_records(salt: &[u8; 16], raw: &[u8]) -> (Vec<Vec<u8>>, usize, Vec<String>) {
    let mut recs = vec![
        [b"s".as_slice(), salt].concat(),
        [b"v".as_slice(), drift::SCOPE.to_string().as_bytes()].concat(),
        [b"k".as_slice(), drift::KIND.as_bytes()].concat(),
    ];
    recs.extend(drift::raw_records(raw));
    let mut gaps = Vec::new();
    let items = match configxml::parse(raw) {
        Ok(c) => drift::items(&c, salt),
        Err(e) => {
            gaps.push(format!("config.xml was sealed but not read, so no item was recorded: {e}"));
            BTreeMap::new()
        }
    };
    recs.extend(gaps.iter().map(|g| [b"g".as_slice(), g.as_bytes()].concat()));
    recs.extend(items.iter().map(|(k, v)| [b"i".as_slice(), k.as_bytes(), b"\0", v.as_bytes()].concat()));
    (recs, items.len(), gaps)
}

#[derive(Debug)]
pub(crate) struct Arrival {
    pub(crate) salt: [u8; 16],
    pub(crate) raw: Vec<u8>,
    pub(crate) gaps: Vec<String>,
}

pub(crate) fn decode_snapshot(records: &[Vec<u8>]) -> Result<Arrival, String> {
    let mut salt = None;
    let mut scope = None;
    let mut kind = None;
    let mut gaps = Vec::new();
    for r in records {
        match r.split_first() {
            Some((b's', rest)) => salt = <[u8; 16]>::try_from(rest).ok(),
            Some((b'v', rest)) => scope = std::str::from_utf8(rest).ok().and_then(|v| v.parse::<u32>().ok()),
            Some((b'k', rest)) => kind = Some(String::from_utf8_lossy(rest).into_owned()),
            Some((b'g', rest)) => gaps.push(String::from_utf8_lossy(rest).into_owned()),
            Some((b'i' | b'R' | b'r', _)) => {}
            _ => return Err("a snapshot record of a kind this build does not know".into()),
        }
    }
    if kind.as_deref() != Some(drift::KIND) {
        return Err(format!(
            "this is not a firewall snapshot (kind {}): a Linux host's arrival snapshot is compared by \
             the Linux agent",
            kind.as_deref().unwrap_or("none")
        ));
    }
    match scope {
        Some(s) if s <= drift::SCOPE => {}
        Some(s) => {
            return Err(format!(
                "the snapshot was taken by a newer build (scope {s}) than this one (scope {}); run drift \
                 with the build that took it",
                drift::SCOPE
            ))
        }
        None => return Err("the snapshot has no scope record".into()),
    }
    let salt = salt.ok_or("the snapshot has no salt record")?;
    let raw = drift::raw_from_records(records.iter().map(Vec::as_slice))?;
    Ok(Arrival { salt, raw, gaps })
}

pub(crate) fn drift_records(arrival_seal: &[u8; 32], raw: &[u8]) -> Vec<Vec<u8>> {
    let mut recs = vec![[b"k".as_slice(), DRIFT_KIND.as_bytes()].concat(), [b"a".as_slice(), arrival_seal].concat()];
    recs.extend(drift::raw_records(raw));
    recs
}

pub(crate) fn decode_drift(records: &[Vec<u8>], arrival_seal: &[u8; 32]) -> Result<Vec<u8>, String> {
    let kind = records.iter().find_map(|r| r.strip_prefix(b"k"));
    if kind != Some(DRIFT_KIND.as_bytes()) {
        return Err("the drift store is not one this run wrote".into());
    }
    if records.iter().find_map(|r| r.strip_prefix(b"a")) != Some(arrival_seal.as_slice()) {
        return Err("the drift store names another arrival snapshot".into());
    }
    drift::raw_from_records(records.iter().map(Vec::as_slice))
}

pub(crate) struct DriftReport {
    pub(crate) snapshot: String,
    pub(crate) pinned: bool,
    pub(crate) arrival_seal: [u8; 32],
    pub(crate) arrival_sha: [u8; 32],
    pub(crate) drift_dir: String,
    pub(crate) drift_seal: [u8; 32],
    pub(crate) now_sha: [u8; 32],
    pub(crate) revision: Option<Revision>,
    pub(crate) findings: Vec<Finding>,
    pub(crate) gaps: Vec<String>,
}

impl DriftReport {

    pub(crate) fn exit_code(&self) -> u8 {
        if self.gaps.is_empty() {
            EXIT_OK
        } else {
            EXIT_PARTIAL
        }
    }
}

pub(crate) fn render_drift(r: &DriftReport) -> String {
    use std::fmt::Write as _;
    let mut o = String::new();
    let _ = writeln!(o, "drift — what changed in config.xml since the arrival snapshot ({})", h(&r.snapshot));
    if r.pinned {
        let _ = writeln!(o, "  snapshot seal key matches ${PIN_ENV}");
    } else {
        let _ = writeln!(
            o,
            "  NOTE: the snapshot's seal key ({}) is not pinned. Root on this box could have re-written \
             the snapshot under a key of its own; set {PIN_ENV} to the key printed when it was taken",
            hex32(&r.arrival_seal)
        );
    }
    let _ = writeln!(
        o,
        "  arrival config.xml sha256 {} · now {}{}",
        hex32(&r.arrival_sha).get(..16).unwrap_or_default(),
        hex32(&r.now_sha).get(..16).unwrap_or_default(),
        if r.arrival_sha == r.now_sha { " (byte-identical)" } else { "" }
    );
    let _ = writeln!(o, "  the current file was sealed before it was judged: {} (key {})", h(&r.drift_dir), hex32(&r.drift_seal));
    if let Some(rev) = &r.revision {

        let by = if rev.description.starts_with(&rev.username) { String::new() } else { format!(" [by {}]", h(&rev.username)) };
        let _ = writeln!(o, "  last written at {} (the box's clock): {}{by}", h(&rev.time), h(&rev.description));
    }
    for f in &r.findings {
        let _ = writeln!(o, "  [{}] {}", f.severity.tag(), h(&f.subject));
        for (i, line) in f.what.lines().enumerate() {
            let _ = writeln!(o, "        {}{}", if i == 0 { "" } else { "  " }, h(line));
        }
        let _ = writeln!(o, "        why: {}", h(&f.why));
    }
    if r.findings.is_empty() && r.gaps.is_empty() {
        let _ = writeln!(o, "  nothing in config.xml has changed since arrival.");
    }
    for g in &r.gaps {
        let _ = writeln!(o, "  NOT COMPARED: {}", h(g));
    }
    let _ = writeln!(
        o,
        "\n  This compares config.xml only. A change made outside it — a file, a running rule, a \
         process — is for `vendor`, `fw rules` and `posture`."
    );
    o
}

pub(crate) fn render_drift_json(r: &DriftReport) -> String {
    let rows: Vec<String> = r
        .findings
        .iter()
        .map(|f| {
            format!(
                "{{\"severity\":\"{}\",\"subject\":\"{}\",\"what\":\"{}\",\"why\":\"{}\"}}",
                f.severity.tag(),
                jesc(&f.subject),
                jesc(&f.what),
                jesc(&f.why)
            )
        })
        .collect();
    let rev = match &r.revision {
        Some(v) => format!(
            "{{\"time\":\"{}\",\"username\":\"{}\",\"description\":\"{}\"}}",
            jesc(&v.time),
            jesc(&v.username),
            jesc(&v.description)
        ),
        None => "null".into(),
    };
    format!(
        "{{\"store\":\"{}\",\"pinned\":{},\"arrival_seal\":\"{}\",\"arrival_sha256\":\"{}\",\
         \"drift_store\":\"{}\",\"drift_seal\":\"{}\",\"now_sha256\":\"{}\",\"revision\":{rev},\
         \"changes\":{},\"gaps\":[{}],\"findings\":[{}],\"complete\":{}}}",
        jesc(&r.snapshot),
        r.pinned,
        hex32(&r.arrival_seal),
        hex32(&r.arrival_sha),
        jesc(&r.drift_dir),
        hex32(&r.drift_seal),
        hex32(&r.now_sha),
        r.findings.len(),
        r.gaps.iter().map(|g| format!("\"{}\"", jesc(g))).collect::<Vec<_>>().join(","),
        rows.join(","),
        r.exit_code() == EXIT_OK
    )
}

#[cfg(target_os = "freebsd")]
mod verbs {
    use std::path::Path;

    use hemostat_sensor_freebsd::configxml::{CONFIG_PATH, MAX_BYTES};
    use hemostat_sensor_freebsd::{drift, saferead, store, tools};

    use super::*;
    use crate::{EXIT_FAILED, EXIT_NOT_BUILT, EXIT_USAGE};

    fn store_arg(args: &[String]) -> String {
        args.iter()
            .position(|a| a == "--store")
            .and_then(|i| args.get(i + 1))
            .cloned()
            .unwrap_or_else(|| DEFAULT_STORE.to_string())
    }

    pub(crate) struct Prepared {
        pub(crate) ids: Ids,
        quota: Option<store::Store>,
    }

    pub(crate) fn prepare(verb: &str, dir: &str) -> Result<Prepared, String> {
        let open = |p: &Path| saferead::open_regular(p, saferead::NOT_REGULAR);
        let loaded = crate::vendor_manifest::load_in_place(None, &open)?;
        let mut sys = tools::System::new(loaded.as_ref());
        prepare_in(verb, dir, &mut sys)
    }

    pub(crate) fn prepare_in(verb: &str, dir: &str, sys: &mut tools::System<'_>) -> Result<Prepared, String> {
        let parent = Path::new(dir).parent().and_then(Path::to_str).filter(|p| !p.is_empty()).unwrap_or("/");
        let quota = if Path::new(dir).starts_with(store::STORE_DIR) {
            Some(store::Store::open(sys, Path::new("/")).map_err(|e| format!("the store has nowhere safe to go: {e}"))?)
        } else {
            store::place(sys, Path::new("/"), parent).map_err(|e| format!("{parent}: {e}"))?;
            None
        };
        let (id, host) = crate::identity::gather_identity_with(sys)
            .map_err(|e| format!("cannot read entropy for the identity: {e}"))?;
        if let Some((sev, what)) = host.finding() {
            eprintln!("hemostat {verb}: {}: {}", sev.tag(), h(&what));
        }
        Ok(Prepared {
            ids: Ids { engagement: id.engagement, host: id.host, agent: id.agent, instance: id.instance, run: id.run_id, boot: id.boot },
            quota,
        })
    }

    pub(crate) fn admit(p: &Prepared, bytes: usize) -> Result<(), String> {
        match &p.quota {

            Some(s) => s.admit(bytes as u64 + 64 * 1024).map_err(|e| e.to_string()),
            None => Ok(()),
        }
    }

    fn read_config() -> Result<Vec<u8>, String> {
        saferead::read_bytes(Path::new(CONFIG_PATH), MAX_BYTES).map_err(|e| format!("{CONFIG_PATH}: {e}"))
    }

    pub(crate) fn take_snapshot(args: &[String], json: bool) -> u8 {
        if let Err(msg) = crate::remedy::require_built(hemostat_buildinfo::ActionClass::Collect) {
            eprintln!("hemostat snapshot: {msg}");
            return EXIT_NOT_BUILT;
        }
        let dir = store_arg(args);
        let prep = match prepare("snapshot", &dir) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("hemostat snapshot: DID NOT RUN — {}", h(&e));
                return EXIT_FAILED;
            }
        };
        if Path::new(&dir).exists() {
            if !args.iter().any(|a| a == "--replace") {
                eprintln!(
                    "hemostat snapshot: {dir} already holds a snapshot. The arrival snapshot is taken \
                     once; replacing it moves what counts as \"arrival\". `--replace` keeps the old one \
                     beside it and takes a new one"
                );
                return EXIT_USAGE;
            }
            let secs = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs());
            let kept = format!("{dir}.{secs}");
            if let Err(e) = std::fs::rename(&dir, &kept) {
                eprintln!("hemostat snapshot: cannot move the old snapshot aside to {kept}: {e}");
                return EXIT_FAILED;
            }
            eprintln!("hemostat snapshot: the previous snapshot is kept at {kept}");
        }
        let raw = match read_config() {
            Ok(r) => r,
            Err(e) => {
                eprintln!("hemostat snapshot: DID NOT RUN — {}", h(&e));
                return EXIT_FAILED;
            }
        };
        let (salt, seed) = match (crate::identity::rand16(), crate::identity::rand32()) {
            (Ok(s), Ok(k)) => (s, k),
            _ => {
                eprintln!("hemostat snapshot: no entropy for the salt or the seal key");
                return EXIT_FAILED;
            }
        };
        let (records, items, gaps) = snapshot_records(&salt, &raw);
        if let Err(e) = admit(&prep, records.iter().map(Vec::len).sum()) {
            eprintln!("hemostat snapshot: DID NOT RUN — {}", h(&e));
            return EXIT_FAILED;
        }
        let w = match seal(&dir, seed, &records, &prep.ids) {
            Ok(w) => w,
            Err(e) => {
                eprintln!("hemostat snapshot: {}", h(&e));
                return EXIT_FAILED;
            }
        };
        let sha = drift::raw_digest(&raw);
        if json {
            jprintln!(
                "{{\"store\":\"{}\",\"items\":{items},\"bytes\":{},\"config_sha256\":\"{}\",\"gaps\":[{}],\
                 \"seal_pub\":\"{}\",\"genesis\":\"{}\"}}",
                jesc(&dir),
                raw.len(),
                hex32(&sha),
                gaps.iter().map(|g| format!("\"{}\"", jesc(g))).collect::<Vec<_>>().join(","),
                hex32(&w.seal_pub),
                hex32(&w.genesis)
            );
        } else {
            println!("snapshot — config.xml as it is on arrival, sealed into {}", h(&dir));
            println!("  {CONFIG_PATH}: {} bytes, sha256 {}, sealed raw", raw.len(), hex32(&sha));
            println!("  {items} item(s) recorded from it");
            println!("  seal key {}", hex32(&w.seal_pub));
            println!("  KEEP THIS OFF-BOX, and pin it for `drift`: {PIN_ENV}={}", hex32(&w.seal_pub));
            for g in &gaps {
                println!("  NOT RECORDED: {}", h(g));
            }
            println!(
                "\n  This records config.xml from here on. It says nothing about what was done before \
                 it, and nothing about the box outside that file."
            );
        }
        if gaps.is_empty() {
            EXIT_OK
        } else {
            EXIT_PARTIAL
        }
    }

    pub(crate) fn drift(args: &[String], json: bool) -> u8 {
        let dir = store_arg(args);
        if !Path::new(&dir).exists() {
            eprintln!(
                "hemostat drift: DID NOT RUN — no arrival snapshot at {dir}. Take one with `hemostat \
                 snapshot` when you arrive; with nothing to compare against, no change can be seen, \
                 which is not the same as none having happened"
            );
            return EXIT_PARTIAL;
        }
        let pin = match crate::identity::pinned_key(PIN_ENV) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("hemostat drift: DID NOT RUN — {}", h(&e));
                return EXIT_FAILED;
            }
        };
        let arrival = match open(&dir, pin).and_then(|o| decode_snapshot(&o.records).map(|a| (a, o.seal_pub))) {
            Ok(a) => a,
            Err(e) => {
                eprintln!("hemostat drift: DID NOT RUN — {}: {}", h(&dir), h(&e));
                return EXIT_FAILED;
            }
        };
        let (arrival, arrival_seal) = arrival;
        let secs = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs());
        let tag: String = crate::identity::rand16()
            .map(|r| r.iter().take(4).map(|b| format!("{b:02x}")).collect())
            .unwrap_or_default();
        let drift_dir = format!("{dir}.drift/{secs}-{tag}");
        let prep = match prepare("drift", &drift_dir) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("hemostat drift: DID NOT RUN — {}", h(&e));
                return EXIT_FAILED;
            }
        };
        let raw = match read_config() {
            Ok(r) => r,
            Err(e) => {
                eprintln!("hemostat drift: DID NOT RUN — {}", h(&e));
                return EXIT_FAILED;
            }
        };
        let records = drift_records(&arrival_seal, &raw);
        if let Err(e) = admit(&prep, records.iter().map(Vec::len).sum()) {
            eprintln!("hemostat drift: DID NOT RUN — {}", h(&e));
            return EXIT_FAILED;
        }

        if let Err(e) = store::create_private(Path::new(&format!("{dir}.drift"))) {
            eprintln!("hemostat drift: cannot make {dir}.drift: {e}");
            return EXIT_FAILED;
        }
        let seed = match crate::identity::rand32() {
            Ok(s) => s,
            Err(e) => {
                eprintln!("hemostat drift: no entropy for the seal key: {e}");
                return EXIT_FAILED;
            }
        };

        let sealed = match seal(&drift_dir, seed, &records, &prep.ids) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("hemostat drift: {}", h(&e));
                return EXIT_FAILED;
            }
        };
        drop(raw);
        let now = match open(&drift_dir, Some(sealed.seal_pub)).and_then(|o| decode_drift(&o.records, &arrival_seal)) {
            Ok(n) => n,
            Err(e) => {
                eprintln!("hemostat drift: the store this run just sealed does not read back: {}", h(&e));
                return EXIT_FAILED;
            }
        };
        let judged = drift::judge_raw(&arrival.raw, &now, &arrival.salt);
        let mut gaps = arrival.gaps;
        gaps.extend(judged.gaps);
        let report = DriftReport {
            snapshot: dir,
            pinned: pin.is_some(),
            arrival_seal,
            arrival_sha: drift::raw_digest(&arrival.raw),
            drift_dir,
            drift_seal: sealed.seal_pub,
            now_sha: drift::raw_digest(&now),
            revision: judged.revision,
            findings: judged.findings,
            gaps,
        };
        if json {
            jprintln!("{}", render_drift_json(&report));
        } else {
            print!("{}", render_drift(&report));
        }
        report.exit_code()
    }
}

#[cfg(target_os = "freebsd")]
pub(crate) use verbs::{admit, drift, prepare, prepare_in, take_snapshot};
