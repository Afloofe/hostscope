use hemostat_sensor_win::drift::{self, Finding};
use hs_core::snapshot::Snapshot;

use crate::render::{h, hex32, jesc};
use crate::{EXIT_OK, EXIT_PARTIAL};

#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
pub(crate) const DEFAULT_STORE: &str = r"C:\ProgramData\hemostat\snapshot";

pub(crate) const PIN_ENV: &str = "HEMOSTAT_SNAPSHOT_PUBKEY";

pub(crate) fn records(salt: &[u8; 16], snap: &Snapshot) -> Vec<Vec<u8>> {
    let mut recs = vec![
        [b"s".as_slice(), salt].concat(),
        [b"v".as_slice(), snap.scope.to_string().as_bytes()].concat(),
        [b"k".as_slice(), drift::KIND.as_bytes()].concat(),
    ];
    recs.extend(snap.gaps.iter().map(|g| [b"g".as_slice(), g.as_bytes()].concat()));
    recs.extend(snap.items.iter().map(|(k, v)| [b"i".as_slice(), k.as_bytes(), b"\0", v.as_bytes()].concat()));
    recs
}

pub(crate) fn decode(records: &[Vec<u8>]) -> Result<([u8; 16], Snapshot), String> {
    let mut salt = None;
    let mut kind = None;
    let mut snap = Snapshot::default();
    let mut scope = None;
    for r in records {
        match r.split_first() {
            Some((b's', rest)) => salt = <[u8; 16]>::try_from(rest).ok(),
            Some((b'v', rest)) => scope = std::str::from_utf8(rest).ok().and_then(|v| v.parse::<u32>().ok()),
            Some((b'k', rest)) => kind = Some(String::from_utf8_lossy(rest).into_owned()),
            Some((b'g', rest)) => snap.gaps.push(String::from_utf8_lossy(rest).into_owned()),
            Some((b'i', rest)) => {
                let nul = rest.iter().position(|b| *b == 0).ok_or("a snapshot record has no key separator")?;
                let (k, v) = rest.split_at(nul);
                snap.items.insert(
                    String::from_utf8_lossy(k).into_owned(),
                    String::from_utf8_lossy(v.get(1..).unwrap_or_default()).into_owned(),
                );
            }
            _ => return Err("a snapshot record of a kind this build does not know".into()),
        }
    }
    if kind.as_deref() != Some(drift::KIND) {
        return Err(format!(
            "this is not a Windows snapshot (kind {}): a Linux host's or the firewall's arrival snapshot is \
             compared by that agent",
            kind.as_deref().unwrap_or("none")
        ));
    }
    snap.scope = match scope {
        Some(s) if s <= drift::SCOPE => s,
        Some(s) => {
            return Err(format!(
                "the snapshot was taken by a newer build (scope {s}) than this one (scope {}); run drift with \
                 the build that took it",
                drift::SCOPE
            ))
        }
        None => return Err("the snapshot has no scope record".into()),
    };
    let salt = salt.ok_or("the snapshot has no salt record")?;
    Ok((salt, snap))
}

pub(crate) struct DriftReport {
    pub(crate) store: String,
    pub(crate) pinned: bool,
    pub(crate) seal: [u8; 32],
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

    fn count(&self, s: hs_core::severity::Severity) -> usize {
        self.findings.iter().filter(|f| f.severity == s).count()
    }
}

pub(crate) fn render_drift(r: &DriftReport) -> String {
    use hs_core::severity::Severity;
    use std::fmt::Write as _;
    let mut o = String::new();
    let _ = writeln!(o, "drift — what changed since the arrival snapshot ({})", h(&r.store));
    if r.pinned {
        let _ = writeln!(o, "  snapshot seal key matches ${PIN_ENV}");
    } else {
        let _ = writeln!(
            o,
            "  NOTE: the snapshot's seal key ({}) is not pinned. An administrator on this host could have \
             re-written the snapshot under a key of their own; set {PIN_ENV} to the key printed when it was taken",
            hex32(&r.seal)
        );
    }
    let _ = writeln!(
        o,
        "  {} change(s): {} CRITICAL, {} WARN, {} note",
        r.findings.len(),
        r.count(Severity::Critical),
        r.count(Severity::Warn),
        r.count(Severity::Note)
    );
    for f in &r.findings {
        let _ = writeln!(o, "  [{}] {}", f.severity.tag(), h(&f.subject));
        for (i, line) in f.what.lines().enumerate() {
            let _ = writeln!(o, "        {}{}", if i == 0 { "" } else { "  " }, h(line));
        }
        let _ = writeln!(o, "        why: {}", h(&f.why));
    }
    if r.findings.is_empty() && r.gaps.is_empty() {
        let _ = writeln!(o, "  nothing recorded on arrival has changed.");
    }
    for g in &r.gaps {
        let _ = writeln!(o, "  NOT COMPARED: {}", h(g));
    }
    let _ = writeln!(
        o,
        "\n  This compares what the snapshot records. A file replaced under the same path, a process, a \
         per-user Run key of a profile nobody is logged on as — those are for the other sweeps."
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
    format!(
        "{{\"store\":\"{}\",\"pinned\":{},\"seal_pub\":\"{}\",\"changes\":{},\"gaps\":[{}],\"findings\":[{}],\
         \"complete\":{}}}",
        jesc(&r.store),
        r.pinned,
        hex32(&r.seal),
        r.findings.len(),
        r.gaps.iter().map(|g| format!("\"{}\"", jesc(g))).collect::<Vec<_>>().join(","),
        rows.join(","),
        r.exit_code() == EXIT_OK
    )
}

#[cfg(any(target_os = "windows", test))]
const MAX_IMAGE: u64 = 1 << 30;

#[cfg(any(target_os = "windows", test))]
pub(crate) fn image_digest(p: &str) -> Result<String, String> {
    use sha2::{Digest as _, Sha256};
    use std::io::Read as _;
    let mut c = p.chars();
    let local = matches!((c.next(), c.next(), c.next()), (Some(d), Some(':'), Some('\\' | '/')) if d.is_ascii_alphabetic());
    if !local {
        return Err("not a path on a local drive: a network or device path is not read".into());
    }
    let md = std::fs::metadata(p).map_err(|e| e.to_string())?;
    if !md.is_file() {
        return Err("not a regular file".into());
    }
    if md.len() > MAX_IMAGE {
        return Err(format!("{} bytes, over the {MAX_IMAGE}-byte cap", md.len()));
    }
    let f = std::fs::File::open(p).map_err(|e| e.to_string())?;
    let mut r = f.take(MAX_IMAGE + 1);
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        match r.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => h.update(buf.get(..n).unwrap_or_default()),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e.to_string()),
        }
    }
    Ok(h.finalize().iter().map(|b| format!("{b:02x}")).collect())
}

#[cfg(target_os = "windows")]
mod verbs {
    use std::path::Path;

    use hemostat_sensor_win::acl;

    use super::*;
    use crate::sealed::{open, seal, Ids};
    use crate::{EXIT_FAILED, EXIT_NOT_BUILT, EXIT_USAGE};

    fn store_arg(args: &[String]) -> String {
        args.iter()
            .position(|a| a == "--store")
            .and_then(|i| args.get(i + 1))
            .cloned()
            .unwrap_or_else(|| DEFAULT_STORE.to_string())
    }

    fn extra_policy() -> Vec<(String, Result<String, String>)> {
        let mut out = Vec::new();
        #[cfg(feature = "mod-sensor-evtlog")]
        out.extend(hemostat_sensor_win::evtlog::policy_readings());
        #[cfg(not(feature = "mod-sensor-evtlog"))]
        out.push(("audit and event-log settings".into(), Err("not built into this variant (mod-sensor-evtlog)".into())));
        #[cfg(feature = "mod-sensor-usn")]
        out.push((
            "usn/C:".into(),
            hemostat_sensor_win::usn::journal_id("C:")
                .map(|j| j.map_or_else(|| "no journal".to_string(), |id| format!("{id:#x}"))),
        ));
        #[cfg(not(feature = "mod-sensor-usn"))]
        out.push(("usn/C:".into(), Err("not built into this variant (mod-sensor-usn)".into())));
        out
    }

    fn place(dir: &str) -> Result<(), String> {
        let parent = Path::new(dir).parent().and_then(Path::to_str).filter(|p| !p.is_empty()).ok_or("the store needs a parent directory")?;
        let default_parent = Path::new(DEFAULT_STORE).parent().and_then(Path::to_str).unwrap_or_default();
        if !Path::new(parent).exists() {
            if parent.eq_ignore_ascii_case(default_parent) {
                acl::create_private_dir(parent)?;
            } else {
                return Err(format!("{parent} does not exist"));
            }
        }
        match acl::dacl_of_read(parent) {
            Ok(aces) if acl::grants_unprivileged_write(&aces) => Err(format!(
                "{parent} can be written by unprivileged users, so any of them could replace or delete a store \
                 there. Give --store a directory only administrators can write"
            )),
            Ok(_) => Ok(()),
            Err(rc) => Err(format!("the DACL of {parent} could not be read (error {rc})")),
        }
    }

    fn add_images(snap: &mut hs_core::snapshot::Snapshot) {
        let host = drift::LiveHost::default();
        let files: std::collections::BTreeSet<String> = drift::run_commands(snap).iter().filter_map(|c| drift::resolve(c, &host)).collect();
        let mut refused = Vec::new();
        for p in files {
            match image_digest(&p) {
                Ok(d) => {
                    snap.items.insert(format!("{}{p}", drift::IMAGE), format!("sha256:{d}"));
                }
                Err(e) => refused.push(format!("{p}: {e}")),
            }
        }
        if !refused.is_empty() {
            snap.gaps.push(format!(
                "run images: {} file(s) something runs were not hashed: {}",
                refused.len(),
                refused.iter().take(5).cloned().collect::<Vec<_>>().join("; ")
            ));
        }
    }

    fn ids() -> Result<(Ids, &'static str), String> {
        let id = crate::identity::gather_identity().map_err(|e| format!("cannot establish identity: {e}"))?;
        Ok((
            Ids { engagement: id.engagement, host: id.host, agent: id.agent, instance: id.instance, run: id.run_id, boot: id.boot },
            id.host_id_source,
        ))
    }

    pub(crate) fn take_snapshot(args: &[String], json: bool) -> u8 {
        if let Err(msg) = crate::remedy::require_built(hemostat_buildinfo::ActionClass::Collect) {
            eprintln!("hemostat snapshot: {msg}");
            return EXIT_NOT_BUILT;
        }
        let dir = store_arg(args);
        if let Err(e) = place(&dir) {
            eprintln!("hemostat snapshot: DID NOT RUN — {}", h(&e));
            return EXIT_FAILED;
        }
        if Path::new(&dir).exists() {
            if !args.iter().any(|a| a == "--replace") {
                eprintln!(
                    "hemostat snapshot: {dir} already holds a snapshot. The arrival snapshot is taken once; \
                     replacing it moves what counts as \"arrival\". `--replace` keeps the old one beside it and \
                     takes a new one"
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
        let (ids, host_source) = match ids() {
            Ok(i) => i,
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
        let mut snap = drift::record(&drift::read(extra_policy()));
        add_images(&mut snap);
        let items = snap.items.keys().filter(|k| !k.starts_with("covered/")).count();
        let w = match seal(&dir, seed, records(&salt, &snap), &ids) {
            Ok(w) => w,
            Err(e) => {
                eprintln!("hemostat snapshot: {}", h(&e));
                return EXIT_FAILED;
            }
        };
        if json {
            jprintln!(
                "{{\"store\":\"{}\",\"items\":{items},\"gaps\":[{}],\"seal_pub\":\"{}\",\"genesis\":\"{}\",\
                 \"host_id_source\":\"{}\"}}",
                jesc(&dir),
                snap.gaps.iter().map(|g| format!("\"{}\"", jesc(g))).collect::<Vec<_>>().join(","),
                hex32(&w.seal_pub),
                hex32(&w.genesis),
                host_source
            );
        } else {
            println!("snapshot — the host as it is on arrival, sealed into {}", h(&dir));
            println!("  {items} item(s) recorded");
            println!("  seal key {}", hex32(&w.seal_pub));
            println!("  KEEP THIS OFF-HOST, and pin it for `drift`: {PIN_ENV}={}", hex32(&w.seal_pub));
            for g in &snap.gaps {
                println!("  NOT RECORDED: {}", h(g));
            }
            println!(
                "\n  This records what changed from here on. It says nothing about what was done before it; \
                 `persistence`, `accounts` and the other sweeps answer that."
            );
        }
        if snap.gaps.is_empty() {
            EXIT_OK
        } else {
            EXIT_PARTIAL
        }
    }

    pub(crate) fn drift(args: &[String], json: bool) -> u8 {
        let dir = store_arg(args);
        if !Path::new(&dir).exists() {
            eprintln!(
                "hemostat drift: DID NOT RUN — no arrival snapshot at {dir}. Take one with `hemostat snapshot` \
                 when you arrive; with nothing to compare against, no change can be seen, which is not the same \
                 as none having happened"
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
        let (opened, (_, was)) = match open(&dir, pin).and_then(|o| decode(&o.records).map(|d| (o, d))) {
            Ok(x) => x,
            Err(e) => {
                eprintln!("hemostat drift: DID NOT RUN — {}: {}", h(&dir), h(&e));
                return EXIT_FAILED;
            }
        };
        let now = drift::record(&drift::read(extra_policy()));
        let (changes, unscoped) = match drift::compare(&was, &now) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("hemostat drift: DID NOT RUN — {}", h(&e));
                return EXIT_FAILED;
            }
        };
        let findings = drift::judge_all(&changes, &now, &mut drift::LiveHost::default());
        let report = DriftReport { store: dir, pinned: pin.is_some(), seal: opened.seal_pub, findings, gaps: unscoped };
        if json {
            jprintln!("{}", render_drift_json(&report));
        } else {
            print!("{}", render_drift(&report));
        }
        report.exit_code()
    }
}

#[cfg(target_os = "windows")]
pub(crate) use verbs::{drift, take_snapshot};
