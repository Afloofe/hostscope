use std::collections::BTreeMap;
use std::path::Path;

use hemostat_evfmt::{RecType, RunContext, StoreHeader, StoreWriter, StreamCrypto, StreamId};
use hemostat_sensor_linux::rootkit::Severity;
use hemostat_sensor_linux::snapshot::{self, Snapshot};

use crate::identity::{gather_identity, rand16, rand32};
use crate::render::{h, hex32, jesc, rootkit_row};
use crate::{EXIT_FAILED, EXIT_OK, EXIT_PARTIAL, EXIT_USAGE};

pub(crate) const DEFAULT_STORE: &str = "/var/lib/hemostat/snapshot";

pub(crate) const PIN_ENV: &str = "HEMOSTAT_SNAPSHOT_PUBKEY";

fn store_arg(args: &[String]) -> String {
    args.iter()
        .position(|a| a == "--store")
        .and_then(|i| args.get(i + 1))
        .cloned()
        .unwrap_or_else(|| DEFAULT_STORE.to_string())
}

fn service_rows() -> (BTreeMap<String, String>, Vec<String>) {
    let declared = hemostat_sensor_linux::services::declarations();
    if declared.is_empty() {
        return (BTreeMap::new(), Vec::new());
    }
    match hemostat_sensor_linux::services::baseline_rows(&declared) {
        Ok(r) => r,
        Err(e) => (BTreeMap::new(), vec![format!("declared services: {e}")]),
    }
}

fn suspects(snap: &Snapshot, m: Option<&hemostat_sensor_linux::vendor::Manifest>) -> Vec<String> {
    use hemostat_sensor_linux::vendor::{judge, Verdict};
    let Some(m) = m else { return Vec::new() };
    snap.items
        .keys()
        .filter_map(|k| k.strip_prefix("service/"))
        .filter(|p| matches!(judge(m, Path::new(p)), Verdict::NotVendor | Verdict::Oversize(_)))
        .map(str::to_string)
        .collect()
}

pub(crate) fn take_snapshot(args: &[String], json: bool) -> u8 {
    if let Err(msg) = crate::remedy::require_built(hemostat_buildinfo::ActionClass::Collect) {
        eprintln!("hemostat snapshot: {msg}");
        return crate::EXIT_NOT_BUILT;
    }
    let dir = store_arg(args);
    if Path::new(&dir).exists() {
        if !args.iter().any(|a| a == "--replace") {
            eprintln!(
                "hemostat snapshot: {dir} already holds a snapshot. The arrival snapshot is taken \
                 once; replacing it moves what counts as \"arrival\". `--replace` keeps the old \
                 one beside it and takes a new one"
            );
            return EXIT_USAGE;
        }
        let secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let kept = format!("{dir}.{secs}");
        if let Err(e) = std::fs::rename(&dir, &kept) {
            eprintln!("hemostat snapshot: cannot move the old snapshot aside to {kept}: {e}");
            return EXIT_FAILED;
        }
        eprintln!("hemostat snapshot: the previous snapshot is kept at {kept}");
    }
    let manifest = match crate::vendor::load_manifest(None) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("hemostat snapshot: {}", h(&e));
            return EXIT_FAILED;
        }
    };
    match write(&dir, manifest.as_deref()) {
        Ok(w) => {
            if json {
                jprintln!(
                    "{{\"store\":\"{}\",\"items\":{},\"gaps\":[{}],\"suspect\":[{}],\"seal_pub\":\"{}\",\
                     \"genesis\":\"{}\",\"manifest\":{}}}",
                    jesc(&dir),
                    w.items,
                    w.gaps.iter().map(|g| format!("\"{}\"", jesc(g))).collect::<Vec<_>>().join(","),
                    w.suspect.iter().map(|g| format!("\"{}\"", jesc(g))).collect::<Vec<_>>().join(","),
                    hex32(&w.seal_pub),
                    hex32(&w.genesis),
                    manifest.is_some()
                );
            } else {
                println!("snapshot — the host as it is on arrival, sealed into {}", h(&dir));
                println!("  {} item(s) recorded", w.items);
                println!("  seal key {}", hex32(&w.seal_pub));
                println!("  KEEP THIS OFF-HOST, and pin it for `drift`: {PIN_ENV}={}", hex32(&w.seal_pub));
                for g in &w.gaps {
                    println!("  NOT RECORDED: {}", h(g));
                }
                if manifest.is_none() {
                    println!("  no vendor manifest was loaded, so nothing here was checked against one");
                }
                for p in &w.suspect {
                    println!(
                        "  [SUSPECT] {} is not the vendor's file — recorded as found; this snapshot \
                         does not vouch for it",
                        h(p)
                    );
                }
                println!(
                    "\n  This records what changed from here on. It says nothing about what was done \
                     before it; `vendor` and the other sweeps answer that."
                );
            }
            if w.gaps.is_empty() {
                EXIT_OK
            } else {
                EXIT_PARTIAL
            }
        }
        Err(e) => {
            eprintln!("hemostat snapshot: {}", h(&e));
            EXIT_FAILED
        }
    }
}

struct Written {
    items: usize,
    gaps: Vec<String>,
    suspect: Vec<String>,
    seal_pub: [u8; 32],
    genesis: [u8; 32],
}

fn write(dir: &str, manifest: Option<&hemostat_sensor_linux::vendor::Manifest>) -> Result<Written, String> {

    let id = gather_identity().map_err(|e| format!("cannot establish identity: {e}"))?;
    if let Some(why) = crate::resources::disk_refusal(Path::new(dir)) {
        return Err(format!("refusing to write the snapshot: {why}"));
    }
    let salt = rand16().map_err(|e| format!("no entropy for the salt: {e}"))?;
    let (rows, svc_gaps) = service_rows();
    let mut snap = snapshot::take(&salt, &rows);
    snap.gaps.extend(svc_gaps);
    let suspect = suspects(&snap, manifest);
    let ids = Ids { engagement: id.engagement, host: id.host, agent: id.agent, instance: id.instance, run: id.run_id, boot: id.boot };
    seal_to(dir, &salt, snap, suspect, &ids)
}

struct Ids {
    engagement: [u8; 16],
    host: [u8; 32],
    agent: [u8; 16],
    instance: [u8; 16],
    run: u32,
    boot: [u8; 16],
}

fn seal_to(dir: &str, salt: &[u8; 16], snap: Snapshot, suspect: Vec<String>, id: &Ids) -> Result<Written, String> {
    use hemostat_evcrypto::seal::{encode_header_keys, HeaderKeys, SealKey};
    let mut seed = rand32().map_err(|e| format!("no entropy for the seal key: {e}"))?;
    let seal = SealKey::from_seed(seed);
    hemostat_evcrypto::secret::wipe_bytes(&mut seed);
    let seal_pub = seal.public_bytes();
    let now_wall = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_nanos()).unwrap_or(i64::MAX))
        .unwrap_or(0);
    let now_boot = hemostat_lifecycle::watch::boot_ns().ok_or("cannot read CLOCK_BOOTTIME")?;
    let header = StoreHeader {
        format_ver: 1,
        suite_id: 1,
        engagement_id: id.engagement,
        host_id: id.host,
        agent_id: id.agent,
        created_wall_ns: now_wall,
        created_mono_ns: now_boot,
        variable_tail: encode_header_keys(&HeaderKeys { seal_pub: Some(seal_pub), store_pub: None, store_wrap: None }),
    };
    let writer = StoreWriter::create(dir, header).map_err(|e| e.to_string())?;

    crate::sealed::announce(writer.header());
    let genesis = writer.genesis();
    let signer: hemostat_evfmt::SealSigner = Box::new(move |b| seal.sign_footer(b));
    let mut c = writer
        .open_stream_clocked(
            StreamId::Custody,
            RunContext::new(id.instance, id.run, id.boot, 1),
            StreamCrypto { signer: Some(signer), cipher: None },
            Box::new(crate::evidence::BootClock::new(now_boot)),
        )
        .map_err(|e| e.to_string())?;
    let mut put = |p: Vec<u8>| c.append(RecType::CUSTODY, 0, &p).map_err(|e| e.to_string());
    put([b"s".as_slice(), salt].concat())?;
    put([b"v".as_slice(), snap.scope.to_string().as_bytes()].concat())?;
    for g in &snap.gaps {
        put([b"g".as_slice(), g.as_bytes()].concat())?;
    }
    for p in &suspect {
        put([b"x".as_slice(), p.as_bytes()].concat())?;
    }
    for (k, v) in &snap.items {
        put([b"i".as_slice(), k.as_bytes(), b"\0", v.as_bytes()].concat())?;
    }
    c.close().map_err(|e| e.to_string())?;
    Ok(Written { items: snap.items.len(), gaps: snap.gaps, suspect, seal_pub, genesis })
}

struct Stored {
    salt: [u8; 16],
    snap: Snapshot,
    suspect: Vec<String>,
    seal_pub: [u8; 32],
    pinned: bool,
}

fn read(dir: &str) -> Result<Stored, String> {
    use hemostat_evfmt::{load_verified, read_store_header};
    let header = read_store_header(dir).map_err(|e| format!("{dir}: {e}"))?;
    let seal_pub = hemostat_evcrypto::seal::decode_seal_pubkey(&header.variable_tail)
        .ok_or("the snapshot store carries no seal key")?;

    let pin = crate::identity::pinned_key(PIN_ENV)?;
    if let Some(p) = pin {
        if p != seal_pub {
            return Err(format!(
                "the snapshot is sealed with {} and ${PIN_ENV} pins {} — it was re-written, or this \
                 is not the snapshot you took",
                hex32(&seal_pub),
                hex32(&p)
            ));
        }
    }
    let check = move |s: &[u8], sig: &[u8]| hemostat_evcrypto::seal::verify_footer(&seal_pub, s, sig);

    let verified = load_verified(dir, &header, StreamId::Custody, Some(&check))
        .map_err(|e| format!("the snapshot does not verify: {e}"))?;
    let rep = &verified.report;

    if !(rep.sealed && rep.signed) {
        return Err(format!(
            "the snapshot is not sealed — `snapshot` always seals it, so it was cut short or its \
             seal was removed, and {} record(s) in it are vouched for by no key. Take a new one \
             with `hemostat snapshot --replace`",
            rep.unsealed_records
        ));
    }
    let segs = verified.segments;
    let (salt, snap, suspect) = decode(segs.iter().flat_map(|s| s.records.iter()).map(|r| r.stored.as_slice()))?;
    Ok(Stored { salt, snap, suspect, seal_pub, pinned: pin.is_some() })
}

fn decode<'a>(records: impl Iterator<Item = &'a [u8]>) -> Result<([u8; 16], Snapshot, Vec<String>), String> {
    let mut salt = None;

    let mut snap = Snapshot { scope: 1, ..Snapshot::default() };
    let mut suspect = Vec::new();
    for b in records {
        match b.split_first() {
            Some((b's', rest)) => salt = rest.try_into().ok(),
            Some((b'v', rest)) => {
                snap.scope = std::str::from_utf8(rest)
                    .ok()
                    .and_then(|v| v.parse().ok())
                    .ok_or("the snapshot's scope record is not a number")?;
            }
            Some((b'g', rest)) => snap.gaps.push(String::from_utf8_lossy(rest).into_owned()),
            Some((b'x', rest)) => suspect.push(String::from_utf8_lossy(rest).into_owned()),
            Some((b'i', rest)) => {
                let Some(nul) = rest.iter().position(|x| *x == 0) else {
                    return Err("a snapshot record has no key separator".into());
                };
                let (k, v) = rest.split_at(nul);
                snap.items.insert(
                    String::from_utf8_lossy(k).into_owned(),
                    String::from_utf8_lossy(v.get(1..).unwrap_or_default()).into_owned(),
                );
            }
            _ => return Err("a snapshot record of a kind this build does not know".into()),
        }
    }
    let salt = salt.ok_or("the snapshot has no salt record")?;
    Ok((salt, snap, suspect))
}

pub(crate) fn service_baseline(dir: &str) -> hemostat_sensor_linux::services::Baseline {
    use hemostat_sensor_linux::services::Baseline;
    if !Path::new(dir).exists() {
        return Baseline::Absent;
    }
    match read(dir) {
        Err(e) => Baseline::Refused(e),
        Ok(st) => Baseline::Snapshot {
            rows: st
                .snap
                .items
                .iter()
                .filter_map(|(k, v)| Some((k.strip_prefix("service/")?.to_string(), v.strip_prefix("sha256:")?.to_string())))
                .collect(),
            anchor: hex32(&st.seal_pub),
            pinned: st.pinned,
        },
    }
}

pub(crate) fn anchor_baseline(dir: &str) -> hemostat_sensor_linux::trust::Baseline {
    use hemostat_sensor_linux::trust::Baseline;
    if !Path::new(dir).exists() {
        return Baseline::None(format!("no arrival snapshot at {dir} (`hemostat snapshot` takes one)"));
    }
    match read(dir) {
        Err(e) => Baseline::None(format!("the arrival snapshot at {dir} was not read: {e}")),
        Ok(st) if st.snap.scope < 4 => Baseline::None(format!(
            "the arrival snapshot at {dir} was taken by an earlier build that did not record trust anchors              (`snapshot --replace` records them from now on)"
        )),
        Ok(st) => Baseline::Anchors(
            st.snap.items.keys().filter_map(|k| k.strip_prefix("anchor/")).map(str::to_string).collect(),
        ),
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
    let stored = match read(&dir) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("hemostat drift: DID NOT RUN — {}", h(&e));
            return EXIT_FAILED;
        }
    };
    let manifest = crate::vendor::load_manifest(None).ok().flatten();
    let (rows, svc_gaps) = service_rows();
    let mut now = snapshot::take(&stored.salt, &rows);
    now.gaps.extend(svc_gaps);

    let (changes, unscoped) = match snapshot::compare(&stored.snap, &now) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("hemostat drift: DID NOT RUN — {}", h(&e));
            return EXIT_FAILED;
        }
    };
    now.gaps.extend(unscoped);
    let mut findings: Vec<_> = changes
        .iter()
        .map(|c| {
            let mut f = snapshot::judge(c, &now);

            if let (Some(m), Some(path)) = (manifest.as_ref(), c.key.strip_prefix("service/")) {
                use hemostat_sensor_linux::vendor::{judge, Verdict};
                if c.after.is_some() && judge(m, Path::new(path)) == Verdict::Vendor {
                    f.severity = Severity::Note;
                    f.what = format!("updated to a version {} shipped", m.release);
                }
            }
            f
        })
        .collect();
    findings.sort_by(|a, b| b.severity.cmp(&a.severity));
    let gaps: Vec<&String> = stored.snap.gaps.iter().chain(now.gaps.iter()).collect();

    if json {
        let rows: Vec<String> = findings.iter().map(rootkit_row).collect();
        jprintln!(
            "{{\"store\":\"{}\",\"pinned\":{},\"changes\":{},\"gaps\":[{}],\"suspect\":[{}],\"findings\":[{}]}}",
            jesc(&dir),
            stored.pinned,
            findings.len(),
            gaps.iter().map(|g| format!("\"{}\"", jesc(g))).collect::<Vec<_>>().join(","),
            stored.suspect.iter().map(|g| format!("\"{}\"", jesc(g))).collect::<Vec<_>>().join(","),
            rows.join(",")
        );
    } else {
        println!("drift — what changed since the arrival snapshot ({})", h(&dir));
        if stored.pinned {
            println!("  snapshot seal key matches ${PIN_ENV}");
        } else {
            println!(
                "  NOTE: the snapshot's seal key ({}) is not pinned. Root on this host could have \
                 re-written the snapshot under a key of its own; set {PIN_ENV} to the key printed \
                 when it was taken",
                hex32(&stored.seal_pub)
            );
        }
        for f in &findings {
            println!("  [{}] {}", f.severity.tag(), h(&f.subject));
            for (i, line) in f.what.lines().enumerate() {
                println!("        {}{}", if i == 0 { "" } else { "  " }, h(line));
            }
            println!("        why: {}", h(&f.why));
        }
        if findings.is_empty() {
            println!("  nothing recorded on arrival has changed.");
        }
        for p in &stored.suspect {
            println!("  reminder: {} was not the vendor's file when the snapshot was taken", h(p));
        }
        for g in &gaps {
            println!("  NOT COMPARED: {}", h(g));
        }
    }
    if gaps.is_empty() {
        EXIT_OK
    } else {
        EXIT_PARTIAL
    }
}
