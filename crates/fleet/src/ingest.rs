use std::fs::{self, File};
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};

use hemostat_evfmt::{read_store_header, Parcel, MAX_PARCEL_BYTES, PARCEL_EXT};
use sha2::{Digest, Sha256};

use crate::check::check_store;
use crate::enroll::Enrolled;
use crate::ledger::Ledger;
use crate::{hex, js, shown};

pub const PER_HOST_QUOTA: u64 = 2 * 1024 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct Layout {
    base: PathBuf,
}

impl Layout {

    pub fn new(root: &Path, engagement: &[u8; 16]) -> Layout {
        Layout { base: root.join(hex(engagement)) }
    }

    pub fn base(&self) -> &Path {
        &self.base
    }

    pub fn hosts(&self) -> PathBuf {
        self.base.join("hosts")
    }

    pub fn rejected(&self) -> PathBuf {
        self.base.join("rejected")
    }

    pub fn ledger(&self) -> PathBuf {
        self.base.join("ledger")
    }

    pub fn incoming(&self) -> PathBuf {
        self.base.join("spool").join("incoming")
    }

    pub fn receipts(&self) -> PathBuf {
        self.base.join("spool").join("receipts")
    }

    pub fn done(&self) -> PathBuf {
        self.base.join("spool").join("done")
    }

    pub fn enroll(&self) -> PathBuf {
        self.base.join("enroll")
    }

    pub fn keys(&self) -> PathBuf {
        self.base.join("keys")
    }

    pub fn pushes(&self) -> PathBuf {
        self.base.join("pushes")
    }

    pub fn announced(&self) -> PathBuf {
        self.base.join("announced")
    }

    pub fn heartbeats(&self) -> PathBuf {
        self.base.join("spool").join("heartbeats")
    }
    fn staging(&self) -> PathBuf {
        self.base.join("spool").join("staging")
    }

    pub fn lock(&self) -> Result<File, String> {
        for d in [
            self.hosts(),
            self.rejected(),
            self.incoming(),
            self.staging(),
            self.receipts(),
            self.done(),
            self.enroll(),
            self.pushes(),
            self.announced(),
            self.heartbeats(),
        ] {
            crate::shared_dir(&d).map_err(|e| format!("cannot create {}: {e}", d.display()))?;
        }
        let path = self.base.join("ingest.lock");
        let existed = fs::symlink_metadata(&path).is_ok();
        let f = fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&path)
            .map_err(|e| format!("cannot open {}: {e}", path.display()))?;
        if !existed {

            let _ = crate::set_mode(&path, 0o660);
        }
        match f.try_lock() {
            Ok(()) => Ok(f),
            Err(fs::TryLockError::WouldBlock) => {
                Err("another ingest holds this collector's lock; wait for it to finish".to_string())
            }
            Err(fs::TryLockError::Error(e)) => Err(format!("cannot lock {}: {e}", path.display())),
        }
    }
}

fn sync_dir(p: &Path) {
    if let Ok(f) = File::open(p) {
        let _ = f.sync_all();
    }
}

#[derive(Debug, Clone, Default)]
pub struct IngestConfig {

    pub engagement: [u8; 16],

    pub operator_pins: Vec<[u8; 32]>,

    pub enrolled: Option<Vec<Enrolled>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Alert {

    pub kind: &'static str,

    pub severity: &'static str,
}

pub const HISTORY_REWRITTEN: Alert = Alert { kind: "history-rewritten", severity: "critical" };

pub const SEAL_KEY_MISMATCH: Alert = Alert { kind: "seal-key-mismatch", severity: "critical" };

pub const UNKNOWN_AGENT: Alert = Alert { kind: "unknown-agent", severity: "warn" };

pub const UNANNOUNCED_STORE: Alert = Alert { kind: "unannounced-store", severity: "warn" };

pub const ANNOUNCED_STORE_MISSING: Alert = Alert { kind: "announced-store-missing", severity: "critical" };

impl Alert {

    pub fn to_json(&self, o: &Outcome) -> String {
        let opt = |v: Option<[u8; 32]>| v.map_or("null".to_string(), |b| format!("\"{}\"", hex(&b)));
        format!(
            "{{\"kind\":\"alert\",\"alert\":\"{}\",\"severity\":\"{}\",\"host\":{},\"genesis\":{},\
             \"parcel_sha256\":\"{}\",\"from\":{},\"at_ns\":{},\"why\":{}}}",
            self.kind,
            self.severity,
            opt(o.host),
            opt(o.genesis),
            hex(&o.sha256),
            o.from.as_deref().map_or("null".to_string(), js),
            o.received_ns,
            js(&o.reason),
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {

    Accepted,

    Rejected,

    AlreadyHeld,
}

impl Verdict {

    pub fn name(self) -> &'static str {
        match self {
            Verdict::Accepted => "accepted",
            Verdict::Rejected => "rejected",
            Verdict::AlreadyHeld => "already-held",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Outcome {

    pub name: String,

    pub sha256: [u8; 32],

    pub bytes: u64,

    pub received_ns: i64,

    pub verdict: Verdict,

    pub reason: String,

    pub host: Option<[u8; 32]>,

    pub genesis: Option<[u8; 32]>,

    pub seal: Option<[u8; 32]>,

    pub pin: Option<&'static str>,

    pub shape: Option<&'static str>,

    pub records: u64,

    pub kept: String,

    pub from: Option<String>,

    pub alert: Option<Alert>,
}

impl Outcome {

    pub fn to_json(&self) -> String {
        let opt = |v: Option<[u8; 32]>| v.map_or("null".to_string(), |b| format!("\"{}\"", hex(&b)));
        let opts = |v: Option<&str>| v.map_or("null".to_string(), js);

        format!(
            "{{\"kind\":\"ingest\",\"verdict\":\"{}\",\"parcel\":{},\"sha256\":\"{}\",\"bytes\":{},\
             \"received_ns\":{},\"host\":{},\"genesis\":{},\"seal\":{},\"pin\":{},\"shape\":{},\
             \"records\":{},\"kept\":{},\"from\":{},\"alert\":{},\"reason\":{}}}",
            self.verdict.name(),
            js(&self.name),
            hex(&self.sha256),
            self.bytes,
            self.received_ns,
            opt(self.host),
            opt(self.genesis),
            opt(self.seal),
            opts(self.pin),
            opts(self.shape),
            self.records,
            js(&self.kept),
            self.from.as_deref().map_or("null".to_string(), js),
            opts(self.alert.map(|a| a.kind)),
            js(&self.reason),
        )
    }
}

#[derive(Debug, Clone, Default)]
pub struct IngestReport {

    pub outcomes: Vec<Outcome>,

    pub ignored: Vec<String>,
}

pub fn ingest_dir(layout: &Layout, source: &Path, cfg: &IngestConfig, ledger: &mut Ledger) -> Result<IngestReport, String> {
    let mut report = IngestReport::default();
    let mut parcels: Vec<(String, PathBuf)> = Vec::new();
    let entries = fs::read_dir(source).map_err(|e| format!("cannot list {}: {e}", source.display()))?;
    for e in entries {
        let e = e.map_err(|e| format!("cannot list {}: {e}", source.display()))?;
        let name = e.file_name().to_string_lossy().into_owned();
        let is_parcel_name = Path::new(&name).extension().and_then(|x| x.to_str()) == Some(PARCEL_EXT);

        let regular = e.file_type().map(|t| t.is_file()).unwrap_or(false);
        if is_parcel_name && regular {
            parcels.push((name, e.path()));
        } else {
            report.ignored.push(shown(&name));
        }
    }
    parcels.sort();
    report.ignored.sort();
    if !report.ignored.is_empty() {
        let sample: Vec<String> = report.ignored.iter().take(20).map(|n| js(n)).collect();
        ledger.append(&format!(
            "{{\"kind\":\"ignored\",\"count\":{},\"names\":[{}],\"why\":\"not a regular file named *.{PARCEL_EXT}\"}}",
            report.ignored.len(),
            sample.join(",")
        ))?;
    }
    for (i, (name, path)) in parcels.iter().enumerate() {
        let tmp = layout.incoming().join(format!("{:010}-{i:06}.part", ledger.run()));
        let outcome = ingest_one(layout, &shown(name), path, &tmp, cfg, None)?;
        record(ledger, &outcome)?;
        report.outcomes.push(outcome);
    }
    Ok(report)
}

pub(crate) fn record(ledger: &mut Ledger, o: &Outcome) -> Result<(), String> {
    ledger.append(&o.to_json())?;
    if let Some(a) = o.alert {
        ledger.append(&a.to_json(o))?;
    }
    Ok(())
}

fn receive(src: &Path, tmp: &Path) -> std::io::Result<([u8; 32], u64, bool)> {
    let before = fs::symlink_metadata(src)?;
    if !before.file_type().is_file() {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "not a regular file"));
    }
    let f = File::open(src)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        let after = f.metadata()?;
        if (before.dev(), before.ino()) != (after.dev(), after.ino()) {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "the file changed while it was opened"));
        }
    }
    let mut o = fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        o.mode(0o600);
    }
    let mut out = o.open(tmp)?;
    let mut h = Sha256::new();
    let mut n: u64 = 0;
    let mut reader = f.take(MAX_PARCEL_BYTES + 1);
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let k = reader.read(&mut buf)?;
        if k == 0 {
            break;
        }
        let chunk = buf.get(..k).unwrap_or_default();
        h.update(chunk);
        out.write_all(chunk)?;
        n += k as u64;
    }
    out.sync_all()?;
    Ok((h.finalize().into(), n, n > MAX_PARCEL_BYTES))
}

pub(crate) fn ingest_one(
    layout: &Layout,
    name: &str,
    src: &Path,
    tmp: &Path,
    cfg: &IngestConfig,
    from: Option<&Enrolled>,
) -> Result<Outcome, String> {
    let received_ns = crate::now_ns();
    let mut o = Outcome {
        name: name.to_string(),
        sha256: [0; 32],
        bytes: 0,
        received_ns,
        verdict: Verdict::Rejected,
        reason: String::new(),
        host: None,
        genesis: None,
        seal: None,
        pin: None,
        shape: None,
        records: 0,
        kept: String::new(),
        from: from.map(|e| e.label.clone()),
        alert: None,
    };

    let _ = fs::remove_file(tmp);
    let (sha, len, over) = match receive(src, tmp) {
        Ok(r) => r,
        Err(e) => {

            let _ = fs::remove_file(tmp);
            o.reason = format!("could not be read off the media: {e}");
            o.kept = "(not received)".to_string();
            return Ok(o);
        }
    };
    o.sha256 = sha;
    o.bytes = len;

    let rej = layout.rejected().join(hex(&sha));
    if fs::symlink_metadata(&rej).is_ok() {
        let _ = fs::remove_file(tmp);
        let before = fs::read_to_string(rej.join("reason")).unwrap_or_default();
        o.verdict = Verdict::AlreadyHeld;
        o.reason = format!("this parcel was rejected before: {}", shown(before.lines().next().unwrap_or("")));
        o.kept = format!("rejected/{}", hex(&sha));
        return Ok(o);
    }

    if over {
        return reject(layout, tmp, o, format!("the parcel is over the {MAX_PARCEL_BYTES}-byte bound; only the first {MAX_PARCEL_BYTES} bytes and one more were copied"));
    }
    let bytes = fs::read(tmp).map_err(|e| format!("cannot read back the spooled copy: {e}"))?;
    let parcel = match Parcel::decode(&bytes) {
        Ok(p) => p,
        Err(e) => return reject(layout, tmp, o, e.to_string()),
    };
    drop(bytes);
    if let Some(h) = parcel.store_header() {
        o.host = Some(h.host_id);
        o.genesis = Some(h.genesis());
        o.seal = hemostat_evcrypto::seal::decode_seal_pubkey(&h.variable_tail);

        if let Some(list) = &cfg.enrolled {
            let why = match from {
                Some(agent) if agent.host != h.host_id => Some(format!(
                    "the parcel was pushed by the agent enrolled as {} (host {}), and the store header names \
                     host {}: an enrolled agent sending another host's store",
                    shown(&agent.label),
                    hex(&agent.host),
                    hex(&h.host_id)
                )),
                Some(_) => None,
                None if !list.iter().any(|e| e.host == h.host_id) => Some(format!(
                    "host {} is not enrolled on this collector; enrolling a host is a human step (`hemostat enroll`)",
                    hex(&h.host_id)
                )),
                None => None,
            };
            if let Some(why) = why {
                o.alert = Some(UNKNOWN_AGENT);
                return reject(layout, tmp, o, why);
            }
        }
    }

    if let Some(h) = parcel.store_header() {
        let g = h.genesis();
        let rel = format!("hosts/{}/{}", hex(&h.host_id), hex(&g));
        let dest = layout.hosts().join(hex(&h.host_id)).join(hex(&g));
        if fs::symlink_metadata(&dest).is_ok() {
            let held = Parcel::pack_dir(&dest).map_err(|e| format!("cannot read the held copy {rel}: {e}"))?.0;
            if let Some(differs) = not_extended(&held, &parcel) {
                o.alert = Some(HISTORY_REWRITTEN);
                return reject(
                    layout,
                    tmp,
                    o,
                    format!(
                        "history rewritten: the collector holds {rel}, verified and receipted, and this copy of the same \
                         store {differs} — what the collector holds was cut or rewritten on the host after it was sent"
                    ),
                );
            }
        }
    }

    let staging = layout.staging().join(hex(&sha));
    if fs::symlink_metadata(&staging).is_ok() {

        fs::remove_dir_all(&staging).map_err(|e| format!("cannot clear stale staging {}: {e}", staging.display()))?;
    }
    if let Err(e) = parcel.unpack_into(&staging) {
        let _ = fs::remove_dir_all(&staging);
        return reject(layout, tmp, o, format!("could not be unpacked: {e}"));
    }
    let checked = match check_store(&staging) {
        Ok(c) => c,
        Err(why) => {
            let _ = fs::remove_dir_all(&staging);
            return reject(layout, tmp, o, why);
        }
    };
    o.host = Some(checked.header.host_id);
    o.genesis = Some(checked.genesis);
    o.seal = Some(checked.seal_pub);
    o.shape = Some(checked.shape.name());
    o.records = checked.records();

    let refuse = |o: Outcome, why: String| {
        let _ = fs::remove_dir_all(&staging);
        reject(layout, tmp, o, why)
    };

    if checked.header.engagement_id != cfg.engagement {
        let why = format!(
            "the store is from engagement {}, and this collector serves {}",
            hex(&checked.header.engagement_id),
            hex(&cfg.engagement)
        );
        return refuse(o, why);
    }

    let (announced, same_run) =
        crate::announce::lookup(layout, &checked.header.host_id, &checked.header.agent_id, &checked.genesis);
    if announced.is_none() {
        if let Some(first) = same_run {
            let why = format!(
                "seal key mismatch: the agent announced this run's store (agent id {}) at {} by the collector's \
                 clock, sealed under {}; this store is sealed under {} — re-sealed after it was opened",
                hex(&checked.header.agent_id),
                first.at_ns,
                first.seal.map_or("no key".to_string(), |k| hex(&k)),
                hex(&checked.seal_pub)
            );
            o.alert = Some(SEAL_KEY_MISMATCH);
            return refuse(o, why);
        }
    }
    if let Some(a) = &announced {
        if a.seal != Some(checked.seal_pub) {
            let why = format!(
                "seal key mismatch: announced under {}, sealed under {}",
                a.seal.map_or("no key".to_string(), |k| hex(&k)),
                hex(&checked.seal_pub)
            );
            o.alert = Some(SEAL_KEY_MISMATCH);
            return refuse(o, why);
        }
    }
    let pin = if !cfg.operator_pins.is_empty() && !cfg.operator_pins.contains(&checked.seal_pub) {
        let why = format!(
            "seal key mismatch: the store is sealed under {}, which is not a key the operator pinned \
             (--seal-key) — it was re-sealed, or it is not the store that was taken",
            hex(&checked.seal_pub)
        );
        o.alert = Some(SEAL_KEY_MISMATCH);
        return refuse(o, why);
    } else if announced.is_some() {
        "announced"
    } else if !cfg.operator_pins.is_empty() {
        "operator"
    } else {
        "first-seen"
    };

    match held_from_same_run(layout, &checked.header.agent_id, &checked.genesis) {
        Ok(Some((path, held_seal))) => {
            o.alert = Some(SEAL_KEY_MISMATCH);
            let why = if held_seal != Some(checked.seal_pub) {
                format!(
                    "seal key mismatch: the collector already holds {path} from the same run (agent id {}), \
                     sealed under {}; this copy is sealed under {} — re-sealed under a new key",
                    hex(&checked.header.agent_id),
                    held_seal.map_or("no key".to_string(), |k| hex(&k)),
                    hex(&checked.seal_pub)
                )
            } else {
                format!(
                    "the collector already holds {path} from the same run (agent id {}) under another genesis — \
                     its header was rewritten",
                    hex(&checked.header.agent_id)
                )
            };
            return refuse(o, why);
        }
        Ok(None) => {}
        Err(e) => {
            let _ = fs::remove_dir_all(&staging);
            let _ = fs::remove_file(tmp);
            return Err(e);
        }
    }

    let host_dir = layout.hosts().join(hex(&checked.header.host_id));
    let rel = format!("hosts/{}/{}", hex(&checked.header.host_id), hex(&checked.genesis));
    let dest = host_dir.join(hex(&checked.genesis));
    if fs::symlink_metadata(&dest).is_ok() {

        let held = Parcel::pack_dir(&dest).map_err(|e| format!("cannot read the held copy {rel}: {e}"))?.0;
        let _ = fs::remove_dir_all(&staging);
        if held == parcel {
            let _ = fs::remove_file(tmp);
            o.verdict = Verdict::AlreadyHeld;
            o.reason = format!("the collector already holds this store, byte for byte, at {rel}");
            o.pin = Some(pin);
            o.kept = rel;
            return Ok(o);
        }

        let added: Vec<&hemostat_evfmt::ParcelFile> =
            parcel.files.iter().filter(|f| !held.files.iter().any(|x| x.path == f.path)).collect();
        let more: u64 = added.iter().map(|f| f.bytes.len() as u64).sum();
        let used = du(&host_dir);
        if used.saturating_add(more) > PER_HOST_QUOTA {
            let why = format!("per-host quota: the collector holds {used} bytes from this host and this extension is {more} more");
            return reject(layout, tmp, o, why);
        }
        for f in &added {
            let to = dest.join(&f.path);
            if let Some(dir) = to.parent() {
                crate::shared_dir(dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
            }
            let part = to.with_extension("part");
            let _ = fs::remove_file(&part);
            let mut oo = fs::OpenOptions::new();
            oo.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt as _;
                oo.mode(0o600);
            }
            let mut w = oo.open(&part).map_err(|e| format!("cannot extend {rel}: {e}"))?;
            w.write_all(&f.bytes).and_then(|()| w.sync_all()).map_err(|e| format!("cannot extend {rel}: {e}"))?;
            fs::rename(&part, &to).map_err(|e| format!("cannot extend {rel}: {e}"))?;
            if let Some(dir) = to.parent() {
                sync_dir(dir);
            }
        }
        let _ = fs::remove_file(tmp);
        crate::share_finished(&dest);
        o.verdict = Verdict::Accepted;
        o.reason = format!("extends the held copy by {} file(s), {more} bytes", added.len());
        o.pin = Some(pin);
        o.kept = rel;
        return Ok(o);
    }

    let used = du(&host_dir);
    if used.saturating_add(parcel.body_len()) > PER_HOST_QUOTA {
        let why = format!(
            "per-host quota: the collector holds {used} bytes from this host and the store is {} more, over {PER_HOST_QUOTA}",
            parcel.body_len()
        );
        return refuse(o, why);
    }

    if pin == "first-seen" {
        if let Some((alert, why)) = unannounced(layout, &checked.header.host_id, &checked.genesis, from) {
            o.alert = Some(alert);
            o.reason = why;
        }
    }

    crate::shared_dir(&host_dir).map_err(|e| format!("cannot create {}: {e}", host_dir.display()))?;
    fs::rename(&staging, &dest).map_err(|e| format!("cannot move the verified store into {rel}: {e}"))?;
    crate::share_finished(&dest);
    sync_dir(&host_dir);
    let _ = fs::remove_file(tmp);
    o.verdict = Verdict::Accepted;
    o.pin = Some(pin);
    o.kept = rel;
    Ok(o)
}

fn reject(layout: &Layout, tmp: &Path, mut o: Outcome, why: String) -> Result<Outcome, String> {
    let dir = layout.rejected().join(hex(&o.sha256));
    crate::shared_dir(&dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    let parcel = dir.join("parcel");
    if fs::symlink_metadata(&parcel).is_err() {
        fs::rename(tmp, &parcel).map_err(|e| format!("cannot keep the rejected parcel at {}: {e}", parcel.display()))?;
    } else {
        let _ = fs::remove_file(tmp);
    }
    let text = format!("{why}\nparcel {}\nreceived_ns {}\n", o.name, o.received_ns);
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(dir.join("reason"))
        .or_else(|_| fs::OpenOptions::new().append(true).open(dir.join("reason")))
        .map_err(|e| format!("cannot write the reason for {}: {e}", dir.display()))?;
    f.write_all(text.as_bytes()).and_then(|()| f.sync_all()).map_err(|e| format!("cannot write the reason: {e}"))?;

    let _ = crate::set_mode(&parcel, 0o640);
    let _ = crate::set_mode(&dir.join("reason"), 0o660);
    sync_dir(&dir);
    o.verdict = Verdict::Rejected;
    o.reason = why;
    o.kept = format!("rejected/{}", hex(&o.sha256));
    Ok(o)
}

fn unannounced(layout: &Layout, host: &[u8; 32], genesis: &[u8; 32], from: Option<&Enrolled>) -> Option<(Alert, String)> {
    let missing = crate::announce::outstanding(layout, host, genesis);
    if !missing.is_empty() {
        let named: Vec<String> = missing
            .iter()
            .take(4)
            .map(|a| {
                format!(
                    "{} (run {}, sealed under {}, announced at {} by the collector's clock)",
                    hex(&a.genesis),
                    hex(&a.agent_id),
                    a.seal.map_or("no key".to_string(), |k| hex(&k)),
                    a.at_ns
                )
            })
            .collect();
        return Some((
            ANNOUNCED_STORE_MISSING,
            format!(
                "store {} was never announced, and host {} announced {} store(s) the collector has never \
                 received: {}{}. A store re-sealed under a fresh run id and key, with the announced one \
                 withheld, looks exactly like this; it is kept, pinned first-seen, so nothing here bounds \
                 when it was sealed",
                hex(genesis),
                hex(host),
                missing.len(),
                named.join("; "),
                if missing.len() > named.len() { "; …" } else { "" }
            ),
        ));
    }
    from.map(|agent| {
        (
            UNANNOUNCED_STORE,
            format!(
                "store {} was pushed by the agent enrolled as {}, and its run never announced it: it is \
                 kept, pinned first-seen, so nothing here bounds when it was sealed. A collector that was \
                 down when the store was opened leaves this; so does a store re-sealed under a fresh run id",
                hex(genesis),
                shown(&agent.label)
            ),
        )
    })
}

type HeldRun = (String, Option<[u8; 32]>);

fn held_from_same_run(layout: &Layout, agent: &[u8; 16], genesis: &[u8; 32]) -> Result<Option<HeldRun>, String> {
    let hosts = layout.hosts();
    let list = |p: &Path| -> Result<Vec<(String, PathBuf)>, String> {
        let mut v = Vec::new();
        for e in fs::read_dir(p).map_err(|e| format!("cannot list {}: {e}", p.display()))? {
            let e = e.map_err(|e| format!("cannot list {}: {e}", p.display()))?;
            v.push((e.file_name().to_string_lossy().into_owned(), e.path()));
        }
        Ok(v)
    };
    for (host, hp) in list(&hosts)? {
        for (g, gp) in list(&hp)? {
            if g == hex(genesis) {
                continue;
            }
            let Ok(h) = read_store_header(&gp) else { continue };
            if &h.agent_id == agent {
                let seal = hemostat_evcrypto::seal::decode_seal_pubkey(&h.variable_tail);
                return Ok(Some((format!("hosts/{host}/{g}"), seal)));
            }
        }
    }
    Ok(None)
}

fn not_extended(held: &Parcel, new: &Parcel) -> Option<String> {
    for f in &held.files {
        match new.files.iter().find(|n| n.path == f.path) {
            None => return Some(format!("lacks {}, which the collector holds", f.path)),
            Some(n) if n.bytes == f.bytes => {}
            Some(n) if n.bytes.len() < f.bytes.len() && f.bytes.starts_with(&n.bytes) => {
                return Some(format!("has {} cut from {} to {} bytes", f.path, f.bytes.len(), n.bytes.len()))
            }
            Some(n) => {
                let at = f.bytes.iter().zip(&n.bytes).position(|(a, b)| a != b).unwrap_or(f.bytes.len().min(n.bytes.len()));
                return Some(format!("differs in {} from byte {at}", f.path));
            }
        }
    }
    None
}

fn du(p: &Path) -> u64 {
    let Ok(m) = fs::symlink_metadata(p) else { return 0 };
    if m.is_file() {
        return m.len();
    }
    if !m.is_dir() {
        return 0;
    }
    fs::read_dir(p).map_or(0, |rd| rd.flatten().map(|e| du(&e.path())).sum())
}
