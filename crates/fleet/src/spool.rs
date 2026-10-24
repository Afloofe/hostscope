use std::fs;
use std::io::{Read as _, Write as _};
use std::path::Path;

use hemostat_evcrypto::receipt::{Receipt, ReceiptKey, ReceiptStream};

use crate::check::check_store;
use crate::enroll::Enrolled;
use crate::announce::Recorded;
use crate::ingest::{ingest_one, record, IngestConfig, Layout, Outcome, Verdict, SEAL_KEY_MISMATCH, UNKNOWN_AGENT};
use crate::ledger::Ledger;
use crate::{hex, js, shown};

#[derive(Debug, Clone)]
pub struct Item {

    pub conn: String,

    pub kind: String,

    pub outcome: Option<Outcome>,

    pub receipted: bool,

    pub line: String,
}

#[derive(Debug, Clone, Default)]
pub struct Report {

    pub items: Vec<Item>,

    pub in_flight: usize,
}

pub fn pending(layout: &Layout) -> Result<(Vec<String>, usize), String> {
    let inc = layout.incoming();
    let mut ready = Vec::new();
    let mut in_flight = 0;
    let rd = match fs::read_dir(&inc) {
        Ok(rd) => rd,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok((ready, 0)),
        Err(e) => return Err(format!("cannot list {}: {e}", inc.display())),
    };
    for e in rd {
        let e = e.map_err(|e| format!("cannot list {}: {e}", inc.display()))?;

        if !e.file_type().map(|t| t.is_dir()).unwrap_or(false) {
            continue;
        }
        let name = e.file_name().to_string_lossy().into_owned();
        if name.ends_with(".part") {
            in_flight += 1;
            continue;
        }
        let base = name.strip_suffix(".failed").unwrap_or(&name);
        if !valid_conn(base) {
            continue;
        }
        if fs::symlink_metadata(layout.done().join(&name)).is_ok() {
            continue;
        }
        ready.push(name);
    }
    ready.sort();
    Ok((ready, in_flight))
}

fn valid_conn(s: &str) -> bool {
    !s.is_empty() && s.len() <= 40 && s.bytes().all(|b| b.is_ascii_digit() || b == b'-')
}

fn meta(dir: &Path) -> Result<Vec<(String, String)>, String> {
    let mut text = String::new();
    fs::File::open(dir.join("meta"))
        .and_then(|f| f.take(64 * 1024).read_to_string(&mut text))
        .map_err(|e| format!("the connection's meta does not read: {e}"))?;
    Ok(text
        .lines()
        .filter_map(|l| l.split_once('='))
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect())
}

fn get<'a>(m: &'a [(String, String)], k: &str) -> &'a str {
    m.iter().find(|(key, _)| key == k).map_or("", |(_, v)| v.as_str())
}

fn parse16(s: &str) -> Option<[u8; 16]> {
    let mut out = [0u8; 16];
    if s.len() != 32 {
        return None;
    }
    for (i, o) in out.iter_mut().enumerate() {
        *o = u8::from_str_radix(s.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let tmp = path.with_extension("tmp");
    let _ = fs::remove_file(&tmp);
    let mut o = fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        o.mode(0o600);
    }
    let mut f = o.open(&tmp).map_err(|e| format!("cannot create {}: {e}", tmp.display()))?;
    f.write_all(bytes).and_then(|()| f.sync_all()).map_err(|e| format!("cannot write {}: {e}", tmp.display()))?;
    fs::rename(&tmp, path).map_err(|e| format!("cannot put {} in place: {e}", path.display()))?;
    if let Some(d) = path.parent().and_then(|p| fs::File::open(p).ok()) {
        let _ = d.sync_all();
    }
    Ok(())
}

fn sign_receipt(layout: &Layout, kept: &str, cfg: &IngestConfig, received_ns: i64, key: &ReceiptKey) -> Result<Vec<u8>, String> {
    let held = check_store(&layout.base().join(kept)).map_err(|e| format!("the held store {kept} does not verify: {e}"))?;
    let r = Receipt {
        engagement_id: cfg.engagement,
        host_id: held.header.host_id,
        genesis: held.genesis,
        received_ns,
        streams: held.tips.iter().map(|&(stream, max_seq, tip)| ReceiptStream { stream, max_seq, tip }).collect(),
    };
    key.sign(&r).ok_or_else(|| "the held store is not a shape a receipt can name".to_string())
}

pub fn ingest_spool(layout: &Layout, cfg: &IngestConfig, receipt_key: &ReceiptKey, ledger: &mut Ledger) -> Result<Report, String> {
    let (ready, in_flight) = pending(layout)?;
    let mut report = Report { items: Vec::new(), in_flight };
    let enrolled: &[Enrolled] = cfg.enrolled.as_deref().unwrap_or_default();
    for (i, name) in ready.iter().enumerate() {
        let dir = layout.incoming().join(name);
        let failed = name.ends_with(".failed");
        let conn = name.strip_suffix(".failed").unwrap_or(name).to_string();
        let m = match meta(&dir) {
            Ok(m) => m,
            Err(why) => {
                ledger.append(&format!("{{\"kind\":\"wire-refused\",\"conn\":{},\"why\":{}}}", js(&conn), js(&why)))?;
                mark_done(layout, name, &why)?;
                report.items.push(Item { conn, kind: "refused".into(), outcome: None, receipted: false, line: why });
                continue;
            }
        };
        let source = get(&m, "source").to_string();
        let at = get(&m, "received_ns").parse::<i64>().unwrap_or(0);
        let why = get(&m, "reason").to_string();
        let kind = if failed { "incomplete" } else { get(&m, "kind") }.to_string();
        let common = format!("\"conn\":{},\"source\":{},\"at_ns\":{at}", js(&conn), js(&shown(&source)));
        let agent = parse32(get(&m, "agent")).and_then(|k| enrolled.iter().find(|e| e.link == Some(k)));
        let mut item = Item { conn: conn.clone(), kind: kind.clone(), outcome: None, receipted: false, line: String::new() };
        match kind.as_str() {
            "unknown-agent" => {
                ledger.append(&format!(
                    "{{\"kind\":\"alert\",\"alert\":\"{}\",\"severity\":\"{}\",{common},\"why\":{}}}",
                    UNKNOWN_AGENT.kind,
                    UNKNOWN_AGENT.severity,
                    js(&why)
                ))?;
                item.line = format!("UNKNOWN AGENT from {}: {}", shown(&source), shown(&why));
            }
            "announce" => {
                let Some(agent) = agent else {
                    let why = "the agent key that opened this announcement is no longer enrolled".to_string();
                    ledger.append(&format!("{{\"kind\":\"wire-refused\",{common},\"why\":{}}}", js(&why)))?;
                    item.line = why.clone();
                    mark_done(layout, name, &why)?;
                    report.items.push(item);
                    continue;
                };
                let mut header = Vec::new();
                let read = fs::File::open(dir.join("announce"))
                    .and_then(|f| f.take(hemostat_remote::MAX_ANNOUNCE as u64 + 1).read_to_end(&mut header));
                let rec = match read {
                    Ok(_) => crate::announce::record(layout, &cfg.engagement, &header, agent, at)?,
                    Err(e) => Recorded::Refused(format!("the spooled announcement does not read: {e}")),
                };
                let fields = |a: &crate::announce::Announced| {
                    format!(
                        "\"genesis\":\"{}\",\"seal\":{},\"agent_id\":\"{}\"",
                        hex(&a.genesis),
                        a.seal.map_or("null".to_string(), |k| format!("\"{}\"", hex(&k))),
                        hex(&a.agent_id)
                    )
                };
                let from = js(&agent.label);
                match &rec {
                    Recorded::Pinned(a) | Recorded::Repeat(a) | Recorded::Late(a) => {
                        let grade = match rec {
                            Recorded::Pinned(_) => "pinned",
                            Recorded::Repeat(_) => "repeat",
                            _ => "late",
                        };
                        ledger.append(&format!(
                            "{{\"kind\":\"announce\",\"pin\":\"{grade}\",{common},\"agent\":{from},\"host\":\"{}\",{}}}",
                            hex(&agent.host),
                            fields(a)
                        ))?;
                        item.line = match grade {
                            "pinned" => format!(
                                "store {} announced, seal key {} pinned",
                                hex(&a.genesis),
                                a.seal.map_or("none".to_string(), |k| hex(&k))
                            ),
                            "repeat" => format!("store {} announced again; the first announcement stands", hex(&a.genesis)),
                            _ => format!(
                                "store {} announced after the collector already held it; it pins nothing",
                                hex(&a.genesis)
                            ),
                        };
                    }
                    Recorded::OtherKey { this, first } => {
                        let why = format!(
                            "a second store of one run announced under another key: run {} announced store {} sealed \
                             under {} at {}, and now store {} sealed under {} — a store re-sealed after it was opened",
                            hex(&this.agent_id),
                            hex(&first.genesis),
                            first.seal.map_or("none".to_string(), |k| hex(&k)),
                            first.at_ns,
                            hex(&this.genesis),
                            this.seal.map_or("none".to_string(), |k| hex(&k))
                        );
                        ledger.append(&format!(
                            "{{\"kind\":\"announce\",\"pin\":\"refused\",{common},\"agent\":{from},\"host\":\"{}\",{}}}",
                            hex(&agent.host),
                            fields(this)
                        ))?;
                        ledger.append(&format!(
                            "{{\"kind\":\"alert\",\"alert\":\"{}\",\"severity\":\"{}\",{common},\"host\":\"{}\",\"genesis\":\"{}\",\"from\":{from},\"why\":{}}}",
                            SEAL_KEY_MISMATCH.kind,
                            SEAL_KEY_MISMATCH.severity,
                            hex(&agent.host),
                            hex(&this.genesis),
                            js(&why)
                        ))?;
                        item.line = format!("SEAL KEY MISMATCH: {why}");
                    }
                    Recorded::Refused(why) => {
                        ledger.append(&format!(
                            "{{\"kind\":\"wire-refused\",{common},\"what\":\"announce\",\"agent\":{from},\"why\":{}}}",
                            js(why)
                        ))?;
                        item.line = format!("announcement refused: {}", shown(why));
                    }
                }
            }
            "incomplete" => {
                ledger.append(&format!(
                    "{{\"kind\":\"push-incomplete\",{common},\"agent\":{},\"push\":{},\"why\":{}}}",
                    agent.map_or("null".to_string(), |a| js(&a.label)),
                    js(get(&m, "push")),
                    js(&why)
                ))?;
                item.line = format!("incomplete push from {}, nothing ingested: {}", shown(&source), shown(&why));
            }
            "parcel" => {
                let Some(agent) = agent else {
                    let why = "the agent key that opened this push is no longer enrolled".to_string();
                    ledger.append(&format!("{{\"kind\":\"wire-refused\",{common},\"why\":{}}}", js(&why)))?;
                    item.line = why.clone();
                    mark_done(layout, name, &why)?;
                    report.items.push(item);
                    continue;
                };
                let push = get(&m, "push").to_string();
                let Some(push_id) = parse16(&push) else {
                    let why = "the connection names no push id".to_string();
                    ledger.append(&format!("{{\"kind\":\"wire-refused\",{common},\"why\":{}}}", js(&why)))?;
                    mark_done(layout, name, &why)?;
                    item.line = why;
                    report.items.push(item);
                    continue;
                };
                let seen = layout.pushes().join(hex(&push_id));
                match fs::read_to_string(&seen) {
                    Ok(first) if first.trim() != conn => {

                        ledger.append(&format!(
                            "{{\"kind\":\"replay\",{common},\"agent\":{},\"push\":{},\"first_conn\":{}}}",
                            js(&agent.label),
                            js(&push),
                            js(&shown(first.trim()))
                        ))?;
                        item.kind = "replay".into();
                        item.line = format!(
                            "REPLAY of push {push} from {} (first seen as connection {}): nothing changed, no receipt",
                            shown(&source),
                            shown(first.trim())
                        );
                        mark_done(layout, name, "replay")?;
                        report.items.push(item);
                        continue;
                    }
                    Ok(_) => {}
                    Err(_) => write_atomic(&seen, format!("{conn}\n").as_bytes())?,
                }
                let tmp = layout.incoming().join(format!("{:010}-w{i:06}.part", ledger.run()));
                let o = ingest_one(layout, &format!("push {conn}"), &dir.join("parcel"), &tmp, cfg, Some(agent))?;
                record(ledger, &o)?;
                item.line = format!("{} {}", o.verdict.name(), if o.reason.is_empty() { &o.kept } else { &o.reason });
                if matches!(o.verdict, Verdict::Accepted | Verdict::AlreadyHeld) && o.kept.starts_with("hosts/") {
                    match sign_receipt(layout, &o.kept, cfg, o.received_ns, receipt_key) {
                        Ok(signed) => {
                            use sha2::Digest as _;
                            let rsha: [u8; 32] = sha2::Sha256::digest(&signed).into();
                            ledger.append(&format!(
                                "{{\"kind\":\"receipt\",{common},\"agent\":{},\"host\":{},\"genesis\":{},\"received_ns\":{},\"receipt_sha256\":\"{}\"}}",
                                js(&agent.label),
                                o.host.map_or("null".to_string(), |h| format!("\"{}\"", hex(&h))),
                                o.genesis.map_or("null".to_string(), |g| format!("\"{}\"", hex(&g))),
                                o.received_ns,
                                hex(&rsha)
                            ))?;
                            write_atomic(&layout.receipts().join(&conn), &signed)?;
                            item.receipted = true;
                        }
                        Err(why) => {
                            ledger.append(&format!("{{\"kind\":\"receipt-failed\",{common},\"why\":{}}}", js(&why)))?;
                        }
                    }
                }
                item.outcome = Some(o);
            }
            other => {

                ledger.append(&format!(
                    "{{\"kind\":\"wire-refused\",{common},\"what\":{},\"why\":{}}}",
                    js(&shown(other)),
                    js(&why)
                ))?;
                item.line = format!("refused connection from {}: {}", shown(&source), shown(&why));
            }
        }
        mark_done(layout, name, &item.line)?;
        report.items.push(item);
    }
    Ok(report)
}

fn parse32(s: &str) -> Option<[u8; 32]> {
    let mut out = [0u8; 32];
    if s.len() != 64 {
        return None;
    }
    for (i, o) in out.iter_mut().enumerate() {
        *o = u8::from_str_radix(s.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

fn mark_done(layout: &Layout, name: &str, line: &str) -> Result<(), String> {
    let conn = name.strip_suffix(".failed").unwrap_or(name);
    write_atomic(&layout.done().join(conn), format!("{}\n", shown(line)).as_bytes())?;
    if conn != name {

        write_atomic(&layout.done().join(name), b"incomplete\n")?;
    }
    Ok(())
}
