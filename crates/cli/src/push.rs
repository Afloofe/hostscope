use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use hemostat_evcrypto::receipt::{self, Receipt};
use hemostat_evfmt::{load_verified, read_store_header, RecType, StoreHeader, StreamId};

use crate::render::{h, hex32, jesc};
use crate::{EXIT_FAILED, EXIT_OK, EXIT_USAGE};

#[cfg(target_os = "linux")]
pub(crate) const CHECKPOINTS: &str = "/var/lib/hemostat/checkpoints";

#[cfg(target_os = "windows")]
pub(crate) const CHECKPOINTS: &str = r"C:\ProgramData\hemostat\checkpoints";

#[cfg(target_os = "windows")]
const WINDOWS_BASE: &str = r"C:\ProgramData\hemostat";

#[cfg(target_os = "windows")]
pub(crate) fn private_dir(dir: &str) -> Result<(), String> {
    let base = Path::new(WINDOWS_BASE);
    let d = Path::new(dir);
    if dir.eq_ignore_ascii_case(WINDOWS_BASE) || d.starts_with(base) {
        crate::win_private::ensure_dir(base)?;
        let mut at = base.to_path_buf();
        for part in d.strip_prefix(base).map_or_else(|_| Vec::new(), |rest| rest.components().collect()) {
            at.push(part);
            crate::win_private::ensure_dir(&at)?;
        }
        return Ok(());
    }
    std::fs::create_dir_all(d).map_err(|e| format!("cannot create {dir}: {e}"))
}

fn self_digest() -> Option<[u8; 32]> {
    use sha2::Digest as _;

    #[cfg(target_os = "linux")]
    let bytes = std::fs::read("/proc/self/exe").ok()?;
    #[cfg(target_os = "windows")]
    let bytes = {
        let mut b = Vec::new();
        std::io::Read::read_to_end(&mut std::fs::File::open(std::env::current_exe().ok()?).ok()?, &mut b).ok()?;
        b
    };
    Some(sha2::Sha256::digest(&bytes).into())
}

pub(crate) const CHECKPOINT_KIND: &str = "hemostat-checkpoint";

const RECEIPT_WAIT: Duration = Duration::from_secs(120);

pub(crate) type Tip = (u8, u64, [u8; 32]);

pub(crate) fn local_tips(dir: &str) -> Result<(StoreHeader, [u8; 32], Vec<Tip>), String> {
    let header = read_store_header(dir).map_err(|e| e.to_string())?;
    let seal_pub = hemostat_evcrypto::seal::decode_seal_pubkey(&header.variable_tail)
        .ok_or("the store carries no seal key, so nothing signs it")?;
    let check = move |s: &[u8], sig: &[u8]| hemostat_evcrypto::seal::verify_footer(&seal_pub, s, sig);
    let mut tips = Vec::new();
    for (name, id) in [
        ("evidence", StreamId::Evidence),
        ("telemetry", StreamId::Telemetry),
        ("journal", StreamId::Journal),
        ("custody", StreamId::Custody),
    ] {
        let v = load_verified(dir, &header, id, Some(&check)).map_err(|e| format!("the {name} stream does not verify: {e}"))?;
        if v.report.segments == 0 {
            continue;
        }
        if !(v.report.sealed && v.report.signed) || v.report.unsealed_records > 0 {
            return Err(format!(
                "the {name} stream is not sealed ({} record(s) after its last seal); open segments never leave \
                 the host — ship it once the verb that writes it has finished",
                v.report.unsealed_records
            ));
        }
        let max_seq = v.segments.iter().flat_map(|s| s.records.iter()).map(|r| r.header.seq).max().unwrap_or(0);
        tips.push((id.to_u8(), max_seq, v.report.tip));
    }
    if tips.is_empty() {
        return Err("the store has a header and no stream data".to_string());
    }
    tips.sort_by_key(|t| t.0);
    Ok((header, seal_pub, tips))
}

fn tips_of(r: &Receipt) -> Vec<Tip> {
    r.streams.iter().map(|s| (s.stream, s.max_seq, s.tip)).collect()
}

pub(crate) fn kept_receipts(dir: &Path, receipt_key: &[u8; 32]) -> Vec<Receipt> {
    let mut out = Vec::new();
    let Ok(rd) = std::fs::read_dir(dir) else { return out };
    for e in rd.flatten() {
        if !e.file_type().map(|t| t.is_dir()).unwrap_or(false) {
            continue;
        }
        let p = e.path();
        let Ok(header) = read_store_header(&p) else { continue };
        let Some(seal_pub) = hemostat_evcrypto::seal::decode_seal_pubkey(&header.variable_tail) else { continue };
        let check = move |s: &[u8], sig: &[u8]| hemostat_evcrypto::seal::verify_footer(&seal_pub, s, sig);
        let Ok(v) = load_verified(&p, &header, StreamId::Custody, Some(&check)) else { continue };
        for r in v.segments.iter().flat_map(|s| s.records.iter()) {
            if r.header.rec_type == RecType::CHECKPOINT {
                if let Ok(rc) = receipt::open(receipt_key, &r.stored) {
                    out.push(rc);
                }
            }
        }
    }
    out
}

fn keep_receipt(dir: &Path, wire: &[u8], r: &Receipt) -> Result<PathBuf, String> {
    use crate::identity::{gather_identity, rand16, rand32};
    #[cfg(target_os = "windows")]
    private_dir(dir.to_str().ok_or("the checkpoints path is not UTF-8")?)?;
    #[cfg(not(target_os = "windows"))]
    std::fs::DirBuilder::new()
        .recursive(true)
        .create(dir)
        .map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    let id = gather_identity().map_err(|e| format!("cannot establish this host's identity: {e}"))?;
    let entropy = |e: std::io::Error| format!("cannot read entropy: {e}");
    let (agent, instance) = (rand16().map_err(entropy)?, rand16().map_err(entropy)?);
    let (r4, seed) = (rand32().map_err(entropy)?, rand32().map_err(entropy)?);
    let [a, b, c, d, ..] = r4;
    let ids = crate::sealed::Ids {
        engagement: r.engagement_id,
        host: id.host,
        agent,
        instance,
        run: u32::from_le_bytes([a, b, c, d]),
        boot: id.boot,
    };
    let path = dir.join(format!("{}-{}", hex32(&r.genesis), r.received_ns.max(0)));
    let path_s = path.to_str().ok_or("the checkpoints path is not UTF-8")?.to_string();
    let kind = [b"k".as_slice(), CHECKPOINT_KIND.as_bytes()].concat();

    crate::sealed::seal_typed(&path_s, seed, [(RecType::CUSTODY, kind), (RecType::CHECKPOINT, wire.to_vec())], &ids, false)?;
    Ok(path)
}

pub(crate) fn announce_opened(header: &StoreHeader) -> Option<String> {
    let to = std::env::var("HEMOSTAT_COLLECTOR").ok().filter(|v| !v.is_empty())?;
    let g = hex32(&header.genesis());
    let Some(ck) = std::env::var("HEMOSTAT_COLLECTOR_KEY").ok().as_deref().map(str::trim).and_then(crate::identity::parse_hex32) else {
        return Some(format!(
            "hemostat: NOT ANNOUNCED — $HEMOSTAT_COLLECTOR is set and $HEMOSTAT_COLLECTOR_KEY is not the collector's 64-hex \
             link key; store {g} will be pinned first-seen"
        ));
    };
    let path = std::env::var("HEMOSTAT_LINK_KEY").map_or_else(|_| PathBuf::from(crate::LINK_KEY), PathBuf::from);
    let sent = (|| -> Result<(), String> {
        let (seed, _) = crate::load_or_create_link_key(&path)?;
        let agent = hemostat_remote::StaticSecret::from(seed);
        let eph = hemostat_remote::StaticSecret::from(crate::identity::rand32().map_err(|e| format!("no entropy: {e}"))?);
        hemostat_remote::link::announce(
            to.as_str(),
            &hemostat_remote::PublicKey::from(ck),
            &agent,
            &header.encode(),
            &eph,
            ANNOUNCE_TIMEOUT,
        )
        .map_err(|e| e.message())
    })();
    Some(match sent {
        Ok(()) => format!("hemostat: announced store {g} (seal key {}) to {}", seal_of(header), h(&to)),
        Err(why) => format!(
            "hemostat: NOT ANNOUNCED — store {g} to {}: {}. The collector will pin it first-seen",
            h(&to),
            h(&why)
        ),
    })
}

pub(crate) const ANNOUNCE_TIMEOUT: Duration = Duration::from_secs(3);

fn seal_of(h: &StoreHeader) -> String {
    hemostat_evcrypto::seal::decode_seal_pubkey(&h.variable_tail).map_or_else(|| "none".to_string(), |k| hex32(&k))
}

fn once<'a>(args: &'a [String], flag: &str) -> Result<Option<&'a str>, String> {
    let v = crate::fleet::flag_values(args, flag);
    match v.as_slice() {
        [] => Ok(None),
        [x] => Ok(Some(x)),
        _ => Err(format!("{flag} was given {} times; name one", v.len())),
    }
}

fn link_key_path(args: &[String]) -> Result<PathBuf, String> {
    Ok(PathBuf::from(
        once(args, "--link-key")?
            .map(str::to_string)
            .or_else(|| std::env::var("HEMOSTAT_LINK_KEY").ok())
            .unwrap_or_else(|| crate::LINK_KEY.to_string()),
    ))
}

pub(crate) fn identity(args: &[String], json: bool) -> u8 {
    let path = match link_key_path(args) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("hemostat ship: {}", h(&e));
            return EXIT_USAGE;
        }
    };
    let (seed, note) = match crate::load_or_create_link_key(&path) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("hemostat ship --identity: {}", h(&e));
            return EXIT_FAILED;
        }
    };
    let link = *hemostat_remote::PublicKey::from(&hemostat_remote::StaticSecret::from(seed)).as_bytes();
    let host = match crate::identity::gather_identity() {
        Ok(i) => i.host,
        Err(e) => {
            eprintln!("hemostat ship --identity: cannot establish this host's identity: {e}");
            return EXIT_FAILED;
        }
    };
    let digest = self_digest();
    if json {
        jprintln!(
            "{{\"link_public\":\"{}\",\"host\":\"{}\",\"self_digest\":{},\"link_key\":\"{}\",\"note\":{}}}",
            hex32(&link),
            hex32(&host),
            digest.map_or("null".to_string(), |d| format!("\"{}\"", hex32(&d))),
            jesc(&path.display().to_string()),
            note.as_deref().map_or("null".to_string(), |n| format!("\"{}\"", jesc(n)))
        );
    } else {
        println!("this agent, for `hemostat enroll` on the collector:\n");
        println!("  --host-id  {}", hex32(&host));
        println!("  --link-key {}   (from {})", hex32(&link), h(&path.display().to_string()));
        if let Some(d) = digest {
            println!(
                "\n  This binary hashes itself to {} — a claim, from the host. Enroll the digest you\n  \
                 checked off-box before you dropped it, not this one.",
                hex32(&d)
            );
        }
        if let Some(n) = note {
            println!("\n  NOTE: {}", h(&n));
        }
    }
    EXIT_OK
}

pub(crate) fn ship_to(args: &[String], stores: &[&str], json: bool) -> u8 {
    use crate::identity::parse_hex32;
    type Parsed = (String, [u8; 32], [u8; 32], PathBuf, PathBuf);
    let parsed = (|| -> Result<Parsed, String> {
        let to = once(args, "--to")?.ok_or("--to HOST:PORT")?.to_string();
        let ck = once(args, "--collector-key")?
            .ok_or("--collector-key <64 hex> is required: the collector's link key, pinned. \"Whoever answers on that port\" is not an identity")?;
        let ck = parse_hex32(ck).ok_or("--collector-key takes 64 hex")?;
        let rk = once(args, "--receipt-key")?
            .ok_or("--receipt-key <64 hex> is required: the collector's receipt key, which every receipt is checked against before it is read")?;
        let rk = parse_hex32(rk).ok_or("--receipt-key takes 64 hex")?;
        let cp = PathBuf::from(once(args, "--checkpoints")?.unwrap_or(CHECKPOINTS));
        Ok((to, ck, rk, link_key_path(args)?, cp))
    })();
    let (to, collector_key, receipt_key, link_path, checkpoints) = match parsed {
        Ok(p) => p,
        Err(why) => {
            eprintln!(
                "hemostat ship: {}\n\nusage: hemostat ship --to <HOST:PORT> --collector-key <HEX> --receipt-key <HEX> \
                 [--link-key <PATH>] [--checkpoints <DIR>] <STORE>...",
                h(&why)
            );
            return EXIT_USAGE;
        }
    };
    if stores.is_empty() {
        eprintln!("hemostat ship --to: name at least one store");
        return EXIT_USAGE;
    }
    let (seed, note) = match crate::load_or_create_link_key(&link_path) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("hemostat ship: {}", h(&e));
            return EXIT_FAILED;
        }
    };
    let agent = hemostat_remote::StaticSecret::from(seed);
    let agent_pub = *hemostat_remote::PublicKey::from(&agent).as_bytes();
    let collector = hemostat_remote::PublicKey::from(collector_key);
    if !json {
        println!("ship --to {} — this agent's link key {}", h(&to), hex32(&agent_pub));
        if let Some(n) = &note {
            println!("  NOTE: {}", h(n));
        }
    }
    let kept = kept_receipts(&checkpoints, &receipt_key);
    let mut code = EXIT_OK;
    let mut docs = Vec::new();
    for store in stores {
        let r = ship_one(store, &to, &collector, &agent, &receipt_key, &checkpoints, &kept);
        let (ok, doc, lines) = match r {
            Ok(Shipped::Skipped { genesis, received_ns }) => (
                true,
                format!("{{\"store\":\"{}\",\"ok\":true,\"skipped\":true,\"genesis\":\"{}\",\"receipt_ns\":{received_ns}}}", jesc(store), hex32(&genesis)),
                vec![format!(
                    "  SKIPPED {}: the collector's receipt (received_ns {received_ns}) already names every tip of it",
                    h(store)
                )],
            ),
            Ok(Shipped::Receipted { genesis, bytes, received_ns, checkpoint, matches, warn }) => {
                let mut lines = Vec::new();
                if let Some(w) = &warn {
                    lines.push(format!("  WARNING {}: {}", h(store), h(w)));
                }
                lines.push(format!("  PUSHED  {} ({bytes} bytes, genesis {})", h(store), hex32(&genesis)));
                lines.push(format!(
                    "          receipt verified under the pinned receipt key; collector received it at {received_ns} (its clock)"
                ));
                if !matches {
                    lines.push("          the receipt names tips other than the ones sent: the store will be sent again".to_string());
                }
                match &checkpoint {
                    Ok(p) => lines.push(format!("          CHECKPOINT kept in {}", h(&p.display().to_string()))),
                    Err(e) => lines.push(format!("          the receipt was NOT kept: {}", h(e))),
                }
                (
                    checkpoint.is_ok(),
                    format!(
                        "{{\"store\":\"{}\",\"ok\":{},\"genesis\":\"{}\",\"bytes\":{bytes},\"receipt_ns\":{received_ns},\"receipt_matches\":{matches},\
                         \"checkpoint\":{},\"warning\":{}}}",
                        jesc(store),
                        checkpoint.is_ok(),
                        hex32(&genesis),
                        checkpoint.as_ref().map_or("null".to_string(), |p| format!("\"{}\"", jesc(&p.display().to_string()))),
                        warn.as_deref().map_or("null".to_string(), |w| format!("\"{}\"", jesc(w)))
                    ),
                    lines,
                )
            }
            Err(why) => (
                false,
                format!("{{\"store\":\"{}\",\"ok\":false,\"error\":\"{}\"}}", jesc(store), jesc(&why)),
                vec![format!("  REFUSED {}: {}", h(store), h(&why))],
            ),
        };
        if !ok {
            code = EXIT_FAILED;
        }
        if json {
            docs.push(doc);
        } else {
            for l in lines {
                println!("{l}");
            }
        }
    }
    if json {
        jprintln!("{{\"to\":\"{}\",\"agent_link\":\"{}\",\"stores\":[{}]}}", jesc(&to), hex32(&agent_pub), docs.join(","));
    } else {
        println!("\nThe stores were copied, not moved: nothing on this host changed but the checkpoints directory.");
    }
    code
}

enum Shipped {
    Skipped {
        genesis: [u8; 32],
        received_ns: i64,
    },
    Receipted {
        genesis: [u8; 32],
        bytes: usize,
        received_ns: i64,
        checkpoint: Result<PathBuf, String>,
        matches: bool,
        warn: Option<String>,
    },
}

fn ship_one(
    store: &str,
    to: &str,
    collector: &hemostat_remote::PublicKey,
    agent: &hemostat_remote::StaticSecret,
    receipt_key: &[u8; 32],
    checkpoints: &Path,
    kept: &[Receipt],
) -> Result<Shipped, String> {
    let covering = |h: &StoreHeader| -> Vec<&Receipt> {
        let g = h.genesis();
        kept.iter().filter(|r| r.genesis == g && r.host_id == h.host_id && r.engagement_id == h.engagement_id).collect()
    };
    let (header, tips, warn) = match local_tips(store) {
        Ok((header, _, tips)) => {
            if let Some(r) = covering(&header).into_iter().find(|r| tips_of(r) == tips) {
                return Ok(Shipped::Skipped { genesis: header.genesis(), received_ns: r.received_ns });
            }
            (header, Some(tips), None)
        }
        Err(why) => {

            let header = read_store_header(store).map_err(|_| why.clone())?;
            if covering(&header).is_empty() {
                return Err(why);
            }
            let warn = format!(
                "this store no longer verifies ({why}), and the collector receipted it before. Pushing it so the \
                 collector, which holds the receipted copy, records what changed"
            );
            (header, None, Some(warn))
        }
    };
    let (parcel, _skipped) = hemostat_evfmt::Parcel::pack_dir(store).map_err(|e| format!("cannot pack it: {e}"))?;
    let bytes = parcel.encode();
    drop(parcel);
    use sha2::Digest as _;
    let digest: [u8; 32] = sha2::Sha256::digest(&bytes).into();
    let push_id = crate::identity::rand16().map_err(|e| format!("no entropy for a push id: {e}"))?;
    let mut fresh = || crate::identity::rand32().map(hemostat_remote::StaticSecret::from);
    let chunks = hemostat_remote::parcel_messages(push_id, digest, &bytes);
    let wire = match hemostat_remote::link::push(to, collector, agent, chunks, &mut fresh, Instant::now() + RECEIPT_WAIT) {
        Ok(w) => w,
        Err(hemostat_remote::link::LinkError::Closed) => {
            return Err(format!(
                "pushed ({} bytes), and the collector sent no receipt: it did not accept the store, or this agent is \
                 not enrolled. It sends nothing back to say which (RFC-003 §2.4); its ledger says",
                bytes.len()
            ))
        }
        Err(e) => return Err(e.message()),
    };

    let r = receipt::open(receipt_key, &wire).map_err(|e| format!("a reply came back and was refused: {e}"))?;
    let g = header.genesis();
    if r.genesis != g || r.host_id != header.host_id || r.engagement_id != header.engagement_id {
        return Err("the receipt verified and is for another store; it was not kept".to_string());
    }
    let matches = tips.as_ref().is_some_and(|t| tips_of(&r) == *t);
    let checkpoint = keep_receipt(checkpoints, &wire, &r);
    Ok(Shipped::Receipted { genesis: g, bytes: bytes.len(), received_ns: r.received_ns, checkpoint, matches, warn })
}
