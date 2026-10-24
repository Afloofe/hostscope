use std::path::Path;

use hemostat_evcrypto::envelope::{aead_open, open_dek, unwrap_store_key_for_read};
use hemostat_evcrypto::secret::Secret32;
use hemostat_evfmt::{load_verified, read_store_header, RecType, Segment, StreamId};
use sha2::{Digest, Sha256};

use crate::check::StoreShape;
use crate::json;
use crate::queue::Sev;

#[derive(Debug, Clone)]
pub struct HeldFinding {

    pub seq: u64,

    pub digest: [u8; 32],

    pub source: String,

    pub severity: Sev,

    pub severity_raw: String,

    pub subject: String,

    pub locus: String,

    pub what: String,

    pub why: String,

    pub files: Vec<FileDigest>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileDigest {

    pub path: String,

    pub sha256: String,

    pub vouched: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeldGap {

    pub source: String,

    pub reason: String,

    pub partial: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Readable {

    Yes,

    NotACollection,

    No(String),
}

#[derive(Debug, Clone)]
pub struct HeldStore {

    pub genesis: [u8; 32],

    pub host: [u8; 32],

    pub created_wall_ns: i64,

    pub seal: [u8; 32],

    pub shape: StoreShape,

    pub findings: Vec<HeldFinding>,

    pub gaps: Vec<HeldGap>,

    pub readable: Readable,

    pub variant: String,

    pub version: String,

    pub unparsed: Vec<u64>,

    pub records: Vec<Vec<u8>>,
}

pub fn parse_sev(tag: &str) -> Sev {
    match tag {
        "CRITICAL" | "critical" => Sev::Critical,
        "WARN" | "warn" => Sev::Warn,
        "note" | "NOTE" => Sev::Note,
        "info" | "INFO" => Sev::Info,
        _ => Sev::Warn,
    }
}

fn custody_into(text: &str, out: &mut HeldStore) {
    let Ok(v) = json::parse(text) else { return };
    match v.str_of("event") {
        "sweep-did-not-run" | "sweep-ran-in-part" => out.gaps.push(HeldGap {
            source: v.str_of("source").to_string(),
            reason: v.str_of("reason").to_string(),
            partial: v.str_of("event") == "sweep-ran-in-part",
        }),
        "evidence-shed" => out.gaps.push(HeldGap {
            source: "*".to_string(),
            reason: v.str_of("reason").to_string(),
            partial: false,
        }),
        "collection-start" => {
            out.variant = v.str_of("variant").to_string();
            out.version = v.str_of("version").to_string();
        }
        _ => {}
    }
}

fn finding_from(seq: u64, pt: &[u8]) -> Option<HeldFinding> {
    let text = std::str::from_utf8(pt).ok()?;
    let v = json::parse(text).ok()?;
    let source = v.str_of("source");
    if source.is_empty() {
        return None;
    }
    let raw = v.str_of("severity").to_string();
    Some(HeldFinding {
        seq,
        digest: Sha256::digest(pt).into(),
        source: source.to_string(),
        severity: parse_sev(&raw),
        severity_raw: raw,
        subject: v.str_of("subject").to_string(),
        locus: v.str_of("locus").to_string(),
        what: v.str_of("what").to_string(),
        why: v.str_of("why").to_string(),
        files: files_of(&v),
    })
}

fn files_of(v: &json::Value) -> Vec<FileDigest> {
    let Some(json::Value::Array(items)) = v.get("files") else { return Vec::new() };
    items
        .iter()
        .filter_map(|f| {
            let sha = f.str_of("sha256").to_ascii_lowercase();
            let path = f.str_of("path");
            (sha.len() == 64 && sha.bytes().all(|b| b.is_ascii_hexdigit()) && path.starts_with('/')).then(|| FileDigest {
                path: path.to_string(),
                sha256: sha,
                vouched: Some(f.str_of("vouched")).filter(|p| !p.is_empty()).map(str::to_string),
            })
        })
        .take(16)
        .collect()
}

pub fn read_held(dir: &Path, read_key: Option<&Secret32>) -> Result<HeldStore, String> {
    let checked = crate::check::check_store(dir)?;
    let header = read_store_header(dir).map_err(|e| format!("the store header does not read: {e}"))?;
    if header.genesis() != checked.genesis {
        return Err("the store header changed between two reads".to_string());
    }
    let seal = checked.seal_pub;
    let check = move |s: &[u8], sig: &[u8]| hemostat_evcrypto::seal::verify_footer(&seal, s, sig);
    let mut out = HeldStore {
        genesis: checked.genesis,
        host: header.host_id,
        created_wall_ns: header.created_wall_ns,
        seal,
        shape: checked.shape,
        findings: Vec::new(),
        gaps: Vec::new(),
        readable: Readable::NotACollection,
        variant: String::new(),
        version: String::new(),
        unparsed: Vec::new(),
        records: Vec::new(),
    };

    let sealed = |name: &str, v: &hemostat_evfmt::VerifiedStream| -> Result<(), String> {
        let r = &v.report;
        if r.segments > 0 && (!r.sealed || !r.signed || r.unsealed_records > 0) {
            return Err(format!("the {name} stream is no longer sealed"));
        }
        Ok(())
    };
    let custody = load_verified(dir, &header, StreamId::Custody, Some(&check))
        .map_err(|e| format!("the custody stream does not verify: {e}"))?;
    sealed("custody", &custody)?;
    for seg in &custody.segments {
        for r in &seg.records {
            if r.header.rec_type == RecType::CUSTODY && !r.header.is_encrypted() {
                custody_into(&String::from_utf8_lossy(&r.stored), &mut out);
            }
        }
    }
    if checked.shape != StoreShape::Collect {
        out.records = custody.segments.into_iter().flat_map(|s| s.records.into_iter().map(|r| r.stored)).collect();
        return Ok(out);
    }
    let evidence = load_verified(dir, &header, StreamId::Evidence, Some(&check))
        .map_err(|e| format!("the evidence stream does not verify: {e}"))?;
    sealed("evidence", &evidence)?;
    let Some(wrap) = hemostat_evcrypto::seal::decode_read_wrap(&header.variable_tail) else {
        out.readable = Readable::No(
            "the store key is not wrapped to the engagement read key: `collect` ran without \
             $HEMOSTAT_READ_PUBKEY, so only the offline recovery key reads its findings"
                .to_string(),
        );
        return Ok(out);
    };
    let Some(rk) = read_key else {
        out.readable = Readable::No(
            "this collector holds no read key (`collector read-key` makes it), so the findings cannot be read"
                .to_string(),
        );
        return Ok(out);
    };
    let Ok(store_secret) = unwrap_store_key_for_read(rk, &wrap) else {
        out.readable = Readable::No(
            "the store key is wrapped to a read key, and not to the one this collector holds".to_string(),
        );
        return Ok(out);
    };
    decrypt_into(&evidence.segments, &store_secret, &mut out)?;
    out.readable = Readable::Yes;
    Ok(out)
}

fn decrypt_into(segments: &[Segment], store_secret: &Secret32, out: &mut HeldStore) -> Result<(), String> {
    for seg in segments {
        let dek = open_dek(store_secret, &seg.header.variable_tail)
            .map_err(|_| format!("the key for evidence segment {} does not open", seg.header.segment_seq))?;
        for r in &seg.records {
            if !r.header.is_encrypted() {

                return Err(format!(
                    "evidence record {} is not encrypted in a store that encrypts every finding; `collect` \
                     did not write it",
                    r.header.seq
                ));
            }
            let pt = aead_open(&dek, &r.header.nonce, &r.header.encode(), &r.stored, &r.tag)
                .map_err(|_| format!("evidence record {} does not decrypt", r.header.seq))?;
            if r.header.rec_type == RecType::CUSTODY {

                custody_into(&String::from_utf8_lossy(&pt), out);
            } else if r.header.rec_type == RecType::DETECTION {
                match finding_from(r.header.seq, &pt) {
                    Some(f) => out.findings.push(f),
                    None => out.unparsed.push(r.header.seq),
                }
            }
        }
    }
    Ok(())
}
