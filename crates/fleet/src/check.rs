use std::path::Path;

use hemostat_evfmt::{load_verified, read_store_header, RecType, StoreHeader, StreamId, VerifyReport};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreShape {

    Collect,

    SealedCustody,
}

impl StoreShape {

    pub fn name(self) -> &'static str {
        match self {
            StoreShape::Collect => "collect",
            StoreShape::SealedCustody => "sealed-custody",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Checked {

    pub header: StoreHeader,

    pub genesis: [u8; 32],

    pub seal_pub: [u8; 32],

    pub shape: StoreShape,

    pub streams: Vec<VerifyReport>,

    pub tips: Vec<(u8, u64, [u8; 32])>,
}

impl Checked {

    pub fn records(&self) -> u64 {
        self.streams.iter().map(|r| r.records).sum()
    }
}

const STREAMS: [(&str, StreamId); 4] = [
    ("evidence", StreamId::Evidence),
    ("custody", StreamId::Custody),
    ("telemetry", StreamId::Telemetry),
    ("journal", StreamId::Journal),
];

pub fn check_store(dir: &Path) -> Result<Checked, String> {
    let header = read_store_header(dir).map_err(|e| format!("the store header does not read: {e}"))?;
    let keys = hemostat_evcrypto::seal::decode_header_keys(&header.variable_tail);
    let Some(seal_pub) = keys.seal_pub else {
        return Err("the store carries no seal key, so nothing signs it (an unsigned store, or its key \
                    was stripped from the header)"
            .to_string());
    };
    let shape = if keys.store_pub.is_some() || keys.store_wrap.is_some() {
        StoreShape::Collect
    } else {
        StoreShape::SealedCustody
    };
    let check = move |signable: &[u8], sig: &[u8]| hemostat_evcrypto::seal::verify_footer(&seal_pub, signable, sig);

    let mut streams = Vec::new();
    let mut tips = Vec::new();
    let mut evidence_holds_custody = false;
    for (name, id) in STREAMS {
        let v = load_verified(dir, &header, id, Some(&check))
            .map_err(|e| format!("the {name} stream does not verify: {e}"))?;
        if v.report.segments == 0 {
            continue;
        }
        if !v.report.sealed || v.report.unsealed_records > 0 {
            return Err(format!(
                "the {name} stream is not sealed: {} record(s) after its last seal are vouched for by no \
                 key (a cut tail, or a store still being written; open segments never leave the host)",
                v.report.unsealed_records
            ));
        }
        if !v.report.signed {
            return Err(format!("the {name} stream's final seal carries no signature"));
        }
        if id == StreamId::Evidence {
            evidence_holds_custody = v
                .segments
                .iter()
                .flat_map(|s| s.records.iter())
                .any(|r| r.header.rec_type == RecType::CUSTODY);
        }
        let max_seq = v.segments.iter().flat_map(|s| s.records.iter()).map(|r| r.header.seq).max().unwrap_or(0);
        tips.push((id.to_u8(), max_seq, v.report.tip));
        streams.push(v.report);
    }
    tips.sort_by_key(|t| t.0);
    let has = |id: StreamId| streams.iter().any(|r| r.stream == id);
    if streams.is_empty() {
        return Err("the store has a header and no stream data".to_string());
    }
    match shape {
        StoreShape::Collect => {
            if !has(StreamId::Evidence) {
                return Err("the evidence stream is MISSING: every store `collect` writes has one, so this \
                            store has lost its evidence"
                    .to_string());
            }

            if !has(StreamId::Custody) && !evidence_holds_custody {
                return Err("the custody stream is MISSING: every store `collect` writes has one, and \
                            without it which sweeps ran cannot be shown"
                    .to_string());
            }
        }
        StoreShape::SealedCustody => {
            if !has(StreamId::Custody) {
                return Err("a store sealed with no store key has its records in the custody stream, and \
                            this one has none"
                    .to_string());
            }
        }
    }
    Ok(Checked { genesis: header.genesis(), header, seal_pub, shape, streams, tips })
}
