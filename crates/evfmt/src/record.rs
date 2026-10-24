use crate::header::{RecordHeader, HEADER_LEN};
use crate::{FormatError, Result};
use sha2::{Digest, Sha256};

pub const MAX_RECORD_BYTES: usize = 4 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {

    pub header: RecordHeader,

    pub stored: Vec<u8>,

    pub tag: Vec<u8>,
}

pub fn record_hash(header_bytes: &[u8], stored: &[u8], tag: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(header_bytes);
    h.update(stored);
    h.update(tag);
    h.finalize().into()
}

pub fn crc32c(data: &[u8]) -> u32 {
    const POLY: u32 = 0x82F6_3B78;
    let mut crc = !0u32;
    for &b in data {
        crc ^= u32::from(b);
        for _ in 0..8 {
            crc = if crc & 1 != 0 { (crc >> 1) ^ POLY } else { crc >> 1 };
        }
    }
    !crc
}

pub fn encode_record(rec: &Record) -> Result<Vec<u8>> {
    rec.header.validate()?;

    let expected_tag = rec.header.aead_alg.tag_len();
    if rec.tag.len() != expected_tag {
        return Err(FormatError::BadField {
            field: "tag_len",
            value: rec.tag.len() as u64,
        });
    }
    if rec.stored.len() != rec.header.payload_stored_len as usize {
        return Err(FormatError::BadField {
            field: "payload_stored_len",
            value: rec.header.payload_stored_len as u64,
        });
    }

    let body_len = HEADER_LEN as usize + rec.stored.len() + rec.tag.len();
    if body_len > MAX_RECORD_BYTES {
        return Err(FormatError::TooLarge { len: body_len });
    }

    let mut out = Vec::with_capacity(4 + body_len + 4);
    out.extend_from_slice(&(body_len as u32).to_le_bytes());
    out.extend_from_slice(&rec.header.encode());
    out.extend_from_slice(&rec.stored);
    out.extend_from_slice(&rec.tag);
    let crc = crc32c(out.get(4..).unwrap_or_default());
    out.extend_from_slice(&crc.to_le_bytes());
    Ok(out)
}

pub fn decode_record(buf: &[u8]) -> Result<(Record, usize)> {
    if buf.len() < 4 {
        return Err(FormatError::Truncated {
            what: "record length prefix",
            need: 4,
            have: buf.len(),
        });
    }
    let body_len = u32::from_le_bytes(take4(buf, 0)?) as usize;
    if body_len > MAX_RECORD_BYTES {
        return Err(FormatError::TooLarge { len: body_len });
    }
    let total = 4 + body_len + 4;
    if buf.len() < total {
        return Err(FormatError::Truncated {
            what: "record body",
            need: total,
            have: buf.len(),
        });
    }

    let body = buf.get(4..4 + body_len).ok_or(FormatError::Truncated {
        what: "record body",
        need: total,
        have: buf.len(),
    })?;
    let stored_crc = u32::from_le_bytes(take4(buf, 4 + body_len)?);
    let computed = crc32c(body);
    if computed != stored_crc {
        return Err(FormatError::BadCrc {
            stored: stored_crc,
            computed,
        });
    }

    let header = RecordHeader::decode(body)?;
    header.validate()?;

    if body.get(..HEADER_LEN as usize) != Some(header.encode().as_slice()) {
        return Err(FormatError::NotCanonical { what: "record header" });
    }

    let tag_len = header.aead_alg.tag_len();
    let stored_len = header.payload_stored_len as usize;
    if body_len != HEADER_LEN as usize + stored_len + tag_len {
        return Err(FormatError::BadField {
            field: "payload_stored_len",
            value: stored_len as u64,
        });
    }

    let stored_start = HEADER_LEN as usize;
    let tag_start = stored_start + stored_len;

    let stored = body
        .get(stored_start..tag_start)
        .ok_or(FormatError::Truncated {
            what: "record payload",
            need: tag_start,
            have: body.len(),
        })?
        .to_vec();
    let tag = body
        .get(tag_start..)
        .ok_or(FormatError::Truncated {
            what: "record tag",
            need: tag_start,
            have: body.len(),
        })?
        .to_vec();
    Ok((Record { header, stored, tag }, total))
}

fn take4(b: &[u8], off: usize) -> Result<[u8; 4]> {
    b.get(off..off.saturating_add(4))
        .and_then(|s| <[u8; 4]>::try_from(s).ok())
        .ok_or(FormatError::Truncated {
            what: "record length prefix",
            need: off.saturating_add(4),
            have: b.len(),
        })
}

pub fn verify_chain(records: &[Record], first_prev: [u8; 32]) -> Result<[u8; 32]> {
    let mut expected = first_prev;
    for rec in records {
        if rec.header.prev_hash != expected {
            return Err(FormatError::ChainBroken {
                seq: rec.header.seq,
            });
        }
        expected = record_hash(&rec.header.encode(), &rec.stored, &rec.tag);
    }
    Ok(expected)
}
