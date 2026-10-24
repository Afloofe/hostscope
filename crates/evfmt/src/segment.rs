use crate::record::{record_hash, Record};
use crate::{FormatError, Result};
use sha2::{Digest, Sha256};

pub const SEGMENT_MAGIC: [u8; 4] = *b"HCS1";

pub const SEGMENT_HEADER_PREFIX_LEN: usize = 172;

const _: () = {
    let sum: usize = 4
        + 2
        + 2
        + 1
        + 3
        + 4
        + 8
        + 8
        + 8
        + 16
        + 16
        + 16
        + 16
        + 32
        + 32
        + 4;
    assert!(
        sum == SEGMENT_HEADER_PREFIX_LEN,
        "SEGMENT_HEADER_PREFIX_LEN disagrees with the sum of the field widths"
    );
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum StreamId {

    Evidence,

    Telemetry,

    Journal,

    Custody,
}

impl StreamId {

    pub const fn to_u8(self) -> u8 {
        match self {
            StreamId::Evidence => 1,
            StreamId::Telemetry => 2,
            StreamId::Journal => 3,
            StreamId::Custody => 4,
        }
    }

    pub const fn from_u8(v: u8) -> Result<Self> {
        match v {
            1 => Ok(StreamId::Evidence),
            2 => Ok(StreamId::Telemetry),
            3 => Ok(StreamId::Journal),
            4 => Ok(StreamId::Custody),
            other => Err(FormatError::BadField {
                field: "stream_id",
                value: other as u64,
            }),
        }
    }

    pub const fn is_encrypted(self) -> bool {
        matches!(self, StreamId::Evidence | StreamId::Telemetry)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SegmentHeader {

    pub format_ver: u16,

    pub suite_id: u16,

    pub stream_id: StreamId,

    pub segment_seq: u64,

    pub engagement_id: [u8; 16],

    pub agent_id: [u8; 16],

    pub instance_id: [u8; 16],

    pub run_id: u32,

    pub store_header_hash: [u8; 32],

    pub prev_segment_tail_hash: [u8; 32],

    pub created_wall_ns: i64,

    pub created_mono_ns: u64,

    pub boot_id: [u8; 16],

    pub variable_tail: Vec<u8>,
}

impl SegmentHeader {

    #[allow(clippy::indexing_slicing)]
    pub fn encode(&self) -> Vec<u8> {
        let mut p = [0u8; SEGMENT_HEADER_PREFIX_LEN];
        p[0..4].copy_from_slice(&SEGMENT_MAGIC);
        p[4..6].copy_from_slice(&self.format_ver.to_le_bytes());
        p[6..8].copy_from_slice(&self.suite_id.to_le_bytes());
        p[8] = self.stream_id.to_u8();

        p[12..16].copy_from_slice(&self.run_id.to_le_bytes());
        p[16..24].copy_from_slice(&self.segment_seq.to_le_bytes());
        p[24..32].copy_from_slice(&self.created_wall_ns.to_le_bytes());
        p[32..40].copy_from_slice(&self.created_mono_ns.to_le_bytes());
        p[40..56].copy_from_slice(&self.engagement_id);
        p[56..72].copy_from_slice(&self.agent_id);
        p[72..88].copy_from_slice(&self.instance_id);
        p[88..104].copy_from_slice(&self.boot_id);
        p[104..136].copy_from_slice(&self.store_header_hash);
        p[136..168].copy_from_slice(&self.prev_segment_tail_hash);
        p[168..172].copy_from_slice(&(self.variable_tail.len() as u32).to_le_bytes());

        let mut out = Vec::with_capacity(SEGMENT_HEADER_PREFIX_LEN + self.variable_tail.len());
        out.extend_from_slice(&p);
        out.extend_from_slice(&self.variable_tail);
        out
    }

    pub fn decode(b: &[u8]) -> Result<(Self, usize)> {
        let magic = take::<4>(b, 0)?;
        if magic != SEGMENT_MAGIC {
            return Err(FormatError::BadField {
                field: "segment magic",
                value: u32::from_le_bytes(magic) as u64,
            });
        }
        let tail_len = u32::from_le_bytes(take::<4>(b, 168)?) as usize;
        let total = SEGMENT_HEADER_PREFIX_LEN
            .checked_add(tail_len)
            .ok_or(FormatError::TooLarge { len: tail_len })?;
        let tail = b
            .get(SEGMENT_HEADER_PREFIX_LEN..total)
            .ok_or(FormatError::Truncated {
                what: "segment header variable tail",
                need: total,
                have: b.len(),
            })?;

        Ok((
            SegmentHeader {
                format_ver: u16::from_le_bytes(take::<2>(b, 4)?),
                suite_id: u16::from_le_bytes(take::<2>(b, 6)?),
                stream_id: StreamId::from_u8(byte(b, 8)?)?,
                run_id: u32::from_le_bytes(take::<4>(b, 12)?),
                segment_seq: u64::from_le_bytes(take::<8>(b, 16)?),
                created_wall_ns: i64::from_le_bytes(take::<8>(b, 24)?),
                created_mono_ns: u64::from_le_bytes(take::<8>(b, 32)?),
                engagement_id: take::<16>(b, 40)?,
                agent_id: take::<16>(b, 56)?,
                instance_id: take::<16>(b, 72)?,
                boot_id: take::<16>(b, 88)?,
                store_header_hash: take::<32>(b, 104)?,
                prev_segment_tail_hash: take::<32>(b, 136)?,
                variable_tail: tail.to_vec(),
            },
            total,
        ))
    }

    pub fn hash(&self) -> [u8; 32] {
        Sha256::digest(self.encode()).into()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealPayload {

    pub segment_seq: u64,

    pub record_count: u64,

    pub tip_hash: [u8; 32],

    pub header_hash: [u8; 32],

    pub next_header_hash: Option<[u8; 32]>,

    pub ts_sealed_wall: i64,

    pub ts_sealed_mono: u64,

    pub boot_id: [u8; 16],

    pub suite_id: u16,

    pub sealed_late: bool,

    pub signature: Vec<u8>,
}

pub const FOOTER_MAGIC: [u8; 4] = *b"HCF1";

pub const SEAL_SIGNABLE_LEN: usize = 152;

pub const SEAL_FIXED_LEN: usize = SEAL_SIGNABLE_LEN + 2;

impl SealPayload {

    pub fn signable_bytes(&self) -> [u8; SEAL_SIGNABLE_LEN] {
        let mut p = [0u8; SEAL_SIGNABLE_LEN];
        p[0..4].copy_from_slice(&FOOTER_MAGIC);
        p[4..12].copy_from_slice(&self.segment_seq.to_le_bytes());
        p[12..20].copy_from_slice(&self.record_count.to_le_bytes());
        p[20..52].copy_from_slice(&self.tip_hash);
        p[52..84].copy_from_slice(&self.header_hash);
        if let Some(h) = self.next_header_hash {
            p[84] = 1;
            p[85..117].copy_from_slice(&h);
        }
        p[117..125].copy_from_slice(&self.ts_sealed_wall.to_le_bytes());
        p[125..133].copy_from_slice(&self.ts_sealed_mono.to_le_bytes());
        p[133..149].copy_from_slice(&self.boot_id);
        p[149..151].copy_from_slice(&self.suite_id.to_le_bytes());
        p[151] = u8::from(self.sealed_late);
        p
    }

    pub fn encode(&self) -> Vec<u8> {
        let signable = self.signable_bytes();
        let sig_len = u16::try_from(self.signature.len()).unwrap_or(u16::MAX);
        let mut out = Vec::with_capacity(SEAL_FIXED_LEN + self.signature.len());
        out.extend_from_slice(&signable);
        out.extend_from_slice(&sig_len.to_le_bytes());
        out.extend_from_slice(&self.signature);
        out
    }

    pub fn decode(b: &[u8]) -> Result<(Self, usize)> {
        let magic = take_in::<4>(FOOTER_FIELD, b, 0)?;
        if magic != FOOTER_MAGIC {
            return Err(FormatError::BadField {
                field: "footer magic",
                value: u32::from_le_bytes(magic) as u64,
            });
        }
        let next_present = byte_in(FOOTER_FIELD, b, 84)?;
        let next_header_hash = match next_present {
            0 => None,
            1 => Some(take_in::<32>(FOOTER_FIELD, b, 85)?),
            other => {
                return Err(FormatError::BadField {
                    field: "next_present",
                    value: other as u64,
                })
            }
        };
        let sealed_late = match byte_in(FOOTER_FIELD, b, 151)? {
            0 => false,
            1 => true,
            other => {
                return Err(FormatError::BadField {
                    field: "sealed_late",
                    value: other as u64,
                })
            }
        };
        let sig_len = u16::from_le_bytes(take_in::<2>(FOOTER_FIELD, b, SEAL_SIGNABLE_LEN)?) as usize;
        let total = SEAL_FIXED_LEN
            .checked_add(sig_len)
            .ok_or(FormatError::TooLarge { len: sig_len })?;
        let signature = b
            .get(SEAL_FIXED_LEN..total)
            .ok_or(FormatError::Truncated {
                what: "segment footer signature",
                need: total,
                have: b.len(),
            })?
            .to_vec();
        Ok((
            SealPayload {
                segment_seq: u64::from_le_bytes(take_in::<8>(FOOTER_FIELD, b, 4)?),
                record_count: u64::from_le_bytes(take_in::<8>(FOOTER_FIELD, b, 12)?),
                tip_hash: take_in::<32>(FOOTER_FIELD, b, 20)?,
                header_hash: take_in::<32>(FOOTER_FIELD, b, 52)?,
                next_header_hash,
                ts_sealed_wall: i64::from_le_bytes(take_in::<8>(FOOTER_FIELD, b, 117)?),
                ts_sealed_mono: u64::from_le_bytes(take_in::<8>(FOOTER_FIELD, b, 125)?),
                boot_id: take_in::<16>(FOOTER_FIELD, b, 133)?,
                suite_id: u16::from_le_bytes(take_in::<2>(FOOTER_FIELD, b, 149)?),
                sealed_late,
                signature,
            },
            total,
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Segment {

    pub header: SegmentHeader,

    pub records: Vec<Record>,

    pub footer: Option<SealPayload>,
}

impl Segment {

    pub fn verify_records(&self) -> Result<[u8; 32]> {
        let mut expected = self.header.hash();
        for rec in &self.records {
            if rec.header.prev_hash != expected {
                return Err(FormatError::ChainBroken {
                    seq: rec.header.seq,
                });
            }
            expected = record_hash(&rec.header.encode(), &rec.stored, &rec.tag);
        }
        Ok(expected)
    }

    pub fn verify(&self) -> Result<[u8; 32]> {
        let tip = self.verify_records()?;
        if let Some(f) = &self.footer {
            if f.header_hash != self.header.hash() {
                return Err(FormatError::SealMismatch {
                    segment_seq: f.segment_seq,
                    what: "header_hash",
                });
            }
            if f.tip_hash != tip {
                return Err(FormatError::SealMismatch {
                    segment_seq: f.segment_seq,
                    what: "tip_hash",
                });
            }
            if f.record_count != self.records.len() as u64 {
                return Err(FormatError::SealMismatch {
                    segment_seq: f.segment_seq,
                    what: "record_count",
                });
            }
            if f.segment_seq != self.header.segment_seq {
                return Err(FormatError::SealMismatch {
                    segment_seq: f.segment_seq,
                    what: "segment_seq",
                });
            }
        }
        Ok(tip)
    }
}

pub fn verify_stream(segments: &[Segment], genesis: [u8; 32]) -> Result<[u8; 32]> {
    verify_stream_inner(segments, genesis, None)
}

pub fn verify_stream_signed(
    segments: &[Segment],
    genesis: [u8; 32],
    verify_seal: &crate::SealVerify,
) -> Result<[u8; 32]> {
    verify_stream_inner(segments, genesis, Some(verify_seal))
}

fn verify_stream_inner(
    segments: &[Segment],
    genesis: [u8; 32],
    verify_seal: Option<&crate::SealVerify>,
) -> Result<[u8; 32]> {
    let mut expected_prev_tail = genesis;
    let mut tip = genesis;

    for (i, seg) in segments.iter().enumerate() {

        if seg.header.prev_segment_tail_hash != expected_prev_tail {
            return Err(FormatError::SegmentDiscontinuity {
                segment_seq: seg.header.segment_seq,
                what: "prev_segment_tail_hash",
            });
        }

        if seg.header.segment_seq != i as u64 {
            return Err(FormatError::SegmentDiscontinuity {
                segment_seq: seg.header.segment_seq,
                what: "segment_seq is not consecutive",
            });
        }

        tip = seg.verify()?;
        expected_prev_tail = tip;

        if let Some(f) = &seg.footer {

            if let Some(verify) = verify_seal {
                if f.signature.is_empty() {
                    return Err(FormatError::SealSignatureInvalid {
                        segment_seq: f.segment_seq,
                        detail: "the seal carries no signature but a seal key was provided",
                    });
                }
                if !verify(&f.signable_bytes(), &f.signature) {
                    return Err(FormatError::SealSignatureInvalid {
                        segment_seq: f.segment_seq,
                        detail: "the signature does not verify against the store's seal key",
                    });
                }
            }
            match (f.next_header_hash, segments.get(i + 1)) {
                (Some(committed), Some(next)) => {
                    if committed != next.header.hash() {
                        return Err(FormatError::ForwardCommitmentBroken {
                            segment_seq: seg.header.segment_seq,
                            detail: "the next segment is not the one this seal committed to \
                                     (it was replaced)",
                        });
                    }
                }
                (Some(_), None) => {
                    return Err(FormatError::ForwardCommitmentBroken {
                        segment_seq: seg.header.segment_seq,
                        detail: "seal commits to a following segment that is not present \
                                 (segments after it were deleted)",
                    });
                }

                (None, None) => {}
                (None, Some(_)) => {
                    return Err(FormatError::ForwardCommitmentBroken {
                        segment_seq: seg.header.segment_seq,
                        detail: "a following segment exists but the seal commits to none \
                                 (a segment was added after the final seal)",
                    });
                }
            }
        } else if i + 1 != segments.len() {

            let rotate_crash = i + 2 == segments.len()
                && segments.get(i + 1).is_some_and(|last| {
                    last.footer.is_none()
                        && last.records.is_empty()
                        && last.header.prev_segment_tail_hash == tip
                });
            if !rotate_crash {
                return Err(FormatError::SegmentDiscontinuity {
                    segment_seq: seg.header.segment_seq,
                    what: "an unsealed segment is followed by another",
                });
            }
        }
    }
    Ok(tip)
}

const FOOTER_FIELD: &str = "segment footer field";

fn take<const N: usize>(b: &[u8], off: usize) -> Result<[u8; N]> {
    take_in("SegmentHeader field", b, off)
}

fn take_in<const N: usize>(what: &'static str, b: &[u8], off: usize) -> Result<[u8; N]> {
    b.get(off..off.saturating_add(N))
        .and_then(|s| <[u8; N]>::try_from(s).ok())
        .ok_or(FormatError::Truncated {
            what,
            need: off.saturating_add(N),
            have: b.len(),
        })
}

fn byte(b: &[u8], off: usize) -> Result<u8> {
    byte_in("SegmentHeader field", b, off)
}

fn byte_in(what: &'static str, b: &[u8], off: usize) -> Result<u8> {
    b.get(off).copied().ok_or(FormatError::Truncated {
        what,
        need: off.saturating_add(1),
        have: b.len(),
    })
}
