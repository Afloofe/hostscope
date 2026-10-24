use crate::{FormatError, Result};
use sha2::{Digest, Sha256};

pub const STORE_MAGIC: [u8; 4] = *b"HSTR";

pub const STORE_HEADER_PREFIX_LEN: usize = 96;

const _: () = {
    let sum: usize = 4
        + 2
        + 2
        + 16
        + 32
        + 16
        + 8
        + 8
        + 4
        + 4;
    assert!(
        sum == STORE_HEADER_PREFIX_LEN,
        "STORE_HEADER_PREFIX_LEN disagrees with the sum of the field widths"
    );
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreHeader {

    pub format_ver: u16,

    pub suite_id: u16,

    pub engagement_id: [u8; 16],

    pub host_id: [u8; 32],

    pub agent_id: [u8; 16],

    pub created_wall_ns: i64,

    pub created_mono_ns: u64,

    pub variable_tail: Vec<u8>,
}

impl StoreHeader {

    #[allow(clippy::indexing_slicing)]
    pub fn encode(&self) -> Vec<u8> {
        let mut p = [0u8; STORE_HEADER_PREFIX_LEN];
        p[0..4].copy_from_slice(&STORE_MAGIC);
        p[4..6].copy_from_slice(&self.format_ver.to_le_bytes());
        p[6..8].copy_from_slice(&self.suite_id.to_le_bytes());
        p[8..24].copy_from_slice(&self.engagement_id);
        p[24..56].copy_from_slice(&self.host_id);
        p[56..72].copy_from_slice(&self.agent_id);
        p[72..80].copy_from_slice(&self.created_wall_ns.to_le_bytes());
        p[80..88].copy_from_slice(&self.created_mono_ns.to_le_bytes());
        p[88..92].copy_from_slice(&(self.variable_tail.len() as u32).to_le_bytes());

        let mut out = Vec::with_capacity(STORE_HEADER_PREFIX_LEN + self.variable_tail.len());
        out.extend_from_slice(&p);
        out.extend_from_slice(&self.variable_tail);
        out
    }

    pub fn decode(b: &[u8]) -> Result<(Self, usize)> {
        let magic = take::<4>(b, 0)?;
        if magic != STORE_MAGIC {
            return Err(FormatError::BadField {
                field: "store magic",
                value: u32::from_le_bytes(magic) as u64,
            });
        }
        let tail_len = u32::from_le_bytes(take::<4>(b, 88)?) as usize;
        let total = STORE_HEADER_PREFIX_LEN
            .checked_add(tail_len)
            .ok_or(FormatError::TooLarge { len: tail_len })?;
        let tail = b
            .get(STORE_HEADER_PREFIX_LEN..total)
            .ok_or(FormatError::Truncated {
                what: "store header variable tail",
                need: total,
                have: b.len(),
            })?;

        Ok((
            StoreHeader {
                format_ver: u16::from_le_bytes(take::<2>(b, 4)?),
                suite_id: u16::from_le_bytes(take::<2>(b, 6)?),
                engagement_id: take::<16>(b, 8)?,
                host_id: take::<32>(b, 24)?,
                agent_id: take::<16>(b, 56)?,
                created_wall_ns: i64::from_le_bytes(take::<8>(b, 72)?),
                created_mono_ns: u64::from_le_bytes(take::<8>(b, 80)?),
                variable_tail: tail.to_vec(),
            },
            total,
        ))
    }

    pub fn genesis(&self) -> [u8; 32] {
        Sha256::digest(self.encode()).into()
    }
}

#[derive(Debug, Clone)]
pub struct StoreView<'a> {

    pub header: &'a StoreHeader,

    pub segments: &'a [crate::segment::Segment],
}

impl StoreView<'_> {

    pub fn verify(&self) -> Result<[u8; 32]> {
        let genesis = self.check_identity()?;
        crate::segment::verify_stream(self.segments, genesis)
    }

    pub fn verify_signed(&self, verify_seal: &crate::SealVerify) -> Result<[u8; 32]> {
        let genesis = self.check_identity()?;
        crate::segment::verify_stream_signed(self.segments, genesis, verify_seal)
    }

    fn check_identity(&self) -> Result<[u8; 32]> {
        let genesis = self.header.genesis();
        for seg in self.segments {
            if seg.header.store_header_hash != genesis {
                return Err(FormatError::SegmentDiscontinuity {
                    segment_seq: seg.header.segment_seq,
                    what: "store_header_hash does not match this store's genesis",
                });
            }
            if seg.header.engagement_id != self.header.engagement_id
                || seg.header.agent_id != self.header.agent_id
            {
                return Err(FormatError::SegmentDiscontinuity {
                    segment_seq: seg.header.segment_seq,
                    what: "segment identity does not match the store header",
                });
            }
        }
        Ok(genesis)
    }
}

fn take<const N: usize>(b: &[u8], off: usize) -> Result<[u8; N]> {
    b.get(off..off.saturating_add(N))
        .and_then(|s| <[u8; N]>::try_from(s).ok())
        .ok_or(FormatError::Truncated {
            what: "StoreHeader field",
            need: off.saturating_add(N),
            have: b.len(),
        })
}
