use crate::{FormatError, Result};

pub const HEADER_LEN: u8 = 100;

const _: () = {
    let sum: usize = 1
        + 1
        + 1
        + 1
        + 1
        + 1
        + 2
        + 8
        + 8
        + 8
        + 16
        + 12
        + 32
        + 4
        + 4;
    assert!(
        sum == HEADER_LEN as usize,
        "HEADER_LEN disagrees with the sum of the field widths"
    );
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RecType(pub u8);

impl RecType {

    pub const VOLATILE_CAPTURE: RecType = RecType(1);

    pub const PROC_EVENT: RecType = RecType(2);

    pub const NET_EVENT: RecType = RecType(3);

    pub const FILE_EVENT: RecType = RecType(4);

    pub const REG_EVENT: RecType = RecType(5);

    pub const DETECTION: RecType = RecType(6);

    pub const AGENT_ACTION: RecType = RecType(7);

    pub const TAMPER: RecType = RecType(8);

    pub const TAMPER_TAIL: RecType = RecType(9);

    pub const CUSTODY: RecType = RecType(10);

    pub const CHECKPOINT: RecType = RecType(12);

    pub const KEY_TRANSITION: RecType = RecType(13);

    pub const ARTIFACT_MANIFEST: RecType = RecType(14);

    pub const SHED_NOTICE: RecType = RecType(16);

    pub const SOURCE_NARROWED: RecType = RecType(17);

    pub const CLOCK_JUMP: RecType = RecType(18);

    pub const BOOT_TRANSITION: RecType = RecType(20);

    pub const fn is_known(self) -> bool {
        matches!(self.0, 1..=10 | 12..=14 | 16..=18 | 20)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlg {

    Sha256,
}

impl HashAlg {

    pub const fn to_u8(self) -> u8 {
        match self {
            HashAlg::Sha256 => 0x01,
        }
    }

    pub const fn from_u8(v: u8) -> Result<Self> {
        match v {
            0x01 => Ok(HashAlg::Sha256),
            other => Err(FormatError::BadField {
                field: "hash_alg",
                value: other as u64,
            }),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AeadAlg {

    None,

    Aes256Gcm,
}

impl AeadAlg {

    pub const fn to_u8(self) -> u8 {
        match self {
            AeadAlg::None => 0x00,
            AeadAlg::Aes256Gcm => 0x01,
        }
    }

    pub const fn from_u8(v: u8) -> Result<Self> {
        match v {
            0x00 => Ok(AeadAlg::None),
            0x01 => Ok(AeadAlg::Aes256Gcm),
            other => Err(FormatError::BadField {
                field: "aead_alg",
                value: other as u64,
            }),
        }
    }

    pub const fn tag_len(self) -> usize {
        match self {
            AeadAlg::None => 0,
            AeadAlg::Aes256Gcm => 16,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompAlg {

    None,

    Lz4Block,
}

impl CompAlg {

    pub const fn to_u8(self) -> u8 {
        match self {
            CompAlg::None => 0x00,
            CompAlg::Lz4Block => 0x01,
        }
    }

    pub const fn from_u8(v: u8) -> Result<Self> {
        match v {
            0x00 => Ok(CompAlg::None),
            0x01 => Ok(CompAlg::Lz4Block),
            other => Err(FormatError::BadField {
                field: "comp_alg",
                value: other as u64,
            }),
        }
    }
}

pub mod flags {

    pub const ENCRYPTED: u8 = 1 << 0;

    pub const P0_BATCH: u8 = 1 << 1;

    pub const COMPRESSED: u8 = 1 << 2;

    pub const REDACTED: u8 = 1 << 3;

    pub const AGGREGATED: u8 = 1 << 4;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecordHeader {

    pub rec_type: RecType,

    pub flags: u8,

    pub hash_alg: HashAlg,

    pub aead_alg: AeadAlg,

    pub comp_alg: CompAlg,

    pub seq: u64,

    pub ts_wall_ns: i64,

    pub ts_mono_ns: u64,

    pub boot_id: [u8; 16],

    pub nonce: [u8; 12],

    pub prev_hash: [u8; 32],

    pub payload_plain_len: u32,

    pub payload_stored_len: u32,
}

impl RecordHeader {

    #[allow(clippy::indexing_slicing)]
    pub fn encode(&self) -> [u8; HEADER_LEN as usize] {
        let mut b = [0u8; HEADER_LEN as usize];
        b[0] = HEADER_LEN;
        b[1] = self.rec_type.0;
        b[2] = self.flags;
        b[3] = self.hash_alg.to_u8();
        b[4] = self.aead_alg.to_u8();
        b[5] = self.comp_alg.to_u8();

        b[8..16].copy_from_slice(&self.seq.to_le_bytes());
        b[16..24].copy_from_slice(&self.ts_wall_ns.to_le_bytes());
        b[24..32].copy_from_slice(&self.ts_mono_ns.to_le_bytes());
        b[32..48].copy_from_slice(&self.boot_id);
        b[48..60].copy_from_slice(&self.nonce);
        b[60..92].copy_from_slice(&self.prev_hash);
        b[92..96].copy_from_slice(&self.payload_plain_len.to_le_bytes());
        b[96..100].copy_from_slice(&self.payload_stored_len.to_le_bytes());
        b
    }

    pub fn decode(b: &[u8]) -> Result<Self> {
        if b.len() < HEADER_LEN as usize {
            return Err(FormatError::Truncated {
                what: "RecordHeader",
                need: HEADER_LEN as usize,
                have: b.len(),
            });
        }
        let found = byte(b, 0)?;
        if found != HEADER_LEN {
            return Err(FormatError::BadHeaderLen {
                found,
                expected: HEADER_LEN,
            });
        }
        Ok(RecordHeader {
            rec_type: RecType(byte(b, 1)?),
            flags: byte(b, 2)?,
            hash_alg: HashAlg::from_u8(byte(b, 3)?)?,
            aead_alg: AeadAlg::from_u8(byte(b, 4)?)?,
            comp_alg: CompAlg::from_u8(byte(b, 5)?)?,
            seq: u64::from_le_bytes(take::<8>(b, 8)?),
            ts_wall_ns: i64::from_le_bytes(take::<8>(b, 16)?),
            ts_mono_ns: u64::from_le_bytes(take::<8>(b, 24)?),
            boot_id: take::<16>(b, 32)?,
            nonce: take::<12>(b, 48)?,
            prev_hash: take::<32>(b, 60)?,
            payload_plain_len: u32::from_le_bytes(take::<4>(b, 92)?),
            payload_stored_len: u32::from_le_bytes(take::<4>(b, 96)?),
        })
    }

    pub const fn is_encrypted(&self) -> bool {
        self.flags & flags::ENCRYPTED != 0
    }

    pub fn validate(&self) -> Result<()> {
        let encrypted_flag = self.is_encrypted();
        let has_aead = !matches!(self.aead_alg, AeadAlg::None);
        if encrypted_flag != has_aead {
            return Err(FormatError::BadField {
                field: "flags/aead_alg",
                value: u64::from(self.flags),
            });
        }
        let compressed_flag = self.flags & flags::COMPRESSED != 0;
        let has_comp = !matches!(self.comp_alg, CompAlg::None);
        if compressed_flag != has_comp {
            return Err(FormatError::BadField {
                field: "flags/comp_alg",
                value: u64::from(self.flags),
            });
        }
        Ok(())
    }
}

fn take<const N: usize>(b: &[u8], off: usize) -> Result<[u8; N]> {
    b.get(off..off.saturating_add(N))
        .and_then(|s| <[u8; N]>::try_from(s).ok())
        .ok_or(FormatError::Truncated {
            what: "RecordHeader field",
            need: off.saturating_add(N),
            have: b.len(),
        })
}

fn byte(b: &[u8], off: usize) -> Result<u8> {
    b.get(off).copied().ok_or(FormatError::Truncated {
        what: "RecordHeader field",
        need: off.saturating_add(1),
        have: b.len(),
    })
}
