#![forbid(unsafe_code)]

use core::fmt;

pub type SealSigner = Box<dyn Fn(&[u8]) -> Vec<u8>>;

pub type SealVerify = dyn Fn(&[u8], &[u8]) -> bool;

pub mod disk;
pub mod header;
pub mod parcel;
pub mod record;
pub mod segment;
pub mod store;
pub mod tsvjournal;

pub use disk::{
    load_stream, load_verified, parse_segment, read_store_header, stream_dir_name,
    verify_stream_dir, verify_stream_dir_signed, Clock, RecordCipher, RunContext, SegmentCipher,
    StoreError, StoreResult, StoreWriter, StreamCrypto, StreamWriter, SystemClock, VerifiedStream,
    VerifyReport, STORE_HEADER_FILE,
};
pub use parcel::{Parcel, ParcelError, ParcelFile, MAX_PARCEL_BYTES, PARCEL_EXT};
pub use header::{AeadAlg, CompAlg, HashAlg, RecType, RecordHeader, HEADER_LEN};
pub use record::{decode_record, encode_record, record_hash, Record, MAX_RECORD_BYTES};
pub use segment::{
    verify_stream, verify_stream_signed, SealPayload, Segment, SegmentHeader, StreamId,
    FOOTER_MAGIC, SEAL_FIXED_LEN, SEAL_SIGNABLE_LEN, SEGMENT_HEADER_PREFIX_LEN, SEGMENT_MAGIC,
};
pub use store::{StoreHeader, StoreView, STORE_HEADER_PREFIX_LEN, STORE_MAGIC};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FormatError {

    Truncated {

        what: &'static str,

        need: usize,

        have: usize,
    },

    BadHeaderLen {

        found: u8,

        expected: u8,
    },

    BadField {

        field: &'static str,

        value: u64,
    },

    TooLarge {

        len: usize,
    },

    BadCrc {

        stored: u32,

        computed: u32,
    },

    ChainBroken {

        seq: u64,
    },

    SealMismatch {

        segment_seq: u64,

        what: &'static str,
    },

    NotCanonical {

        what: &'static str,
    },

    SegmentDiscontinuity {

        segment_seq: u64,

        what: &'static str,
    },

    SealSignatureInvalid {

        segment_seq: u64,

        detail: &'static str,
    },

    ForwardCommitmentBroken {

        segment_seq: u64,

        detail: &'static str,
    },
}

impl fmt::Display for FormatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FormatError::Truncated { what, need, have } => {
                write!(f, "truncated while reading {what}: need {need} bytes, have {have}")
            }
            FormatError::BadHeaderLen { found, expected } => write!(
                f,
                "header_len is {found} (0x{found:02x}), expected {expected} (0x{expected:02x})"
            ),
            FormatError::BadField { field, value } => {
                write!(f, "field {field} holds undefined value {value}")
            }
            FormatError::TooLarge { len } => write!(
                f,
                "record length {len} exceeds the {MAX_RECORD_BYTES}-byte maximum; \
                 objects this large belong in the artifact blob store"
            ),
            FormatError::BadCrc { stored, computed } => write!(
                f,
                "crc32c mismatch: stored {stored:#010x}, computed {computed:#010x} \
                 (storage corruption or a torn write, not necessarily tampering)"
            ),
            FormatError::ChainBroken { seq } => write!(
                f,
                "chain broken at seq {seq}: prev_hash does not match the preceding record \
                 (a record was inserted, removed, reordered or modified)"
            ),
            FormatError::NotCanonical { what } => write!(
                f,
                "{what}: the bytes on disk are not what they re-encode to, so part of them is \
                 covered by no digest (tampering, not corruption)"
            ),
            FormatError::SealMismatch { segment_seq, what } => write!(
                f,
                "segment {segment_seq} seal disagrees with its contents: {what}"
            ),
            FormatError::SegmentDiscontinuity { segment_seq, what } => write!(
                f,
                "stream discontinuity at segment {segment_seq}: {what}"
            ),
            FormatError::ForwardCommitmentBroken { segment_seq, detail } => {
                write!(f, "forward commitment broken at segment {segment_seq}: {detail}")
            }
            FormatError::SealSignatureInvalid { segment_seq, detail } => write!(
                f,
                "seal signature invalid at segment {segment_seq}: {detail} \
                 (the footer was forged or its signature stripped)"
            ),
        }
    }
}

impl std::error::Error for FormatError {}

pub type Result<T> = core::result::Result<T, FormatError>;
