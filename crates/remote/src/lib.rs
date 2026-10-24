#![forbid(unsafe_code)]

pub mod frame;
pub mod link;
pub mod liveness;

pub use x25519_dalek::{PublicKey, StaticSecret};

use std::time::Duration;

pub const VERSION: u8 = 3;

pub const BEACON_INTERVAL: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {

    Heartbeat {

        run: u64,

        seq: u64,

        uptime_secs: u64,

        wall_ns: i64,
    },

    Announce {

        header: Vec<u8>,
    },

    Parcel {

        push: [u8; 16],

        index: u32,

        count: u32,

        total: u64,

        digest: [u8; 32],

        chunk: Vec<u8>,
    },

    Receipt {

        signed: Vec<u8>,
    },
}

pub const PARCEL_CHUNK: usize = frame::MAX_BODY - 4096;

pub const MAX_ANNOUNCE: usize = 64 * 1024;

pub const MAX_RECEIPT: usize = 4096;

pub const RETIRED_TAGS: [(u8, &str); 3] = [(2, "Finding"), (3, "Request"), (4, "Ack")];

impl Message {

    pub const fn tag(&self) -> u8 {
        match self {
            Message::Heartbeat { .. } => 1,
            Message::Announce { .. } => 5,
            Message::Parcel { .. } => 6,
            Message::Receipt { .. } => 7,
        }
    }

    pub const fn from_console(&self) -> bool {
        match self {
            Message::Receipt { .. } => true,
            Message::Heartbeat { .. } | Message::Announce { .. } | Message::Parcel { .. } => false,
        }
    }

    pub const fn from_agent(&self) -> bool {
        match self {
            Message::Heartbeat { .. } | Message::Announce { .. } | Message::Parcel { .. } => true,
            Message::Receipt { .. } => false,
        }
    }
}

pub fn parcel_messages<'a>(push: [u8; 16], digest: [u8; 32], bytes: &'a [u8]) -> impl Iterator<Item = Message> + 'a {
    let count = bytes.len().div_ceil(PARCEL_CHUNK).max(1);
    let count32 = u32::try_from(count).unwrap_or(u32::MAX);
    let total = bytes.len() as u64;
    (0..count).map(move |i| {
        let from = i.saturating_mul(PARCEL_CHUNK);
        let to = from.saturating_add(PARCEL_CHUNK).min(bytes.len());
        Message::Parcel {
            push,
            index: u32::try_from(i).unwrap_or(u32::MAX),
            count: count32,
            total,
            digest,
            chunk: bytes.get(from..to).unwrap_or_default().to_vec(),
        }
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {

    Agent,

    Console,
}

impl Role {

    pub const fn accepts(self, m: &Message) -> bool {
        match self {
            Role::Agent => m.from_console(),
            Role::Console => m.from_agent(),
        }
    }

    pub const fn refusal(self) -> &'static str {
        match self {
            Role::Agent => {
                "this is the agent, and the only thing it accepts is the collector's signed \
                 Receipt: RFC-003 removed every other inbound message. A frame that opens here \
                 and is anything else is not a protocol error somebody made — it is the shape \
                 of something on the network pretending to be the other end"
            }
            Role::Console => {
                "this is the collector, and an agent sends it only a Heartbeat, an Announce or a \
                 Parcel. Anything else arriving here is not from an agent this tree built"
            }
        }
    }
}
