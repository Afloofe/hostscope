use hemostat_evcrypto::composed;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::{Message, Role, MAX_ANNOUNCE, MAX_RECEIPT, PARCEL_CHUNK, RETIRED_TAGS, VERSION};

pub const MAGIC: u8 = 0x48;

pub const MAX_BODY: usize = 1024 * 1024;

pub const HEADER_LEN: usize = 1 + 1 + 4 + composed::NENC;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameError {

    Incomplete {

        need: usize,
    },

    NotAFrame,

    Version {

        got: u8,
    },

    TooLarge {

        claimed: usize,
    },

    NotAuthentic,

    Malformed(String),

    WrongDirection {

        why: &'static str,
    },
}

pub fn seal(
    to: &PublicKey,
    from: Role,
    sender: &StaticSecret,
    msg: &Message,
    ephemeral: &StaticSecret,
) -> Result<Vec<u8>, FrameError> {
    let body = encode(msg);
    let info = direction_info(from);
    let mut header = Vec::with_capacity(HEADER_LEN);
    header.push(MAGIC);
    header.push(VERSION);

    let (enc, ct) = composed::seal_auth_deterministic(ephemeral, to, sender, info, &aad(VERSION), &body)
        .map_err(|_| FrameError::NotAuthentic)?;

    let total = u32::try_from(ct.len()).map_err(|_| FrameError::TooLarge { claimed: ct.len() })?;
    header.extend_from_slice(&total.to_be_bytes());
    header.extend_from_slice(&enc);
    header.extend_from_slice(&ct);
    Ok(header)
}

pub fn open(
    buf: &[u8],
    me: Role,
    my_secret: &StaticSecret,
    peer: &PublicKey,
) -> Result<(Message, usize), FrameError> {
    if buf.len() < HEADER_LEN {
        return Err(FrameError::Incomplete { need: HEADER_LEN });
    }
    if buf[0] != MAGIC {
        return Err(FrameError::NotAFrame);
    }
    if buf[1] != VERSION {
        return Err(FrameError::Version { got: buf[1] });
    }
    let len = u32::from_be_bytes([buf[2], buf[3], buf[4], buf[5]]) as usize;

    if len > MAX_BODY {
        return Err(FrameError::TooLarge { claimed: len });
    }
    let total = HEADER_LEN + len;
    if buf.len() < total {
        return Err(FrameError::Incomplete { need: total });
    }

    let mut enc = [0_u8; composed::NENC];
    enc.copy_from_slice(&buf[6..HEADER_LEN]);

    let info = direction_info(match me {
        Role::Agent => Role::Console,
        Role::Console => Role::Agent,
    });
    let pt = composed::open_auth(my_secret, peer, &enc, info, &aad(buf[1]), &buf[HEADER_LEN..total])
        .map_err(|_| FrameError::NotAuthentic)?;

    let msg = decode(&pt)?;
    if !me.accepts(&msg) {
        return Err(FrameError::WrongDirection { why: me.refusal() });
    }
    Ok((msg, total))
}

pub fn open_from_any(
    buf: &[u8],
    me: Role,
    my_secret: &StaticSecret,
    peers: &[PublicKey],
) -> Result<(Message, usize, usize), FrameError> {
    let mut last = FrameError::NotAuthentic;
    for (i, peer) in peers.iter().enumerate() {
        match open(buf, me, my_secret, peer) {
            Ok((m, used)) => return Ok((m, used, i)),
            Err(FrameError::NotAuthentic) => {}

            Err(e) => return Err(e),
        }
    }
    if peers.is_empty() {

        if let Err(e) = open(buf, me, my_secret, &PublicKey::from([0_u8; 32])) {
            if e != FrameError::NotAuthentic {
                last = e;
            }
        }
    }
    Err(last)
}

const fn direction_info(from: Role) -> &'static [u8] {
    match from {
        Role::Agent => b"hemostat/agentlink/agent->console",
        Role::Console => b"hemostat/agentlink/console->agent",
    }
}

pub fn aad(version: u8) -> [u8; 2] {
    [MAGIC, version]
}

pub fn encode(m: &Message) -> Vec<u8> {
    let mut out = vec![m.tag()];

    let bytes = |out: &mut Vec<u8>, b: &[u8]| {
        out.extend_from_slice(&u32::try_from(b.len()).unwrap_or(u32::MAX).to_be_bytes());
        out.extend_from_slice(b);
    };
    match m {
        Message::Heartbeat { run, seq, uptime_secs, wall_ns } => {
            out.extend_from_slice(&run.to_be_bytes());
            out.extend_from_slice(&seq.to_be_bytes());
            out.extend_from_slice(&uptime_secs.to_be_bytes());
            out.extend_from_slice(&wall_ns.to_be_bytes());
        }
        Message::Announce { header } => bytes(&mut out, header),
        Message::Parcel { push, index, count, total, digest, chunk } => {
            out.extend_from_slice(push);
            out.extend_from_slice(&index.to_be_bytes());
            out.extend_from_slice(&count.to_be_bytes());
            out.extend_from_slice(&total.to_be_bytes());
            out.extend_from_slice(digest);
            bytes(&mut out, chunk);
        }
        Message::Receipt { signed } => bytes(&mut out, signed),
    }
    out
}

pub fn decode(b: &[u8]) -> Result<Message, FrameError> {
    let (&tag, mut rest) = b.split_first().ok_or_else(|| FrameError::Malformed("empty body".into()))?;

    fn take<const N: usize>(rest: &mut &[u8]) -> Result<[u8; N], FrameError> {
        if rest.len() < N {
            return Err(FrameError::Malformed("the body ends mid-field".to_string()));
        }
        let (a, b) = rest.split_at(N);
        *rest = b;
        Ok(a.try_into().unwrap_or([0; N]))
    }
    let u64_ = |rest: &mut &[u8]| take::<8>(rest).map(u64::from_be_bytes);
    let u32_ = |rest: &mut &[u8]| take::<4>(rest).map(u32::from_be_bytes);

    let field = |rest: &mut &[u8], cap: usize, what: &str| -> Result<Vec<u8>, FrameError> {
        let n = take::<4>(rest).map(u32::from_be_bytes)? as usize;
        if n > cap {
            return Err(FrameError::Malformed(format!("{what} is {n} bytes, over its {cap}-byte bound")));
        }
        if rest.len() < n {
            return Err(FrameError::Malformed(format!("{what} claims {n} bytes and {} remain", rest.len())));
        }
        let (a, b) = rest.split_at(n);
        *rest = b;
        Ok(a.to_vec())
    };
    let msg = match tag {
        1 => Message::Heartbeat {
            run: u64_(&mut rest)?,
            seq: u64_(&mut rest)?,
            uptime_secs: u64_(&mut rest)?,
            wall_ns: take::<8>(&mut rest).map(i64::from_be_bytes)?,
        },
        5 => Message::Announce { header: field(&mut rest, MAX_ANNOUNCE, "the announced store header")? },
        6 => {
            let push = take::<16>(&mut rest)?;
            let index = u32_(&mut rest)?;
            let count = u32_(&mut rest)?;
            let total = u64_(&mut rest)?;
            let digest = take::<32>(&mut rest)?;
            let chunk = field(&mut rest, PARCEL_CHUNK, "a parcel chunk")?;
            if count == 0 || index >= count {
                return Err(FrameError::Malformed(format!("parcel chunk {index} of {count}")));
            }
            Message::Parcel { push, index, count, total, digest, chunk }
        }
        7 => Message::Receipt { signed: field(&mut rest, MAX_RECEIPT, "a receipt")? },
        other => {
            let why = match RETIRED_TAGS.iter().find(|(t, _)| *t == other) {
                Some((_, was)) => format!(
                    "message tag {other} was `{was}`, removed by RFC-003; this build neither \
                     sends nor accepts it"
                ),
                None => format!("unknown message tag {other}"),
            };
            return Err(FrameError::Malformed(why));
        }
    };
    if !rest.is_empty() {
        return Err(FrameError::Malformed(format!("{} trailing byte(s)", rest.len())));
    }
    Ok(msg)
}
