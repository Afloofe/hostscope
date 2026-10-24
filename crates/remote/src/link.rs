use std::io::{Read as _, Write as _};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

use x25519_dalek::{PublicKey, StaticSecret};

use crate::frame::{self, FrameError, HEADER_LEN, MAX_BODY};
use crate::{Message, Role};

pub const READ_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug)]
pub enum LinkError {

    Io(std::io::Error),

    Frame(FrameError),

    Oversized,

    Closed,
}

impl LinkError {

    pub fn message(&self) -> String {
        match self {
            LinkError::Io(e) => format!("the connection failed: {e}"),
            LinkError::Frame(FrameError::NotAuthentic) => {
                "a frame arrived that this key cannot open. Either it is not from the console \
                 you pinned, or it was changed in flight — which are the same thing from here, \
                 and both mean somebody is on the path"
                    .to_string()
            }
            LinkError::Frame(FrameError::WrongDirection { why }) => (*why).to_string(),
            LinkError::Frame(f) => format!("the frame could not be read: {f:?}"),
            LinkError::Oversized => format!(
                "the peer sent more than {MAX_BODY} bytes for one frame without completing it"
            ),
            LinkError::Closed => "the peer closed before completing a frame".to_string(),
        }
    }
}

impl From<std::io::Error> for LinkError {
    fn from(e: std::io::Error) -> Self {
        LinkError::Io(e)
    }
}

pub fn read_frame(
    stream: &mut TcpStream,
    me: Role,
    my_secret: &StaticSecret,
    peer: &PublicKey,
) -> Result<Message, LinkError> {
    read_frame_by(stream, me, my_secret, peer, Instant::now() + READ_TIMEOUT)
}

pub fn read_frame_by(
    stream: &mut TcpStream,
    me: Role,
    my_secret: &StaticSecret,
    peer: &PublicKey,
    deadline: Instant,
) -> Result<Message, LinkError> {
    let buf = read_raw_frame(stream, deadline)?;
    frame::open(&buf, me, my_secret, peer)
        .map(|(m, _)| m)
        .map_err(LinkError::Frame)
}

pub fn read_raw_frame(stream: &mut TcpStream, deadline: Instant) -> Result<Vec<u8>, LinkError> {
    let mut buf = vec![0_u8; HEADER_LEN];
    read_exact(stream, &mut buf, deadline)?;
    if buf.first() != Some(&frame::MAGIC) {
        return Err(LinkError::Frame(FrameError::NotAFrame));
    }
    if buf.get(1) != Some(&crate::VERSION) {
        return Err(LinkError::Frame(FrameError::Version { got: buf.get(1).copied().unwrap_or(0) }));
    }
    let len = buf.get(2..6).and_then(|b| <[u8; 4]>::try_from(b).ok()).map_or(usize::MAX, |b| u32::from_be_bytes(b) as usize);

    if len > MAX_BODY {
        return Err(LinkError::Frame(FrameError::TooLarge { claimed: len }));
    }
    buf.resize(HEADER_LEN + len, 0);
    let (_, tail) = buf.split_at_mut(HEADER_LEN);
    read_exact(stream, tail, deadline)?;
    Ok(buf)
}

fn read_exact(stream: &mut TcpStream, buf: &mut [u8], deadline: Instant) -> Result<(), LinkError> {
    let mut at = 0;
    while at < buf.len() {

        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(LinkError::Io(std::io::ErrorKind::TimedOut.into()));
        }
        stream.set_read_timeout(Some(left))?;
        match stream.read(buf.get_mut(at..).unwrap_or_default()) {
            Ok(0) => return Err(LinkError::Closed),
            Ok(n) => at += n,
            Err(e) => return Err(LinkError::Io(e)),
        }
    }
    Ok(())
}

pub fn write_frame(
    stream: &mut TcpStream,
    to: &PublicKey,
    from: Role,
    sender: &StaticSecret,
    msg: &Message,
    ephemeral: &StaticSecret,
) -> Result<(), LinkError> {
    let wire = frame::seal(to, from, sender, msg, ephemeral).map_err(LinkError::Frame)?;
    stream.write_all(&wire)?;
    stream.flush()?;
    Ok(())
}

pub fn beacon<A: ToSocketAddrs>(
    to: A,
    console: &PublicKey,
    agent: &StaticSecret,
    msg: &Message,
    ephemeral: &StaticSecret,
) -> Result<(), LinkError> {
    let mut s = connect(to, READ_TIMEOUT)?;
    write_frame(&mut s, console, Role::Agent, agent, msg, ephemeral)
}

fn connect<A: ToSocketAddrs>(to: A, timeout: Duration) -> Result<TcpStream, LinkError> {
    let addr = to
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| std::io::Error::other("no address"))?;
    Ok(TcpStream::connect_timeout(&addr, timeout)?)
}

pub fn announce<A: ToSocketAddrs>(
    to: A,
    collector: &PublicKey,
    agent: &StaticSecret,
    header: &[u8],
    ephemeral: &StaticSecret,
    timeout: Duration,
) -> Result<(), LinkError> {
    let mut s = connect(to, timeout)?;
    let msg = Message::Announce { header: header.to_vec() };
    write_frame(&mut s, collector, Role::Agent, agent, &msg, ephemeral)
}

pub fn push<A: ToSocketAddrs>(
    to: A,
    collector: &PublicKey,
    agent: &StaticSecret,
    chunks: impl IntoIterator<Item = Message>,
    fresh: &mut dyn FnMut() -> std::io::Result<StaticSecret>,
    receipt_by: Instant,
) -> Result<Vec<u8>, LinkError> {
    let mut s = connect(to, READ_TIMEOUT)?;
    for m in chunks {
        if !matches!(m, Message::Parcel { .. }) {
            return Err(LinkError::Io(std::io::Error::other("a push carries parcel chunks only")));
        }
        let eph = fresh()?;
        write_frame(&mut s, collector, Role::Agent, agent, &m, &eph)?;
    }
    match read_frame_by(&mut s, Role::Agent, agent, collector, receipt_by)? {
        Message::Receipt { signed } => Ok(signed),

        _ => Err(LinkError::Frame(FrameError::WrongDirection { why: Role::Agent.refusal() })),
    }
}
