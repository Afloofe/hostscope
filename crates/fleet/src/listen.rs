use std::fs;
use std::io::{Read as _, Write as _};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use hemostat_remote::frame::{self, FrameError};
use hemostat_remote::link::{self, LinkError, READ_TIMEOUT};
use hemostat_remote::{Message, PublicKey, Role, StaticSecret, MAX_RECEIPT, PARCEL_CHUNK};
use sha2::{Digest as _, Sha256};

use crate::{hex, now_ns};

const MAX_PARCEL: u64 = hemostat_evfmt::MAX_PARCEL_BYTES;

#[derive(Debug, Clone)]
pub struct Dirs {

    pub incoming: PathBuf,

    pub receipts: PathBuf,

    pub done: PathBuf,

    pub enroll: PathBuf,

    pub heartbeats: PathBuf,
}

pub type Entropy = Arc<dyn Fn() -> std::io::Result<[u8; 32]> + Send + Sync>;

pub type DiskCheck = Arc<dyn Fn() -> Option<String> + Send + Sync>;

#[derive(Clone)]
pub struct Config {

    pub dirs: Dirs,

    pub receipt_wait: Duration,

    pub max_conns: usize,

    pub until: Option<Instant>,

    pub entropy: Entropy,

    pub disk: DiskCheck,

    pub log: Arc<dyn Fn(&str) + Send + Sync>,
}

impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config").field("dirs", &self.dirs).field("receipt_wait", &self.receipt_wait).finish_non_exhaustive()
    }
}

#[derive(Debug)]
pub struct Listener {
    inner: TcpListener,
}

impl Listener {

    pub fn local_addr(&self) -> Result<SocketAddr, String> {
        self.inner.local_addr().map_err(|e| e.to_string())
    }
}

pub fn open_port(addr: &str) -> Result<Listener, String> {
    let inner = TcpListener::bind(addr).map_err(|e| format!("cannot listen on {}: {e}", crate::shown(addr)))?;
    Ok(Listener { inner })
}

#[derive(Debug, Default, Clone, Copy)]
pub struct Served {

    pub connections: u64,

    pub busy: u64,
}

pub fn serve(l: Listener, cfg: Config, link: [u8; 32]) -> Result<Served, String> {
    l.inner.set_nonblocking(true).map_err(|e| e.to_string())?;
    let link = Arc::new(StaticSecret::from(link));
    let active = Arc::new(AtomicUsize::new(0));
    let counter = Arc::new(AtomicU64::new(0));
    let mut served = Served::default();
    let started_ns = now_ns();
    let mut ticked_ns = i64::MIN;
    let mut tick_failing = false;
    loop {
        if cfg.until.is_some_and(|u| Instant::now() >= u) {
            break;
        }
        let now = now_ns();
        if now.saturating_sub(ticked_ns) >= crate::heartbeat::TICK_NS {
            ticked_ns = now;
            let tick = crate::heartbeat::Listening { started_ns, tick_ns: now };
            match crate::heartbeat::write_listening(&cfg.dirs.heartbeats, tick) {
                Ok(()) => tick_failing = false,
                Err(e) if !tick_failing => {
                    tick_failing = true;
                    (cfg.log)(&format!(
                        "cannot renew the listening tick ({e}): the ingest role will judge no agent silent while it is stale"
                    ));
                }
                Err(_) => {}
            }
        }
        match l.inner.accept() {
            Ok((stream, peer)) => {
                served.connections += 1;
                let _ = stream.set_nonblocking(false);
                if active.load(Ordering::SeqCst) >= cfg.max_conns {
                    served.busy += 1;
                    (cfg.log)(&format!("{peer}: busy ({} connections open); closed unread", cfg.max_conns));
                    continue;
                }
                active.fetch_add(1, Ordering::SeqCst);
                let n = counter.fetch_add(1, Ordering::SeqCst);
                let (cfg2, link2, active2) = (cfg.clone(), Arc::clone(&link), Arc::clone(&active));
                std::thread::spawn(move || {
                    let conn = format!("{:020}-{n:06}", now_ns().max(0));
                    let line = handle(stream, peer, &conn, &cfg2, &link2);
                    (cfg2.log)(&format!("{conn} {peer}: {line}"));
                    active2.fetch_sub(1, Ordering::SeqCst);
                });
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => std::thread::sleep(Duration::from_millis(50)),
            Err(e) => {
                (cfg.log)(&format!("accept failed: {e}"));
                std::thread::sleep(Duration::from_millis(200));
            }
        }
    }

    crate::heartbeat::clear_listening(&cfg.dirs.heartbeats);

    let end = Instant::now() + cfg.receipt_wait + READ_TIMEOUT;
    while active.load(Ordering::SeqCst) > 0 && Instant::now() < end {
        std::thread::sleep(Duration::from_millis(50));
    }
    Ok(served)
}

fn enrolled_keys(dir: &Path) -> Result<Vec<PublicKey>, String> {
    Ok(crate::enroll::read_dir(dir)?.into_iter().filter_map(|e| e.link).map(PublicKey::from).collect())
}

struct Spool {
    part: PathBuf,
    meta: Vec<(String, String)>,
    received_ns: i64,
}

impl Spool {
    fn new(incoming: &Path, conn: &str, peer: SocketAddr) -> std::io::Result<Spool> {
        let part = incoming.join(format!("{conn}.part"));
        private_dir(&part)?;
        let received_ns = now_ns();
        let meta = vec![
            ("conn".to_string(), conn.to_string()),
            ("source".to_string(), peer.to_string()),
            ("received_ns".to_string(), received_ns.to_string()),
        ];
        Ok(Spool { part, meta, received_ns })
    }

    fn set(&mut self, k: &str, v: impl Into<String>) {
        let v: String = v.into();

        let v = crate::shown(&v);
        self.meta.push((k.to_string(), v));
    }

    fn write_file(&self, name: &str, bytes: &[u8]) -> std::io::Result<()> {
        let mut f = new_file(&self.part.join(name))?;
        f.write_all(bytes)?;
        f.sync_all()
    }

    fn finish(self, suffix: &str) -> std::io::Result<PathBuf> {
        let text: String = self.meta.iter().map(|(k, v)| format!("{k}={v}\n")).collect();
        self.write_file("meta", text.as_bytes())?;
        let conn = self.meta.first().map(|(_, v)| v.clone()).unwrap_or_default();
        let parent = self.part.parent().map(Path::to_path_buf).unwrap_or_default();
        let dest = parent.join(format!("{conn}{suffix}"));
        fs::rename(&self.part, &dest)?;
        sync_dir(&parent);
        Ok(dest)
    }
}

fn private_dir(p: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        fs::DirBuilder::new().mode(0o700).create(p)
    }
    #[cfg(not(unix))]
    {
        fs::DirBuilder::new().create(p)
    }
}

fn new_file(p: &Path) -> std::io::Result<fs::File> {
    let mut o = fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        o.mode(0o600);
    }
    o.open(p)
}

fn sync_dir(p: &Path) {
    if let Ok(f) = fs::File::open(p) {
        let _ = f.sync_all();
    }
}

fn handle(mut s: TcpStream, peer: SocketAddr, conn: &str, cfg: &Config, link: &StaticSecret) -> String {
    let spool = match Spool::new(&cfg.dirs.incoming, conn, peer) {
        Ok(sp) => sp,
        Err(e) => return format!("cannot spool: {e}"),
    };
    let record = |mut sp: Spool, kind: &str, reason: &str| {
        sp.set("kind", kind);
        if !reason.is_empty() {
            sp.set("reason", reason);
        }
        match sp.finish("") {
            Ok(_) => format!("{kind}{}{reason}", if reason.is_empty() { "" } else { ": " }),
            Err(e) => format!("{kind}, and the record of it failed: {e}"),
        }
    };
    if let Some(why) = (cfg.disk)() {
        return record(spool, "refused", &format!("the collector's disk is past its ceiling: {why}"));
    }
    let peers = match enrolled_keys(&cfg.dirs.enroll) {
        Ok(p) => p,
        Err(e) => return record(spool, "refused", &format!("the enrollment does not read, so no frame was opened: {e}")),
    };
    let first = match link::read_raw_frame(&mut s, Instant::now() + READ_TIMEOUT) {
        Ok(b) => b,
        Err(e) => return record(spool, "refused", &e.message()),
    };
    let (msg, who) = match frame::open_from_any(&first, Role::Console, link, &peers) {
        Ok((m, _, i)) => (m, i),
        Err(FrameError::NotAuthentic) => {

            return record(
                spool,
                "unknown-agent",
                "a frame no enrolled agent's key opens: an agent that was never enrolled, a fresh key, or \
                 a frame changed in flight",
            );
        }
        Err(e) => return record(spool, "refused", &LinkError::Frame(e).message()),
    };
    let Some(agent) = peers.get(who).copied() else { return record(spool, "refused", "internal: no such peer") };
    let mut spool = spool;
    spool.set("agent", hex(agent.as_bytes()));
    match msg {
        Message::Heartbeat { run, seq, uptime_secs, wall_ns } => {

            let _ = fs::remove_dir(&spool.part);
            let b = crate::heartbeat::Beat { received_ns: spool.received_ns, run, seq, uptime_secs, wall_ns };
            match crate::heartbeat::append(&cfg.dirs.heartbeats, agent.as_bytes(), &b) {
                Ok(()) => format!("heartbeat run {run:016x} seq {seq}"),
                Err(e) => format!("heartbeat run {run:016x} seq {seq}, NOT logged: {e}"),
            }
        }
        Message::Announce { header } => {
            if let Err(e) = spool.write_file("announce", &header) {
                return format!("announce, and spooling it failed: {e}");
            }
            spool.set("bytes", header.len().to_string());
            record(spool, "announce", "")
        }
        Message::Parcel { push, index, count, total, digest, chunk } => {
            spool.set("push", hex(&push));
            spool.set("kind", "parcel");
            match receive_parcel(&mut s, &mut spool, cfg, link, &agent, (push, index, count, total, digest, chunk)) {
                Err(why) => {
                    spool.set("reason", why.clone());

                    let _ = spool.finish(".failed");
                    format!("incomplete push: {why}")
                }
                Ok(()) => {
                    let sha = hex(&digest);
                    spool.set("bytes", total.to_string());
                    spool.set("sha256", sha.clone());
                    if let Err(e) = spool.finish("") {
                        return format!("parcel in, and putting it in the spool failed: {e}");
                    }
                    match wait_for_receipt(&cfg.dirs, conn, cfg.receipt_wait) {
                        Some(signed) => {
                            let eph = match (cfg.entropy)() {
                                Ok(e) => StaticSecret::from(e),
                                Err(e) => return format!("parcel {sha} in; no entropy to seal the receipt: {e}"),
                            };
                            let r = Message::Receipt { signed };
                            match link::write_frame(&mut s, &agent, Role::Console, link, &r, &eph) {
                                Ok(()) => format!("parcel {sha} ({total} bytes) in; receipt sent"),
                                Err(e) => format!("parcel {sha} in; the receipt did not reach the agent: {}", e.message()),
                            }
                        }
                        None => format!("parcel {sha} ({total} bytes) in; no receipt (not accepted, or not judged in time)"),
                    }
                }
            }
        }
        Message::Receipt { .. } => {

            record(spool, "refused", "a receipt sent to the collector")
        }
    }
}

type First = ([u8; 16], u32, u32, u64, [u8; 32], Vec<u8>);

fn receive_parcel(
    s: &mut TcpStream,
    spool: &mut Spool,
    cfg: &Config,
    link: &StaticSecret,
    agent: &PublicKey,
    first: First,
) -> Result<(), String> {
    let (push, index, count, total, digest, chunk) = first;
    if index != 0 {
        return Err(format!("the push began at chunk {index}, not 0"));
    }
    if total > MAX_PARCEL {
        return Err(format!("the push claims {total} bytes, over the {MAX_PARCEL}-byte parcel bound"));
    }
    let want = usize::try_from(total).map_err(|_| "too large")?.div_ceil(PARCEL_CHUNK).max(1);
    if count as usize != want {
        return Err(format!("{count} chunks for {total} bytes; that length takes {want}"));
    }
    let path = spool.part.join("parcel.part");
    let mut f = new_file(&path).map_err(|e| format!("cannot create the spool file: {e}"))?;
    let mut h = Sha256::new();
    let mut got: u64 = 0;
    let mut take = |chunk: &[u8], i: u32| -> Result<(), String> {
        let last = i + 1 == count;
        let full = chunk.len() == PARCEL_CHUNK;
        if !(full || last) || (last && got + chunk.len() as u64 != total) {
            return Err(format!("chunk {i} is {} bytes, which does not fit {total} bytes in {count} chunks", chunk.len()));
        }
        h.update(chunk);
        f.write_all(chunk).map_err(|e| format!("cannot write the spool file: {e}"))?;
        got += chunk.len() as u64;
        Ok(())
    };
    take(&chunk, 0)?;
    for i in 1..count {
        if let Some(why) = (cfg.disk)() {
            return Err(format!("the collector's disk passed its ceiling mid-push: {why}"));
        }
        let m = link::read_frame(s, Role::Console, link, agent).map_err(|e| e.message())?;
        match m {
            Message::Parcel { push: p, index: j, count: c, total: t, digest: d, chunk } => {
                if (p, c, t, d) != (push, count, total, digest) {
                    return Err(format!("chunk {j} disagrees with chunk 0 about the push"));
                }
                if j != i {
                    return Err(format!("chunk {j} arrived where chunk {i} was due"));
                }
                take(&chunk, i)?;
            }
            _ => return Err("a message that is not a parcel chunk arrived mid-push".to_string()),
        }
    }
    f.sync_all().map_err(|e| format!("cannot sync the spool file: {e}"))?;
    drop(f);
    let sha: [u8; 32] = h.finalize().into();
    if sha != digest {
        return Err(format!("the bytes received hash to {}, and the push said {}", hex(&sha), hex(&digest)));
    }
    fs::rename(&path, spool.part.join("parcel")).map_err(|e| format!("cannot complete the spool file: {e}"))?;
    Ok(())
}

fn wait_for_receipt(dirs: &Dirs, conn: &str, wait: Duration) -> Option<Vec<u8>> {
    let end = Instant::now() + wait;
    let receipt = dirs.receipts.join(conn);
    let done = dirs.done.join(conn);
    loop {
        if let Ok(m) = fs::symlink_metadata(&receipt) {
            if m.file_type().is_file() && m.len() as usize <= MAX_RECEIPT {
                let mut b = Vec::new();
                let read = fs::File::open(&receipt).and_then(|f| f.take(MAX_RECEIPT as u64 + 1).read_to_end(&mut b));
                if read.is_ok() && b.len() <= MAX_RECEIPT {
                    return Some(b);
                }
            }
            return None;
        }
        if fs::symlink_metadata(&done).is_ok() {

            return fs::read(&receipt).ok().filter(|b| b.len() <= MAX_RECEIPT);
        }
        if Instant::now() >= end {
            return None;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}
