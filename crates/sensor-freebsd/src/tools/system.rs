use std::collections::BTreeMap;
use std::io::Write as _;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use hemostat_evcrypto::manifest::Verified;

use super::verify::at;
use super::{Invocation, Output, PhpExt, RunError, Runner, Tool, Unverified, Verification, Verifier};
use crate::saferead::Throttle;

const MAX_STDERR: u64 = 1024 * 1024;

#[derive(Debug)]
pub struct System<'m> {
    verifier: Verifier<'m>,
    verified: BTreeMap<(Tool, Vec<PhpExt>), Verification>,
}

impl<'m> System<'m> {

    pub fn new(manifest: Option<&'m Verified>) -> System<'m> {
        System { verifier: Verifier::new(manifest), verified: BTreeMap::new() }
    }

    pub fn with_root(manifest: Option<&'m Verified>, root: PathBuf) -> System<'m> {
        System { verifier: Verifier::with_root(manifest, root, Throttle::unlimited()), verified: BTreeMap::new() }
    }

    pub fn with_meta(self, meta: Option<&'m hemostat_evcrypto::manifest::meta::VerifiedMeta>) -> System<'m> {
        System { verifier: self.verifier.with_meta(meta), verified: self.verified }
    }

    pub fn verify(&mut self, tool: Tool, exts: &[PhpExt]) -> Result<&Verification, Unverified> {
        let key = (tool, exts.to_vec());
        let fresh = match self.verified.get(&key) {
            Some(v) => v.recheck(self.verifier.root()).is_err(),
            None => true,
        };
        if fresh {
            self.verified.remove(&key);
            let v = self.verifier.verify(tool, exts)?;
            self.verified.insert(key.clone(), v);
        }
        self.verified.get(&key).ok_or(Unverified::NoManifest)
    }

    pub fn hashed(&self) -> u64 {
        self.verifier.hashed()
    }
}

impl Runner for System<'_> {
    fn run(&mut self, inv: &Invocation) -> Result<Output, RunError> {
        if let Some(why) = inv.refusal() {
            return Err(RunError::Refused(why));
        }
        let root = self.verifier.root().to_path_buf();
        let v = self.verify(inv.tool(), inv.exts()).map_err(RunError::Unverified)?.clone();

        v.recheck(&root).map_err(RunError::Unverified)?;
        spawn(&at(&root, inv.tool().path()), &v, inv)
    }

    fn tool_sha256(&self, tool: Tool) -> Option<[u8; 32]> {
        self.verified.get(&(tool, Vec::new())).and_then(Verification::digest)
    }
}

fn spawn(program: &std::path::Path, v: &Verification, inv: &Invocation) -> Result<Output, RunError> {
    let mut cmd = Command::new(program);
    cmd.args(inv.argv())
        .env_clear()
        .envs(v.env())
        .current_dir("/")
        .stdin(if inv.stdin_bytes().is_some() { Stdio::piped() } else { Stdio::null() })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().map_err(|e| RunError::Spawn(format!("{}: {e}", inv.tool())))?;

    let feeder = child.stdin.take().map(|mut w| {
        let data = inv.stdin_bytes().unwrap_or_default().to_vec();
        std::thread::spawn(move || {
            let _ = w.write_all(&data);
        })
    });
    let cap = inv.output_cap();
    let out = child.stdout.take().map(|r| std::thread::spawn(move || drain(r, cap)));
    let err = child.stderr.take().map(|r| std::thread::spawn(move || drain(r, MAX_STDERR)));

    let deadline = Instant::now() + inv.time_limit();
    let status = loop {
        match child.try_wait() {
            Ok(Some(s)) => break Some(s),
            Ok(None) => {}
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(RunError::Spawn(e.to_string()));
            }
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            break None;
        }
        std::thread::sleep(Duration::from_millis(5));
    };
    if let Some(f) = feeder {
        let _ = f.join();
    }
    let (stdout, over) = out.and_then(|t| t.join().ok()).unwrap_or_default();
    let (stderr, _) = err.and_then(|t| t.join().ok()).unwrap_or_default();
    let Some(status) = status else { return Err(RunError::Timeout(inv.time_limit())) };
    if over {
        return Err(RunError::TooLarge(cap));
    }
    Ok(Output { status: status.code(), stdout, stderr })
}

fn drain(mut r: impl std::io::Read, cap: u64) -> (Vec<u8>, bool) {
    let mut kept = Vec::new();
    let mut over = false;
    let mut buf = [0u8; 64 * 1024];
    loop {
        match r.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                let room = usize::try_from(cap.saturating_sub(kept.len() as u64)).unwrap_or(usize::MAX);
                let take = n.min(room);
                kept.extend_from_slice(buf.get(..take).unwrap_or_default());
                over |= take < n;
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => break,
        }
    }
    (kept, over)
}
