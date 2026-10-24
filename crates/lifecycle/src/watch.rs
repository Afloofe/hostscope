use crate::image::Sealed;
use crate::restart::{next, History, Next, Policy};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Target {

    pub pid: u32,

    pub start_time: u64,
}

impl Target {

    pub fn of(pid: u32) -> Option<Self> {
        Some(Target { pid, start_time: start_time(pid)? })
    }

    pub fn alive(&self) -> bool {
        match stat_fields(self.pid) {
            Some((state, start)) => start == self.start_time && state != 'Z',
            None => false,
        }
    }

    pub fn held(&self) -> Option<Held> {
        let (state, start) = stat_fields(self.pid)?;
        if start != self.start_time {
            return None;
        }
        match state {
            'T' => Some(Held::Stopped),
            't' => Some(Held::Traced { tracer: tracer_of(self.pid) }),
            'Z' | 'X' => None,
            _ if cgroup_frozen(self.pid) => Some(Held::Frozen),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Held {

    Stopped,

    Traced {

        tracer: Option<u32>,
    },

    Frozen,
}

impl Held {

    pub fn describe(&self) -> String {
        match self {
            Held::Stopped => "stopped by a signal (state T)".to_string(),
            Held::Traced { tracer: Some(p) } => format!("stopped under a tracer, pid {p} (state t)"),
            Held::Traced { tracer: None } => "stopped under a tracer (state t)".to_string(),
            Held::Frozen => "in a frozen cgroup (cgroup.freeze)".to_string(),
        }
    }
}

fn tracer_of(pid: u32) -> Option<u32> {

    let status = String::from_utf8_lossy(&std::fs::read(format!("/proc/{pid}/status")).ok()?).into_owned();
    let tracer: u32 = status.lines().find_map(|l| l.strip_prefix("TracerPid:"))?.trim().parse().ok()?;
    (tracer != 0).then_some(tracer)
}

fn cgroup_frozen(pid: u32) -> bool {
    let Ok(groups) = std::fs::read_to_string(format!("/proc/{pid}/cgroup")) else { return false };
    let Some(path) = unified_path(&groups) else { return false };
    std::fs::read_to_string(format!("/sys/fs/cgroup{path}/cgroup.events"))
        .is_ok_and(|e| events_say_frozen(&e))
}

fn unified_path(groups: &str) -> Option<&str> {
    let path = groups.lines().find_map(|l| l.strip_prefix("0::"))?;
    (!path.split('/').any(|c| c == "..")).then_some(path)
}

fn events_say_frozen(events: &str) -> bool {
    events.lines().any(|l| l.trim() == "frozen 1")
}

fn stat_fields(pid: u32) -> Option<(char, u64)> {
    let stat = std::fs::read(format!("/proc/{pid}/stat")).ok()?;

    let stat = String::from_utf8_lossy(&stat);
    let tail = stat.rsplit_once(')')?.1;

    let mut f = tail.split_whitespace();
    let state = f.next()?.chars().next()?;
    let start = f.nth(18)?.parse().ok()?;
    Some((state, start))
}

fn start_time(pid: u32) -> Option<u64> {
    stat_fields(pid).map(|(_, t)| t)
}

fn reap() {
    loop {
        let mut status: libc::c_int = 0;

        let pid = unsafe { libc::waitpid(-1, core::ptr::addr_of_mut!(status), libc::WNOHANG) };
        if pid <= 0 {
            return;
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Stopped {

    Asked {

        relaunches: usize,
    },

    GaveUp {

        attempts: usize,
    },

    Failed {

        reason: String,
    },
}

pub fn relaunch(image: &Sealed, argv: &[String], env: &[(String, String)]) -> Result<u32, String> {
    use std::os::fd::AsRawFd as _;

    if !image.sealed() {
        return Err(
            "refusing to relaunch: the image descriptor is no longer sealed, so what it \
             holds is not what was verified"
                .into(),
        );
    }

    let c_args: Vec<std::ffi::CString> = argv
        .iter()
        .map(|a| std::ffi::CString::new(a.as_str()).unwrap_or_else(|_| c"".to_owned()))
        .collect();
    let mut argp: Vec<*const libc::c_char> = c_args.iter().map(|a| a.as_ptr()).collect();
    argp.push(core::ptr::null());

    let c_env: Vec<std::ffi::CString> = env
        .iter()
        .filter(|(k, _)| !k.is_empty() && !k.contains('='))
        .filter_map(|(k, v)| std::ffi::CString::new(format!("{k}={v}")).ok())
        .collect();
    let mut envp: Vec<*const libc::c_char> = c_env.iter().map(|e| e.as_ptr()).collect();
    envp.push(core::ptr::null());

    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(format!("fork failed: {}", std::io::Error::last_os_error()));
    }
    if pid == 0 {

        unsafe {
            let devnull = libc::open(c"/dev/null".as_ptr(), libc::O_RDWR);
            if devnull >= 0 {
                libc::dup2(devnull, 0);
                libc::dup2(devnull, 1);
                libc::dup2(devnull, 2);
                if devnull > 2 {
                    libc::close(devnull);
                }
            }
        }

        unsafe {
            libc::fexecve(image.as_fd().as_raw_fd(), argp.as_ptr(), envp.as_ptr());

            libc::_exit(127);
        }
    }
    Ok(pid as u32)
}

pub fn now_ms() -> u64 {
    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };

    let rc = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, core::ptr::addr_of_mut!(ts)) };
    if rc != 0 {
        return 0;
    }
    (ts.tv_sec as u64)
        .saturating_mul(1_000)
        .saturating_add((ts.tv_nsec as u64) / 1_000_000)
}

pub fn boot_ns() -> Option<u64> {
    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };

    let rc = unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, core::ptr::addr_of_mut!(ts)) };
    if rc != 0 {
        return None;
    }
    let secs = u64::try_from(ts.tv_sec).ok()?;
    let nanos = u64::try_from(ts.tv_nsec).ok()?;
    secs.checked_mul(1_000_000_000)?.checked_add(nanos)
}

#[allow(clippy::too_many_arguments)]
pub fn supervise(
    target: Target,
    image: &Sealed,
    argv: &[String],
    env: &[(String, String)],
    policy: &Policy,
    poll_ms: u64,
    should_continue: impl FnMut() -> bool,
    on_event: impl FnMut(&str),
) -> Stopped {

    supervise_with(target, image, argv, env, policy, poll_ms, |_| Claim::Mine, should_continue, on_event)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Claim {

    Mine,

    Adopted(Target),

    Peer,
}

#[allow(clippy::too_many_arguments)]
pub fn supervise_with(
    mut target: Target,
    image: &Sealed,
    argv: &[String],
    env: &[(String, String)],
    policy: &Policy,
    poll_ms: u64,
    mut claim: impl FnMut(&[String]) -> Claim,
    mut should_continue: impl FnMut() -> bool,
    mut on_event: impl FnMut(&str),
) -> Stopped {
    let mut history = History::new();

    let mut peer_since: Option<u64> = None;
    let mut peer_said: Option<u64> = None;

    let mut held_since: Option<u64> = None;
    let mut held_said = false;
    loop {
        if !should_continue() {
            return Stopped::Asked { relaunches: history.in_window(now_ms(), policy.window_ms) };
        }

        reap();
        if target.alive() {

            let now = now_ms();
            match target.held() {
                Some(how) => {
                    let since = *held_since.get_or_insert(now);
                    if !held_said && now.saturating_sub(since) >= policy.held_ms {
                        on_event(&format!(
                            "P0: THE AGENT IS NOT RUNNING: pid {} is alive but {} and has been for \
                             {}ms. Not relaunching — it still holds its store, and a second agent \
                             beside it is the worse failure. Whether to resume it is the \
                             operator's call",
                            target.pid,
                            how.describe(),
                            now.saturating_sub(since)
                        ));
                        held_said = true;
                    }
                }
                None => {
                    if held_said {
                        on_event(&format!(
                            "pid {} is running again after being held for {}ms",
                            target.pid,
                            now.saturating_sub(held_since.unwrap_or(now))
                        ));
                    }
                    held_since = None;
                    held_said = false;
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(poll_ms));
            continue;
        }
        held_since = None;
        held_said = false;

        match claim(argv) {
            Claim::Mine => {}
            Claim::Adopted(t) => {
                on_event(&format!(
                    "a peer relaunched the agent as pid {}; adopting it rather than starting a \
                     second one",
                    t.pid
                ));
                target = t;
                peer_since = None;
                peer_said = None;
                continue;
            }
            Claim::Peer => {
                let now = now_ms();
                let since = *peer_since.get_or_insert(now);
                let due = peer_said.map_or(true, |t| now.saturating_sub(t) >= policy.peer_standby_ms);
                if now.saturating_sub(since) >= policy.peer_standby_ms && due {
                    on_event(&format!(
                        "NO AGENT IS RUNNING: it died {}ms ago and the claim to relaunch it is \
                         held by something that has not done so — a dead or wedged peer \
                         sentinel, or a local process squatting the lease. Standing by, because \
                         two agents is the worse failure; find the holder",
                        now.saturating_sub(since)
                    ));
                    peer_said = Some(now);
                }
                std::thread::sleep(std::time::Duration::from_millis(poll_ms));
                continue;
            }
        }
        peer_since = None;
        peer_said = None;

        let now = now_ms();
        history.prune(now, policy.window_ms);
        match next(policy, &history, now) {
            Next::GiveUp { attempts } => {
                on_event(&format!(
                    "giving up after {attempts} relaunch(es) inside {}ms — the agent will not \
                     stay up, and a supervisor that kept trying would be the crash loop it is \
                     supposed to end",
                    policy.window_ms
                ));
                return Stopped::GaveUp { attempts };
            }
            Next::Backoff { wait_ms } => {
                std::thread::sleep(std::time::Duration::from_millis(wait_ms.min(poll_ms.max(1))));
            }
            Next::Relaunch => match relaunch(image, argv, env) {
                Ok(pid) => {
                    history.record(now_ms());
                    match Target::of(pid) {
                        Some(t) => {
                            target = t;
                            on_event(&format!("relaunched as pid {pid} from the sealed image"));
                        }

                        None => on_event(&format!(
                            "relaunched as pid {pid}, which did not survive long enough to be \
                             identified"
                        )),
                    }
                }
                Err(reason) => {
                    on_event(&format!("relaunch failed: {reason}"));
                    return Stopped::Failed { reason };
                }
            },
        }
    }
}

pub fn argv_of(pid: u32) -> Option<Vec<String>> {

    let mut raw = Vec::new();
    std::io::Read::read_to_end(
        &mut std::io::Read::take(std::fs::File::open(format!("/proc/{pid}/cmdline")).ok()?, 1 << 20),
        &mut raw,
    )
    .ok()?;

    let argv: Vec<String> = raw
        .split(|b| *b == 0)
        .filter(|s| !s.is_empty())
        .map(|s| String::from_utf8_lossy(s).into_owned())
        .collect();
    if argv.is_empty() {
        None
    } else {
        Some(argv)
    }
}

pub fn environ_of(pid: u32) -> Option<Vec<(String, String)>> {
    let mut raw = Vec::new();
    std::io::Read::read_to_end(
        &mut std::io::Read::take(std::fs::File::open(format!("/proc/{pid}/environ")).ok()?, 1 << 20),
        &mut raw,
    )
    .ok()?;
    Some(
        raw.split(|b| *b == 0)
            .filter_map(|kv| {
                let kv = String::from_utf8_lossy(kv);
                let (k, v) = kv.split_once('=')?;
                Some((k.to_string(), v.to_string()))
            })
            .collect(),
    )
}

pub fn image_digest_of(pid: u32) -> Option<String> {

    let bytes = std::fs::read(format!("/proc/{pid}/exe")).ok()?;
    Some(crate::image::digest(&bytes))
}

pub fn find_by(digest: &str, argv: &[String], skip: u32) -> Option<Target> {
    let entries = std::fs::read_dir("/proc").ok()?;
    for e in entries.flatten() {
        let Some(pid) = e.file_name().to_str().and_then(|n| n.parse::<u32>().ok()) else {
            continue;
        };
        if pid == skip {
            continue;
        }

        if argv_of(pid).as_deref() != Some(argv) {
            continue;
        }
        if image_digest_of(pid).as_deref() != Some(digest) {
            continue;
        }
        if let Some(t) = Target::of(pid) {
            if t.alive() {
                return Some(t);
            }
        }
    }
    None
}

pub fn find_all_where(digest: &str, skip: u32, accept: impl Fn(&[String]) -> bool) -> Vec<Target> {
    let Ok(entries) = std::fs::read_dir("/proc") else { return Vec::new() };
    let mut out = Vec::new();
    for e in entries.flatten() {
        let Some(pid) = e.file_name().to_str().and_then(|n| n.parse::<u32>().ok()) else {
            continue;
        };
        if pid == skip {
            continue;
        }
        if !argv_of(pid).is_some_and(|a| accept(&a)) {
            continue;
        }
        if image_digest_of(pid).as_deref() != Some(digest) {
            continue;
        }
        if let Some(t) = Target::of(pid) {
            if t.alive() {
                out.push(t);
            }
        }
    }
    out
}

pub struct PeerWatch {
    digest: String,
    me: u32,
    accept: Box<dyn Fn(&[String]) -> bool>,
    known: Vec<Target>,

    holds: Vec<(Target, u64, bool)>,
}

impl PeerWatch {

    pub fn sentinels(digest: &str, spec: &str, me: u32) -> Self {
        let spec = spec.to_string();
        Self::matching(digest, me, move |a| is_sentinel_for(a, &spec))
    }

    pub fn matching(digest: &str, me: u32, accept: impl Fn(&[String]) -> bool + 'static) -> Self {
        let mut w = PeerWatch {
            digest: digest.to_string(),
            me,
            accept: Box::new(accept),
            known: Vec::new(),
            holds: Vec::new(),
        };
        w.known = w.scan();
        w
    }

    fn scan(&self) -> Vec<Target> {
        find_all_where(&self.digest, self.me, |a| (self.accept)(a))
    }

    pub fn poll(&mut self) -> Vec<Target> {
        let now = self.scan();
        let gone: Vec<Target> = self.known.iter().filter(|t| !now.contains(t)).copied().collect();
        self.known = now;
        gone
    }

    pub fn held(&mut self, now_ms: u64, after_ms: u64) -> Vec<(Target, Held)> {
        let mut out = Vec::new();
        let mut holds = Vec::new();
        for t in &self.known {
            let Some(how) = t.held() else { continue };
            let (since, said) =
                self.holds.iter().find(|(p, ..)| p == t).map_or((now_ms, false), |&(_, s, d)| (s, d));
            let due = !said && now_ms.saturating_sub(since) >= after_ms;
            if due {
                out.push((*t, how));
            }
            holds.push((*t, since, said || due));
        }
        self.holds = holds;
        out
    }

    pub fn peers(&self) -> usize {
        self.known.len()
    }
}

pub fn is_sentinel_for(argv: &[String], spec: &str) -> bool {
    matches!(argv, [_, s, w, sp] if s == "sentinel" && w == "--watch" && sp == spec)
}

pub fn encode_argv(argv: &[String]) -> String {
    let joined = argv.join("\0");
    joined.bytes().map(|b| format!("{b:02x}")).collect()
}

pub fn decode_argv(hex: &str) -> Option<Vec<String>> {
    if !hex.len().is_multiple_of(2) || hex.is_empty() {
        return None;
    }
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    let raw = hex.as_bytes();
    let mut i = 0;
    while i < raw.len() {
        let pair = hex.get(i..i + 2)?;
        bytes.push(u8::from_str_radix(pair, 16).ok()?);
        i += 2;
    }
    let text = String::from_utf8(bytes).ok()?;
    let argv: Vec<String> = text.split('\0').map(str::to_string).collect();
    if argv.iter().all(|a| a.is_empty()) {
        None
    } else {
        Some(argv)
    }
}
