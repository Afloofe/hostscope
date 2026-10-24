use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs;
use std::io::{Read as _, Seek as _, SeekFrom, Write as _};
use std::path::{Path, PathBuf};
use std::time::Duration;

use hemostat_remote::liveness::{Beat as Arrival, Liveness, Verdict};

use crate::enroll::Enrolled;
use crate::ingest::{Alert, Layout};
use crate::{hex, js};

pub const AGENT_SILENT: Alert = Alert { kind: "agent-silent", severity: "critical" };

pub const CLOCK_JUMP: Alert = Alert { kind: "clock-jump", severity: "warn" };

pub const LOG_EXT: &str = "beats";

pub const LISTENING_FILE: &str = "listening";

pub const MAX_LOG_BYTES: u64 = 64 * 1024 * 1024;

pub const TICK_NS: i64 = 5_000_000_000;

pub const LISTENER_STALE_NS: i64 = 20_000_000_000;

pub const CLOCK_JUMP_NS: i64 = 2_000_000_000;

const NO_STEP_SLACK_NS: i64 = 1_500_000_000;

pub const CLOCK_WINDOW: usize = 8;

pub const SUMMARY_EVERY_NS: i64 = 600 * 1_000_000_000;

const READ_PER_POLL: u64 = 8 * 1024 * 1024;

const NS: i64 = 1_000_000_000;

fn dead_after_ns() -> i64 {
    i64::try_from(Liveness::dead_after().as_nanos()).unwrap_or(i64::MAX)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Beat {

    pub received_ns: i64,

    pub run: u64,

    pub seq: u64,

    pub uptime_secs: u64,

    pub wall_ns: i64,
}

impl Beat {

    pub fn line(&self) -> String {
        format!("{} {} {} {} {}\n", self.received_ns, self.run, self.seq, self.uptime_secs, self.wall_ns)
    }

    pub fn parse(line: &str) -> Option<Beat> {
        let mut it = line.split(' ');
        let b = Beat {
            received_ns: it.next()?.parse().ok()?,
            run: it.next()?.parse().ok()?,
            seq: it.next()?.parse().ok()?,
            uptime_secs: it.next()?.parse().ok()?,
            wall_ns: it.next()?.parse().ok()?,
        };
        it.next().is_none().then_some(b)
    }

    pub fn offset_ns(&self) -> i64 {
        self.received_ns.saturating_sub(self.wall_ns)
    }
}

pub fn log_path(dir: &Path, link: &[u8; 32]) -> PathBuf {
    dir.join(format!("{}.{LOG_EXT}", hex(link)))
}

pub fn append(dir: &Path, link: &[u8; 32], b: &Beat) -> Result<(), String> {
    let path = log_path(dir, link);
    match fs::symlink_metadata(&path) {
        Ok(m) if !m.file_type().is_file() => {
            return Err("the agent's heartbeat log is not a regular file; nothing is written through it".to_string())
        }
        Ok(m) if m.len() >= MAX_LOG_BYTES => {
            return Err(format!("the agent's heartbeat log is full ({MAX_LOG_BYTES} bytes); this beat is not kept"))
        }
        _ => {}
    }
    let mut o = fs::OpenOptions::new();
    o.append(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;

        o.mode(0o640);
    }
    let mut f = o.open(&path).map_err(|e| format!("cannot open the heartbeat log: {e}"))?;
    f.write_all(b.line().as_bytes()).map_err(|e| format!("cannot write the heartbeat log: {e}"))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Listening {

    pub started_ns: i64,

    pub tick_ns: i64,
}

pub fn write_listening(dir: &Path, l: Listening) -> std::io::Result<()> {
    let tmp = dir.join(format!("{LISTENING_FILE}.tmp"));
    let _ = fs::remove_file(&tmp);
    let mut o = fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        o.mode(0o640);
    }
    let mut f = o.open(&tmp)?;
    f.write_all(format!("started_ns={}\ntick_ns={}\n", l.started_ns, l.tick_ns).as_bytes())?;
    drop(f);
    fs::rename(&tmp, dir.join(LISTENING_FILE))
}

pub fn clear_listening(dir: &Path) {
    let _ = fs::remove_file(dir.join(LISTENING_FILE));
}

pub fn read_listening(dir: &Path) -> Option<Listening> {
    let mut text = String::new();
    fs::File::open(dir.join(LISTENING_FILE)).ok()?.take(256).read_to_string(&mut text).ok()?;
    let get = |k: &str| text.lines().find_map(|l| l.strip_prefix(k)?.strip_prefix('=')?.parse::<i64>().ok());
    Some(Listening { started_ns: get("started_ns")?, tick_ns: get("tick_ns")? })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Jump {

    pub from_ns: i64,

    pub to_ns: i64,

    pub host_step_ns: Option<i64>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Clock {
    window: VecDeque<i64>,
    prev: Option<(u64, u64, i64)>,

    pub samples: u64,

    pub jumps: u64,

    pub late: u64,
}

impl Clock {

    pub fn sample(&mut self, b: &Beat) -> Option<Jump> {
        let o = b.offset_ns();
        let host_step_ns = match self.prev {
            Some((run, up, wall)) if run == b.run && b.uptime_secs >= up => {
                let mono = i64::try_from(b.uptime_secs - up).unwrap_or(i64::MAX).saturating_mul(NS);
                Some(b.wall_ns.saturating_sub(wall).saturating_sub(mono))
            }
            _ => None,
        };
        self.prev = Some((b.run, b.uptime_secs, b.wall_ns));
        self.samples += 1;
        let Some(med) = self.offset_ns() else {
            self.window.push_back(o);
            return None;
        };
        if o.saturating_sub(med).saturating_abs() <= CLOCK_JUMP_NS {
            self.window.push_back(o);
            while self.window.len() > CLOCK_WINDOW {
                self.window.pop_front();
            }
            return None;
        }
        if matches!(host_step_ns, Some(s) if s.saturating_abs() <= NO_STEP_SLACK_NS) {
            self.late += 1;
            return None;
        }

        self.jumps += 1;
        self.window.clear();
        self.window.push_back(o);
        Some(Jump { from_ns: med, to_ns: o, host_step_ns })
    }

    pub fn offset_ns(&self) -> Option<i64> {
        let mut v: Vec<i64> = self.window.iter().copied().collect();
        v.sort_unstable();
        let n = v.len();
        match n {
            0 => None,
            _ if n % 2 == 1 => v.get(n / 2).copied(),
            _ => {
                let (a, b) = (v.get(n / 2 - 1).copied()?, v.get(n / 2).copied()?);
                Some(a / 2 + b / 2 + (a % 2 + b % 2) / 2)
            }
        }
    }

    pub fn spread_ns(&self) -> Option<i64> {
        let med = self.offset_ns()?;
        self.window.iter().map(|o| o.saturating_sub(med).saturating_abs()).max()
    }

    pub fn window_len(&self) -> usize {
        self.window.len()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {

    Restarted {

        previous: Option<u64>,
    },

    Lost {

        missing: u64,

        after_seq: u64,
    },

    HeardAgain {

        silent_after: u64,

        silent_from_ns: i64,
    },

    ClockJump(Jump),

    Silent {

        since_ns: i64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Noted {

    pub key: String,

    pub event: Event,

    pub run: u64,

    pub seq: u64,

    pub at_ns: i64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Track {

    pub live: Liveness,

    pub clock: Clock,

    pub last_life: Option<(i64, u64, u64)>,

    pub silent: bool,
}

fn key(link: &str, what: &str, run: u64, seq: Option<u64>) -> String {
    match seq {
        Some(s) => format!("{link}:{what}:{run:016x}:{s}"),
        None => format!("{link}:{what}:{run:016x}"),
    }
}

impl Track {

    pub fn feed(&mut self, link: &str, b: &Beat, known: &BTreeSet<String>) -> Vec<Noted> {
        let before_missing = self.live.missing;
        let before_run = self.live.run;
        let before_life = self.last_life;
        let arrival = self.live.beacon(b.run, b.seq);
        if !arrival.proves_life() {
            return Vec::new();
        }
        let mut out = Vec::new();
        let note = |what: &str, seq: Option<u64>, event: Event| Noted {
            key: key(link, what, b.run, seq),
            event,
            run: b.run,
            seq: b.seq,
            at_ns: b.received_ns,
        };
        if let Some((at, run, seq)) = before_life {
            if known.contains(&key(link, "silent", run, Some(seq))) {
                out.push(note("heard", Some(b.seq), Event::HeardAgain { silent_after: seq, silent_from_ns: at }));
            }
        }
        match arrival {
            Arrival::Restarted => out.push(note("restart", None, Event::Restarted { previous: before_run })),
            Arrival::Fresh if self.live.missing > before_missing => {
                let after_seq = before_life.map_or(0, |(_, _, s)| s);
                out.push(note("lost", Some(b.seq), Event::Lost { missing: self.live.missing - before_missing, after_seq }));
            }
            _ => {}
        }
        self.last_life = Some((b.received_ns, b.run, b.seq));
        self.silent = false;
        if let Some(j) = self.clock.sample(b) {
            out.push(note("jump", Some(b.seq), Event::ClockJump(j)));
        }
        out
    }

    pub fn silence(&self, link: &str, now_ns: i64, listening: Option<Listening>, known: &BTreeSet<String>) -> Option<Noted> {
        let (at, run, seq) = self.last_life?;
        let l = listening?;
        if now_ns.saturating_sub(l.tick_ns) > LISTENER_STALE_NS {
            return None;
        }
        let since_ns = now_ns.saturating_sub(at.max(l.started_ns));
        if since_ns <= dead_after_ns() {
            return None;
        }
        let k = key(link, "silent", run, Some(seq));
        if known.contains(&k) {
            return None;
        }
        Some(Noted { key: k, event: Event::Silent { since_ns }, run, seq, at_ns: now_ns })
    }

    pub fn state(&self) -> &'static str {
        if self.last_life.is_none() {
            "unknown"
        } else if self.silent {
            "silent"
        } else if self.live.missing > 0 {
            "lossy"
        } else {
            "alive"
        }
    }

    fn snapshot(&self) -> String {
        let (last_ns, run, seq) = self.last_life.unwrap_or((0, 0, 0));
        let opt = |v: Option<i64>| v.map_or("null".to_string(), |x| x.to_string());
        format!(
            "\"state\":\"{}\",\"run\":\"{run:016x}\",\"seq\":{seq},\"last_ns\":{last_ns},\"received\":{},\"missing\":{},\
             \"restarts\":{},\"stale\":{},\"offset_ns\":{},\"spread_ns\":{},\"window\":{},\"samples\":{},\"jumps\":{},\"late\":{}",
            self.state(),
            self.live.received,
            self.live.missing,
            self.live.restarts,
            self.live.stale,
            opt(self.clock.offset_ns()),
            opt(self.clock.spread_ns()),
            self.clock.window_len(),
            self.clock.samples,
            self.clock.jumps,
            self.clock.late,
        )
    }
}

pub fn secs(ns: i64) -> String {
    let sign = if ns < 0 { '-' } else { '+' };
    let a = ns.unsigned_abs();
    format!("{sign}{}.{:03}s", a / 1_000_000_000, a % 1_000_000_000 / 1_000_000)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pending {

    pub key: Option<String>,

    pub record: String,

    pub line: String,
}

fn render(e: &Enrolled, link: &str, t: &Track, n: &Noted) -> Pending {
    let who = format!(
        "\"key\":{},\"agent\":{},\"from\":{},\"host\":\"{}\",\"link\":\"{link}\",\"conn\":\"heartbeats/{link}\",\"at_ns\":{}",
        js(&n.key),
        js(&e.label),
        js(&e.label),
        hex(&e.host),
        n.at_ns
    );
    let label = crate::shown(&e.label);
    let (record, line) = match &n.event {
        Event::Silent { since_ns } => {
            let since = Duration::from_nanos(u64::try_from(*since_ns).unwrap_or(0));
            let why = Verdict::Silent { since, last_seq: n.seq }.message();
            (
                format!(
                    "{{\"kind\":\"alert\",\"alert\":\"{}\",\"severity\":\"{}\",{who},\"since_ns\":{since_ns},{},\"why\":{}}}",
                    AGENT_SILENT.kind,
                    AGENT_SILENT.severity,
                    t.snapshot(),
                    js(&format!("{why}. (run {:016x}, judged against a listener that was listening)", n.run))
                ),
                format!("AGENT SILENT {label}: {why}"),
            )
        }
        Event::ClockJump(j) => {
            let by = j.to_ns.saturating_sub(j.from_ns);
            let host = match j.host_step_ns {
                Some(s) => format!(
                    "the host's own wall clock moved {} beyond its monotonic clock since the beat before, so this is \
                     the host's clock being set, not a late beat",
                    secs(s)
                ),
                None => "the beat is the first of a new agent run, so the host's monotonic clock cannot say whether the \
                         beat was late or the clock moved"
                    .to_string(),
            };

            let why = format!(
                "the host's clock stepped {} against the collector's at sequence {} (offset {} -> {}): {host}. Host \
                 times in its stores from before and after the step are not on one scale",
                secs(by.saturating_neg()),
                n.seq,
                secs(j.from_ns),
                secs(j.to_ns)
            );
            (
                format!(
                    "{{\"kind\":\"alert\",\"alert\":\"{}\",\"severity\":\"{}\",{who},\"from_offset_ns\":{},\"to_offset_ns\":{},\
                     \"host_step_ns\":{},{},\"why\":{}}}",
                    CLOCK_JUMP.kind,
                    CLOCK_JUMP.severity,
                    j.from_ns,
                    j.to_ns,
                    j.host_step_ns.map_or("null".to_string(), |s| s.to_string()),
                    t.snapshot(),
                    js(&why)
                ),
                format!("CLOCK JUMP {label}: {why}"),
            )
        }
        Event::Lost { missing, after_seq } => {
            let why = Verdict::Lossy { missing: *missing, seq: n.seq }.message();
            (
                format!(
                    "{{\"kind\":\"heartbeat\",\"event\":\"lost\",{who},\"lost\":{missing},\"after_seq\":{after_seq},{}}}",
                    t.snapshot()
                ),
                format!("lossy {label}: {missing} beacon(s) between {after_seq} and {} never arrived. {why}", n.seq),
            )
        }
        Event::Restarted { previous } => (
            format!(
                "{{\"kind\":\"heartbeat\",\"event\":\"restarted\",{who},\"previous_run\":{},{}}}",
                previous.map_or("null".to_string(), |r| format!("\"{r:016x}\"")),
                t.snapshot()
            ),
            match previous {
                Some(p) => format!("restarted {label}: run {:016x} replaced run {p:016x}", n.run),
                None => format!("heard {label}: run {:016x}, sequence {}", n.run, n.seq),
            },
        ),
        Event::HeardAgain { silent_after, silent_from_ns } => (
            format!(
                "{{\"kind\":\"heartbeat\",\"event\":\"heard-again\",{who},\"silent_after\":{silent_after},\"silent_from_ns\":{silent_from_ns},{}}}",
                t.snapshot()
            ),
            format!(
                "heard again {label}: run {:016x} sequence {}, after silence from sequence {silent_after}. The silent alert \
                 stays until a human resolves it",
                n.run, n.seq
            ),
        ),
    };
    Pending { key: Some(n.key.clone()), record, line }
}

fn summary(e: &Enrolled, link: &str, t: &Track, now_ns: i64) -> Pending {
    let o = t.clock.offset_ns().map_or("not measured".to_string(), secs);
    let s = t.clock.spread_ns().map_or(String::new(), |s| format!(" ± {}", secs(s).trim_start_matches('+')));
    Pending {
        key: None,
        record: format!(
            "{{\"kind\":\"heartbeat\",\"event\":\"summary\",\"agent\":{},\"host\":\"{}\",\"link\":\"{link}\",\"at_ns\":{now_ns},{}}}",
            js(&e.label),
            hex(&e.host),
            t.snapshot()
        ),
        line: format!(
            "heartbeats {}: {} · {} received, {} missing, {} replayed, {} restart(s) · clock offset {o}{s}",
            crate::shown(&e.label),
            t.state(),
            t.live.received,
            t.live.missing,
            t.live.stale,
            t.live.restarts
        ),
    }
}

#[derive(Debug, Default)]
pub struct Watch {
    tracks: BTreeMap<[u8; 32], Track>,
    read: BTreeMap<[u8; 32], u64>,
    recorded: BTreeSet<String>,
    pending: Vec<Pending>,
    last_summary_ns: Option<i64>,
    heard_since_summary: BTreeSet<[u8; 32]>,

    notes: Vec<String>,
}

impl Watch {

    pub fn new(layout: &Layout) -> Result<Watch, String> {
        let mut w = Watch::default();
        let dir = layout.ledger();
        if fs::symlink_metadata(dir.join(crate::ledger::KEY_FILE)).is_err() {
            return Ok(w);
        }
        let pk = crate::ledger::ledger_public_key(&dir)?;
        for run in crate::ledger::audit(&dir, &pk)? {
            for raw in run.records.iter().skip(2) {
                let Some(v) = std::str::from_utf8(raw).ok().and_then(|t| crate::json::parse(t).ok()) else { continue };
                if matches!(v.str_of("kind"), "heartbeat" | "alert") && !v.str_of("link").is_empty() {
                    let k = v.str_of("key");
                    if !k.is_empty() {
                        w.recorded.insert(k.to_string());
                    }
                }
            }
        }
        Ok(w)
    }

    pub fn track(&self, link: &[u8; 32]) -> Option<&Track> {
        self.tracks.get(link)
    }

    pub fn pending(&self) -> &[Pending] {
        &self.pending
    }

    pub fn commit(&mut self) {
        for p in self.pending.drain(..) {
            if let Some(k) = p.key {
                self.recorded.insert(k);
            }
        }
    }

    pub fn take_notes(&mut self) -> Vec<String> {
        std::mem::take(&mut self.notes)
    }

    fn known(&self) -> BTreeSet<String> {
        let mut k = self.recorded.clone();
        k.extend(self.pending.iter().filter_map(|p| p.key.clone()));
        k
    }

    pub fn poll(&mut self, layout: &Layout, enrolled: &[Enrolled], now_ns: i64) -> Result<(), String> {
        let listening = read_listening(&layout.heartbeats());
        self.poll_with(layout, enrolled, now_ns, listening)
    }

    pub fn poll_with(&mut self, layout: &Layout, enrolled: &[Enrolled], now_ns: i64, listening: Option<Listening>) -> Result<(), String> {
        let dir = layout.heartbeats();
        let mut known = self.known();
        for e in enrolled {
            let Some(link) = e.link else { continue };
            let lh = hex(&link);
            let beats = self.read_new(&dir, &link)?;
            let t = self.tracks.entry(link).or_default();
            if !beats.is_empty() {
                self.heard_since_summary.insert(link);
            }
            for b in &beats {
                for n in t.feed(&lh, b, &known) {
                    known.insert(n.key.clone());
                    if !self.recorded.contains(&n.key) {
                        self.pending.push(render(e, &lh, t, &n));
                    }
                }
            }
            if let Some((_, run, seq)) = t.last_life {
                if known.contains(&key(&lh, "silent", run, Some(seq))) {
                    t.silent = true;
                }
            }
            if let Some(n) = t.silence(&lh, now_ns, listening, &known) {
                t.silent = true;
                known.insert(n.key.clone());
                self.pending.push(render(e, &lh, t, &n));
            }
        }
        let due = self.last_summary_ns.is_none_or(|at| now_ns.saturating_sub(at) >= SUMMARY_EVERY_NS);
        if due {
            let first = self.last_summary_ns.is_none();
            for e in enrolled {
                let Some(link) = e.link else { continue };
                let Some(t) = self.tracks.get(&link) else { continue };
                if t.last_life.is_some() && (first || self.heard_since_summary.contains(&link)) {
                    self.pending.push(summary(e, &hex(&link), t, now_ns));
                }
            }
            self.last_summary_ns = Some(now_ns);
            self.heard_since_summary.clear();
        }
        Ok(())
    }

    fn read_new(&mut self, dir: &Path, link: &[u8; 32]) -> Result<Vec<Beat>, String> {
        let path = log_path(dir, link);
        let mut f = match fs::File::open(&path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(format!("cannot open {}: {e}", path.display())),
        };
        let len = f.metadata().map_err(|e| format!("cannot examine {}: {e}", path.display()))?.len();
        let mut at = self.read.get(link).copied().unwrap_or(0);
        if len < at {

            self.notes.push(format!(
                "the heartbeat log of agent {} is shorter than what was already read ({len} < {at} bytes): something \
                 other than the listener changed it. Read again from the start",
                hex(link)
            ));
            at = 0;
            self.tracks.remove(link);
        }
        f.seek(SeekFrom::Start(at)).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        let mut buf = Vec::new();
        f.take(READ_PER_POLL).read_to_end(&mut buf).map_err(|e| format!("cannot read {}: {e}", path.display()))?;

        let whole = buf.iter().rposition(|&b| b == b'\n').map_or(0, |i| i + 1);
        let mut out = Vec::new();
        let mut bad = 0_u64;
        for line in buf.get(..whole).unwrap_or_default().split(|&b| b == b'\n').filter(|l| !l.is_empty()) {
            match std::str::from_utf8(line).ok().and_then(Beat::parse) {
                Some(b) => out.push(b),
                None => bad += 1,
            }
        }
        if bad > 0 {
            self.notes.push(format!("{bad} line(s) of agent {}'s heartbeat log are not heartbeats; skipped", hex(link)));
        }
        self.read.insert(*link, at + whole as u64);
        Ok(out)
    }
}
