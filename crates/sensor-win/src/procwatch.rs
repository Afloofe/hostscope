use std::collections::VecDeque;

use crate::procexec::{ProcStart, Source};

pub const WAIT_MS: u32 = 250;

pub const HEALTH_EVERY_MS: u64 = 5_000;

pub const PULL_LIMIT: usize = 4_096;

pub const RING_CAP: usize = 8_192;

pub const CHANGES_CAP: usize = 1_024;

pub const ERROR_ACCESS_DENIED: u32 = 5;

pub const ERROR_INVALID_OPERATION: u32 = 4_317;

pub const ERROR_EVT_INVALID_CHANNEL_PATH: u32 = 15_000;

pub const ERROR_EVT_CHANNEL_NOT_FOUND: u32 = 15_007;

pub const ERROR_EVT_QUERY_RESULT_STALE: u32 = 15_011;

pub const RPC_GONE: [u32; 6] = [1_717, 1_722, 1_726, 1_727, 1_753, 1_818];

#[derive(Debug, Clone)]
pub struct Ring<T> {
    items: VecDeque<T>,
    cap: usize,
    dropped: u64,
}

impl<T> Ring<T> {

    #[must_use]
    pub fn new(cap: usize) -> Self {
        Self { items: VecDeque::with_capacity(cap.min(1_024)), cap, dropped: 0 }
    }

    pub fn push(&mut self, t: T) {
        if self.cap == 0 {
            self.dropped += 1;
            return;
        }
        if self.items.len() >= self.cap {
            self.items.pop_front();
            self.dropped += 1;
        }
        self.items.push_back(t);
    }

    pub fn drain(&mut self) -> Vec<T> {
        self.items.drain(..).collect()
    }

    #[must_use]
    pub const fn dropped(&self) -> u64 {
        self.dropped
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.items.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    #[must_use]
    pub const fn cap(&self) -> usize {
        self.cap
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Health {

    Live,

    Absent(String),

    NotBuilt(String),

    Unaudited(String),

    Denied(String),

    Disabled(String),

    Stopped(String),

    Stalled(String),

    Failed(String),
}

impl Health {

    #[must_use]
    pub const fn token(&self) -> &'static str {
        match self {
            Health::Live => "live",
            Health::Absent(_) => "absent",
            Health::NotBuilt(_) => "not_built",
            Health::Unaudited(_) => "unaudited",
            Health::Denied(_) => "denied",
            Health::Disabled(_) => "disabled",
            Health::Stopped(_) => "stopped",
            Health::Stalled(_) => "stalled",
            Health::Failed(_) => "failed",
        }
    }

    #[must_use]
    pub fn why(&self) -> Option<&str> {
        match self {
            Health::Live => None,
            Health::Absent(w)
            | Health::NotBuilt(w)
            | Health::Unaudited(w)
            | Health::Denied(w)
            | Health::Disabled(w)
            | Health::Stopped(w)
            | Health::Stalled(w)
            | Health::Failed(w) => Some(w),
        }
    }

    #[must_use]
    pub const fn is_fault(&self) -> bool {
        matches!(
            self,
            Health::Denied(_) | Health::Disabled(_) | Health::Stopped(_) | Health::Stalled(_) | Health::Failed(_)
        )
    }

    #[must_use]
    pub const fn is_live(&self) -> bool {
        matches!(self, Health::Live)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelSeen {

    Enabled,

    Disabled,

    Absent,

    Unreadable(u32),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observed {

    pub service: Option<u32>,

    pub channel: ChannelSeen,

    pub subscription: Result<(), u32>,

    pub audited: Option<bool>,

    pub stalled: Option<u64>,
}

#[must_use]
pub fn classify(source: Source, rc: u32) -> Health {
    let channel = source.channel();
    match rc {
        ERROR_ACCESS_DENIED => Health::Denied(format!(
            "the subscription to {channel} was refused (error 5, access denied): the channel's access \
             does not grant this account read"
        )),
        ERROR_EVT_CHANNEL_NOT_FOUND | ERROR_EVT_INVALID_CHANNEL_PATH => match source {
            Source::Sysmon1 => Health::Absent("Sysmon is not installed: its channel does not exist".into()),
            Source::Security4688 => Health::Failed(format!("the {channel} channel was not found (error {rc})")),
        },
        r if RPC_GONE.contains(&r) => {
            Health::Stopped(format!("the Windows Event Log service did not answer (error {rc})"))
        }
        ERROR_EVT_QUERY_RESULT_STALE => Health::Failed(format!(
            "{channel} overwrote records before the subscription read them (error {rc}); it is reopened \
             after the last record delivered"
        )),
        _ => Health::Failed(format!(
            "the subscription to {channel} failed (error {rc}); it is reopened at the next check"
        )),
    }
}

#[must_use]
pub fn judge(source: Source, o: &Observed) -> Health {
    let channel = source.channel();
    if let Some(st) = o.service {
        if st != crate::sysmon::SERVICE_RUNNING {
            return Health::Stopped(format!(
                "the Windows Event Log service is {}, so no channel is written or delivered",
                crate::sysmon::service_state_name(st)
            ));
        }
    }
    match o.channel {
        ChannelSeen::Absent => {
            return match source {
                Source::Sysmon1 => Health::Absent("Sysmon is not installed: its channel does not exist".into()),
                Source::Security4688 => Health::Failed(format!("the {channel} channel was not found")),
            }
        }
        ChannelSeen::Disabled => {
            return Health::Disabled(format!("{channel} is disabled, so nothing is written to it"))
        }
        ChannelSeen::Enabled | ChannelSeen::Unreadable(_) => {}
    }
    if let Err(rc) = o.subscription {
        return classify(source, rc);
    }
    if let Some(r) = o.stalled {
        return Health::Stalled(format!(
            "{channel} holds record {r}, which the subscription has not delivered since the previous check"
        ));
    }
    if source == Source::Security4688 && o.audited == Some(false) {
        return Health::Unaudited(
            "Process Creation is not audited for success, so Security writes no 4688. \
             `auditpol /set /subcategory:{0CCE922B-69AE-11D9-BED3-505054503030} /success:enable` \
             turns it on"
                .into(),
        );
    }
    Health::Live
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct StallWatch {
    pending: Option<u64>,
}

impl StallWatch {

    pub fn check(&mut self, newest: Option<u64>, delivered: Option<u64>) -> Option<u64> {
        let Some(n) = newest else {
            self.pending = None;
            return None;
        };
        if delivered.is_some_and(|d| d >= n) {
            self.pending = None;
            return None;
        }
        match self.pending {
            Some(p) if delivered.is_none_or(|d| d < p) => Some(p),
            _ => {
                self.pending = Some(n);
                None
            }
        }
    }

    pub fn reset(&mut self) {
        self.pending = None;
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Arrival {

    pub start: ProcStart,

    pub seen: i64,
}

impl Arrival {

    #[must_use]
    pub fn latency_ms(&self) -> Option<i64> {
        self.start.time.map(|t| (self.seen - t) / 10_000)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceStatus {

    pub source: Source,

    pub health: Health,

    pub since: i64,

    pub delivered: u64,

    pub foreign: u64,

    pub unrendered: u64,

    pub last_record: Option<u64>,

    pub reopened: u32,

    pub resume_error: Option<u32>,

    pub caught_up: u64,
}

impl SourceStatus {

    #[must_use]
    pub const fn new(source: Source, health: Health, since: i64) -> Self {
        Self {
            source,
            health,
            since,
            delivered: 0,
            foreign: 0,
            unrendered: 0,
            last_record: None,
            reopened: 0,
            resume_error: None,
            caught_up: 0,
        }
    }
}

#[must_use]
pub fn catch_up_xpath(source: Source, after: u64) -> String {
    format!("*[System[(EventID={}) and (EventRecordID > {after})]]", source.event_id())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Change {

    pub at: i64,

    pub source: Source,

    pub from: Option<Health>,

    pub to: Health,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Drain {

    pub arrivals: Vec<Arrival>,

    pub dropped: u64,

    pub changes_dropped: u64,

    pub changes: Vec<Change>,

    pub status: Vec<SourceStatus>,
}

const FILETIME_UNIX: i64 = 116_444_736_000_000_000;

#[must_use]
pub fn filetime_now() -> i64 {
    let ns = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_nanos()).unwrap_or(i64::MAX));
    ns / 100 + FILETIME_UNIX
}

#[cfg(target_os = "windows")]
pub use live::Live;

#[cfg(target_os = "windows")]
mod live {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use windows_sys::Win32::Foundation::{
        CloseHandle, GetLastError, ERROR_NO_MORE_ITEMS, ERROR_TIMEOUT, HANDLE, WAIT_OBJECT_0,
    };
    use windows_sys::Win32::System::EventLog::{
        EvtChannelConfigEnabled, EvtClose, EvtCreateBookmark, EvtGetChannelConfigProperty, EvtNext,
        EvtOpenChannelConfig, EvtSubscribe, EvtSubscribeStartAfterBookmark, EvtSubscribeStrict,
        EvtSubscribeToFutureEvents, EvtUpdateBookmark, EvtVarTypeBoolean, EVT_HANDLE, EVT_VARIANT,
    };
    use windows_sys::Win32::System::Threading::{
        CreateEventW, ResetEvent, SetEvent, WaitForMultipleObjects, WaitForSingleObject,
    };

    use super::{
        classify, filetime_now, judge, Arrival, Change, ChannelSeen, Drain, Health, Observed, Ring,
        SourceStatus, StallWatch, CHANGES_CAP, ERROR_EVT_CHANNEL_NOT_FOUND, ERROR_EVT_INVALID_CHANNEL_PATH,
        HEALTH_EVERY_MS, PULL_LIMIT, WAIT_MS,
    };
    use crate::evtlog::{render, render_context, wide};
    use crate::procexec::{self, Source};

    struct Shared {
        ring: Ring<Arrival>,
        changes: Ring<Change>,
        status: Vec<SourceStatus>,
        ready: bool,
    }

    pub struct Live {
        shared: Arc<Mutex<Shared>>,
        stop: Arc<AtomicBool>,
        thread: Option<std::thread::JoinHandle<()>>,
    }

    impl Live {

        #[must_use]
        pub fn start(security: Result<(), String>, sysmon: Result<(), String>, cap: usize) -> Self {
            let shared = Arc::new(Mutex::new(Shared {
                ring: Ring::new(cap),
                changes: Ring::new(CHANGES_CAP),
                status: Vec::new(),
                ready: false,
            }));
            let stop = Arc::new(AtomicBool::new(false));
            let (s, t) = (Arc::clone(&shared), Arc::clone(&stop));
            let thread = std::thread::Builder::new()
                .name("hemostat-procwatch".into())
                .spawn(move || run(&s, &t, [sysmon, security]))
                .ok();
            let live = Self { shared, stop, thread };
            let until = Instant::now() + Duration::from_secs(10);
            while Instant::now() < until && !live.shared.lock().is_ok_and(|g| g.ready) {
                std::thread::sleep(Duration::from_millis(20));
            }
            live
        }

        #[must_use]
        pub fn running(&self) -> bool {
            self.thread.as_ref().is_some_and(|t| !t.is_finished())
        }

        #[must_use]
        pub fn drain(&self) -> Drain {
            let Ok(mut g) = self.shared.lock() else {
                return Drain::default();
            };
            Drain {
                arrivals: g.ring.drain(),
                dropped: g.ring.dropped(),
                changes_dropped: g.changes.dropped(),
                changes: g.changes.drain(),
                status: g.status.clone(),
            }
        }
    }

    impl Drop for Live {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Relaxed);
            if let Some(t) = self.thread.take() {
                let _ = t.join();
            }
        }
    }

    fn run(shared: &Mutex<Shared>, stop: &AtomicBool, built: [Result<(), String>; 2]) {
        let mut feeds: Vec<Feed> = Source::ALL.iter().zip(built).map(|(s, b)| Feed::new(*s, b)).collect();
        let service = crate::sysmon::service_state("EventLog");
        for f in &mut feeds {
            f.check(service);
        }
        publish(shared, &mut feeds, Vec::new(), true);
        let mut next = Instant::now() + Duration::from_millis(HEALTH_EVERY_MS);
        while !stop.load(Ordering::Relaxed) {
            let signals: Vec<HANDLE> = feeds.iter().filter(|f| f.sub != 0).map(|f| f.signal).collect();
            if signals.is_empty() {
                std::thread::sleep(Duration::from_millis(u64::from(WAIT_MS)));
            } else {

                unsafe { WaitForMultipleObjects(signals.len() as u32, signals.as_ptr(), 0, WAIT_MS) };
            }
            let mut arrivals = Vec::new();
            for f in &mut feeds {
                f.pull(&mut arrivals);
            }
            if Instant::now() >= next {
                let service = crate::sysmon::service_state("EventLog");
                for f in &mut feeds {
                    f.check(service);
                }
                next = Instant::now() + Duration::from_millis(HEALTH_EVERY_MS);
            }
            publish(shared, &mut feeds, arrivals, false);
        }
    }

    fn publish(shared: &Mutex<Shared>, feeds: &mut [Feed], arrivals: Vec<Arrival>, ready: bool) {
        let Ok(mut g) = shared.lock() else { return };
        for a in arrivals {
            g.ring.push(a);
        }
        for f in feeds.iter_mut() {
            for c in f.changes.drain(..) {
                g.changes.push(c);
            }
        }
        g.status = feeds.iter().map(|f| f.status.clone()).collect();
        if ready {
            g.ready = true;
        }
    }

    struct Feed {
        source: Source,
        built: Result<(), String>,

        signal: HANDLE,

        sub: EVT_HANDLE,

        ctx: EVT_HANDLE,

        want: usize,

        bookmark: EVT_HANDLE,

        bookmarked: bool,

        last_err: Option<u32>,

        opened_once: bool,

        checked: bool,
        stall: StallWatch,

        policy: Option<bool>,
        status: SourceStatus,
        changes: Vec<Change>,

        pending: Vec<Arrival>,

        caught: std::collections::HashSet<u64>,
    }

    impl Feed {
        fn new(source: Source, built: Result<(), String>) -> Self {

            let signal = unsafe { CreateEventW(std::ptr::null(), 1, 0, std::ptr::null()) };
            let start = match &built {
                Ok(()) => Health::Failed("not checked yet".into()),
                Err(why) => Health::NotBuilt(why.clone()),
            };
            Self {
                source,
                built,
                signal,
                sub: 0,
                ctx: 0,
                want: 0,
                bookmark: 0,
                bookmarked: false,
                last_err: None,
                opened_once: false,
                checked: false,
                stall: StallWatch::default(),
                policy: None,
                status: SourceStatus::new(source, start, filetime_now()),
                changes: Vec::new(),
                pending: Vec::new(),
                caught: std::collections::HashSet::new(),
            }
        }

        fn paths(&self) -> &'static [&'static str] {
            match self.source {
                Source::Security4688 => &procexec::PATHS_4688,
                Source::Sysmon1 => &procexec::PATHS_SYSMON1,
            }
        }

        fn set(&mut self, h: Health, first: bool) {
            if first || self.status.health.token() != h.token() {
                let now = filetime_now();
                self.changes.push(Change {
                    at: now,
                    source: self.source,
                    from: if first { None } else { Some(self.status.health.clone()) },
                    to: h.clone(),
                });
                self.status.since = now;
            }
            self.status.health = h;
        }

        fn close_sub(&mut self) {
            if self.sub != 0 {

                unsafe { EvtClose(self.sub) };
                self.sub = 0;
            }

            if !self.signal.is_null() {

                unsafe { ResetEvent(self.signal) };
            }
        }

        fn open(&mut self) {
            if self.sub != 0 || self.built.is_err() {
                return;
            }
            if self.signal.is_null() {

                self.last_err = Some(unsafe { GetLastError() });
                return;
            }
            if self.ctx == 0 {
                match render_context(self.paths()) {
                    Ok((c, w)) => (self.ctx, self.want) = (c, w),
                    Err(_) => {

                        self.last_err = Some(unsafe { GetLastError() });
                        return;
                    }
                }
            }
            if self.bookmark == 0 {

                self.bookmark = unsafe { EvtCreateBookmark(std::ptr::null()) };
                if self.bookmark == 0 {

                    self.last_err = Some(unsafe { GetLastError() });
                    return;
                }
            }
            let reopen = self.opened_once;
            let mut refused = None;
            if self.bookmarked {
                match self.subscribe(true) {
                    Ok(h) => {
                        self.sub = h;
                        self.after_open(reopen, false);
                        return;
                    }
                    Err(rc) if rc == super::ERROR_ACCESS_DENIED || super::RPC_GONE.contains(&rc) => {
                        self.last_err = Some(rc);
                        return;
                    }
                    Err(rc) => refused = Some(rc),
                }
            }
            match self.subscribe(false) {
                Ok(h) => {
                    self.sub = h;
                    let delivered = self.status.last_record;
                    self.after_open(reopen, true);
                    if let (Some(rc), Some(after)) = (refused, delivered) {
                        self.catch_up(rc, after);
                    }
                }
                Err(rc) => self.last_err = Some(rc),
            }
        }

        fn catch_up(&mut self, rc: u32, after: u64) {
            self.status.resume_error = Some(rc);
            self.caught.clear();
            let ceiling = self.status.last_record;
            let channel = self.source.channel();
            let read = crate::evtlog::read_records(
                channel,
                &super::catch_up_xpath(self.source, after),
                PULL_LIMIT,
                self.paths(),
            );
            let why = match read {
                Ok(mut recs) => {
                    let capped = recs.len() >= PULL_LIMIT;
                    recs.sort_by_key(|r| r.id);
                    let seen = filetime_now();
                    for r in recs.iter().filter(|r| ceiling.is_none_or(|c| r.id <= c)) {
                        self.caught.insert(r.id);
                        self.status.caught_up += 1;
                        if let Some(a) = self.normalise(r, seen) {
                            self.pending.push(a);
                        }
                    }
                    if !capped {
                        return;
                    }
                    format!("the catch-up query stopped at {PULL_LIMIT} records, so older ones were not delivered")
                }
                Err(e) => format!("the catch-up query failed ({e}), so records written meanwhile were not delivered"),
            };
            let h = Health::Failed(format!(
                "the subscription to {channel} could not resume after record {after} (error {rc}) and was \
                 reopened from new records; {why}"
            ));
            self.set(h, false);
        }

        fn normalise(&mut self, r: &crate::evtlog::Rendered, seen: i64) -> Option<Arrival> {
            if !crate::evtlog::from_provider(r.provider, self.source.provider()) {
                self.status.foreign += 1;
                return None;
            }
            let start = match self.source {
                Source::Security4688 => procexec::from_4688(&procexec::raw_4688(r), self.policy),
                Source::Sysmon1 => procexec::from_sysmon1(&procexec::raw_sysmon1(r)),
            };
            Some(Arrival { start, seen })
        }

        fn subscribe(&self, after_bookmark: bool) -> Result<EVT_HANDLE, u32> {
            let channel = wide(self.source.channel());
            let query = wide(&procexec::xpath(self.source));
            let (bookmark, flags) = if after_bookmark {
                (self.bookmark, EvtSubscribeStartAfterBookmark | EvtSubscribeStrict)
            } else {
                (0, EvtSubscribeToFutureEvents)
            };

            let h = unsafe {
                EvtSubscribe(0, self.signal, channel.as_ptr(), query.as_ptr(), bookmark, std::ptr::null(), None, flags)
            };
            if h == 0 {

                Err(unsafe { GetLastError() })
            } else {
                Ok(h)
            }
        }

        fn after_open(&mut self, reopen: bool, fresh: bool) {
            self.last_err = None;
            self.opened_once = true;

            unsafe { SetEvent(self.signal) };
            self.stall.reset();
            if reopen {
                self.status.reopened += 1;
            }
            if fresh {
                let newest = newest_record(self.source);
                self.status.last_record = self.status.last_record.max(newest);
            }
        }

        fn pull(&mut self, out: &mut Vec<Arrival>) {
            out.append(&mut self.pending);
            if self.sub == 0 {
                return;
            }

            if unsafe { WaitForSingleObject(self.signal, 0) } != WAIT_OBJECT_0 {
                return;
            }

            unsafe { ResetEvent(self.signal) };
            let mut batch: [EVT_HANDLE; 64] = [0; 64];
            let mut pulled = 0_usize;
            loop {
                let mut returned: u32 = 0;

                let ok = unsafe {
                    EvtNext(self.sub, batch.len() as u32, batch.as_mut_ptr(), 0, 0, std::ptr::addr_of_mut!(returned))
                };
                if ok == 0 {

                    let rc = unsafe { GetLastError() };
                    if rc != ERROR_NO_MORE_ITEMS && rc != ERROR_TIMEOUT && rc != super::ERROR_INVALID_OPERATION {
                        self.last_err = Some(rc);
                        self.close_sub();
                        self.set(classify(self.source, rc), false);
                    }
                    break;
                }
                let seen = filetime_now();
                for h in batch.iter().take(returned as usize) {

                    if unsafe { EvtUpdateBookmark(self.bookmark, *h) } != 0 {
                        self.bookmarked = true;
                    }
                    self.status.delivered += 1;
                    match render(self.ctx, *h, self.want) {
                        Some(r) => {
                            self.status.last_record = self.status.last_record.max(Some(r.id));

                            if !self.caught.remove(&r.id) {
                                if let Some(a) = self.normalise(&r, seen) {
                                    out.push(a);
                                }
                            }
                        }
                        None => self.status.unrendered += 1,
                    }

                    unsafe { EvtClose(*h) };
                }
                pulled += returned as usize;
                if returned == 0 {
                    break;
                }
                if pulled >= PULL_LIMIT {

                    unsafe { SetEvent(self.signal) };
                    break;
                }
            }
        }

        fn check(&mut self, service: Option<u32>) {
            let first = !self.checked;
            self.checked = true;
            if let Err(why) = &self.built {
                let h = Health::NotBuilt(why.clone());
                self.set(h, first);
                return;
            }
            let running = service.is_none_or(|s| s == crate::sysmon::SERVICE_RUNNING);
            if self.sub == 0 && running {
                self.open();
            }
            let channel = channel_seen(self.source.channel());
            let audited = match self.source {
                Source::Security4688 => {
                    self.policy = crate::evtlog::command_line_policy();
                    crate::evtlog::read_process_creation_audit().ok()
                }
                Source::Sysmon1 => None,
            };
            let stalled = if self.sub != 0 {
                let newest = newest_record(self.source);
                self.stall.check(newest, self.status.last_record)
            } else {
                self.stall.reset();
                None
            };
            let subscription = if self.sub != 0 { Ok(()) } else { Err(self.last_err.unwrap_or(0)) };
            let h = judge(self.source, &Observed { service, channel, subscription, audited, stalled });
            self.set(h, first);
        }
    }

    impl Drop for Feed {
        fn drop(&mut self) {
            self.close_sub();

            unsafe {
                if self.ctx != 0 {
                    EvtClose(self.ctx);
                }
                if self.bookmark != 0 {
                    EvtClose(self.bookmark);
                }
                if !self.signal.is_null() {
                    CloseHandle(self.signal);
                }
            }
        }
    }

    fn newest_record(source: Source) -> Option<u64> {
        crate::evtlog::read_records(source.channel(), &procexec::xpath(source), 1, &[])
            .ok()
            .and_then(|v| v.iter().map(|r| r.id).max())
    }

    fn channel_seen(name: &str) -> ChannelSeen {
        let path = wide(name);

        let cfg = unsafe { EvtOpenChannelConfig(0, path.as_ptr(), 0) };
        if cfg == 0 {

            let rc = unsafe { GetLastError() };
            return if rc == ERROR_EVT_CHANNEL_NOT_FOUND || rc == ERROR_EVT_INVALID_CHANNEL_PATH {
                ChannelSeen::Absent
            } else {
                ChannelSeen::Unreadable(rc)
            };
        }

        let mut v: EVT_VARIANT = unsafe { std::mem::zeroed() };
        let mut used: u32 = 0;

        let ok = unsafe {
            EvtGetChannelConfigProperty(
                cfg,
                EvtChannelConfigEnabled,
                0,
                std::mem::size_of::<EVT_VARIANT>() as u32,
                std::ptr::addr_of_mut!(v),
                std::ptr::addr_of_mut!(used),
            )
        };

        let rc = if ok == 0 { unsafe { GetLastError() } } else { 0 };

        unsafe { EvtClose(cfg) };
        if ok == 0 {
            return ChannelSeen::Unreadable(rc);
        }
        if v.Type != EvtVarTypeBoolean as u32 {
            return ChannelSeen::Unreadable(0);
        }

        if unsafe { v.Anonymous.BooleanVal } != 0 {
            ChannelSeen::Enabled
        } else {
            ChannelSeen::Disabled
        }
    }
}
