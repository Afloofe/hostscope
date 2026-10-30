#[cfg(any(test, all(target_os = "windows", feature = "mod-tui")))]
use hemostat_detect::{Level, RuleSet};
#[cfg(any(test, all(target_os = "windows", feature = "mod-tui")))]
use hemostat_sensor_win::posture::Finding;
use hemostat_sensor_win::procexec::{self, Collection, ReadState, MAPPING};
#[cfg(any(test, all(target_os = "windows", feature = "mod-tui")))]
use hemostat_sensor_win::Severity;
use hs_core::identity::{AgentId, EngagementId, HostId, InstanceId};
use hs_core::time::BootId;
use hs_core::Origin;

#[cfg(any(test, all(target_os = "windows", feature = "mod-tui")))]
use crate::analysis::event_line;
use crate::analysis::DetectInput;
use crate::render::json_str;

fn origin() -> Origin {
    Origin {
        engagement: EngagementId::from_bytes([0; 16]),
        host: HostId::from_bytes([0; 32]),
        agent: AgentId::from_bytes([0; 16]),
        instance: InstanceId::from_bytes([0; 16]),
    }
}

fn when(ft: Option<i64>) -> String {
    ft.map_or_else(|| "no time".into(), hemostat_sensor_win::provenance::utc)
}

fn state_token(s: &ReadState) -> &'static str {
    match s {
        ReadState::Read => "read",
        ReadState::Absent(_) => "absent",
        ReadState::NotBuilt(_) => "not_built",
        ReadState::Failed(_) => "failed",
    }
}

pub(crate) fn input(c: &Collection, own_image: Option<&str>) -> DetectInput {
    let boot = BootId::from_bytes([0; 16]);
    let o = origin();
    let mut events = Vec::with_capacity(c.starts.len());
    let mut about = Vec::with_capacity(c.starts.len());
    let mut own = 0_usize;
    for s in &c.starts {
        let ours = match (own_image, s.parent_image.as_deref()) {
            (Some(me), Some(parent)) => parent.eq_ignore_ascii_case(me),
            _ => false,
        };
        if ours {
            own += 1;
            continue;
        }
        let seq = u64::try_from(events.len()).unwrap_or(u64::MAX);
        events.push(s.to_event(seq, boot, o));
        about.push(format!("{} record {}, {}", s.source.name(), s.record_id, when(s.time)));
    }

    let mut notes = Vec::new();
    let mut gaps = Vec::new();
    let mut json = Vec::new();
    for r in &c.sources {
        let name = r.source.name();
        let line = match &r.state {
            ReadState::Read => {
                let span = r.span.map_or_else(String::new, |(a, b)| {
                    format!(", {} to {}", when(Some(a)), when(Some(b)))
                });
                let cap = if r.capped {
                    format!(" — the newest {}, so older records were NOT evaluated", procexec::READ_CAP)
                } else {
                    String::new()
                };
                let foreign = if r.foreign > 0 {
                    format!("; {} skipped as not from the source's provider", r.foreign)
                } else {
                    String::new()
                };
                format!("{name}: {} record(s){span}{cap}{foreign}", r.records)
            }
            ReadState::Absent(why) => format!("{name}: none — {why}"),
            ReadState::NotBuilt(why) => format!("{name}: not read — {why}"),
            ReadState::Failed(why) => {
                gaps.push(format!("{name}: {why}"));
                format!("{name}: NOT read — {why}")
            }
        };
        notes.push(line);
        for (f, why, n) in &r.lacks {
            notes.push(format!("  {name} lacks {f} in {n} record(s): {why}"));
        }
        let lacks: Vec<String> = r
            .lacks
            .iter()
            .map(|(f, why, n)| {
                format!("{{\"field\":{},\"why\":{},\"records\":{n}}}", json_str(f.as_str()), json_str(why))
            })
            .collect();
        let why = match &r.state {
            ReadState::Read => "null".to_string(),
            ReadState::Absent(w) | ReadState::NotBuilt(w) | ReadState::Failed(w) => json_str(w),
        };
        json.push(format!(
            "{{\"source\":{},\"state\":\"{}\",\"why\":{why},\"records\":{},\"foreign\":{},\"capped\":{},\
             \"from\":{},\"to\":{},\"lacks\":[{}]}}",
            json_str(name),
            state_token(&r.state),
            r.records,
            r.foreign,
            r.capped,
            r.span.map_or("null".into(), |(a, _)| json_str(&when(Some(a)))),
            r.span.map_or("null".into(), |(_, b)| json_str(&when(Some(b)))),
            lacks.join(",")
        ));
    }
    if c.merged > 0 {
        notes.push(format!(
            "{} Security 4688 record(s) described a start Sysmon also recorded, and were evaluated once, \
             from Sysmon's record",
            c.merged
        ));
    }
    if own > 0 {
        notes.push(format!(
            "{own} record(s) of a process this agent's own image started were not evaluated ({})",
            own_image.unwrap_or_default()
        ));
        json.push(format!(
            "{{\"source\":\"this agent's own children\",\"state\":\"excluded\",\"why\":{},\"records\":{own}}}",
            json_str(&format!("the parent image is {}", own_image.unwrap_or_default()))
        ));
    }
    notes.push(format!("fields, by source: {}", mapping_line()));

    let no_events = if c.sources.iter().any(|r| matches!(r.state, ReadState::Failed(_))) {
        "no process-start record could be read, so no rule was evaluated against anything. Exit 7."
    } else {
        "neither source holds a process-start record, so no rule was evaluated against anything. \
         Exit 7."
    }
    .to_string();

    DetectInput {
        events,
        about,
        notes,
        gaps,
        sources_json: format!("[{}]", json.join(",")),
        no_events,
    }
}

fn cut_count(n: impl std::fmt::Display, what: &str) -> String {
    format!(
        "{n} {what}(s) had a field over {} bytes, of which only the head and the tail were evaluated — a rule \
         keyed on text in the cut middle could not have matched them",
        hs_core::MAX_FIELD_BYTES
    )
}

fn cut_hit_note() -> String {
    format!(
        "a field of this event was over {} bytes and was cut: its head and tail were evaluated, not its middle",
        hs_core::MAX_FIELD_BYTES
    )
}

fn mapping_line() -> String {
    MAPPING
        .iter()
        .map(|(f, a, b)| {
            format!("{f} = 4688 {} / Sysmon {}", a.unwrap_or("(none)"), b.unwrap_or("(none)"))
        })
        .collect::<Vec<_>>()
        .join("; ")
}

#[cfg(target_os = "windows")]
pub(crate) fn collect() -> DetectInput {
    let me = std::env::current_exe().ok().map(|p| p.display().to_string());
    input(&procexec::collect(security_built(), sysmon_built(), procexec::READ_CAP), me.as_deref())
}

#[cfg(all(target_os = "windows", feature = "mod-sensor-evtlog"))]
fn security_built() -> Result<(), String> {
    Ok(())
}
#[cfg(all(target_os = "windows", not(feature = "mod-sensor-evtlog")))]
fn security_built() -> Result<(), String> {
    Err(hemostat_modules::module_refusal(hemostat_buildinfo::ModuleId::SensorEvtlog, crate::MANIFEST.variant))
}
#[cfg(all(target_os = "windows", feature = "mod-sensor-sysmon"))]
fn sysmon_built() -> Result<(), String> {
    Ok(())
}
#[cfg(all(target_os = "windows", not(feature = "mod-sensor-sysmon")))]
fn sysmon_built() -> Result<(), String> {
    Err(hemostat_modules::module_refusal(hemostat_buildinfo::ModuleId::SensorSysmon, crate::MANIFEST.variant))
}

#[cfg(any(test, all(target_os = "windows", feature = "mod-tui")))]
pub(crate) const fn severity(l: Level) -> Severity {
    match l {
        Level::Critical => Severity::Critical,
        Level::High | Level::Medium => Severity::Warn,
        Level::Low | Level::Informational => Severity::Note,
    }
}

#[cfg(any(test, all(target_os = "windows", feature = "mod-tui")))]
pub(crate) fn findings(set: &RuleSet, input: &DetectInput) -> Vec<Finding> {
    hemostat_detect::run(set, &input.events)
        .into_iter()
        .map(|hit| {
            let what = input.event(hit.seq).map_or_else(|| format!("event {}", hit.seq), event_line);
            Finding {
                severity: severity(hit.level),
                subject: hit.title.clone(),
                what,
                why: format!(
                    "Sigma rule{} at level {} matched {}. A rule match is a lead, not a verdict{}",
                    hit.id.as_ref().map_or_else(String::new, |i| format!(" {i}")),
                    hit.level.token(),
                    input.about(hit.seq).unwrap_or("an event"),
                    if hit.truncated { format!("; {}", cut_hit_note()) } else { String::new() }
                ),
                fix: None,
            }
        })
        .collect()
}

#[cfg(any(test, all(target_os = "windows", feature = "mod-tui")))]
pub(crate) fn console_result(
    rules: Option<(&RuleSet, &[String])>,
    looked: &str,
    input: impl FnOnce() -> DetectInput,
) -> (Vec<Finding>, crate::coverage::Covered) {
    use crate::coverage::Covered;
    let Some((set, unreadable)) = rules else {
        return (
            vec![Finding {
                severity: Severity::Note,
                subject: "detect: no rules given".into(),
                what: format!("no Sigma rule was evaluated: {looked}"),
                why: "detect has no built-in rules, so with none given it was not run. This says \
                      nothing about the process-start records on this host. `console --rules \
                      DIR`, or a `rules` folder beside the executable, gives it some"
                    .into(),
                fix: None,
            }],
            Covered::Fully,
        );
    };
    if set.rules.is_empty() {
        return (Vec::new(), Covered::NotAtAll(format!("no rule in {looked} loaded: {}", set.coverage())));
    }
    let input = input();
    if input.events.is_empty() {
        let why = input.gaps.first().cloned().unwrap_or_else(|| input.no_events.clone());
        return (Vec::new(), Covered::NotAtAll(why));
    }
    let found = findings(set, &input);
    let mut part: Vec<String> = Vec::new();
    if !set.rejected.is_empty() {
        part.push(format!("{} rule(s) did not load", set.rejected.len()));
    }
    if !unreadable.is_empty() {
        part.push(format!("{} rule file(s) could not be read", unreadable.len()));
    }
    part.extend(input.gaps.iter().cloned());
    let cut = hemostat_detect::truncated_events(&input.events);
    if cut > 0 {
        part.push(cut_count(cut, "event"));
    }
    let covered = if part.is_empty() { Covered::Fully } else { Covered::InPart(part.join("; ")) };
    (found, covered)
}

#[cfg(all(target_os = "windows", feature = "mod-tui"))]
static CONSOLE_RULES: std::sync::OnceLock<Option<String>> = std::sync::OnceLock::new();

#[cfg(all(target_os = "windows", feature = "mod-tui"))]
pub(crate) fn set_console_rules(dir: Option<String>) {
    let _ = CONSOLE_RULES.set(dir);
}

#[cfg(all(target_os = "windows", feature = "mod-tui"))]
pub(crate) fn console_rules_dir() -> (Option<String>, String) {
    if let Some(Some(d)) = CONSOLE_RULES.get() {
        return (Some(d.clone()), format!("--rules {d}"));
    }
    let beside = std::env::current_exe().ok().and_then(|p| p.parent().map(|d| d.join("rules")));
    match beside {
        Some(d) if d.is_dir() => {
            let s = d.display().to_string();
            (Some(s.clone()), s)
        }
        Some(d) => (None, format!("no --rules was given and {} does not exist", d.display())),
        None => (None, "no --rules was given and the executable's directory is unknown".into()),
    }
}

use hemostat_sensor_win::procwatch::{Arrival, Change, Health, SourceStatus};
use hemostat_sensor_win::procexec::Source;

#[cfg(any(test, all(target_os = "windows", feature = "mod-tui")))]
pub(crate) const LIVE_SOURCE: &str = "detect-live";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LiveHit {
    pub(crate) level: hemostat_detect::Level,
    pub(crate) title: String,
    pub(crate) id: Option<String>,

    pub(crate) about: String,

    pub(crate) line: String,

    pub(crate) event_json: String,

    pub(crate) seen: i64,

    pub(crate) latency_ms: Option<i64>,

    pub(crate) truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LiveCut {

    pub(crate) about: String,

    pub(crate) line: String,

    pub(crate) event_json: String,

    pub(crate) seen: i64,
}

#[derive(Debug, Default)]
pub(crate) struct Fed {

    pub(crate) hits: Vec<LiveHit>,

    pub(crate) cut: Vec<LiveCut>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Latency {
    pub(crate) n: u64,
    pub(crate) min: i64,
    pub(crate) max: i64,
    sum: i128,
    pub(crate) over_1s: u64,
    pub(crate) over_5s: u64,
}

impl Latency {
    fn add(&mut self, ms: i64) {
        if self.n == 0 || ms < self.min {
            self.min = ms;
        }
        if self.n == 0 || ms > self.max {
            self.max = ms;
        }
        self.n += 1;
        self.sum += i128::from(ms);
        self.over_1s += u64::from(ms > 1_000);
        self.over_5s += u64::from(ms > 5_000);
    }

    pub(crate) fn mean(&self) -> Option<i64> {
        (self.n > 0).then(|| i64::try_from(self.sum / i128::from(self.n)).unwrap_or(i64::MAX))
    }
}

const RECENT_HITS: usize = 512;

pub(crate) struct LiveEval {
    own: Option<String>,
    seq: u64,
    recent: std::collections::VecDeque<(String, u64, String, i64, Source)>,

    pub(crate) evaluated: [u64; 2],

    pub(crate) excluded_own: u64,

    pub(crate) suppressed: u64,
    pub(crate) hits: u64,
    pub(crate) latency: Latency,

    pub(crate) truncated: u64,
}

const fn source_index(s: Source) -> usize {
    match s {
        Source::Sysmon1 => 0,
        Source::Security4688 => 1,
    }
}

impl LiveEval {
    pub(crate) fn new(own_image: Option<String>) -> Self {
        Self {
            own: own_image,
            seq: 0,
            recent: std::collections::VecDeque::with_capacity(RECENT_HITS),
            evaluated: [0; 2],
            excluded_own: 0,
            suppressed: 0,
            hits: 0,
            latency: Latency::default(),
            truncated: 0,
        }
    }

    pub(crate) fn evaluated_total(&self) -> u64 {
        self.evaluated.iter().sum()
    }

    pub(crate) fn feed(&mut self, set: &hemostat_detect::RuleSet, arrivals: &[Arrival]) -> Fed {
        let boot = BootId::from_bytes([0; 16]);
        let o = origin();
        let mut out = Fed::default();
        for a in arrivals {
            let s = &a.start;
            let ours = match (self.own.as_deref(), s.parent_image.as_deref()) {
                (Some(me), Some(parent)) => parent.eq_ignore_ascii_case(me),
                _ => false,
            };
            if ours {
                self.excluded_own += 1;
                continue;
            }
            if let Some(n) = self.evaluated.get_mut(source_index(s.source)) {
                *n += 1;
            }
            let latency_ms = a.latency_ms();
            if let Some(ms) = latency_ms {
                self.latency.add(ms);
            }
            let event = s.to_event(self.seq, boot, o);
            self.seq += 1;

            if event.truncated() {
                self.truncated += 1;
                out.cut.push(LiveCut {
                    about: format!("{} record {}, {}", s.source.name(), s.record_id, when(s.time)),
                    line: crate::analysis::event_line(&event),
                    event_json: crate::analysis::event_json(&event),
                    seen: a.seen,
                });
            }
            for hit in hemostat_detect::run(set, std::slice::from_ref(&event)) {
                let key = hit.id.clone().unwrap_or_else(|| hit.title.clone());
                let image = s.image.as_deref().unwrap_or_default().to_lowercase();
                let dup = match (s.pid, s.time) {
                    (Some(pid), Some(t)) => self.recent.iter().any(|(k, p, i, u, src)| {
                        *k == key
                            && *p == pid
                            && *i == image
                            && *src != s.source
                            && (u - t).abs() <= procexec::SAME_START_TICKS
                    }),
                    _ => false,
                };
                if dup {
                    self.suppressed += 1;
                    continue;
                }
                if let (Some(pid), Some(t)) = (s.pid, s.time) {
                    if self.recent.len() >= RECENT_HITS {
                        self.recent.pop_front();
                    }
                    self.recent.push_back((key, pid, image, t, s.source));
                }
                self.hits += 1;
                out.hits.push(LiveHit {
                    level: hit.level,
                    title: hit.title,
                    id: hit.id,
                    about: format!("{} record {}, {}", s.source.name(), s.record_id, when(s.time)),
                    line: crate::analysis::event_line(&event),
                    event_json: crate::analysis::event_json(&event),
                    seen: a.seen,
                    latency_ms,
                    truncated: hit.truncated,
                });
            }
        }
        out
    }
}

pub(crate) fn cut_line(c: &LiveCut) -> String {
    format!(
        "{}: a field was over {} bytes and was cut — its head and tail were evaluated, not its middle, so a \
         rule keyed on text there could not have matched it",
        c.about,
        hs_core::MAX_FIELD_BYTES
    )
}

pub(crate) fn cut_json(c: &LiveCut) -> String {
    format!(
        "{{\"type\":\"truncated\",\"from\":{},\"seen\":{},\"event\":{}}}",
        json_str(&c.about),
        json_str(&when(Some(c.seen))),
        c.event_json
    )
}

pub(crate) fn change_line(c: &Change) -> String {
    let to = match c.to.why() {
        Some(why) => format!("{} — {why}", c.to.token()),
        None => c.to.token().to_string(),
    };
    match &c.from {
        Some(f) => format!("{} {}: {} -> {to}", when(Some(c.at)), c.source.name(), f.token()),
        None => format!("{} {}: {to}", when(Some(c.at)), c.source.name()),
    }
}

pub(crate) fn status_line(s: &SourceStatus) -> String {
    let state = match s.health.why() {
        Some(why) => format!("{} — {why}", s.health.token()),
        None => format!("{}, subscribed to {}", s.health.token(), s.source.channel()),
    };
    let mut extra = Vec::new();
    if s.delivered > 0 {
        extra.push(format!("{} delivered", s.delivered));
    }
    if s.foreign > 0 {
        extra.push(format!("{} skipped as not from the source's provider", s.foreign));
    }
    if s.unrendered > 0 {
        extra.push(format!("{} did not render", s.unrendered));
    }
    if s.reopened > 0 {
        extra.push(format!("reopened {} time(s)", s.reopened));
    }
    if let Some(rc) = s.resume_error {
        extra.push(format!(
            "a resume after the last delivered record was refused (error {rc}); {} record(s) read back by \
             a catch-up query",
            s.caught_up
        ));
    }
    if extra.is_empty() {
        format!("{}: {state}", s.source.name())
    } else {
        format!("{}: {state} ({})", s.source.name(), extra.join(", "))
    }
}

pub(crate) fn status_json(s: &SourceStatus) -> String {
    format!(
        "{{\"source\":{},\"state\":\"{}\",\"why\":{},\"since\":{},\"delivered\":{},\"foreign\":{},\
         \"unrendered\":{},\"last_record\":{},\"reopened\":{},\"resume_error\":{},\"caught_up\":{}}}",
        json_str(s.source.name()),
        s.health.token(),
        s.health.why().map_or("null".into(), json_str),
        json_str(&when(Some(s.since))),
        s.delivered,
        s.foreign,
        s.unrendered,
        s.last_record.map_or("null".into(), |r| r.to_string()),
        s.reopened,
        s.resume_error.map_or("null".into(), |r| r.to_string()),
        s.caught_up
    )
}

#[derive(Debug, Default)]
pub(crate) struct Ledger {
    pub(crate) faults: Vec<String>,
    blind_since: Option<i64>,
}

impl Ledger {
    pub(crate) fn observe(&mut self, changes: &[Change], status: &[SourceStatus], now: i64) {
        for c in changes {
            if c.to.is_fault() {
                self.faults.push(change_line(c));
            } else if matches!(c.to, Health::Unaudited(_)) && c.from.as_ref().is_some_and(Health::is_live) {
                self.faults.push(format!("Process Creation auditing was turned off during the watch: {}", change_line(c)));
            }
        }
        let live = status.iter().any(|s| s.health.is_live());
        match (live, self.blind_since) {
            (false, None) => self.blind_since = Some(now),
            (true, Some(t)) => {
                self.faults.push(blind_line(t, now));
                self.blind_since = None;
            }
            _ => {}
        }
    }

    pub(crate) fn finish(&mut self, now: i64) {
        if let Some(t) = self.blind_since.take() {
            self.faults.push(blind_line(t, now));
        }
    }

    #[cfg(any(test, all(target_os = "windows", feature = "mod-tui")))]
    pub(crate) fn blind(&self) -> bool {
        self.blind_since.is_some()
    }
}

fn blind_line(from: i64, to: i64) -> String {
    format!("no source was delivering process starts from {} to {}", when(Some(from)), when(Some(to)))
}

pub(crate) fn watch_complete(
    set: &hemostat_detect::RuleSet,
    unreadable: &[String],
    ledger: &Ledger,
    eval: &LiveEval,
    dropped: u64,
) -> bool {
    set.complete()
        && unreadable.is_empty()
        && ledger.faults.is_empty()
        && dropped == 0
        && eval.evaluated_total() > 0
        && eval.truncated == 0
}

pub(crate) fn hit_json(h: &LiveHit) -> String {
    format!(
        "{{\"type\":\"hit\",\"level\":\"{}\",\"title\":{},\"id\":{},\"from\":{},\"seen\":{},\"latency_ms\":{},\
         \"truncated\":{},\"event\":{}}}",
        h.level.token(),
        json_str(&h.title),
        h.id.as_ref().map_or("null".into(), |i| json_str(i)),
        json_str(&h.about),
        json_str(&when(Some(h.seen))),
        h.latency_ms.map_or("null".into(), |l| l.to_string()),
        h.truncated,
        h.event_json
    )
}

pub(crate) fn change_json(c: &Change) -> String {
    format!(
        "{{\"type\":\"health\",\"at\":{},\"source\":{},\"from\":{},\"to\":\"{}\",\"why\":{}}}",
        json_str(&when(Some(c.at))),
        json_str(c.source.name()),
        c.from.as_ref().map_or("null".into(), |f| format!("\"{}\"", f.token())),
        c.to.token(),
        c.to.why().map_or("null".into(), json_str)
    )
}

fn secs(ms: i64) -> String {
    format!("{}.{:02}s", ms / 1_000, (ms % 1_000).abs() / 10)
}

pub(crate) fn summary(
    eval: &LiveEval,
    ledger: &Ledger,
    status: &[SourceStatus],
    dropped: u64,
    cap: usize,
    secs_watched: u64,
    complete: bool,
) -> (Vec<String>, String) {
    let l = &eval.latency;
    let lat = match l.mean() {
        Some(mean) => format!(
            "delivery latency min {} / mean {} / max {}; {} over 1s, {} over 5s",
            secs(l.min),
            secs(mean),
            secs(l.max),
            l.over_1s,
            l.over_5s
        ),
        None => "no delivery latency: nothing was evaluated".into(),
    };
    let mut lines = vec![
        format!(
            "{} process start(s) evaluated in {secs_watched}s (Sysmon 1 {}, Security 4688 {}), {} hit(s)",
            eval.evaluated_total(),
            eval.evaluated[0],
            eval.evaluated[1],
            eval.hits
        ),
        lat,
        format!("{} record(s) of this agent's own children not evaluated", eval.excluded_own),
        format!("{} hit(s) suppressed as the other source's record of the same start", eval.suppressed),
        if dropped > 0 {
            format!("{dropped} record(s) DROPPED: the ring (cap {cap}) was full, so they were NOT evaluated")
        } else {
            format!("0 dropped by the ring (cap {cap})")
        },
        if eval.truncated > 0 {
            format!("{}, so this watch is NOT complete", cut_count(eval.truncated, "record"))
        } else {
            format!("0 record(s) had a field cut at {} bytes", hs_core::MAX_FIELD_BYTES)
        },
    ];
    for s in status {
        lines.push(status_line(s));
    }
    let json = format!(
        "{{\"type\":\"summary\",\"seconds\":{secs_watched},\"complete\":{complete},\"evaluated\":{},\
         \"by_source\":{{\"Sysmon 1\":{},\"Security 4688\":{}}},\"hits\":{},\"excluded_own\":{},\
         \"suppressed\":{},\"dropped\":{dropped},\"ring_cap\":{cap},\"truncated_events\":{},\
         \"latency_ms\":{{\"n\":{},\"min\":{},\"mean\":{},\"max\":{},\"over_1s\":{},\"over_5s\":{}}},\
         \"faults\":[{}],\"sources\":[{}]}}",
        eval.evaluated_total(),
        eval.evaluated[0],
        eval.evaluated[1],
        eval.hits,
        eval.excluded_own,
        eval.suppressed,
        eval.truncated,
        l.n,
        if l.n > 0 { l.min.to_string() } else { "null".into() },
        l.mean().map_or("null".into(), |m| m.to_string()),
        if l.n > 0 { l.max.to_string() } else { "null".into() },
        l.over_1s,
        l.over_5s,
        ledger.faults.iter().map(|f| json_str(f)).collect::<Vec<_>>().join(","),
        status.iter().map(status_json).collect::<Vec<_>>().join(",")
    );
    (lines, json)
}

#[cfg(target_os = "windows")]
fn own_image() -> Option<String> {
    std::env::current_exe().ok().map(|p| p.display().to_string())
}

#[cfg(target_os = "windows")]
pub(crate) fn print_watch(json: bool, set: &hemostat_detect::RuleSet, unreadable: &[String], secs_watched: u64) -> u8 {
    use crate::render::h;
    use hemostat_sensor_win::procwatch::{filetime_now, Live, RING_CAP};
    use std::time::{Duration, Instant};

    let live = Live::start(security_built(), sysmon_built(), RING_CAP);
    let mut eval = LiveEval::new(own_image());
    let mut ledger = Ledger::default();
    if !live.running() {
        ledger.faults.push("the subscription reader thread could not be started".into());
    }

    let first = live.drain();
    if json {
        jprintln!(
            "{{\"type\":\"start\",\"seconds\":{secs_watched},\"evaluated\":{},\"not_evaluated\":{},\
             \"unreadable\":{},\"ring_cap\":{RING_CAP},\"sources\":[{}]}}",
            set.rules.len(),
            set.rejected.len(),
            unreadable.len(),
            first.status.iter().map(status_json).collect::<Vec<_>>().join(",")
        );
    } else {
        println!("detect --watch — Sigma rules over process starts as they are written\n");
        println!("  {}", h(&set.coverage()));
        if !unreadable.is_empty() {
            println!("  {} rule file(s) could not be read:", unreadable.len());
            for u in unreadable {
                println!("    {}", h(u));
            }
        }
        for s in &first.status {
            println!("  {}", h(&status_line(s)));
        }
        println!("  fields, by source: {}", h(&mapping_line()));
        println!(
            "  watching for {secs_watched}s from now; records already in the log are not evaluated \
             (`detect` without --watch reads those)\n"
        );
    }

    let deadline = Instant::now() + Duration::from_secs(secs_watched);
    let mut d = first;
    let mut dropped;
    let mut status;
    let mut initial = true;
    loop {
        for c in &d.changes {
            if json {
                jprintln!("{}", change_json(c));
            } else if !initial {
                println!("  health: {}", h(&change_line(c)));
            }
        }
        initial = false;
        ledger.observe(&d.changes, &d.status, filetime_now());
        let fed = eval.feed(set, &d.arrivals);

        for cut in &fed.cut {
            if json {
                jprintln!("{}", cut_json(cut));
            } else {
                println!("  [cut] {}", h(&cut_line(cut)));
                println!("      {}", h(&cut.line));
            }
        }
        for hit in fed.hits {
            if json {
                jprintln!("{}", hit_json(&hit));
            } else {
                println!("  [{}] {}", hit.level.token(), h(&hit.title));
                println!(
                    "      at {}, {} after it was written; from {}",
                    when(Some(hit.seen)),
                    hit.latency_ms.map_or_else(|| "an unknown time".into(), secs),
                    h(&hit.about)
                );
                println!("      {}", h(&hit.line));
                if hit.truncated {
                    println!("      {}", cut_hit_note());
                }
            }
        }
        dropped = d.dropped;
        status = d.status;
        if d.changes_dropped > 0 && !ledger.faults.iter().any(|f| f.contains("health changes")) {
            ledger.faults.push(format!("{} health changes were dropped before they were read", d.changes_dropped));
        }
        if Instant::now() >= deadline {
            break;
        }
        std::thread::sleep(Duration::from_millis(250));
        d = live.drain();
    }
    if !live.running() && !ledger.faults.iter().any(|f| f.contains("reader thread")) {
        ledger.faults.push("the subscription reader thread stopped before the watch ended".into());
    }
    drop(live);
    ledger.finish(filetime_now());

    let complete = watch_complete(set, unreadable, &ledger, &eval, dropped);
    let (lines, doc) = summary(&eval, &ledger, &status, dropped, RING_CAP, secs_watched, complete);
    if json {
        jprintln!("{doc}");
    } else {
        println!();
        for l in &lines {
            println!("  {}", h(l));
        }
        if eval.evaluated_total() == 0 {
            println!("  no process start was evaluated, so no rule was evaluated against anything. Exit 7.");
        }
        if !ledger.faults.is_empty() {
            println!("\n  THE WATCH DID NOT COVER THE WHOLE WINDOW ({}):", ledger.faults.len());
            for f in &ledger.faults {
                println!("    {}", h(f));
            }
        }
        println!(
            "\n  A Sigma rule is a lead, not a verdict. Nothing here changes the host: the watch\n  \
             reads two channels and reports."
        );
    }
    if complete {
        crate::EXIT_OK
    } else {
        crate::EXIT_PARTIAL
    }
}

#[cfg(all(target_os = "windows", feature = "mod-tui"))]
struct ConsoleLive {
    live: hemostat_sensor_win::procwatch::Live,
    set: RuleSet,
    eval: LiveEval,
    ledger: Ledger,

    rows: Vec<(String, hemostat_tui::FindingRow)>,

    rows_dropped: u64,
    dropped: u64,
    status: Vec<SourceStatus>,
}

#[cfg(any(test, all(target_os = "windows", feature = "mod-tui")))]
const CONSOLE_ROWS_CAP: usize = 1_000;

#[cfg(all(target_os = "windows", feature = "mod-tui"))]
static CONSOLE_LIVE: std::sync::Mutex<Option<ConsoleLive>> = std::sync::Mutex::new(None);

#[cfg(any(test, all(target_os = "windows", feature = "mod-tui")))]
pub(crate) fn live_row(hit: &LiveHit) -> hemostat_tui::FindingRow {
    let sev = match severity(hit.level) {
        Severity::Critical => hemostat_tui::Sev::Critical,
        Severity::Warn => hemostat_tui::Sev::Warn,
        Severity::Note => hemostat_tui::Sev::Note,
    };
    hemostat_tui::FindingRow {
        severity: sev,
        source: LIVE_SOURCE.into(),
        subject: hit.title.clone(),
        what: hit.line.clone(),
        why: format!(
            "Sigma rule{} at level {} matched {}, seen live at {}{}. A rule match is a lead, not a verdict{}",
            hit.id.as_ref().map_or_else(String::new, |i| format!(" {i}")),
            hit.level.token(),
            hit.about,
            when(Some(hit.seen)),
            hit.latency_ms.map_or_else(String::new, |l| format!(", {} after it was written", secs(l))),
            if hit.truncated { format!("; {}", cut_hit_note()) } else { String::new() }
        ),
        remedy: None,
        evidence: Vec::new(),
    }
}

#[cfg(any(test, all(target_os = "windows", feature = "mod-tui")))]
pub(crate) fn live_gap(ledger: &Ledger, dropped: u64, rows_dropped: u64, truncated: u64) -> Option<hemostat_tui::Gap> {
    let mut why: Vec<String> = Vec::new();
    if ledger.blind() {
        why.push("no source is delivering process starts now".into());
    }
    if let Some(last) = ledger.faults.last() {
        why.push(format!("{} fault(s) since the console started; the latest: {last}", ledger.faults.len()));
    }
    if dropped > 0 {
        why.push(format!("{dropped} record(s) dropped by the ring before evaluation"));
    }
    if rows_dropped > 0 {
        why.push(format!("{rows_dropped} live row(s) dropped at the cap of {CONSOLE_ROWS_CAP}"));
    }
    if truncated > 0 {
        why.push(cut_count(truncated, "live record"));
    }
    if why.is_empty() {
        return None;
    }
    let text = why.join("; ");
    Some(if ledger.blind() { hemostat_tui::Gap::did_not_run(LIVE_SOURCE, text) } else { hemostat_tui::Gap::partial(LIVE_SOURCE, text) })
}

#[cfg(all(target_os = "windows", feature = "mod-tui"))]
pub(crate) fn console_live_start() {
    let (Some(dir), _) = console_rules_dir() else { return };
    let (docs, _) = crate::analysis::collect_rule_documents(&dir);
    let set = RuleSet::from_documents(&docs);
    if set.rules.is_empty() {
        return;
    }
    let live = hemostat_sensor_win::procwatch::Live::start(
        security_built(),
        sysmon_built(),
        hemostat_sensor_win::procwatch::RING_CAP,
    );
    let mut ledger = Ledger::default();
    if !live.running() {
        ledger.faults.push("the subscription reader thread could not be started".into());
    }
    if let Ok(mut g) = CONSOLE_LIVE.lock() {
        *g = Some(ConsoleLive {
            live,
            set,
            eval: LiveEval::new(std::env::current_exe().ok().map(|p| p.display().to_string())),
            ledger,
            rows: Vec::new(),
            rows_dropped: 0,
            dropped: 0,
            status: Vec::new(),
        });
    }
}

#[cfg(all(target_os = "windows", feature = "mod-tui"))]
pub(crate) fn console_live_tick(model: &mut hemostat_tui::ConsoleModel) -> bool {
    let Ok(mut g) = CONSOLE_LIVE.lock() else { return false };
    let Some(c) = g.as_mut() else { return false };
    let d = c.live.drain();
    c.ledger.observe(&d.changes, &d.status, hemostat_sensor_win::procwatch::filetime_now());
    c.dropped = d.dropped;
    c.status = d.status;
    let mut new_rows = Vec::new();

    for hit in c.eval.feed(&c.set, &d.arrivals).hits {
        let row = live_row(&hit);
        if c.rows.len() >= CONSOLE_ROWS_CAP {
            c.rows.remove(0);
            c.rows_dropped += 1;
        }
        c.rows.push((hit.about.clone(), row.clone()));
        new_rows.push(row);
    }
    let changed = !new_rows.is_empty();
    model.add_rows(new_rows);
    let gap = live_gap(&c.ledger, c.dropped, c.rows_dropped, c.eval.truncated);
    model.set_gap(LIVE_SOURCE, gap) || changed
}

#[cfg(all(target_os = "windows", feature = "mod-tui"))]
pub(crate) fn console_live_rows(rows: &mut Vec<hemostat_tui::FindingRow>, gaps: &mut Vec<hemostat_tui::Gap>) {
    let Ok(g) = CONSOLE_LIVE.lock() else { return };
    let Some(c) = g.as_ref() else { return };
    rows.extend(c.rows.iter().map(|(_, r)| r.clone()));
    gaps.extend(live_gap(&c.ledger, c.dropped, c.rows_dropped, c.eval.truncated));
}

#[cfg(all(target_os = "windows", feature = "mod-tui"))]
pub(crate) fn console_live_supersede(about: &[String]) {
    let Ok(mut g) = CONSOLE_LIVE.lock() else { return };
    let Some(c) = g.as_mut() else { return };
    let seen: std::collections::HashSet<&str> = about.iter().map(String::as_str).collect();
    c.rows.retain(|(a, _)| !seen.contains(a.as_str()));
}
