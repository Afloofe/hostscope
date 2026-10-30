use std::time::{Duration, Instant};

use ratatui_core::buffer::Buffer;
use ratatui_core::layout::Rect;
use ratatui_core::style::{Color, Modifier, Style};

use crate::chrome::{dim, draw_buttons, flow, scrollbar, text_panel, text_panel_height, Hits};
use crate::console::wrap;
use crate::draw::{clear, frame, put};
use crate::input::{Action, Mode};
use crate::sanitize;

pub mod registry;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {

    Linux,

    FreeBsd,

    Windows,

    Collector,

    Portable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {

    Read,

    Watch,

    Write,

    Act,

    Change,
}

impl Kind {
    fn tag(self) -> &'static str {
        match self {
            Kind::Read => "read",
            Kind::Watch => "watch",
            Kind::Write => "writes",
            Kind::Act => "ACTS",
            Kind::Change => "CHANGES",
        }
    }

    fn stoppable(self) -> bool {
        matches!(self, Kind::Read | Kind::Watch)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Choices {

    None,

    Fixed(&'static [&'static str]),

    Live(&'static str),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Field {

    pub name: &'static str,

    pub value: Option<&'static str>,

    pub positional: bool,

    pub required: bool,

    pub repeat: bool,

    pub choices: Choices,

    pub desc: &'static str,
}

pub const fn switch(name: &'static str, desc: &'static str) -> Field {
    Field { name, value: None, positional: false, required: false, repeat: false, choices: Choices::None, desc }
}

pub const fn opt(name: &'static str, value: &'static str, choices: Choices, desc: &'static str) -> Field {
    Field { name, value: Some(value), positional: false, required: false, repeat: false, choices, desc }
}

pub const fn opt_many(name: &'static str, value: &'static str, choices: Choices, desc: &'static str) -> Field {
    Field { name, value: Some(value), positional: false, required: false, repeat: true, choices, desc }
}

pub const fn req(name: &'static str, value: &'static str, choices: Choices, desc: &'static str) -> Field {
    Field { name, value: Some(value), positional: false, required: true, repeat: false, choices, desc }
}

pub const fn pos(value: &'static str, choices: Choices, desc: &'static str) -> Field {
    Field { name: value, value: Some(value), positional: true, required: true, repeat: false, choices, desc }
}

pub const fn pos_opt(value: &'static str, choices: Choices, desc: &'static str) -> Field {
    Field { name: value, value: Some(value), positional: true, required: false, repeat: false, choices, desc }
}

pub const fn pos_many(value: &'static str, required: bool, choices: Choices, desc: &'static str) -> Field {
    Field { name: value, value: Some(value), positional: true, required, repeat: true, choices, desc }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Arm {

    Flag(&'static str),

    Window {

        flag: &'static str,

        choices: &'static [&'static str],

        default: &'static str,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Commit {

    Window {

        what: &'static str,

        keep: &'static [&'static str],

        revert: &'static [&'static str],

        fixed: &'static [&'static str],

        fixed_secs: u64,
    },

    Block {

        what: &'static str,

        marker: &'static str,

        deadline: &'static str,

        default_secs: u64,

        keep: &'static [&'static str],

        revert: &'static [&'static str],

        carry: &'static [&'static str],
    },
}

#[derive(Debug, Clone, Copy)]
pub struct VerbSpec {

    pub name: &'static str,

    pub argv: &'static [&'static str],

    pub platforms: &'static [Platform],

    pub kind: Kind,

    pub needs: &'static [&'static str],

    pub fields: &'static [Field],

    pub arm: Option<Arm>,

    pub commit: Option<Commit>,

    pub warn: &'static str,
}

#[derive(Debug, Clone)]
pub struct VerbItem {

    pub spec: &'static VerbSpec,

    pub disabled: Option<String>,

    pub help: String,

    pub preset: Vec<(&'static str, String)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TicketEnv {

    Inherit,

    Unset,

    Set(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunRequest {

    pub argv: Vec<String>,

    pub ticket: TicketEnv,

    pub armed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerbRequest {

    Start(RunRequest),

    Stop,

    Choices(&'static str),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {

    pub code: Option<i32>,

    pub label: String,

    pub plan_ok: bool,
}

pub trait Running {

    fn poll(&mut self) -> (Vec<String>, Option<Outcome>);

    fn stop(&mut self);
}

pub trait VerbHost {

    fn start(&mut self, req: &RunRequest) -> Result<Box<dyn Running>, String>;

    fn choices(&mut self, key: &str) -> Vec<String>;

    fn inherited_ticket(&self) -> Option<String>;
}

pub struct Verbs {

    pub items: Vec<VerbItem>,

    pub host: Box<dyn VerbHost>,
}

struct NoHost;

impl VerbHost for NoHost {
    fn start(&mut self, _: &RunRequest) -> Result<Box<dyn Running>, String> {
        Err("this view was opened with no verbs behind it".into())
    }
    fn choices(&mut self, _: &str) -> Vec<String> {
        Vec::new()
    }
    fn inherited_ticket(&self) -> Option<String> {
        None
    }
}

impl Verbs {

    pub fn none() -> Self {
        Verbs { items: Vec::new(), host: Box::new(NoHost) }
    }
}

pub(crate) struct Driver {
    host: Box<dyn VerbHost>,
    running: Option<Box<dyn Running>>,
}

impl Driver {
    pub(crate) fn new(host: Box<dyn VerbHost>) -> Self {
        Driver { host, running: None }
    }

    pub(crate) fn inherited_ticket(&self) -> Option<String> {
        self.host.inherited_ticket()
    }

    pub(crate) fn service(&mut self, pane: &mut VerbsPane, now: Instant) -> bool {
        let mut changed = pane.tick(now);
        while let Some(r) = pane.take_request() {
            changed = true;
            match r {
                VerbRequest::Start(req) => match self.host.start(&req) {
                    Ok(h) => {
                        self.running = Some(h);
                        pane.started(Ok(()));
                    }
                    Err(e) => pane.started(Err(e)),
                },
                VerbRequest::Stop => {
                    if let Some(h) = self.running.as_mut() {
                        h.stop();
                    }
                }
                VerbRequest::Choices(key) => {
                    let v = self.host.choices(key);
                    pane.set_choices(v);
                }
            }
        }
        if let Some(h) = self.running.as_mut() {
            let (lines, done) = h.poll();
            if !lines.is_empty() {
                pane.feed(lines);
                changed = true;
            }
            if let Some(o) = done {
                self.running = None;
                pane.finished(o, now);
                changed = true;
            }
        }
        changed
    }

    pub(crate) fn leave(&mut self) {
        if let Some(h) = self.running.as_mut() {
            h.stop();
        }
    }
}

pub const MAX_VALUE: usize = 256;

const MAX_LINES: usize = 5000;

const MAX_WINDOW: u64 = 86_400;

const PAGE: usize = crate::bindings::CANNED_SLOTS;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stage {
    List,
    Form,
    Value,
    Output,
    Confirm,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Purpose {

    Plan,

    Armed,

    Plain,

    Keep,

    Revert,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Target {
    Field(usize),
    Window,
    Ticket,
}

#[derive(Debug, Clone)]
struct Form {
    item: usize,
    values: Vec<Option<String>>,
    window: Option<String>,
    field: usize,

    plan: Option<Vec<String>>,
}

#[derive(Debug, Clone)]
struct Entry {
    target: Target,
    text: String,
    choices: Vec<String>,
    page: usize,
    back: Stage,
}

#[derive(Debug, Clone)]
struct Run {
    item: usize,
    argv: Vec<String>,
    purpose: Purpose,
    kind: Kind,
    started: Instant,
    lines: Vec<String>,
    dropped: usize,
    outcome: Option<Outcome>,
    stopping: bool,
    ticket: String,
}

#[derive(Debug, Clone)]
struct Window {
    what: String,
    short: &'static str,
    verb: &'static str,
    deadline: Instant,
    keep: Option<Vec<String>>,
    revert: Option<Vec<String>>,
    note: Option<String>,
    closed: Option<String>,
}

#[derive(Debug, Clone)]
struct Pending {
    req: RunRequest,
    purpose: Purpose,
    headline: String,
    lines: Vec<String>,
    back: Stage,
}

#[derive(Debug, Clone)]
pub struct VerbsPane {
    items: Vec<VerbItem>,
    selected: usize,
    stage: Stage,
    form: Option<Form>,
    entry: Option<Entry>,
    run: Option<Run>,
    window: Option<Window>,
    pending: Option<Pending>,
    requests: Vec<VerbRequest>,
    ticket: TicketEnv,
    inherited: Option<String>,

    pub shift: bool,

    pub confirm_opened: Option<Instant>,

    pub status: Option<String>,
    scroll: usize,
    follow: bool,
    now: Option<Instant>,
    quit_asked: bool,
    shown_secs: Option<u64>,
}

pub(crate) struct Drawn {

    pub(crate) confirm: bool,
}

impl VerbsPane {

    pub fn new(items: Vec<VerbItem>) -> Self {
        VerbsPane {
            items,
            selected: 0,
            stage: Stage::List,
            form: None,
            entry: None,
            run: None,
            window: None,
            pending: None,
            requests: Vec::new(),
            ticket: TicketEnv::Inherit,
            inherited: None,
            shift: false,
            confirm_opened: None,
            status: None,
            scroll: 0,
            follow: true,
            now: None,
            quit_asked: false,
            shown_secs: None,
        }
    }

    pub fn set_inherited_ticket(&mut self, t: Option<String>) {
        self.inherited = t;
    }

    pub fn items(&self) -> &[VerbItem] {
        &self.items
    }

    pub fn chain(&self) -> &'static [Mode] {
        match self.stage {
            Stage::List => &[Mode::VerbList, Mode::Global],
            Stage::Form => &[Mode::VerbForm, Mode::Global],
            Stage::Value => &[Mode::VerbValue, Mode::TextEntry],
            Stage::Output => &[Mode::VerbOutput, Mode::Global],
            Stage::Confirm => &[Mode::VerbConfirm],
        }
    }

    pub(crate) const OPENERS: &'static [&'static [Mode]] =
        &[&[Mode::VerbForm, Mode::Global], &[Mode::VerbOutput, Mode::Global]];

    pub fn confirming(&self) -> bool {
        self.stage == Stage::Confirm
    }

    pub fn busy(&self) -> bool {
        self.running() || self.window_open()
    }

    fn running(&self) -> bool {
        self.run.as_ref().is_some_and(|r| r.outcome.is_none())
    }

    fn window_open(&self) -> bool {
        self.window.as_ref().is_some_and(|w| w.closed.is_none())
    }

    pub fn take_request(&mut self) -> Option<VerbRequest> {
        if self.requests.is_empty() { None } else { Some(self.requests.remove(0)) }
    }

    fn now(&self) -> Instant {
        self.now.unwrap_or_else(Instant::now)
    }

    fn secs_left(&self) -> Option<u64> {
        let w = self.window.as_ref().filter(|w| w.closed.is_none())?;
        Some(w.deadline.saturating_duration_since(self.now()).as_secs())
    }

    pub fn alert(&self) -> Option<String> {
        let s = self.secs_left()?;
        let w = self.window.as_ref()?;
        Some(format!("{} {s}s", w.short))
    }

    pub fn tick(&mut self, now: Instant) -> bool {
        self.now = Some(now);
        let mut changed = false;
        if let Some(w) = self.window.as_mut() {
            if w.closed.is_none() && now >= w.deadline {
                w.closed = Some(format!(
                    "the window closed at its deadline. The host's own rollback was due then and nothing \
                     was run from here: run the verb again (its dry run) to see what is in force now — {} \
                     was NOT kept",
                    w.what
                ));
                self.status = w.closed.clone();
                changed = true;
            }
        }
        let shown = self.secs_left();
        if shown != self.shown_secs {
            self.shown_secs = shown;
            changed = true;
        }
        if self.running() {
            changed = true;
        }
        changed
    }

    pub fn quit_ok(&mut self) -> bool {
        if let Some(r) = self.run.as_ref().filter(|r| r.outcome.is_none()) {
            if !r.kind.stoppable() || matches!(r.purpose, Purpose::Armed | Purpose::Keep | Purpose::Revert) {
                self.status = Some(format!(
                    "`hemostat {}` is still running and is not interrupted: wait for it to finish",
                    r.argv.join(" ")
                ));
                return false;
            }
        }
        if let (Some(s), false) = (self.secs_left(), self.quit_asked) {
            self.quit_asked = true;
            self.status = Some(format!(
                "a window is open ({s}s left). Leaving does not keep the change: the host's own rollback \
                 still happens. Quit again to leave anyway"
            ));
            return false;
        }
        true
    }

    pub fn started(&mut self, r: Result<(), String>) {
        if let (Err(e), Some(run)) = (r, self.run.as_mut()) {
            run.outcome = Some(Outcome { code: None, label: format!("did NOT start, so nothing ran: {e}"), plan_ok: false });
        }
    }

    pub fn feed(&mut self, lines: Vec<String>) {
        let Some(run) = self.run.as_mut() else { return };
        run.lines.extend(lines);
        if run.lines.len() > MAX_LINES {
            let cut = run.lines.len() - MAX_LINES;
            run.lines.drain(..cut);
            run.dropped += cut;
            self.scroll = self.scroll.saturating_sub(cut);
        }
    }

    pub fn set_choices(&mut self, v: Vec<String>) {
        if let Some(e) = self.entry.as_mut() {
            for c in v {
                if !e.choices.contains(&c) {
                    e.choices.push(c);
                }
            }
        }
    }

    pub fn finished(&mut self, o: Outcome, now: Instant) {
        let Some(run) = self.run.as_mut() else { return };
        let o = if run.stopping && o.code.is_none() {
            Outcome { label: format!("stopped by you: {}", o.label), ..o }
        } else {
            o
        };
        run.outcome = Some(o.clone());
        let (purpose, item, argv, started) = (run.purpose, run.item, run.argv.clone(), run.started);
        self.status = Some(format!("`hemostat {}`: {}", argv.join(" "), o.label));
        let Some(spec) = self.items.get(item).map(|i| i.spec) else { return };
        match purpose {
            Purpose::Plan => {
                if let Some(f) = self.form.as_mut().filter(|f| f.item == item) {
                    f.plan = o.plan_ok.then(|| argv.clone());
                }

                if o.plan_ok {
                    self.status = Some(match self.shown_digest() {
                        Some(d) => format!(
                            "the plan is above (digest {d}); nothing was applied. Arm (a) applies exactly this plan, after \
                             asking: the armed run refuses if the plan it builds from the host is not this one ({})",
                            o.label
                        ),
                        None => format!(
                            "the plan is above; nothing was applied. Arm (a) runs these flags armed, after asking: the \
                             armed run checks the host again and acts on what it finds then ({})",
                            o.label
                        ),
                    });
                }
            }
            Purpose::Armed => {
                if let Some(f) = self.form.as_mut() {
                    f.plan = None;
                }
                if o.code == Some(0) {
                    self.open_window(spec, &argv, started);
                }
            }
            Purpose::Keep | Purpose::Revert => {
                if let Some(w) = self.window.as_mut() {
                    if o.code == Some(0) {
                        w.closed = Some(if purpose == Purpose::Keep {
                            format!("{} was KEPT: {}", w.what, o.label)
                        } else {
                            format!("{} was REVERTED: {}", w.what, o.label)
                        });
                        self.status = w.closed.clone();
                    } else {
                        self.status = Some(format!(
                            "NOT {} — {}. The window is still open and the rollback still happens unless kept",
                            if purpose == Purpose::Keep { "kept" } else { "reverted" },
                            o.label
                        ));
                    }
                }
            }
            Purpose::Plain => {}
        }
        let _ = now;
    }

    fn open_window(&mut self, spec: &VerbSpec, argv: &[String], started: Instant) {
        let Some(c) = spec.commit else { return };
        let owned = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        match c {
            Commit::Window { what, keep, revert, fixed, fixed_secs } => {
                let Some(Arm::Window { flag, default, .. }) = spec.arm else { return };
                let secs = if argv.iter().any(|a| fixed.contains(&a.as_str())) {
                    fixed_secs
                } else {
                    argv.iter()
                        .position(|a| a == flag)
                        .and_then(|i| argv.get(i + 1))
                        .and_then(|v| v.parse::<u64>().ok())
                        .or_else(|| default.parse().ok())
                        .unwrap_or(0)
                };
                self.window = Some(Window {
                    what: what.into(),
                    short: "ROLLBACK IN",
                    verb: "roll back",
                    deadline: started + Duration::from_secs(secs.min(MAX_WINDOW)),
                    keep: Some(owned(keep)),
                    revert: Some(owned(revert)),
                    note: None,
                    closed: None,
                });
            }
            Commit::Block { what, marker, deadline, default_secs, keep, revert, carry } => {
                let secs = argv
                    .iter()
                    .position(|a| a == deadline)
                    .and_then(|i| argv.get(i + 1))
                    .and_then(|v| v.parse::<u64>().ok())
                    .unwrap_or(default_secs);
                let id = self.run.as_ref().and_then(|r| find_id(&r.lines, marker));
                let carried: Vec<String> = carry
                    .iter()
                    .filter_map(|f| argv.iter().position(|a| a == f).and_then(|i| argv.get(i + 1)).map(|v| [f.to_string(), v.clone()]))
                    .flatten()
                    .collect();
                let with = |v: &[&str], id: &str| {
                    let mut o = owned(v);
                    o.push(id.to_string());
                    o.extend(carried.iter().cloned());
                    o
                };
                self.window = Some(Window {
                    what: what.into(),
                    short: "BLOCK LIFTS IN",
                    verb: "lift",
                    deadline: started + Duration::from_secs(secs.min(MAX_WINDOW)),
                    keep: id.as_deref().map(|i| with(keep, i)),
                    revert: id.as_deref().map(|i| with(revert, i)),
                    note: id.is_none().then(|| {
                        format!(
                            "the block's id was not found after {marker:?} in the output, so [Keep] and \
                             [Revert] cannot name it: the `fw status` verb lists it, and the `fw confirm` and \
                             `undo` verbs take it"
                        )
                    }),
                    closed: None,
                });
            }
        }
        self.quit_asked = false;
    }

    fn spec(&self) -> Option<&'static VerbSpec> {
        self.form.as_ref().and_then(|f| self.items.get(f.item)).map(|i| i.spec)
    }

    fn field_count(&self) -> usize {
        self.spec().map_or(0, |s| s.fields.len() + usize::from(matches!(s.arm, Some(Arm::Window { .. }))))
    }

    fn base_argv(&self) -> Result<Vec<String>, String> {
        let (Some(f), Some(spec)) = (self.form.as_ref(), self.spec()) else { return Err("no verb is open".into()) };
        let mut out: Vec<String> = spec.argv.iter().map(|s| s.to_string()).collect();
        let value = |i: usize| f.values.get(i).cloned().flatten();
        for (i, fd) in spec.fields.iter().enumerate().filter(|(_, fd)| fd.positional) {
            match value(i) {
                Some(v) if fd.repeat => out.extend(v.split_whitespace().map(str::to_string)),
                Some(v) => out.push(v),
                None if fd.required => return Err(format!("{} is required: Edit (e) it first", fd.name)),
                None => {}
            }
        }
        for (i, fd) in spec.fields.iter().enumerate().filter(|(_, fd)| !fd.positional) {
            match (value(i), fd.value) {
                (Some(_), None) => out.push(fd.name.to_string()),
                (Some(v), Some(_)) if fd.repeat => {
                    for p in v.split_whitespace() {
                        out.push(fd.name.to_string());
                        out.push(p.to_string());
                    }
                }
                (Some(v), Some(_)) => {
                    out.push(fd.name.to_string());
                    out.push(v);
                }
                (None, _) if fd.required => {
                    return Err(format!("{} is required: Edit (e) it first", fd.name));
                }
                (None, _) => {}
            }
        }
        Ok(out)
    }

    fn plan_argv(&self) -> Result<Vec<String>, String> {

        self.base_argv()
    }

    fn armed_argv(&self, plan: &[String]) -> Vec<String> {
        let mut v: Vec<String> = plan.to_vec();
        match self.spec().and_then(|s| s.arm) {
            Some(Arm::Flag(f)) => v.push(f.to_string()),
            Some(Arm::Window { flag, default, .. }) => {
                v.push(flag.to_string());
                let w = self.form.as_ref().and_then(|f| f.window.clone()).unwrap_or_else(|| default.to_string());
                v.push(w);
            }
            None => {}
        }
        if let Some(d) = self.shown_digest() {
            v.push(PLAN_FLAG.to_string());
            v.push(d);
        }
        v
    }

    fn shown_digest(&self) -> Option<String> {
        if self.spec().and_then(|s| s.argv.first()) != Some(&PLAN_VERB) {
            return None;
        }
        self.run.as_ref().filter(|r| r.purpose == Purpose::Plan).and_then(|r| plan_digest(&r.lines))
    }

    fn ticket_text(&self) -> String {
        match &self.ticket {
            TicketEnv::Inherit => match &self.inherited {
                Some(t) => format!("$HEMOSTAT_TICKET as the view started: {t}"),
                None => "none — $HEMOSTAT_TICKET is not set, so the authorization stage is not performed (the verb says so)".into(),
            },
            TicketEnv::Unset => "none — removed for this run, so the authorization stage is not performed (the verb says so)".into(),
            TicketEnv::Set(p) => format!("{p} (as $HEMOSTAT_TICKET for the run)"),
        }
    }

    pub fn enabled(&self, a: Action) -> bool {
        let spec = self.spec();
        let disabled = self.form.as_ref().and_then(|f| self.items.get(f.item)).is_some_and(|i| i.disabled.is_some());
        match a {
            Action::DryRun => self.stage == Stage::Form && !disabled && spec.is_some_and(|s| s.kind == Kind::Act),
            Action::RunVerb => self.stage == Stage::Form && !disabled && spec.is_some_and(|s| s.kind != Kind::Act),
            Action::ShowOutput => self.run.is_some(),
            Action::Arm => self.arm_ready().is_ok(),
            Action::Stop => self.run.as_ref().is_some_and(|r| r.outcome.is_none() && !r.stopping && stoppable(r)),
            Action::Keep => self.window_open() && self.window.as_ref().is_some_and(|w| w.keep.is_some()),
            Action::Revert => self.window_open() && self.window.as_ref().is_some_and(|w| w.revert.is_some()),
            Action::Clear | Action::Edit => self.field_count() > 0,
            _ => true,
        }
    }

    fn arm_ready(&self) -> Result<Vec<String>, String> {
        let spec = self.spec().ok_or("no verb is open")?;
        if spec.kind != Kind::Act {
            return Err(format!("`{}` changes nothing, so there is nothing to arm", spec.name));
        }
        let run = self.run.as_ref().ok_or("no dry run yet: Dry run (d) shows the plan first")?;
        if run.purpose != Purpose::Plan || run.outcome.is_none() {
            return Err("the dry run has not finished: the plan is not complete".into());
        }
        let plan = self.form.as_ref().and_then(|f| f.plan.clone()).ok_or_else(|| {
            run.outcome.as_ref().map_or_else(String::new, |o| {
                format!("the dry run did not end as a plan ({}), so there is nothing to arm", o.label)
            })
        })?;
        if self.plan_argv().ok().as_deref() != Some(plan.as_slice()) {
            return Err("a flag changed since the dry run: Dry run (d) again to see the plan for it".into());
        }
        Ok(plan)
    }

    pub(crate) fn act(&mut self, a: Action, now: Instant) {
        self.now = Some(now);
        if !matches!(a, Action::Quit) {
            self.quit_asked = false;
        }
        match self.stage {
            Stage::List => self.act_list(a),
            Stage::Form => self.act_form(a, now),
            Stage::Value => self.act_value(a),
            Stage::Output => self.act_output(a, now),
            Stage::Confirm => self.act_confirm(a),
        }
    }

    fn act_list(&mut self, a: Action) {
        let last = self.items.len().saturating_sub(1);
        match a {
            Action::Up => self.selected = self.selected.saturating_sub(1),
            Action::Down => self.selected = (self.selected + 1).min(last),
            Action::PageUp => self.selected = self.selected.saturating_sub(10),
            Action::PageDown => self.selected = (self.selected + 10).min(last),
            Action::Select(i) if i < self.items.len() => {
                if i == self.selected {
                    self.open(i);
                } else {
                    self.selected = i;
                }
            }
            Action::Open => self.open(self.selected),
            Action::Ticket => self.open_entry(Target::Ticket),
            _ => {}
        }
    }

    fn open(&mut self, item: usize) {
        let Some(it) = self.items.get(item) else { return };
        let keep = self.form.as_ref().filter(|f| f.item == item).cloned();
        let values = it
            .spec
            .fields
            .iter()
            .map(|f| it.preset.iter().find(|(n, _)| *n == f.name).map(|(_, v)| v.clone()))
            .collect();
        self.form = Some(keep.unwrap_or(Form { item, values, window: None, field: 0, plan: None }));
        self.status = it.disabled.as_ref().map(|d| format!("NOT available in this image: {d}"));
        self.stage = Stage::Form;
    }

    fn act_form(&mut self, a: Action, now: Instant) {
        let n = self.field_count();
        let Some(spec) = self.spec() else {
            self.stage = Stage::List;
            return;
        };
        match a {
            Action::Up => {
                if let Some(f) = self.form.as_mut() {
                    f.field = f.field.saturating_sub(1);
                }
            }
            Action::Down => {
                if let Some(f) = self.form.as_mut() {
                    f.field = (f.field + 1).min(n.saturating_sub(1));
                }
            }
            Action::Select(i) if i < n => {
                let at = self.form.as_ref().map_or(0, |f| f.field);
                if i == at {
                    self.act_form(Action::Edit, now);
                } else if let Some(f) = self.form.as_mut() {
                    f.field = i;
                }
            }
            Action::Edit => {
                let at = self.form.as_ref().map_or(0, |f| f.field);
                match spec.fields.get(at) {
                    Some(fd) if fd.value.is_none() => {
                        if let Some(f) = self.form.as_mut() {
                            if let Some(v) = f.values.get_mut(at) {
                                *v = if v.is_some() { None } else { Some("on".into()) };
                            }
                        }
                    }
                    Some(_) => self.open_entry(Target::Field(at)),
                    None if n > 0 => self.open_entry(Target::Window),
                    None => {}
                }
            }
            Action::Clear => {
                let at = self.form.as_ref().map_or(0, |f| f.field);
                if let Some(f) = self.form.as_mut() {
                    match f.values.get_mut(at) {
                        Some(v) => *v = None,
                        None => f.window = None,
                    }
                }
            }
            Action::DryRun => self.dry_run(now),
            Action::RunVerb => self.run_plain(now),
            Action::ShowOutput => {
                if self.run.is_some() {
                    self.stage = Stage::Output;
                } else {
                    self.status = Some("nothing has run yet".into());
                }
            }
            Action::Ticket => self.open_entry(Target::Ticket),
            Action::Back => self.stage = Stage::List,
            _ => {}
        }
    }

    fn refusal(&self) -> Option<String> {
        if let Some(d) = self.form.as_ref().and_then(|f| self.items.get(f.item)).and_then(|i| i.disabled.clone()) {
            return Some(format!("NOT available in this image, so nothing was run: {d}"));
        }
        if let Some(r) = self.run.as_ref().filter(|r| r.outcome.is_none()) {
            return Some(format!("one run at a time: `hemostat {}` is still running", r.argv.join(" ")));
        }
        None
    }

    fn dry_run(&mut self, now: Instant) {
        let Some(spec) = self.spec() else { return };
        if spec.kind != Kind::Act {
            self.status = Some(format!("`{}` changes nothing, so it has no dry run: Run (r) runs it", spec.name));
            return;
        }
        if let Some(why) = self.refusal() {
            self.status = Some(why);
            return;
        }
        match self.plan_argv() {
            Ok(argv) => self.start(argv, Purpose::Plan, false, now),
            Err(why) => self.status = Some(why),
        }
    }

    fn run_plain(&mut self, now: Instant) {
        let Some(spec) = self.spec() else { return };
        if spec.kind == Kind::Act {
            self.status = Some(format!(
                "`{}` changes the host: Dry run (d) shows its plan first, and Arm (a) applies that plan after asking",
                spec.name
            ));
            return;
        }
        if let Some(why) = self.refusal() {
            self.status = Some(why);
            return;
        }
        let argv = match self.base_argv() {
            Ok(v) => v,
            Err(why) => {
                self.status = Some(why);
                return;
            }
        };
        if matches!(spec.kind, Kind::Write | Kind::Change) {
            let change = spec.kind == Kind::Change;
            let mut lines = vec![format!("  hemostat {}", argv.join(" "))];
            lines.push(if change {
                "This CHANGES THE HOST, and the verb has no dry run of its own: what it does is below and in its help on the form.".into()
            } else {
                "This writes files (evidence, a ledger record, a key or a ticket). It changes no setting of the host.".into()
            });
            if !spec.warn.is_empty() {
                lines.push(spec.warn.to_string());
            }
            if change {
                lines.push(format!("ticket: {}", self.ticket_text()));
            }
            let headline = if change { "CHANGE THE HOST? (no dry run)" } else { "RUN THIS? It writes" };
            let req = RunRequest { argv, ticket: self.ticket.clone(), armed: change };
            self.ask(req, Purpose::Plain, headline.into(), lines, now);
        } else {
            self.start(argv, Purpose::Plain, false, now);
        }
    }

    fn ask(&mut self, req: RunRequest, purpose: Purpose, headline: String, lines: Vec<String>, now: Instant) {
        self.pending = Some(Pending { req, purpose, headline, lines, back: self.stage });
        self.stage = Stage::Confirm;
        self.confirm_opened = Some(now);
    }

    fn start(&mut self, argv: Vec<String>, purpose: Purpose, armed: bool, now: Instant) {
        let (Some(item), Some(spec)) = (self.form.as_ref().map(|f| f.item), self.spec()) else { return };
        let req = RunRequest { argv: argv.clone(), ticket: self.ticket.clone(), armed };
        self.run = Some(Run {
            item,
            argv,
            purpose,
            kind: spec.kind,
            started: now,
            lines: Vec::new(),
            dropped: 0,
            outcome: None,
            stopping: false,
            ticket: self.ticket_text(),
        });
        self.requests.push(VerbRequest::Start(req));
        self.stage = Stage::Output;
        self.scroll = 0;
        self.follow = true;
        self.status = None;
    }

    fn open_entry(&mut self, target: Target) {
        let (choices, live, text) = match target {
            Target::Ticket => {
                let mut c = vec!["none".to_string()];
                if let Some(t) = &self.inherited {
                    c.insert(0, t.clone());
                }
                let text = match &self.ticket {
                    TicketEnv::Set(p) => p.clone(),
                    TicketEnv::Unset => "none".into(),
                    TicketEnv::Inherit => String::new(),
                };
                (c, Some("ticket"), text)
            }
            Target::Window => {
                let Some(Some(Arm::Window { choices, .. })) = self.spec().map(|s| s.arm) else { return };
                let text = self.form.as_ref().and_then(|f| f.window.clone()).unwrap_or_default();
                (choices.iter().map(|s| s.to_string()).collect(), None, text)
            }
            Target::Field(i) => {
                let Some(fd) = self.spec().and_then(|s| s.fields.get(i)) else { return };
                let text = self.form.as_ref().and_then(|f| f.values.get(i).cloned().flatten()).unwrap_or_default();
                match fd.choices {
                    Choices::None => (Vec::new(), None, text),
                    Choices::Fixed(v) => (v.iter().map(|s| s.to_string()).collect(), None, text),
                    Choices::Live(k) => (Vec::new(), Some(k), text),
                }
            }
        };
        if let Some(k) = live {
            self.requests.push(VerbRequest::Choices(k));
        }
        self.entry = Some(Entry { target, text, choices, page: 0, back: self.stage });
        self.stage = Stage::Value;
    }

    fn act_value(&mut self, a: Action) {
        let Some(e) = self.entry.as_mut() else {
            self.stage = Stage::Form;
            return;
        };
        match a {
            Action::Type(c) => {
                if e.text.chars().count() < MAX_VALUE && !c.is_control() {
                    e.text.push(c);
                }
            }
            Action::Erase => {
                e.text.pop();
            }
            Action::ShiftCase => self.shift = !self.shift,
            Action::Canned(i) => {
                if let Some(c) = e.choices.get(e.page * PAGE + i) {

                    e.text = c.split("  ").next().unwrap_or(c).chars().take(MAX_VALUE).collect();
                }
            }
            Action::PageDown => {
                if (e.page + 1) * PAGE < e.choices.len() {
                    e.page += 1;
                }
            }
            Action::PageUp => e.page = e.page.saturating_sub(1),
            Action::CancelEntry => {
                self.stage = e.back;
                self.entry = None;
                self.status = Some("left as it was".into());
            }
            Action::Submit => {
                let text = e.text.trim().to_string();
                let (target, back) = (e.target, e.back);
                if let Some(why) = bad_value(&text) {
                    self.status = Some(why);
                    return;
                }
                self.entry = None;
                self.stage = back;
                match target {
                    Target::Ticket => {
                        self.ticket = match text.as_str() {
                            "" => TicketEnv::Inherit,
                            "none" => TicketEnv::Unset,
                            p => TicketEnv::Set(p.to_string()),
                        };
                        self.status = Some(format!("ticket: {}", self.ticket_text()));
                    }
                    Target::Window => {
                        if let Some(f) = self.form.as_mut() {
                            f.window = (!text.is_empty()).then_some(text);
                        }
                    }
                    Target::Field(i) => {
                        if let Some(v) = self.form.as_mut().and_then(|f| f.values.get_mut(i)) {
                            *v = (!text.is_empty()).then_some(text);
                        }
                    }
                }
            }
            _ => {}
        }
    }

    fn act_output(&mut self, a: Action, now: Instant) {
        let total = self.run.as_ref().map_or(0, |r| r.lines.len());
        match a {
            Action::ScrollUp => {
                self.follow = false;
                self.scroll = self.scroll.saturating_sub(1);
            }
            Action::ScrollDown => self.scroll = (self.scroll + 1).min(total),
            Action::PageUp => {
                self.follow = false;
                self.scroll = self.scroll.saturating_sub(10);
            }
            Action::PageDown => self.scroll = (self.scroll + 10).min(total),
            Action::Top => {
                self.follow = false;
                self.scroll = 0;
            }
            Action::Bottom => {
                self.follow = true;
                self.scroll = total;
            }
            Action::Arm => match self.arm_ready() {
                Err(why) => self.status = Some(why),
                Ok(plan) => {
                    let Some(spec) = self.spec() else { return };
                    let argv = self.armed_argv(&plan);
                    let mut lines = vec![format!("  hemostat {}", argv.join(" "))];
                    lines.push(match self.shown_digest() {
                        Some(d) => format!(
                            "The plan you saw is the dry run `hemostat {}` (digest {d}), on the Output page: the armed run \
                             refuses if the plan it builds is not this one.",
                            plan.join(" ")
                        ),
                        None => format!(
                            "The plan you saw is the dry run `hemostat {}`, on the Output page: the armed run checks the \
                             host again and acts on what it finds then.",
                            plan.join(" ")
                        ),
                    });
                    if !spec.warn.is_empty() {
                        lines.push(spec.warn.to_string());
                    }
                    lines.push(format!("ticket: {}", self.ticket_text()));
                    let req = RunRequest { argv, ticket: self.ticket.clone(), armed: true };
                    self.ask(req, Purpose::Armed, "ARMED RUN: this changes the host".into(), lines, now);
                }
            },
            Action::Stop => match self.run.as_mut() {
                Some(r) if r.outcome.is_none() && stoppable(r) => {
                    r.stopping = true;
                    self.requests.push(VerbRequest::Stop);
                    self.status = Some("stopping…".into());
                }
                Some(r) if r.outcome.is_none() => {
                    self.status = Some("an armed run, or one that writes, is not interrupted: it finishes or fails on its own".into());
                }
                _ => self.status = Some("nothing is running".into()),
            },
            Action::Keep | Action::Revert => {
                let keep = a == Action::Keep;
                let Some(w) = self.window.as_ref().filter(|w| w.closed.is_none()) else {
                    self.status = Some("no window is open".into());
                    return;
                };
                let argv = if keep { w.keep.clone() } else { w.revert.clone() };
                let Some(argv) = argv else {
                    self.status = w.note.clone();
                    return;
                };
                if let Some(why) = self.refusal() {
                    self.status = Some(why);
                    return;
                }
                let left = self.secs_left().unwrap_or(0);
                let lines = vec![
                    format!("  hemostat {}", argv.join(" ")),
                    if keep {
                        format!(
                            "Keeps {} so it does not {} at the deadline ({left}s left). Check a second way in works first.",
                            w.what, w.verb
                        )
                    } else {
                        format!("Puts {} back now, without waiting for the deadline ({left}s left).", w.what)
                    },
                    format!("ticket: {}", self.ticket_text()),
                ];
                let req = RunRequest { argv, ticket: self.ticket.clone(), armed: true };
                let (p, h) = if keep { (Purpose::Keep, "KEEP THE CHANGE?") } else { (Purpose::Revert, "REVERT NOW?") };
                self.ask(req, p, h.into(), lines, now);
            }
            Action::Back => self.stage = if self.form.is_some() { Stage::Form } else { Stage::List },
            _ => {}
        }
    }

    fn act_confirm(&mut self, a: Action) {
        let Some(p) = self.pending.take() else {
            self.stage = Stage::Output;
            return;
        };
        self.confirm_opened = None;
        if a == Action::Apply {
            let now = self.now();
            self.stage = p.back;
            self.start(p.req.argv, p.purpose, p.req.armed, now);
        } else {
            self.stage = p.back;
            self.status = Some("cancelled; nothing was changed".into());
        }
    }

    pub(crate) fn render(&self, area: Rect, buf: &mut Buffer, hits: &mut Hits) -> Drawn {
        let mut out = Drawn { confirm: false };
        if area.width < 40 || area.height < 8 {
            put(buf, area.x, area.y, "(terminal too small for the verbs tab)", Style::default(), area);
            return out;
        }
        let mut body = area;

        if let Some(w) = &self.window {
            let (text, style) = match (&w.closed, self.secs_left()) {
                (None, Some(s)) => (
                    format!(
                        "⚠ {} WILL {} in {s}s unless kept · Keep (p) or Revert (u) on the Output page (each asks first){}",
                        w.what.to_uppercase(),
                        w.verb.to_uppercase(),
                        w.note.as_ref().map_or("", |_| " · its id was NOT found: see the note")
                    ),
                    Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
                ),
                (Some(c), _) => (c.clone(), dim()),
                _ => (String::new(), dim()),
            };
            put(buf, area.x, area.y, &sanitize(&text).cell(usize::from(area.width)), style, area);
            body = Rect::new(area.x, area.y + 1, area.width, area.height - 1);
        }
        if let Some(s) = &self.status {
            let y = body.bottom() - 1;
            put(buf, body.x, y, &sanitize(s).cell(usize::from(body.width)), Style::default().fg(Color::Yellow), body);
            body.height -= 1;
        }
        match self.stage {
            Stage::List => self.render_list(body, buf, hits),
            Stage::Form => self.render_form(body, buf, hits),
            Stage::Value => {
                self.render_form(body, buf, &mut Hits::default());
                self.render_entry(body, buf, hits);
            }
            Stage::Output => self.render_output(body, buf, hits),
            Stage::Confirm => {
                self.render_confirm(area, buf, hits);
                out.confirm = true;
            }
        }
        out
    }

    fn render_list(&self, r: Rect, buf: &mut Buffer, hits: &mut Hits) {
        let bold = Style::default().add_modifier(Modifier::BOLD);
        let list_h = (r.height * 3 / 5).max(5).min(r.height);
        let lr = Rect::new(r.x, r.y, r.width, list_h);
        let title = format!(
            " VERBS · {} · each runs as `hemostat <verb>`, the CLI's own code, its output shown here ",
            self.items.len()
        );
        frame(buf, lr, &title, bold, dim(), r);
        let rows = usize::from(list_h.saturating_sub(2));
        let offset = if rows == 0 { 0 } else { self.selected.saturating_sub(rows - 1) };
        let w = usize::from(r.width.saturating_sub(4));
        for (k, it) in self.items.iter().enumerate().skip(offset).take(rows) {
            let y = lr.y + 1 + (k - offset) as u16;
            let mark = if k == self.selected { "▸" } else { " " };
            let tag = if it.disabled.is_some() { "--" } else { it.spec.kind.tag() };
            let about = match &it.disabled {
                Some(d) => format!("NOT available: {d}"),
                None => it.help.lines().next().unwrap_or("").to_string(),
            };
            let line = format!("{mark} {:<16} {:<6} {about}", it.spec.name, tag);
            let style = match (&it.disabled, it.spec.kind, k == self.selected) {
                (_, _, true) => Style::default().add_modifier(Modifier::REVERSED),
                (Some(_), _, _) => dim(),
                (None, Kind::Act, _) => Style::default().fg(Color::Yellow),
                _ => Style::default(),
            };
            put(buf, lr.x + 1, y, &sanitize(&line).cell(w), style, r);
            hits.push(Rect::new(lr.x + 1, y, lr.width.saturating_sub(3), 1), Action::Select(k));
        }
        if self.items.is_empty() {
            put(buf, lr.x + 2, lr.y + 1, "no verbs are offered in this view", dim(), r);
        }
        if lr.height >= 4 {
            scrollbar(buf, lr.right() - 1, lr.y + 1, lr.height - 2, self.items.len(), offset, rows,
                (Action::Up, Action::Down, Action::PageUp, Action::PageDown), r, hits);
        }
        let hr = Rect::new(r.x, lr.bottom(), r.width, r.height - list_h);
        if hr.height >= 3 {
            if let Some(it) = self.items.get(self.selected) {
                frame(buf, hr, &format!(" hemostat {} ", it.spec.name), bold, dim(), r);
                let mut lines = vec![format!("ticket for armed runs: {}", self.ticket_text())];
                lines.extend(wrap(&sanitize(&it.help).text, w));
                for (i, l) in lines.iter().take(usize::from(hr.height - 2)).enumerate() {
                    put(buf, hr.x + 2, hr.y + 1 + i as u16, &sanitize(l).cell(w), if i == 0 { dim() } else { Style::default() }, r);
                }
            }
        }
    }

    fn field_label(fd: &Field) -> String {
        match (fd.positional, fd.value, fd.required) {
            (true, Some(m), true) => format!("{m} (required)"),
            (true, Some(m), false) => format!("{m} (optional)"),
            (false, Some(m), true) => format!("{} {m} (required)", fd.name),
            (false, Some(m), false) => format!("{} {m}", fd.name),
            _ => fd.name.to_string(),
        }
    }

    fn render_form(&self, r: Rect, buf: &mut Buffer, hits: &mut Hits) {
        let (Some(f), Some(it)) = (self.form.as_ref(), self.form.as_ref().and_then(|f| self.items.get(f.item))) else { return };
        let spec = it.spec;
        let bold = Style::default().add_modifier(Modifier::BOLD);
        let how = match spec.kind {
            Kind::Act => "CHANGES THE HOST: Dry run (d) first, then Arm (a)",
            Kind::Write => "writes files: Run (r) asks first",
            Kind::Watch => "watches for a window: Run (r), Stop (s)",
            Kind::Read => "reads: Run (r)",
            Kind::Change => "CHANGES THE HOST, no dry run: Run (r) asks first",
        };
        let n = self.field_count();
        let fh = (n as u16 + 5).min(r.height.saturating_sub(3)).max(4).min(r.height);
        let fr = Rect::new(r.x, r.y, r.width, fh);
        frame(buf, fr, &format!(" hemostat {} · {how} ", spec.name), bold, dim(), r);
        let w = usize::from(r.width.saturating_sub(4));
        let mut y = fr.y + 1;
        let inner_bottom = fr.bottom().saturating_sub(1);
        if let Some(d) = &it.disabled {
            put(buf, fr.x + 2, y, &sanitize(&format!("NOT AVAILABLE IN THIS IMAGE: {d}")).cell(w), Style::default().fg(Color::Red).add_modifier(Modifier::BOLD), r);
            y += 1;
        }
        let rows = usize::from(inner_bottom.saturating_sub(y).saturating_sub(2));
        let offset = if rows == 0 { 0 } else { f.field.saturating_sub(rows - 1) };
        for i in (0..n).skip(offset).take(rows) {
            let (label, value) = match spec.fields.get(i) {
                Some(fd) => {
                    let v = f.values.get(i).cloned().flatten();
                    let shown = match (fd.value, v) {
                        (None, Some(_)) => "on".to_string(),
                        (None, None) => "off".to_string(),
                        (Some(_), Some(v)) => v,
                        (Some(_), None) => "unset".to_string(),
                    };
                    (Self::field_label(fd), shown)
                }
                None => {
                    let d = match spec.arm {
                        Some(Arm::Window { default, flag, .. }) => format!("{flag} {}", f.window.clone().unwrap_or_else(|| default.to_string())),
                        _ => String::new(),
                    };
                    ("rollback window (s)".to_string(), format!("{d}  (only Arm (a) uses it)"))
                }
            };
            let mark = if i == f.field { "▸" } else { " " };
            let line = format!("{mark} {:<28} {value}", label);
            let style = if i == f.field { Style::default().add_modifier(Modifier::REVERSED) } else { Style::default() };
            put(buf, fr.x + 1, y, &sanitize(&line).cell(w + 1), style, r);
            hits.push(Rect::new(fr.x + 1, y, fr.width.saturating_sub(2), 1), Action::Select(i));
            y += 1;
        }
        if n == 0 {
            put(buf, fr.x + 2, y, "this verb takes no flags here", dim(), r);
            y += 1;
        }
        let will = match (spec.kind, self.plan_argv()) {
            (Kind::Act, Ok(v)) => format!("dry run: hemostat {}", v.join(" ")),
            (_, Ok(v)) => format!("runs: hemostat {}", v.join(" ")),
            (_, Err(why)) => why,
        };
        if y < inner_bottom {
            put(buf, fr.x + 2, y, &sanitize(&will).cell(w), Style::default().fg(Color::Cyan), r);
            y += 1;
        }
        if y < inner_bottom {
            put(buf, fr.x + 2, y, &sanitize(&format!("ticket: {}", self.ticket_text())).cell(w), dim(), r);
        }
        let hr = Rect::new(r.x, fr.bottom(), r.width, r.height - fh);
        if hr.height >= 3 {
            frame(buf, hr, " about ", bold, dim(), r);
            let mut lines: Vec<String> = Vec::new();
            if let Some(fd) = spec.fields.get(f.field) {
                lines.extend(wrap(&format!("{}: {}", Self::field_label(fd), fd.desc), w));
            }
            lines.extend(wrap(&sanitize(&it.help).text, w));
            if !spec.warn.is_empty() {
                lines.extend(wrap(spec.warn, w));
            }
            for (i, l) in lines.iter().take(usize::from(hr.height - 2)).enumerate() {
                put(buf, hr.x + 2, hr.y + 1 + i as u16, &sanitize(l).cell(w), Style::default(), r);
            }
        }
    }

    fn render_entry(&self, r: Rect, buf: &mut Buffer, hits: &mut Hits) {
        let Some(e) = &self.entry else { return };
        let name = match e.target {
            Target::Ticket => "$HEMOSTAT_TICKET (empty: as started; none: no ticket)".to_string(),
            Target::Window => "rollback window, seconds".to_string(),
            Target::Field(i) => self.spec().and_then(|s| s.fields.get(i)).map_or_else(String::new, Self::field_label),
        };
        let start = e.page * PAGE;
        let page: Vec<&str> = e.choices.iter().skip(start).take(PAGE).map(String::as_str).collect();
        let more = if e.choices.len() > PAGE {
            format!(" · choices {}–{} of {} (PgUp/PgDn)", start + 1, start + page.len(), e.choices.len())
        } else {
            String::new()
        };
        let title = format!(" {name}{more} · Enter sets, Esc leaves it ");
        let want = text_panel_height(r.width, page.len().max(if e.choices.is_empty() { 0 } else { PAGE }));
        let h = want.min(r.height);
        if h >= 3 {
            let pr = Rect::new(r.x, r.bottom() - h, r.width, h);
            clear(buf, pr);
            text_panel(buf, pr, &title, &e.text, MAX_VALUE, &page, self.shift, r, hits);
        }
    }

    fn render_output(&self, r: Rect, buf: &mut Buffer, hits: &mut Hits) {
        let Some(run) = &self.run else {
            put(buf, r.x + 1, r.y + 1, "nothing has run yet", dim(), r);
            return;
        };
        let bold = Style::default().add_modifier(Modifier::BOLD);
        let what = match run.purpose {
            Purpose::Plan => "DRY RUN",
            Purpose::Armed => "ARMED",
            Purpose::Keep => "KEEP",
            Purpose::Revert => "REVERT",
            Purpose::Plain => "RUN",
        };
        frame(buf, r, &format!(" {what} · hemostat {} ", run.argv.join(" ")), bold, dim(), r);
        let w = usize::from(r.width.saturating_sub(4));
        let (head, style) = match &run.outcome {
            None => (
                format!(
                    "RUNNING {}s{}",
                    self.now().saturating_duration_since(run.started).as_secs(),
                    if run.stopping { " · stopping" } else { "" }
                ),
                Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
            ),
            Some(o) => (
                o.label.clone(),
                match o.code {
                    Some(0) => Style::default().fg(Color::Green).add_modifier(Modifier::BOLD),
                    Some(5) => Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
                    _ => Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                },
            ),
        };
        put(buf, r.x + 2, r.y + 1, &sanitize(&head).cell(w), style, r);
        let second = match (run.purpose, &run.outcome) {

            (Purpose::Plan, Some(_)) if self.arm_ready().is_ok() => match self.shown_digest() {
                Some(d) => format!("the plan is below and NOTHING was applied · Arm (a) applies exactly this plan ({d}), after asking"),
                None => "the plan is below and NOTHING was applied · Arm (a) runs these flags armed, after asking: it checks the host again"
                    .to_string(),
            },
            (Purpose::Armed | Purpose::Keep | Purpose::Revert, _) => format!("ticket: {}", run.ticket),
            _ if run.dropped > 0 => format!("{} earlier line(s) were not kept", run.dropped),
            _ => format!("{} line(s)", run.lines.len()),
        };
        put(buf, r.x + 2, r.y + 2, &sanitize(&second).cell(w), dim(), r);
        let top = r.y + 3;
        let rows = usize::from(r.bottom().saturating_sub(1).saturating_sub(top));
        let max = run.lines.len().saturating_sub(rows);
        let start = if self.follow && run.outcome.is_none() { max } else { self.scroll.min(max) };
        for (i, l) in run.lines.iter().skip(start).take(rows).enumerate() {
            put(buf, r.x + 2, top + i as u16, &sanitize(l).cell(w), Style::default(), r);
        }
        if run.lines.is_empty() && rows > 0 {
            put(buf, r.x + 2, top, if run.outcome.is_none() { "(nothing printed yet)" } else { "(it printed nothing)" }, dim(), r);
        }
        if rows >= 2 {
            scrollbar(buf, r.right() - 1, top, rows as u16, run.lines.len(), start, rows,
                (Action::ScrollUp, Action::ScrollDown, Action::PageUp, Action::PageDown), r, hits);
        }
    }

    fn render_confirm(&self, r: Rect, buf: &mut Buffer, hits: &mut Hits) {
        let Some(p) = &self.pending else { return };
        let warn = Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD);
        clear(buf, r);
        frame(buf, r, " APPLY? ", warn, dim(), r);
        let w = usize::from(r.width.saturating_sub(4));
        let mut y = r.y + 1;
        let ask = r.bottom().saturating_sub(3);
        put(buf, r.x + 2, y, &sanitize(&p.headline).cell(w), warn, r);
        y += 1;
        for l in &p.lines {
            for part in wrap(&sanitize(l).text, w) {
                if y >= ask {
                    break;
                }
                put(buf, r.x + 2, y, &part, Style::default(), r);
                y += 1;
            }
        }
        if ask > r.y + 1 {
            put(buf, r.x + 2, ask, &sanitize("APPLY? y to apply, any other key to cancel").cell(w), warn, r);
        }

        let ay = r.bottom().saturating_sub(2);
        if ay > ask {
            let text = crate::bindings::verb_apply_text();
            let placed = flow(&[(text, Action::Apply)], r.x + 2, ay, r.width.saturating_sub(4), 1);
            let apply = Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD | Modifier::REVERSED);
            draw_buttons(buf, &placed, r, hits, |_| apply);
            if let Some(pl) = placed.first() {
                let clip = Rect::new(r.x, ay, r.width.saturating_sub(1), 1);
                put(buf, pl.rect.right() + 2, ay, "any other click or key cancels", dim(), clip);
            }
        }
    }
}

fn stoppable(r: &Run) -> bool {
    r.kind.stoppable() && matches!(r.purpose, Purpose::Plain | Purpose::Plan)
}

fn bad_value(v: &str) -> Option<String> {
    if v.split_whitespace().any(|p| p.starts_with('-')) {
        return Some(format!(
            "{v:?} is refused: a value beginning with '-' would be read as a flag. Flags are set on the form, \
             one field each"
        ));
    }
    None
}

fn find_id(lines: &[String], marker: &str) -> Option<String> {
    lines.iter().find_map(|l| {
        let rest = l.split_once(marker)?.1;
        let tok: String = rest.trim_start().chars().take_while(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_').collect();
        (!tok.is_empty()).then_some(tok)
    })
}

pub const PLAN_FLAG: &str = "--plan";

pub const PLAN_VERB: &str = "network";

pub const DIGEST_HEX: usize = 16;

pub fn plan_digest(lines: &[String]) -> Option<String> {
    let marker = format!("{PLAN_FLAG} ");
    let line = lines.iter().rev().find(|l| l.contains(&marker))?;
    let (_, rest) = line.rsplit_once(&marker)?;
    let tok = rest.split_whitespace().next()?;
    (tok.len() == DIGEST_HEX && tok.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))).then(|| tok.to_string())
}
