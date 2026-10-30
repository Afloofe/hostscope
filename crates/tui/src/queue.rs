use ratatui_core::buffer::Buffer;
use ratatui_core::layout::Rect;
use ratatui_core::style::{Color, Modifier, Style};

use crate::console::{wrap, Sev};
use crate::input::{Action, Mode};
use crate::draw::{frame, pad, put};
use crate::sanitize;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueueRow {

    pub id: String,

    pub severity: Sev,

    pub current: Option<Sev>,

    pub host: String,

    pub variant: String,

    pub source: String,

    pub subject: String,

    pub sightings: usize,

    pub state: String,

    pub owner: String,

    pub age: String,

    pub absent: bool,

    pub detail: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QView {

    Queue,

    Hosts,

    Detail,

    Cluster,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Prompt {

    Resolve {

        kind: Option<char>,

        text: String,
    },

    Note {

        text: String,
    },
}

pub use crate::input::Key as QKey;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QCommand {

    Ack(String),

    Investigate(String),

    Resolve(String, char, String),

    Note(String, String),

    Refresh,

    Quit,
}

pub const MAX_REASON: usize = 500;

#[derive(Debug, Clone, Default)]
pub struct QueueModel {

    pub title: String,

    pub actor: String,

    pub rows: Vec<QueueRow>,

    pub hosts: Vec<String>,

    pub cluster: Vec<String>,

    pub anomalies: Vec<String>,

    pub selected: usize,

    pub view: Option<QView>,

    pub prompt: Option<Prompt>,

    pub status: Option<String>,

    pub scroll: usize,
}

impl QueueModel {

    pub fn current_view(&self) -> QView {
        self.view.unwrap_or(QView::Queue)
    }

    pub fn selected_id(&self) -> Option<&str> {
        self.rows.get(self.selected).map(|r| r.id.as_str())
    }

    pub fn carry_from(&mut self, old: &QueueModel) {
        if let Some(id) = old.selected_id() {
            if let Some(i) = self.rows.iter().position(|r| r.id == id) {
                self.selected = i;
            }
        }
        if self.selected >= self.rows.len() {
            self.selected = self.rows.len().saturating_sub(1);
        }
        self.view = old.view;
        self.scroll = old.scroll;
    }

    pub(crate) fn chain(&self) -> &'static [Mode] {
        match &self.prompt {
            Some(Prompt::Resolve { kind: None, .. }) => &[Mode::ResolveKind],
            Some(_) => &[Mode::Reason, Mode::TextEntry],
            None => match self.current_view() {
                QView::Queue => &[Mode::Alerts, Mode::Global],
                QView::Detail => &[Mode::Detail, Mode::Global],
                QView::Hosts | QView::Cluster => &[Mode::Lines, Mode::Global],
            },
        }
    }

    pub fn canned(&self) -> &'static [&'static str] {
        match &self.prompt {
            Some(Prompt::Resolve { kind: Some(_), .. }) => RESOLVE_REASONS,
            Some(Prompt::Note { .. }) => NOTE_TEXTS,
            _ => &[],
        }
    }

    pub fn key(&mut self, k: QKey) -> Option<QCommand> {
        if self.prompt.is_none() {
            self.status = None;
        }
        let a = crate::bindings::QUEUE.lookup(self.chain(), k)?;
        self.act(a)
    }

    pub fn act(&mut self, a: Action) -> Option<QCommand> {
        if self.prompt.is_some() {
            return self.prompt_act(a);
        }
        self.status = None;
        let view = self.current_view();
        let id = self.selected_id().map(str::to_string);
        let last = self.rows.len().saturating_sub(1);
        match a {
            Action::Quit => return Some(QCommand::Quit),
            Action::Back => {
                self.view = Some(QView::Queue);
                self.scroll = 0;
            }
            Action::Up => self.selected = self.selected.saturating_sub(1),
            Action::Down => self.selected = (self.selected + 1).min(last),
            Action::ScrollUp => self.scroll = self.scroll.saturating_sub(1),
            Action::ScrollDown => self.scroll += 1,
            Action::PageUp => match view {
                QView::Queue => self.selected = self.selected.saturating_sub(10),
                _ => self.scroll = self.scroll.saturating_sub(10),
            },
            Action::PageDown => match view {
                QView::Queue => self.selected = (self.selected + 10).min(last),
                _ => self.scroll += 10,
            },

            Action::Select(i) if i < self.rows.len() => {
                if i == self.selected && view == QView::Queue {
                    return self.act(Action::Open);
                }
                self.selected = i;
            }
            Action::Open => {
                if view == QView::Queue && id.is_some() {
                    self.view = Some(QView::Detail);
                    self.scroll = 0;
                }
            }
            Action::NextTab | Action::PrevTab => {
                let order = [QView::Queue, QView::Hosts, QView::Cluster];
                let at = order.iter().position(|v| *v == view).unwrap_or(0);
                let n = if a == Action::NextTab { at + 1 } else { at + order.len() - 1 };
                self.view = order.get(n % order.len()).copied();
                self.scroll = 0;
            }
            Action::GoTab(i) => {
                self.view = Some(match i {
                    1 => QView::Hosts,
                    2 => QView::Cluster,
                    _ => QView::Queue,
                });
                self.scroll = 0;
            }
            Action::Reread => return Some(QCommand::Refresh),
            Action::Ack | Action::Investigate | Action::Resolve | Action::Note => {

                if !matches!(view, QView::Queue | QView::Detail) {
                    self.status = Some("triage keys work on the queue and the detail view".to_string());
                    return None;
                }
                let id = id?;
                match a {
                    Action::Ack => return Some(QCommand::Ack(id)),
                    Action::Investigate => return Some(QCommand::Investigate(id)),
                    Action::Resolve => self.prompt = Some(Prompt::Resolve { kind: None, text: String::new() }),
                    _ => self.prompt = Some(Prompt::Note { text: String::new() }),
                }
            }
            _ => {}
        }
        None
    }

    fn prompt_act(&mut self, a: Action) -> Option<QCommand> {
        let id = self.selected_id().map(str::to_string);
        let canned = self.canned();
        let p = self.prompt.as_mut()?;
        if a == Action::CancelEntry {
            self.prompt = None;
            self.status = Some("cancelled; nothing was recorded".to_string());
            return None;
        }
        let text = match p {
            Prompt::Resolve { kind: kind @ None, .. } => {
                if let Action::ResolveAs(c @ ('t' | 'f' | 'b')) = a {
                    *kind = Some(c);
                }
                return None;
            }
            Prompt::Resolve { text, .. } | Prompt::Note { text } => text,
        };
        match a {
            Action::Type(c) if !c.is_control() => {
                if text.chars().count() < MAX_REASON {
                    text.push(c);
                }
                None
            }
            Action::Erase => {
                text.pop();
                None
            }

            Action::Canned(i) => {
                if let Some(c) = canned.get(i) {
                    *text = c.chars().take(MAX_REASON).collect();
                }
                None
            }
            Action::Submit => {
                if text.trim().is_empty() {
                    self.status = Some("a reason is required: it is what the ledger keeps of the judgement".to_string());
                    return None;
                }
                let reason = text.trim().to_string();
                let cmd = match (self.prompt.take(), id) {
                    (Some(Prompt::Resolve { kind: Some(kind), .. }), Some(id)) => QCommand::Resolve(id, kind, reason),
                    (Some(Prompt::Note { .. }), Some(id)) => QCommand::Note(id, reason),
                    _ => return None,
                };
                Some(cmd)
            }
            _ => None,
        }
    }
}

pub const RESOLVE_REASONS: &[&str] = &[
    "authorised admin activity, confirmed with the host owner",
    "red team implant: removed on the host and verified gone",
    "scoring engine or white team traffic",
    "stock package behaviour, verified against the package",
    "duplicate of another alert about the same thing",
    "expected: a change the response team made",
];

pub const NOTE_TEXTS: &[&str] = &[
    "looked at the host: still present",
    "looked at the host: gone",
    "escalated to the team lead",
    "waiting on the host owner",
    "evidence collected from the host",
    "needs a second pair of eyes",
];

fn dim() -> Style {
    Style::default().fg(Color::DarkGray)
}

pub fn render(model: &QueueModel, area: Rect, buf: &mut Buffer) {
    let _ = render_body(model, area, buf, false);
}

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct QBody {

    pub(crate) list: Option<(Rect, usize, usize)>,

    pub(crate) lines: Option<(Rect, usize, usize)>,

    pub(crate) footer_y: Option<u16>,
}

pub(crate) fn render_body(model: &QueueModel, area: Rect, buf: &mut Buffer, live: bool) -> QBody {
    let mut out = QBody::default();
    if area.width < 60 || area.height < 10 {
        put(buf, area.x, area.y, "(terminal too small for the queue)", Style::default(), area);
        return out;
    }
    let bold = Style::default().add_modifier(Modifier::BOLD);
    let crit = model.rows.iter().filter(|r| r.severity == Sev::Critical).count();
    let warn = model.rows.iter().filter(|r| r.severity == Sev::Warn).count();
    let note = model.rows.len() - crit - warn;
    let title = format!(" Mahoraga queue · {} · {} ", sanitize(&model.title).text, sanitize(&model.actor).text);
    let head = Rect::new(area.x, area.y, area.width, 3);
    frame(buf, head, &title, bold, dim(), area);
    let mut cx = area.x + 2;
    for (s, n, sev) in [("CRITICAL", crit, Sev::Critical), ("WARN", warn, Sev::Warn), ("note", note, Sev::Note)] {
        let t = format!("{n} {s}");
        put(buf, cx, area.y + 1, &t, if n > 0 { sev.style() } else { dim() }, area);
        cx += t.chars().count() as u16 + 3;
    }
    let tabs = match model.current_view() {
        QView::Queue => "[queue] hosts cluster",
        QView::Hosts => "queue [hosts] cluster",
        QView::Cluster => "queue hosts [cluster]",
        QView::Detail => "[detail] queue hosts cluster",
    };
    let tx = area.right().saturating_sub(tabs.chars().count() as u16 + 2);
    if tx > cx && !live {
        put(buf, tx, area.y + 1, tabs, dim(), area);
    }

    let mut top = area.y + 3;
    for a in model.anomalies.iter().take(2) {
        let line = sanitize(&format!("! {a}"));
        put(buf, area.x + 1, top, &line.cell(area.width as usize - 2), Sev::Critical.style(), area);
        top += 1;
    }
    if model.anomalies.len() > 2 {
        put(buf, area.x + 1, top, &format!("! and {} more: `queue list` prints them all", model.anomalies.len() - 2), Sev::Critical.style(), area);
        top += 1;
    }

    let foot_h = if live { 1u16 } else { 2u16 };
    let body = Rect::new(area.x, top, area.width, area.bottom().saturating_sub(top + foot_h));
    match model.current_view() {
        QView::Queue => out.list = Some(render_list(model, body, buf, area, bold)),
        QView::Detail => {
            let lines = model.rows.get(model.selected).map(|r| r.detail.clone()).unwrap_or_default();
            out.lines = Some(render_lines(" DETAIL ", &lines, model.scroll, body, buf, area, bold));
        }
        QView::Hosts => out.lines = Some(render_lines(" HOSTS ", &model.hosts, model.scroll, body, buf, area, bold)),
        QView::Cluster => {
            out.lines = Some(render_lines(" CLUSTER ", &model.cluster, model.scroll, body, buf, area, bold));
        }
    }
    let fy = area.bottom().saturating_sub(foot_h);
    out.footer_y = Some(fy);
    render_footer(model, fy, buf, area, live);
    out
}

fn render_list(model: &QueueModel, r: Rect, buf: &mut Buffer, area: Rect, bold: Style) -> (Rect, usize, usize) {
    frame(buf, r, &format!(" {} ALERT(S) ", model.rows.len()), bold, dim(), area);
    if r.height < 4 {
        return (r, 0, 0);
    }
    let w = r.width as usize - 2;

    let (hw, vw, sw, nw, stw, ow, aw) = (12usize, 9usize, 12usize, 4usize, 24usize, 16usize, 6usize);
    let fixed = 2 + 9 + hw + vw + sw + nw + stw + ow + aw + 9;
    let subw = w.saturating_sub(fixed).max(10);
    let header = format!(
        "  {} {} {} {} {} {} {} {} {}",
        pad("SEV", 8),
        pad("HOST", hw),
        pad("VARIANT", vw),
        pad("SOURCE", sw),
        pad("SUBJECT", subw),
        pad("SEEN", nw),
        pad("STATE", stw),
        pad("OWNER", ow),
        "AGE"
    );

    let (head, _) = hemostat_safestr::truncate_to_width(&header, w);
    put(buf, r.x + 1, r.y + 1, &head, bold, area);
    let rows = r.height.saturating_sub(3) as usize;
    if model.rows.is_empty() {
        put(buf, r.x + 2, r.y + 2, "no alerts: nothing ingested has raised one (the host view says what was heard from)", dim(), area);
        return (r, 0, 0);
    }
    let offset = if rows > 0 && model.selected >= rows { model.selected + 1 - rows } else { 0 };
    let geometry = (r, offset, rows.min(model.rows.len() - offset.min(model.rows.len())));
    for (i, row) in model.rows.iter().enumerate().skip(offset).take(rows) {
        let y = r.y + 2 + (i - offset) as u16;
        let sel = i == model.selected;
        let state = if row.absent { format!("{} · absent", row.state) } else { row.state.clone() };

        let sev = match row.current {
            Some(c) if c != row.severity => format!("{}*", row.severity.tag()),
            _ => row.severity.tag().to_string(),
        };
        let line = format!(
            "{}{} {} {} {} {} {} {} {} {}",
            if sel { "▸ " } else { "  " },
            pad(&sanitize(&sev).cell(8), 8),
            pad(&sanitize(&row.host).cell(hw), hw),
            pad(&sanitize(&row.variant).cell(vw), vw),
            pad(&sanitize(&row.source).cell(sw), sw),
            pad(&sanitize(&row.subject).cell(subw), subw),
            pad(&row.sightings.to_string(), nw),
            pad(&sanitize(&state).cell(stw), stw),
            pad(&sanitize(&row.owner).cell(ow), ow),
            sanitize(&row.age).cell(aw),
        );
        let resolved = row.state.starts_with("resolved");

        let mut style = row.severity.style();
        if resolved {
            style = style.add_modifier(Modifier::DIM);
        }
        if sel {
            style = style.add_modifier(Modifier::REVERSED);
        }
        put(buf, r.x + 1, y, &pad(&line, w), style, area);
    }
    geometry
}

fn render_lines(
    title: &str, lines: &[String], scroll: usize, r: Rect, buf: &mut Buffer, area: Rect, bold: Style,
) -> (Rect, usize, usize) {
    frame(buf, r, title, bold, dim(), area);
    let w = (r.width as usize).saturating_sub(4);
    let wrapped: Vec<String> = lines.iter().flat_map(|l| {
        let s = sanitize(l).text;
        let v = wrap(&s, w);
        if v.is_empty() { vec![String::new()] } else { v }
    }).collect();
    let rows = r.height.saturating_sub(2) as usize;
    let start = scroll.min(wrapped.len().saturating_sub(1));
    for (i, l) in wrapped.iter().skip(start).take(rows).enumerate() {
        put(buf, r.x + 2, r.y + 1 + i as u16, l, Style::default(), area);
    }
    (r, wrapped.len(), rows)
}

fn render_footer(model: &QueueModel, y: u16, buf: &mut Buffer, area: Rect, live: bool) {
    let w = area.width as usize - 2;
    let (line1, style) = match &model.prompt {
        Some(Prompt::Resolve { kind: None, .. }) => (
            "resolve as: t true-positive · f false-positive · b benign   (Esc cancels)".to_string(),
            Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
        ),
        Some(Prompt::Resolve { kind: Some(k), text }) => {
            let as_ = match k {
                't' => "true-positive",
                'f' => "false-positive",
                _ => "benign",
            };
            (format!("resolve {as_}, reason: {}▏ (Enter records, Esc cancels)", sanitize(text).text), Style::default().fg(Color::Yellow))
        }
        Some(Prompt::Note { text }) => {
            (format!("note: {}▏ (Enter records, Esc cancels)", sanitize(text).text), Style::default().fg(Color::Yellow))
        }
        None => match &model.status {
            Some(s) => (sanitize(s).text, Style::default().fg(Color::Green)),

            None if live => ("nothing here reaches a host".to_string(), dim()),
            None => (String::new(), dim()),
        },
    };
    put(buf, area.x + 1, y, &sanitize(&line1).cell(w), style, area);
    if live {
        return;
    }

    let keys = "nothing here reaches a host   ↑↓ move  Enter detail  Tab/h/c views  a ack  \
                i investigating  r resolve  n note  g re-read  q quit";
    put(buf, area.x + 1, y + 1, &sanitize(keys).cell(w), dim(), area);
}

pub fn to_text(model: &QueueModel, width: u16, height: u16) -> String {
    let area = Rect::new(0, 0, width, height);
    let mut buf = Buffer::empty(area);
    render(model, area, &mut buf);
    let mut out = String::new();
    for y in 0..height {
        let mut line = String::new();
        for x in 0..width {
            line.push(buf.cell((x, y)).map_or(' ', |c| c.symbol().chars().next().unwrap_or(' ')));
        }
        out.push_str(line.trim_end());
        out.push('\n');
    }
    out
}
