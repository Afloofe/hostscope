use std::time::{Duration, Instant};

use ratatui_core::buffer::Buffer;
use ratatui_core::layout::Rect;
use ratatui_core::style::{Color, Modifier, Style};

use crate::bindings::{CONSOLE, CONSOLE_TABS, POSTURE, POSTURE_TABS, QUEUE, QUEUE_TABS};
use crate::chrome::{button_style, dim, draw_buttons, flow, rows_needed, scrollbar, tab_bar, text_panel, text_panel_height, Hits};
use crate::console::ConsoleModel;
use crate::docs::{self, DocsState};
use crate::draw::put;
use crate::input::{Action, Input, Mode, Table};
use crate::posture::PostureModel;
use crate::queue::{Prompt, QCommand, QView, QueueModel, MAX_REASON};
use crate::verbs::{VerbItem, VerbsPane};

pub const CLICK_GUARD: Duration = Duration::from_millis(400);

const WHEEL_LINES: usize = 3;

const MAX_BAND: u16 = 3;

struct Screen {
    tabs: Option<Rect>,
    body: Rect,
    band: Rect,
}

fn screen(area: Rect, band_h: u16) -> Screen {
    if area.height < 3 {
        return Screen { tabs: None, body: Rect::new(area.x, area.y, area.width, 0), band: area };
    }
    let band_h = band_h.min(area.height - 2);
    let body_h = area.height - 1 - band_h;
    Screen {
        tabs: Some(Rect::new(area.x, area.y, area.width, 1)),
        body: Rect::new(area.x, area.y + 1, area.width, body_h),
        band: Rect::new(area.x, area.y + 1 + body_h, area.width, band_h),
    }
}

fn band_rows(items: &[(String, Action)], area: Rect) -> u16 {
    rows_needed(items, area.width.saturating_sub(1), MAX_BAND)
}

fn items_for(table: &Table, chain: &[Mode], area: Rect) -> Vec<(String, Action)> {
    let mut items = table.buttons(chain);
    if area.height < 3 {
        items.retain(|(_, a)| matches!(a, Action::Quit | Action::Cancel | Action::CancelEntry));
    }
    items
}

fn draw_band(buf: &mut Buffer, band: Rect, items: &[(String, Action)], hits: &mut Hits, style: impl Fn(Action) -> Style) {
    let placed = flow(items, band.x + 1, band.y, band.width.saturating_sub(1), band.height);
    draw_buttons(buf, &placed, band, hits, style);
}

fn clicked(hits: &Hits, table: &Table, chain: &[Mode], x: u16, y: u16) -> Option<Action> {
    hits.at(x, y).filter(|a| table.permits(chain, *a))
}

fn is_scroll(a: Action) -> bool {
    matches!(a, Action::ScrollUp | Action::ScrollDown)
}

fn docs_chain(d: &DocsState) -> &'static [Mode] {
    if d.typing.is_some() { &[Mode::TextEntry] } else { &[Mode::Docs, Mode::Global] }
}

fn is_docs_action(a: Action) -> bool {
    matches!(
        a,
        Action::Back
            | Action::ScrollUp
            | Action::ScrollDown
            | Action::PageUp
            | Action::PageDown
            | Action::Top
            | Action::Bottom
            | Action::Search
            | Action::NextMatch
            | Action::PrevMatch
            | Action::NextSection
            | Action::PrevSection
            | Action::Section(_)
            | Action::Contents
            | Action::Type(_)
            | Action::Erase
            | Action::ShiftCase
            | Action::Submit
            | Action::CancelEntry
    )
}

fn verb_confirm_band(table: &Table, area: Rect) -> u16 {
    let rows = |c: &[Mode]| band_rows(&items_for(table, c, area), area);
    VerbsPane::OPENERS.iter().map(|c| rows(c)).chain([rows(&[Mode::VerbConfirm])]).max().unwrap_or(1)
}

fn verb_style(pane: &VerbsPane, open: bool, a: Action) -> Style {
    let verb_action = matches!(
        a,
        Action::DryRun | Action::RunVerb | Action::ShowOutput | Action::Arm | Action::Stop | Action::Keep | Action::Revert | Action::Edit | Action::Clear
    );
    if open && verb_action && !pane.enabled(a) { dim() } else { button_style(a) }
}

fn verb_confirm_click(pane: &mut VerbsPane, hits: &Hits, x: u16, y: u16, now: Instant) {
    if pane.confirm_opened.is_some_and(|t| now.saturating_duration_since(t) < CLICK_GUARD) {
        return;
    }
    let yes = hits.at(x, y) == Some(Action::Apply);
    pane.act(if yes { Action::Apply } else { Action::Cancel }, now);
}

fn step_tab(at: usize, n: usize, a: Action) -> Option<usize> {
    match a {
        Action::NextTab => Some((at + 1) % n),
        Action::PrevTab => Some((at + n - 1) % n),
        Action::GoTab(i) => Some(usize::from(i).min(n - 1)),
        Action::Docs => Some(n - 1),
        _ => None,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsoleEffect {

    None,

    Quit,

    Rescan,

    Confirm(bool),
}

#[derive(Debug, Clone)]
pub struct ConsoleApp {

    pub model: ConsoleModel,

    pub docs_open: bool,

    pub docs: DocsState,

    pub evidence_scroll: usize,

    pub confirm_opened: Option<Instant>,

    pub verbs: VerbsPane,

    pub verbs_open: bool,
    md: String,
}

impl ConsoleApp {

    pub fn new(model: ConsoleModel) -> Self {
        ConsoleApp {
            model,
            docs_open: false,
            docs: DocsState::default(),
            evidence_scroll: 0,
            confirm_opened: None,
            verbs: VerbsPane::new(Vec::new()),
            verbs_open: false,
            md: docs::markdown(&CONSOLE),
        }
    }

    pub fn with_verbs(mut self, items: Vec<VerbItem>) -> Self {
        self.verbs = VerbsPane::new(items);
        self
    }

    pub fn chain(&self) -> &'static [Mode] {
        if self.model.confirming {
            &[Mode::Confirm]
        } else if self.verbs_open && self.verbs.confirming() {
            &[Mode::VerbConfirm]
        } else if self.docs_open {
            docs_chain(&self.docs)
        } else if self.verbs_open {
            self.verbs.chain()
        } else if self.model.inspecting {
            &[Mode::Evidence, Mode::Global]
        } else {
            &[Mode::Findings, Mode::Global]
        }
    }

    fn tab(&self) -> usize {
        if self.docs_open {
            3
        } else if self.verbs_open {
            2
        } else if self.model.inspecting {
            1
        } else {
            0
        }
    }

    fn band_h(&self, area: Rect) -> u16 {
        let rows = |chain: &[Mode]| band_rows(&items_for(&CONSOLE, chain, area), area);
        if self.model.confirming {
            [&[Mode::Findings, Mode::Global][..], &[Mode::Evidence, Mode::Global], &[Mode::Confirm]]
                .iter()
                .map(|c| rows(c))
                .max()
                .unwrap_or(1)
        } else if self.verbs_open && self.verbs.confirming() {
            verb_confirm_band(&CONSOLE, area)
        } else {
            rows(self.chain())
        }
    }

    pub fn render(&self, area: Rect, buf: &mut Buffer) -> Hits {
        let mut hits = Hits::default();
        let chain = self.chain();
        let mut items = items_for(&CONSOLE, chain, area);

        items.retain(|(_, a)| *a != Action::Apply);
        let scr = screen(area, self.band_h(area));
        if let Some(t) = scr.tabs {
            tab_bar(buf, t, CONSOLE_TABS, self.tab(), self.verbs.alert().as_deref(), &mut hits);
        }
        if self.docs_open {
            docs::render(&self.md, &self.docs, scr.body, buf, &mut hits);
        } else if self.verbs_open {
            self.verbs.render(scr.body, buf, &mut hits);
        } else if scr.body.height > 0 {
            let body = crate::console::render_body(&self.model, scr.body, buf, Some(self.evidence_scroll));
            if let Some((r, offset, rows)) = body.list {
                for k in 0..rows {
                    hits.push(Rect::new(r.x + 1, r.y + 1 + k as u16, r.width.saturating_sub(3), 1), Action::Select(offset + k));
                }
                if r.height >= 4 {
                    let visible = usize::from(r.height - 2);
                    scrollbar(buf, r.right() - 1, r.y + 1, r.height - 2, self.model.findings.len(), offset, visible,
                        (Action::Up, Action::Down, Action::PageUp, Action::PageDown), area, &mut hits);
                }
            }
            if let Some((r, total, visible)) = body.evidence {
                if r.height >= 4 {
                    scrollbar(buf, r.right() - 1, r.y + 1, r.height - 2, total, self.evidence_scroll, visible,
                        (Action::ScrollUp, Action::ScrollDown, Action::PageUp, Action::PageDown), area, &mut hits);
                }
            }
            if body.confirm {

                let y = scr.body.bottom() - 2;
                if let Some(text) = CONSOLE.in_mode(Mode::Confirm).find(|b| b.action == Action::Apply).and_then(|b| b.button_text()) {
                    let placed = flow(&[(text, Action::Apply)], scr.body.x + 2, y, scr.body.width.saturating_sub(4), 1);
                    let apply = Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD | Modifier::REVERSED);
                    draw_buttons(buf, &placed, area, &mut hits, |_| apply);
                    if let Some(p) = placed.first() {
                        let clip = Rect::new(scr.body.x, y, scr.body.width.saturating_sub(1), 1);
                        put(buf, p.rect.right() + 2, y, "any other click or key cancels", dim(), clip);
                    }
                }
            }
        }
        let has_fix = self.model.findings.get(self.model.selected).is_some_and(|f| f.remedy.is_some());
        let open = self.verbs_open;
        draw_band(buf, scr.band, &items, &mut hits, |a| {
            if a == Action::Fix && !has_fix { dim() } else { verb_style(&self.verbs, open, a) }
        });
        hits
    }

    fn body_area(&self, area: Rect) -> Rect {
        screen(area, self.band_h(area)).body
    }

    pub fn handle(&mut self, input: Input, now: Instant, area: Rect) -> ConsoleEffect {
        let chain = self.chain();
        match input {
            Input::Key(k) => match CONSOLE.lookup(chain, k) {
                Some(a) => self.act(a, now, area),
                None => ConsoleEffect::None,
            },
            Input::Click { x, y } => {
                if self.model.confirming {

                    if self.confirm_opened.is_some_and(|t| now.saturating_duration_since(t) < CLICK_GUARD) {
                        return ConsoleEffect::None;
                    }
                    let mut scratch = Buffer::empty(area);
                    let hits = self.render(area, &mut scratch);
                    let yes = hits.at(x, y) == Some(Action::Apply);
                    return self.act(if yes { Action::Apply } else { Action::Cancel }, now, area);
                }
                if self.verbs_open && self.verbs.confirming() {
                    let mut scratch = Buffer::empty(area);
                    let hits = self.render(area, &mut scratch);
                    verb_confirm_click(&mut self.verbs, &hits, x, y, now);
                    return ConsoleEffect::None;
                }
                let mut scratch = Buffer::empty(area);
                let hits = self.render(area, &mut scratch);
                match clicked(&hits, &CONSOLE, chain, x, y) {
                    Some(a) => self.act(a, now, area),
                    None => ConsoleEffect::None,
                }
            }
            Input::Wheel { up } => {
                let Some(a) = CONSOLE.wheel(chain, up) else { return ConsoleEffect::None };
                let n = if is_scroll(a) { WHEEL_LINES } else { 1 };
                for _ in 0..n {
                    self.act(a, now, area);
                }
                ConsoleEffect::None
            }
        }
    }

    fn evidence_dims(&self, area: Rect) -> (usize, usize) {
        let mut scratch = Buffer::empty(area);
        let b = crate::console::render_body(&self.model, self.body_area(area), &mut scratch, Some(0));
        b.evidence.map_or((0, 0), |(_, t, v)| (t, v))
    }

    fn act(&mut self, a: Action, now: Instant, area: Rect) -> ConsoleEffect {
        if self.model.confirming {
            return match a {
                Action::Apply => ConsoleEffect::Confirm(true),
                _ => ConsoleEffect::Confirm(false),
            };
        }
        if self.verbs_open && self.verbs.confirming() {
            self.verbs.act(a, now);
            return ConsoleEffect::None;
        }
        if let Some(t) = step_tab(self.tab(), CONSOLE_TABS.len(), a) {
            self.docs_open = t == 3;

            if t < 3 {
                self.verbs_open = t == 2;
            }
            if t < 2 {
                if self.model.inspecting != (t == 1) {
                    self.model.last_result = None;
                    self.evidence_scroll = 0;
                }
                self.model.inspecting = t == 1;
            }
            return ConsoleEffect::None;
        }
        if a == Action::Quit {
            return if self.verbs.quit_ok() { ConsoleEffect::Quit } else { ConsoleEffect::None };
        }
        if self.docs_open {
            let body = self.body_area(area);
            if is_docs_action(a) && docs::act(&self.md, &mut self.docs, a, body) {
                self.docs_open = false;
            }
            return ConsoleEffect::None;
        }
        if self.verbs_open {
            self.verbs.act(a, now);
            return ConsoleEffect::None;
        }
        match a {
            Action::Up => {
                self.model.up();
                self.evidence_scroll = 0;
            }
            Action::Down => {
                self.model.down();
                self.evidence_scroll = 0;
            }
            Action::PageUp | Action::PageDown if !self.model.inspecting => {
                let mut scratch = Buffer::empty(area);
                let page = crate::console::render_body(&self.model, self.body_area(area), &mut scratch, Some(0))
                    .list
                    .map_or(1, |(r, _, _)| usize::from(r.height.saturating_sub(2)).max(1));
                for _ in 0..page {
                    if a == Action::PageUp { self.model.up() } else { self.model.down() }
                }
            }
            Action::ScrollUp | Action::ScrollDown | Action::PageUp | Action::PageDown => {
                let (total, visible) = self.evidence_dims(area);
                let max = total.saturating_sub(visible);
                let page = visible.saturating_sub(1).max(1);
                self.evidence_scroll = match a {
                    Action::ScrollUp => self.evidence_scroll.saturating_sub(1),
                    Action::ScrollDown => self.evidence_scroll + 1,
                    Action::PageUp => self.evidence_scroll.saturating_sub(page),
                    _ => self.evidence_scroll + page,
                }
                .min(max);
            }
            Action::Select(i) if i < self.model.findings.len() => self.model.selected = i,
            Action::Inspect => {
                self.model.inspecting = !self.model.inspecting;
                self.model.last_result = None;
                self.evidence_scroll = 0;
            }
            Action::Fix => {
                self.model.offer_fix();
                if self.model.confirming {
                    self.confirm_opened = Some(now);
                }
            }
            Action::Rescan => return ConsoleEffect::Rescan,
            _ => {}
        }
        ConsoleEffect::None
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PostureEffect {

    None,

    Quit,

    Reprobe,
}

#[derive(Debug, Clone)]
pub struct PostureApp {

    pub model: PostureModel,

    pub docs_open: bool,

    pub docs: DocsState,

    pub verbs: VerbsPane,

    pub verbs_open: bool,
    md: String,
}

impl PostureApp {

    pub fn new(model: PostureModel) -> Self {
        PostureApp {
            model,
            docs_open: false,
            docs: DocsState::default(),
            verbs: VerbsPane::new(Vec::new()),
            verbs_open: false,
            md: docs::markdown(&POSTURE),
        }
    }

    pub fn with_verbs(mut self, items: Vec<VerbItem>) -> Self {
        self.verbs = VerbsPane::new(items);
        self
    }

    pub fn chain(&self) -> &'static [Mode] {
        if self.verbs_open && self.verbs.confirming() {
            &[Mode::VerbConfirm]
        } else if self.docs_open {
            docs_chain(&self.docs)
        } else if self.verbs_open {
            self.verbs.chain()
        } else {
            &[Mode::Posture, Mode::Global]
        }
    }

    fn tab(&self) -> usize {
        if self.docs_open {
            2
        } else {
            usize::from(self.verbs_open)
        }
    }

    fn scr(&self, area: Rect) -> Screen {
        if self.verbs_open && self.verbs.confirming() {
            return screen(area, verb_confirm_band(&POSTURE, area));
        }
        screen(area, band_rows(&items_for(&POSTURE, self.chain(), area), area))
    }

    pub fn render(&self, area: Rect, buf: &mut Buffer) -> Hits {
        let mut hits = Hits::default();
        let mut items = items_for(&POSTURE, self.chain(), area);
        items.retain(|(_, a)| *a != Action::Apply);
        let scr = self.scr(area);
        if let Some(t) = scr.tabs {
            tab_bar(buf, t, POSTURE_TABS, self.tab(), self.verbs.alert().as_deref(), &mut hits);
        }
        if self.docs_open {
            docs::render(&self.md, &self.docs, scr.body, buf, &mut hits);
        } else if self.verbs_open {
            self.verbs.render(scr.body, buf, &mut hits);
        } else if scr.body.height > 0 {
            crate::posture::render_view(&self.model, scr.body, buf, false);
        }
        let open = self.verbs_open;
        draw_band(buf, scr.band, &items, &mut hits, |a| verb_style(&self.verbs, open, a));
        hits
    }

    pub fn handle(&mut self, input: Input, area: Rect) -> PostureEffect {
        self.handle_at(input, Instant::now(), area)
    }

    pub fn handle_at(&mut self, input: Input, now: Instant, area: Rect) -> PostureEffect {
        let chain = self.chain();
        let a = match input {
            Input::Key(k) => POSTURE.lookup(chain, k),
            Input::Click { x, y } => {
                let mut scratch = Buffer::empty(area);
                let hits = self.render(area, &mut scratch);
                if self.verbs_open && self.verbs.confirming() {
                    verb_confirm_click(&mut self.verbs, &hits, x, y, now);
                    return PostureEffect::None;
                }
                clicked(&hits, &POSTURE, chain, x, y)
            }
            Input::Wheel { up } => POSTURE.wheel(chain, up),
        };
        let Some(a) = a else { return PostureEffect::None };
        let n = if matches!(input, Input::Wheel { .. }) && is_scroll(a) { WHEEL_LINES } else { 1 };
        let mut out = PostureEffect::None;
        for _ in 0..n {
            out = self.act(a, now, area);
        }
        out
    }

    fn act(&mut self, a: Action, now: Instant, area: Rect) -> PostureEffect {
        if self.verbs_open && self.verbs.confirming() {
            self.verbs.act(a, now);
            return PostureEffect::None;
        }
        if let Some(t) = step_tab(self.tab(), POSTURE_TABS.len(), a) {
            self.docs_open = t == 2;
            if t < 2 {
                self.verbs_open = t == 1;
            }
            return PostureEffect::None;
        }
        if a == Action::Quit {
            return if self.verbs.quit_ok() { PostureEffect::Quit } else { PostureEffect::None };
        }
        if self.verbs_open && !self.docs_open {
            self.verbs.act(a, now);
            return PostureEffect::None;
        }
        match a {
            Action::Reprobe if !self.docs_open => PostureEffect::Reprobe,
            a if self.docs_open && is_docs_action(a) => {
                let body = self.scr(area).body;
                if docs::act(&self.md, &mut self.docs, a, body) {
                    self.docs_open = false;
                }
                PostureEffect::None
            }
            _ => PostureEffect::None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QueueEffect {

    None,

    Quit,

    Command(QCommand),
}

#[derive(Debug, Clone)]
pub struct QueueApp {

    pub model: QueueModel,

    pub docs_open: bool,

    pub docs: DocsState,

    pub shift: bool,

    pub verbs: VerbsPane,

    pub verbs_open: bool,
    md: String,
}

impl QueueApp {

    pub fn new(model: QueueModel) -> Self {
        QueueApp {
            model,
            docs_open: false,
            docs: DocsState::default(),
            shift: false,
            verbs: VerbsPane::new(Vec::new()),
            verbs_open: false,
            md: docs::markdown(&QUEUE),
        }
    }

    pub fn with_verbs(mut self, items: Vec<VerbItem>) -> Self {
        self.verbs = VerbsPane::new(items);
        self
    }

    pub fn chain(&self) -> &'static [Mode] {
        if self.verbs_open && self.verbs.confirming() {
            &[Mode::VerbConfirm]
        } else if self.docs_open {
            docs_chain(&self.docs)
        } else if self.verbs_open {
            self.verbs.chain()
        } else {
            self.model.chain()
        }
    }

    fn tab(&self) -> usize {
        if self.docs_open {
            return 4;
        }
        if self.verbs_open {
            return 3;
        }
        match self.model.current_view() {
            QView::Queue | QView::Detail => 0,
            QView::Hosts => 1,
            QView::Cluster => 2,
        }
    }

    fn scr(&self, area: Rect) -> Screen {
        if self.verbs_open && self.verbs.confirming() {
            return screen(area, verb_confirm_band(&QUEUE, area));
        }
        screen(area, band_rows(&items_for(&QUEUE, self.chain(), area), area))
    }

    pub fn render(&self, area: Rect, buf: &mut Buffer) -> Hits {
        let mut hits = Hits::default();
        let mut items = items_for(&QUEUE, self.chain(), area);
        items.retain(|(_, a)| *a != Action::Apply);
        let scr = self.scr(area);
        if let Some(t) = scr.tabs {
            tab_bar(buf, t, QUEUE_TABS, self.tab(), self.verbs.alert().as_deref(), &mut hits);
        }
        if self.docs_open {
            docs::render(&self.md, &self.docs, scr.body, buf, &mut hits);
        } else if self.verbs_open {
            self.verbs.render(scr.body, buf, &mut hits);
        } else if scr.body.height > 0 {
            let body = crate::queue::render_body(&self.model, scr.body, buf, true);

            if let (Some((r, offset, rows)), None) = (body.list, &self.model.prompt) {
                for k in 0..rows {
                    hits.push(Rect::new(r.x + 1, r.y + 2 + k as u16, r.width.saturating_sub(3), 1), Action::Select(offset + k));
                }
                if r.height >= 5 {
                    scrollbar(buf, r.right() - 1, r.y + 2, r.height - 3, self.model.rows.len(), offset, usize::from(r.height - 3),
                        (Action::Up, Action::Down, Action::PageUp, Action::PageDown), area, &mut hits);
                }
            }
            if let Some((r, total, visible)) = body.lines {
                if r.height >= 4 {
                    scrollbar(buf, r.right() - 1, r.y + 1, r.height - 2, total, self.model.scroll, visible,
                        (Action::ScrollUp, Action::ScrollDown, Action::PageUp, Action::PageDown), area, &mut hits);
                }
            }

            if let (Some(fy), Some(p)) = (body.footer_y, &self.model.prompt) {
                let title = match p {
                    Prompt::Resolve { kind: Some(k), .. } => Some(format!(
                        " RESOLVE {} AS {}: REASON ",
                        self.model.selected_id().unwrap_or("?"),
                        match k { 't' => "TRUE-POSITIVE", 'f' => "FALSE-POSITIVE", _ => "BENIGN" }
                    )),
                    Prompt::Note { .. } => Some(format!(" NOTE ON {} ", self.model.selected_id().unwrap_or("?"))),
                    Prompt::Resolve { kind: None, .. } => None,
                };
                let text = match p {
                    Prompt::Resolve { text, .. } | Prompt::Note { text } => text.as_str(),
                };
                if let Some(title) = title {
                    let canned = self.model.canned();
                    let want = text_panel_height(scr.body.width, canned.len());
                    let h = want.min(fy.saturating_sub(scr.body.y));
                    if h >= 3 {
                        let r = Rect::new(scr.body.x, fy - h, scr.body.width, h);
                        crate::draw::clear(buf, r);
                        text_panel(buf, r, &title, text, MAX_REASON, canned, self.shift, area, &mut hits);
                    }
                }
            }
        }
        let open = self.verbs_open;
        draw_band(buf, scr.band, &items, &mut hits, |a| verb_style(&self.verbs, open, a));
        hits
    }

    pub fn handle(&mut self, input: Input, area: Rect) -> QueueEffect {
        self.handle_at(input, Instant::now(), area)
    }

    pub fn handle_at(&mut self, input: Input, now: Instant, area: Rect) -> QueueEffect {
        let chain = self.chain();
        let a = match input {
            Input::Key(k) => {
                if self.model.prompt.is_none() && !self.docs_open && !self.verbs_open {
                    self.model.status = None;
                }
                QUEUE.lookup(chain, k)
            }
            Input::Click { x, y } => {
                let mut scratch = Buffer::empty(area);
                let hits = self.render(area, &mut scratch);
                if self.verbs_open && self.verbs.confirming() {
                    verb_confirm_click(&mut self.verbs, &hits, x, y, now);
                    return QueueEffect::None;
                }
                clicked(&hits, &QUEUE, chain, x, y)
            }
            Input::Wheel { up } => QUEUE.wheel(chain, up),
        };
        let Some(a) = a else { return QueueEffect::None };
        let n = if matches!(input, Input::Wheel { .. }) && is_scroll(a) { WHEEL_LINES } else { 1 };
        let mut out = QueueEffect::None;
        for _ in 0..n {
            out = self.act(a, now, area);
        }
        out
    }

    fn act(&mut self, a: Action, now: Instant, area: Rect) -> QueueEffect {
        if self.verbs_open && self.verbs.confirming() {
            self.verbs.act(a, now);
            return QueueEffect::None;
        }
        if a == Action::ShiftCase && (self.model.prompt.is_some() && !self.docs_open && !self.verbs_open) {
            self.shift = !self.shift;
            return QueueEffect::None;
        }
        if self.model.prompt.is_none() {
            if let Some(t) = step_tab(self.tab(), QUEUE_TABS.len(), a) {
                self.docs_open = t == 4;
                if t < 4 {
                    self.verbs_open = t == 3;
                }
                if t < 3 {
                    self.model.act(Action::GoTab(t as u8));
                }
                return QueueEffect::None;
            }
        }
        if a == Action::Quit && !self.verbs.quit_ok() {
            return QueueEffect::None;
        }
        if self.verbs_open && !self.docs_open {
            if a == Action::Quit {
                return QueueEffect::Quit;
            }
            self.verbs.act(a, now);
            return QueueEffect::None;
        }
        if self.docs_open {
            if a == Action::Quit {
                return QueueEffect::Quit;
            }
            let body = self.scr(area).body;
            if is_docs_action(a) && docs::act(&self.md, &mut self.docs, a, body) {
                self.docs_open = false;
            }
            return QueueEffect::None;
        }
        match self.model.act(a) {
            Some(QCommand::Quit) => QueueEffect::Quit,
            Some(c) => QueueEffect::Command(c),
            None => QueueEffect::None,
        }
    }
}
