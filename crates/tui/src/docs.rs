use ratatui_core::buffer::Buffer;
use ratatui_core::layout::Rect;
use ratatui_core::style::{Color, Modifier, Style};

use crate::chrome::{dim, scrollbar, text_panel, text_panel_height, Hits};
use crate::console::wrap;
use crate::draw::{frame, put};
use crate::input::{Action, Table};
use crate::sanitize;

const PAGES: &[&str] = &[
    include_str!("../../../docs/operator/01-getting-around.md"),
    include_str!("../../../docs/operator/02-console.md"),
    include_str!("../../../docs/operator/10-verbs-tab.md"),
    include_str!("../../../docs/operator/03-severities.md"),
    include_str!("../../../docs/operator/04-human-only.md"),
    include_str!("../../../docs/operator/05-remedies.md"),
    include_str!("../../../docs/operator/06-posture.md"),
    include_str!("../../../docs/operator/07-queue.md"),
    include_str!("../../../docs/operator/08-verbs.md"),
    include_str!("../../../docs/operator/09-recovery.md"),
];

pub fn markdown(this: &Table) -> String {
    let mut out = String::new();
    for (i, p) in PAGES.iter().enumerate() {
        out.push_str(p);
        out.push('\n');
        if i == 0 {
            out.push_str("# Controls\n\nGenerated from the same tables the keys and buttons are dispatched from. Each line is: what it does, its keys, its mouse targets.\n\n");
            out.push_str(&this.controls_markdown());
            for t in crate::bindings::ALL {
                if t.view != this.view {
                    out.push_str(&t.controls_markdown());
                }
            }
        }
    }
    out
}

#[derive(Debug, Clone)]
pub(crate) struct Line {
    pub(crate) text: String,
    pub(crate) style: Style,
}

#[derive(Debug, Clone)]
pub(crate) struct Section {
    pub(crate) title: String,
    pub(crate) level: u8,
    pub(crate) line: usize,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct Laid {
    pub(crate) lines: Vec<Line>,
    pub(crate) sections: Vec<Section>,
}

fn inline(s: &str) -> String {
    s.replace("**", "").replace('`', "")
}

pub(crate) fn layout(md: &str, width: usize) -> Laid {
    let width = width.max(8);
    let mut laid = Laid::default();
    let mut para: Option<(String, bool)> = None;
    fn flush(laid: &mut Laid, para: &mut Option<(String, bool)>, width: usize) {
        if let Some((text, bullet)) = para.take() {
            let clean = sanitize(&inline(&text)).text;
            let w = if bullet { width - 2 } else { width };
            for (i, l) in wrap(&clean, w).into_iter().enumerate() {
                let text = match (bullet, i) {
                    (true, 0) => format!("• {l}"),
                    (true, _) => format!("  {l}"),
                    _ => l,
                };
                laid.lines.push(Line { text, style: Style::default() });
            }
        }
    }
    fn blank(laid: &mut Laid) {
        if laid.lines.last().is_some_and(|l| !l.text.is_empty()) {
            laid.lines.push(Line { text: String::new(), style: Style::default() });
        }
    }
    for raw in md.lines() {
        let line = raw.trim_end();
        let heading = line.chars().take_while(|c| *c == '#').count();
        if heading > 0 && line.chars().nth(heading) == Some(' ') {
            flush(&mut laid, &mut para, width);
            blank(&mut laid);
            let title = sanitize(&inline(line[heading..].trim())).text;
            let level = u8::try_from(heading).unwrap_or(3);
            if level <= 2 {
                laid.sections.push(Section { title: title.clone(), level, line: laid.lines.len() });
            }
            let style = match level {
                1 => Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
                _ => Style::default().add_modifier(Modifier::BOLD),
            };
            let shown = if level == 1 { title.to_uppercase() } else { title };
            for l in wrap(&shown, width) {
                laid.lines.push(Line { text: l, style });
            }
            laid.lines.push(Line { text: String::new(), style: Style::default() });
            continue;
        }
        if line.trim().is_empty() {
            flush(&mut laid, &mut para, width);
            blank(&mut laid);
            continue;
        }
        if let Some(rest) = line.strip_prefix("- ") {
            flush(&mut laid, &mut para, width);
            para = Some((rest.to_string(), true));
            continue;
        }
        match &mut para {
            Some((t, _)) => {
                t.push(' ');
                t.push_str(line.trim());
            }
            None => para = Some((line.trim().to_string(), false)),
        }
    }
    flush(&mut laid, &mut para, width);
    laid
}

#[derive(Debug, Clone, Default)]
pub struct DocsState {

    pub scroll: usize,

    pub query: String,

    pub current: Option<usize>,

    pub contents_toggled: bool,

    pub typing: Option<String>,

    pub shift: bool,

    pub status: Option<String>,
}

const MAX_QUERY: usize = 64;

struct Geom {
    toc: Option<Rect>,
    content: Option<Rect>,
    panel: Option<Rect>,
}

const WIDE: u16 = 72;
const TOC_W: u16 = 26;

fn geom(state: &DocsState, area: Rect) -> Geom {
    let mut rest = area;
    let panel = state.typing.as_ref().map(|_| {
        let want = text_panel_height(area.width, 0).min(area.height.saturating_sub(4).max(3));
        let h = want.min(area.height);
        rest.height = area.height - h;
        Rect::new(area.x, area.y + rest.height, area.width, h)
    });
    let wide = area.width >= WIDE;
    let (toc, content) = if wide {
        if state.contents_toggled {
            (None, Some(rest))
        } else {
            (
                Some(Rect::new(rest.x, rest.y, TOC_W, rest.height)),
                Some(Rect::new(rest.x + TOC_W, rest.y, rest.width - TOC_W, rest.height)),
            )
        }
    } else if state.contents_toggled {
        (Some(rest), None)
    } else {
        (None, Some(rest))
    };
    Geom { toc, content, panel }
}

fn content_dims(r: Rect) -> (usize, usize) {
    (usize::from(r.width.saturating_sub(4)), usize::from(r.height.saturating_sub(2)))
}

fn laid_for(md: &str, state: &DocsState, area: Rect) -> (Laid, usize) {
    let g = geom(state, area);
    let (w, rows) = g.content.map_or((usize::from(area.width.saturating_sub(4)), 0), content_dims);
    (layout(md, w), rows)
}

fn current_section(laid: &Laid, scroll: usize) -> Option<usize> {
    laid.sections.iter().rposition(|s| s.line <= scroll)
}

fn matches(laid: &Laid, q: &str) -> Vec<usize> {
    if q.is_empty() {
        return Vec::new();
    }
    let q = q.to_lowercase();
    laid.lines.iter().enumerate().filter(|(_, l)| l.text.to_lowercase().contains(&q)).map(|(i, _)| i).collect()
}

pub(crate) fn render(md: &str, state: &DocsState, area: Rect, buf: &mut Buffer, hits: &mut Hits) {
    if area.width < 10 || area.height < 3 {
        return;
    }
    let bold = Style::default().add_modifier(Modifier::BOLD);
    let g = geom(state, area);
    let (laid, rows) = laid_for(md, state, area);
    let here = current_section(&laid, state.scroll);
    if let Some(t) = g.toc {
        frame(buf, t, " CONTENTS ", bold, dim(), area);
        let n = usize::from(t.height.saturating_sub(2));
        let first = match here {
            Some(h) if n > 0 && h >= n => h + 1 - n,
            _ => 0,
        };
        for (i, s) in laid.sections.iter().enumerate().skip(first).take(n) {
            let y = t.y + 1 + (i - first) as u16;
            let indent = if s.level == 1 { "" } else { "  " };
            let text = sanitize(&format!("{indent}{}", s.title)).cell(usize::from(t.width.saturating_sub(3)));
            let mut style = if s.level == 1 { bold } else { Style::default() };
            if Some(i) == here {
                style = style.add_modifier(Modifier::REVERSED);
            }
            put(buf, t.x + 1, y, &text, style, area);
            hits.push(Rect::new(t.x + 1, y, t.width.saturating_sub(2), 1), Action::Section(i));
        }
    }
    if let Some(c) = g.content {
        let found = matches(&laid, &state.query);
        let title = match (&state.status, state.query.is_empty()) {
            (Some(s), _) => format!(" DOCS · {s} "),
            (None, false) => format!(" DOCS · /{} ", state.query),
            (None, true) => " DOCS ".to_string(),
        };
        frame(buf, c, &title, bold, dim(), area);
        let start = state.scroll.min(laid.lines.len().saturating_sub(1));
        for (i, l) in laid.lines.iter().enumerate().skip(start).take(rows) {
            let y = c.y + 1 + (i - start) as u16;
            let mut style = l.style;
            if found.contains(&i) {
                style = style.fg(Color::Yellow);
                if state.current == Some(i) {
                    style = style.add_modifier(Modifier::REVERSED);
                }
            }
            put(buf, c.x + 2, y, &l.text, style, area);
        }
        if c.height >= 4 {
            scrollbar(
                buf,
                c.right() - 1,
                c.y + 1,
                c.height - 2,
                laid.lines.len(),
                state.scroll,
                rows,
                (Action::ScrollUp, Action::ScrollDown, Action::PageUp, Action::PageDown),
                area,
                hits,
            );
        }
    }
    if let (Some(p), Some(text)) = (g.panel, &state.typing) {
        text_panel(buf, p, " FIND (Enter searches, Esc stops) ", text, MAX_QUERY, &[], state.shift, area, hits);
    }
}

pub(crate) fn act(md: &str, state: &mut DocsState, a: Action, area: Rect) -> bool {
    let (laid, rows) = laid_for(md, state, area);
    let max = laid.lines.len().saturating_sub(rows.max(1));
    let page = rows.saturating_sub(2).max(1);
    if let Some(text) = state.typing.as_mut() {
        match a {
            Action::Type(c) => {
                if text.chars().count() < MAX_QUERY {
                    text.push(c);
                }
            }
            Action::Erase => {
                text.pop();
            }
            Action::ShiftCase => state.shift = !state.shift,
            Action::CancelEntry => state.typing = None,
            Action::Submit => {
                state.query = state.typing.take().unwrap_or_default().trim().to_string();
                state.current = None;
                let (laid, rows) = laid_for(md, state, area);
                seek(state, &laid, rows, true);
            }
            _ => {}
        }
        return false;
    }
    state.status = None;
    match a {
        Action::ScrollUp => state.scroll = state.scroll.saturating_sub(1),
        Action::ScrollDown => state.scroll = (state.scroll + 1).min(max),
        Action::PageUp => state.scroll = state.scroll.saturating_sub(page),
        Action::PageDown => state.scroll = (state.scroll + page).min(max),
        Action::Top => state.scroll = 0,
        Action::Bottom => state.scroll = max,
        Action::Search => state.typing = Some(state.query.clone()),
        Action::NextMatch => seek(state, &laid, rows, true),
        Action::PrevMatch => seek(state, &laid, rows, false),
        Action::Section(i) => {
            if let Some(s) = laid.sections.get(i) {
                state.scroll = s.line.min(max);
                if area.width < WIDE {
                    state.contents_toggled = false;
                }
            }
        }
        Action::NextSection => {
            if let Some(s) = laid.sections.iter().find(|s| s.line > state.scroll) {
                state.scroll = s.line.min(max);
            }
        }
        Action::PrevSection => {
            if let Some(s) = laid.sections.iter().rev().find(|s| s.line < state.scroll) {
                state.scroll = s.line.min(max);
            }
        }
        Action::Contents => state.contents_toggled = !state.contents_toggled,
        Action::Back => return true,
        _ => {}
    }
    false
}

fn seek(state: &mut DocsState, laid: &Laid, rows: usize, forward: bool) {
    let found = matches(laid, &state.query);
    if state.query.is_empty() {
        state.status = Some("nothing searched yet: / to search".into());
        return;
    }
    if found.is_empty() {
        state.status = Some(format!("no match for {}", state.query));
        state.current = None;
        return;
    }
    let from = state.current.unwrap_or_else(|| if forward { state.scroll.saturating_sub(1) } else { state.scroll });
    let next = if state.current.is_none() && forward {
        found.iter().copied().find(|&l| l >= state.scroll)
    } else if forward {
        found.iter().copied().find(|&l| l > from)
    } else {
        found.iter().rev().copied().find(|&l| l < from)
    };
    let wrapped = if forward { found.first() } else { found.last() };
    let Some(line) = next.or(wrapped.copied()) else { return };
    state.current = Some(line);
    let max = laid.lines.len().saturating_sub(rows.max(1));
    state.scroll = line.saturating_sub(1).min(max);
    let n = found.iter().position(|&l| l == line).map_or(0, |p| p + 1);
    state.status = Some(format!("/{} · match {n} of {}", state.query, found.len()));
}
