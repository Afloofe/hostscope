use ratatui_core::buffer::Buffer;
use ratatui_core::layout::Rect;
use ratatui_core::style::{Color, Modifier, Style};

use crate::draw::{frame, pad, put};
use crate::sanitize;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Confidence {

    Measured,

    Inferred,

    Unknown,
}

impl Confidence {
    fn tag(self) -> &'static str {
        match self {
            Confidence::Measured => "measured",
            Confidence::Inferred => "inferred",
            Confidence::Unknown => "unknown",
        }
    }

    fn style(self) -> Style {
        match self {
            Confidence::Measured => Style::default().fg(Color::Green),
            Confidence::Inferred => Style::default().fg(Color::Yellow),
            Confidence::Unknown => Style::default().fg(Color::Red),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Row {

    pub label: String,

    pub value: String,

    pub confidence: Confidence,

    pub note: String,
}

#[derive(Debug, Clone, Default)]
pub struct PostureModel {

    pub variant: String,

    pub version: String,

    pub tier: String,

    pub tier_meaning: String,

    pub rows: Vec<Row>,

    pub warnings: Vec<String>,

    pub hooks: Vec<HookLine>,
}

#[derive(Debug, Clone)]
pub struct HookLine {

    pub name: String,

    pub state: String,

    pub buys: String,

    pub usable: bool,
}

pub fn render(model: &PostureModel, area: Rect, buf: &mut Buffer) {
    render_view(model, area, buf, true);
}

pub(crate) fn render_view(model: &PostureModel, area: Rect, buf: &mut Buffer, keys: bool) {
    if area.width < 46 || area.height < 12 {
        put(buf, area.x, area.y, "(terminal too small for the posture view)",
            Style::default(), area);
        return;
    }
    let dim = Style::default().fg(Color::DarkGray);
    let bold = Style::default().add_modifier(Modifier::BOLD);

    let warn_h = if model.warnings.is_empty() { 0 } else { model.warnings.len() as u16 + 2 };
    let cap_h = model.rows.len() as u16 + 2;
    let head_h = 4;
    let hooks_h = area.height.saturating_sub(head_h + cap_h + warn_h + u16::from(keys));

    let mut y = area.y;

    let title = format!(
        " HEMOSTAT {} · variant {} ",
        sanitize(&model.version).text,
        sanitize(&model.variant).text
    );
    frame(buf, Rect::new(area.x, y, area.width, head_h), &title, bold, dim, area);
    let tier = sanitize(&model.tier);
    put(buf, area.x + 2, y + 1, "enforcement tier", dim, area);
    put(buf, area.x + 19, y + 1, &tier.text,
        Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD), area);
    let meaning = sanitize(&model.tier_meaning);
    put(buf, area.x + 2, y + 2, &meaning.cell(area.width as usize - 4), dim, area);
    y += head_h;

    frame(buf, Rect::new(area.x, y, area.width, cap_h), " WHAT THIS HOST PERMITS ", bold, dim, area);
    let label_w = model.rows.iter()
        .map(|r| sanitize(&r.label).text.chars().count()).max().unwrap_or(8).clamp(8, 22);
    let value_w = model.rows.iter()
        .map(|r| sanitize(&r.value).text.chars().count()).max().unwrap_or(4).clamp(4, 16);
    for (i, row) in model.rows.iter().enumerate() {
        let ry = y + 1 + i as u16;
        if ry >= y + cap_h - 1 { break; }
        let label = sanitize(&row.label);
        let value = sanitize(&row.value);
        let note = sanitize(&row.note);
        put(buf, area.x + 2, ry, &pad(&label.cell(label_w), label_w), Style::default(), area);
        let vx = area.x + 2 + label_w as u16 + 2;
        put(buf, vx, ry, &pad(&value.cell(value_w), value_w), bold, area);
        let cx = vx + value_w as u16 + 2;
        put(buf, cx, ry, row.confidence.tag(), row.confidence.style(), area);
        let nx = cx + 10;
        if nx < area.right() - 2 && !note.text.is_empty() {
            put(buf, nx, ry, &note.cell((area.right() - 2 - nx) as usize), dim, area);
        }
        if let Some(kind) = worst_of(&[&label, &value, &note]) {
            let wx = area.right().saturating_sub(kind.len() as u16 + 2);
            if wx > nx { put(buf, wx, ry, kind, Style::default().fg(Color::Red), area); }
        }
    }
    y += cap_h;

    if hooks_h >= 3 && !model.hooks.is_empty() {
        let usable = model.hooks.iter().filter(|h| h.usable).count();
        let t = format!(" LSM HOOKS · {usable} of {} usable ", model.hooks.len());
        frame(buf, Rect::new(area.x, y, area.width, hooks_h), &t, bold, dim, area);
        let name_w = model.hooks.iter()
            .map(|h| sanitize(&h.name).text.chars().count()).max().unwrap_or(20).clamp(12, 30);
        for (i, h) in model.hooks.iter().enumerate() {
            let hy = y + 1 + i as u16;
            if hy >= y + hooks_h - 1 { break; }
            let name = sanitize(&h.name);
            let state = sanitize(&h.state);
            let buys = sanitize(&h.buys);
            put(buf, area.x + 2, hy, &pad(&name.cell(name_w), name_w), Style::default(), area);
            let sx = area.x + 2 + name_w as u16 + 2;
            put(buf, sx, hy, &pad(&state.cell(18), 18),
                if h.usable { Style::default().fg(Color::Green) }
                else { Style::default().fg(Color::Red) }, area);
            let bx = sx + 20;
            if bx < area.right() - 2 {
                put(buf, bx, hy, &buys.cell((area.right() - 2 - bx) as usize), dim, area);
            }
        }
        y += hooks_h;
    }

    if warn_h > 0 && y + warn_h <= area.bottom() {
        frame(buf, Rect::new(area.x, y, area.width, warn_h), " ACT ON THIS ", bold,
              Style::default().fg(Color::Yellow), area);
        for (i, w) in model.warnings.iter().enumerate() {
            let wy = y + 1 + i as u16;
            if wy >= y + warn_h - 1 { break; }
            let s = sanitize(w);
            put(buf, area.x + 2, wy, &format!("! {}", s.cell(area.width as usize - 6)),
                Style::default().fg(Color::Yellow), area);
        }
        y += warn_h;
    }

    if keys && y < area.bottom() {
        put(buf, area.x + 1, y, "q quit   r re-probe", dim, area);
    }
}

fn worst_of(parts: &[&sanitize::Sanitized]) -> Option<&'static str> {
    parts.iter().find_map(|p| p.threats.worst())
}

pub fn to_text(model: &PostureModel, width: u16, height: u16) -> String {
    let area = Rect::new(0, 0, width, height);
    let mut buf = Buffer::empty(area);
    render_view(model, area, &mut buf, false);
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
