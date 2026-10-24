use ratatui_core::buffer::Buffer;
use ratatui_core::layout::Rect;
use ratatui_core::style::{Color, Modifier, Style};

use crate::draw::put;
use crate::input::Action;
use crate::sanitize;

#[derive(Debug, Clone, Default)]
pub struct Hits(Vec<(Rect, Action)>);

impl Hits {

    pub fn push(&mut self, r: Rect, a: Action) {
        if r.width > 0 && r.height > 0 {
            self.0.push((r, a));
        }
    }

    pub fn at(&self, x: u16, y: u16) -> Option<Action> {
        self.0.iter().rev().find(|(r, _)| x >= r.x && x < r.right() && y >= r.y && y < r.bottom()).map(|(_, a)| *a)
    }

    pub fn rect_of(&self, a: Action) -> Option<Rect> {
        self.0.iter().find(|(_, x)| *x == a).map(|(r, _)| *r)
    }

    pub fn iter(&self) -> impl Iterator<Item = &(Rect, Action)> {
        self.0.iter()
    }

    pub fn any(&self, f: impl Fn(Action) -> bool) -> bool {
        self.0.iter().any(|(_, a)| f(*a))
    }
}

pub(crate) fn dim() -> Style {
    Style::default().fg(Color::DarkGray)
}

fn width_of(s: &str) -> u16 {
    u16::try_from(sanitize::display_width(s)).unwrap_or(u16::MAX)
}

pub(crate) fn tab_bar(
    buf: &mut Buffer,
    row: Rect,
    tabs: &[(&str, Action)],
    active: usize,
    alert: Option<&str>,
    hits: &mut Hits,
) {
    if row.height == 0 || row.width == 0 {
        return;
    }
    let mut x = row.x;
    for (i, (label, action)) in tabs.iter().enumerate() {
        let text = format!(" {} {label} ", i + 1);
        let w = width_of(&text);
        if x.saturating_add(w) > row.right() {
            break;
        }
        let style = if i == active {
            Style::default().add_modifier(Modifier::BOLD | Modifier::REVERSED)
        } else {
            Style::default()
        };
        put(buf, x, row.y, &text, style, row);
        hits.push(Rect::new(x, row.y, w, 1), *action);
        x += w;
        if x < row.right() {
            put(buf, x, row.y, "│", dim(), row);
            x += 1;
        }
    }
    let (hint, style) = match alert {
        Some(a) => (sanitize(a).text, Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
        None => ("F1/? docs".to_string(), dim()),
    };
    let hw = width_of(&hint);
    if row.right() > hw && x + 2 < row.right() - hw {
        put(buf, row.right() - hw - 1, row.y, &hint, style, row);
    }
}

#[derive(Debug, Clone)]
pub(crate) struct Placed {
    pub(crate) rect: Rect,
    pub(crate) text: String,
    pub(crate) action: Action,
}

pub(crate) fn flow(items: &[(String, Action)], x0: u16, y0: u16, width: u16, max_rows: u16) -> Vec<Placed> {
    let mut out = Vec::new();
    if width < 3 || max_rows == 0 {
        return out;
    }
    let right = x0.saturating_add(width);
    let (mut x, mut row) = (x0, 0u16);
    for (label, action) in items {
        let mut text = format!("[{label}]");
        let mut w = width_of(&text);
        if w > width {
            let inner = sanitize(label).cell(usize::from(width.saturating_sub(2)));
            text = format!("[{inner}]");
            w = width_of(&text).min(width);
        }
        if x > x0 && x.saturating_add(w) > right {
            row += 1;
            x = x0;
        }
        if row >= max_rows {
            break;
        }
        out.push(Placed { rect: Rect::new(x, y0.saturating_add(row), w, 1), text, action: *action });
        x = x.saturating_add(w).saturating_add(1);
    }
    out
}

pub(crate) fn rows_needed(items: &[(String, Action)], width: u16, cap: u16) -> u16 {
    flow(items, 0, 0, width, cap).iter().map(|p| p.rect.y + 1).max().unwrap_or(0)
}

pub(crate) fn draw_buttons(buf: &mut Buffer, placed: &[Placed], area: Rect, hits: &mut Hits, style: impl Fn(Action) -> Style) {
    for p in placed {
        put(buf, p.rect.x, p.rect.y, &p.text, style(p.action), area);
        hits.push(p.rect, p.action);
    }
}

pub(crate) fn button_style(_: Action) -> Style {
    Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn scrollbar(
    buf: &mut Buffer,
    x: u16,
    y: u16,
    h: u16,
    total: usize,
    offset: usize,
    visible: usize,
    (up, down, pgup, pgdn): (Action, Action, Action, Action),
    area: Rect,
    hits: &mut Hits,
) {
    if h < 2 || x >= area.right() {
        return;
    }
    let arrow = Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD);
    put(buf, x, y, "▲", arrow, area);
    hits.push(Rect::new(x, y, 1, 1), up);
    put(buf, x, y + h - 1, "▼", arrow, area);
    hits.push(Rect::new(x, y + h - 1, 1, 1), down);
    let track = h.saturating_sub(2);
    if track == 0 {
        return;
    }
    let t = usize::from(track);
    let (start, len) = if total <= visible || total == 0 {
        (0, t)
    } else {
        let len = (t * visible / total).clamp(1, t);
        let span = total - visible;
        let start = ((t - len) * offset.min(span)) / span.max(1);
        (start, len)
    };
    for i in 0..t {
        let yy = y + 1 + i as u16;
        let thumb = i >= start && i < start + len;
        put(buf, x, yy, if thumb { "█" } else { "░" }, dim(), area);
        if !thumb {
            hits.push(Rect::new(x, yy, 1, 1), if i < start { pgup } else { pgdn });
        }
    }
}

const KEYS: &str = "abcdefghijklmnopqrstuvwxyz0123456789.,-_/:;'()!?@#+=%&";

pub(crate) fn keyboard(buf: &mut Buffer, r: Rect, shift: bool, area: Rect, hits: &mut Hits) -> u16 {
    let items = keyboard_items(shift);
    let placed = flow(&items, r.x, r.y, r.width, r.height);
    for p in &placed {
        let style = match p.action {
            Action::Type(_) => Style::default().add_modifier(Modifier::BOLD),
            _ => Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
        };
        put(buf, p.rect.x, p.rect.y, &p.text, style, area);
        hits.push(p.rect, p.action);
    }
    placed.iter().map(|p| p.rect.y + 1 - r.y).max().unwrap_or(0)
}

fn keyboard_items(shift: bool) -> Vec<(String, Action)> {
    let mut items: Vec<(String, Action)> = KEYS
        .chars()
        .map(|c| {
            let c = if shift { c.to_ascii_uppercase() } else { c };
            (c.to_string(), Action::Type(c))
        })
        .collect();
    items.push(("Space".into(), Action::Type(' ')));
    items.push(("⌫".into(), Action::Erase));
    items.push((if shift { "aA".into() } else { "Aa".into() }, Action::ShiftCase));
    items
}

pub(crate) fn keyboard_rows(width: u16) -> u16 {
    rows_needed(&keyboard_items(false), width, 12)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn text_panel(
    buf: &mut Buffer,
    r: Rect,
    title: &str,
    text: &str,
    max: usize,
    canned: &[&str],
    shift: bool,
    area: Rect,
    hits: &mut Hits,
) {
    let warn = Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD);
    crate::draw::frame(buf, r, title, warn, dim(), area);
    if r.width < 6 || r.height < 3 {
        return;
    }
    let inner = Rect::new(r.x + 2, r.y + 1, r.width - 4, r.height - 2);
    let count = format!(" {}/{max}", text.chars().count());
    let shown = sanitize(text).text;

    let room = usize::from(inner.width).saturating_sub(sanitize::display_width(&count) + 1);
    let tail: String = {
        let mut cs: Vec<char> = shown.chars().collect();
        while sanitize::display_width(&cs.iter().collect::<String>()) > room && !cs.is_empty() {
            cs.remove(0);
        }
        cs.into_iter().collect()
    };
    put(buf, inner.x, inner.y, &format!("{tail}▏{count}"), Style::default().fg(Color::Yellow), area);
    let mut y = inner.y + 1;
    for (i, c) in canned.iter().enumerate().take(crate::bindings::CANNED_SLOTS) {
        if y >= inner.bottom() {
            break;
        }
        let line = format!("F{} · {}", i + 2, c);
        let cell = sanitize(&line).cell(usize::from(inner.width));
        put(buf, inner.x, y, &cell, Style::default().fg(Color::Green), area);
        hits.push(Rect::new(inner.x, y, width_of(&cell).min(inner.width), 1), Action::Canned(i));
        y += 1;
    }
    if y < inner.bottom() {
        keyboard(buf, Rect::new(inner.x, y, inner.width, inner.bottom() - y), shift, area, hits);
    }
}

pub(crate) fn text_panel_height(width: u16, canned: usize) -> u16 {
    2 + 1 + canned.min(crate::bindings::CANNED_SLOTS) as u16 + keyboard_rows(width.saturating_sub(4))
}
