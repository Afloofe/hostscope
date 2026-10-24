use ratatui_core::buffer::Buffer;
use ratatui_core::layout::Rect;
use ratatui_core::style::Style;

use crate::sanitize;

pub(crate) fn put(buf: &mut Buffer, x: u16, y: u16, s: &str, style: Style, area: Rect) {
    if y < area.y || y >= area.bottom() {
        return;
    }
    for (cx, ch) in (x..).zip(s.chars()) {
        if cx >= area.right() {
            break;
        }
        if let Some(cell) = buf.cell_mut((cx, y)) {
            cell.set_char(ch);
            cell.set_style(style);
        }
    }
}

pub(crate) fn frame(buf: &mut Buffer, r: Rect, title: &str, title_style: Style, rule: Style, area: Rect) {
    if r.width < 4 || r.height < 2 { return; }
    let inner = r.width as usize - 2;
    put(buf, r.x, r.y, &format!("┌{}┐", "─".repeat(inner)), rule, area);
    for yy in (r.y + 1)..(r.y + r.height - 1) {
        put(buf, r.x, yy, "│", rule, area);
        put(buf, r.x + r.width - 1, yy, "│", rule, area);
    }
    put(buf, r.x, r.y + r.height - 1, &format!("└{}┘", "─".repeat(inner)), rule, area);
    let t = sanitize(title);
    put(buf, r.x + 2, r.y, &t.cell(inner.saturating_sub(2)), title_style, area);
}

pub(crate) fn pad(s: &str, w: usize) -> String {
    let n = sanitize::display_width(s);
    if n >= w { s.to_string() } else { format!("{s}{}", " ".repeat(w - n)) }
}

pub(crate) fn clear(buf: &mut Buffer, r: Rect) {
    let r = r.intersection(buf.area);
    for y in r.y..r.bottom() {
        for x in r.x..r.right() {
            if let Some(cell) = buf.cell_mut((x, y)) {
                cell.reset();
            }
        }
    }
}
