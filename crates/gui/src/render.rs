use hemostat_tui::Hits;
use ratatui_core::buffer::{Buffer, Cell};
use ratatui_core::layout::Position;
use ratatui_core::style::{Color, Modifier};

use crate::font::{self, CELL_H, CELL_W};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {

    pub width: u32,

    pub height: u32,

    pub pixels: Vec<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Look {

    pub scale: u32,

    pub hover: Option<(u16, u16)>,

    pub pointer: Option<(i32, i32)>,
}

pub(crate) const BG: u32 = 0x000F_1419;

pub(crate) const FG: u32 = 0x00D5_DBE1;

pub(crate) const BUTTON: u32 = 0x0023_2B36;

pub(crate) const BUTTON_HOVER: u32 = 0x0036_4456;

pub(crate) const BUTTON_EDGE: u32 = 0x004C_5B6D;

pub(crate) const POINTER_EDGE: u32 = 0x0000_0000;

pub(crate) const POINTER_FILL: u32 = 0x00FF_FFFF;

const UNDERLINE_ROW: u32 = 14;

const MAX_SCALE: u32 = 16;

pub(crate) const MAX_SIDE: u32 = 8192;

fn color(c: Color) -> u32 {
    match c {
        Color::Reset => FG,
        Color::Black => 0x001C_2128,
        Color::Red => 0x00E5_534B,
        Color::Green => 0x0057_AB5A,
        Color::Yellow => 0x00D4_A72C,
        Color::Blue => 0x0053_9BF5,
        Color::Magenta => 0x00B0_83F0,
        Color::Cyan => 0x0039_C5CF,
        Color::Gray => 0x00AD_BAC7,
        Color::DarkGray => 0x0076_8390,
        Color::LightRed => 0x00FF_938A,
        Color::LightGreen => 0x008D_DB8C,
        Color::LightYellow => 0x00F2_CC60,
        Color::LightBlue => 0x0096_D0FF,
        Color::LightMagenta => 0x00DC_BDFB,
        Color::LightCyan => 0x0096_E8F0,
        Color::White => 0x00F0_F3F6,
        Color::Rgb(r, g, b) => rgb(r, g, b),
        Color::Indexed(i) => indexed(i),
    }
}

fn rgb(r: u8, g: u8, b: u8) -> u32 {
    (u32::from(r) << 16) | (u32::from(g) << 8) | u32::from(b)
}

fn indexed(i: u8) -> u32 {
    const NAMED: [Color; 16] = [
        Color::Black,
        Color::Red,
        Color::Green,
        Color::Yellow,
        Color::Blue,
        Color::Magenta,
        Color::Cyan,
        Color::Gray,
        Color::DarkGray,
        Color::LightRed,
        Color::LightGreen,
        Color::LightYellow,
        Color::LightBlue,
        Color::LightMagenta,
        Color::LightCyan,
        Color::White,
    ];
    let level = |v: u8| if v == 0 { 0 } else { 55 + 40 * v };
    match i {
        0..=15 => NAMED.get(usize::from(i)).map_or(FG, |c| color(*c)),
        16..=231 => {
            let n = i - 16;
            rgb(level(n / 36), level((n / 6) % 6), level(n % 6))
        }
        _ => {
            let v = 8 + 10 * (i - 232);
            rgb(v, v, v)
        }
    }
}

fn mix(a: u32, b: u32, num: u32, den: u32) -> u32 {
    let ch = |shift: u32| {
        let (x, y) = ((a >> shift) & 0xFF, (b >> shift) & 0xFF);
        let v = if y >= x { x + (y - x) * num / den } else { x - (x - y) * num / den };
        (v & 0xFF) << shift
    };
    ch(16) | ch(8) | ch(0)
}

fn brighten(c: u32) -> u32 {
    mix(c, 0x00FF_FFFF, 2, 5)
}

impl Frame {
    fn filled(width: u32, height: u32, color: u32) -> Self {
        let n = usize::try_from(u64::from(width) * u64::from(height)).unwrap_or(0);
        Frame { width, height, pixels: vec![color; n] }
    }

    #[cfg(test)]
    pub(crate) fn pixel(&self, x: u32, y: u32) -> Option<u32> {
        if x >= self.width || y >= self.height {
            return None;
        }
        let i = usize::try_from(u64::from(y) * u64::from(self.width) + u64::from(x)).ok()?;
        self.pixels.get(i).copied()
    }

    fn fill(&mut self, x: i64, y: i64, w: i64, h: i64, color: u32) {
        let (x0, y0) = (x.max(0), y.max(0));
        let x1 = x.saturating_add(w).min(i64::from(self.width));
        let y1 = y.saturating_add(h).min(i64::from(self.height));
        if x0 >= x1 || y0 >= y1 {
            return;
        }
        let stride = self.width as usize;
        let (x0, x1) = (x0 as usize, x1 as usize);
        for yy in y0 as usize..y1 as usize {
            let row = yy * stride;
            if let Some(span) = self.pixels.get_mut(row + x0..row + x1) {
                span.fill(color);
            }
        }
    }
}

pub(crate) const EMBLEM: u32 = 0x00D4_A72C;

pub(crate) fn wheel(frame: &mut Frame, cx: i64, cy: i64, r: i64, color: u32) {

    const DIRS: [(i64, i64); 8] =
        [(1000, 0), (707, 707), (0, 1000), (-707, 707), (-1000, 0), (-707, -707), (0, -1000), (707, -707)];
    if r < 4 {
        return;
    }
    let half = (r / 12).max(1);
    let hub = r / 5;
    let reach = r + r / 3;
    let knob = (r / 8).max(2);
    let extent = reach + knob;
    for y in (cy - extent).max(0)..(cy + extent + 1).min(i64::from(frame.height)) {
        for x in (cx - extent).max(0)..(cx + extent + 1).min(i64::from(frame.width)) {
            let (dx, dy) = (x - cx, y - cy);
            let d2 = dx * dx + dy * dy;
            let rim = (r - half) * (r - half) <= d2 && d2 <= (r + half) * (r + half);
            let spoke = DIRS.iter().any(|&(ux, uy)| {
                (0..=reach * 1000).contains(&(dx * ux + dy * uy)) && (dx * uy - dy * ux).abs() <= half * 1000
            });
            let knobbed = DIRS.iter().any(|&(ux, uy)| {
                let (kx, ky) = (dx - reach * ux / 1000, dy - reach * uy / 1000);
                kx * kx + ky * ky <= knob * knob
            });
            if rim || spoke || knobbed || d2 <= hub * hub {
                frame.fill(x, y, 1, 1, color);
            }
        }
    }
}

pub(crate) fn under(hits: &Hits, (x, y): (u16, u16)) -> Option<usize> {
    hits.iter().enumerate().filter(|(_, (r, _))| r.contains(Position { x, y })).map(|(i, _)| i).last()
}

pub fn render(buf: &Buffer, hits: &Hits, look: &Look) -> Frame {
    let scale = look.scale.clamp(1, MAX_SCALE);
    let area = buf.area;
    let width = (u32::from(area.width) * CELL_W * scale).min(MAX_SIDE);
    let height = (u32::from(area.height) * CELL_H * scale).min(MAX_SIDE);
    let mut f = Frame::filled(width, height, BG);
    if width == 0 || height == 0 {
        return f;
    }
    let (cw, ch) = (i64::from(CELL_W * scale), i64::from(CELL_H * scale));

    let at = |x: u16, y: u16| (i64::from(x.saturating_sub(area.x)) * cw, i64::from(y.saturating_sub(area.y)) * ch);
    let index = |x: u16, y: u16| {
        usize::from(y.saturating_sub(area.y)) * usize::from(area.width) + usize::from(x.saturating_sub(area.x))
    };

    let hovered = look.hover.and_then(|c| under(hits, c));
    let mut plain = vec![false; usize::from(area.width) * usize::from(area.height)];
    for (i, (r, _)) in hits.iter().enumerate() {
        let r = r.intersection(area);
        if r.is_empty() {
            continue;
        }
        let (x, y) = at(r.x, r.y);
        let (w, h) = (i64::from(r.width) * cw, i64::from(r.height) * ch);
        f.fill(x, y, w, h, BUTTON_EDGE);
        f.fill(x + 1, y + 1, w - 2, h - 2, if hovered == Some(i) { BUTTON_HOVER } else { BUTTON });
        let (first, last) = ((r.x, r.y), (r.right() - 1, r.bottom() - 1));
        if r.width >= 2 && symbol(buf, first) == Some("[") && symbol(buf, last) == Some("]") {
            for (cx, cy) in [first, last] {
                if let Some(p) = plain.get_mut(index(cx, cy)) {
                    *p = true;
                }
            }
        }
    }

    for y in area.top()..area.bottom() {
        for x in area.left()..area.right() {
            if plain.get(index(x, y)).copied().unwrap_or(false) {
                continue;
            }
            if let Some(cell) = buf.cell((x, y)) {
                let (px, py) = at(x, y);
                draw_cell(&mut f, cell, px, py, scale);
            }
        }
    }

    if let Some((px, py)) = look.pointer {
        draw_pointer(&mut f, px, py, scale);
    }
    f
}

fn symbol(buf: &Buffer, (x, y): (u16, u16)) -> Option<&str> {
    buf.cell((x, y)).map(Cell::symbol)
}

fn draw_cell(f: &mut Frame, cell: &Cell, x: i64, y: i64, scale: u32) {
    let m = cell.modifier;
    let mut fg = color(cell.fg);
    let mut bg = match cell.bg {
        Color::Reset => None,
        c => Some(color(c)),
    };
    if m.contains(Modifier::BOLD) {
        fg = brighten(fg);
    }
    if m.contains(Modifier::DIM) {
        fg = mix(fg, bg.unwrap_or(BG), 1, 2);
    }
    if m.contains(Modifier::REVERSED) {
        let was = fg;
        fg = bg.unwrap_or(BG);
        bg = Some(was);
    }
    let s = i64::from(scale);
    if let Some(b) = bg {
        f.fill(x, y, i64::from(CELL_W) * s, i64::from(CELL_H) * s, b);
    }

    if let Some(c) = cell.symbol().chars().next().filter(|c| *c != ' ') {
        for (row, bits) in (0i64..).zip(font::glyph(c)) {
            for col in 0..8i64 {
                if bits & (0x80 >> col) != 0 {
                    f.fill(x + col * s, y + row * s, s, s, fg);
                }
            }
        }
    }
    if m.contains(Modifier::UNDERLINED) {
        f.fill(x, y + i64::from(UNDERLINE_ROW) * s, i64::from(CELL_W) * s, s, fg);
    }
}

const ARROW: [&str; 17] = [
    "X",
    "XX",
    "X.X",
    "X..X",
    "X...X",
    "X....X",
    "X.....X",
    "X......X",
    "X.......X",
    "X........X",
    "X.....XXXXX",
    "X..X..X",
    "X.X X..X",
    "XX  X..X",
    "X    X..X",
    "     X..X",
    "      XX",
];

fn draw_pointer(f: &mut Frame, px: i32, py: i32, scale: u32) {
    let s = i64::from(scale);
    for (row, line) in (0i64..).zip(ARROW) {
        for (col, b) in (0i64..).zip(line.bytes()) {
            let c = match b {
                b'X' => POINTER_EDGE,
                b'.' => POINTER_FILL,
                _ => continue,
            };
            f.fill(i64::from(px) + col * s, i64::from(py) + row * s, s, s, c);
        }
    }
}
