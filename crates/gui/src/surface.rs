use std::io;
use std::time::{Duration, Instant};

use hemostat_tui::{Hits, Input, Key, Surface, SurfaceEvent};
use ratatui_core::buffer::Buffer;
use ratatui_core::layout::Rect;
use ratatui_core::style::Style;

use crate::backend::{Backend, Mods, RawEvent, RawKey};
use crate::font::{CELL_H, CELL_W};
use crate::render::{self, Look};

const WINDOW: Duration = Duration::from_millis(250);

const MOVE_EVERY: Duration = Duration::from_millis(33);

const AUTO_MAX: u32 = 4;

const WANT: (u32, u32) = (100, 30);

const MAX_ZOOM: u32 = 8;

pub(crate) fn auto_scale((width, height): (u32, u32), floor: u32) -> u32 {
    let floor = floor.clamp(1, AUTO_MAX);
    (floor..=AUTO_MAX)
        .rev()
        .find(|s| width / (CELL_W * s) >= WANT.0 && height / (CELL_H * s) >= WANT.1)
        .unwrap_or(floor)
}

fn view_key(key: RawKey) -> Option<Key> {
    Some(match key {
        RawKey::Char(c) => return char_key(c),
        RawKey::Enter => Key::Enter,
        RawKey::Esc => Key::Esc,
        RawKey::Backspace => Key::Backspace,
        RawKey::Tab => Key::Tab,
        RawKey::BackTab => Key::BackTab,
        RawKey::Up => Key::Up,
        RawKey::Down => Key::Down,
        RawKey::PageUp => Key::PageUp,
        RawKey::PageDown => Key::PageDown,
        RawKey::Home => Key::Home,
        RawKey::End => Key::End,
        RawKey::F(n) => Key::F(n),
        RawKey::Left | RawKey::Right | RawKey::Delete => return None,
    })
}

fn char_key(c: char) -> Option<Key> {
    match c {
        '\r' | '\n' => Some(Key::Enter),
        '\u{8}' | '\u{7f}' => Some(Key::Backspace),
        '\t' => Some(Key::Tab),
        '\u{1b}' => Some(Key::Esc),
        '\u{1}'..='\u{1a}' => char::from_u32(u32::from(c) + 0x60).map(Key::Char),
        c if c.is_control() => None,
        c => Some(Key::Char(c)),
    }
}

pub struct GuiSurface<B: Backend> {
    backend: B,

    scale: u32,

    zoomed: bool,

    hits: Hits,

    pointer: Option<(i32, i32)>,

    hover: Option<(u16, u16)>,

    moved: bool,

    last_move: Option<Instant>,

    since: Option<Instant>,
}

impl<B: Backend> GuiSurface<B> {

    pub fn new(backend: B) -> Self {
        let scale = auto_scale(backend.size(), backend.scale_floor());
        GuiSurface {
            backend,
            scale,
            zoomed: false,
            hits: Hits::default(),
            pointer: None,
            hover: None,
            moved: false,
            last_move: None,
            since: None,
        }
    }

    pub fn backend_mut(&mut self) -> &mut B {
        &mut self.backend
    }

    pub fn notice(&mut self, text: &str) -> io::Result<()> {
        let area = self.area()?;
        let mut buf = Buffer::empty(area);
        let line = hemostat_tui::sanitize(text).cell(usize::from(area.width));
        let width = u16::try_from(hemostat_tui::sanitize::display_width(&line)).unwrap_or(area.width);
        buf.set_string(area.width.saturating_sub(width) / 2, area.height / 2, &line, Style::default());
        self.hits = Hits::default();
        self.moved = false;
        let look = Look { scale: self.scale, hover: self.hover, pointer: self.pointer.filter(|_| self.backend.wants_pointer()) };
        let mut frame = render::render(&buf, &self.hits, &look);

        let cell = i64::from(CELL_H * self.scale);
        let room = i64::from(area.height / 2) * cell - 2 * cell;
        let r = (room / 3).min(i64::from(90 * self.scale)).min(i64::from(frame.width) / 4);
        let extent = r + r / 3 + (r / 8).max(2);
        let centre = i64::from(frame.width) / 2;
        render::wheel(&mut frame, centre, room - extent, r, render::EMBLEM);
        self.backend.present(&frame)
    }

    fn grid(&self) -> (u16, u16) {
        let (w, h) = self.backend.size();
        let cells = |px: u32, per: u32| u16::try_from((px.min(render::MAX_SIDE) / per).max(1)).unwrap_or(u16::MAX);
        (cells(w, CELL_W * self.scale), cells(h, CELL_H * self.scale))
    }

    fn cell_at(&self, x: i32, y: i32) -> Option<(u16, u16)> {
        let (cols, rows) = self.grid();
        let cx = u16::try_from(u32::try_from(x).ok()? / (CELL_W * self.scale)).ok()?;
        let cy = u16::try_from(u32::try_from(y).ok()? / (CELL_H * self.scale)).ok()?;
        (cx < cols && cy < rows).then_some((cx, cy))
    }

    fn point(&mut self, x: i32, y: i32) -> bool {
        let was = (self.hover.and_then(|c| render::under(&self.hits, c)), self.pointer);
        self.pointer = Some((x, y));
        self.hover = self.cell_at(x, y);
        let control = self.hover.and_then(|c| render::under(&self.hits, c));
        control != was.0 || (self.backend.wants_pointer() && self.pointer != was.1)
    }

    fn set_scale(&mut self, scale: u32) {
        self.scale = scale.clamp(1, MAX_ZOOM);

        self.hover = self.pointer.and_then(|(x, y)| self.cell_at(x, y));
    }

    fn zoom(&mut self, c: char) -> bool {
        match c {
            '+' | '=' => {
                self.zoomed = true;
                self.set_scale(self.scale + 1);
            }
            '-' => {
                self.zoomed = true;
                self.set_scale(self.scale.saturating_sub(1));
            }
            '0' => {
                self.zoomed = false;
                self.set_scale(auto_scale(self.backend.size(), self.backend.scale_floor()));
            }
            _ => return false,
        }
        true
    }

    fn key(&mut self, key: RawKey, mods: Mods) -> Option<SurfaceEvent> {
        if let RawKey::Char(c) = key {
            if (mods.ctrl || mods.alt) && self.zoom(c) {
                return Some(SurfaceEvent::Resize);
            }
        }
        view_key(key).map(|k| SurfaceEvent::In(Input::Key(k)))
    }

    fn translate(&mut self, ev: RawEvent) -> Option<SurfaceEvent> {
        match ev {
            RawEvent::Key(k, m) => self.key(k, m),
            RawEvent::PointerMove { x, y } => {
                let changed = self.point(x, y);
                self.moved |= changed;
                None
            }
            RawEvent::PointerDown { x, y } => {
                let changed = self.point(x, y);
                self.moved |= changed;
                self.cell_at(x, y).map(|(x, y)| SurfaceEvent::In(Input::Click { x, y }))
            }
            RawEvent::Wheel { up } => Some(SurfaceEvent::In(Input::Wheel { up })),

            RawEvent::Resized { .. } => {
                let scale =
                    if self.zoomed { self.scale } else { auto_scale(self.backend.size(), self.backend.scale_floor()) };
                self.set_scale(scale);
                Some(SurfaceEvent::Resize)
            }
            RawEvent::Close => Some(SurfaceEvent::Close),
        }
    }

    fn move_due(&self, now: Instant) -> Option<Duration> {
        if !self.moved {
            return None;
        }
        let due = self.last_move.and_then(|t| t.checked_add(MOVE_EVERY)).unwrap_or(now);
        Some(due.saturating_duration_since(now))
    }
}

impl<B: Backend> Surface for GuiSurface<B> {
    fn area(&mut self) -> io::Result<Rect> {
        let (cols, rows) = self.grid();
        Ok(Rect::new(0, 0, cols, rows))
    }

    fn next(&mut self, idle: bool) -> io::Result<Option<SurfaceEvent>> {
        loop {
            let now = Instant::now();
            let start = *self.since.get_or_insert(now);
            let spent = now.saturating_duration_since(start);
            if spent >= WINDOW {
                self.since = None;
                if idle {
                    return Ok(None);
                }
                continue;
            }
            if self.move_due(now) == Some(Duration::ZERO) {
                self.moved = false;
                self.last_move = Some(now);
                return Ok(Some(SurfaceEvent::Resize));
            }
            let left = WINDOW.saturating_sub(spent);
            let wait = self.move_due(now).map_or(left, |d| d.min(left));
            if let Some(ev) = self.backend.poll(wait)? {
                if let Some(out) = self.translate(ev) {
                    self.since = None;
                    return Ok(Some(out));
                }
            }
        }
    }

    fn present(&mut self, buf: &Buffer, hits: &Hits) -> io::Result<()> {
        self.hits = hits.clone();

        self.moved = false;
        let look = Look { scale: self.scale, hover: self.hover, pointer: self.pointer.filter(|_| self.backend.wants_pointer()) };
        let frame = render::render(buf, hits, &look);
        self.backend.present(&frame)
    }

    fn release(&mut self) {
        self.since = None;
        self.backend.release();
    }
}
