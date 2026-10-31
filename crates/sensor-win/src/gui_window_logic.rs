use std::collections::VecDeque;
use std::io;
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WinKey {

    Char(char),

    Enter,

    Esc,

    Backspace,

    Tab,

    BackTab,

    Up,

    Down,

    Left,

    Right,

    PageUp,

    PageDown,

    Home,

    End,

    Delete,

    F(u8),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WinEvent {

    Key {

        key: WinKey,

        ctrl: bool,

        alt: bool,

        shift: bool,
    },

    PointerMove {

        x: i32,

        y: i32,
    },

    PointerDown {

        x: i32,

        y: i32,
    },

    Wheel {

        up: bool,
    },

    Resized {

        width: u32,

        height: u32,
    },

    Close,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct KeyMods {

    pub ctrl: bool,

    pub alt: bool,

    pub shift: bool,
}

pub fn key_event(key: WinKey, mods: KeyMods) -> WinEvent {
    WinEvent::Key { key, ctrl: mods.ctrl, alt: mods.alt, shift: mods.shift }
}

pub(crate) const VK_BACK: u16 = 0x08;
pub(crate) const VK_TAB: u16 = 0x09;
pub(crate) const VK_RETURN: u16 = 0x0D;
pub(crate) const VK_ESCAPE: u16 = 0x1B;
pub(crate) const VK_PRIOR: u16 = 0x21;
pub(crate) const VK_NEXT: u16 = 0x22;
pub(crate) const VK_END: u16 = 0x23;
pub(crate) const VK_HOME: u16 = 0x24;
pub(crate) const VK_LEFT: u16 = 0x25;
pub(crate) const VK_UP: u16 = 0x26;
pub(crate) const VK_RIGHT: u16 = 0x27;
pub(crate) const VK_DOWN: u16 = 0x28;
pub(crate) const VK_DELETE: u16 = 0x2E;
pub(crate) const VK_0: u16 = 0x30;
pub(crate) const VK_NUMPAD0: u16 = 0x60;
pub(crate) const VK_ADD: u16 = 0x6B;
pub(crate) const VK_SUBTRACT: u16 = 0x6D;
pub(crate) const VK_F1: u16 = 0x70;
pub(crate) const VK_F4: u16 = 0x73;
pub(crate) const VK_F12: u16 = 0x7B;
pub(crate) const VK_OEM_PLUS: u16 = 0xBB;
pub(crate) const VK_OEM_MINUS: u16 = 0xBD;

pub(crate) const SC_KEYMENU: usize = 0xF100;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyDown {

    Report(WinEvent),

    Pass,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Typing {

    echo: Option<u8>,

    high: Option<u16>,
}

impl Typing {

    pub fn key_down(&mut self, vk: u16, scan: u8, mods: KeyMods) -> KeyDown {
        let decision = classify_key_down(vk, mods);
        self.echo = match decision {
            KeyDown::Report(_) => Some(scan),
            KeyDown::Pass => None,
        };
        decision
    }

    pub fn char_unit(&mut self, unit: u16, scan: u8, mods: KeyMods) -> Option<WinEvent> {
        if self.echo.take() == Some(scan) {
            return None;
        }
        let c = self.assemble(unit)?;
        char_event(c, mods)
    }

    fn assemble(&mut self, unit: u16) -> Option<char> {
        match unit {
            0xD800..=0xDBFF => {
                self.high = Some(unit);
                None
            }
            0xDC00..=0xDFFF => {
                let high = self.high.take()?;
                char::decode_utf16([high, unit]).next()?.ok()
            }
            _ => {
                self.high = None;
                char::from_u32(u32::from(unit))
            }
        }
    }
}

fn classify_key_down(vk: u16, mods: KeyMods) -> KeyDown {
    let report = |key| KeyDown::Report(key_event(key, mods));

    if vk == VK_F4 && mods.alt {
        return KeyDown::Pass;
    }

    if mods.ctrl && !mods.alt {
        let zoom = match vk {

            VK_OEM_PLUS if mods.shift => Some('+'),
            VK_OEM_PLUS => Some('='),
            VK_ADD => Some('+'),
            VK_OEM_MINUS | VK_SUBTRACT => Some('-'),
            VK_0 | VK_NUMPAD0 => Some('0'),
            _ => None,
        };
        if let Some(c) = zoom {
            return report(WinKey::Char(c));
        }
    }
    let key = match vk {
        VK_RETURN => WinKey::Enter,
        VK_ESCAPE => WinKey::Esc,
        VK_BACK => WinKey::Backspace,
        VK_TAB if mods.shift => WinKey::BackTab,
        VK_TAB => WinKey::Tab,
        VK_UP => WinKey::Up,
        VK_DOWN => WinKey::Down,
        VK_LEFT => WinKey::Left,
        VK_RIGHT => WinKey::Right,
        VK_PRIOR => WinKey::PageUp,
        VK_NEXT => WinKey::PageDown,
        VK_HOME => WinKey::Home,
        VK_END => WinKey::End,
        VK_DELETE => WinKey::Delete,
        VK_F1..=VK_F12 => match u8::try_from(vk - VK_F1 + 1) {
            Ok(n) => WinKey::F(n),
            Err(_) => return KeyDown::Pass,
        },
        _ => return KeyDown::Pass,
    };
    report(key)
}

fn char_event(c: char, mods: KeyMods) -> Option<WinEvent> {
    let code = u32::from(c);

    if (1..=26).contains(&code) {
        if !mods.ctrl {
            return None;
        }
        let letter = char::from_u32(u32::from(b'a') + code - 1)?;
        return Some(key_event(WinKey::Char(letter), mods));
    }

    if c.is_control() {
        return None;
    }

    let mods = if mods.ctrl && mods.alt { KeyMods { ctrl: false, alt: false, ..mods } } else { mods };
    Some(key_event(WinKey::Char(c), mods))
}

pub fn swallows_menu_key(wparam: usize, lparam: isize) -> bool {
    wparam & 0xFFF0 == SC_KEYMENU && lparam == 0
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Wheel {

    rest: i32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Notches {

    pub count: u16,

    pub up: bool,
}

pub const WHEEL_NOTCH: i32 = 120;

impl Wheel {

    pub fn feed(&mut self, delta: i16) -> Notches {
        let delta = i32::from(delta);
        if (delta > 0 && self.rest < 0) || (delta < 0 && self.rest > 0) {
            self.rest = 0;
        }

        self.rest += delta;
        let whole = self.rest / WHEEL_NOTCH;
        self.rest -= whole * WHEEL_NOTCH;
        Notches { count: u16::try_from(whole.unsigned_abs()).unwrap_or(u16::MAX), up: whole > 0 }
    }
}

pub const QUEUE_LIMIT: usize = 256;

pub fn enqueue(queue: &mut VecDeque<WinEvent>, event: WinEvent) {
    if let Some(last) = queue.back_mut() {
        let replaces = matches!(
            (&*last, &event),
            (WinEvent::PointerMove { .. }, WinEvent::PointerMove { .. })
                | (WinEvent::Resized { .. }, WinEvent::Resized { .. })
        );
        if replaces {
            *last = event;
            return;
        }
    }
    if event == WinEvent::Close {
        if !queue.contains(&WinEvent::Close) {
            queue.push_back(event);
        }
        return;
    }
    if queue.len() < QUEUE_LIMIT {
        queue.push_back(event);
    }
}

pub fn forget_input(queue: &mut VecDeque<WinEvent>) {
    queue.retain(|e| matches!(e, WinEvent::PointerMove { .. } | WinEvent::Resized { .. } | WinEvent::Close));
}

pub(crate) const HTCLIENT: u16 = 1;

pub const fn hit_test_from_lparam(lparam: isize) -> u16 {
    low_word(lparam as usize)
}

pub fn eats_activating_click(hit_test: u16) -> bool {
    hit_test == HTCLIENT
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bounds {

    pub left: i32,

    pub top: i32,

    pub right: i32,

    pub bottom: i32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Placement {

    pub origin: Option<(i32, i32)>,

    pub size: (i32, i32),
}

pub const PREFERRED_CLIENT: (i32, i32) = (1280, 800);

pub const BASE_DPI: u32 = 96;

const MAX_DPI_SCALE: u32 = 4;

pub fn dpi_scale(dpi: u32) -> u32 {
    (dpi.saturating_mul(2).saturating_add(BASE_DPI) / (2 * BASE_DPI)).clamp(1, MAX_DPI_SCALE)
}

pub fn preferred_client(dpi: u32) -> (i32, i32) {
    let dpi = i64::from(dpi.max(BASE_DPI));
    let base = i64::from(BASE_DPI);
    let at = |side: i32| saturate((i64::from(side) * dpi + base / 2) / base);
    (at(PREFERRED_CLIENT.0), at(PREFERRED_CLIENT.1))
}

pub const WORK_AREA_PERCENT: i64 = 85;

const MAX_FRAME: i32 = 1024;

pub fn placement(work: Option<Bounds>, frame: (i32, i32)) -> Placement {
    placement_for(work, frame, PREFERRED_CLIENT)
}

pub fn placement_for(work: Option<Bounds>, frame: (i32, i32), client: (i32, i32)) -> Placement {
    let frame_w = i64::from(frame.0.clamp(0, MAX_FRAME));
    let frame_h = i64::from(frame.1.clamp(0, MAX_FRAME));
    let want_w = i64::from(client.0.max(1)) + frame_w;
    let want_h = i64::from(client.1.max(1)) + frame_h;
    let Some(work) = work.filter(|w| w.right > w.left && w.bottom > w.top) else {
        return Placement { origin: None, size: (saturate(want_w), saturate(want_h)) };
    };

    let work_w = i64::from(work.right) - i64::from(work.left);
    let work_h = i64::from(work.bottom) - i64::from(work.top);
    let width = want_w.min(work_w * WORK_AREA_PERCENT / 100).max(1);
    let height = want_h.min(work_h * WORK_AREA_PERCENT / 100).max(1);

    let x = i64::from(work.left) + (work_w - width) / 2;
    let y = i64::from(work.top) + (work_h - height) / 2;
    Placement { origin: Some((saturate(x), saturate(y))), size: (saturate(width), saturate(height)) }
}

fn saturate(v: i64) -> i32 {
    i32::try_from(v).unwrap_or(if v < 0 { i32::MIN } else { i32::MAX })
}

pub fn wait_millis(timeout: Duration) -> u32 {
    let ms = timeout.as_nanos().div_ceil(1_000_000);
    u32::try_from(ms).unwrap_or(u32::MAX).min(u32::MAX - 1)
}

pub fn frame_len(width: u32, height: u32, available: usize) -> io::Result<usize> {
    if i32::try_from(width).is_err() || i32::try_from(height).is_err() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("a {width} x {height} frame is larger than a device-independent bitmap can describe"),
        ));
    }

    let n = usize::try_from(u64::from(width) * u64::from(height)).map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidInput, format!("a {width} x {height} frame does not fit in memory"))
    })?;
    if available < n {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("a {width} x {height} frame needs {n} pixels and {available} were given"),
        ));
    }
    Ok(n)
}

pub fn margins(frame: (u32, u32), client: (u32, u32)) -> [Option<Bounds>; 2] {
    let px = |v: u32| i32::try_from(v).unwrap_or(i32::MAX);
    let (fw, fh) = (px(frame.0), px(frame.1));
    let (cw, ch) = (px(client.0), px(client.1));
    let right = (cw > fw && ch > 0).then_some(Bounds { left: fw, top: 0, right: cw, bottom: ch });
    let below_w = fw.min(cw);
    let below = (ch > fh && below_w > 0).then_some(Bounds { left: 0, top: fh, right: below_w, bottom: ch });
    [right, below]
}

pub fn margin_colour(pixels: &[u32]) -> u32 {
    pixels.last().map_or(0, |p| p & 0x00FF_FFFF)
}

pub const fn colorref(rgb: u32) -> u32 {
    ((rgb & 0xFF) << 16) | (rgb & 0xFF00) | ((rgb >> 16) & 0xFF)
}

const fn low_word(v: usize) -> u16 {
    (v & 0xFFFF) as u16
}

const fn high_word(v: usize) -> u16 {
    ((v >> 16) & 0xFFFF) as u16
}

pub const fn point_from_lparam(lparam: isize) -> (i32, i32) {
    let v = lparam as usize;
    (low_word(v) as i16 as i32, high_word(v) as i16 as i32)
}

pub const fn size_from_lparam(lparam: isize) -> (u32, u32) {
    let v = lparam as usize;
    (low_word(v) as u32, high_word(v) as u32)
}

pub const fn wheel_delta(wparam: usize) -> i16 {
    high_word(wparam) as i16
}

pub const fn key_from_wparam(wparam: usize) -> u16 {
    low_word(wparam)
}

pub const fn scan_from_lparam(lparam: isize) -> u8 {
    (((lparam as usize) >> 16) & 0xFF) as u8
}

pub fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().filter(|&u| u != 0).chain(std::iter::once(0)).collect()
}

pub const SESSION_ZERO: &str = "this process is in session 0, where services run and no desktop is \
     ever shown, so a window opened here would be drawn where nobody can see it: the GUI needs an \
     interactive desktop session — run it from the logged-in console or an RDP session";

pub fn refuses_session(session: Option<u32>) -> bool {
    session == Some(0)
}
