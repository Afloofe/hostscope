#![forbid(unsafe_code)]

use std::collections::VecDeque;
use std::fs;
use std::io::{self, Read, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

const SOCKET_DIR: &str = "/tmp/.X11-unix";

const COOKIE_NAME: &[u8] = b"MIT-MAGIC-COOKIE-1";

const MAX_AUTH_FILE: u64 = 64 * 1024;

const MAX_ATTEMPTS: usize = 16;

const MAX_SETUP: usize = 1 << 20;

const MAX_REPLY: usize = 1 << 20;

const ANSWER_WITHIN: Duration = Duration::from_secs(5);

const WRITE_WITHIN: Duration = Duration::from_secs(10);

const MAPPED_WITHIN: Duration = Duration::from_secs(3);

const FIRST_SIZE: (u32, u32) = (1280, 800);

const CREATE_WINDOW: u8 = 1;
const MAP_WINDOW: u8 = 8;
const INTERN_ATOM: u8 = 16;
const CHANGE_PROPERTY: u8 = 18;
const CREATE_GC: u8 = 55;
const CLEAR_AREA: u8 = 61;
const PUT_IMAGE: u8 = 72;
const GET_KEYBOARD_MAPPING: u8 = 101;

const ERROR: u8 = 0;
const REPLY: u8 = 1;
const KEY_PRESS: u8 = 2;
const BUTTON_PRESS: u8 = 4;
const MOTION_NOTIFY: u8 = 6;
const EXPOSE: u8 = 12;
const MAP_NOTIFY: u8 = 19;
const CONFIGURE_NOTIFY: u8 = 22;
const CLIENT_MESSAGE: u8 = 33;
const MAPPING_NOTIFY: u8 = 34;
const GENERIC_EVENT: u8 = 35;

const KEY_PRESS_MASK: u32 = 1 << 0;
const BUTTON_PRESS_MASK: u32 = 1 << 2;
const POINTER_MOTION_MASK: u32 = 1 << 6;
const EXPOSURE_MASK: u32 = 1 << 15;
const STRUCTURE_NOTIFY_MASK: u32 = 1 << 17;

const SHIFT: u16 = 1 << 0;
const LOCK: u16 = 1 << 1;
const CONTROL: u16 = 1 << 2;
const MOD1: u16 = 1 << 3;

const ATOM_ATOM: u32 = 4;
const ATOM_STRING: u32 = 31;
const ATOM_WM_NAME: u32 = 39;
const ATOM_WM_CLASS: u32 = 67;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XKey {

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
pub enum XEvent {

    Key {

        key: XKey,

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

pub fn display_from_env() -> Option<io::Result<Display>> {
    let value = std::env::var_os("DISPLAY")?;
    let value = value.to_str()?.trim();
    if value.is_empty() {
        return None;
    }
    Some(Display::parse(value))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Display {
    number: u32,
    socket: PathBuf,
}

impl Display {

    fn parse(value: &str) -> io::Result<Self> {
        let unsupported = |why: &str| io::Error::new(io::ErrorKind::Unsupported, format!("DISPLAY={value}: {why}"));
        let (host, rest) = value.rsplit_once(':').ok_or_else(|| unsupported("not of the form :N"))?;
        if !host.is_empty() && host != "unix" {
            return Err(unsupported("a display on another host; the GUI opens only on this host's own display"));
        }
        let number = rest.split('.').next().unwrap_or_default();
        let number: u32 = number.parse().map_err(|_| unsupported("the display number is not a number"))?;
        Ok(Display { number, socket: Path::new(SOCKET_DIR).join(format!("X{number}")) })
    }

    pub fn name(&self) -> String {
        format!(":{}", self.number)
    }

    fn check_socket(&self) -> io::Result<()> {
        let refuse = |why: String| io::Error::new(io::ErrorKind::PermissionDenied, why);
        let dir = fs::symlink_metadata(SOCKET_DIR)?;
        if !dir.is_dir() || dir.uid() != 0 || dir.permissions().mode() & 0o1000 == 0 {
            return Err(refuse(format!("{SOCKET_DIR} is not a root-owned sticky directory")));
        }
        let socket = fs::symlink_metadata(&self.socket)
            .map_err(|e| io::Error::new(e.kind(), format!("{}: {e}", self.socket.display())))?;
        let owner = socket.uid();
        let logged_in = Path::new("/run/user").join(owner.to_string()).is_dir();
        if owner != 0 && !logged_in {
            return Err(refuse(format!(
                "{} belongs to uid {owner}, which is neither root nor a logged-in user",
                self.socket.display()
            )));
        }
        Ok(())
    }
}

pub struct Window {
    conn: Conn,
    window: u32,
    gc: u32,
    width: u32,
    height: u32,
    format: PixelFormat,
    keymap: Keymap,
    wm_protocols: u32,
    wm_delete: u32,
    floor: u32,

    scratch: Vec<u8>,
}

impl Window {

    pub fn open(display: &Display, title: &str, background: u32) -> io::Result<Self> {
        display.check_socket()?;
        let mut conn = Conn::connect(display)?;
        let setup = conn.setup.clone();
        let format = PixelFormat::of(&setup)?;

        let (sw, sh) = (u32::from(setup.root_width), u32::from(setup.root_height));
        let width = FIRST_SIZE.0.min(sw.saturating_sub(80)).max(320);
        let height = FIRST_SIZE.1.min(sh.saturating_sub(80)).max(240);

        let window = conn.new_id()?;
        let events = KEY_PRESS_MASK | BUTTON_PRESS_MASK | POINTER_MOTION_MASK | EXPOSURE_MASK | STRUCTURE_NOTIFY_MASK;
        let mut req = Request::new(CREATE_WINDOW, 0);
        req.u32(window).u32(setup.root).u16(0).u16(0).u16(side(width)?).u16(side(height)?);

        req.u16(0).u16(1).u32(0).u32(0x0000_0002 | 0x0000_0800).u32(format.encode(background)).u32(events);
        conn.send(req)?;

        let wm_protocols = conn.intern(b"WM_PROTOCOLS")?;
        let wm_delete = conn.intern(b"WM_DELETE_WINDOW")?;
        let net_wm_name = conn.intern(b"_NET_WM_NAME")?;
        let utf8_string = conn.intern(b"UTF8_STRING")?;
        conn.set_property(window, ATOM_WM_NAME, ATOM_STRING, 8, &latin1(title))?;
        conn.set_property(window, net_wm_name, utf8_string, 8, title.as_bytes())?;
        conn.set_property(window, ATOM_WM_CLASS, ATOM_STRING, 8, b"mahoraga\0Mahoraga\0")?;
        conn.set_property(window, wm_protocols, ATOM_ATOM, 32, &wm_delete.to_le_bytes())?;

        let gc = conn.new_id()?;
        let mut req = Request::new(CREATE_GC, 0);

        req.u32(gc).u32(window).u32(0x0001_0000).u32(0);
        conn.send(req)?;

        let keymap = conn.keymap()?;

        let mut req = Request::new(MAP_WINDOW, 0);
        req.u32(window);
        conn.send(req)?;

        let mut this = Window {
            conn,
            window,
            gc,
            width,
            height,
            format,
            keymap,
            wm_protocols,
            wm_delete,
            floor: scale_floor(&setup),
            scratch: Vec::new(),
        };
        this.wait_mapped()?;
        Ok(this)
    }

    pub fn size(&self) -> (u32, u32) {
        (self.width, self.height)
    }

    pub fn scale_floor(&self) -> u32 {
        self.floor
    }

    pub fn poll(&mut self, timeout: Duration) -> io::Result<Option<XEvent>> {
        let deadline = Instant::now() + timeout;
        let mut looked = false;
        loop {
            if let Some(event) = self.conn.held.pop_front() {
                return Ok(Some(event));
            }
            while let Some(message) = self.conn.next_message()? {
                if let Some(event) = self.event(&message)? {
                    return Ok(Some(event));
                }
            }
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() && looked {
                return Ok(None);
            }
            looked = true;
            self.conn.fill(left)?;
        }
    }

    pub fn forget_input(&mut self) -> io::Result<()> {
        while self.conn.fill(Duration::ZERO)? {}
        let mut events: Vec<XEvent> = self.conn.held.drain(..).collect();
        while let Some(message) = self.conn.next_message()? {
            events.extend(self.event(&message)?);
        }
        self.conn.held = events.into_iter().filter(|e| matches!(e, XEvent::Resized { .. } | XEvent::Close)).collect();
        Ok(())
    }

    pub fn present(&mut self, width: u32, height: u32, pixels: &[u32]) -> io::Result<()> {
        let w = width.min(self.width);
        let h = height.min(self.height);
        let needed = u64::from(width) * u64::from(height);
        if (pixels.len() as u64) < needed {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "a frame with fewer pixels than its size"));
        }
        if w > 0 && h > 0 {
            self.put_image(width, w, h, pixels)?;
        }
        if w < self.width {
            self.clear(w, 0, self.width - w, self.height)?;
        }
        if h < self.height {
            self.clear(0, h, w, self.height - h)?;
        }
        self.conn.flush()
    }

    fn put_image(&mut self, stride: u32, w: u32, h: u32, pixels: &[u32]) -> io::Result<()> {
        let row_bytes = self.format.row_bytes(w);
        let room = self.conn.max_request_bytes().saturating_sub(24);
        let rows_per = u32::try_from(room / row_bytes.max(1)).unwrap_or(u32::MAX);
        if rows_per == 0 {
            return Err(io::Error::new(io::ErrorKind::Unsupported, "the window is wider than one X request can draw"));
        }
        let mut top = 0;
        while top < h {
            let rows = rows_per.min(h - top);
            self.scratch.clear();
            for y in top..top + rows {
                let start = (y as usize) * (stride as usize);
                let row = pixels.get(start..start + w as usize).unwrap_or_default();
                self.format.write_row(row, row_bytes, &mut self.scratch);
            }
            let mut req = Request::new(PUT_IMAGE, 2);
            req.u32(self.window).u32(self.gc).u16(side(w)?).u16(side(rows)?).u16(0).u16(side(top)?);
            req.u8(0).u8(self.format.depth).u16(0).bytes(&self.scratch);
            self.conn.send(req)?;
            top += rows;
        }
        Ok(())
    }

    fn clear(&mut self, x: u32, y: u32, w: u32, h: u32) -> io::Result<()> {
        if w == 0 || h == 0 {
            return Ok(());
        }
        let mut req = Request::new(CLEAR_AREA, 0);
        req.u32(self.window).u16(side(x)?).u16(side(y)?).u16(side(w)?).u16(side(h)?);
        self.conn.send(req)
    }

    fn wait_mapped(&mut self) -> io::Result<()> {
        self.conn.flush()?;
        let deadline = Instant::now() + MAPPED_WITHIN;
        loop {
            while let Some(message) = self.conn.next_message()? {
                let code = byte(&message, 0) & 0x7f;

                if let Some(event) = self.event(&message)? {
                    self.conn.held.push_back(event);
                }
                if code == MAP_NOTIFY || code == EXPOSE {
                    return Ok(());
                }
            }
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Ok(());
            }
            self.conn.fill(left)?;
        }
    }

    fn event(&mut self, m: &[u8]) -> io::Result<Option<XEvent>> {
        let code = byte(m, 0) & 0x7f;
        Ok(match code {
            ERROR => {
                return Err(io::Error::other(format!(
                    "the X server refused request {} (error {})",
                    byte(m, 10),
                    byte(m, 1)
                )))
            }
            KEY_PRESS => {
                let state = u16_at(m, 28);
                self.keymap.key(byte(m, 1), state).map(|key| XEvent::Key {
                    key,
                    ctrl: state & CONTROL != 0,
                    alt: state & MOD1 != 0,
                    shift: state & SHIFT != 0,
                })
            }
            BUTTON_PRESS => {
                let (x, y) = (i32::from(i16_at(m, 24)), i32::from(i16_at(m, 26)));
                match byte(m, 1) {
                    1 => Some(XEvent::PointerDown { x, y }),
                    4 => Some(XEvent::Wheel { up: true }),
                    5 => Some(XEvent::Wheel { up: false }),
                    _ => None,
                }
            }
            MOTION_NOTIFY => Some(XEvent::PointerMove { x: i32::from(i16_at(m, 24)), y: i32::from(i16_at(m, 26)) }),

            EXPOSE if u16_at(m, 16) == 0 => Some(XEvent::Resized { width: self.width, height: self.height }),
            CONFIGURE_NOTIFY if u32_at(m, 8) == self.window => {
                let (width, height) = (u32::from(u16_at(m, 20)), u32::from(u16_at(m, 22)));
                if (width, height) == (self.width, self.height) || width == 0 || height == 0 {
                    None
                } else {
                    self.width = width;
                    self.height = height;
                    Some(XEvent::Resized { width, height })
                }
            }
            CLIENT_MESSAGE if u32_at(m, 8) == self.wm_protocols && u32_at(m, 12) == self.wm_delete => Some(XEvent::Close),

            MAPPING_NOTIFY if byte(m, 4) == 1 => {
                self.keymap = self.conn.keymap()?;
                None
            }
            _ => None,
        })
    }
}

#[derive(Debug, Clone, Copy)]
struct PixelFormat {
    depth: u8,

    bytes: usize,

    pad: u32,
    msb_first: bool,
    red: Channel,
    green: Channel,
    blue: Channel,
}

#[derive(Debug, Clone, Copy)]
struct Channel {
    shift: u32,
    bits: u32,
}

impl Channel {
    fn of(mask: u32) -> Option<Channel> {
        let shift = mask.trailing_zeros();
        let bits = (mask >> shift.min(31)).trailing_ones();

        (mask != 0 && (1..=16).contains(&bits) && mask >> shift.min(31) == (1u32 << bits) - 1)
            .then_some(Channel { shift, bits })
    }

    fn place(self, value: u32) -> u32 {
        let v = value & 0xff;
        let scaled = if self.bits <= 8 { v >> (8 - self.bits) } else { v << (self.bits - 8) };
        scaled << self.shift
    }
}

impl PixelFormat {

    fn of(setup: &Setup) -> io::Result<Self> {
        let unsupported = |why: String| io::Error::new(io::ErrorKind::Unsupported, why);
        let visual = setup
            .visual
            .ok_or_else(|| unsupported("the screen's visual is not described in the setup".into()))?;
        if visual.class != 4 && visual.class != 5 {
            return Err(unsupported(format!("visual class {} (this draws true colour)", visual.class)));
        }
        let bpp = setup
            .formats
            .iter()
            .find(|f| f.0 == setup.root_depth)
            .map(|f| (f.1, f.2))
            .ok_or_else(|| unsupported(format!("no pixmap format for depth {}", setup.root_depth)))?;
        let bytes = match bpp.0 {
            16 => 2,
            24 => 3,
            32 => 4,
            other => return Err(unsupported(format!("{other} bits per pixel (this draws 16, 24 or 32)"))),
        };
        let channel = |mask: u32, name: &str| {
            Channel::of(mask).ok_or_else(|| unsupported(format!("the {name} mask {mask:#x} is not one run of bits")))
        };
        Ok(PixelFormat {
            depth: setup.root_depth,
            bytes,
            pad: u32::from(bpp.1).max(8),
            msb_first: setup.image_byte_order == 1,
            red: channel(visual.red, "red")?,
            green: channel(visual.green, "green")?,
            blue: channel(visual.blue, "blue")?,
        })
    }

    fn encode(&self, rgb: u32) -> u32 {
        self.red.place(rgb >> 16) | self.green.place(rgb >> 8) | self.blue.place(rgb)
    }

    fn row_bytes(&self, width: u32) -> usize {
        let bits = u64::from(width) * (self.bytes as u64) * 8;
        let pad = u64::from(self.pad);
        (bits.div_ceil(pad) * pad / 8) as usize
    }

    fn write_row(&self, row: &[u32], row_bytes: usize, out: &mut Vec<u8>) {
        let start = out.len();
        for &rgb in row {
            let v = self.encode(rgb);
            let le = v.to_le_bytes();
            let be = v.to_be_bytes();
            match (self.bytes, self.msb_first) {
                (4, false) => out.extend_from_slice(&le),
                (4, true) => out.extend_from_slice(&be),
                (3, false) => out.extend_from_slice(le.get(..3).unwrap_or_default()),
                (3, true) => out.extend_from_slice(be.get(1..).unwrap_or_default()),
                (_, false) => out.extend_from_slice(le.get(..2).unwrap_or_default()),
                (_, true) => out.extend_from_slice(be.get(2..).unwrap_or_default()),
            }
        }
        out.resize(start + row_bytes, 0);
    }
}

#[derive(Debug, Default)]
struct Keymap {
    min: u8,
    per: usize,
    syms: Vec<u32>,
}

impl Keymap {

    fn key(&self, code: u8, state: u16) -> Option<XKey> {
        let at = usize::from(code.checked_sub(self.min)?) * self.per;
        let sym = |col: usize| if col < self.per { self.syms.get(at + col).copied().unwrap_or(0) } else { 0 };
        let lower = sym(0);
        let upper = match sym(1) {
            0 => upper_latin(lower),
            s => s,
        };
        let shift = state & SHIFT != 0;
        let mut chosen = if shift { upper } else { lower };

        if state & LOCK != 0 && !shift {
            chosen = upper_latin(chosen);
        }
        let key = keysym_key(chosen)?;

        Some(match key {
            XKey::Char(c) if state & CONTROL != 0 => XKey::Char(c.to_ascii_lowercase()),
            other => other,
        })
    }
}

fn upper_latin(sym: u32) -> u32 {
    if (0x61..=0x7a).contains(&sym) {
        sym - 0x20
    } else {
        sym
    }
}

fn keysym_key(sym: u32) -> Option<XKey> {
    Some(match sym {
        0xff0d | 0xff8d => XKey::Enter,
        0xff1b => XKey::Esc,
        0xff08 => XKey::Backspace,
        0xff09 => XKey::Tab,
        0xfe20 => XKey::BackTab,
        0xff52 | 0xff97 => XKey::Up,
        0xff54 | 0xff99 => XKey::Down,
        0xff51 | 0xff96 => XKey::Left,
        0xff53 | 0xff98 => XKey::Right,
        0xff55 | 0xff9a => XKey::PageUp,
        0xff56 | 0xff9b => XKey::PageDown,
        0xff50 | 0xff95 => XKey::Home,
        0xff57 | 0xff9c => XKey::End,
        0xffff | 0xff9f => XKey::Delete,
        0xffbe..=0xffc9 => XKey::F(u8::try_from(sym - 0xffbe + 1).ok()?),
        0x20..=0x7e | 0xa0..=0xff => XKey::Char(char::from_u32(sym)?),
        0x0100_00a0..=0x0110_ffff => XKey::Char(char::from_u32(sym - 0x0100_0000)?),
        _ => return None,
    })
}

#[derive(Debug, Clone, Default)]
struct Setup {
    id_base: u32,
    id_mask: u32,
    max_request_len: u16,
    image_byte_order: u8,
    min_keycode: u8,
    max_keycode: u8,

    formats: Vec<(u8, u8, u8)>,
    root: u32,
    root_width: u16,
    root_height: u16,
    root_width_mm: u16,
    root_depth: u8,
    visual: Option<Visual>,
}

#[derive(Debug, Clone, Copy)]
struct Visual {
    class: u8,
    red: u32,
    green: u32,
    blue: u32,
}

impl Setup {

    fn parse(b: &[u8]) -> io::Result<Self> {
        let mut r = Reader::new(b);
        r.skip(4)?;
        let id_base = r.u32()?;
        let id_mask = r.u32()?;
        r.skip(4)?;
        let vendor_len = usize::from(r.u16()?);
        let max_request_len = r.u16()?;
        let screens = r.u8()?;
        let nformats = r.u8()?;
        let image_byte_order = r.u8()?;
        r.skip(3)?;
        let min_keycode = r.u8()?;
        let max_keycode = r.u8()?;
        r.skip(4)?;
        r.skip(pad4(vendor_len))?;
        let mut formats = Vec::with_capacity(usize::from(nformats));
        for _ in 0..nformats {
            let depth = r.u8()?;
            let bpp = r.u8()?;
            let pad = r.u8()?;
            r.skip(5)?;
            formats.push((depth, bpp, pad));
        }
        if screens == 0 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "the display has no screen"));
        }
        let root = r.u32()?;
        r.skip(16)?;
        let root_width = r.u16()?;
        let root_height = r.u16()?;
        let root_width_mm = r.u16()?;
        r.skip(6)?;
        let root_visual = r.u32()?;
        r.skip(2)?;
        let root_depth = r.u8()?;
        let ndepths = r.u8()?;
        let mut visual = None;
        for _ in 0..ndepths {
            r.u8()?;
            r.skip(1)?;
            let nvisuals = r.u16()?;
            r.skip(4)?;
            for _ in 0..nvisuals {
                let id = r.u32()?;
                let class = r.u8()?;
                r.skip(3)?;
                let (red, green, blue) = (r.u32()?, r.u32()?, r.u32()?);
                r.skip(4)?;
                if id == root_visual {
                    visual = Some(Visual { class, red, green, blue });
                }
            }
        }
        Ok(Setup {
            id_base,
            id_mask,
            max_request_len,
            image_byte_order,
            min_keycode,
            max_keycode,
            formats,
            root,
            root_width,
            root_height,
            root_width_mm,
            root_depth,
            visual,
        })
    }
}

fn scale_floor(setup: &Setup) -> u32 {
    if setup.root_width_mm == 0 {
        return 1;
    }
    let dpi = u32::from(setup.root_width) * 254 / (u32::from(setup.root_width_mm) * 10);
    if dpi >= 168 {
        2
    } else {
        1
    }
}

struct Conn {
    stream: UnixStream,
    setup: Setup,
    next_id: u32,

    seq: u16,
    out: Vec<u8>,
    inbuf: Vec<u8>,

    held: VecDeque<XEvent>,
}

impl Conn {

    fn connect(display: &Display) -> io::Result<Self> {
        let mut refusals = Vec::new();
        let mut cookies = cookies_for(display);
        cookies.truncate(MAX_ATTEMPTS - 1);
        cookies.push(Vec::new());
        for cookie in &cookies {
            match Self::try_connect(display, cookie)? {
                Ok(conn) => return Ok(conn),
                Err(reason) => refusals.push(reason),
            }
        }
        refusals.dedup();
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "the X server on {} refused this process ({} cookie(s) tried): {}. As root, keep the desktop's \
                 DISPLAY and XAUTHORITY (sudo does), or run `xhost +si:localuser:root` on the desktop",
                display.name(),
                cookies.len() - 1,
                refusals.join("; ")
            ),
        ))
    }

    fn try_connect(display: &Display, cookie: &[u8]) -> io::Result<Result<Self, String>> {
        let mut stream = UnixStream::connect(&display.socket)
            .map_err(|e| io::Error::new(e.kind(), format!("{}: {e}", display.socket.display())))?;
        stream.set_read_timeout(Some(ANSWER_WITHIN))?;
        stream.set_write_timeout(Some(ANSWER_WITHIN))?;

        let name: &[u8] = if cookie.is_empty() { &[] } else { COOKIE_NAME };
        let mut hello = Vec::with_capacity(12 + pad4(name.len()) + pad4(cookie.len()));
        hello.extend_from_slice(&[b'l', 0]);
        hello.extend_from_slice(&11u16.to_le_bytes());
        hello.extend_from_slice(&0u16.to_le_bytes());
        hello.extend_from_slice(&len16(name.len())?.to_le_bytes());
        hello.extend_from_slice(&len16(cookie.len())?.to_le_bytes());
        hello.extend_from_slice(&[0, 0]);
        put_padded(&mut hello, name);
        put_padded(&mut hello, cookie);
        stream.write_all(&hello)?;

        let mut head = [0u8; 8];
        stream.read_exact(&mut head)?;
        let extra = usize::from(u16_at(&head, 6)) * 4;
        if extra > MAX_SETUP {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "the X server's setup is implausibly large"));
        }
        let mut body = vec![0u8; extra];
        stream.read_exact(&mut body)?;
        match head.first().copied().unwrap_or_default() {
            1 => {}
            status => {
                let len = if status == 0 { usize::from(byte(&head, 1)) } else { body.len() };
                let reason = String::from_utf8_lossy(body.get(..len).unwrap_or_default()).trim().to_string();
                return Ok(Err(if reason.is_empty() { "no reason given".into() } else { reason }));
            }
        }
        let setup = Setup::parse(&body)?;
        if setup.id_mask == 0 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "the X server gave no resource ids"));
        }
        Ok(Ok(Conn {
            stream,
            next_id: 0,
            seq: 0,
            setup,
            out: Vec::new(),
            inbuf: Vec::new(),
            held: VecDeque::new(),
        }))
    }

    fn new_id(&mut self) -> io::Result<u32> {
        let mask = self.setup.id_mask;
        let step = 1u32 << mask.trailing_zeros().min(31);
        let id = self.next_id;
        if id & !mask != 0 {
            return Err(io::Error::other("out of X resource ids"));
        }
        self.next_id = id.wrapping_add(step);
        Ok(self.setup.id_base | id)
    }

    fn max_request_bytes(&self) -> usize {
        usize::from(self.setup.max_request_len) * 4
    }

    fn send(&mut self, req: Request) -> io::Result<()> {
        let bytes = req.finish()?;
        if bytes.len() > self.max_request_bytes() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "an X request larger than the server takes"));
        }
        self.out.extend_from_slice(&bytes);
        self.seq = self.seq.wrapping_add(1);
        if self.out.len() >= 1 << 18 {
            self.flush()?;
        }
        Ok(())
    }

    fn flush(&mut self) -> io::Result<()> {
        if self.out.is_empty() {
            return Ok(());
        }

        self.stream.set_nonblocking(false)?;
        self.stream.set_write_timeout(Some(WRITE_WITHIN))?;
        let out = std::mem::take(&mut self.out);
        self.stream.write_all(&out)
    }

    fn fill(&mut self, timeout: Duration) -> io::Result<bool> {
        self.flush()?;
        if timeout.is_zero() {
            self.stream.set_nonblocking(true)?;
        } else {
            self.stream.set_nonblocking(false)?;
            self.stream.set_read_timeout(Some(timeout))?;
        }
        let mut buf = [0u8; 8192];
        let got = match self.stream.read(&mut buf) {
            Ok(0) => return Err(io::Error::new(io::ErrorKind::BrokenPipe, "the X server closed the connection")),
            Ok(n) => n,
            Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) => 0,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => 0,
            Err(e) => return Err(e),
        };
        self.inbuf.extend_from_slice(buf.get(..got).unwrap_or_default());
        Ok(got > 0)
    }

    fn next_message(&mut self) -> io::Result<Option<Vec<u8>>> {
        if self.inbuf.len() < 32 {
            return Ok(None);
        }
        let code = byte(&self.inbuf, 0) & 0x7f;

        let extra = if code == REPLY || code == GENERIC_EVENT { u32_at(&self.inbuf, 4) as usize * 4 } else { 0 };
        if extra > MAX_REPLY {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "an X message implausibly large"));
        }
        let len = 32 + extra;
        if self.inbuf.len() < len {
            return Ok(None);
        }
        let rest = self.inbuf.split_off(len);
        Ok(Some(std::mem::replace(&mut self.inbuf, rest)))
    }

    fn round_trip(&mut self, req: Request) -> io::Result<Vec<u8>> {
        self.send(req)?;
        let want = self.seq;
        let deadline = Instant::now() + ANSWER_WITHIN;
        let mut pending = Vec::new();
        let reply = loop {
            match self.next_message()? {
                Some(m) if byte(&m, 0) == REPLY && u16_at(&m, 2) == want => break m,
                Some(m) if byte(&m, 0) == ERROR && u16_at(&m, 2) == want => {
                    return Err(io::Error::other(format!("the X server refused request {} (error {})", byte(&m, 10), byte(&m, 1))))
                }
                Some(m) => pending.push(m),
                None => {
                    let left = deadline.saturating_duration_since(Instant::now());
                    if left.is_zero() {
                        return Err(io::Error::new(io::ErrorKind::TimedOut, "the X server did not answer"));
                    }
                    self.fill(left)?;
                }
            }
        };

        let mut back: Vec<u8> = pending.concat();
        back.extend_from_slice(&self.inbuf);
        self.inbuf = back;
        Ok(reply)
    }

    fn intern(&mut self, name: &[u8]) -> io::Result<u32> {
        let mut req = Request::new(INTERN_ATOM, 0);
        req.u16(len16(name.len())?).u16(0).bytes(name);
        let reply = self.round_trip(req)?;
        match u32_at(&reply, 8) {
            0 => Err(io::Error::other(format!("the X server has no atom {}", String::from_utf8_lossy(name)))),
            atom => Ok(atom),
        }
    }

    fn set_property(&mut self, window: u32, property: u32, kind: u32, format: u8, data: &[u8]) -> io::Result<()> {
        let units = data.len() / usize::from(format / 8).max(1);
        let mut req = Request::new(CHANGE_PROPERTY, 0);
        req.u32(window).u32(property).u32(kind).u8(format).u8(0).u16(0);
        req.u32(u32::try_from(units).map_err(|_| io::Error::other("a property too long"))?).bytes(data);
        self.send(req)
    }

    fn keymap(&mut self) -> io::Result<Keymap> {
        let (min, max) = (self.setup.min_keycode, self.setup.max_keycode);
        let count = max.saturating_sub(min).saturating_add(1);
        let mut req = Request::new(GET_KEYBOARD_MAPPING, 0);
        req.u8(min).u8(count).u16(0);
        let reply = self.round_trip(req)?;
        let per = usize::from(byte(&reply, 1));
        let syms = reply.get(32..).unwrap_or_default().as_chunks::<4>().0.iter().map(|c| u32::from_le_bytes(*c)).collect();
        Ok(Keymap { min, per, syms })
    }
}

struct Request {
    bytes: Vec<u8>,
}

impl Request {
    fn new(opcode: u8, data: u8) -> Self {
        Request { bytes: vec![opcode, data, 0, 0] }
    }
    fn u8(&mut self, v: u8) -> &mut Self {
        self.bytes.push(v);
        self
    }
    fn u16(&mut self, v: u16) -> &mut Self {
        self.bytes.extend_from_slice(&v.to_le_bytes());
        self
    }
    fn u32(&mut self, v: u32) -> &mut Self {
        self.bytes.extend_from_slice(&v.to_le_bytes());
        self
    }
    fn bytes(&mut self, v: &[u8]) -> &mut Self {
        put_padded(&mut self.bytes, v);
        self
    }

    fn finish(mut self) -> io::Result<Vec<u8>> {
        let padded = pad4(self.bytes.len());
        self.bytes.resize(padded, 0);
        let units = u16::try_from(padded / 4).map_err(|_| io::Error::other("an X request too large"))?;
        if let Some(len) = self.bytes.get_mut(2..4) {
            len.copy_from_slice(&units.to_le_bytes());
        }
        Ok(self.bytes)
    }
}

struct Reader<'a> {
    b: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn new(b: &'a [u8]) -> Self {
        Reader { b, at: 0 }
    }
    fn take(&mut self, n: usize) -> io::Result<&'a [u8]> {
        let end = self.at.checked_add(n).filter(|&e| e <= self.b.len());
        let s = end.and_then(|e| self.b.get(self.at..e));
        let s = s.ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "the X server's setup is cut short"))?;
        self.at += n;
        Ok(s)
    }
    fn skip(&mut self, n: usize) -> io::Result<()> {
        self.take(n).map(|_| ())
    }
    fn u8(&mut self) -> io::Result<u8> {
        Ok(byte(self.take(1)?, 0))
    }
    fn u16(&mut self) -> io::Result<u16> {
        Ok(u16_at(self.take(2)?, 0))
    }
    fn u32(&mut self) -> io::Result<u32> {
        Ok(u32_at(self.take(4)?, 0))
    }
}

fn cookies_for(display: &Display) -> Vec<Vec<u8>> {
    let mut files: Vec<PathBuf> = Vec::new();
    if let Some(p) = std::env::var_os("XAUTHORITY") {
        files.push(PathBuf::from(p));
    }
    if let Some(home) = std::env::var_os("HOME") {
        files.push(Path::new(&home).join(".Xauthority"));
    }

    if let Some(home) = std::env::var("SUDO_UID").ok().and_then(|uid| home_of(&uid)) {
        files.push(home.join(".Xauthority"));
    }

    if let Ok(users) = fs::read_dir("/run/user") {
        for user in users.flatten() {
            let dir = user.path();
            files.push(dir.join("gdm/Xauthority"));
            if let Ok(entries) = fs::read_dir(&dir) {
                for e in entries.flatten() {
                    let name = e.file_name();
                    let name = name.to_string_lossy();
                    if name.starts_with(".mutter-Xwaylandauth.") || name.starts_with("xauth_") || name == ".Xauthority" {
                        files.push(e.path());
                    }
                }
            }
            if let Some(home) = home_of(&user.file_name().to_string_lossy()) {
                files.push(home.join(".Xauthority"));
            }
        }
    }
    files.push(Path::new("/run/lightdm/root").join(display.name()));
    if let Ok(entries) = fs::read_dir("/run/sddm") {
        files.extend(entries.flatten().map(|e| e.path()));
    }

    let host = fs::read_to_string("/proc/sys/kernel/hostname").unwrap_or_default();
    let number = display.number.to_string();
    let mut cookies: Vec<Vec<u8>> = Vec::new();
    for file in files {
        for cookie in read_authority(&file, host.trim().as_bytes(), number.as_bytes()) {
            if !cookies.contains(&cookie) {
                cookies.push(cookie);
            }
        }
    }
    cookies
}

fn home_of(uid: &str) -> Option<PathBuf> {
    let passwd = fs::read_to_string("/etc/passwd").ok()?;
    passwd.lines().find_map(|line| {
        let f: Vec<&str> = line.split(':').collect();
        (f.get(2) == Some(&uid)).then(|| f.get(5).map(PathBuf::from)).flatten()
    })
}

fn read_authority(path: &Path, host: &[u8], number: &[u8]) -> Vec<Vec<u8>> {
    let Ok(file) = fs::File::open(path) else { return Vec::new() };
    let mut data = Vec::new();
    if file.take(MAX_AUTH_FILE).read_to_end(&mut data).is_err() {
        return Vec::new();
    }
    let (mut ours, mut wild) = (Vec::new(), Vec::new());
    let mut r = Reader::new(&data);

    while let Ok(f) = r.take(2) {
        let family = u16::from_be_bytes([byte(f, 0), byte(f, 1)]);
        let (Some(address), Some(num), Some(name), Some(cookie)) =
            (auth_field(&mut r), auth_field(&mut r), auth_field(&mut r), auth_field(&mut r))
        else {
            break;
        };
        if name != COOKIE_NAME || cookie.is_empty() || !(num.is_empty() || num == number) {
            continue;
        }
        match family {

            256 if address == host => ours.push(cookie),
            256 => wild.push(cookie),

            65535 => wild.push(cookie),
            _ => {}
        }
    }
    ours.extend(wild);
    ours
}

fn auth_field(r: &mut Reader<'_>) -> Option<Vec<u8>> {
    let len = r.take(2).ok().map(|b| u16::from_be_bytes([byte(b, 0), byte(b, 1)]))?;
    r.take(usize::from(len)).ok().map(<[u8]>::to_vec)
}

fn pad4(n: usize) -> usize {
    n.div_ceil(4) * 4
}

fn put_padded(out: &mut Vec<u8>, v: &[u8]) {
    out.extend_from_slice(v);
    out.resize(out.len() + pad4(v.len()) - v.len(), 0);
}

fn len16(n: usize) -> io::Result<u16> {
    u16::try_from(n).map_err(|_| io::Error::other("a field too long for X"))
}

fn side(n: u32) -> io::Result<u16> {
    u16::try_from(n).map_err(|_| io::Error::other("a size too large for X"))
}

fn latin1(s: &str) -> Vec<u8> {
    s.chars().map(|c| u8::try_from(u32::from(c)).unwrap_or(b'?')).collect()
}

fn byte(b: &[u8], at: usize) -> u8 {
    b.get(at).copied().unwrap_or_default()
}

fn u16_at(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([byte(b, at), byte(b, at + 1)])
}

fn i16_at(b: &[u8], at: usize) -> i16 {
    i16::from_le_bytes([byte(b, at), byte(b, at + 1)])
}

fn u32_at(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([byte(b, at), byte(b, at + 1), byte(b, at + 2), byte(b, at + 3)])
}
