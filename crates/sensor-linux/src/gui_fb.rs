use std::fs::{self, File};
use std::io::{self, Read as _};
use std::mem::MaybeUninit;
use std::os::fd::{AsFd as _, AsRawFd as _, RawFd};
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _, OpenOptionsExt as _};
use std::path::Path;
use std::ptr::{self, NonNull};
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, AtomicU8, Ordering};
use std::time::Duration;

const IOC_READ: libc::c_ulong = 2;

const fn ioc_read(ty: u8, nr: u16, size: usize) -> libc::c_ulong {
    (IOC_READ << 30) | ((size as libc::c_ulong) << 16) | ((ty as libc::c_ulong) << 8) | nr as libc::c_ulong
}

const FBIOGET_VSCREENINFO: libc::c_ulong = 0x4600;

const FBIOGET_FSCREENINFO: libc::c_ulong = 0x4602;

const FB_TYPE_PACKED_PIXELS: u32 = 0;

const FB_VISUAL_TRUECOLOR: u32 = 2;

const KDSETMODE: libc::c_ulong = 0x4B3A;

const KDGETMODE: libc::c_ulong = 0x4B3B;

const KD_TEXT: libc::c_int = 0x00;

const KD_GRAPHICS: libc::c_int = 0x01;

const VT_GETSTATE: libc::c_ulong = 0x5603;

const VT_GETMODE: libc::c_ulong = 0x5601;

const VT_SETMODE: libc::c_ulong = 0x5602;

const VT_AUTO: libc::c_char = 0x00;

const VT_PROCESS: libc::c_char = 0x01;

const TTY_MAJOR: u32 = 4;

const MAX_NR_CONSOLES: u32 = 63;

const FB_MAJOR: u32 = 29;

const INPUT_MAJOR: u32 = 13;

const EV_SYN: u16 = 0x00;
const EV_KEY: u16 = 0x01;
const EV_REL: u16 = 0x02;
const EV_ABS: u16 = 0x03;
const SYN_REPORT: u16 = 0;
const SYN_DROPPED: u16 = 3;
const BTN_LEFT: u16 = 0x110;
const KEY_MAX: u16 = 0x2ff;
const REL_X: u16 = 0x00;
const REL_Y: u16 = 0x01;
const REL_WHEEL: u16 = 0x08;
const REL_MAX: u16 = 0x0f;
const ABS_X: u16 = 0x00;
const ABS_Y: u16 = 0x01;
const ABS_MAX: u16 = 0x3f;

const fn bitmap_len(max: u16) -> usize {
    max as usize / 8 + 1
}
const KEY_BITS: usize = bitmap_len(KEY_MAX);
const REL_BITS: usize = bitmap_len(REL_MAX);
const ABS_BITS: usize = bitmap_len(ABS_MAX);

const fn eviocgbit(ev: u16, len: usize) -> libc::c_ulong {
    ioc_read(b'E', 0x20 + ev, len)
}

const fn eviocgabs(abs: u16) -> libc::c_ulong {
    ioc_read(b'E', 0x40 + abs, core::mem::size_of::<libc::input_absinfo>())
}

const EVENT_SIZE: usize = 24;

#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct FbBitfield {
    offset: u32,
    length: u32,
    msb_right: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
struct FbVarScreeninfo {
    xres: u32,
    yres: u32,
    xres_virtual: u32,
    yres_virtual: u32,
    xoffset: u32,
    yoffset: u32,
    bits_per_pixel: u32,
    grayscale: u32,
    red: FbBitfield,
    green: FbBitfield,
    blue: FbBitfield,
    transp: FbBitfield,
    nonstd: u32,
    activate: u32,
    height: u32,
    width: u32,
    accel_flags: u32,
    pixclock: u32,
    left_margin: u32,
    right_margin: u32,
    upper_margin: u32,
    lower_margin: u32,
    hsync_len: u32,
    vsync_len: u32,
    sync: u32,
    vmode: u32,
    rotate: u32,
    colorspace: u32,
    reserved: [u32; 4],
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
struct FbFixScreeninfo {
    id: [u8; 16],
    smem_start: libc::c_ulong,
    smem_len: u32,
    type_: u32,
    type_aux: u32,
    visual: u32,
    xpanstep: u16,
    ypanstep: u16,
    ywrapstep: u16,
    line_length: u32,
    mmio_start: libc::c_ulong,
    mmio_len: u32,
    accel: u32,
    capabilities: u16,
    reserved: [u16; 2],
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
struct VtStat {
    v_active: u16,
    v_signal: u16,
    v_state: u16,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct VtMode {
    mode: libc::c_char,
    waitv: libc::c_char,
    relsig: libc::c_short,
    acqsig: libc::c_short,
    frsig: libc::c_short,
}

const _: () = {
    assert!(core::mem::size_of::<FbBitfield>() == 12);
    assert!(core::mem::size_of::<FbVarScreeninfo>() == 160);
    assert!(core::mem::offset_of!(FbVarScreeninfo, xoffset) == 16);
    assert!(core::mem::offset_of!(FbVarScreeninfo, bits_per_pixel) == 24);
    assert!(core::mem::offset_of!(FbVarScreeninfo, red) == 32);
    assert!(core::mem::offset_of!(FbVarScreeninfo, transp) == 68);
    assert!(core::mem::offset_of!(FbVarScreeninfo, nonstd) == 80);
    assert!(core::mem::size_of::<FbFixScreeninfo>() == 80);
    assert!(core::mem::offset_of!(FbFixScreeninfo, smem_len) == 24);
    assert!(core::mem::offset_of!(FbFixScreeninfo, type_) == 28);
    assert!(core::mem::offset_of!(FbFixScreeninfo, visual) == 36);
    assert!(core::mem::offset_of!(FbFixScreeninfo, line_length) == 48);
    assert!(core::mem::offset_of!(FbFixScreeninfo, mmio_start) == 56);
    assert!(core::mem::size_of::<VtStat>() == 6);
    assert!(core::mem::size_of::<VtMode>() == 8);
    assert!(core::mem::offset_of!(VtMode, relsig) == 2);
    assert!(core::mem::offset_of!(VtMode, frsig) == 6);

    assert!(core::mem::size_of::<libc::input_event>() == EVENT_SIZE);
    assert!(core::mem::offset_of!(libc::input_event, type_) == 16);
    assert!(core::mem::offset_of!(libc::input_event, code) == 18);
    assert!(core::mem::offset_of!(libc::input_event, value) == 20);
    assert!(core::mem::size_of::<libc::input_absinfo>() == 24);
};

fn context(e: io::Error, what: &str) -> io::Error {
    io::Error::new(e.kind(), format!("{what}: {e}"))
}

fn open_device(path: &Path, major: u32, write: bool, flags: libc::c_int) -> io::Result<File> {
    let at = crate::saferead::open_o_path(path)?;
    let meta = at.metadata()?;
    if !meta.file_type().is_char_device() || libc::major(meta.rdev()) != major {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("not a character device {major}:N, so it was not opened"),
        ));
    }
    fs::OpenOptions::new()
        .read(true)
        .write(write)
        .custom_flags(flags | libc::O_CLOEXEC | libc::O_NOCTTY)
        .open(format!("/proc/self/fd/{}", at.as_raw_fd()))
        .map_err(|e| {

            if e.kind() == io::ErrorKind::NotFound {
                io::Error::other(format!("not reopened through /proc/self/fd ({e})"))
            } else {
                e
            }
        })
}

const FB_PATH: &str = "/dev/fb0";

const MAX_SIDE: u32 = 16_384;

const BACKGROUND: u32 = 0x0000_0000;

struct PixelFormat {

    bytes: usize,

    red: [u32; 256],
    green: [u32; 256],
    blue: [u32; 256],

    opaque: u32,
}

impl PixelFormat {

    fn new(
        bits_per_pixel: u32,
        red: FbBitfield,
        green: FbBitfield,
        blue: FbBitfield,
        transp: FbBitfield,
    ) -> Result<Self, String> {
        let bytes = match bits_per_pixel {
            16 => 2,
            24 => 3,
            32 => 4,
            other => return Err(format!("{other} bits per pixel (this draws 16, 24 or 32)")),
        };
        Ok(PixelFormat {
            bytes,
            red: channel(red, bits_per_pixel, "red")?,
            green: channel(green, bits_per_pixel, "green")?,
            blue: channel(blue, bits_per_pixel, "blue")?,
            opaque: opaque(transp, bits_per_pixel),
        })
    }

    fn value(&self, rgb: u32) -> u32 {
        let [_, r, g, b] = rgb.to_be_bytes();
        let at = |table: &[u32; 256], v: u8| table.get(usize::from(v)).copied().unwrap_or(0);
        at(&self.red, r) | at(&self.green, g) | at(&self.blue, b) | self.opaque
    }

    fn put(&self, value: u32, out: &mut [u8]) {
        for (slot, byte) in out.iter_mut().zip(value.to_le_bytes()) {
            *slot = byte;
        }
    }
}

fn channel(field: FbBitfield, bits_per_pixel: u32, name: &str) -> Result<[u32; 256], String> {
    let FbBitfield { offset, length, msb_right } = field;
    if msb_right != 0 {
        return Err(format!("the {name} field is stored most significant bit on the right"));
    }
    if !(1..=16).contains(&length) {
        return Err(format!("the {name} field is {length} bit(s) wide (this draws 1 to 16)"));
    }
    if offset.checked_add(length).is_none_or(|end| end > bits_per_pixel) {
        return Err(format!(
            "the {name} field ({length} bit(s) at bit {offset}) does not fit in a {bits_per_pixel}-bit pixel"
        ));
    }
    let max = (1u32 << length) - 1;
    let mut table = [0u32; 256];
    for (v, slot) in (0u32..).zip(table.iter_mut()) {

        let scaled = (v * max + 127) / 255;
        *slot = scaled.checked_shl(offset).unwrap_or(0);
    }
    Ok(table)
}

fn opaque(field: FbBitfield, bits_per_pixel: u32) -> u32 {
    let FbBitfield { offset, length, .. } = field;
    if !(1..=16).contains(&length) || offset.checked_add(length).is_none_or(|end| end > bits_per_pixel) {
        return 0;
    }
    ((1u32 << length) - 1).checked_shl(offset).unwrap_or(0)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Geometry {
    xres: u32,
    yres: u32,

    stride: usize,

    base: usize,

    row_bytes: usize,

    map_len: usize,
}

impl Geometry {

    fn new(var: &FbVarScreeninfo, fix: &FbFixScreeninfo, bytes_per_pixel: usize) -> Result<Self, String> {
        let (xres, yres) = (var.xres, var.yres);
        if !(1..=MAX_SIDE).contains(&xres) || !(1..=MAX_SIDE).contains(&yres) {
            return Err(format!("a {xres}x{yres} screen (this drives 1 to {MAX_SIDE} pixels a side)"));
        }
        let too_big = || {
            format!(
                "a {xres}x{yres} screen at offset {}x{} and {} bytes a row does not fit in the {} bytes \
                 the driver maps",
                var.xoffset, var.yoffset, fix.line_length, fix.smem_len
            )
        };
        let n = |v: u32| usize::try_from(v).ok();
        let row_bytes = n(xres).and_then(|x| x.checked_mul(bytes_per_pixel)).ok_or_else(too_big)?;
        let stride = n(fix.line_length).ok_or_else(too_big)?;
        if stride < row_bytes {
            return Err(format!("rows of {stride} bytes cannot hold {xres} pixels of {bytes_per_pixel} bytes"));
        }
        let skip_rows = n(var.yoffset).and_then(|y| y.checked_mul(stride));
        let skip_pixels = n(var.xoffset).and_then(|x| x.checked_mul(bytes_per_pixel));
        let base = skip_rows.zip(skip_pixels).and_then(|(r, p)| r.checked_add(p)).ok_or_else(too_big)?;
        let map_len = n(yres - 1)
            .and_then(|last| last.checked_mul(stride))
            .and_then(|o| o.checked_add(base))
            .and_then(|o| o.checked_add(row_bytes))
            .ok_or_else(too_big)?;
        if n(fix.smem_len).is_none_or(|have| map_len > have) {
            return Err(too_big());
        }
        Ok(Geometry { xres, yres, stride, base, row_bytes, map_len })
    }

    fn row_offset(&self, y: u32) -> Option<usize> {
        if y >= self.yres {
            return None;
        }
        usize::try_from(y).ok()?.checked_mul(self.stride)?.checked_add(self.base)
    }
}

fn refit(var: &FbVarScreeninfo, fix: &FbFixScreeninfo, mapped: usize) -> Result<(PixelFormat, Geometry), String> {
    let (fmt, geo) = describe(var, fix)?;
    if geo.map_len > mapped {
        return Err(format!(
            "the screen changed under the GUI: it now needs {} bytes of the framebuffer and {mapped} are mapped",
            geo.map_len
        ));
    }
    Ok((fmt, geo))
}

fn describe(var: &FbVarScreeninfo, fix: &FbFixScreeninfo) -> Result<(PixelFormat, Geometry), String> {
    if fix.type_ != FB_TYPE_PACKED_PIXELS {
        return Err(format!("framebuffer type {} (this draws packed pixels, type 0)", fix.type_));
    }
    if fix.visual != FB_VISUAL_TRUECOLOR {
        return Err(format!("framebuffer visual {} (this draws true colour, visual 2)", fix.visual));
    }
    if var.grayscale != 0 || var.nonstd != 0 {
        return Err("a greyscale, FOURCC or non-standard pixel format".into());
    }
    let fmt = PixelFormat::new(var.bits_per_pixel, var.red, var.green, var.blue, var.transp)?;
    let geo = Geometry::new(var, fix, fmt.bytes)?;
    Ok((fmt, geo))
}

#[derive(Clone, Copy)]
struct FrameRef<'a> {
    width: usize,
    height: usize,
    pixels: &'a [u32],
}

impl<'a> FrameRef<'a> {
    fn new(width: u32, height: u32, pixels: &'a [u32]) -> io::Result<Self> {
        let w = usize::try_from(width).ok();
        let h = usize::try_from(height).ok();
        match (w, h) {
            (Some(w), Some(h)) if w.checked_mul(h).is_some_and(|need| pixels.len() >= need) => {
                Ok(FrameRef { width: w, height: h, pixels })
            }
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("a {width}x{height} frame carrying {} pixel(s)", pixels.len()),
            )),
        }
    }

    fn row(&self, y: usize) -> &'a [u32] {
        if y >= self.height {
            return &[];
        }
        y.checked_mul(self.width)
            .and_then(|start| self.pixels.get(start..start.checked_add(self.width)?))
            .unwrap_or(&[])
    }
}

fn pack_row(fmt: &PixelFormat, src: &[u32], background: u32, out: &mut [u8]) {
    let mut from = src.iter();
    for slot in out.chunks_exact_mut(fmt.bytes.max(1)) {
        let value = from.next().map_or(background, |&rgb| fmt.value(rgb));
        fmt.put(value, slot);
    }
}

fn blit_into(
    geo: &Geometry,
    fmt: &PixelFormat,
    background: u32,
    frame: FrameRef<'_>,
    row: &mut Vec<u8>,
    mut store: impl FnMut(usize, &[u8]) -> bool,
) -> io::Result<()> {
    row.resize(geo.row_bytes, 0);
    for y in 0..geo.yres {
        let src = usize::try_from(y).map_or(&[][..], |y| frame.row(y));
        pack_row(fmt, src, background, row);
        if !geo.row_offset(y).is_some_and(|offset| store(offset, row)) {
            return Err(io::Error::other(format!(
                "row {y} of the screen falls outside the {}-byte mapping; it and the rows after it were not drawn",
                geo.map_len
            )));
        }
    }
    Ok(())
}

struct Mapping {
    ptr: NonNull<u8>,
    len: usize,
}

impl Mapping {

    fn new(fd: RawFd, len: usize, flags: libc::c_int) -> io::Result<Self> {

        let p = unsafe { libc::mmap(ptr::null_mut(), len, libc::PROT_READ | libc::PROT_WRITE, flags, fd, 0) };
        if p == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }

        let ptr = NonNull::new(p.cast::<u8>()).ok_or_else(|| io::Error::other("mmap answered address 0"))?;
        Ok(Mapping { ptr, len })
    }

    fn store(&mut self, offset: usize, bytes: &[u8]) -> bool {
        if offset.checked_add(bytes.len()).is_none_or(|end| end > self.len) {
            return false;
        }

        unsafe { ptr::copy_nonoverlapping(bytes.as_ptr(), self.ptr.as_ptr().add(offset), bytes.len()) };
        true
    }
}

impl Drop for Mapping {
    fn drop(&mut self) {

        unsafe { libc::munmap(self.ptr.as_ptr().cast(), self.len) };
    }
}

fn screen_info(fd: RawFd) -> io::Result<(FbVarScreeninfo, FbFixScreeninfo)> {
    let mut var = FbVarScreeninfo::default();

    if unsafe { libc::ioctl(fd, FBIOGET_VSCREENINFO as _, &raw mut var) } != 0 {
        return Err(context(io::Error::last_os_error(), &format!("{FB_PATH}: FBIOGET_VSCREENINFO")));
    }
    let mut fix = FbFixScreeninfo::default();

    if unsafe { libc::ioctl(fd, FBIOGET_FSCREENINFO as _, &raw mut fix) } != 0 {
        return Err(context(io::Error::last_os_error(), &format!("{FB_PATH}: FBIOGET_FSCREENINFO")));
    }
    Ok((var, fix))
}

pub struct Framebuffer {
    map: Mapping,

    device: File,
    geo: Geometry,
    fmt: Box<PixelFormat>,

    background: u32,

    row: Vec<u8>,
}

impl Framebuffer {

    pub fn open() -> io::Result<Self> {

        let device = open_device(Path::new(FB_PATH), FB_MAJOR, true, 0).map_err(|e| {
            let hint = match e.kind() {
                io::ErrorKind::NotFound => "this console has no framebuffer to draw on; use the terminal console",
                io::ErrorKind::PermissionDenied => "drawing on the console needs root",
                _ => "cannot open the framebuffer",
            };
            io::Error::new(e.kind(), format!("{FB_PATH}: {e} ({hint})"))
        })?;
        let fd = device.as_raw_fd();
        let (var, fix) = screen_info(fd)?;
        let (fmt, geo) = describe(&var, &fix)
            .map_err(|why| io::Error::new(io::ErrorKind::Unsupported, format!("{FB_PATH}: {why}")))?;

        let len = usize::try_from(fix.smem_len).unwrap_or(geo.map_len).max(geo.map_len);
        let map = Mapping::new(fd, len, libc::MAP_SHARED)
            .map_err(|e| context(e, &format!("{FB_PATH}: mapping {len} bytes")))?;
        let background = fmt.value(BACKGROUND);
        Ok(Framebuffer { map, device, geo, fmt: Box::new(fmt), background, row: vec![0; geo.row_bytes] })
    }

    pub fn refresh(&mut self) -> io::Result<()> {
        let (var, fix) = screen_info(self.device.as_raw_fd())?;
        let (fmt, geo) = refit(&var, &fix, self.map.len)
            .map_err(|why| io::Error::new(io::ErrorKind::Unsupported, format!("{FB_PATH}: {why}")))?;
        self.background = fmt.value(BACKGROUND);
        *self.fmt = fmt;
        self.geo = geo;
        Ok(())
    }

    pub fn size(&self) -> (u32, u32) {
        (self.geo.xres, self.geo.yres)
    }

    pub fn blit(&mut self, width: u32, height: u32, pixels: &[u32]) -> io::Result<()> {
        let frame = FrameRef::new(width, height, pixels)?;
        let map = &mut self.map;
        let store = |offset: usize, bytes: &[u8]| map.store(offset, bytes);
        blit_into(&self.geo, &self.fmt, self.background, frame, &mut self.row, store)
    }
}

static VT_FD: AtomicI32 = AtomicI32::new(-1);

static VT_MODE: AtomicI32 = AtomicI32::new(KD_TEXT);

static VT_NUM: AtomicI32 = AtomicI32::new(0);

static TTY_FD: AtomicI32 = AtomicI32::new(-1);

static TTY_IFLAG: AtomicU32 = AtomicU32::new(0);
static TTY_OFLAG: AtomicU32 = AtomicU32::new(0);
static TTY_LFLAG: AtomicU32 = AtomicU32::new(0);
static TTY_VMIN: AtomicU8 = AtomicU8::new(1);
static TTY_VTIME: AtomicU8 = AtomicU8::new(0);

static OWNER_PID: AtomicI32 = AtomicI32::new(0);

static VT_OWNED: AtomicBool = AtomicBool::new(false);
static TTY_OWNED: AtomicBool = AtomicBool::new(false);

static HOOK_INSTALLED: AtomicBool = AtomicBool::new(false);

const FATAL_SIGNALS: [libc::c_int; 22] = [
    libc::SIGTERM,
    libc::SIGINT,
    libc::SIGHUP,
    libc::SIGQUIT,
    libc::SIGABRT,
    libc::SIGPIPE,
    libc::SIGALRM,
    libc::SIGUSR1,
    libc::SIGUSR2,
    libc::SIGVTALRM,
    libc::SIGPROF,
    libc::SIGIO,
    libc::SIGPWR,
    libc::SIGSTKFLT,
    libc::SIGXCPU,
    libc::SIGXFSZ,
    libc::SIGSYS,
    libc::SIGTRAP,
    libc::SIGILL,
    libc::SIGFPE,
    libc::SIGSEGV,
    libc::SIGBUS,
];

const CLEAR_SCREEN: &[u8] = b"\x1b[H\x1b[2J";

const NOT_A_CONSOLE: &str = "standard input is not a Linux virtual console: run it from the host's console \
                             (Compsole, noVNC, a local screen); over SSH use the terminal console. On the console, \
                             a sudo that allocates a pseudo-terminal (use_pty, on by default in recent sudo) hides \
                             the console too: log in as root there, use su, or give the GUI a console of its own \
                             with `sudo openvt -s -w -- <full path of this binary> gui`";
const IN_GRAPHICS: &str = "this VT is in graphics mode (X or Wayland owns it); switch to a text console with \
                           Ctrl+Alt+F3 and log in there";
const UNKNOWN_MODE: &str = "this VT reports a console mode that is neither text nor graphics; refusing to take it";
const SWITCHING_HELD: &str = "another process has taken over switching this VT (VT_PROCESS: a display server or \
                              another console program); refusing to take it";
const SWITCHING_UNKNOWN: &str = "the kernel would not say who switches this VT (VT_GETMODE failed); refusing to \
                                 take it";
const IN_BACKGROUND: &str = "it was started in the background; run it in the foreground on the console, or the \
                             first key it reads stops it with the console still in graphics mode";

fn vt_verdict(mode: Option<libc::c_int>) -> Result<(), &'static str> {
    match mode {
        None => Err(NOT_A_CONSOLE),
        Some(KD_TEXT) => Ok(()),
        Some(KD_GRAPHICS) => Err(IN_GRAPHICS),
        Some(_) => Err(UNKNOWN_MODE),
    }
}

fn switching_verdict(mode: Option<VtMode>) -> Result<(), &'static str> {
    match mode.map(|m| m.mode) {
        Some(VT_AUTO) => Ok(()),
        Some(_) => Err(SWITCHING_HELD),
        None => Err(SWITCHING_UNKNOWN),
    }
}

fn foreground_verdict(own: u32, active: Option<u16>) -> Result<(), String> {
    match active {
        Some(on_screen) if u32::from(on_screen) != own => Err(format!(
            "this is tty{own}, but tty{on_screen} is the console on screen; run it from the console that is showing"
        )),
        _ => Ok(()),
    }
}

fn job_verdict(tty_group: Option<libc::pid_t>, own_group: libc::pid_t) -> Result<(), &'static str> {
    match tty_group {
        Some(group) if group != own_group => Err(IN_BACKGROUND),
        _ => Ok(()),
    }
}

fn kd_mode(fd: RawFd) -> Option<libc::c_int> {
    let mut mode: libc::c_int = -1;

    let rc = unsafe { libc::ioctl(fd, KDGETMODE as _, &raw mut mode) };
    (rc == 0).then_some(mode)
}

fn kd_set(fd: RawFd, mode: libc::c_int) -> io::Result<()> {
    let arg = libc::c_ulong::try_from(mode).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;

    if unsafe { libc::ioctl(fd, KDSETMODE as _, arg) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn active_console(fd: RawFd) -> Option<u16> {
    let mut state = VtStat::default();

    let rc = unsafe { libc::ioctl(fd, VT_GETSTATE as _, &raw mut state) };
    (rc == 0).then_some(state.v_active)
}

fn switching(fd: RawFd) -> Option<VtMode> {
    let mut mode = VtMode::default();

    let rc = unsafe { libc::ioctl(fd, VT_GETMODE as _, &raw mut mode) };
    (rc == 0).then_some(mode)
}

fn set_switching(fd: RawFd, mode: libc::c_char) -> io::Result<()> {
    let arg = VtMode { mode, waitv: 0, relsig: 0, acqsig: 0, frsig: 0 };

    if unsafe { libc::ioctl(fd, VT_SETMODE as _, &raw const arg) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

pub fn on_screen() -> bool {
    console_number().is_none_or(|own| foreground_verdict(own, active_console(libc::STDIN_FILENO)).is_ok())
}

fn console_number() -> Option<u32> {
    let (major, minor) = char_device(libc::STDIN_FILENO)?;
    (major == TTY_MAJOR && (1..=MAX_NR_CONSOLES).contains(&minor)).then_some(minor)
}

fn console_path(num: i32) -> Option<[u8; 16]> {
    let n = u8::try_from(num).ok().filter(|&n| u32::from(n) <= MAX_NR_CONSOLES)?;
    let mut path = [0u8; 16];
    let mut len = 0;
    let mut push = |b: u8| {
        if let Some(slot) = path.get_mut(len) {
            *slot = b;
        }
        len += 1;
    };
    for &b in b"/dev/tty" {
        push(b);
    }
    if n >= 10 {
        push(b'0' + n / 10);
    }
    push(b'0' + n % 10);

    Some(path)
}

fn current_pid() -> libc::pid_t {

    unsafe { libc::getpid() }
}

fn write_ignoring(fd: RawFd, bytes: &[u8]) {

    let _ = unsafe { libc::write(fd, bytes.as_ptr().cast(), bytes.len()) };
}

fn restore_vt_mode() {
    let fd = VT_FD.load(Ordering::Acquire);
    if fd < 0 || OWNER_PID.load(Ordering::Relaxed) != current_pid() {
        return;
    }
    let mode = VT_MODE.load(Ordering::Relaxed);
    if kd_set(fd, mode).and_then(|()| set_switching(fd, VT_AUTO)).is_ok() {
        write_ignoring(fd, CLEAR_SCREEN);
    } else {

        reopen_and_set(VT_NUM.load(Ordering::Relaxed), mode);
    }
    VT_FD.store(-1, Ordering::Release);
}

fn reopen_and_set(num: i32, mode: libc::c_int) {
    let Some(path) = console_path(num) else {
        return;
    };

    let at = unsafe { libc::open(path.as_ptr().cast(), libc::O_PATH | libc::O_CLOEXEC) };
    if at < 0 {
        return;
    }
    let vetted = char_device(at).is_some_and(|dev| is_console(dev, num));
    if let Some(reopen) = proc_fd_path(at).filter(|_| vetted) {

        let fd = unsafe { libc::open(reopen.as_ptr().cast(), libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC) };
        if fd >= 0 {
            let _ = kd_set(fd, mode);
            let _ = set_switching(fd, VT_AUTO);

            unsafe { libc::close(fd) };
        }
    }

    unsafe { libc::close(at) };
}

fn char_device(fd: RawFd) -> Option<(u32, u32)> {
    let mut st = MaybeUninit::<libc::stat>::uninit();

    if unsafe { libc::fstat(fd, st.as_mut_ptr()) } != 0 {
        return None;
    }

    let st = unsafe { st.assume_init() };
    (st.st_mode & libc::S_IFMT == libc::S_IFCHR).then_some((libc::major(st.st_rdev), libc::minor(st.st_rdev)))
}

fn is_console(dev: (u32, u32), num: i32) -> bool {
    u32::try_from(num).is_ok_and(|n| dev == (TTY_MAJOR, n))
}

fn proc_fd_path(fd: RawFd) -> Option<[u8; 32]> {
    let mut n = u32::try_from(fd).ok()?;

    let mut digits = [0u8; 10];
    let mut count = 0;
    loop {
        if let Some(d) = digits.get_mut(count) {
            *d = b'0' + (n % 10) as u8;
        }
        count += 1;
        n /= 10;
        if n == 0 {
            break;
        }
    }
    let mut path = [0u8; 32];
    let mut len = 0;
    let mut push = |b: u8| {
        if let Some(slot) = path.get_mut(len) {
            *slot = b;
        }
        len += 1;
    };
    for &b in b"/proc/self/fd/" {
        push(b);
    }
    for i in (0..count).rev() {
        push(digits.get(i).copied().unwrap_or(b'0'));
    }

    Some(path)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Cooked {
    iflag: libc::tcflag_t,
    oflag: libc::tcflag_t,
    lflag: libc::tcflag_t,
    vmin: libc::cc_t,
    vtime: libc::cc_t,
}

const RAW_IFLAG_OFF: libc::tcflag_t = libc::IXON | libc::ICRNL | libc::INLCR | libc::IGNCR | libc::ISTRIP;

const RAW_OFLAG_OFF: libc::tcflag_t = libc::OPOST;

const RAW_LFLAG_OFF: libc::tcflag_t = libc::ICANON | libc::ECHO | libc::ISIG | libc::IEXTEN;

fn cooked_of(t: &libc::termios) -> Cooked {
    Cooked {
        iflag: t.c_iflag,
        oflag: t.c_oflag,
        lflag: t.c_lflag,
        vmin: t.c_cc.get(libc::VMIN).copied().unwrap_or(1),
        vtime: t.c_cc.get(libc::VTIME).copied().unwrap_or(0),
    }
}

fn make_raw(t: &mut libc::termios) {
    t.c_iflag &= !RAW_IFLAG_OFF;
    t.c_oflag &= !RAW_OFLAG_OFF;
    t.c_lflag &= !RAW_LFLAG_OFF;
    if let Some(v) = t.c_cc.get_mut(libc::VMIN) {
        *v = 0;
    }
    if let Some(v) = t.c_cc.get_mut(libc::VTIME) {
        *v = 0;
    }
}

fn put_back(t: &mut libc::termios, c: Cooked) {
    t.c_iflag = c.iflag;
    t.c_oflag = c.oflag;
    t.c_lflag = c.lflag;
    if let Some(v) = t.c_cc.get_mut(libc::VMIN) {
        *v = c.vmin;
    }
    if let Some(v) = t.c_cc.get_mut(libc::VTIME) {
        *v = c.vtime;
    }
}

fn save_cooked(c: Cooked) {
    TTY_IFLAG.store(c.iflag, Ordering::Relaxed);
    TTY_OFLAG.store(c.oflag, Ordering::Relaxed);
    TTY_LFLAG.store(c.lflag, Ordering::Relaxed);
    TTY_VMIN.store(c.vmin, Ordering::Relaxed);
    TTY_VTIME.store(c.vtime, Ordering::Relaxed);
}

fn saved_cooked() -> Cooked {
    Cooked {
        iflag: TTY_IFLAG.load(Ordering::Relaxed),
        oflag: TTY_OFLAG.load(Ordering::Relaxed),
        lflag: TTY_LFLAG.load(Ordering::Relaxed),
        vmin: TTY_VMIN.load(Ordering::Relaxed),
        vtime: TTY_VTIME.load(Ordering::Relaxed),
    }
}

fn restore_tty() {
    let fd = TTY_FD.load(Ordering::Acquire);
    if fd < 0 || OWNER_PID.load(Ordering::Relaxed) != current_pid() {
        return;
    }
    let mut now = MaybeUninit::<libc::termios>::uninit();

    if unsafe { libc::tcgetattr(fd, now.as_mut_ptr()) } == 0 {

        let mut t = unsafe { now.assume_init() };
        put_back(&mut t, saved_cooked());

        unsafe { libc::tcsetattr(fd, libc::TCSANOW, &raw const t) };

        unsafe { libc::tcflush(fd, libc::TCIFLUSH) };
    }
    TTY_FD.store(-1, Ordering::Release);
}

pub fn restore_vt_now() {
    restore_vt_mode();
    restore_tty();
}

fn install_panic_hook() {
    if HOOK_INSTALLED.swap(true, Ordering::AcqRel) {
        return;
    }
    let prior = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        restore_vt_now();
        prior(info);
    }));
}

extern "C" fn on_fatal_signal(sig: libc::c_int) {
    restore_vt_now();

    unsafe { libc::raise(sig) };
}

fn empty_sigaction() -> libc::sigaction {

    unsafe { std::mem::zeroed() }
}

fn install_handlers() -> io::Result<Vec<(libc::c_int, libc::sigaction)>> {
    let mut prior = Vec::with_capacity(FATAL_SIGNALS.len());
    for sig in FATAL_SIGNALS {
        let mut old = empty_sigaction();

        if unsafe { libc::sigaction(sig, ptr::null(), &raw mut old) } != 0 {
            let e = io::Error::last_os_error();
            restore_handlers(&prior);
            return Err(e);
        }
        if old.sa_sigaction != libc::SIG_DFL {
            continue;
        }
        let mut new = empty_sigaction();
        new.sa_sigaction = on_fatal_signal as extern "C" fn(libc::c_int) as libc::sighandler_t;
        new.sa_flags = libc::SA_RESETHAND | libc::SA_ONSTACK;

        if unsafe { libc::sigaction(sig, &raw const new, &raw mut old) } != 0 {
            let e = io::Error::last_os_error();
            restore_handlers(&prior);
            return Err(e);
        }
        prior.push((sig, old));
    }
    Ok(prior)
}

fn restore_handlers(prior: &[(libc::c_int, libc::sigaction)]) {
    for (sig, old) in prior {

        unsafe { libc::sigaction(*sig, old, ptr::null_mut()) };
    }
}

pub struct VtGraphics {

    prior: Vec<(libc::c_int, libc::sigaction)>,
}

impl VtGraphics {

    pub fn check() -> io::Result<()> {
        let fd = libc::STDIN_FILENO;
        vt_verdict(kd_mode(fd)).map_err(|why| io::Error::new(io::ErrorKind::Unsupported, why))?;
        switching_verdict(switching(fd)).map_err(|why| io::Error::new(io::ErrorKind::Unsupported, why))?;
        if let Some(own) = console_number() {
            foreground_verdict(own, active_console(fd))
                .map_err(|why| io::Error::new(io::ErrorKind::Unsupported, why))?;
        }

        let tty_group = unsafe { libc::tcgetpgrp(fd) };

        let own_group = unsafe { libc::getpgrp() };
        job_verdict((tty_group >= 0).then_some(tty_group), own_group)
            .map_err(|why| io::Error::new(io::ErrorKind::Unsupported, why))
    }

    pub fn enter() -> io::Result<Self> {
        let fd = libc::STDIN_FILENO;
        Self::check()?;
        let own = console_number();
        if VT_OWNED.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire).is_err() {
            return Err(io::Error::new(
                io::ErrorKind::ResourceBusy,
                "this process already holds the console in graphics mode",
            ));
        }
        install_panic_hook();

        OWNER_PID.store(current_pid(), Ordering::Relaxed);
        VT_MODE.store(KD_TEXT, Ordering::Relaxed);
        VT_NUM.store(own.and_then(|n| i32::try_from(n).ok()).unwrap_or(0), Ordering::Relaxed);
        VT_FD.store(fd, Ordering::Release);
        let prior = match install_handlers() {
            Ok(prior) => prior,
            Err(e) => {
                VT_FD.store(-1, Ordering::Release);
                VT_OWNED.store(false, Ordering::Release);
                return Err(context(e, "cannot install the console's signal handlers"));
            }
        };

        let withdraw = |switching_taken: bool| {
            if switching_taken {
                let _ = set_switching(fd, VT_AUTO);
            }
            VT_FD.store(-1, Ordering::Release);
            restore_handlers(&prior);
            VT_OWNED.store(false, Ordering::Release);
        };
        let hint = |e: &io::Error| {
            if e.kind() == io::ErrorKind::PermissionDenied {
                " (it needs root, or the console as the controlling terminal)"
            } else {
                ""
            }
        };
        if let Err(e) = set_switching(fd, VT_PROCESS) {
            withdraw(false);
            let what = format!("cannot take over switching the console{}", hint(&e));
            return Err(context(e, &what));
        }

        if let Some(why) = own.and_then(|own| foreground_verdict(own, active_console(fd)).err()) {
            withdraw(true);
            return Err(io::Error::new(io::ErrorKind::Unsupported, why));
        }
        if let Err(e) = kd_set(fd, KD_GRAPHICS) {
            withdraw(true);
            let what = format!("cannot switch the console to graphics mode{}", hint(&e));
            return Err(context(e, &what));
        }
        Ok(VtGraphics { prior })
    }
}

impl Drop for VtGraphics {
    fn drop(&mut self) {

        restore_vt_mode();
        restore_handlers(&self.prior);
        VT_OWNED.store(false, Ordering::Release);
    }
}

pub struct RawTty {

    tty: File,
}

impl RawTty {

    pub fn enter() -> io::Result<Self> {
        let fd = libc::STDIN_FILENO;
        let tty = File::from(io::stdin().as_fd().try_clone_to_owned().map_err(|e| context(e, "standard input"))?);
        if TTY_OWNED.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire).is_err() {
            return Err(io::Error::new(io::ErrorKind::ResourceBusy, "this process already holds the tty in raw mode"));
        }
        install_panic_hook();
        let mut now = MaybeUninit::<libc::termios>::uninit();

        if unsafe { libc::tcgetattr(fd, now.as_mut_ptr()) } != 0 {
            let e = io::Error::last_os_error();
            TTY_OWNED.store(false, Ordering::Release);
            return Err(context(e, "standard input is not a terminal; run it from the host's console"));
        }

        let cooked = unsafe { now.assume_init() };
        save_cooked(cooked_of(&cooked));
        OWNER_PID.store(current_pid(), Ordering::Relaxed);
        TTY_FD.store(fd, Ordering::Release);
        let mut raw = cooked;
        make_raw(&mut raw);

        if unsafe { libc::tcsetattr(fd, libc::TCSAFLUSH, &raw const raw) } != 0 {
            let e = io::Error::last_os_error();

            restore_tty();
            TTY_OWNED.store(false, Ordering::Release);
            return Err(context(e, "cannot put the tty in raw mode"));
        }
        Ok(RawTty { tty })
    }

    pub fn fd(&self) -> RawFd {
        self.tty.as_raw_fd()
    }

    pub fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        match self.tty.read(buf) {
            Ok(0) if hung_up(self.tty.as_raw_fd()) => {
                Err(io::Error::new(io::ErrorKind::BrokenPipe, "the console hung up (its session ended)"))
            }
            Ok(n) => Ok(n),

            Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted) => Ok(0),
            Err(e) => Err(e),
        }
    }
}

impl Drop for RawTty {
    fn drop(&mut self) {
        restore_tty();
        TTY_OWNED.store(false, Ordering::Release);
    }
}

fn hung_up(fd: RawFd) -> bool {
    let mut p = libc::pollfd { fd, events: libc::POLLIN, revents: 0 };

    let rc = unsafe { libc::poll(&raw mut p, 1, 0) };
    rc > 0 && p.revents & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) != 0
}

const INPUT_DIR: &str = "/dev/input";

const MAX_POINTERS: usize = 16;

const MAX_ENTRIES: usize = 1024;

const EVENTS_PER_SYSCALL: usize = 64;

const READS_PER_DRAIN: usize = 16;

const MAX_NOTCHES: u64 = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PointerEvent {

    Move {

        x: i32,

        y: i32,
    },

    Down {

        x: i32,

        y: i32,
    },

    Wheel {

        up: bool,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct InputEvent {
    kind: u16,
    code: u16,
    value: i32,
}

fn decode_one(record: &[u8; EVENT_SIZE]) -> InputEvent {
    let [.., t0, t1, c0, c1, v0, v1, v2, v3] = *record;
    InputEvent {
        kind: u16::from_ne_bytes([t0, t1]),
        code: u16::from_ne_bytes([c0, c1]),
        value: i32::from_ne_bytes([v0, v1, v2, v3]),
    }
}

fn decode(bytes: &[u8]) -> impl Iterator<Item = InputEvent> + '_ {
    let (whole, _tail) = bytes.as_chunks::<EVENT_SIZE>();
    whole.iter().map(decode_one)
}

fn bit(bits: &[u8], n: u16) -> bool {
    bits.get(usize::from(n / 8)).is_some_and(|byte| byte & (1 << (n % 8)) != 0)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {

    Tablet,

    Mouse,
}

fn classify(keys: &[u8], rels: &[u8], abss: &[u8]) -> Option<Kind> {
    if !bit(keys, BTN_LEFT) {
        return None;
    }
    if bit(abss, ABS_X) && bit(abss, ABS_Y) {
        return Some(Kind::Tablet);
    }
    if bit(rels, REL_X) && bit(rels, REL_Y) {
        return Some(Kind::Mouse);
    }
    None
}

fn is_event_node(name: &[u8]) -> bool {
    name.strip_prefix(b"event").is_some_and(|n| !n.is_empty() && n.iter().all(u8::is_ascii_digit))
}

fn side(len: u32) -> i64 {
    i64::from(len.clamp(1, i32::MAX as u32))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct AbsRange {
    min: i32,
    max: i32,
}

impl AbsRange {
    fn new(min: i32, max: i32) -> Option<Self> {
        (max > min).then_some(AbsRange { min, max })
    }

    fn to_pixel(self, value: i32, len: u32) -> i32 {
        let last = side(len) - 1;
        let span = i64::from(self.max) - i64::from(self.min);
        let into = i64::from(value.clamp(self.min, self.max)) - i64::from(self.min);

        let px = into.checked_mul(last).and_then(|p| p.checked_add(span / 2)).map_or(last, |p| p / span);
        i32::try_from(px.clamp(0, last)).unwrap_or(0)
    }
}

fn nudge(pos: i32, delta: i64, len: u32) -> i32 {
    let moved = i64::from(pos).saturating_add(delta).clamp(0, side(len) - 1);
    i32::try_from(moved).unwrap_or(0)
}

fn rescale(pos: i32, from: u32, to: u32) -> i32 {
    let (old_last, new_last) = (side(from) - 1, side(to) - 1);
    let moved = if old_last == 0 {
        new_last / 2
    } else {
        let pos = i64::from(pos).clamp(0, old_last);
        pos.checked_mul(new_last).map_or(new_last, |p| (p + old_last / 2) / old_last)
    };
    i32::try_from(moved.clamp(0, new_last)).unwrap_or(0)
}

fn centre(screen: (u32, u32)) -> (i32, i32) {
    let mid = |len: u32| i32::try_from((side(len) - 1) / 2).unwrap_or(0);
    (mid(screen.0), mid(screen.1))
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct Ranges {
    x: Option<AbsRange>,
    y: Option<AbsRange>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct Batch {
    abs_x: Option<i32>,
    abs_y: Option<i32>,
    dx: i64,
    dy: i64,
    wheel: i64,
    pressed: bool,

    dropped: bool,
}

impl Batch {

    fn feed(
        &mut self,
        ev: InputEvent,
        ranges: Ranges,
        screen: (u32, u32),
        at: &mut (i32, i32),
        out: &mut Vec<PointerEvent>,
    ) {
        if self.dropped {

            if (ev.kind, ev.code) == (EV_SYN, SYN_REPORT) {
                *self = Batch::default();
            }
            return;
        }
        match (ev.kind, ev.code) {
            (EV_SYN, SYN_REPORT) => {
                self.apply(ranges, screen, at, out);
                *self = Batch::default();
            }
            (EV_SYN, SYN_DROPPED) => *self = Batch { dropped: true, ..Batch::default() },
            (EV_ABS, ABS_X) => self.abs_x = Some(ev.value),
            (EV_ABS, ABS_Y) => self.abs_y = Some(ev.value),
            (EV_REL, REL_X) => self.dx = self.dx.saturating_add(i64::from(ev.value)),
            (EV_REL, REL_Y) => self.dy = self.dy.saturating_add(i64::from(ev.value)),
            (EV_REL, REL_WHEEL) => self.wheel = self.wheel.saturating_add(i64::from(ev.value)),

            (EV_KEY, BTN_LEFT) if ev.value == 1 => self.pressed = true,
            _ => {}
        }
    }

    fn apply(&self, ranges: Ranges, screen: (u32, u32), at: &mut (i32, i32), out: &mut Vec<PointerEvent>) {
        let before = *at;
        let x = match (self.abs_x, ranges.x) {
            (Some(v), Some(r)) => r.to_pixel(v, screen.0),
            _ => before.0,
        };
        let y = match (self.abs_y, ranges.y) {
            (Some(v), Some(r)) => r.to_pixel(v, screen.1),
            _ => before.1,
        };
        let (x, y) = (nudge(x, self.dx, screen.0), nudge(y, self.dy, screen.1));
        *at = (x, y);
        if *at != before {
            out.push(PointerEvent::Move { x, y });
        }
        if self.pressed {
            out.push(PointerEvent::Down { x, y });
        }
        for _ in 0..self.wheel.unsigned_abs().min(MAX_NOTCHES) {
            out.push(PointerEvent::Wheel { up: self.wheel > 0 });
        }
    }
}

struct Device {
    file: File,
    ranges: Ranges,
    batch: Batch,
}

fn event_bits<const N: usize>(file: &File, ev: u16) -> [u8; N] {
    let mut bits = [0u8; N];

    let rc = unsafe { libc::ioctl(file.as_raw_fd(), eviocgbit(ev, N) as _, bits.as_mut_ptr()) };
    if rc < 0 {
        return [0u8; N];
    }
    bits
}

fn abs_range(file: &File, axis: u16) -> Option<AbsRange> {
    let mut info = libc::input_absinfo { value: 0, minimum: 0, maximum: 0, fuzz: 0, flat: 0, resolution: 0 };

    let rc = unsafe { libc::ioctl(file.as_raw_fd(), eviocgabs(axis) as _, &raw mut info) };
    if rc < 0 {
        return None;
    }
    AbsRange::new(info.minimum, info.maximum)
}

impl Device {

    fn open(path: &Path) -> Option<Device> {
        let file = open_device(path, INPUT_MAJOR, false, libc::O_NONBLOCK).ok()?;
        let keys: [u8; KEY_BITS] = event_bits(&file, EV_KEY);
        let rels: [u8; REL_BITS] = event_bits(&file, EV_REL);
        let abss: [u8; ABS_BITS] = event_bits(&file, EV_ABS);
        let ranges = match classify(&keys, &rels, &abss)? {
            Kind::Tablet => Ranges { x: abs_range(&file, ABS_X), y: abs_range(&file, ABS_Y) },
            Kind::Mouse => Ranges::default(),
        };
        Some(Device { file, ranges, batch: Batch::default() })
    }

    fn drain(&mut self, screen: (u32, u32), at: &mut (i32, i32), out: &mut Vec<PointerEvent>) -> bool {
        let mut buf = [0u8; EVENT_SIZE * EVENTS_PER_SYSCALL];
        for _ in 0..READS_PER_DRAIN {
            match self.file.read(&mut buf) {

                Ok(0) => return true,
                Ok(n) => {
                    for ev in decode(buf.get(..n).unwrap_or_default()) {
                        self.batch.feed(ev, self.ranges, screen, at, out);
                    }
                }

                Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted) => return true,
                Err(_) => return false,
            }
        }
        true
    }
}

pub struct Pointers {
    devices: Vec<Device>,
    screen: (u32, u32),
    at: (i32, i32),
}

impl Pointers {

    pub fn open(screen: (u32, u32)) -> io::Result<Self> {
        let mut devices = Vec::new();
        let entries = match fs::read_dir(INPUT_DIR) {
            Ok(entries) => entries,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Self::with(devices, screen)),
            Err(e) => return Err(context(e, INPUT_DIR)),
        };
        for entry in entries.take(MAX_ENTRIES).flatten() {
            if devices.len() >= MAX_POINTERS {
                break;
            }
            if !is_event_node(entry.file_name().as_bytes()) {
                continue;
            }
            if let Some(device) = Device::open(&entry.path()) {
                devices.push(device);
            }
        }
        Ok(Self::with(devices, screen))
    }

    fn with(devices: Vec<Device>, screen: (u32, u32)) -> Self {
        Pointers { devices, screen, at: centre(screen) }
    }

    pub fn fds(&self) -> Vec<RawFd> {
        self.devices.iter().map(|d| d.file.as_raw_fd()).collect()
    }

    pub fn position(&self) -> (i32, i32) {
        self.at
    }

    pub fn read(&mut self) -> Vec<PointerEvent> {
        let mut out = Vec::new();
        let screen = self.screen;
        let at = &mut self.at;
        self.devices.retain_mut(|device| device.drain(screen, at, &mut out));
        out
    }

    pub fn set_screen(&mut self, screen: (u32, u32)) {
        self.at = (rescale(self.at.0, self.screen.0, screen.0), rescale(self.at.1, self.screen.1, screen.1));
        self.screen = screen;
    }
}

fn poll_millis(timeout: Duration) -> libc::c_int {
    libc::c_int::try_from(timeout.as_micros().div_ceil(1000)).unwrap_or(libc::c_int::MAX)
}

fn ready(revents: libc::c_short) -> bool {
    revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) != 0
}

pub fn wait_readable(fds: &[RawFd], timeout: Duration) -> io::Result<Vec<bool>> {
    let mut polled: Vec<libc::pollfd> =
        fds.iter().map(|&fd| libc::pollfd { fd, events: libc::POLLIN, revents: 0 }).collect();
    let count = libc::nfds_t::try_from(polled.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "too many descriptors to wait on"))?;

    let rc = unsafe { libc::poll(polled.as_mut_ptr(), count, poll_millis(timeout)) };
    if rc < 0 {
        let e = io::Error::last_os_error();
        if e.kind() == io::ErrorKind::Interrupted {
            return Ok(vec![false; fds.len()]);
        }
        return Err(e);
    }
    Ok(polled.iter().map(|p| ready(p.revents)).collect())
}
