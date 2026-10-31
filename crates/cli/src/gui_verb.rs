use std::io;
use std::process::ExitCode;
use std::time::Duration;

#[cfg(target_os = "linux")]
use std::collections::VecDeque;
#[cfg(target_os = "linux")]
use std::io::Write as _;
#[cfg(target_os = "linux")]
use std::time::Instant;

use hemostat_gui::backend::{Backend, RawEvent};
#[cfg(target_os = "linux")]
use hemostat_gui::keys::TtyKeys;
use hemostat_gui::render::Frame;
use hemostat_gui::surface::GuiSurface;
#[cfg(target_os = "linux")]
use hemostat_sensor_linux::gui_fb::{self, Framebuffer, PointerEvent, Pointers, RawTty, VtGraphics};
#[cfg(target_os = "linux")]
use hemostat_sensor_linux::gui_x11::{self, XEvent, XKey};
#[cfg(target_os = "windows")]
use hemostat_sensor_win::gui_window::Window;
#[cfg(any(target_os = "windows", test))]
use hemostat_sensor_win::gui_window_logic::{WinEvent, WinKey};

use crate::{EXIT_OK, EXIT_USAGE};

const SWEEPING: &str = "hemostat: sweeping this host…";

#[cfg(target_os = "linux")]
const SWEEPING_AGAIN: &str = "hemostat gui: sweeping this host… the view comes back when the sweep is done \
                              (Ctrl+C ends the GUI at once, without waiting for a seal in progress)";

#[cfg(any(target_os = "windows", target_os = "linux"))]
const TITLE: &str = "Mahoraga — findings console";

pub(crate) fn gui(args: &[String]) -> ExitCode {

    #[cfg(not(all(target_os = "windows", feature = "mod-detect-sigma")))]
    let every = match every_secs(args) {
        Ok(every) => every,
        Err(why) => {
            eprintln!("{why}");
            return ExitCode::from(EXIT_USAGE);
        }
    };
    #[cfg(all(target_os = "windows", feature = "mod-detect-sigma"))]
    crate::win_detect::set_console_rules(
        args.iter().position(|a| a == "--rules").and_then(|i| args.get(i + 1)).cloned(),
    );

    #[cfg(target_os = "linux")]
    install_restore_hook();
    let backend = match open() {
        Ok(backend) => backend,
        Err(e) => {
            eprintln!("{}", cannot_open(&e));
            return ExitCode::from(EXIT_USAGE);
        }
    };
    let mut surface = GuiSurface::new(backend);
    sweeping(&mut surface);

    #[cfg(all(target_os = "windows", feature = "mod-detect-sigma"))]
    let ran = {
        crate::win_detect::console_live_start();
        hemostat_tui::run_console_live_on(
            surface,
            crate::console_model(),
            crate::console_model,
            crate::apply_remedy,
            crate::win_detect::console_live_tick,
            crate::tui_verbs::verbs(crate::tui_verbs::this_platform()),
        )
    };
    #[cfg(not(all(target_os = "windows", feature = "mod-detect-sigma")))]
    let ran = {
        let verbs = crate::tui_verbs::verbs(crate::tui_verbs::this_platform());
        match every {
            Some(secs) => hemostat_tui::run_console_every_on(
                surface,
                crate::live_console_model(),
                crate::live_console_model,
                crate::periodic_console_model,
                crate::apply_remedy,
                std::time::Duration::from_secs(secs.max(5)),
                verbs,
            ),
            #[cfg(target_os = "linux")]
            None => hemostat_tui::run_console_live_on(
                surface,
                crate::live_console_model(),
                crate::live_console_model,
                crate::apply_remedy,
                crate::evidence::console_seal_tick,
                verbs,
            ),
            #[cfg(not(target_os = "linux"))]
            None => hemostat_tui::run_console_on(
                surface,
                crate::live_console_model(),
                crate::live_console_model,
                crate::apply_remedy,
                verbs,
            ),
        }
    };

    #[cfg(target_os = "linux")]
    crate::evidence::console_seal_finish();
    match ran {
        Ok(()) => ExitCode::from(EXIT_OK),
        Err(e) => {
            eprintln!("hemostat gui: display error: {}", crate::render::h(&e.to_string()));
            ExitCode::from(EXIT_USAGE)
        }
    }
}

#[cfg(any(test, not(all(target_os = "windows", feature = "mod-detect-sigma"))))]
fn every_secs(args: &[String]) -> Result<Option<u64>, String> {
    match args.iter().position(|a| a == "--every") {
        None => Ok(None),
        Some(i) => args
            .get(i + 1)
            .filter(|v| !v.starts_with("--"))
            .and_then(|v| v.parse::<u64>().ok())
            .map(Some)
            .ok_or_else(|| "hemostat gui: --every takes a whole number of seconds".to_string()),
    }
}

fn cannot_open(e: &io::Error) -> String {
    format!(
        "hemostat gui: the GUI cannot open here: {}\n  Nothing was swept or changed. Use the \
         terminal console instead: hemostat console{}",
        crate::render::h(&e.to_string()),
        desktop_hint()
    )
}

fn desktop_hint() -> &'static str {
    if cfg!(target_os = "linux") && std::env::var_os("DISPLAY").is_none() {
        "\n  On a desktop, run it from a terminal there so it opens as a window: sudo keeps \
         DISPLAY; after su -, use DISPLAY=:0 hemostat gui"
    } else {
        ""
    }
}

#[cfg(target_os = "windows")]
fn sweeping(surface: &mut GuiSurface<WinBackend>) {

    let _ = surface.notice(SWEEPING);

    surface.backend_mut().forget = true;
}

#[cfg(target_os = "linux")]
fn sweeping(surface: &mut GuiSurface<LinuxBackend>) {
    if matches!(surface.backend_mut(), LinuxBackend::Console(_)) {
        eprintln!("{SWEEPING}");
        return;
    }

    let _ = surface.notice(SWEEPING);
    if let LinuxBackend::Window(window) = surface.backend_mut() {
        window.forget = true;
    }
}

#[cfg(target_os = "linux")]
fn install_restore_hook() {
    let prior = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        gui_fb::restore_vt_now();
        prior(info);
    }));
}

#[cfg(target_os = "linux")]
fn open() -> io::Result<LinuxBackend> {
    match gui_x11::display_from_env() {
        Some(display) => {
            let window = gui_x11::Window::open(&display?, TITLE, hemostat_gui::render::BG)?;
            Ok(LinuxBackend::Window(XBackend { window, forget: false }))
        }
        None => FbBackend::open().map(LinuxBackend::Console),
    }
}

#[cfg(target_os = "linux")]
enum LinuxBackend {

    Window(XBackend),

    Console(FbBackend),
}

#[cfg(target_os = "linux")]
impl Backend for LinuxBackend {
    fn size(&self) -> (u32, u32) {
        match self {
            LinuxBackend::Window(b) => b.size(),
            LinuxBackend::Console(b) => b.size(),
        }
    }

    fn poll(&mut self, timeout: Duration) -> io::Result<Option<RawEvent>> {
        match self {
            LinuxBackend::Window(b) => b.poll(timeout),
            LinuxBackend::Console(b) => b.poll(timeout),
        }
    }

    fn present(&mut self, frame: &Frame) -> io::Result<()> {
        match self {
            LinuxBackend::Window(b) => b.present(frame),
            LinuxBackend::Console(b) => b.present(frame),
        }
    }

    fn wants_pointer(&self) -> bool {
        match self {
            LinuxBackend::Window(b) => b.wants_pointer(),
            LinuxBackend::Console(b) => b.wants_pointer(),
        }
    }

    fn scale_floor(&self) -> u32 {
        match self {
            LinuxBackend::Window(b) => b.scale_floor(),
            LinuxBackend::Console(b) => b.scale_floor(),
        }
    }

    fn release(&mut self) {
        match self {
            LinuxBackend::Window(b) => b.release(),
            LinuxBackend::Console(b) => b.release(),
        }
    }
}

#[cfg(target_os = "linux")]
struct XBackend {
    window: gui_x11::Window,

    forget: bool,
}

#[cfg(target_os = "linux")]
impl Backend for XBackend {
    fn size(&self) -> (u32, u32) {
        self.window.size()
    }

    fn poll(&mut self, timeout: Duration) -> io::Result<Option<RawEvent>> {
        Ok(self.window.poll(timeout)?.map(x_event))
    }

    fn present(&mut self, frame: &Frame) -> io::Result<()> {
        if std::mem::take(&mut self.forget) {
            self.window.forget_input()?;
        }
        self.window.present(frame.width, frame.height, &frame.pixels)
    }

    fn wants_pointer(&self) -> bool {
        false
    }

    fn scale_floor(&self) -> u32 {
        self.window.scale_floor()
    }

    fn release(&mut self) {
        self.forget = true;
    }
}

#[cfg(target_os = "linux")]
fn x_event(event: XEvent) -> RawEvent {
    use hemostat_gui::backend::{Mods, RawKey};
    match event {
        XEvent::Key { key, ctrl, alt, shift } => {
            let key = match key {
                XKey::Char(c) => RawKey::Char(c),
                XKey::Enter => RawKey::Enter,
                XKey::Esc => RawKey::Esc,
                XKey::Backspace => RawKey::Backspace,
                XKey::Tab => RawKey::Tab,
                XKey::BackTab => RawKey::BackTab,
                XKey::Up => RawKey::Up,
                XKey::Down => RawKey::Down,
                XKey::Left => RawKey::Left,
                XKey::Right => RawKey::Right,
                XKey::PageUp => RawKey::PageUp,
                XKey::PageDown => RawKey::PageDown,
                XKey::Home => RawKey::Home,
                XKey::End => RawKey::End,
                XKey::Delete => RawKey::Delete,
                XKey::F(n) => RawKey::F(n),
            };
            RawEvent::Key(key, Mods { ctrl, alt, shift })
        }
        XEvent::PointerMove { x, y } => RawEvent::PointerMove { x, y },
        XEvent::PointerDown { x, y } => RawEvent::PointerDown { x, y },
        XEvent::Wheel { up } => RawEvent::Wheel { up },
        XEvent::Resized { width, height } => RawEvent::Resized { width, height },
        XEvent::Close => RawEvent::Close,
    }
}

#[cfg(target_os = "linux")]
struct FbBackend {

    vt: Option<VtGraphics>,
    input: FbInput,
    fb: Framebuffer,
    keys: TtyInput,
    queue: VecDeque<RawEvent>,
}

#[cfg(target_os = "linux")]
impl FbBackend {
    fn open() -> io::Result<Self> {

        VtGraphics::check()?;
        let fb = Framebuffer::open()?;
        let pointers = Pointers::open(fb.size())?;
        Ok(FbBackend {
            vt: None,
            input: FbInput { tty: None, pointers },
            fb,
            keys: TtyInput::default(),
            queue: VecDeque::new(),
        })
    }

    fn ready(&mut self) -> io::Result<bool> {
        if self.vt.is_some() {
            return Ok(true);
        }
        if !gui_fb::on_screen() {
            return Ok(false);
        }
        match self.take() {
            Ok(()) => Ok(true),

            Err(_) if !gui_fb::on_screen() => Ok(false),
            Err(e) => Err(e),
        }
    }

    fn take(&mut self) -> io::Result<()> {

        let vt = VtGraphics::enter()?;
        let tty = RawTty::enter()?;
        self.fb.refresh()?;

        let _ = self.input.pointers.read();
        self.input.pointers.set_screen(self.fb.size());

        if !self.input.pointers.fds().is_empty() {
            let (x, y) = self.input.pointers.position();
            self.queue.push_back(RawEvent::PointerMove { x, y });
        }

        let (width, height) = self.fb.size();
        self.queue.push_back(RawEvent::Resized { width, height });
        self.vt = Some(vt);
        self.input.tty = Some(tty);
        Ok(())
    }
}

#[cfg(target_os = "linux")]
impl Backend for FbBackend {
    fn size(&self) -> (u32, u32) {
        self.fb.size()
    }

    fn poll(&mut self, timeout: Duration) -> io::Result<Option<RawEvent>> {
        if !self.ready()? {
            std::thread::sleep(timeout);
            return Ok(None);
        }
        poll_devices(&mut self.input, &mut self.keys, &mut self.queue, timeout)
    }

    fn present(&mut self, frame: &Frame) -> io::Result<()> {
        if !self.ready()? {
            return Ok(());
        }
        self.fb.blit(frame.width, frame.height, &frame.pixels)
    }

    fn wants_pointer(&self) -> bool {
        true
    }

    fn release(&mut self) {
        let held = self.vt.is_some();

        self.vt = None;
        self.input.tty = None;
        self.keys = TtyInput::default();
        self.queue.clear();
        if held {

            let _ = writeln!(io::stderr(), "{SWEEPING_AGAIN}");
        }
    }
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct Ready {
    tty: bool,
    pointers: bool,
}

#[cfg(target_os = "linux")]
trait Devices {

    fn wait(&mut self, timeout: Duration) -> io::Result<Ready>;

    fn read_tty(&mut self, buf: &mut [u8]) -> io::Result<usize>;

    fn read_pointers(&mut self) -> Vec<PointerEvent>;
}

#[cfg(target_os = "linux")]
struct FbInput {
    tty: Option<RawTty>,
    pointers: Pointers,
}

#[cfg(target_os = "linux")]
impl Devices for FbInput {
    fn wait(&mut self, timeout: Duration) -> io::Result<Ready> {

        let ttys: Vec<_> = self.tty.iter().map(RawTty::fd).collect();
        let mut fds = ttys.clone();
        fds.extend(self.pointers.fds());
        let ready = gui_fb::wait_readable(&fds, timeout)?;
        let (tty, pointers) = ready.split_at(ttys.len().min(ready.len()));
        Ok(Ready { tty: tty.iter().any(|r| *r), pointers: pointers.iter().any(|r| *r) })
    }

    fn read_tty(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.tty.as_mut().map_or(Ok(0), |tty| tty.read(buf))
    }

    fn read_pointers(&mut self) -> Vec<PointerEvent> {
        self.pointers.read()
    }
}

#[cfg(target_os = "linux")]
const ESC_WAIT: Duration = Duration::from_millis(50);

#[cfg(target_os = "linux")]
const TTY_READS: usize = 16;
#[cfg(target_os = "linux")]
const TTY_CHUNK: usize = 256;

#[cfg(target_os = "linux")]
#[derive(Debug, Default)]
struct TtyInput {
    keys: TtyKeys,

    since: Option<Instant>,
}

#[cfg(target_os = "linux")]
impl TtyInput {

    fn feed(&mut self, bytes: &[u8], now: Instant) -> Vec<RawEvent> {
        let keys = self.keys.feed(bytes);
        self.since = self.keys.pending_escape().then_some(now);
        keys.into_iter().map(|(k, m)| RawEvent::Key(k, m)).collect()
    }

    fn wait(&self, now: Instant, left: Duration) -> Duration {
        self.since.map_or(left, |t| left.min(ESC_WAIT.saturating_sub(now.saturating_duration_since(t))))
    }

    fn expire(&mut self, now: Instant) -> Vec<RawEvent> {
        match self.since {
            Some(t) if now.saturating_duration_since(t) >= ESC_WAIT => {
                self.since = None;
                self.keys.flush_escape().into_iter().map(|(k, m)| RawEvent::Key(k, m)).collect()
            }
            _ => Vec::new(),
        }
    }
}

#[cfg(target_os = "linux")]
fn poll_devices<D: Devices>(
    dev: &mut D,
    keys: &mut TtyInput,
    queue: &mut VecDeque<RawEvent>,
    timeout: Duration,
) -> io::Result<Option<RawEvent>> {
    let start = Instant::now();
    let mut looked = false;
    loop {
        let now = Instant::now();
        queue.extend(keys.expire(now));
        if let Some(event) = queue.pop_front() {
            return Ok(Some(event));
        }
        let left = timeout.saturating_sub(now.saturating_duration_since(start));
        if left.is_zero() && looked {
            return Ok(None);
        }
        looked = true;

        let ready = dev.wait(keys.wait(now, left))?;
        if ready.tty {
            let mut buf = [0u8; TTY_CHUNK];
            for _ in 0..TTY_READS {

                let n = dev.read_tty(&mut buf)?;
                let bytes = buf.get(..n).unwrap_or_default();
                if bytes.is_empty() {
                    break;
                }
                queue.extend(keys.feed(bytes, Instant::now()));
                if n < buf.len() {
                    break;
                }
            }
        }
        if ready.pointers {
            queue.extend(dev.read_pointers().into_iter().map(pointer_event));
        }
    }
}

#[cfg(target_os = "linux")]
fn pointer_event(event: PointerEvent) -> RawEvent {
    match event {
        PointerEvent::Move { x, y } => RawEvent::PointerMove { x, y },
        PointerEvent::Down { x, y } => RawEvent::PointerDown { x, y },
        PointerEvent::Wheel { up } => RawEvent::Wheel { up },
    }
}

#[cfg(target_os = "windows")]
fn open() -> io::Result<WinBackend> {
    Ok(WinBackend { window: Window::open(TITLE)?, forget: false })
}

#[cfg(target_os = "windows")]
struct WinBackend {
    window: Window,

    forget: bool,
}

#[cfg(target_os = "windows")]
impl Backend for WinBackend {
    fn size(&self) -> (u32, u32) {
        self.window.size()
    }

    fn poll(&mut self, timeout: Duration) -> io::Result<Option<RawEvent>> {
        Ok(self.window.poll(timeout)?.map(win_event))
    }

    fn present(&mut self, frame: &Frame) -> io::Result<()> {
        if std::mem::take(&mut self.forget) {
            self.window.forget_input();
            let _ = hemostat_sensor_win::console::ignore_ctrl_c();
        }
        self.window.present(frame.width, frame.height, &frame.pixels)
    }

    fn wants_pointer(&self) -> bool {
        false
    }

    fn scale_floor(&self) -> u32 {
        self.window.scale_floor()
    }

    fn release(&mut self) {
        self.forget = true;
    }
}

#[cfg(target_os = "windows")]
impl Drop for WinBackend {
    fn drop(&mut self) {
        hemostat_sensor_win::console::discard_typeahead();
    }
}

#[cfg(any(target_os = "windows", test))]
fn win_event(event: WinEvent) -> RawEvent {
    use hemostat_gui::backend::Mods;
    match event {
        WinEvent::Key { key, ctrl, alt, shift } => RawEvent::Key(win_key(key), Mods { ctrl, alt, shift }),
        WinEvent::PointerMove { x, y } => RawEvent::PointerMove { x, y },
        WinEvent::PointerDown { x, y } => RawEvent::PointerDown { x, y },
        WinEvent::Wheel { up } => RawEvent::Wheel { up },
        WinEvent::Resized { width, height } => RawEvent::Resized { width, height },
        WinEvent::Close => RawEvent::Close,
    }
}

#[cfg(any(target_os = "windows", test))]
fn win_key(key: WinKey) -> hemostat_gui::backend::RawKey {
    use hemostat_gui::backend::RawKey;
    match key {
        WinKey::Char(c) => RawKey::Char(c),
        WinKey::Enter => RawKey::Enter,
        WinKey::Esc => RawKey::Esc,
        WinKey::Backspace => RawKey::Backspace,
        WinKey::Tab => RawKey::Tab,
        WinKey::BackTab => RawKey::BackTab,
        WinKey::Up => RawKey::Up,
        WinKey::Down => RawKey::Down,
        WinKey::Left => RawKey::Left,
        WinKey::Right => RawKey::Right,
        WinKey::PageUp => RawKey::PageUp,
        WinKey::PageDown => RawKey::PageDown,
        WinKey::Home => RawKey::Home,
        WinKey::End => RawKey::End,
        WinKey::Delete => RawKey::Delete,
        WinKey::F(n) => RawKey::F(n),
    }
}
