use std::io::{self, Write as _};
use std::sync::{mpsc, Mutex};
use std::time::{Duration, Instant};

use crossterm::event::{
    self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind, MouseButton, MouseEventKind,
};
use crossterm::{cursor, execute, terminal};
use ratatui_core::buffer::Buffer;
use ratatui_core::layout::Rect;
use ratatui_core::style::{Color, Modifier};

use crate::app::{ConsoleApp, ConsoleEffect, PostureApp, PostureEffect, QueueApp, QueueEffect};
use crate::chrome::Hits;
use crate::console::FindingRow;
use crate::input::{Input, Key};
use crate::posture::PostureModel;
use crate::surface::{Surface, SurfaceEvent};
use crate::verbs::{Driver, Verbs, VerbsPane};

struct TerminalSurface;

impl TerminalSurface {
    fn enter() -> io::Result<Self> {
        install_panic_hook();
        terminal::enable_raw_mode()?;
        execute!(io::stdout(), terminal::EnterAlternateScreen, cursor::Hide)?;

        if mouse_enabled() {
            execute!(io::stdout(), EnableMouseCapture)?;
        }
        Ok(TerminalSurface)
    }
}

fn mouse_enabled() -> bool {
    std::env::var_os("HEMOSTAT_MOUSE").is_some()
}

fn restore() {
    if mouse_enabled() {
        let _ = execute!(io::stdout(), DisableMouseCapture);
    }
    let _ = execute!(io::stdout(), cursor::Show, terminal::LeaveAlternateScreen);
    let _ = terminal::disable_raw_mode();
}

impl Drop for TerminalSurface {
    fn drop(&mut self) {
        restore();
    }
}

fn install_panic_hook() {
    let prior = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        restore();
        prior(info);
    }));
}

impl Surface for TerminalSurface {
    fn area(&mut self) -> io::Result<Rect> {
        screen_area()
    }

    fn next(&mut self, idle: bool) -> io::Result<Option<SurfaceEvent>> {
        next(idle)
    }

    fn present(&mut self, buf: &Buffer, _hits: &Hits) -> io::Result<()> {
        present(buf, buf.area.width, buf.area.height)
    }
}

pub enum Tick {

    Reprobe,

    Quit,
}

fn translate(ev: Event) -> Option<SurfaceEvent> {
    match ev {
        Event::Key(k) if k.kind == KeyEventKind::Press => {
            let key = match k.code {
                KeyCode::Char(c) => Key::Char(c),
                KeyCode::Enter => Key::Enter,
                KeyCode::Esc => Key::Esc,
                KeyCode::Backspace => Key::Backspace,
                KeyCode::Up => Key::Up,
                KeyCode::Down => Key::Down,
                KeyCode::PageUp => Key::PageUp,
                KeyCode::PageDown => Key::PageDown,
                KeyCode::Home => Key::Home,
                KeyCode::End => Key::End,
                KeyCode::Tab => Key::Tab,
                KeyCode::BackTab => Key::BackTab,
                KeyCode::F(n) => Key::F(n),
                _ => return None,
            };
            Some(SurfaceEvent::In(Input::Key(key)))
        }
        Event::Mouse(m) => match m.kind {
            MouseEventKind::Down(MouseButton::Left) => Some(SurfaceEvent::In(Input::Click { x: m.column, y: m.row })),
            MouseEventKind::ScrollUp => Some(SurfaceEvent::In(Input::Wheel { up: true })),
            MouseEventKind::ScrollDown => Some(SurfaceEvent::In(Input::Wheel { up: false })),
            _ => None,
        },
        Event::Resize(_, _) => Some(SurfaceEvent::Resize),
        _ => None,
    }
}

fn next(idle: bool) -> io::Result<Option<SurfaceEvent>> {
    loop {
        if !event::poll(Duration::from_millis(250))? {
            if idle {
                return Ok(None);
            }
            continue;
        }
        if let Some(e) = translate(event::read()?) {
            return Ok(Some(e));
        }
    }
}

fn screen_area() -> io::Result<Rect> {
    let (w, h) = terminal::size()?;
    Ok(Rect::new(0, 0, w, h))
}

fn draw<S: Surface>(surface: &mut S, render: impl FnOnce(Rect, &mut Buffer) -> Hits) -> io::Result<()> {
    let area = surface.area()?;
    let mut buf = Buffer::empty(area);
    let hits = render(area, &mut buf);
    surface.present(&buf, &hits)
}

fn release_for_sweep<S: Surface>(surface: &mut S, verbs: &VerbsPane) {
    if !verbs.busy() {
        surface.release();
    }
}

pub fn run<F>(initial: PostureModel, refresh: F, verbs: Verbs) -> io::Result<()>
where
    F: FnMut() -> PostureModel,
{
    run_on(TerminalSurface::enter()?, initial, refresh, verbs)
}

pub fn run_on<S: Surface, F>(mut surface: S, initial: PostureModel, mut refresh: F, verbs: Verbs) -> io::Result<()>
where
    F: FnMut() -> PostureModel,
{
    let Verbs { items, host } = verbs;
    let mut driver = Driver::new(host);
    let mut app = PostureApp::new(initial).with_verbs(items);
    app.verbs.set_inherited_ticket(driver.inherited_ticket());
    let mut redraw = true;
    loop {
        if redraw {
            draw(&mut surface, |area, buf| app.render(area, buf))?;
        }
        redraw = true;
        let input = match surface.next(app.verbs.busy())? {
            None => {
                redraw = driver.service(&mut app.verbs, Instant::now());
                continue;
            }
            Some(SurfaceEvent::Resize) => continue,
            Some(SurfaceEvent::Close) => {
                if app.verbs.quit_ok() {
                    driver.leave();
                    return Ok(());
                }
                continue;
            }
            Some(SurfaceEvent::In(i)) => i,
        };
        let now = Instant::now();
        match app.handle_at(input, now, surface.area()?) {
            PostureEffect::Quit => {
                driver.leave();
                return Ok(());
            }
            PostureEffect::Reprobe => {
                release_for_sweep(&mut surface, &app.verbs);
                app.model = refresh();
            }
            PostureEffect::None => {}
        }
        driver.service(&mut app.verbs, now);
    }
}

pub fn run_queue<H>(initial: crate::queue::QueueModel, handle: H, verbs: Verbs) -> io::Result<()>
where
    H: FnMut(&crate::queue::QCommand) -> Result<(crate::queue::QueueModel, String), String>,
{
    run_queue_on(TerminalSurface::enter()?, initial, handle, verbs)
}

pub fn run_queue_on<S: Surface, H>(
    mut surface: S,
    initial: crate::queue::QueueModel,
    mut handle: H,
    verbs: Verbs,
) -> io::Result<()>
where
    H: FnMut(&crate::queue::QCommand) -> Result<(crate::queue::QueueModel, String), String>,
{
    let Verbs { items, host } = verbs;
    let mut driver = Driver::new(host);
    let mut app = QueueApp::new(initial).with_verbs(items);
    app.verbs.set_inherited_ticket(driver.inherited_ticket());
    let mut redraw = true;
    loop {
        if redraw {
            draw(&mut surface, |area, buf| app.render(area, buf))?;
        }
        redraw = true;
        let input = match surface.next(app.verbs.busy())? {
            None => {
                redraw = driver.service(&mut app.verbs, Instant::now());
                continue;
            }
            Some(SurfaceEvent::Resize) => continue,
            Some(SurfaceEvent::Close) => {
                if app.verbs.quit_ok() {
                    driver.leave();
                    return Ok(());
                }
                continue;
            }
            Some(SurfaceEvent::In(i)) => i,
        };
        let now = Instant::now();
        let effect = app.handle_at(input, now, surface.area()?);
        driver.service(&mut app.verbs, now);
        let cmd = match effect {
            QueueEffect::Quit => {
                driver.leave();
                return Ok(());
            }
            QueueEffect::None => continue,
            QueueEffect::Command(c) => c,
        };
        match handle(&cmd) {
            Ok((mut next, said)) => {
                next.carry_from(&app.model);
                next.status = Some(said);
                app.model = next;
            }
            Err(why) => app.model.status = Some(format!("refused: {why}")),
        }
    }
}

fn present(buf: &Buffer, w: u16, h: u16) -> io::Result<()> {
    let mut out = String::with_capacity((w as usize + 8) * h as usize);
    let mut style_open = false;
    for y in 0..h {
        out.push_str(&format!("\x1b[{};1H", y + 1));
        for x in 0..w {
            let Some(cell) = buf.cell((x, y)) else { continue };

            let s = cell.style();
            let sgr = sgr_for(s.fg.unwrap_or(Color::Reset), s.add_modifier);
            if !sgr.is_empty() {
                out.push_str(&sgr);
                style_open = true;
            } else if style_open {
                out.push_str("\x1b[0m");
                style_open = false;
            }
            out.push_str(cell.symbol());
        }
        out.push_str("\x1b[0m");
        style_open = false;
        out.push_str("\x1b[K");
    }

    let mut stdout = io::stdout().lock();
    stdout.write_all(out.as_bytes())?;
    stdout.flush()
}

fn sgr_for(fg: Color, m: Modifier) -> String {
    let mut codes = Vec::new();
    if m.contains(Modifier::BOLD) {
        codes.push("1".to_string());
    }
    match fg {
        Color::Red => codes.push("31".into()),
        Color::Green => codes.push("32".into()),
        Color::Yellow => codes.push("33".into()),
        Color::Cyan => codes.push("36".into()),
        Color::DarkGray => codes.push("90".into()),
        _ => {}
    }
    if codes.is_empty() { String::new() } else { format!("\x1b[{}m", codes.join(";")) }
}

pub fn run_console<F, A>(initial: crate::console::ConsoleModel, refresh: F, apply: A, verbs: Verbs) -> io::Result<()>
where
    F: FnMut() -> crate::console::ConsoleModel + Send,
    A: FnMut(&str) -> Result<String, String> + Send,
{
    run_console_on(TerminalSurface::enter()?, initial, refresh, apply, verbs)
}

pub fn run_console_on<S: Surface, F, A>(
    surface: S,
    initial: crate::console::ConsoleModel,
    refresh: F,
    apply: A,
    verbs: Verbs,
) -> io::Result<()>
where
    F: FnMut() -> crate::console::ConsoleModel + Send,
    A: FnMut(&str) -> Result<String, String> + Send,
{
    run_loop(surface, initial, refresh, apply, None::<fn(&mut crate::console::ConsoleModel) -> bool>, None, None::<fn() -> crate::console::ConsoleModel>, verbs)
}

pub fn run_console_live<F, A, T>(
    initial: crate::console::ConsoleModel,
    refresh: F,
    apply: A,
    tick: T,
    verbs: Verbs,
) -> io::Result<()>
where
    F: FnMut() -> crate::console::ConsoleModel + Send,
    A: FnMut(&str) -> Result<String, String> + Send,
    T: FnMut(&mut crate::console::ConsoleModel) -> bool,
{
    run_console_live_on(TerminalSurface::enter()?, initial, refresh, apply, tick, verbs)
}

pub fn run_console_live_on<S: Surface, F, A, T>(
    surface: S,
    initial: crate::console::ConsoleModel,
    refresh: F,
    apply: A,
    tick: T,
    verbs: Verbs,
) -> io::Result<()>
where
    F: FnMut() -> crate::console::ConsoleModel + Send,
    A: FnMut(&str) -> Result<String, String> + Send,
    T: FnMut(&mut crate::console::ConsoleModel) -> bool,
{
    run_loop(surface, initial, refresh, apply, Some(tick), None, None::<fn() -> crate::console::ConsoleModel>, verbs)
}

pub fn run_console_every<F, P, A>(
    initial: crate::console::ConsoleModel,
    refresh: F,
    periodic: P,
    apply: A,
    every: std::time::Duration,
    verbs: Verbs,
) -> io::Result<()>
where
    F: FnMut() -> crate::console::ConsoleModel + Send,
    P: FnMut() -> crate::console::ConsoleModel,
    A: FnMut(&str) -> Result<String, String> + Send,
{
    run_console_every_on(TerminalSurface::enter()?, initial, refresh, periodic, apply, every, verbs)
}

pub fn run_console_every_on<S: Surface, F, P, A>(
    surface: S,
    initial: crate::console::ConsoleModel,
    refresh: F,
    periodic: P,
    apply: A,
    every: std::time::Duration,
    verbs: Verbs,
) -> io::Result<()>
where
    F: FnMut() -> crate::console::ConsoleModel + Send,
    P: FnMut() -> crate::console::ConsoleModel,
    A: FnMut(&str) -> Result<String, String> + Send,
{
    run_loop(surface, initial, refresh, apply, None::<fn(&mut crate::console::ConsoleModel) -> bool>, Some(every), Some(periodic), verbs)
}

enum JobNews {

    Applied(Result<String, String>),

    Swept(crate::console::ConsoleModel),
}

struct Pending {
    target: Option<crate::console::Identity>,
    deferred: Option<&'static str>,
    outcome: Option<Result<String, String>>,
}

struct Job<'scope> {
    news: mpsc::Receiver<JobNews>,
    handle: std::thread::ScopedJoinHandle<'scope, ()>,
    started: Instant,

    fix: Option<Pending>,

    keep: usize,

    shown: u64,
}

const SWEEPING: &str = "re-scanning this host to confirm; this takes as long as start-up did";

const APPLYING: &str = "applying the fix";

const BUSY: &str = "a fix or re-scan is still running; wait for it to finish";

fn job_footer(job: &Job<'_>, secs: u64) -> String {
    let keys = "you can move around meanwhile";
    match &job.fix {
        None => format!("{SWEEPING} ({secs} s; {keys})"),
        Some(Pending { outcome: None, .. }) => format!("{APPLYING}… ({secs} s)"),
        Some(Pending { outcome: Some(Ok(done)), .. }) => format!("written: {done} — {SWEEPING} ({secs} s; {keys})"),
        Some(Pending { outcome: Some(Err(why)), .. }) => {
            format!("NOT applied — nothing was changed: {why} — {SWEEPING} ({secs} s; {keys})")
        }
    }
}

fn verdict(
    outcome: Result<String, String>,
    target: Option<crate::console::Identity>,
    deferred: Option<&'static str>,
    model: &crate::console::ConsoleModel,
) -> String {
    match (outcome, target) {
        (Err(why), _) => format!("NOT applied — nothing was changed: {why}"),

        (Ok(done), Some(_)) if deferred.is_some() => {
            format!("configured, but NOT YET IN EFFECT: {done}. {}", deferred.unwrap_or_default())
        }

        (Ok(done), Some(t)) if model.still_present(&t) => format!(
            "applied, but the finding is STILL PRESENT after a re-scan: \
             {done}. The change was made and the problem is still here — \
             something is putting it back, or it was never the whole \
             cause. Do NOT treat this as fixed"
        ),

        (Ok(done), Some(t)) if !model.source_ran(&t.source) => format!(
            "applied: {done} — but this CANNOT be confirmed: the `{}` sweep \
             did not run on the re-scan, so the finding is absent because \
             nobody looked, not because it is gone. Re-run once that sweep \
             can run",
            t.source
        ),
        (Ok(done), Some(_)) => format!("applied, and confirmed gone by a re-scan: {done}"),

        (Ok(done), None) => format!(
            "applied: {done} — could not confirm by re-scan, so this is \
             the write succeeding and not the problem being gone"
        ),
    }
}

fn work<W>(m: &Mutex<W>) -> std::sync::MutexGuard<'_, W> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[allow(clippy::too_many_arguments)]
fn run_loop<S, F, A, T, P>(
    mut surface: S,
    initial: crate::console::ConsoleModel,
    refresh: F,
    apply: A,
    mut tick: Option<T>,
    every: Option<std::time::Duration>,
    mut periodic: Option<P>,
    verbs: Verbs,
) -> io::Result<()>
where
    S: Surface,
    F: FnMut() -> crate::console::ConsoleModel + Send,
    A: FnMut(&str) -> Result<String, String> + Send,
    T: FnMut(&mut crate::console::ConsoleModel) -> bool,
    P: FnMut() -> crate::console::ConsoleModel,
{
    let tools = Mutex::new((refresh, apply));
    std::thread::scope(|scope| -> io::Result<()> {
        let Verbs { items, host } = verbs;
        let mut driver = Driver::new(host);
        let mut app = ConsoleApp::new(initial).with_verbs(items);
        app.verbs.set_inherited_ticket(driver.inherited_ticket());

        let mut job: Option<Job<'_>> = None;
        let mut redraw = true;
        let mut last_sweep = Instant::now();
        loop {
            if redraw {
                draw(&mut surface, |area, buf| app.render(area, buf))?;
            }
            redraw = true;

            if let Some(j) = job.as_mut() {
                let mut finished = None;
                for news in j.news.try_iter() {
                    match news {
                        JobNews::Applied(outcome) => {
                            if let Some(p) = j.fix.as_mut() {
                                p.outcome = Some(outcome);
                            }
                        }
                        JobNews::Swept(model) => finished = Some(model),
                    }
                }
                if let Some(mut model) = finished {
                    model.selected = j.keep.min(model.findings.len().saturating_sub(1));
                    if let Some(p) = j.fix.take() {
                        let outcome = p.outcome.unwrap_or_else(|| Err("the fix reported nothing".into()));
                        model.last_result = Some(verdict(outcome, p.target, p.deferred, &model));
                    }
                    app.model = model;
                    app.confirm_opened = None;
                    if let Some(done) = job.take() {
                        let _ = done.handle.join();
                    }
                    continue;
                }
                let secs = j.started.elapsed().as_secs();
                if secs != j.shown || app.model.last_result.is_none() {
                    j.shown = secs;
                    app.model.last_result = Some(job_footer(j, secs));
                    continue;
                }
            }

            let idle = tick.is_some() || every.is_some() || app.verbs.busy() || job.is_some();
            let input = match surface.next(idle)? {
                None => {
                    let now = Instant::now();
                    let ran = driver.service(&mut app.verbs, now);

                    let asking = app.model.confirming || app.verbs.confirming();
                    let ticked = !asking && tick.as_mut().is_some_and(|t| t(&mut app.model));

                    let swept = !asking
                        && job.is_none()
                        && every.is_some_and(|iv| now.duration_since(last_sweep) >= iv)
                        && periodic.as_mut().is_some_and(|p| {
                            let keep = app.model.selected;
                            release_for_sweep(&mut surface, &app.verbs);
                            app.model = p();
                            app.model.selected = keep.min(app.model.findings.len().saturating_sub(1));
                            last_sweep = now;
                            true
                        });
                    redraw = ran || ticked || swept;
                    continue;
                }
                Some(SurfaceEvent::Resize) => continue,
                Some(SurfaceEvent::Close) => {

                    if app.verbs.quit_ok() {
                        finish(&mut surface, &mut app, job.take())?;
                        driver.leave();
                        return Ok(());
                    }
                    continue;
                }
                Some(SurfaceEvent::In(i)) => i,
            };
            let now = Instant::now();
            let effect = app.handle(input, now, surface.area()?);
            driver.service(&mut app.verbs, now);
            match effect {
                ConsoleEffect::None => {}
                ConsoleEffect::Quit => {
                    finish(&mut surface, &mut app, job.take())?;
                    driver.leave();
                    return Ok(());
                }
                ConsoleEffect::Rescan | ConsoleEffect::Confirm(true) if job.is_some() => {
                    app.model.confirming = false;
                    app.confirm_opened = None;
                    app.model.last_result = Some(BUSY.into());
                }
                ConsoleEffect::Rescan => {
                    let (tx, rx) = mpsc::channel();
                    let tools = &tools;
                    let handle = scope.spawn(move || {
                        let model = (work(tools).0)();
                        let _ = tx.send(JobNews::Swept(model));
                    });
                    job = Some(Job { news: rx, handle, started: Instant::now(), fix: None, keep: app.model.selected, shown: 0 });
                    app.model.last_result = None;
                }
                ConsoleEffect::Confirm(yes) => {
                    let model = &mut app.model;
                    app.confirm_opened = None;
                    model.confirming = false;
                    if !yes {
                        model.last_result = Some("cancelled; nothing was changed".into());
                        continue;
                    }
                    let selected = model.findings.get(model.selected);
                    let Some(id) = selected.and_then(|f| f.remedy.as_ref()).map(|r| r.id.clone()) else {
                        continue;
                    };

                    let fix = Pending {
                        target: selected.map(FindingRow::identity),
                        deferred: selected.and_then(|f| f.remedy.as_ref()).and_then(|r| r.risk.deferred()),
                        outcome: None,
                    };
                    let (tx, rx) = mpsc::channel();
                    let tools = &tools;
                    let handle = scope.spawn(move || {

                        let mut tools = work(tools);
                        let outcome = (tools.1)(&id);
                        let _ = tx.send(JobNews::Applied(outcome));
                        let model = (tools.0)();
                        let _ = tx.send(JobNews::Swept(model));
                    });
                    job = Some(Job { news: rx, handle, started: Instant::now(), fix: Some(fix), keep: model.selected, shown: 0 });
                    model.last_result = None;
                }
            }
        }
    })
}

fn finish<S: Surface>(surface: &mut S, app: &mut ConsoleApp, job: Option<Job<'_>>) -> io::Result<()> {
    let Some(job) = job else { return Ok(()) };
    app.model.last_result = Some("leaving once the running fix or re-scan finishes…".into());
    draw(surface, |area, buf| app.render(area, buf))?;
    let _ = job.handle.join();
    Ok(())
}
