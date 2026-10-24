use std::io::{self, Write as _};
use std::time::{Duration, Instant};

use crossterm::event::{
    self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind, MouseButton, MouseEventKind,
};
use crossterm::{cursor, execute, terminal};
use ratatui_core::buffer::Buffer;
use ratatui_core::layout::Rect;
use ratatui_core::style::{Color, Modifier};

use crate::app::{ConsoleApp, ConsoleEffect, PostureApp, PostureEffect, QueueApp, QueueEffect};
use crate::console::FindingRow;
use crate::input::{Input, Key};
use crate::posture::PostureModel;
use crate::verbs::{Driver, Verbs};

struct Terminal;

impl Terminal {
    fn enter() -> io::Result<Self> {
        install_panic_hook();
        terminal::enable_raw_mode()?;
        execute!(io::stdout(), terminal::EnterAlternateScreen, cursor::Hide, EnableMouseCapture)?;
        Ok(Terminal)
    }
}

fn restore() {
    let _ = execute!(io::stdout(), DisableMouseCapture, cursor::Show, terminal::LeaveAlternateScreen);
    let _ = terminal::disable_raw_mode();
}

impl Drop for Terminal {
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

pub enum Tick {

    Reprobe,

    Quit,
}

enum Ev {
    In(Input),
    Resize,
}

fn translate(ev: Event) -> Option<Ev> {
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
            Some(Ev::In(Input::Key(key)))
        }
        Event::Mouse(m) => match m.kind {
            MouseEventKind::Down(MouseButton::Left) => Some(Ev::In(Input::Click { x: m.column, y: m.row })),
            MouseEventKind::ScrollUp => Some(Ev::In(Input::Wheel { up: true })),
            MouseEventKind::ScrollDown => Some(Ev::In(Input::Wheel { up: false })),
            _ => None,
        },
        Event::Resize(_, _) => Some(Ev::Resize),
        _ => None,
    }
}

fn next(idle: bool) -> io::Result<Option<Ev>> {
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

fn draw_with(render: impl FnOnce(Rect, &mut Buffer)) -> io::Result<()> {
    let area = screen_area()?;
    let mut buf = Buffer::empty(area);
    render(area, &mut buf);
    present(&buf, area.width, area.height)
}

pub fn run<F>(initial: PostureModel, mut refresh: F, verbs: Verbs) -> io::Result<()>
where
    F: FnMut() -> PostureModel,
{
    let _guard = Terminal::enter()?;
    let Verbs { items, host } = verbs;
    let mut driver = Driver::new(host);
    let mut app = PostureApp::new(initial).with_verbs(items);
    app.verbs.set_inherited_ticket(driver.inherited_ticket());
    let mut redraw = true;
    loop {
        if redraw {
            draw_with(|area, buf| {
                let _ = app.render(area, buf);
            })?;
        }
        redraw = true;
        let input = match next(app.verbs.busy())? {
            None => {
                redraw = driver.service(&mut app.verbs, Instant::now());
                continue;
            }
            Some(Ev::Resize) => continue,
            Some(Ev::In(i)) => i,
        };
        let now = Instant::now();
        match app.handle_at(input, now, screen_area()?) {
            PostureEffect::Quit => {
                driver.leave();
                return Ok(());
            }
            PostureEffect::Reprobe => app.model = refresh(),
            PostureEffect::None => {}
        }
        driver.service(&mut app.verbs, now);
    }
}

pub fn run_queue<H>(initial: crate::queue::QueueModel, mut handle: H, verbs: Verbs) -> io::Result<()>
where
    H: FnMut(&crate::queue::QCommand) -> Result<(crate::queue::QueueModel, String), String>,
{
    let _guard = Terminal::enter()?;
    let Verbs { items, host } = verbs;
    let mut driver = Driver::new(host);
    let mut app = QueueApp::new(initial).with_verbs(items);
    app.verbs.set_inherited_ticket(driver.inherited_ticket());
    let mut redraw = true;
    loop {
        if redraw {
            draw_with(|area, buf| {
                let _ = app.render(area, buf);
            })?;
        }
        redraw = true;
        let input = match next(app.verbs.busy())? {
            None => {
                redraw = driver.service(&mut app.verbs, Instant::now());
                continue;
            }
            Some(Ev::Resize) => continue,
            Some(Ev::In(i)) => i,
        };
        let now = Instant::now();
        let effect = app.handle_at(input, now, screen_area()?);
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
    F: FnMut() -> crate::console::ConsoleModel,
    A: FnMut(&str) -> Result<String, String>,
{
    run_loop(initial, refresh, apply, None::<fn(&mut crate::console::ConsoleModel) -> bool>, None, None::<fn() -> crate::console::ConsoleModel>, verbs)
}

pub fn run_console_live<F, A, T>(
    initial: crate::console::ConsoleModel,
    refresh: F,
    apply: A,
    tick: T,
    verbs: Verbs,
) -> io::Result<()>
where
    F: FnMut() -> crate::console::ConsoleModel,
    A: FnMut(&str) -> Result<String, String>,
    T: FnMut(&mut crate::console::ConsoleModel) -> bool,
{
    run_loop(initial, refresh, apply, Some(tick), None, None::<fn() -> crate::console::ConsoleModel>, verbs)
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
    F: FnMut() -> crate::console::ConsoleModel,
    P: FnMut() -> crate::console::ConsoleModel,
    A: FnMut(&str) -> Result<String, String>,
{
    run_loop(initial, refresh, apply, None::<fn(&mut crate::console::ConsoleModel) -> bool>, Some(every), Some(periodic), verbs)
}

fn run_loop<F, A, T, P>(
    initial: crate::console::ConsoleModel,
    mut refresh: F,
    mut apply: A,
    mut tick: Option<T>,
    every: Option<std::time::Duration>,
    mut periodic: Option<P>,
    verbs: Verbs,
) -> io::Result<()>
where
    F: FnMut() -> crate::console::ConsoleModel,
    A: FnMut(&str) -> Result<String, String>,
    T: FnMut(&mut crate::console::ConsoleModel) -> bool,
    P: FnMut() -> crate::console::ConsoleModel,
{
    let _guard = Terminal::enter()?;
    let Verbs { items, host } = verbs;
    let mut driver = Driver::new(host);
    let mut app = ConsoleApp::new(initial).with_verbs(items);
    app.verbs.set_inherited_ticket(driver.inherited_ticket());

    let mut redraw = true;
    let mut last_sweep = Instant::now();
    loop {
        if redraw {
            draw_with(|area, buf| {
                let _ = app.render(area, buf);
            })?;
        }
        redraw = true;
        let input = match next(tick.is_some() || every.is_some() || app.verbs.busy())? {
            None => {
                let now = Instant::now();
                let ran = driver.service(&mut app.verbs, now);

                let asking = app.model.confirming || app.verbs.confirming();
                let ticked = !asking && tick.as_mut().is_some_and(|t| t(&mut app.model));

                let swept = !asking
                    && every.is_some_and(|iv| now.duration_since(last_sweep) >= iv)
                    && periodic.as_mut().is_some_and(|p| {
                        let keep = app.model.selected;
                        app.model = p();
                        app.model.selected = keep.min(app.model.findings.len().saturating_sub(1));
                        last_sweep = now;
                        true
                    });
                redraw = ran || ticked || swept;
                continue;
            }
            Some(Ev::Resize) => continue,
            Some(Ev::In(i)) => i,
        };
        let now = Instant::now();
        let effect = app.handle(input, now, screen_area()?);
        driver.service(&mut app.verbs, now);
        match effect {
            ConsoleEffect::None => {}
            ConsoleEffect::Quit => {
                driver.leave();
                return Ok(());
            }
            ConsoleEffect::Rescan => {
                let keep = app.model.selected;
                app.model = refresh();
                app.model.selected = keep.min(app.model.findings.len().saturating_sub(1));
            }
            ConsoleEffect::Confirm(yes) => {
                let model = &mut app.model;
                app.confirm_opened = None;
                model.confirming = false;
                if yes {
                    let id = model
                        .findings
                        .get(model.selected)
                        .and_then(|f| f.remedy.as_ref())
                        .map(|r| r.id.clone());
                    if let Some(id) = id {

                        let target = model.findings.get(model.selected).map(FindingRow::identity);

                        let deferred = model
                            .findings
                            .get(model.selected)
                            .and_then(|f| f.remedy.as_ref())
                            .and_then(|r| r.risk.deferred());

                        let outcome = apply(&id);
                        let keep = model.selected;
                        *model = refresh();
                        model.selected = keep.min(model.findings.len().saturating_sub(1));

                        model.last_result = Some(match (outcome, target) {
                            (Err(why), _) => format!("NOT applied — nothing was changed: {why}"),

                            (Ok(done), Some(_)) if deferred.is_some() => format!(
                                "configured, but NOT YET IN EFFECT: {done}. {}",
                                deferred.unwrap_or_default()
                            ),

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
                            (Ok(done), Some(_)) => {
                                format!("applied, and confirmed gone by a re-scan: {done}")
                            }

                            (Ok(done), None) => format!(
                                "applied: {done} — could not confirm by re-scan, so this is \
                                 the write succeeding and not the problem being gone"
                            ),
                        });
                    }
                } else {
                    model.last_result = Some("cancelled; nothing was changed".into());
                }
            }
        }
    }
}
