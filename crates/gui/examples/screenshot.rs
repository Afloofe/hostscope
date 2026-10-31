use std::collections::VecDeque;
use std::io;
use std::time::Duration;

use hemostat_gui::backend::{Backend, RawEvent};
use hemostat_gui::png;
use hemostat_gui::render::Frame;
use hemostat_gui::surface::GuiSurface;
use hemostat_tui::{Action, ConsoleApp, ConsoleModel, FindingRow, Remedy, Risk, Sev, Surface};
use ratatui_core::buffer::Buffer;

struct Shot {
    size: (u32, u32),
    events: VecDeque<RawEvent>,
    frame: Option<Frame>,
}

impl Backend for Shot {
    fn size(&self) -> (u32, u32) {
        self.size
    }

    fn poll(&mut self, _: Duration) -> io::Result<Option<RawEvent>> {
        Ok(self.events.pop_front())
    }

    fn present(&mut self, frame: &Frame) -> io::Result<()> {
        self.frame = Some(frame.clone());
        Ok(())
    }

    fn wants_pointer(&self) -> bool {
        true
    }
}

fn findings() -> ConsoleModel {
    let rows = (0..14)
        .map(|i| FindingRow {
            severity: if i < 3 { Sev::Critical } else if i < 8 { Sev::Warn } else { Sev::Note },
            source: "persistence".into(),
            subject: format!("cron · /etc/cron.d/fixture-{i:02}"),
            what: "a job that runs a shell out of /dev/shm".into(),
            why: "cron jobs do not normally execute from tmpfs".into(),
            remedy: (i % 2 == 0).then(|| Remedy {
                what: format!("move /etc/cron.d/fixture-{i:02} into the vault"),
                risk: Risk::MayBreak,
                note: "FIXTURE: nothing is applied by this binary".into(),
                undo: "hemostat undo <journal>".into(),
                id: format!("fixture:{i}"),
            }),
            evidence: (0..40).map(|k| format!("/etc/cron.d/fixture-{i:02} evidence line {k:02}")).collect(),
        })
        .collect();
    ConsoleModel::new("fixture-host".into(), "fixture".into(), rows)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let usage = "usage: screenshot OUT.png [WIDTHxHEIGHT] [findings | evidence | confirm | docs | notice]";
    let mut args = std::env::args().skip(1);
    let out = args.next().ok_or(usage)?;
    let size = args.next().unwrap_or_else(|| "1280x800".into());
    let (w, h) = size.split_once('x').ok_or(usage)?;
    let size = (w.parse::<u32>()?, h.parse::<u32>()?);

    let view = args.next();

    if view.as_deref() == Some("notice") {
        let mut gui = GuiSurface::new(Shot { size, events: VecDeque::new(), frame: None });
        gui.notice("hemostat: sweeping this host…")?;
        let frame = gui.backend_mut().frame.take().ok_or("nothing was presented")?;
        std::fs::write(&out, png::encode(&frame))?;
        println!("{out}: {}x{} pixels, the start-up notice", frame.width, frame.height);
        return Ok(());
    }
    let mut app = ConsoleApp::new(findings());
    match view.as_deref().unwrap_or("findings") {
        "findings" => {}
        "evidence" => app.model.inspecting = true,
        "confirm" => app.model.offer_fix(),
        "docs" => app.docs_open = true,
        _ => return Err(usage.into()),
    }

    let mut gui = GuiSurface::new(Shot { size, events: VecDeque::new(), frame: None });
    let area = gui.area()?;
    let mut buf = Buffer::empty(area);
    let hits = app.render(area, &mut buf);
    gui.present(&buf, &hits)?;

    let frame = gui.backend_mut().frame.take().ok_or("nothing was presented")?;
    let scale = (frame.width / (u32::from(area.width) * 8)).max(1);
    if let Some(r) = hits.rect_of(Action::Fix).or_else(|| hits.rect_of(Action::Apply)) {
        let x = (u32::from(r.x) * 2 + u32::from(r.width)) * 4 * scale;
        let y = (u32::from(r.y) * 2 + 1) * 8 * scale;
        gui.backend_mut().events.push_back(RawEvent::PointerMove { x: i32::try_from(x)?, y: i32::try_from(y)? });
        gui.next(true)?;
        let mut buf = Buffer::empty(area);
        let hits = app.render(area, &mut buf);
        gui.present(&buf, &hits)?;
    }

    let frame = gui.backend_mut().frame.take().unwrap_or(frame);
    std::fs::write(&out, png::encode(&frame))?;
    println!(
        "{out}: {}x{} pixels, {}x{} cells at scale {scale}",
        frame.width, frame.height, area.width, area.height
    );
    Ok(())
}
