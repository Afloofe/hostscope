use ratatui_core::buffer::Buffer;
use ratatui_core::layout::Rect;
use ratatui_core::style::{Color, Modifier, Style};

use crate::draw::{frame, pad, put};
use crate::sanitize;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sev {

    Critical,

    Warn,

    Note,
}

impl Sev {
    fn rank(self) -> u8 {
        match self {
            Sev::Critical => 0,
            Sev::Warn => 1,
            Sev::Note => 2,
        }
    }

    pub(crate) fn tag(self) -> &'static str {
        match self {
            Sev::Critical => "CRITICAL",
            Sev::Warn => "WARN",
            Sev::Note => "note",
        }
    }

    pub(crate) fn style(self) -> Style {
        match self {
            Sev::Critical => Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            Sev::Warn => Style::default().fg(Color::Yellow),
            Sev::Note => Style::default().fg(Color::DarkGray),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Risk {

    Safe,

    NeedsReboot,

    NeedsReload,

    MayBreak,
}

impl Risk {

    pub fn deferred(self) -> Option<&'static str> {
        match self {
            Risk::NeedsReboot => Some(
                "It does not take hold until this host reboots, and the re-scan can only see \
                 the setting, not whether it is in force. Re-check after the reboot",
            ),
            Risk::NeedsReload => Some(
                "It is written and was verified against the service's own resolved config, but \
                 the RUNNING service is still using the old value. HEMOSTAT will not restart it \
                 for you — on a host you are connected through, that is the step that loses \
                 machines. Restart it yourself when you are ready, with a second way in open",
            ),
            Risk::Safe | Risk::MayBreak => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {

    pub source: String,

    pub subject: String,
}

impl FindingRow {

    pub fn identity(&self) -> Identity {
        Identity { source: self.source.clone(), subject: self.subject.clone() }
    }
}

impl ConsoleModel {

    pub fn still_present(&self, id: &Identity) -> bool {
        self.findings.iter().any(|f| &f.identity() == id)
    }
}

impl Risk {

    pub fn token(self) -> &'static str {
        match self {
            Risk::Safe => "safe",
            Risk::NeedsReboot => "needs reboot",
            Risk::NeedsReload => "staged; needs a service restart",
            Risk::MayBreak => "may break something",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Remedy {

    pub what: String,

    pub risk: Risk,

    pub note: String,

    pub undo: String,

    pub id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindingRow {

    pub severity: Sev,

    pub source: String,

    pub subject: String,

    pub what: String,

    pub why: String,

    pub remedy: Option<Remedy>,

    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gap {

    pub source: String,

    pub reason: String,

    pub partial: bool,
}

impl Gap {

    pub fn did_not_run(source: impl Into<String>, reason: impl Into<String>) -> Self {
        Gap { source: source.into(), reason: reason.into(), partial: false }
    }

    pub fn partial(source: impl Into<String>, reason: impl Into<String>) -> Self {
        Gap { source: source.into(), reason: reason.into(), partial: true }
    }
}

#[derive(Debug, Clone, Default)]
pub struct ConsoleModel {

    pub host: String,

    pub when: String,

    pub findings: Vec<FindingRow>,

    pub selected: usize,

    pub confirming: bool,

    pub last_result: Option<String>,

    pub inspecting: bool,

    pub gaps: Vec<Gap>,
}

impl ConsoleModel {

    pub fn new(host: String, when: String, mut findings: Vec<FindingRow>) -> Self {
        findings.sort_by_key(|f| f.severity.rank());
        ConsoleModel {
            host,
            when,
            findings,
            selected: 0,
            confirming: false,
            last_result: None,
            inspecting: false,
            gaps: Vec::new(),
        }
    }

    pub fn with_gaps(mut self, gaps: Vec<Gap>) -> Self {
        self.gaps = gaps;
        self
    }

    pub fn source_ran(&self, source: &str) -> bool {
        !self.gaps.iter().any(|g| g.source == source)
    }

    pub fn up(&mut self) {
        self.selected = self.selected.saturating_sub(1);
    }

    pub fn down(&mut self) {
        if self.selected + 1 < self.findings.len() {
            self.selected += 1;
        }
    }

    pub fn offer_fix(&mut self) {
        self.last_result = None;
        if self.findings.get(self.selected).is_some_and(|f| f.remedy.is_some()) {
            self.confirming = true;
            self.inspecting = false;
        }
    }

    pub fn add_rows(&mut self, rows: Vec<FindingRow>) {
        if rows.is_empty() {
            return;
        }
        if let Some(rank) = self.findings.get(self.selected).map(|f| f.severity.rank()) {
            self.selected += rows.iter().filter(|r| r.severity.rank() < rank).count();
        }
        self.findings.extend(rows);
        self.findings.sort_by_key(|f| f.severity.rank());
    }

    pub fn set_gap(&mut self, source: &str, gap: Option<Gap>) -> bool {
        let before = self.gaps.clone();
        self.gaps.retain(|g| g.source != source);
        if let Some(g) = gap {
            self.gaps.push(g);
        }
        self.gaps != before
    }

    fn count(&self, s: Sev) -> usize {
        self.findings.iter().filter(|f| f.severity == s).count()
    }
}

struct Bands {
    header: Rect,
    list: Rect,
    detail: Rect,
    footer_y: u16,
}

fn bands(area: Rect) -> Bands {
    const HEAD_H: u16 = 3;
    const FOOT_H: u16 = 1;

    const MIN_LIST_H: u16 = 3;

    let detail_h = 8u16.min(area.height.saturating_sub(HEAD_H + FOOT_H + MIN_LIST_H));
    let list_h = area.height.saturating_sub(HEAD_H + detail_h + FOOT_H);
    Bands {
        header: Rect::new(area.x, area.y, area.width, HEAD_H),
        list: Rect::new(area.x, area.y + HEAD_H, area.width, list_h),
        detail: Rect::new(area.x, area.y + HEAD_H + list_h, area.width, detail_h),
        footer_y: area.y + HEAD_H + list_h + detail_h,
    }
}

pub fn render(model: &ConsoleModel, area: Rect, buf: &mut Buffer) {
    let _ = render_body(model, area, buf, None);
}

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct Body {

    pub(crate) list: Option<(Rect, usize, usize)>,

    pub(crate) evidence: Option<(Rect, usize, usize)>,

    pub(crate) confirm: bool,
}

pub(crate) fn render_body(model: &ConsoleModel, area: Rect, buf: &mut Buffer, live: Option<usize>) -> Body {
    let mut body = Body::default();
    if area.width < 40 || area.height < 12 {
        put(buf, area.x, area.y, "(terminal too small for the findings console)",
            Style::default(), area);
        return body;
    }
    let dim = Style::default().fg(Color::DarkGray);

    if model.confirming {
        render_confirm(model, area, buf, dim, live.is_some());
        body.confirm = true;
        return body;
    }

    if model.inspecting {
        let (total, visible) = render_evidence(model, area, buf, dim, live);
        body.evidence = Some((area, total, visible));
        return body;
    }
    let bold = Style::default().add_modifier(Modifier::BOLD);
    let b = bands(area);

    render_header(model, b.header, buf, area, bold, dim);
    body.list = Some(render_list(model, b.list, buf, area, bold, dim));
    render_detail(model, b.detail, buf, area, bold, dim);
    render_footer(model, b.footer_y, buf, area, dim, live.is_some());
    body
}

fn render_header(
    model: &ConsoleModel, r: Rect, buf: &mut Buffer, area: Rect, bold: Style, dim: Style,
) {
    let crit = model.count(Sev::Critical);
    let warn = model.count(Sev::Warn);
    let note = model.count(Sev::Note);
    let title = format!(" HEMOSTAT findings · {} ", sanitize(&model.host).text);
    frame(buf, r, &title, bold, dim, area);

    let mut cx = r.x + 2;
    let crit_s = format!("{crit} CRITICAL");
    put(buf, cx, r.y + 1, &crit_s,
        if crit > 0 { Sev::Critical.style() } else { dim }, area);
    cx += crit_s.chars().count() as u16 + 3;
    let warn_s = format!("{warn} WARN");
    put(buf, cx, r.y + 1, &warn_s, if warn > 0 { Sev::Warn.style() } else { dim }, area);
    cx += warn_s.chars().count() as u16 + 3;
    put(buf, cx, r.y + 1, &format!("{note} note"), dim, area);

    let when = sanitize(&model.when);
    if !when.text.is_empty() {
        let wx = r.right().saturating_sub(when.text.chars().count() as u16 + 2);
        if wx > cx + 4 {
            put(buf, wx, r.y + 1, &when.text, dim, area);
        }
    }
}

fn list_title(model: &ConsoleModel, width: u16) -> String {
    if model.gaps.is_empty() {
        return format!(" {} FINDING(S) ", model.findings.len());
    }
    let names: Vec<&str> = model.gaps.iter().map(|g| g.source.as_str()).collect();

    let label = if model.gaps.iter().any(|g| g.partial) {
        "NOT FULLY SEARCHED"
    } else {
        "DID NOT RUN"
    };
    let listed = format!(
        " {} FINDING(S) — {label}: {} ",
        model.findings.len(),
        names.join(", ")
    );

    if listed.chars().count() + 4 <= width as usize {
        listed
    } else {
        format!(
            " {} FINDING(S) — {} SWEEP(S) {label} ",
            model.findings.len(),
            model.gaps.len()
        )
    }
}

fn render_list(
    model: &ConsoleModel, r: Rect, buf: &mut Buffer, area: Rect, bold: Style, dim: Style,
) -> (Rect, usize, usize) {
    let rows = r.height.saturating_sub(2) as usize;
    let offset = if rows > 0 && model.selected >= rows {
        model.selected + 1 - rows
    } else {
        0
    };
    let geometry = (r, offset, rows.min(model.findings.len().saturating_sub(offset)));
    frame(buf, r, &list_title(model, r.width), bold, dim, area);

    if model.findings.is_empty() {

        let line = if model.gaps.is_empty() {
            "no findings — every sweep ran, and every one of them was clean".to_string()
        } else {
            format!(
                "no findings — but {} sweep(s) did not run or did not finish, so this host \
                 has not been fully examined. See below.",
                model.gaps.len()
            )
        };
        put(buf, r.x + 2, r.y + 1, &line, dim, area);
        for (i, g) in model.gaps.iter().take(rows.saturating_sub(2)).enumerate() {
            put(
                buf,
                r.x + 2,
                r.y + 3 + i as u16,
                &format!("  {}: {}", sanitize(&g.source).text, sanitize(&g.reason).text),
                dim,
                area,
            );
        }
    }

    let src_w = 12usize;
    for (i, f) in model.findings.iter().enumerate().skip(offset).take(rows) {
        let ry = r.y + 1 + (i - offset) as u16;
        let selected = i == model.selected;
        let marker = if selected { "▸ " } else { "  " };
        let src = sanitize(&f.source);
        let subject = sanitize(&f.subject);
        let avail = (r.width as usize).saturating_sub(4 + 2 + 10 + src_w + 2);
        let line = format!(
            "{marker}[{:8}] {}  {}",
            f.severity.tag(),
            pad(&src.cell(src_w), src_w),
            subject.cell(avail),
        );

        let style = if selected {
            f.severity.style().add_modifier(Modifier::REVERSED)
        } else {
            f.severity.style()
        };
        put(buf, r.x + 1, ry, &pad(&line, r.width as usize - 2), style, area);
    }
    geometry
}

fn render_detail(
    model: &ConsoleModel, r: Rect, buf: &mut Buffer, area: Rect, bold: Style, dim: Style,
) {
    frame(buf, r, " DETAIL ", bold, dim, area);
    let Some(f) = model.findings.get(model.selected) else { return };

    let inner_w = r.width as usize - 4;
    let subject = sanitize(&f.subject);
    put(buf, r.x + 2, r.y + 1,
        &format!("[{}] {} — {}", f.severity.tag(), sanitize(&f.source).text,
            subject.cell(inner_w.saturating_sub(20))),
        f.severity.style(), area);

    let what = sanitize(&f.what);
    let mut ly = r.y + 2;
    for line in wrap(&what.text, inner_w).into_iter().take(2) {
        put(buf, r.x + 2, ly, &line, Style::default(), area);
        ly += 1;
    }

    let why = sanitize(&f.why);

    let reserve = 1 + u16::from(f.remedy.is_some());
    for line in wrap(&format!("why: {}", why.text), inner_w)
        .into_iter()
        .take((r.y + r.height).saturating_sub(ly + 1 + reserve) as usize)
    {
        put(buf, r.x + 2, ly, &line, dim, area);
        ly += 1;
    }

    let Some(rem) = &f.remedy else { return };

    let bottom = r.y + r.height - 2;

    let offer = sanitize(&format!("f  fix [{}]: {}", rem.risk.token(), rem.what));
    put(buf, r.x + 2, bottom, &offer.cell(inner_w), Style::default().fg(Color::Green), area);
}

fn render_confirm(model: &ConsoleModel, area: Rect, buf: &mut Buffer, dim: Style, live: bool) {
    let warn = Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD);
    frame(buf, area, " APPLY? ", warn, dim, area);
    let inner_w = area.width as usize - 4;

    let legend = area.y + area.height - 2;
    let ask = legend - 1;
    let Some((f, rem)) =
        model.findings.get(model.selected).and_then(|f| f.remedy.as_ref().map(|r| (f, r)))
    else {
        put(buf, area.x + 2, area.y + 1, "nothing to apply", dim, area);
        if !live {
            put(buf, area.x + 1, legend, "any key  back", dim, area);
        }
        return;
    };

    let on = format!("[{}] {} — {}", f.severity.tag(), f.source, f.subject);
    let mut lines = vec![(sanitize(&on).cell(inner_w), f.severity.style()), (String::new(), dim)];
    for (text, style) in [
        (format!("[{}]", rem.risk.token()), warn),
        (rem.what.clone(), Style::default().add_modifier(Modifier::BOLD)),
        (String::new(), dim),
        (rem.note.clone(), Style::default()),
        (String::new(), dim),
        (format!("undo: {}", rem.undo), dim),
    ] {
        let wrapped = wrap(&sanitize(&text).text, inner_w);
        if wrapped.is_empty() {
            lines.push((String::new(), style));
        }
        lines.extend(wrapped.into_iter().map(|l| (l, style)));
    }

    let rows = ask.saturating_sub(area.y + 1) as usize;
    let shown = if lines.len() > rows { rows.saturating_sub(1) } else { lines.len() };
    for (i, (line, style)) in lines.iter().take(shown).enumerate() {
        put(buf, area.x + 2, area.y + 1 + i as u16, line, *style, area);
    }
    if shown < lines.len() {
        let cut = format!(
            "… {} more line(s) cut off — make the terminal taller to read them before answering",
            lines.len() - shown
        );
        put(buf, area.x + 2, area.y + 1 + shown as u16, &sanitize(&cut).cell(inner_w), warn, area);
    }
    put(buf, area.x + 2, ask, &sanitize("APPLY? y to apply, any other key to cancel").cell(inner_w),
        warn, area);

    if !live {
        put(buf, area.x + 1, legend, "y  apply    any other key  cancel", dim, area);
    }
}

fn render_footer(model: &ConsoleModel, y: u16, buf: &mut Buffer, area: Rect, dim: Style, live: bool) {
    let foot = match &model.last_result {
        Some(r) => sanitize(r).cell(area.width as usize - 2),
        None if live => String::new(),
        None => "↑/↓ or j/k  move    i  inspect    f  fix    r  re-scan    q  quit".to_string(),
    };
    put(buf, area.x + 1, y, &foot, dim, area);
}

fn render_evidence(
    model: &ConsoleModel, area: Rect, buf: &mut Buffer, dim: Style, live: Option<usize>,
) -> (usize, usize) {
    let bold = Style::default().add_modifier(Modifier::BOLD);
    frame(buf, area, " EVIDENCE ", bold, dim, area);
    let inner_w = area.width as usize - 4;
    let Some(f) = model.findings.get(model.selected) else {
        put(buf, area.x + 2, area.y + 1, "no finding selected", dim, area);
        return (0, 0);
    };

    let mut lines: Vec<(u16, String, Style)> = Vec::new();
    let blank = |lines: &mut Vec<(u16, String, Style)>| lines.push((2, String::new(), Style::default()));
    lines.push((2, format!("[{}] {}", f.severity.tag(), sanitize(&f.source).text), f.severity.style()));
    for line in wrap(&sanitize(&f.subject).text, inner_w) {
        lines.push((2, line, bold));
    }
    blank(&mut lines);
    for line in wrap(&sanitize(&f.what).text, inner_w) {
        lines.push((2, line, Style::default()));
    }
    blank(&mut lines);

    for line in wrap(&format!("why: {}", sanitize(&f.why).text), inner_w) {
        lines.push((2, line, dim));
    }
    if !f.evidence.is_empty() {
        blank(&mut lines);
        lines.push((2, "go and look at:".into(), bold));
        for e in &f.evidence {

            for line in wrap(&sanitize(e).text, inner_w.saturating_sub(2)) {
                lines.push((4, line, Style::default().fg(Color::Cyan)));
            }
        }
    }
    if let Some(rem) = &f.remedy {
        blank(&mut lines);
        lines.push((
            2,
            sanitize(&format!("f  fix [{}]: {}", rem.risk.token(), rem.what)).cell(inner_w),
            Style::default().fg(Color::Green),
        ));
    }

    if !model.gaps.is_empty() {
        blank(&mut lines);
        lines.push((2, "COVERAGE GAPS — these were not searched in full:".into(), bold));
        for g in &model.gaps {
            let how = if g.partial { "ran in part" } else { "did not run" };
            for line in wrap(
                &format!("{} [{how}]: {}", sanitize(&g.source).text, sanitize(&g.reason).text),
                inner_w.saturating_sub(2),
            ) {
                lines.push((4, line, Style::default().fg(Color::Yellow)));
            }
        }
    }

    let visible = usize::from(area.height.saturating_sub(if live.is_some() { 2 } else { 3 }));
    let max = lines.len().saturating_sub(visible);
    let offset = live.unwrap_or(0).min(max);
    let cut = live.is_none() && lines.len() > visible;
    let shown = if cut { visible.saturating_sub(1) } else { visible };
    for (i, (indent, text, style)) in lines.iter().skip(offset).take(shown).enumerate() {
        put(buf, area.x + indent, area.y + 1 + i as u16, text, *style, area);
    }
    if cut {
        let more = format!("… {} more line(s): scroll them in the live view", lines.len() - shown);
        put(buf, area.x + 2, area.y + 1 + shown as u16, &more, Style::default().fg(Color::Yellow), area);
    }
    if live.is_none() {
        put(buf, area.x + 2, area.y + area.height - 2,
            "i or esc  back    f  fix    q  quit", dim, area);
    }
    (lines.len(), visible)
}

pub(crate) fn wrap(s: &str, width: usize) -> Vec<String> {
    if width == 0 {
        return Vec::new();
    }

    fn pieces(word: &str, width: usize) -> Vec<String> {
        let mut out = Vec::new();
        let mut rest = word;
        while !rest.is_empty() {
            let (head, cut) = hemostat_safestr::truncate_to_width(rest, width);
            if head.is_empty() {

                let mut it = rest.chars();
                let c = it.next().unwrap_or(' ');
                out.push(c.to_string());
                rest = it.as_str();
                continue;
            }
            rest = &rest[head.len()..];
            out.push(head);
            if !cut {
                break;
            }
        }
        out
    }
    let cols = hemostat_safestr::display_width;

    let mut lines = Vec::new();
    let mut cur = String::new();
    for word in s.split_whitespace() {
        let wlen = cols(word);
        if !cur.is_empty() && cols(&cur) + 1 + wlen <= width {
            cur.push(' ');
            cur.push_str(word);
            continue;
        }
        if !cur.is_empty() {
            lines.push(std::mem::take(&mut cur));
        }
        if wlen <= width {
            cur = word.to_string();
        } else {

            let mut ps = pieces(word, width);
            cur = ps.pop().unwrap_or_default();
            lines.extend(ps);
        }
    }
    if !cur.is_empty() {
        lines.push(cur);
    }
    lines
}

pub fn to_text(model: &ConsoleModel, width: u16, height: u16) -> String {
    let area = Rect::new(0, 0, width, height);
    let mut buf = Buffer::empty(area);
    render(model, area, &mut buf);
    let mut out = String::new();
    for y in 0..height {
        let mut line = String::new();
        for x in 0..width {
            line.push(buf.cell((x, y)).map_or(' ', |c| c.symbol().chars().next().unwrap_or(' ')));
        }
        out.push_str(line.trim_end());
        out.push('\n');
    }
    out
}
