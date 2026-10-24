#![forbid(unsafe_code)]

use vte::{Parser, Perform};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Threat {

    pub controls: usize,

    pub csi: usize,

    pub osc: usize,

    pub other_escapes: usize,

    pub deceptive_unicode: usize,
}

impl Threat {

    pub fn any(&self) -> bool {
        self.total() > 0
    }

    pub fn total(&self) -> usize {
        self.controls + self.csi + self.osc + self.other_escapes + self.deceptive_unicode
    }

    pub fn deliberate(&self) -> bool {
        self.csi + self.osc + self.other_escapes + self.deceptive_unicode > 0
    }

    pub fn worst(&self) -> Option<&'static str> {
        if self.osc > 0 {
            Some("terminal-osc")
        } else if self.deceptive_unicode > 0 {
            Some("bidi-or-zero-width")
        } else if self.csi > 0 {
            Some("terminal-csi")
        } else if self.other_escapes > 0 {
            Some("escape-sequence")
        } else if self.controls > 0 {
            Some("control-chars")
        } else {
            None
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Sanitized {

    pub text: String,

    pub threats: Threat,
}

impl Sanitized {

    pub fn cell(&self, width: usize) -> String {
        if width == 0 {
            return String::new();
        }
        if display_width(&self.text) <= width {
            return self.text.clone();
        }

        let (kept, _) = truncate_to_width(&self.text, width.saturating_sub(1));
        kept + "…"
    }
}

fn is_deceptive(c: char) -> bool {
    matches!(c,

        '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' | '\u{200E}' | '\u{200F}' | '\u{061C}'

        | '\u{200B}'..='\u{200D}' | '\u{FEFF}'

        | '\u{2028}' | '\u{2029}'

        | '\u{00AD}' | '\u{180E}' | '\u{2060}'..='\u{2064}' | '\u{206A}'..='\u{206F}'
        | '\u{FFF9}'..='\u{FFFB}'

        | '\u{E0000}'..='\u{E007F}'

        | '\u{115F}' | '\u{1160}' | '\u{3164}' | '\u{FFA0}'
    )
}

fn placeholder(out: &mut String, c: char) {
    out.push_str(&format!("<U+{:04X}>", c as u32));
}

const SEQUENCE_MARKER: &str = "<ESC>";

pub const MAX_RUN: usize = 32;

pub const MAX_CHARS: usize = 16_384;

pub fn display_width(s: &str) -> usize {
    unicode_width::UnicodeWidthStr::width(s)
}

pub fn truncate_to_width(s: &str, cols: usize) -> (String, bool) {
    if display_width(s) <= cols {
        return (s.to_string(), false);
    }
    let mut out = String::new();
    let mut used = 0usize;
    for c in s.chars() {
        let w = unicode_width::UnicodeWidthChar::width(c).unwrap_or(0);
        if used + w > cols {
            return (out, true);
        }
        used += w;
        out.push(c);
    }
    (out, false)
}

#[derive(Default)]
struct Collector {
    out: String,
    threats: Threat,

    unmarked: bool,
}

impl Collector {

    fn settle(&mut self) {
        if std::mem::take(&mut self.unmarked) {
            self.threats.other_escapes += 1;
            self.out.push_str(SEQUENCE_MARKER);
        }
    }
}

impl Perform for Collector {

    fn print(&mut self, c: char) {

        self.settle();
        if is_deceptive(c) {
            self.threats.deceptive_unicode += 1;
            placeholder(&mut self.out, c);
        } else if c.is_control() {
            self.threats.controls += 1;
            placeholder(&mut self.out, c);
        } else {
            self.out.push(c);
        }
    }

    fn execute(&mut self, byte: u8) {

        if matches!(byte, 0x18 | 0x1a) {
            self.settle();
        }
        match byte {
            b'\t' => self.out.push(' '),
            b'\n' => {
                self.threats.controls += 1;
                self.out.push(' ');
            }
            _ => {
                self.threats.controls += 1;
                placeholder(&mut self.out, char::from(byte));
            }
        }
    }

    fn csi_dispatch(&mut self, _: &vte::Params, _: &[u8], _: bool, _: char) {
        self.unmarked = false;
        self.threats.csi += 1;
        self.out.push_str(SEQUENCE_MARKER);
    }

    fn osc_dispatch(&mut self, _: &[&[u8]], _: bool) {
        self.unmarked = false;
        self.threats.osc += 1;
        self.out.push_str(SEQUENCE_MARKER);
    }

    fn esc_dispatch(&mut self, _: &[u8], _: bool, _: u8) {
        self.unmarked = false;
        self.threats.other_escapes += 1;
        self.out.push_str(SEQUENCE_MARKER);
    }

    fn hook(&mut self, _: &vte::Params, _: &[u8], _: bool, _: char) {
        self.unmarked = false;
        self.threats.other_escapes += 1;
        self.out.push_str(SEQUENCE_MARKER);
    }
}

pub fn sanitize(raw: &str) -> Sanitized {
    let mut parser = Parser::new();
    let mut collector = Collector::default();

    for &byte in raw.as_bytes() {
        parser.advance(&mut collector, byte);
        if byte == 0x1b {

            collector.settle();
            collector.unmarked = true;
        }
    }

    collector.settle();
    Sanitized { text: capped(&collapse_runs(&collector.out)), threats: collector.threats }
}

fn collapse_runs(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        let mut n = 1usize;
        while chars.peek() == Some(&c) {
            chars.next();
            n += 1;
        }
        if n > MAX_RUN {
            out.push_str(&format!("[{c} x {n}]"));
        } else {
            out.extend(std::iter::repeat_n(c, n));
        }
    }
    out
}

fn capped(s: &str) -> String {
    let total = s.chars().count();
    if total <= MAX_CHARS {
        return s.to_string();
    }
    let mut out: String = s.chars().take(MAX_CHARS).collect();
    out.push_str(&format!("...(+{} chars)", total - MAX_CHARS));
    out
}
