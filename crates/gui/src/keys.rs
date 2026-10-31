use crate::backend::{Mods, RawKey};

const ESC: u8 = 0x1b;

const MAX_SEQ: usize = 32;

#[derive(Debug, Default)]
pub struct TtyKeys {
    pending: Vec<u8>,
}

#[derive(Debug, PartialEq, Eq)]
enum Step {

    Empty,

    Key(usize, RawKey, Mods),

    Skip(usize),

    Wait,
}

impl TtyKeys {

    pub fn new() -> Self {
        Self::default()
    }

    pub fn feed(&mut self, bytes: &[u8]) -> Vec<(RawKey, Mods)> {
        self.pending.extend_from_slice(bytes);
        let mut out = Vec::new();
        let mut at = 0;
        loop {
            match parse(self.pending.get(at..).unwrap_or_default()) {
                Step::Key(n, key, mods) => {
                    out.push((key, mods));
                    at += n;
                }
                Step::Skip(n) => at += n,
                Step::Wait | Step::Empty => break,
            }
        }
        self.pending.drain(..at.min(self.pending.len()));
        out
    }

    pub fn pending_escape(&self) -> bool {
        self.pending.first() == Some(&ESC)
    }

    pub fn flush_escape(&mut self) -> Vec<(RawKey, Mods)> {
        if !self.pending_escape() {
            return Vec::new();
        }
        let lone = self.pending.len() == 1;
        self.pending.clear();
        if lone { vec![(RawKey::Esc, Mods::default())] } else { Vec::new() }
    }
}

fn parse(b: &[u8]) -> Step {
    match b.first() {
        None => Step::Empty,
        Some(&ESC) => escape(b),
        Some(_) => plain(b),
    }
}

fn plain(b: &[u8]) -> Step {
    let none = Mods::default();
    match b.first() {
        None => Step::Empty,
        Some(b'\r' | b'\n') => Step::Key(1, RawKey::Enter, none),
        Some(0x7f | 0x08) => Step::Key(1, RawKey::Backspace, none),
        Some(b'\t') => Step::Key(1, RawKey::Tab, none),

        Some(&c @ 0x01..=0x1a) => Step::Key(1, RawKey::Char(char::from(b'a' + c - 1)), Mods { ctrl: true, ..none }),
        Some(&c @ 0x20..=0x7e) => Step::Key(1, RawKey::Char(char::from(c)), none),
        Some(0x80..=0xff) => utf8(b),

        Some(_) => Step::Skip(1),
    }
}

fn utf8(b: &[u8]) -> Step {
    let len = match b.first() {
        Some(0xc2..=0xdf) => 2,
        Some(0xe0..=0xef) => 3,
        Some(0xf0..=0xf4) => 4,

        _ => return Step::Skip(1),
    };
    let Some(seq) = b.get(..len) else {

        let broken = std::str::from_utf8(b).err().is_some_and(|e| e.error_len().is_some());
        return if broken { Step::Skip(1) } else { Step::Wait };
    };
    match std::str::from_utf8(seq).ok().and_then(|s| s.chars().next()) {
        Some(c) if !c.is_control() => Step::Key(len, RawKey::Char(c), Mods::default()),
        Some(_) => Step::Skip(len),
        None => Step::Skip(1),
    }
}

fn escape(b: &[u8]) -> Step {
    match b.get(1) {
        None => Step::Wait,
        Some(b'[') => csi(b),
        Some(b'O') => ss3(b),

        Some(&ESC) => Step::Key(1, RawKey::Esc, Mods::default()),

        Some(_) => match plain(b.get(1..).unwrap_or_default()) {
            Step::Key(n, key, mods) => Step::Key(n + 1, key, Mods { alt: true, ..mods }),
            Step::Skip(n) => Step::Skip(n + 1),
            Step::Wait | Step::Empty => Step::Wait,
        },
    }
}

fn csi(b: &[u8]) -> Step {
    let body = b.get(2..).unwrap_or_default();
    if body.first() == Some(&b'[') {
        return match body.get(1) {
            None => Step::Wait,
            Some(&c @ b'A'..=b'E') => Step::Key(4, RawKey::F(c - b'A' + 1), Mods::default()),
            Some(_) => Step::Skip(4),
        };
    }
    for (i, &c) in body.iter().enumerate() {
        match c {
            0x20..=0x3f => {}
            0x40..=0x7e => {
                let n = 2 + i + 1;
                let params = body.get(..i).unwrap_or_default();

                if c == b'M' && params.is_empty() {
                    return if b.len() >= n + 3 { Step::Skip(n + 3) } else { Step::Wait };
                }
                return match csi_key(params, c) {
                    Some((key, mods)) => Step::Key(n, key, mods),
                    None => Step::Skip(n),
                };
            }

            _ => return Step::Skip(2 + i),
        }
    }
    if b.len() >= MAX_SEQ { Step::Skip(b.len()) } else { Step::Wait }
}

fn csi_key(params: &[u8], fin: u8) -> Option<(RawKey, Mods)> {
    let params = std::str::from_utf8(params).ok()?;
    let mut fields = params.split(';');
    let first = fields.next().unwrap_or_default();
    let mods = match fields.next() {
        None => Mods::default(),
        Some(m) => modifiers(m)?,
    };
    if fields.next().is_some() {
        return None;
    }
    let key = if fin == b'~' {
        let n: u8 = first.parse().ok()?;
        match n {
            1 | 7 => RawKey::Home,
            3 => RawKey::Delete,
            4 | 8 => RawKey::End,
            5 => RawKey::PageUp,
            6 => RawKey::PageDown,
            11..=15 => RawKey::F(n - 10),
            17..=21 => RawKey::F(n - 11),
            23 | 24 => RawKey::F(n - 12),
            _ => return None,
        }
    } else {

        if !(first.is_empty() || first == "1") {
            return None;
        }
        match fin {
            b'A' => RawKey::Up,
            b'B' => RawKey::Down,
            b'C' => RawKey::Right,
            b'D' => RawKey::Left,
            b'H' => RawKey::Home,
            b'F' => RawKey::End,
            b'P' => RawKey::F(1),
            b'Q' => RawKey::F(2),
            b'R' => RawKey::F(3),
            b'S' => RawKey::F(4),
            b'Z' => RawKey::BackTab,
            _ => return None,
        }
    };
    Some((key, mods))
}

fn modifiers(m: &str) -> Option<Mods> {
    let bits = m.parse::<u8>().ok().filter(|v| (1..=16).contains(v))? - 1;
    Some(Mods { shift: bits & 1 != 0, alt: bits & 2 != 0, ctrl: bits & 4 != 0 })
}

fn ss3(b: &[u8]) -> Step {
    let key = match b.get(2) {
        None => return Step::Wait,
        Some(b'A') => RawKey::Up,
        Some(b'B') => RawKey::Down,
        Some(b'C') => RawKey::Right,
        Some(b'D') => RawKey::Left,
        Some(b'H') => RawKey::Home,
        Some(b'F') => RawKey::End,
        Some(b'P') => RawKey::F(1),
        Some(b'Q') => RawKey::F(2),
        Some(b'R') => RawKey::F(3),
        Some(b'S') => RawKey::F(4),
        Some(0x40..=0x7e) => return Step::Skip(3),

        Some(_) => return Step::Skip(2),
    };
    Step::Key(3, key, Mods::default())
}
