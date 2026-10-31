use std::sync::OnceLock;

pub const CELL_W: u32 = 8;

pub const CELL_H: u32 = 16;

const HEX: &str = include_str!("unscii-16-subset.hex");

const REPLACEMENT: char = '\u{FFFD}';

const HOLLOW: [u8; 16] = [0, 0, 0x7E, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x7E, 0, 0, 0];

fn table() -> &'static [(u32, [u8; 16])] {
    static TABLE: OnceLock<Vec<(u32, [u8; 16])>> = OnceLock::new();
    TABLE.get_or_init(|| parse(HEX))
}

fn parse(text: &str) -> Vec<(u32, [u8; 16])> {
    let mut out: Vec<(u32, [u8; 16])> = text.lines().filter_map(parse_line).collect();
    out.sort_by_key(|(cp, _)| *cp);
    out.dedup_by_key(|(cp, _)| *cp);
    out
}

fn parse_line(line: &str) -> Option<(u32, [u8; 16])> {
    let line = line.trim();
    if line.starts_with('#') {
        return None;
    }
    let (cp, hex) = line.split_once(':')?;

    let hexdigits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_hexdigit());
    if !hexdigits(cp) || cp.len() > 6 || !hexdigits(hex) || hex.len() != 32 {
        return None;
    }
    let cp = u32::from_str_radix(cp, 16).ok()?;
    let mut rows = [0u8; 16];
    let (pairs, _) = hex.as_bytes().as_chunks::<2>();
    for (row, pair) in rows.iter_mut().zip(pairs) {
        *row = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
    }
    Some((cp, rows))
}

fn lookup(ch: char) -> Option<[u8; 16]> {
    let t = table();
    let i = t.binary_search_by_key(&u32::from(ch), |(cp, _)| *cp).ok()?;
    t.get(i).map(|(_, g)| *g)
}

pub fn glyph(ch: char) -> [u8; 16] {
    lookup(ch).or_else(|| lookup(REPLACEMENT)).unwrap_or(HOLLOW)
}
