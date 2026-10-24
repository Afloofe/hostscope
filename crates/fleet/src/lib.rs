#![forbid(unsafe_code)]

pub mod announce;
pub mod check;
pub mod enroll;
pub mod export;
pub mod heartbeat;
pub mod held;
pub mod ingest;
pub mod joins;
pub mod json;
pub mod keys;
pub mod ledger;
pub mod listen;
pub mod queue;
pub mod readkey;
pub mod rejudge;
pub mod spool;

pub fn hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        s.push_str(&format!("{x:02x}"));
    }
    s
}

pub fn shown(raw: &str) -> String {
    let mut s = String::new();
    for (i, b) in raw.bytes().enumerate() {
        if i == 200 {
            s.push_str("...");
            break;
        }
        if (0x20..0x7f).contains(&b) && b != b'\\' {
            s.push(char::from(b));
        } else {
            s.push_str(&format!("\\x{b:02x}"));
        }
    }
    s
}

pub fn js(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if (c as u32) < 0x20 || c == '\u{7f}' => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

pub(crate) fn shared_dir(p: &std::path::Path) -> std::io::Result<()> {
    if std::fs::metadata(p).map(|m| m.is_dir()).unwrap_or(false) {
        return Ok(());
    }
    if let Some(parent) = p.parent() {
        if !parent.as_os_str().is_empty() {
            shared_dir(parent)?;
        }
    }
    match std::fs::create_dir(p) {
        Ok(()) => set_mode(p, 0o2770),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        Err(e) => Err(e),
    }
}

pub(crate) fn set_mode(p: &std::path::Path, mode: u32) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode))
    }
    #[cfg(not(unix))]
    {
        let _ = (p, mode);
        Ok(())
    }
}

pub(crate) fn share_finished(p: &std::path::Path) {
    #[cfg(unix)]
    let gid = {
        use std::os::unix::fs::MetadataExt as _;
        p.parent().and_then(|d| std::fs::metadata(d).ok()).map(|m| m.gid())
    };
    #[cfg(not(unix))]
    let gid: Option<u32> = None;
    share_finished_as(p, gid);
}

fn share_finished_as(p: &std::path::Path, gid: Option<u32>) {
    let Ok(m) = std::fs::symlink_metadata(p) else { return };
    #[cfg(unix)]
    if let Some(g) = gid {
        let _ = std::os::unix::fs::lchown(p, None, Some(g));
    }
    if m.is_dir() {
        if let Ok(rd) = std::fs::read_dir(p) {
            for e in rd.flatten() {
                share_finished_as(&e.path(), gid);
            }
        }
        let _ = set_mode(p, 0o2750);
    } else if m.is_file() {
        let _ = set_mode(p, 0o640);
    }
}

pub fn now_ns() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_nanos()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

pub fn utc(ns: i64) -> String {
    let secs = ns.div_euclid(1_000_000_000);
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);

    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02}Z", rem / 3600, rem % 3600 / 60, rem % 60)
}

pub fn span(ns: i64) -> String {
    let s = ns.max(0) / 1_000_000_000;
    match s {
        0..=59 => format!("{s}s"),
        60..=3599 => format!("{}m", s / 60),
        3600..=86_399 => format!("{}h{:02}m", s / 3600, s % 3600 / 60),
        _ => format!("{}d{:02}h", s / 86_400, s % 86_400 / 3600),
    }
}
