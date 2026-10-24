pub(crate) fn hex(b: &[u8]) -> String {
    use core::fmt::Write;
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        let _ = write!(s, "{x:02x}");
    }
    s
}

pub(crate) fn hex16(b: &[u8; 16]) -> String {
    hex(b)
}

pub(crate) fn hex32(b: &[u8; 32]) -> String {
    hex(b)
}

#[cfg(target_os = "linux")]
pub(crate) fn rfc3339_now() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());

    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

#[cfg(any(target_os = "linux", target_os = "windows", feature = "mod-detect-sigma", test))]
pub(crate) fn json_str(v: &str) -> String {
    let mut s = String::with_capacity(v.len() + 2);
    s.push('"');
    for c in v.chars() {
        match c {
            '"' => s.push_str("\\\""),
            '\\' => s.push_str("\\\\"),
            '\n' => s.push_str("\\n"),
            '\r' => s.push_str("\\r"),
            '\t' => s.push_str("\\t"),
            c if (c as u32) < 0x20 => s.push_str(&format!("\\u{:04x}", c as u32)),
            c => s.push(c),
        }
    }
    s.push('"');
    s
}

#[cfg(target_os = "linux")]
pub(crate) fn json_array(v: &[String]) -> String {
    let items: Vec<String> = v.iter().map(|x| json_str(x)).collect();
    format!("[{}]", items.join(","))
}

#[cfg(any(target_os = "windows", target_os = "linux"))]
pub(crate) fn wrap_why(text: &str, prefix: &str) -> String {
    const WIDTH: usize = 78;
    let indent = " ".repeat(prefix.len());
    let mut out = String::from(prefix);
    let mut col = prefix.len();
    for word in text.split_whitespace() {
        if col + word.len() + 1 > WIDTH {
            out.push('\n');
            out.push_str(&indent);
            col = indent.len();
        } else if col > prefix.len() {
            out.push(' ');
            col += 1;
        }
        out.push_str(word);
        col += word.len();
    }
    out
}

#[cfg(target_os = "linux")]
pub(crate) fn human_secs(s: u64) -> String {
    let (d, h, m) = (s / 86_400, (s % 86_400) / 3600, (s % 3600) / 60);
    if d > 0 {
        format!("{d}d {h}h {m}m")
    } else if h > 0 {
        format!("{h}h {m}m")
    } else {
        format!("{m}m")
    }
}

pub(crate) fn jesc(s: &str) -> String {

    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

pub(crate) fn h(s: &str) -> String {
    let clean = hemostat_safestr::sanitize(s);

    match clean.threats.worst().filter(|_| clean.threats.deliberate()) {
        Some(kind) => format!("{} [!{kind} removed]", clean.text),
        None => clean.text,
    }
}

#[cfg(all(
    target_os = "linux",
    any(feature = "mod-sidecar", feature = "mod-enf-persistence")
))]
pub(crate) fn hl(s: &str) -> String {
    s.split('\n').map(h).collect::<Vec<_>>().join("\n")
}

#[cfg(target_os = "linux")]
pub(crate) fn triage_row(f: &hemostat_sensor_linux::triage::Finding) -> String {
    format!(
        "{{\"severity\":\"{}\",\"subject\":\"{}\",\"locus\":\"{}\",\"what\":\"{}\",\"why\":\"{}\"}}",
        f.severity.tag(),
        jesc(&f.subject),
        jesc(&f.locus),
        jesc(&f.what),
        jesc(&f.why)
    )
}

#[cfg(target_os = "linux")]
pub(crate) fn rootkit_row(f: &hemostat_sensor_linux::rootkit::Finding) -> String {
    format!(
        "{{\"severity\":\"{}\",\"subject\":\"{}\",\"what\":\"{}\",\"why\":\"{}\"}}",
        f.severity.tag(),
        jesc(&f.subject),
        jesc(&f.what),
        jesc(&f.why)
    )
}

#[cfg(target_os = "linux")]
pub(crate) fn finding_rows(findings: &[hemostat_sensor_linux::rootkit::Finding]) -> String {
    findings.iter().map(rootkit_row).collect::<Vec<_>>().join(",")
}

#[cfg(target_os = "linux")]
pub(crate) fn accounts_row(f: &hemostat_sensor_linux::accounts::Finding) -> String {
    format!(
        "{{\"severity\":\"{}\",\"subject\":\"{}\",\"what\":\"{}\",\"why\":\"{}\"}}",
        f.severity.tag(),
        jesc(&f.subject),
        jesc(&f.what),
        jesc(&f.why)
    )
}

static KIND: std::sync::OnceLock<String> = std::sync::OnceLock::new();

pub(crate) fn set_kind(verb: &str) {
    let _ = KIND.set(verb.to_string());
}

pub(crate) const SCHEMA: &str = "hemostat.cli.v1";

pub(crate) fn envelope(doc: &str) -> String {
    envelope_as(KIND.get().map_or("unknown", String::as_str), doc)
}

fn envelope_as(kind: &str, doc: &str) -> String {
    let t = doc.trim();
    let head = format!("\"schema\":\"{SCHEMA}\",\"kind\":\"{}\"", jesc(kind));
    if t.starts_with('{') && t.ends_with('}') {
        let inner = t[1..t.len() - 1].trim();
        if inner.is_empty() {
            format!("{{{head}}}")
        } else {
            format!("{{{head},{inner}}}")
        }
    } else if t.starts_with('[') && t.ends_with(']') {
        format!("{{{head},\"items\":{t}}}")
    } else {
        doc.to_string()
    }
}
