use crate::posture::{Finding, Severity};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stream {

    pub path: String,

    pub name: String,

    pub size: u64,

    pub magic: Option<[u8; 4]>,

    pub magic_unreadable: bool,
}

const ORDINARY: &[&str] = &[
    "Zone.Identifier",
    "SmartScreen",
    "Wof",
    "WofCompressedData",
    "$EFS",
    "$TXF_DATA",
    "encryptable",
    "OECustomProperty",
    "favicon",
];

pub fn is_ordinary_name(name: &str) -> bool {
    ORDINARY.iter().any(|o| o.eq_ignore_ascii_case(name))
}

fn looks_executable(magic: Option<[u8; 4]>) -> bool {
    matches!(magic, Some([b'M', b'Z', _, _] | [0x7f, b'E', b'L', b'F'] | [b'#', b'!', _, _]))
}

pub const MAX_ORDINARY_ZONE_BYTES: u64 = 4096;

const MAX_COMMAND_PATH: usize = 1024;

const MAX_COMMAND_STREAM: usize = 255;

const MAX_COMMAND_RUN: usize = 16;

const WHY_NOT_A_DRIVE: &str = "the path does not start at a drive letter, so a pasted command could resolve it somewhere else";
const WHY_NETWORK: &str = "the path is on a network share, and reading it would connect to that host as you";
const WHY_ENVIRONMENT: &str = "the path starts at an environment variable, which expands for the account the autostart runs as, not for you";
const WHY_NAMESPACE: &str = r"the path carries a \\?\, \\.\ or \??\ prefix, which PowerShell does not resolve the way Windows does";
const WHY_CHARACTER: &str = "a name holds a character a pasted command would not keep as itself — a quote-like or invisible \
                             character, a control, unusual whitespace, or one of & | < > ^ % \" that cmd.exe acts on";
const WHY_COLON: &str = "the path holds a colon after its drive, which PowerShell reads as naming a stream of its own";
const WHY_TRAILING: &str = "a name ends in a dot or a space, which Windows drops when it resolves a path, so a command would \
                            name a different file or stream";
const WHY_WILDCARD: &str = "the stream name holds * ? [ ] or `, which -Stream matches as a wildcard pattern";
const WHY_SEPARATOR: &str = "the stream name is empty or holds a path separator or a colon";
const WHY_LONG: &str = "a name is too long to show as one command";
const WHY_RUN: &str = "it would hold a run of one character long enough for the display to shorten it";
const WHY_SPACES: &str = "a name holds two or more spaces in a row, which a wrapped display shows as one, so a copied \
                          command would name a different file or stream";

fn plain(c: char) -> bool {
    match c {
        ' ' => true,
        '&' | '|' | '<' | '>' | '^' | '%' | '"' => false,
        c if c.is_ascii() => c.is_ascii_graphic(),
        '\u{115F}' | '\u{1160}' | '\u{3164}' | '\u{FFA0}' => false,
        c => c.is_alphanumeric(),
    }
}

fn ps_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

fn command_path(path: &str) -> Result<String, &'static str> {
    let b = path.as_bytes();
    let drive = b.first().is_some_and(u8::is_ascii_alphabetic)
        && b.get(1) == Some(&b':')
        && matches!(b.get(2), Some(b'\\' | b'/'));
    if !drive {
        return Err(if [r"\\?\", r"\\.\", r"\??\"].iter().any(|p| path.starts_with(p)) {
            WHY_NAMESPACE
        } else if path.starts_with(r"\\") || path.starts_with("//") {
            WHY_NETWORK
        } else if path.starts_with('%') {
            WHY_ENVIRONMENT
        } else {
            WHY_NOT_A_DRIVE
        });
    }
    if path.chars().count() > MAX_COMMAND_PATH {
        return Err(WHY_LONG);
    }
    if !path.chars().all(plain) {
        return Err(WHY_CHARACTER);
    }
    let rest = path.get(3..).unwrap_or_default();
    if rest.contains(':') {
        return Err(WHY_COLON);
    }
    if rest.split(['\\', '/']).any(|segment| segment.ends_with(['.', ' '])) {
        return Err(WHY_TRAILING);
    }
    if path.contains("  ") {
        return Err(WHY_SPACES);
    }
    Ok(ps_quote(path))
}

fn command_stream(stream: &str) -> Result<String, &'static str> {
    if stream.is_empty() || stream.contains(['\\', '/', ':']) {
        return Err(WHY_SEPARATOR);
    }
    if stream.chars().count() > MAX_COMMAND_STREAM {
        return Err(WHY_LONG);
    }
    if !stream.chars().all(plain) {
        return Err(WHY_CHARACTER);
    }
    if stream.contains(['*', '?', '[', ']', '`']) {
        return Err(WHY_WILDCARD);
    }
    if stream.starts_with(' ') || stream.ends_with(['.', ' ']) {
        return Err(WHY_TRAILING);
    }
    if stream.contains("  ") {
        return Err(WHY_SPACES);
    }
    Ok(ps_quote(stream))
}

fn hex_view(stream: &str, path: &str) -> String {
    format!(
        "Format-Hex -InputObject ([byte[]](Get-Content -Stream {stream} -Encoding Byte -ReadCount 0 \
         -LiteralPath {path}))"
    )
}

fn longest_run(s: &str) -> usize {
    let (mut best, mut run, mut prev) = (0, 0, None);
    for c in s.chars() {
        run = if prev == Some(c) { run + 1 } else { 1 };
        prev = Some(c);
        best = best.max(run);
    }
    best
}

fn stream_fix(path: &str, stream: &str, lead: &str, commands: impl FnOnce(&str, &str) -> String) -> String {
    let offered = command_path(path).and_then(|p| Ok((p, command_stream(stream)?))).and_then(|(p, n)| {
        let text = commands(&p, &n);
        if longest_run(&text) > MAX_COMMAND_RUN {
            Err(WHY_RUN)
        } else {
            Ok(text)
        }
    });
    offered.unwrap_or_else(|why| {
        format!("{lead} by hand. No command is offered, because {why}. The file is {path:?} and the stream {stream:?}")
    })
}

pub fn judge(s: &Stream) -> Option<Finding> {

    if s.name.is_empty() {
        return None;
    }

    let exec = looks_executable(s.magic);
    let ordinary_name = is_ordinary_name(s.name.as_str());

    if s.magic_unreadable && !(ordinary_name && s.size <= MAX_ORDINARY_ZONE_BYTES) {
        return Some(Finding {
            severity: Severity::Warn,
            subject: format!("ads:{}:{}", s.path, s.name),
            what: format!(
                "the alternate data stream {}:{} ({} bytes) could not be read",
                s.path, s.name, s.size
            ),
            why: "whether it holds an executable was not established — an unreadable stream is \
                  unchecked, not clean, and an attacker hiding a payload has every reason to \
                  make it unreadable"
                .into(),
            fix: Some(stream_fix(&s.path, &s.name, "read it as an administrator", |p, n| {
                format!("read it as an administrator: `Get-Item -Stream {n} -LiteralPath {p}`")
            })),
        });
    }

    if exec {
        return Some(Finding {
            severity: Severity::Critical,
            subject: format!("ads:{}:{}", s.path, s.name),
            what: format!(
                "the alternate data stream {}:{} is {} bytes and begins with an executable header",
                s.path, s.name, s.size
            ),
            why: "an executable body in an alternate data stream does not appear in a directory \
                  listing, does not change the file's displayed size, and can be launched \
                  directly by path. It is a hiding place, and nothing benign uses it this way"
                .into(),
            fix: Some(stream_fix(&s.path, &s.name, "read it before deleting it, then remove it", |p, n| {
                let read = hex_view(n, p);
                format!(
                    "read it before deleting it — `{read}` shows its bytes as hex — then remove it with \
                     `Remove-Item -Stream {n} -LiteralPath {p}`"
                )
            })),
        });
    }

    if ordinary_name && s.size <= MAX_ORDINARY_ZONE_BYTES {
        return None;
    }

    if ordinary_name {
        return Some(Finding {
            severity: Severity::Warn,
            subject: format!("ads:{}:{}", s.path, s.name),
            what: format!(
                "{}:{} carries {} bytes — a stream by that name normally holds a few hundred",
                s.path, s.name, s.size
            ),
            why: "the names the OS writes are the names tools skip on sight, which is exactly \
                  why something hiding data picks one. The size no longer matches the name"
                .into(),
            fix: Some(stream_fix(&s.path, &s.name, "look at the content", |p, n| {
                format!("look at the content as hex: `{}`", hex_view(n, p))
            })),
        });
    }

    Some(Finding {
        severity: Severity::Warn,
        subject: format!("ads:{}:{}", s.path, s.name),
        what: format!("{} carries an unrecognised alternate data stream {} of {} bytes",
            s.path, s.name, s.size),
        why: "content in a named stream is invisible to a directory listing and to any tool \
              that reads the file by path alone"
            .into(),
        fix: Some(stream_fix(&s.path, &s.name, "look at it without executing it", |p, n| {
            format!("`{}` shows its bytes as hex without executing it", hex_view(n, p))
        })),
    })
}

pub fn path_names_a_stream(path: &str) -> Option<(String, String)> {
    let p = path.trim().trim_matches('"');
    let b = p.as_bytes();
    let is_drive = |at: usize| {
        b.get(at).is_some_and(u8::is_ascii_alphabetic)
            && b.get(at + 1) == Some(&b':')
            && matches!(b.get(at + 2), Some(b'\\' | b'/'))
    };
    let body = if is_drive(0) {
        3
    } else if (p.starts_with(r"\\?\") || p.starts_with(r"\\.\") || p.starts_with(r"\??\"))
        && is_drive(4)
    {
        7
    } else if let Some(var) = p.strip_prefix('%').and_then(|r| r.find('%')) {

        let after = var + 2;
        if var == 0 || !matches!(b.get(after), Some(b'\\' | b'/')) {
            return None;
        }
        after
    } else if p.starts_with(r"\\") {
        2
    } else {
        return None;
    };

    let idx = (body..b.len()).find(|&i| {
        b.get(i) == Some(&b':')
            && !(b.get(i - 1).is_some_and(u8::is_ascii_alphabetic)
                && matches!(b.get(i - 2), Some(b',' | b';' | b' ' | b'=')))
    })?;
    let file = p.get(..idx)?.to_string();
    let rest = p.get(idx + 1..)?;
    let stream = rest.split(',').next().unwrap_or(rest);
    let stream = stream.strip_suffix(":$DATA").unwrap_or(stream).to_string();
    if stream.is_empty() || stream.contains(['\\', '/', ':']) {
        return None;
    }
    Some((file, stream))
}

fn words(command: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quoted = false;
    for c in command.chars() {
        match c {
            '"' => quoted = !quoted,
            c if c.is_whitespace() && !quoted => {
                if !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
            }
            c => cur.push(c),
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

pub fn stream_references(command: &str) -> Vec<(String, String)> {
    let w = words(command);
    let mut candidates: Vec<String> = w.clone();
    if !command.trim_start().starts_with('"') {
        if let Some(first) = w.first() {
            let mut image = first.clone();
            for next in w.iter().skip(1) {
                let leaf = image.rsplit(['\\', '/']).next().unwrap_or(&image);
                let bare_colon = next
                    .find(':')
                    .is_some_and(|c| !next.get(..c).unwrap_or_default().contains(['\\', '/']));
                if leaf.contains('.') || next.starts_with(['-', '/']) || bare_colon {
                    break;
                }
                image = format!("{image} {next}");
                candidates.push(image.clone());
            }
        }
    }
    let mut out: Vec<(String, String)> =
        candidates.iter().filter_map(|c| path_names_a_stream(c)).collect();
    out.sort();
    out.dedup();
    out
}

pub fn judge_autostart(locus: &str, name: &str, command: &str) -> Option<Finding> {
    let (file, stream) = stream_references(command).into_iter().next()?;
    Some(Finding {
        severity: Severity::Critical,
        subject: format!("ads:{file}:{stream}"),
        what: format!(
            "`{name}` in {locus} runs code out of the alternate data stream {file}:{stream}"
        ),
        why: "an executable body in a named stream does not appear in a directory listing or in \
              the file's size, and a sweep that reads the path sees an ordinary file. Nothing \
              legitimate starts itself from one; the stream is the hiding place"
            .into(),
        fix: Some(stream_fix(
            &file,
            &stream,
            "capture it before anything else, then remove the autostart, then the stream",
            |p, n| {
                let read = hex_view(n, p);
                format!(
                    "capture it before anything else — `{read}` shows its bytes as hex — then remove the \
                     autostart, then the stream with `Remove-Item -Stream {n} -LiteralPath {p}`"
                )
            },
        )),
    })
}

pub fn parse_stream_name(raw: &str) -> String {
    let once = raw.strip_prefix(':').unwrap_or(raw);
    once.strip_suffix(":$DATA").unwrap_or(once).to_string()
}

#[cfg(target_os = "windows")]
pub fn streams_of(path: &str) -> Option<(Vec<Stream>, bool)> {
    use windows_sys::Win32::Foundation::{GetLastError, ERROR_HANDLE_EOF, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Storage::FileSystem::{
        FindClose, FindFirstStreamW, FindNextStreamW, FindStreamInfoStandard, WIN32_FIND_STREAM_DATA,
    };

    let wide: Vec<u16> = path.encode_utf16().chain(core::iter::once(0)).collect();

    let mut data: WIN32_FIND_STREAM_DATA = unsafe { core::mem::zeroed() };

    let handle = unsafe {
        FindFirstStreamW(
            wide.as_ptr(),
            FindStreamInfoStandard,
            core::ptr::addr_of_mut!(data).cast(),
            0,
        )
    };
    if handle == INVALID_HANDLE_VALUE {

        return (unsafe { GetLastError() } == ERROR_HANDLE_EOF).then(|| (Vec::new(), false));
    }

    let mut out = Vec::new();
    let cut_short = loop {

        let raw = &data.cStreamName;
        let len = raw.iter().position(|c| *c == 0).unwrap_or(raw.len());
        let name_full = String::from_utf16_lossy(&raw[..len]);
        let name = parse_stream_name(&name_full);
        let size = data.StreamSize.max(0) as u64;

        let (magic, magic_unreadable) = if name.is_empty() {
            (None, false)
        } else {
            match read_magic(path, &name) {
                Ok(m) => (m, false),
                Err(()) => (None, true),
            }
        };

        out.push(Stream { path: path.to_string(), name, size, magic, magic_unreadable });

        let more = unsafe { FindNextStreamW(handle, core::ptr::addr_of_mut!(data).cast()) };
        if more == 0 {

            break unsafe { GetLastError() } != ERROR_HANDLE_EOF;
        }
    };

    unsafe { FindClose(handle) };
    Some((out, cut_short))
}

#[cfg(target_os = "windows")]
fn read_magic(path: &str, stream: &str) -> Result<Option<[u8; 4]>, ()> {
    use std::io::Read as _;

    let mut f = std::fs::File::open(format!("{path}:{stream}")).map_err(|_| ())?;
    let mut buf = [0u8; 4];
    match f.read(&mut buf) {
        Ok(4) => Ok(Some(buf)),
        Ok(_) => Ok(None),
        Err(_) => Err(()),
    }
}
