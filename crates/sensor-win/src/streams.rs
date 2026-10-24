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
            fix: Some(format!("read it as an administrator: `Get-Item -Path '{}' -Stream '{}'`", s.path, s.name)),
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
            fix: Some(format!(
                "read it before deleting it — `Get-Content -Path '{}' -Stream '{}' -Raw` — then \
                 remove it with `Remove-Item -Path '{}' -Stream '{}'`",
                s.path, s.name, s.path, s.name
            )),
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
            fix: Some(format!(
                "look at the content: `Get-Content -Path '{}' -Stream '{}' -Raw`",
                s.path, s.name
            )),
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
        fix: Some(format!(
            "`Get-Content -Path '{}' -Stream '{}' -Raw` shows it without executing it",
            s.path, s.name
        )),
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
        fix: Some(format!(
            "capture it before anything else — `Get-Content -Path '{file}' -Stream '{stream}' \
             -Raw` — then remove the autostart, then the stream with `Remove-Item -Path '{file}' \
             -Stream '{stream}'`"
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
