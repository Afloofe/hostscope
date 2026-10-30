pub const DRIVE_NO_ROOT_DIR: u32 = 1;

pub const DRIVE_FIXED: u32 = 3;

pub fn local(path: &str) -> Result<String, String> {
    let p = path.replace('/', "\\");
    let refuse = |why: &str| Err(format!("not a path on a local drive: {why}"));
    let body = match p.strip_prefix(r"\\?\").or_else(|| p.strip_prefix(r"\??\")) {
        Some(rest) if is_drive_form(rest) => rest,
        Some(rest) if rest.get(..4).is_some_and(|h| h.eq_ignore_ascii_case(r"UNC\")) => return refuse(SHARE),
        Some(_) => {
            return refuse(
                "it is in the object namespace (`\\\\?\\`, `\\??\\`), which names volumes, pipes and \
                 devices as readily as files",
            )
        }
        None if p.starts_with(r"\\.\") => {
            return refuse("it is a device path (`\\\\.\\`), which can be a pipe or a driver")
        }
        None if p.starts_with(r"\\") => return refuse(SHARE),
        None if p.starts_with('\\') => return refuse("it names no drive"),
        None => p.as_str(),
    };
    if !is_drive_form(body) {
        return if body.is_empty() {
            refuse("the path is empty")
        } else if body.as_bytes().get(1) == Some(&b':') {
            refuse("it is relative to that drive's current directory")
        } else {
            refuse("it is relative, so it names wherever this process's current directory is")
        };
    }
    let (drive, rest) = (body.get(..2).unwrap_or_default(), body.get(2..).unwrap_or_default());
    let mut out = String::with_capacity(body.len());
    out.push_str(drive);
    for c in rest.split('\\').filter(|c| !c.is_empty()) {
        if let Some(why) = bad_component(c) {
            return refuse(&format!("it has {why}"));
        }
        out.push('\\');
        out.push_str(c);
    }
    if out.len() == drive.len() {
        out.push('\\');
    }
    Ok(out)
}

const SHARE: &str = "it is a share, and opening one authenticates to that server as this process";

fn is_drive_form(s: &str) -> bool {
    matches!(s.as_bytes(), [d, b':', b'\\', ..] if d.is_ascii_alphabetic())
}

fn bad_component(c: &str) -> Option<String> {
    if c == "." || c == ".." {
        return Some(format!(
            "a `{c}` component, which Windows resolves, so what would open is not the path that \
             was checked"
        ));
    }
    if c.ends_with('.') || c.ends_with(' ') {
        return Some(format!(
            "a component ending in a dot or a space (`{c}`), which Windows strips, so what would \
             open is not the path that was checked"
        ));
    }
    if let Some(ch) = c.chars().find(|ch| ch.is_control() || matches!(ch, '<' | '>' | ':' | '"' | '|' | '?' | '*')) {
        return Some(format!(
            "`{}` in `{}`: a `:` names a stream or a device, and no file name may hold the others",
            ch.escape_debug(),
            c.escape_debug()
        ));
    }
    if is_device_name(c) {
        return Some(format!(
            "the component `{c}`, a device's name, which Windows opens as that device wherever it \
             appears"
        ));
    }
    None
}

fn is_device_name(c: &str) -> bool {
    let stem = c.split('.').next().unwrap_or(c).trim_end_matches(' ').to_ascii_uppercase();
    match stem.as_str() {
        "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$" | "CLOCK$" => true,
        s => s.strip_prefix("COM").or_else(|| s.strip_prefix("LPT")).is_some_and(|n| {
            let mut digits = n.chars();
            matches!((digits.next(), digits.next()), (Some('0'..='9' | '\u{b9}' | '\u{b2}' | '\u{b3}'), None))
        }),
    }
}

pub fn within(path: &str, dir: &str) -> bool {
    let dir = dir.trim_end_matches('\\');
    path.get(..dir.len()).is_some_and(|head| head.eq_ignore_ascii_case(dir))
        && path.get(dir.len()..).is_some_and(|rest| rest.len() > 1 && rest.starts_with('\\'))
}

const NETWORK_DEVICES: &[&str] = &[
    r"\Device\Mup\",
    r"\Device\LanmanRedirector\",
    r"\Device\WebDavRedirector\",
    r"\Device\RdpDr\",
    r"\??\UNC\",
    r"\DosDevices\UNC\",
    r"\GLOBAL??\UNC\",
];

pub fn is_network(kernel: &str) -> bool {
    NETWORK_DEVICES.iter().any(|d| kernel.get(..d.len()).is_some_and(|h| h.eq_ignore_ascii_case(d)))
}

pub fn drive_target(drive: &str, device: &str) -> Result<(), String> {
    if is_network(&format!("{device}\\")) {
        return Err(format!(
            "{drive} names {device}, a share, and opening a file there authenticates to its server \
             as this process"
        ));
    }
    if !device.get(..8).is_some_and(|h| h.eq_ignore_ascii_case(r"\Device\")) {
        return Err(format!(
            "{drive} names {device}, another name rather than a device, which can lead to another \
             machine, and a path the host supplied is opened only on a drive that names its disk"
        ));
    }
    Ok(())
}

pub fn on_drive(kernel: &str, drives: &[(char, String)]) -> Result<String, String> {
    for (letter, device) in drives {
        let device = device.trim_end_matches('\\');
        if device.is_empty() || !kernel.get(..device.len()).is_some_and(|h| h.eq_ignore_ascii_case(device)) {
            continue;
        }
        if let Some(rest) = kernel.get(device.len()..).filter(|r| r.len() > 1 && r.starts_with('\\')) {
            return local(&format!("{letter}:{rest}"));
        }
    }
    if is_network(kernel) {
        Err(format!(
            "the kernel maps it from {kernel}, a network path, and opening it would authenticate to \
             that host as this process"
        ))
    } else {
        Err(format!("the kernel maps it from {kernel}, which is on no local fixed drive with a letter"))
    }
}

pub fn drive_kind(drive: &str, kind: u32) -> Result<(), String> {
    let only = "and a path the host supplied is opened only on a fixed drive";
    match kind {
        DRIVE_FIXED => Ok(()),
        4 => Err(format!(
            "{drive} is a network drive, and opening a file there authenticates to its server as \
             this process"
        )),
        2 => Err(format!("{drive} is a removable drive, {only}")),
        5 => Err(format!("{drive} is an optical drive, {only}")),
        6 => Err(format!("{drive} is a RAM disk, {only}")),
        DRIVE_NO_ROOT_DIR => Err(format!("there is no drive {drive}")),
        other => Err(format!("what kind of drive {drive} is could not be established ({other}), {only}")),
    }
}

#[cfg(target_os = "windows")]
pub fn vet(path: &str) -> Result<Option<(String, std::fs::Metadata)>, String> {
    use windows_sys::Win32::Storage::FileSystem::GetDriveTypeW;

    let p = local(path)?;
    let drive = p.get(..2).unwrap_or_default();
    match dos_device(drive, &mut [0; 1024]) {
        Some(device) => drive_target(drive, &device)?,

        None if !letter_in_use(drive) => return Ok(None),
        None => {
            return Err(format!(
                "what {drive} names could not be read, so where a path on it leads was not established"
            ))
        }
    }
    let root = format!("{drive}\\");
    let wide: Vec<u16> = root.encode_utf16().chain(core::iter::once(0)).collect();

    let kind = unsafe { GetDriveTypeW(wide.as_ptr()) };
    if kind == DRIVE_NO_ROOT_DIR {
        return Ok(None);
    }
    drive_kind(drive, kind)?;
    let mut at = root;
    let mut last = None;
    for c in p.get(3..).unwrap_or_default().split('\\').filter(|c| !c.is_empty()) {
        if !at.ends_with('\\') {
            at.push('\\');
        }
        at.push_str(c);
        match std::fs::symlink_metadata(&at) {
            Ok(md) if md.file_type().is_symlink() => {
                return Err(format!(
                    "{at} is a symbolic link, a junction or a mount point, and none is followed on a \
                     path the host supplied: it can lead to another machine"
                ))
            }
            Ok(md) => last = Some(md),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(format!("{at} could not be read: {e}")),
        }
    }
    let md = match last {
        Some(md) => md,
        None => std::fs::symlink_metadata(&at).map_err(|e| format!("{at} could not be read: {e}"))?,
    };
    Ok(Some((p, md)))
}

#[cfg(target_os = "windows")]
pub fn open(path: &str) -> Result<std::fs::File, String> {
    use std::os::windows::fs::OpenOptionsExt as _;
    use std::os::windows::io::AsRawHandle as _;
    use windows_sys::Win32::Storage::FileSystem::{GetFileType, FILE_TYPE_DISK, SECURITY_IDENTIFICATION};

    let (p, md) = vet(path)?.ok_or_else(|| "nothing is there".to_string())?;
    if !md.is_file() {
        return Err("it is not a file".into());
    }
    let f = std::fs::OpenOptions::new()
        .read(true)
        .security_qos_flags(SECURITY_IDENTIFICATION)
        .open(&p)
        .map_err(|e| format!("it could not be opened: {e}"))?;

    let kind = unsafe { GetFileType(f.as_raw_handle()) };
    if kind != FILE_TYPE_DISK {
        return Err(format!(
            "it opened as something other than a file on disk (type {kind}), so it was closed unread"
        ));
    }
    Ok(f)
}

#[cfg(target_os = "windows")]
pub fn fixed_drives() -> Vec<(char, String)> {
    use windows_sys::Win32::Storage::FileSystem::{GetDriveTypeW, GetLogicalDrives};

    let mask = unsafe { GetLogicalDrives() };
    let mut out = Vec::new();
    let mut buf = vec![0_u16; 1024];
    for (i, letter) in ('A'..='Z').enumerate() {
        if mask & (1_u32 << i) == 0 {
            continue;
        }
        let Some(device) = dos_device(&format!("{letter}:"), &mut buf) else { continue };
        if drive_target(&format!("{letter}:"), &device).is_err() {
            continue;
        }
        let root: Vec<u16> = format!("{letter}:\\").encode_utf16().chain(core::iter::once(0)).collect();

        if unsafe { GetDriveTypeW(root.as_ptr()) } == DRIVE_FIXED {
            out.push((letter, device));
        }
    }
    out
}

#[cfg(target_os = "windows")]
fn letter_in_use(drive: &str) -> bool {
    use windows_sys::Win32::Storage::FileSystem::GetLogicalDrives;

    let Some(i) = drive.bytes().next().filter(u8::is_ascii_alphabetic).map(|b| b.to_ascii_uppercase() - b'A') else {
        return false;
    };

    let mask = unsafe { GetLogicalDrives() };
    mask & (1_u32 << i) != 0
}

#[cfg(target_os = "windows")]
fn dos_device(drive: &str, buf: &mut [u16]) -> Option<String> {
    use windows_sys::Win32::Storage::FileSystem::QueryDosDeviceW;

    let name: Vec<u16> = drive.encode_utf16().chain(core::iter::once(0)).collect();

    let n = unsafe { QueryDosDeviceW(name.as_ptr(), buf.as_mut_ptr(), buf.len() as u32) };
    let got = buf.get(..n as usize).unwrap_or_default();
    let first = got.split(|c| *c == 0).next().unwrap_or_default();
    (!first.is_empty()).then(|| String::from_utf16_lossy(first))
}
