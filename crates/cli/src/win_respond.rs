#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet};

#[cfg(target_os = "windows")]
use crate::render::h;
#[cfg(target_os = "windows")]
use crate::{EXIT_DRYRUN, EXIT_ENFORCER, EXIT_FAILED, EXIT_OK, EXIT_POLICY, EXIT_USAGE};

#[cfg(target_os = "windows")]
fn sys32(exe: &str) -> String {
    let sysroot = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_string());
    format!(r"{sysroot}\System32\{exe}")
}

pub(crate) const CRITICAL_PROCS: &[&str] = &[
    "System", "Idle", "smss.exe", "csrss.exe", "wininit.exe", "services.exe",
    "lsass.exe", "winlogon.exe", "Registry", "Memory Compression",
    "Secure System", "LsaIso.exe",
];

pub(crate) fn is_critical_proc(name: &str) -> bool {
    CRITICAL_PROCS.iter().any(|c| c.eq_ignore_ascii_case(name))
}

pub(crate) const SERVICE_IMAGES: &[&str] =
    &["dns.exe", r"inetsrv\w3wp.exe", r"inetsrv\inetinfo.exe", "tlntsvr.exe", r"OpenSSH\sshd.exe"];

pub(crate) const SERVICE_HOST: &str = "svchost.exe";

const SESSION_ROOTS: &[&str] = &["explorer.exe", "services.exe", "wininit.exe", "winlogon.exe", "smss.exe"];

#[derive(Debug, Clone, Default)]
pub(crate) struct KillFacts {

    pub(crate) agent: u32,

    pub(crate) procs: Option<Vec<(u32, u32, String)>>,

    pub(crate) image: Option<String>,

    pub(crate) listeners: Option<BTreeMap<u32, BTreeSet<u16>>>,

    pub(crate) system_dirs: Vec<String>,
}

pub(crate) fn norm(p: &str) -> String {
    let s = p.replace('/', "\\");
    let s = s.strip_prefix(r"\\?\").unwrap_or(&s);
    s.trim_end_matches('\\').to_ascii_lowercase()
}

pub(crate) fn under(path: &str, dir: &str) -> bool {
    !dir.is_empty() && (path == dir || path.strip_prefix(dir).is_some_and(|rest| rest.starts_with('\\')))
}

pub(crate) fn local(p: &str) -> bool {
    let mut c = p.chars();
    matches!((c.next(), c.next(), c.next()), (Some(d), Some(':'), Some('\\')) if d.is_ascii_alphabetic())
}

fn system_image(image: &str, dirs: &[String], rel: &str) -> bool {
    let rel = rel.to_ascii_lowercase();
    dirs.iter().any(|d| image == format!("{d}\\{rel}"))
}

pub(crate) fn session_chain(start: u32, procs: &[(u32, u32, String)]) -> BTreeSet<u32> {
    let mut chain = BTreeSet::new();
    let mut at = start;
    for _ in 0..64 {
        if !chain.insert(at) {
            break;
        }
        match procs.iter().find(|(pid, _, _)| *pid == at) {
            Some((_, _, name)) if SESSION_ROOTS.iter().any(|r| r.eq_ignore_ascii_case(name)) => break,
            Some((_, ppid, _)) if *ppid != 0 && *ppid != at => at = *ppid,
            _ => break,
        }
    }
    chain
}

pub(crate) fn kill_refusal(pid: u32, f: &KillFacts, allow_listener: bool) -> Option<String> {
    if pid <= 4 {
        return Some(format!("PID {pid} is System/Idle and is never killed"));
    }
    if pid == f.agent {
        return Some(format!("PID {pid} is this HEMOSTAT process"));
    }
    let Some(procs) = &f.procs else {
        return Some(format!(
            "the process list could not be read, so PID {pid} cannot be checked against the processes this box \
             cannot lose"
        ));
    };
    let Some((_, _, name)) = procs.iter().find(|(p, _, _)| *p == pid) else {
        return Some(format!("PID {pid} is not running"));
    };
    if session_chain(f.agent, procs).contains(&pid) {
        return Some(format!(
            "{name} (PID {pid}) is one of the processes this session runs in — your shell, terminal or \
             connection. Killing it cuts you off"
        ));
    }
    let image = f.image.as_deref().map(norm).filter(|i| local(i));
    let Some(img) = image else {
        if is_critical_proc(name) {
            return Some(format!("{name} (PID {pid}) is a critical Windows process; killing it would bugcheck the box"));
        }
        return Some(format!(
            "where {name} (PID {pid}) runs from could not be read, so it cannot be told from a system process. \
             Run elevated, or end it by hand if you are certain"
        ));
    };
    let dirs = &f.system_dirs;
    if CRITICAL_PROCS.iter().any(|c| system_image(&img, dirs, c)) {
        return Some(format!("{name} (PID {pid}) is a critical Windows process; killing it would bugcheck the box"));
    }
    if system_image(&img, dirs, SERVICE_HOST) {
        return Some(format!(
            "{name} (PID {pid}) is a shared service host: it carries several services at once (WinRM, SMB, RPC \
             and DCOM among them), some critical. Stop the one service you mean with `sc stop` instead"
        ));
    }
    if SERVICE_IMAGES.iter().any(|s| system_image(&img, dirs, s)) {
        return Some(format!("{name} (PID {pid}) is a scored service's own image ({img}); killing it takes the service down"));
    }
    if img.split('\\').any(|c| c == "datadog") {
        return Some(format!("{name} (PID {pid}) is DataDog's ({img}), which is protected (packet rule 14)"));
    }

    if img.split('\\').any(|c| c == "netbird" || c == "netbird.exe") {
        return Some(format!(
            "{name} (PID {pid}) is NetBird's ({img}): the packet says its traffic is never blocked, and \
             killing it cuts the tunnel"
        ));
    }
    if allow_listener {
        return None;
    }
    match &f.listeners {
        None => Some(format!(
            "the socket tables could not be read whole, so whether {name} (PID {pid}) answers a port — as every \
             service does — is unknown. If you have checked it, --allow-listener kills it anyway"
        )),
        Some(map) => map.get(&pid).map(|ports| {
            let ports: Vec<String> = ports.iter().map(u16::to_string).collect();
            format!(
                "{name} (PID {pid}) answers on port {}: a scored service listens too, and the two are not told \
                 apart by that. If it is the red team's, --allow-listener kills it anyway",
                ports.join(", ")
            )
        }),
    }
}

pub(crate) fn same_image(judged: Option<&str>, now: Option<&str>) -> bool {
    matches!((judged, now), (Some(a), Some(b)) if norm(a) == norm(b))
}

#[cfg(target_os = "windows")]
fn resolved_image(pid: u32) -> Option<String> {
    let raw = hemostat_sensor_win::overview::image_path(pid)?;
    if !local(&norm(&raw)) {
        return Some(raw);
    }
    Some(std::fs::canonicalize(&raw).map_or(raw, |p| p.display().to_string()))
}

#[cfg(target_os = "windows")]
fn system_dirs() -> Vec<String> {
    let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_string());
    let mut out: Vec<String> = Vec::new();
    for base in [root.as_str(), r"C:\Windows"] {
        for sub in ["System32", "SysWOW64"] {
            let d = format!(r"{base}\{sub}");
            let n = norm(&std::fs::canonicalize(&d).map_or(d, |p| p.display().to_string()));
            if !out.contains(&n) {
                out.push(n);
            }
        }
    }
    out
}

#[cfg(target_os = "windows")]
fn kill_facts(pid: u32) -> KillFacts {
    use hemostat_sensor_win::overview;

    let _ = hemostat_sensor_win::modules::enable_debug_privilege();
    let procs = overview::processes().map(|v| v.into_iter().map(|p| (p.pid, p.ppid, p.name)).collect());
    let image = resolved_image(pid);
    let ov = overview::report();
    let listeners = ov.complete().then(|| {
        let mut m: BTreeMap<u32, BTreeSet<u16>> = BTreeMap::new();
        for s in ov.sockets.iter().filter(|s| s.listening()) {
            m.entry(s.pid).or_default().insert(s.port);
        }
        m
    });
    KillFacts { agent: std::process::id(), procs, image, listeners, system_dirs: system_dirs() }
}

#[cfg(target_os = "windows")]
pub(crate) fn kill(args: &[String], _json: bool) -> u8 {
    let Some(i) = args.iter().position(|a| a == "--pid") else {
        eprintln!("hemostat kill --pid <N> [--allow-listener] [--arm]: name the PID to terminate");
        return EXIT_USAGE;
    };
    let Some(pid) = args.get(i + 1).and_then(|v| v.parse::<u32>().ok()) else {
        eprintln!("hemostat kill --pid <N>: <N> must be a PID");
        return EXIT_USAGE;
    };
    if pid <= 4 {
        eprintln!("hemostat kill: refused — PID {pid} is System/Idle and is never killed");
        return EXIT_POLICY;
    }
    let facts = kill_facts(pid);
    if let Some(why) = kill_refusal(pid, &facts, args.iter().any(|a| a == "--allow-listener")) {
        eprintln!("hemostat kill: refused — {}. Nothing was changed", h(&why));
        return EXIT_POLICY;
    }
    let name = facts.procs.iter().flatten().find(|(p, _, _)| *p == pid).map_or("unknown", |(_, _, n)| n.as_str());
    let label = h(&format!("{name}, {}", facts.image.as_deref().unwrap_or("unknown")));
    let armed = args.iter().any(|a| a == "--arm");
    if !armed {
        println!("kill PID {pid} ({label})  —  taskkill /F /PID {pid}");
        println!("  Irreversible: a killed process cannot be restarted. Acquire it first if it is wanted as evidence.");
        println!("\nNothing was changed. Add --arm to apply.");
        return EXIT_DRYRUN;
    }

    if !same_image(facts.image.as_deref(), resolved_image(pid).as_deref()) {
        eprintln!("hemostat kill: refused — PID {pid} no longer runs the image that was checked. Nothing was killed; run it again");
        return EXIT_POLICY;
    }
    match std::process::Command::new(sys32("taskkill.exe")).args(["/F", "/PID", &pid.to_string()]).output() {
        Ok(o) if o.status.success() => {
            crate::win_restore::audit_or_warn(&format!("kill PID {pid} ({label})"));
            println!("killed PID {pid} ({label})");
            EXIT_OK
        }
        Ok(o) => {
            eprintln!("hemostat kill: taskkill failed: {}", String::from_utf8_lossy(&o.stdout).trim());
            EXIT_ENFORCER
        }
        Err(e) => {
            eprintln!("hemostat kill: could not run taskkill: {e}");
            EXIT_ENFORCER
        }
    }
}

pub(crate) const QUARANTINE_DIR: &str = "quarantine";

pub(crate) fn quarantine_refusal(spellings: &[String], roots: &[String]) -> Option<String> {
    for s in spellings {
        let n = norm(s);
        if !local(&n) {
            return Some(format!("{s} is not a path on a local drive"));
        }
        if let Some(r) = roots.iter().find(|r| under(&n, r)) {
            return Some(format!(
                "{s} is under {r}, a system, program or protected directory; moving it could break the box"
            ));
        }
    }
    None
}

#[cfg(target_os = "windows")]
fn protected_roots() -> Vec<String> {
    let env = |k: &str| std::env::var(k).ok();
    let mut dirs: Vec<String> = [
        env("SystemRoot"),
        Some(r"C:\Windows".into()),
        env("ProgramFiles"),
        env("ProgramFiles(x86)"),
        env("ProgramW6432"),
        Some(r"C:\Program Files".into()),
        Some(r"C:\Program Files (x86)".into()),
    ]
    .into_iter()
    .flatten()
    .collect();
    for pd in [env("ProgramData"), Some(r"C:\ProgramData".into())].into_iter().flatten() {
        dirs.push(format!(r"{pd}\Datadog"));
        dirs.push(format!(r"{pd}\hemostat"));
    }
    let mut out: Vec<String> = Vec::new();
    for d in dirs {
        let n = norm(&std::fs::canonicalize(&d).map_or(d, |p| p.display().to_string()));
        if !n.is_empty() && !out.contains(&n) {
            out.push(n);
        }
    }
    out
}

#[cfg(target_os = "windows")]
pub(crate) fn quarantine(args: &[String], path: &str, _json: bool) -> u8 {
    use std::os::windows::fs::MetadataExt as _;

    const REPARSE_POINT: u32 = 0x400;
    let p = std::path::Path::new(path);

    match std::fs::symlink_metadata(p) {
        Ok(md) if md.is_file() && md.file_attributes() & REPARSE_POINT == 0 => {}
        Ok(_) => {
            eprintln!(
                "hemostat quarantine: {} is not a regular file (a link, a directory or a device); nothing to quarantine",
                h(path)
            );
            return EXIT_USAGE;
        }
        Err(_) => {
            eprintln!("hemostat quarantine: {} is not a file (nothing to quarantine)", h(path));
            return EXIT_USAGE;
        }
    }

    let dir_of = match p.parent() {
        Some(d) if !d.as_os_str().is_empty() => d,
        _ => std::path::Path::new("."),
    };
    let spellings = match (std::fs::canonicalize(p), std::fs::canonicalize(dir_of), p.file_name()) {
        (Ok(full), Ok(dir), Some(leaf)) => vec![full.display().to_string(), dir.join(leaf).display().to_string()],
        _ => {
            eprintln!(
                "hemostat quarantine: refused — {} could not be resolved, so it cannot be shown to be outside a \
                 system directory. Nothing was changed",
                h(path)
            );
            return EXIT_POLICY;
        }
    };
    if let Some(why) = quarantine_refusal(&spellings, &protected_roots()) {
        eprintln!("hemostat quarantine: refused — {}. Nothing was changed", h(&why));
        return EXIT_POLICY;
    }
    let base = p.file_name().and_then(|n| n.to_str()).unwrap_or("file");
    let uniq = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
    let dest_name = format!("{base}.{uniq}.quarantined");
    let dest = crate::win_private::root().join(QUARANTINE_DIR).join(&dest_name);
    let dest_s = h(&dest.display().to_string());
    let path_h = h(path);

    let armed = crate::win_wmi::is_armed(args, path);
    if !armed {
        println!("quarantine {path_h}  ->  {dest_s}");
        println!("  undo: move it back (the .orig sidecar records the original path)");
        if let Err(e) = crate::win_private::verify(&[QUARANTINE_DIR]) {
            println!("  REFUSED when armed: {}", h(&e));
        }
        println!("\nNothing was changed. Add --arm to apply.");
        return EXIT_DRYRUN;
    }

    let dir = match crate::win_private::ensure(&[QUARANTINE_DIR]) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("hemostat quarantine: {}. Nothing was changed", h(&e));
            return EXIT_FAILED;
        }
    };
    let dest = dir.join(&dest_name);
    if dest.exists() {
        eprintln!("hemostat quarantine: {dest_s} already exists; nothing was changed. Run it again");
        return EXIT_FAILED;
    }

    let moved = std::fs::rename(path, &dest).or_else(|_| {
        std::fs::copy(path, &dest).and_then(|_| std::fs::remove_file(path)).map(|_| ())
    });
    match moved {
        Ok(()) => {
            let _ = crate::win_private::write_atomic(&dir, &format!("{dest_name}.orig"), path.as_bytes());
            crate::win_restore::audit_or_warn(&format!("quarantine {} -> {}", path, dest.display()));
            println!("quarantined {path_h}");
            println!("  vault: {dest_s}");
            println!("  undo: move \"{dest_s}\" \"{path_h}\"");
            EXIT_OK
        }
        Err(e) => {
            eprintln!("hemostat quarantine: could not move {path_h}: {e}");
            EXIT_ENFORCER
        }
    }
}

pub(crate) fn is_system_task(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    l.contains(r"\microsoft\") || l.starts_with("microsoft\\")
}

pub(crate) const REMOVED_TASKS_DIR: &str = "removed-tasks";

pub(crate) fn task_file_stem(name: &str) -> String {
    let safe: String = name
        .trim_start_matches('\\')
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') { c } else { '_' })
        .collect();
    let safe: String = safe.trim_matches('.').chars().take(64).collect();
    let tag = crate::win_binvault::sha256_hex(name.as_bytes());
    format!("{}-{}", if safe.is_empty() { "task" } else { safe.as_str() }, tag.get(..8).unwrap_or(&tag))
}

#[cfg(target_os = "windows")]
fn schtasks() -> String {
    sys32("schtasks.exe")
}

#[cfg(target_os = "windows")]
pub(crate) fn remove_task(args: &[String], name: &str, _json: bool) -> u8 {
    if is_system_task(name) {
        eprintln!("hemostat remediate: refused — `{name}` is a Microsoft/system task and is never removed");
        return EXIT_POLICY;
    }

    let q = std::process::Command::new(schtasks()).args(["/query", "/tn", name, "/xml", "ONE"]).output();
    let xml = match q {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).into_owned(),
        _ => {
            eprintln!("hemostat remediate: scheduled task `{name}` not found");
            return EXIT_POLICY;
        }
    };

    let armed = crate::win_wmi::is_armed(args, name);
    let file = format!("{}.xml", task_file_stem(name));
    let xml_path = crate::win_private::root().join(REMOVED_TASKS_DIR).join(&file);
    let name_h = h(name);
    let xml_s = h(&xml_path.display().to_string());
    if !armed {
        println!("remove scheduled task `{name_h}`  —  schtasks /delete /tn \"{name_h}\" /f");
        println!("  its XML is exported to {xml_s} first, so it is reversible:");
        println!("  undo: schtasks /create /tn \"{name_h}\" /xml \"{xml_s}\"");
        if let Err(e) = crate::win_private::verify(&[REMOVED_TASKS_DIR]) {
            println!("  REFUSED when armed: {}", h(&e));
        }
        println!("\nNothing was changed. Add --arm to apply.");
        return EXIT_DRYRUN;
    }

    let dir = match crate::win_private::ensure(&[REMOVED_TASKS_DIR]) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("hemostat remediate: {}. Nothing was changed", h(&e));
            return EXIT_FAILED;
        }
    };
    if let Err(e) = crate::win_private::write_atomic(&dir, &file, xml.as_bytes()) {
        eprintln!("hemostat remediate: could not export the task XML to {xml_s}: {}", h(&e));
        return EXIT_ENFORCER;
    }

    if let Err(e) = crate::win_restore::audit(&format!("remove-task {} (xml: {})", name, xml_path.display())) {
        eprintln!("hemostat remediate: the fix log could not be written ({e}), so `{name_h}` was not removed");
        return EXIT_ENFORCER;
    }
    match std::process::Command::new(schtasks()).args(["/delete", "/tn", name, "/f"]).output() {
        Ok(o) if o.status.success() => {
            println!("removed scheduled task `{name_h}`");
            println!("  undo: schtasks /create /tn \"{name_h}\" /xml \"{xml_s}\"");
            EXIT_OK
        }
        Ok(o) => {
            crate::win_restore::audit_or_warn(&format!("remove-task {name}: schtasks /delete failed, not removed"));
            eprintln!("hemostat remediate: schtasks /delete failed: {}", h(String::from_utf8_lossy(&o.stderr).trim()));
            EXIT_ENFORCER
        }
        Err(e) => {
            crate::win_restore::audit_or_warn(&format!("remove-task {name}: schtasks did not run, not removed"));
            eprintln!("hemostat remediate: could not run schtasks: {e}");
            EXIT_ENFORCER
        }
    }
}

pub(crate) const RUN_KEYS: &[&str] = &[
    r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
    r"HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    r"HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
    r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
    r"HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce",
];

pub(crate) fn parse_run_value(out: &str, name: &str) -> Option<(String, String)> {
    for line in out.lines() {
        let t = line.trim_start();
        let Some(rest) = t.strip_prefix(name) else { continue };
        let rest = rest.trim_start();
        let mut parts = rest.splitn(2, char::is_whitespace);
        let ty = parts.next().unwrap_or("").trim();
        if !ty.starts_with("REG_") {
            continue;
        }
        let data = parts.next().unwrap_or("").trim();
        return Some((ty.to_string(), data.to_string()));
    }
    None
}

pub(crate) fn run_is_protected(name: &str, data: &str) -> bool {
    let n = name.to_ascii_lowercase();
    let d = data.to_ascii_lowercase();
    ["datadog", "ddagent", "dd-agent"].iter().any(|p| n.contains(p) || d.contains(p))
}

pub(crate) fn split_run_key(key: &str) -> Option<(&'static str, &str)> {
    if let Some(sub) = key.strip_prefix(r"HKLM\") {
        return Some(("HKEY_LOCAL_MACHINE", sub));
    }
    key.strip_prefix(r"HKCU\").map(|sub| ("HKEY_CURRENT_USER", sub))
}

pub(crate) fn reg_type_number(ty: &str) -> Option<u32> {
    Some(match ty {
        "REG_NONE" => 0,
        "REG_SZ" => 1,
        "REG_EXPAND_SZ" => 2,
        "REG_BINARY" => 3,
        "REG_DWORD" => 4,
        "REG_DWORD_BIG_ENDIAN" => 5,
        "REG_MULTI_SZ" => 7,
        "REG_QWORD" => 11,
        _ => return None,
    })
}

pub(crate) fn reg_string(ty: &str, data: &[u8]) -> Option<String> {
    if ty != "REG_SZ" && ty != "REG_EXPAND_SZ" {
        return None;
    }
    let (pairs, _odd) = data.as_chunks::<2>();
    let units: Vec<u16> = pairs.iter().copied().map(u16::from_le_bytes).take_while(|u| *u != 0).collect();
    Some(String::from_utf16_lossy(&units))
}

fn reg_sz_text(data: &[u8]) -> Option<String> {
    let (pairs, odd) = data.as_chunks::<2>();
    if !odd.is_empty() {
        return None;
    }
    let units: Vec<u16> = pairs.iter().copied().map(u16::from_le_bytes).collect();
    let (last, body) = units.split_last()?;
    if *last != 0 || body.contains(&0) {
        return None;
    }
    let text = String::from_utf16(body).ok()?;
    (!text.chars().any(|c| c.is_control() || matches!(c, '\u{2028}' | '\u{2029}' | '\u{FEFF}'))).then_some(text)
}

fn reg_escape(s: &str) -> String {
    s.replace('\\', r"\\").replace('"', "\\\"")
}

fn reg_hex(prefix: &str, data: &[u8]) -> String {
    let mut out = String::from(prefix);
    let mut width = prefix.chars().count();
    for (i, b) in data.iter().enumerate() {
        out.push_str(&format!("{b:02x}"));
        width += 2;
        if i + 1 < data.len() {
            out.push(',');
            width += 1;
            if width >= 76 {
                out.push_str("\\\r\n  ");
                width = 2;
            }
        }
    }
    out
}

pub(crate) fn single_value_reg(key: &str, name: &str, kind: u32, data: &[u8]) -> Result<String, String> {
    let (root, sub) = split_run_key(key).ok_or_else(|| format!("{key} is not an HKLM or HKCU key"))?;
    if sub.is_empty() || sub.contains(['[', ']']) || sub.chars().any(char::is_control) {
        return Err(format!("{key} cannot be written as a .reg key line"));
    }
    if name.is_empty() || name.chars().any(char::is_control) {
        return Err("the value's name is empty or holds a control character, which a .reg file cannot carry".into());
    }
    let value = format!("\"{}\"", reg_escape(name));
    let line = match kind {
        1 => match reg_sz_text(data) {
            Some(text) => format!("{value}=\"{}\"", reg_escape(&text)),
            None => reg_hex(&format!("{value}=hex(1):"), data),
        },
        3 => reg_hex(&format!("{value}=hex:"), data),
        4 => match <[u8; 4]>::try_from(data) {
            Ok(dword) => format!("{value}=dword:{:08x}", u32::from_le_bytes(dword)),
            Err(_) => reg_hex(&format!("{value}=hex(4):"), data),
        },
        k => reg_hex(&format!("{value}=hex({k:x}):"), data),
    };
    Ok(format!("Windows Registry Editor Version 5.00\r\n\r\n[{root}\\{sub}]\r\n{line}\r\n\r\n"))
}

pub(crate) fn reg_file_bytes(text: &str) -> Vec<u8> {
    let mut out = vec![0xFF, 0xFE];
    out.extend(text.encode_utf16().flat_map(u16::to_le_bytes));
    out
}

pub(crate) fn run_undo_file_name(name: &str) -> String {
    let stem: String = name
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
        .take(40)
        .collect();
    format!("run-{stem}.reg")
}

pub(crate) fn reg_import_command(path: &str) -> Option<String> {
    path.chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '\\' | ':' | '.' | '_' | '-' | ' '))
        .then(|| format!("reg import \"{path}\""))
}

#[cfg(target_os = "windows")]
pub(crate) fn remove_run(args: &[String], name: &str, _json: bool) -> u8 {
    if name.trim().is_empty() {
        eprintln!("hemostat remediate --remove-run <name> [--arm]: name the Run value to remove");
        return EXIT_USAGE;
    }
    let reg = sys32("reg.exe");
    let mut found = None;
    for key in RUN_KEYS {
        if let Ok(o) = std::process::Command::new(&reg).args(["query", key, "/v", name]).output() {
            if o.status.success() {
                if let Some((ty, data)) = parse_run_value(&String::from_utf8_lossy(&o.stdout), name) {
                    found = Some((*key, ty, data));
                    break;
                }
            }
        }
    }
    let Some((key, ty, data)) = found else {
        eprintln!("hemostat remediate --remove-run: no Run value named `{name}` under the HKLM/HKCU Run keys");
        return EXIT_POLICY;
    };
    if run_is_protected(name, &data) {
        eprintln!("hemostat remediate --remove-run: refused — `{}` -> {} is a DataDog value (protected, packet rule 14)", h(name), h(&data));
        return EXIT_POLICY;
    }

    let kept = run_value_bytes(key, name)
        .and_then(|d| d.ok_or_else(|| "it was gone by the time its data was read".to_string()))
        .and_then(|raw| {
            let kind = reg_type_number(&ty).ok_or_else(|| format!("its type, {ty}, is not one an undo can write back"))?;
            Ok((single_value_reg(key, name, kind, &raw)?, raw))
        });
    let (text, raw) = match kept {
        Ok(k) => k,
        Err(e) => {
            eprintln!(
                "hemostat remediate --remove-run: refused — `{}` cannot be kept exactly for its undo ({}), so it is not removed",
                h(name),
                h(&e)
            );
            return EXIT_POLICY;
        }
    };
    let shown = reg_string(&ty, &raw).unwrap_or_else(|| data.clone());
    if run_is_protected(name, &shown) {
        eprintln!("hemostat remediate --remove-run: refused — `{}` -> {} is a DataDog value (protected, packet rule 14)", h(name), h(&shown));
        return EXIT_POLICY;
    }
    let base = run_undo_root().display().to_string();
    let file_name = run_undo_file_name(name);
    if reg_import_command(&format!(r"{base}\removed-run-0\{file_name}")).is_none() {
        eprintln!(
            "hemostat remediate --remove-run: refused — its undo would be kept under {}, a path a shell could read as \
             something else, so it is not removed",
            h(&base)
        );
        return EXIT_POLICY;
    }
    let (name_h, data_h, key_h) = (h(name), h(&shown), h(key));

    let armed = crate::win_wmi::is_armed(args, name);
    if !armed {
        println!("remove Run entry `{name_h}` ({key_h}, {ty})  ->  {data_h}");
        println!("  its type and exact data ({} bytes) are kept first in an admin-only .reg file, so it is reversible:", raw.len());
        println!("  undo: reg import \"{}\\removed-run-<time>\\{file_name}\"  (the file is named when armed)", h(&base));
        println!("\nNothing was changed. Add --arm to apply.");
        return EXIT_DRYRUN;
    }
    let file = match keep_run_undo(&file_name, &text) {
        Ok(f) => f.display().to_string(),
        Err(e) => {
            eprintln!("hemostat remediate --remove-run: its undo could not be kept, so nothing was removed: {}", h(&e));
            return EXIT_ENFORCER;
        }
    };
    let Some(undo) = reg_import_command(&file) else {
        eprintln!("hemostat remediate --remove-run: its undo was kept at {}, a path a shell could misread, so nothing was removed", h(&file));
        return EXIT_ENFORCER;
    };

    let moved = match run_value_bytes(key, name) {
        Ok(Some(now)) if now == raw => None,
        Ok(Some(_)) => Some("changed after it was read".to_string()),
        Ok(None) => Some("was removed by something else after it was read".to_string()),
        Err(e) => Some(format!("could not be read again ({e})")),
    };
    if let Some(what) = moved {
        eprintln!(
            "hemostat remediate --remove-run: `{name_h}` {}, so nothing was removed (the copy kept in {} is of the \
             value as it was first read)",
            h(&what),
            h(&file)
        );
        return EXIT_POLICY;
    }

    if let Err(e) = crate::win_restore::audit(&format!("remove-run {name:?} ({key}, {ty}) -> {shown:?}; undo: {undo}")) {
        eprintln!(
            "hemostat remediate --remove-run: the fix log could not be written ({}), so `{name_h}` was not removed (its undo is kept in {})",
            h(&e.to_string()),
            h(&file)
        );
        return EXIT_ENFORCER;
    }
    match std::process::Command::new(&reg).args(["delete", key, "/v", name, "/f"]).output() {
        Ok(o) if o.status.success() => {
            println!("removed Run entry `{name_h}` ({key_h})");
            println!("  kept: {}", h(&file));
            println!("  undo: {}", h(&undo));
            EXIT_OK
        }
        Ok(o) => {
            crate::win_restore::audit_or_warn(&format!("remove-run {name}: reg delete failed, not removed"));
            eprintln!("hemostat remediate --remove-run: reg delete failed: {}", h(String::from_utf8_lossy(&o.stderr).trim()));
            EXIT_ENFORCER
        }
        Err(e) => {
            crate::win_restore::audit_or_warn(&format!("remove-run {name}: reg did not run, not removed"));
            eprintln!("hemostat remediate --remove-run: could not run reg: {e}");
            EXIT_ENFORCER
        }
    }
}

#[cfg(target_os = "windows")]
const RUN_VALUE_CAP: usize = 1 << 20;

#[cfg(target_os = "windows")]
fn run_undo_root() -> std::path::PathBuf {
    std::path::PathBuf::from(std::env::var("ProgramData").unwrap_or_else(|_| r"C:\ProgramData".to_string())).join("hemostat")
}

#[cfg(target_os = "windows")]
fn run_value_bytes(key: &str, name: &str) -> Result<Option<Vec<u8>>, String> {
    use hemostat_sensor_win::reg::{self, Hive};
    let (root, sub) = split_run_key(key).ok_or_else(|| format!("{key} is not an HKLM or HKCU key"))?;
    let hive = if root == "HKEY_LOCAL_MACHINE" { Hive::Machine } else { Hive::User };
    reg::binary(hive, sub, name, RUN_VALUE_CAP).map_err(|rc| match rc {

        234 => format!("it holds more than {RUN_VALUE_CAP} bytes"),
        rc => format!("its data could not be read (error {rc})"),
    })
}

#[cfg(target_os = "windows")]
fn keep_run_undo(file_name: &str, text: &str) -> Result<std::path::PathBuf, String> {
    use hemostat_sensor_win::acl;
    use std::io::Write as _;
    use std::os::windows::fs::MetadataExt as _;

    const REPARSE_POINT: u32 = 0x400;

    let base = run_undo_root();
    let base_s = base.to_str().ok_or("the hemostat directory's path is not valid UTF-16 text")?;
    match std::fs::symlink_metadata(&base) {
        Ok(md) if md.is_dir() && md.file_attributes() & REPARSE_POINT == 0 => {}
        Ok(_) => return Err(format!("{base_s} is not a plain directory (a link, a junction or a file)")),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => acl::create_private_dir(base_s)?,
        Err(e) => return Err(format!("cannot examine {base_s}: {e}")),
    }
    let stamp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
    let dir = base.join(format!("removed-run-{stamp}"));
    acl::create_private_dir(dir.to_str().ok_or("the undo directory's path is not valid UTF-16 text")?)?;
    let file = dir.join(file_name);
    let bytes = reg_file_bytes(text);
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&file)
        .and_then(|mut f| {
            f.write_all(&bytes)?;
            f.sync_all()
        })
        .map_err(|e| format!("cannot write {}: {e}", file.display()))?;

    match crate::win_private::read_regular(&file, bytes.len() as u64) {
        Ok(back) if back == bytes => Ok(file),
        Ok(_) => Err(format!("{} does not read back as it was written", file.display())),
        Err(e) => Err(format!("cannot read {} back: {e}", file.display())),
    }
}
