#![allow(dead_code)]

pub(crate) fn parse_running(out: &str) -> Option<bool> {
    out.lines().find(|l| l.contains("STATE")).map(|l| l.contains("RUNNING"))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WinStep {

    Up,

    Start,

    NeedsHuman,

    Unknown,
}

pub(crate) fn win_step(running: Option<bool>, port_closed: Option<bool>) -> WinStep {
    match (running, port_closed) {
        (Some(true), Some(true)) => WinStep::NeedsHuman,
        (Some(false), _) | (None, Some(true)) => WinStep::Start,
        (Some(true), Some(false) | None) | (None, Some(false)) => WinStep::Up,
        (None, None) => WinStep::Unknown,
    }
}

pub(crate) fn back_after_start(port: Option<u16>, port_open: Option<bool>) -> bool {
    port.is_none() || port_open == Some(true)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Strike {

    StartFailed,

    StartedPortClosed,

    RunningPortClosed,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Streak {
    start_failed: u32,
    started_port_closed: u32,
    running_port_closed: u32,
}

impl Streak {

    pub(crate) fn strike(&mut self, why: Strike) {
        let n = match why {
            Strike::StartFailed => &mut self.start_failed,
            Strike::StartedPortClosed => &mut self.started_port_closed,
            Strike::RunningPortClosed => &mut self.running_port_closed,
        };
        *n = n.saturating_add(1);
    }

    pub(crate) fn total(&self) -> u32 {
        self.start_failed.saturating_add(self.started_port_closed).saturating_add(self.running_port_closed)
    }

    pub(crate) fn backed_off_why(&self, port: &str, hint: &str) -> String {
        let n = self.total();
        match (self.start_failed, self.started_port_closed, self.running_port_closed) {
            (1.., 0, 0) => format!("sc start failed on each of the last {n} tries — needs a human"),
            (0, 1.., 0) => format!(
                "sc start brought it to RUNNING on each of the last {n} tries, but port {port} did not answer — \
                 needs a human: {hint}"
            ),
            (0, 0, 1..) => format!(
                "RUNNING with port {port} closed on each of the last {n} checks, so no start was tried (it would \
                 change nothing) — needs a human: {hint}"
            ),
            (failed, started, running) => {
                let mut parts = Vec::new();
                if failed > 0 {
                    parts.push(format!("sc start failed {failed} time(s)"));
                }
                if started > 0 {
                    parts.push(format!("it reached RUNNING {started} time(s) without port {port} answering"));
                }
                if running > 0 {
                    parts.push(format!("it was RUNNING with port {port} closed {running} time(s), so no start was tried"));
                }
                if parts.is_empty() {
                    return "needs a human".to_string();
                }
                format!("the last {n} ticks did not bring it back: {} — needs a human: {hint}", parts.join("; "))
            }
        }
    }
}

pub(crate) fn port_closed_hint(probe: crate::golden::Probe) -> &'static str {
    use crate::golden::Probe;
    match probe {
        Probe::WinRm => "its listener may be gone: `winrm enumerate winrm/config/listener`, then `winrm quickconfig`",
        Probe::Iis => "the site or its app pool may be stopped: `Get-Website`, then `Start-Website`",
        Probe::Smb => "check `Get-SmbServerConfiguration` and what holds 445",
        Probe::Telnet => "check what the Telnet server is bound to",
        _ => "check what the service is bound to",
    }
}

pub(crate) const STOCK_IMAGES: &[(&str, &str, Option<&str>)] = &[
    ("NTDS", "lsass.exe", None),
    ("DNS", "dns.exe", None),
    ("TlntSvr", "tlntsvr.exe", None),
    ("WinRM", "svchost.exe", Some("WsmSvc.dll")),
    ("LanmanServer", "svchost.exe", Some("srvsvc.dll")),
    ("W3SVC", "svchost.exe", Some(r"inetsrv\iisw3adm.dll")),
];

pub(crate) fn parse_binary_path(out: &str) -> Option<String> {
    out.lines()
        .find_map(|l| l.trim_start().strip_prefix("BINARY_PATH_NAME"))
        .and_then(|rest| rest.split_once(':'))
        .map(|(_, v)| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

fn image_of(cmd: &str) -> &str {
    let cmd = cmd.trim();
    match cmd.strip_prefix('"') {
        Some(rest) => rest.split('"').next().unwrap_or(rest),
        None => cmd.split_whitespace().next().unwrap_or(cmd),
    }
}

fn in_system32(path: &str, roots: &[String], rel: &str) -> bool {
    let p = crate::win_respond::norm(path);
    let tail = format!(r"\system32\{}", rel.to_ascii_lowercase());
    ["%systemroot%", "%windir%"].iter().map(|r| (*r).to_string()).chain(roots.iter().cloned()).any(|r| p == format!("{r}{tail}"))
}

pub(crate) fn image_refusal(name: &str, binary: &str, dlls: &[String], roots: &[String]) -> Option<String> {
    let Some(&(_, exe, dll)) = STOCK_IMAGES.iter().find(|(s, _, _)| s.eq_ignore_ascii_case(name)) else {
        return Some(format!("{name} has no stock binary on record here, so what a start would run cannot be checked"));
    };
    if !in_system32(image_of(binary), roots, exe) {
        return Some(format!("it is configured to run `{binary}`, not System32\\{exe}"));
    }
    match dll {

        None => None,
        Some(dll) if dlls.is_empty() => {
            Some(format!("it names no ServiceDll, where svchost.exe is to load System32\\{dll} for it"))
        }
        Some(dll) => dlls
            .iter()
            .find(|d| !in_system32(d, roots, dll))
            .map(|d| format!("its ServiceDll is `{d}`, not System32\\{dll}")),
    }
}

pub(crate) fn one_line(stdout: &[u8], stderr: &[u8]) -> String {
    let both = format!("{} {}", String::from_utf8_lossy(stdout), String::from_utf8_lossy(stderr));
    let flat = both.split_whitespace().collect::<Vec<_>>().join(" ");
    if flat.is_empty() {
        return "nothing".to_string();
    }
    match flat.char_indices().nth(400) {
        Some((at, _)) => format!("{}…", flat.get(..at).unwrap_or(&flat)),
        None => flat,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum StartError {

    NotStock(String),

    Failed(String),
}

#[cfg(target_os = "windows")]
fn sc_path() -> std::path::PathBuf {
    let sysroot = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_string());
    std::path::PathBuf::from(format!(r"{sysroot}\System32\sc.exe"))
}

#[cfg(target_os = "windows")]
pub(crate) fn service_running(name: &str) -> Option<bool> {
    let out = std::process::Command::new(sc_path()).args(["query", name]).output().ok()?;
    parse_running(&String::from_utf8_lossy(&out.stdout))
}

#[cfg(target_os = "windows")]
fn windows_roots() -> Vec<String> {
    let env = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_string());
    let mut out = vec![crate::win_respond::norm(&env)];
    let default = crate::win_respond::norm(r"C:\Windows");
    if !out.contains(&default) {
        out.push(default);
    }
    out
}

#[cfg(target_os = "windows")]
fn configured_binary(name: &str) -> Result<String, String> {
    let out = std::process::Command::new(sc_path())
        .args(["qc", name, "8192"])
        .output()
        .map_err(|e| format!("could not run `sc qc {name}`: {e}"))?;
    parse_binary_path(&String::from_utf8_lossy(&out.stdout))
        .ok_or_else(|| format!("`sc qc {name}` named no binary (sc said: {})", one_line(&out.stdout, &out.stderr)))
}

#[cfg(target_os = "windows")]
fn service_dlls(name: &str) -> Result<Vec<String>, String> {
    use hemostat_sensor_win::reg;
    let key = format!(r"SYSTEM\CurrentControlSet\Services\{name}");
    let mut out = Vec::new();
    for sub in [format!(r"{key}\Parameters"), key] {
        match reg::hklm_values_read(&sub) {
            Ok(values) => {
                out.extend(values.into_iter().filter(|(n, _)| n.eq_ignore_ascii_case("ServiceDll")).map(|(_, v)| v));
            }
            Err(reg::ABSENT) => {}
            Err(rc) => return Err(format!(r"HKLM\{sub} could not be read (error {rc})")),
        }
    }
    Ok(out)
}

#[cfg(target_os = "windows")]
pub(crate) fn stock_refusal(name: &str) -> Option<String> {
    let binary = match configured_binary(name) {
        Ok(b) => b,
        Err(e) => return Some(format!("what it is configured to run could not be read: {e}")),
    };
    let hosted = STOCK_IMAGES.iter().any(|(s, _, dll)| s.eq_ignore_ascii_case(name) && dll.is_some());
    let dlls = if hosted {
        match service_dlls(name) {
            Ok(d) => d,
            Err(e) => return Some(format!("its ServiceDll could not be read: {e}")),
        }
    } else {
        Vec::new()
    };
    image_refusal(name, &binary, &dlls, &windows_roots())
}

#[cfg(target_os = "windows")]
pub(crate) fn start_and_verify(name: &str) -> Result<(), StartError> {
    if let Some(why) = stock_refusal(name) {
        return Err(StartError::NotStock(why));
    }
    let out = std::process::Command::new(sc_path())
        .args(["start", name])
        .output()
        .map_err(|e| StartError::Failed(format!("could not run `sc start {name}`: {e}")))?;
    for _ in 0..12 {
        if service_running(name) == Some(true) {
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
    Err(StartError::Failed(format!(
        "{name} did not reach RUNNING after `sc start` (sc said: {}) — check `sc query {name}` and the Event Log",
        one_line(&out.stdout, &out.stderr)
    )))
}
