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
pub(crate) fn start_and_verify(name: &str) -> Result<(), String> {
    std::process::Command::new(sc_path())
        .args(["start", name])
        .output()
        .map_err(|e| format!("could not run `sc start {name}`: {e}"))?;
    for _ in 0..12 {
        if service_running(name) == Some(true) {
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
    Err(format!("{name} did not reach RUNNING after `sc start` — check `sc query {name}` and the Event Log"))
}
