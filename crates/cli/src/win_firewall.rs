#![allow(dead_code)]

#[cfg(target_os = "windows")]
use crate::golden::{self, ScoredService};
#[cfg(target_os = "windows")]
use crate::{EXIT_DRYRUN, EXIT_ENFORCER, EXIT_OK, EXIT_POLICY, EXIT_USAGE};

pub(crate) fn marker(port: u16) -> String {
    format!("mahoraga-allow-{port}")
}

#[cfg(target_os = "windows")]
fn ps(script: &str) -> Result<String, String> {
    let sysroot = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_string());
    let exe = format!(r"{sysroot}\System32\WindowsPowerShell\v1.0\powershell.exe");
    let uniq = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let tmp = std::env::temp_dir().join(format!("hmfw-{}-{uniq}.ps1", std::process::id()));
    std::fs::write(&tmp, script).map_err(|e| format!("could not write the firewall script: {e}"))?;
    let out = std::process::Command::new(exe)
        .args(["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File"])
        .arg(&tmp)
        .output();
    let _ = std::fs::remove_file(&tmp);
    let out = out.map_err(|e| format!("could not run powershell: {e}"))?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
    }
}

#[cfg(target_os = "windows")]
fn audit(what: &str) {
    use std::io::Write as _;

    let Some(dir) = crate::win_private::log_dir(what) else { return };
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(dir.join("fixes.log")) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let _ = writeln!(f, "epoch={now} {what}");
    }
}

#[cfg(target_os = "windows")]
pub(crate) fn firewall_blocked() -> Vec<&'static ScoredService> {
    if !golden::active() {
        return Vec::new();
    }
    let host = std::env::var("COMPUTERNAME").unwrap_or_default();
    let mine = golden::services_for_box(&host);
    let ov = hemostat_sensor_win::overview::report();
    if !ov.available {
        return Vec::new();
    }
    use std::collections::BTreeSet;
    let listening: BTreeSet<u16> =
        ov.sockets.iter().filter(|s| s.world_reachable()).map(|s| s.port).collect();

    let ask: Vec<u16> = mine.iter().filter_map(|s| s.port).filter(|p| listening.contains(p)).collect();
    if ask.is_empty() {
        return Vec::new();
    }
    let blocked = blocked_set(&ask);
    mine.into_iter()
        .filter(|s| s.port.is_some_and(|p| listening.contains(&p) && blocked.contains(&p)))
        .collect()
}

#[cfg(target_os = "windows")]
fn blocked_set(ports: &[u16]) -> std::collections::BTreeSet<u16> {
    use std::collections::BTreeSet;
    let list = ports.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(",");

    let script = format!(
        r#"$def = @(Get-NetFirewallProfile -ErrorAction SilentlyContinue | Where-Object {{ $_.Enabled -eq 'True' -and $_.DefaultInboundAction -eq 'Block' }}).Count -gt 0
$allowPorts = @(Get-NetFirewallRule -Direction Inbound -Enabled True -Action Allow -ErrorAction SilentlyContinue | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue | Where-Object {{ $_.Protocol -eq 'TCP' }} | ForEach-Object {{ "$($_.LocalPort)" }})
$blockPorts = @(Get-NetFirewallRule -Direction Inbound -Enabled True -Action Block -ErrorAction SilentlyContinue | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue | Where-Object {{ $_.Protocol -eq 'TCP' }} | ForEach-Object {{ "$($_.LocalPort)" }})
foreach ($p in @({list})) {{
  $a = ($allowPorts -contains "$p") -or ($allowPorts -contains 'Any')
  $b = ($blockPorts -contains "$p") -or ($blockPorts -contains 'Any')
  $isBlocked = if ($b) {{ $true }} elseif ($a) {{ $false }} elseif ($def) {{ $true }} else {{ $false }}
  Write-Output ("$($p):" + $isBlocked)
}}"#
    );
    let out = match ps(&script) {
        Ok(o) => o,
        Err(_) => return BTreeSet::new(),
    };
    out.lines()
        .filter_map(|l| {
            let (p, b) = l.trim().split_once(':')?;
            (b.eq_ignore_ascii_case("true")).then(|| p.parse::<u16>().ok()).flatten()
        })
        .collect()
}

#[cfg(target_os = "windows")]
pub(crate) fn allow(args: &[String], _json: bool) -> u8 {
    let Some(i) = args.iter().position(|a| a == "--allow") else {
        eprintln!("hemostat firewall --allow <port> [--arm]: name the TCP port to allow inbound");
        return EXIT_USAGE;
    };
    let Some(port) = args.get(i + 1).and_then(|v| v.parse::<u16>().ok()).filter(|p| *p > 0) else {
        eprintln!("hemostat firewall --allow <port>: <port> must be a TCP port number, 1-65535");
        return EXIT_USAGE;
    };
    let name = marker(port);
    let exists = ps(&format!(
        "if (Get-NetFirewallRule -DisplayName '{name}' -ErrorAction SilentlyContinue) {{'yes'}} else {{'no'}}"
    ))
    .unwrap_or_default();
    if exists == "yes" {
        eprintln!("hemostat firewall: tcp/{port} is already allowed by a mahoraga rule ({name}); nothing to do");
        return EXIT_POLICY;
    }

    let armed = args.iter().any(|a| a == "--arm");
    if !armed {
        println!("allow inbound tcp/{port} through Windows Firewall");
        println!("  Add an inbound Allow rule `{name}` for TCP {port} — additive, it cannot lock anyone out.");
        println!("  Note: this fixes a default-deny firewall. If an explicit Block rule is blocking {port}, remove THAT rule — an Allow does not override a Block on Windows.");
        println!("  undo: Remove-NetFirewallRule -DisplayName '{name}'");
        println!("\nNothing was changed. Add --arm to apply.");
        return EXIT_DRYRUN;
    }
    match ps(&format!(
        "New-NetFirewallRule -DisplayName '{name}' -Direction Inbound -Protocol TCP -LocalPort {port} -Action Allow -Profile Any -ErrorAction Stop | Out-Null; 'ok'"
    )) {
        Ok(_) => {
            let ok = ps(&format!(
                "if (Get-NetFirewallRule -DisplayName '{name}' -ErrorAction SilentlyContinue) {{'yes'}} else {{'no'}}"
            ))
            .unwrap_or_default();
            if ok == "yes" {
                audit(&format!("firewall allow tcp/{port} ({name})"));
                println!("allowed inbound tcp/{port} through Windows Firewall (rule `{name}`)");
                println!("  undo: Remove-NetFirewallRule -DisplayName '{name}'");
                EXIT_OK
            } else {
                eprintln!("hemostat firewall: added the rule but could not find it afterward — the change did not take");
                EXIT_ENFORCER
            }
        }
        Err(e) => {
            eprintln!("hemostat firewall: New-NetFirewallRule failed: {e}");
            EXIT_ENFORCER
        }
    }
}
