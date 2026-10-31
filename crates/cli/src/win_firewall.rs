#![allow(dead_code)]

#[cfg(target_os = "windows")]
use crate::golden::{self, ScoredService};
#[cfg(target_os = "windows")]
use crate::{EXIT_DRYRUN, EXIT_ENFORCER, EXIT_OK, EXIT_POLICY, EXIT_USAGE};

pub(crate) fn marker(port: u16) -> String {
    format!("mahoraga-allow-{port}")
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NamedRule {

    pub(crate) enabled: String,

    pub(crate) direction: String,

    pub(crate) action: String,

    pub(crate) protocol: String,

    pub(crate) local_port: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Named {

    Absent,

    Allows,

    NotOurs(String),
}

pub(crate) fn named_rules_script(name: &str) -> String {
    format!(
        r#"$rules = @(Get-NetFirewallRule -DisplayName '{name}' -ErrorAction SilentlyContinue)
foreach ($r in $rules) {{
  $pf = @($r | Get-NetFirewallPortFilter -ErrorAction Stop)
  $proto = ($pf | ForEach-Object {{ "$($_.Protocol)" }}) -join ','
  $ports = ($pf | ForEach-Object {{ ($_.LocalPort | ForEach-Object {{ "$_" }}) -join ',' }}) -join ';'
  Write-Output ("rule|" + $r.Enabled + "|" + $r.Direction + "|" + $r.Action + "|" + $proto + "|" + $ports)
}}
Write-Output ("count|" + $rules.Count)"#
    )
}

pub(crate) fn parse_named_rules(out: &str) -> Result<Vec<NamedRule>, String> {
    let mut rules = Vec::new();
    let mut count = None;
    for line in out.lines().map(str::trim).filter(|l| !l.is_empty()) {
        if let Some(rest) = line.strip_prefix("rule|") {
            let fields: Vec<&str> = rest.split('|').collect();
            let [enabled, direction, action, protocol, local_port] = fields.as_slice() else {
                return Err(format!("a rule line the check does not write: {line}"));
            };
            rules.push(NamedRule {
                enabled: (*enabled).to_string(),
                direction: (*direction).to_string(),
                action: (*action).to_string(),
                protocol: (*protocol).to_string(),
                local_port: (*local_port).to_string(),
            });
        } else if let Some(n) = line.strip_prefix("count|") {
            count = n.trim().parse::<usize>().ok();
        }
    }
    match count {
        Some(n) if n == rules.len() => Ok(rules),
        Some(n) => Err(format!("the check printed {} of the {n} rule(s) it counted", rules.len())),
        None => Err("the check did not finish".to_string()),
    }
}

pub(crate) fn judge_named(port: u16, rules: &[NamedRule]) -> Named {
    let want = port.to_string();
    for r in rules {
        let mut wrong: Vec<String> = Vec::new();
        if !r.enabled.eq_ignore_ascii_case("True") {
            wrong.push("disabled".into());
        }
        if !r.direction.eq_ignore_ascii_case("Inbound") {
            wrong.push(format!("{} rather than inbound", r.direction));
        }
        if !r.action.eq_ignore_ascii_case("Allow") {
            wrong.push(format!("a {} rule rather than an Allow", r.action));
        }
        if !r.protocol.eq_ignore_ascii_case("TCP") {
            wrong.push(format!("for protocol {} rather than TCP", r.protocol));
        }
        if r.local_port != want {
            wrong.push(format!("on local port {} rather than {port} alone", r.local_port));
        }
        if !wrong.is_empty() {
            return Named::NotOurs(format!("a rule named {} is {}", marker(port), wrong.join(", ")));
        }
    }
    if rules.is_empty() {
        Named::Absent
    } else {
        Named::Allows
    }
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
fn named_rules(port: u16) -> Result<Named, String> {
    let out = ps(&named_rules_script(&marker(port)))?;
    Ok(judge_named(port, &parse_named_rules(&out)?))
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

    match named_rules(port) {
        Ok(Named::Absent) => {}
        Ok(Named::Allows) => {
            eprintln!(
                "hemostat firewall: tcp/{port} is already allowed by a mahoraga rule ({name}: enabled, inbound, \
                 Allow, TCP {port}); nothing to do"
            );
            return EXIT_POLICY;
        }
        Ok(Named::NotOurs(why)) => {
            eprintln!(
                "hemostat firewall: refused — {}. A rule that carries this tool's name is not trusted for it: look \
                 at it (Get-NetFirewallRule -DisplayName '{name}'), remove or rename it by hand, then run this \
                 again. Nothing was changed",
                crate::render::h(&why)
            );
            return EXIT_POLICY;
        }
        Err(e) => {
            eprintln!(
                "hemostat firewall: the rules named {name} could not be read ({}), so whether one is there, and \
                 what it does, is unknown. Nothing was changed",
                crate::render::h(&e)
            );
            return EXIT_ENFORCER;
        }
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

        Ok(_) => match named_rules(port) {
            Ok(Named::Allows) => {

                crate::win_restore::audit_or_warn(&format!("firewall allow tcp/{port} ({name})"));
                println!("allowed inbound tcp/{port} through Windows Firewall (rule `{name}`)");
                println!("  undo: Remove-NetFirewallRule -DisplayName '{name}'");
                EXIT_OK
            }
            Ok(Named::Absent) => {
                eprintln!("hemostat firewall: added the rule but could not find it afterward — the change did not take");
                EXIT_ENFORCER
            }
            Ok(Named::NotOurs(why)) => {
                eprintln!(
                    "hemostat firewall: the rule was added, but {} — the port may still be shut. Look at the rules \
                     named {name} (Get-NetFirewallRule -DisplayName '{name}')",
                    crate::render::h(&why)
                );
                EXIT_ENFORCER
            }
            Err(e) => {
                eprintln!(
                    "hemostat firewall: the rule was added but could not be read back ({}); look at the rules named \
                     {name} (Get-NetFirewallRule -DisplayName '{name}')",
                    crate::render::h(&e)
                );
                EXIT_ENFORCER
            }
        },
        Err(e) => {
            eprintln!("hemostat firewall: New-NetFirewallRule failed: {e}");
            EXIT_ENFORCER
        }
    }
}
