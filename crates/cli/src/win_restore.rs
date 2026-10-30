use std::collections::{BTreeMap, BTreeSet};

use crate::golden::{self, ScoredService};
use crate::winservice::WinStep;
use crate::{EXIT_DRYRUN, EXIT_ENFORCER, EXIT_OK, EXIT_PARTIAL, EXIT_POLICY};

const MAX_CONSECUTIVE_FAILURES: u32 = 3;

pub(crate) fn watch(args: &[String], json: bool, every_secs: u64) -> u8 {
    if !golden::active() {
        eprintln!(
            "hemostat services --restore --every: the IRSeC golden baseline is off (set \
             HEMOSTAT_GOLDEN=1 on a competition box); there is no scored roster to watch."
        );
        return EXIT_POLICY;
    }
    let armed = args.iter().any(|a| a == "--arm");
    let every = every_secs.max(1);
    let mut failures: BTreeMap<String, u32> = BTreeMap::new();

    if !json {
        println!(
            "mahoraga watchdog (windows) — scored-service uptime, every {every}s {}\n  Ctrl-C to stop.\n",
            if armed { "(ARMED: auto-fix)" } else { "(dry run: reporting only — add --arm to auto-fix)" }
        );

        if let Ok(r) = golden::resolve_role(None, golden::role_override().as_deref()) {
            println!("  {}: the computer name is not used\n", golden::role_said(&r));
        }
    }
    loop {
        let tick = std::time::Instant::now();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let host = std::env::var("COMPUTERNAME").unwrap_or_default();
        let role = golden::this_role(Some(&host));
        let mine = role.as_ref().map(|r| golden::services_of_role(r.name)).unwrap_or_default();
        let ov = hemostat_sensor_win::overview::report();

        let gap = role.err().or_else(|| {
            (!ov.available).then(|| "the socket table could not be read, so DOWN cannot be asserted".to_string())
        });
        let acted = if let Some(why) = gap {
            if !json {
                println!("[{now}] NOT CHECKED  {} — nothing was checked or changed this tick", crate::render::h(&why));
            }
            true
        } else {
            let listening: BTreeSet<u16> =
                ov.sockets.iter().filter(|s| s.world_reachable()).map(|s| s.port).collect();
            let down = down_services(&mine, &listening);

            for &s in &mine {
                for &w in golden::win_services_for(s.probe) {
                    if !down.iter().any(|(_, d, _)| *d == w) {
                        failures.remove(w);
                    }
                }
            }

            let unprobed: Vec<&str> = mine
                .iter()
                .filter(|s| s.port.is_none() && golden::win_services_for(s.probe).is_empty())
                .map(|s| s.service)
                .collect();
            let mut did = !unprobed.is_empty();
            if did && !json {
                println!("[{now}] NOT CHECKED  {} (no scored port or Windows service to probe)", unprobed.join(", "));
            }
            for (s, w, step) in down {
                did = true;
                let port = s.port.map_or_else(|| "its port".to_string(), |p| p.to_string());
                let backed_off = failures.get(w).copied().unwrap_or(0) >= MAX_CONSECUTIVE_FAILURES;
                if backed_off {
                    if !json {
                        println!("[{now}] BACKED-OFF {} → {} (sc start keeps failing — needs a human)", s.service, w);
                    }
                    continue;
                }
                match step {
                    WinStep::Up | WinStep::Start => {}

                    WinStep::NeedsHuman => {
                        if armed {
                            *failures.entry(w.to_string()).or_default() += 1;
                        }
                        if !json {
                            println!(
                                "[{now}] RUNNING, PORT CLOSED {} → {} (port {port} is not listening — a restart will not help; needs a human: {})",
                                s.service, w, crate::winservice::port_closed_hint(s.probe)
                            );
                        }
                        continue;
                    }
                    WinStep::Unknown => {
                        if !json {
                            println!("[{now}] NOT CHECKED  {} → {} (its state could not be read, and it has no scored port)", s.service, w);
                        }
                        continue;
                    }
                }
                if !armed {
                    if !json {
                        println!("[{now}] DOWN   {} → sc start {} (dry run)", s.service, w);
                    }
                    continue;
                }
                match crate::winservice::start_and_verify(w) {
                    Ok(()) => {

                        let back = crate::winservice::back_after_start(s.port, s.port.and_then(await_port));
                        if back {
                            failures.remove(w);
                        } else {
                            *failures.entry(w.to_string()).or_default() += 1;
                        }
                        audit_or_warn(&format!("watchdog {} -> sc start {} [running]", s.service, w));
                        if !json {
                            if back {
                                println!("[{now}] FIXED  {} → {} RUNNING", s.service, w);
                            } else {
                                println!(
                                    "[{now}] NOT FIXED {} → {} RUNNING, but port {port} did not answer within {}s — needs a human: {}",
                                    s.service, w, crate::uptime::PORT_WAIT_SECS, crate::winservice::port_closed_hint(s.probe)
                                );
                            }
                        }
                    }
                    Err(e) => {
                        *failures.entry(w.to_string()).or_default() += 1;
                        if !json {
                            println!("[{now}] FAILED {} → {}: {}", s.service, w, e);
                        }
                    }
                }
            }
            did
        };
        if !acted && !json {
            println!("[{now}] all scored services up");
        }
        let remaining = every.saturating_sub(tick.elapsed().as_secs());
        if remaining > 0 {
            std::thread::sleep(std::time::Duration::from_secs(remaining));
        }
    }
}

fn down_services(
    mine: &[&'static ScoredService],
    listening: &BTreeSet<u16>,
) -> Vec<(&'static ScoredService, &'static str, WinStep)> {
    mine.iter()
        .flat_map(|&s| {
            golden::win_services_for(s.probe).iter().filter_map(move |&w| {
                let port_closed = s.port.map(|p| !listening.contains(&p));
                match crate::winservice::win_step(crate::winservice::service_running(w), port_closed) {
                    WinStep::Up => None,
                    step => Some((s, w, step)),
                }
            })
        })
        .collect()
}

fn await_port(p: u16) -> Option<bool> {
    crate::uptime::poll_until_up(
        crate::uptime::PORT_WAIT_SECS,
        || {
            let ov = hemostat_sensor_win::overview::report();
            ov.available.then(|| ov.sockets.iter().any(|s| s.world_reachable() && s.port == p))
        },
        || std::thread::sleep(std::time::Duration::from_secs(1)),
    )
}

pub(crate) fn restore_scored(args: &[String], json: bool) -> u8 {
    if !golden::active() {
        eprintln!(
            "hemostat services --restore: the IRSeC golden baseline is off (set HEMOSTAT_GOLDEN=1 \
             on a competition box); there is no scored roster to restore."
        );
        return EXIT_POLICY;
    }
    let host = std::env::var("COMPUTERNAME").unwrap_or_default();
    let armed = args.iter().any(|a| a == "--arm");
    let not_checked = |why: &str| {
        if json {
            println!(
                "{{\"restore\":{{\"os\":\"windows\",\"armed\":{armed},\"not_checked\":{}}}}}",
                crate::render::json_str(why)
            );
        } else {
            println!("scored services — NOT CHECKED: {}\n  nothing was checked or restarted", crate::render::h(why));
        }
        EXIT_PARTIAL
    };
    let role = match golden::this_role(Some(&host)) {
        Ok(r) => r,
        Err(why) => return not_checked(&why),
    };
    let mine = golden::services_of_role(role.name);

    let role_json = golden::role_json(Some(&role));
    if role.from_override && !json {
        println!("scored services — {}, not the computer name `{}`", golden::role_said(&role), crate::render::h(&host));
    }
    let ov = hemostat_sensor_win::overview::report();
    if !ov.available {
        return not_checked("the socket table could not be read, so DOWN cannot be asserted");
    }
    let listening: BTreeSet<u16> =
        ov.sockets.iter().filter(|s| s.world_reachable()).map(|s| s.port).collect();
    let down = down_services(&mine, &listening);
    let pick = |want: WinStep| -> Vec<(&'static ScoredService, &'static str)> {
        down.iter().filter(|(_, _, st)| *st == want).map(|(s, w, _)| (*s, *w)).collect()
    };
    let plan = pick(WinStep::Start);
    let stuck = pick(WinStep::NeedsHuman);
    let unread = pick(WinStep::Unknown);
    let port_of = |s: &ScoredService| s.port.map_or_else(|| "its port".to_string(), |p| p.to_string());
    let extra_json = || {
        let row = |(s, w): &(&'static ScoredService, &'static str), outcome: &str| {
            format!("{{\"service\":\"{}\",\"unit\":\"{}\",\"outcome\":\"{outcome}\"}}", s.service, w)
        };
        let human: Vec<String> = stuck.iter().map(|x| row(x, "running-port-closed")).collect();
        let unknown: Vec<String> = unread.iter().map(|x| row(x, "not-checked")).collect();
        format!("\"needs_human\":[{}],\"not_checked\":[{}]", human.join(","), unknown.join(","))
    };
    let print_extra = || {
        for (s, w) in &stuck {
            println!(
                "  [RUNNING, PORT CLOSED] {} → {}: port {} is not listening — a restart will not help; needs a human ({})",
                s.service, w, port_of(s), crate::winservice::port_closed_hint(s.probe)
            );
        }
        for (s, w) in &unread {
            println!("  [NOT CHECKED] {} → {}: its state could not be read, and it has no scored port", s.service, w);
        }
    };

    let rest = if !stuck.is_empty() {
        EXIT_POLICY
    } else if !unread.is_empty() {
        EXIT_PARTIAL
    } else {
        EXIT_OK
    };

    if plan.is_empty() {
        if json {
            println!("{{\"restore\":{{\"os\":\"windows\",\"armed\":{armed}{role_json},\"planned\":[],{}}}}}", extra_json());
        } else if stuck.is_empty() && unread.is_empty() {
            println!(
                "scored services — every service this box owns is up (or none is a restartable \
                 Windows service)"
            );
        } else {
            println!("scored services — not all up, and nothing here to start:");
            print_extra();
        }
        return rest;
    }

    if !armed {
        if json {
            let rows: Vec<String> = plan
                .iter()
                .map(|(s, w)| format!("{{\"service\":\"{}\",\"unit\":\"{}\",\"outcome\":\"planned\"}}", s.service, w))
                .collect();
            println!("{{\"restore\":{{\"os\":\"windows\",\"armed\":false{role_json},\"planned\":[{}],{}}}}}", rows.join(","), extra_json());
        } else {
            println!("scored services — {} down (dry run — add --arm to restart):", plan.len());
            for (s, w) in &plan {
                println!("  [plan] {} → sc start {}", s.service, w);
            }
            print_extra();
        }
        return EXIT_DRYRUN;
    }

    if !json {
        println!("scored services — restarting {} down service(s)", plan.len());
    }
    let mut any_fail = false;
    let mut rows: Vec<String> = Vec::new();
    for (s, w) in &plan {
        match crate::winservice::start_and_verify(w) {
            Ok(()) => {

                let back = crate::winservice::back_after_start(s.port, s.port.and_then(await_port));
                if !json {
                    if back {
                        println!("  [done] {} → {} RUNNING", s.service, w);
                    } else {
                        eprintln!(
                            "  [not fixed] {} → {} RUNNING, but port {} did not answer within {}s — needs a human ({})",
                            s.service, w, port_of(s), crate::uptime::PORT_WAIT_SECS, crate::winservice::port_closed_hint(s.probe)
                        );
                    }
                }
                audit_or_warn(&format!("restore {} -> sc start {} [running]", s.service, w));
                any_fail |= !back;
                let outcome = if back { "running" } else { "started-port-closed" };
                rows.push(format!("{{\"service\":\"{}\",\"unit\":\"{}\",\"outcome\":\"{outcome}\"}}", s.service, w));
            }
            Err(e) => {
                any_fail = true;
                if !json {
                    eprintln!("  [failed] {} → {}: {}", s.service, w, e);
                }
                rows.push(format!("{{\"service\":\"{}\",\"unit\":\"{}\",\"outcome\":\"failed\"}}", s.service, w));
            }
        }
    }
    if json {
        println!("{{\"restore\":{{\"os\":\"windows\",\"armed\":true{role_json},\"planned\":[{}],{}}}}}", rows.join(","), extra_json());
    } else {
        print_extra();
    }
    if any_fail {
        EXIT_ENFORCER
    } else {
        rest
    }
}

fn schtasks() -> String {
    let sysroot = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_string());
    format!(r"{sysroot}\System32\schtasks.exe")
}

const WATCHDOG_TASK: &str = "mahoraga-watchdog";

pub(crate) fn install_watchdog(args: &[String], every: u64) -> u8 {
    use crate::{EXIT_DRYRUN, EXIT_ENFORCER, EXIT_FAILED, EXIT_OK};
    let armed = args.iter().any(|a| a == "--arm");
    let plan = match crate::win_private::watchdog_plan(every) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("hemostat services: {}. Nothing was changed", crate::render::h(&e));
            return EXIT_FAILED;
        }
    };
    let exe = plan.copy.display().to_string();
    let wrapper = plan.wrapper.display().to_string();
    if !armed {
        println!("install the uptime watchdog as a Windows scheduled task (`{WATCHDOG_TASK}`, at startup, SYSTEM):");
        println!(
            "  {}  ->  {}  (a copy only administrators can change; sha256 {}…)",
            crate::render::h(&plan.source.display().to_string()),
            crate::render::h(&exe),
            crate::win_binvault::short(&plan.sha)
        );

        let role = plan.role.as_deref().map_or_else(String::new, |r| format!(" & set HEMOSTAT_ROLE={r}"));
        println!("  {wrapper}  ->  set HEMOSTAT_GOLDEN=1{role} & \"{exe}\" services --restore --every {every} --arm");
        if let Err(e) = crate::win_private::check_watchdog(&plan) {
            println!("  REFUSED when armed: {}", crate::render::h(&e));
        }
        println!("\nNothing was changed. Add --arm to install (remove later with `services --uninstall-watchdog --arm`).");
        return EXIT_DRYRUN;
    }
    if let Err(e) = crate::win_private::stage_watchdog(&plan) {
        eprintln!("hemostat services: could not put the watchdog in place: {}. The task was not created", crate::render::h(&e));
        return EXIT_ENFORCER;
    }
    let create = std::process::Command::new(schtasks())
        .args(["/create", "/tn", WATCHDOG_TASK, "/tr", &wrapper, "/sc", "onstart", "/ru", "SYSTEM", "/rl", "HIGHEST", "/f"])
        .output();
    match create {
        Ok(o) if o.status.success() => {
            let _ = std::process::Command::new(schtasks()).args(["/run", "/tn", WATCHDOG_TASK]).output();
            println!("installed and started the uptime watchdog scheduled task (`{WATCHDOG_TASK}`, every {every}s)");
            if let Some(r) = &plan.role {
                println!("  HEMOSTAT_ROLE={r} is carried into the task, as it was set here");
            }
            println!("  remove: mahoraga services --uninstall-watchdog --arm");
            EXIT_OK
        }
        Ok(o) => {
            eprintln!("hemostat services: schtasks /create failed: {}", String::from_utf8_lossy(&o.stderr).trim());
            EXIT_ENFORCER
        }
        Err(e) => {
            eprintln!("hemostat services: could not run schtasks: {e}");
            EXIT_ENFORCER
        }
    }
}

fn watchdog_task_installed() -> Result<bool, String> {
    let out = std::process::Command::new(schtasks())
        .args(["/query", "/fo", "csv", "/nh"])
        .output()
        .map_err(|e| format!("could not run schtasks: {e}"))?;
    if !out.status.success() {
        return Err(format!("schtasks /query failed: {}", String::from_utf8_lossy(&out.stderr).trim()));
    }
    Ok(crate::actions::win_task_listed(&String::from_utf8_lossy(&out.stdout), WATCHDOG_TASK))
}

fn watchdog_task_procs(wrapper: &str, pids: &[u32]) -> Result<crate::actions::WinWatchdogProcs, String> {
    let sysroot = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_string());
    let exe = format!(r"{sysroot}\System32\WindowsPowerShell\v1.0\powershell.exe");
    let out = std::process::Command::new(&exe)
        .args(["-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand"])
        .arg(hemostat_sensor_win::wmi::encoded_command(&crate::actions::win_watchdog_query(wrapper, pids)))
        .stdin(std::process::Stdio::null())
        .output()
        .map_err(|e| format!("could not run {exe}: {e}"))?;
    if !out.status.success() {
        return Err(format!("the process query failed: {}", String::from_utf8_lossy(&out.stderr).trim()));
    }
    crate::actions::parse_win_watchdog_procs(&String::from_utf8_lossy(&out.stdout))
}

pub(crate) fn uninstall_watchdog(args: &[String]) -> u8 {
    use crate::render::h;
    use crate::{EXIT_DRYRUN, EXIT_ENFORCER, EXIT_FAILED, EXIT_OK};
    let armed = args.iter().any(|a| a == "--arm");
    let pd = std::env::var("ProgramData").unwrap_or_else(|_| r"C:\ProgramData".to_string());
    let wrapper = format!(r"{pd}\hemostat\watchdog.cmd");

    let by_hand = format!("by hand: schtasks /end /tn {WATCHDOG_TASK}, then schtasks /delete /tn {WATCHDOG_TASK} /f");
    let task = match watchdog_task_installed() {
        Ok(t) => t,
        Err(e) => {
            eprintln!("hemostat services: could not tell whether the watchdog task is installed ({}); nothing was changed. {by_hand}", h(&e));
            return EXIT_FAILED;
        }
    };
    let found = match watchdog_task_procs(&wrapper, &[]) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("hemostat services: could not tell what the watchdog task is running ({}); nothing was changed. {by_hand}", h(&e));
            return EXIT_FAILED;
        }
    };
    let kill = crate::actions::win_watchdog_kill_list(&found, std::process::id());
    let wrapper_there = std::path::Path::new(&wrapper).exists();

    let strays = |f: &crate::actions::WinWatchdogProcs| {
        for (p, n) in &f.strays {
            println!("  note: PID {p} ({}) is also running `services --restore --every … --arm` and was not started by the task now; it was left running — `taskkill /F /PID {p}` stops it if it is one", h(n));
        }
    };
    if !task && kill.is_empty() && !wrapper_there {
        println!("the watchdog task is not installed (nothing to remove)");
        strays(&found);
        return EXIT_OK;
    }
    let procs: Vec<String> = found
        .wrappers
        .iter()
        .chain(&found.children)
        .filter(|(p, _)| kill.contains(p))
        .map(|(p, n)| format!("PID {p} ({})", h(n)))
        .collect();
    if !armed {
        println!("remove the uptime watchdog scheduled task (`{WATCHDOG_TASK}`):");
        if !procs.is_empty() {
            println!("  stop what the task is running: {}  —  taskkill /F /PID <pid>, each by its own pid", procs.join(", "));
        }
        if task {
            println!("  end and delete the task  —  schtasks /end, schtasks /delete /tn {WATCHDOG_TASK} /f");
        }
        if wrapper_there {
            println!("  delete its wrapper {wrapper}");
        }
        println!("  No other process is touched. The scored services it kept up are left as they are.");
        strays(&found);
        println!("\nNothing was changed. Add --arm to remove it.");
        return EXIT_DRYRUN;
    }

    let sysroot = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_string());
    let taskkill = format!(r"{sysroot}\System32\taskkill.exe");
    let mut problems: Vec<String> = Vec::new();

    for pid in &kill {
        match std::process::Command::new(&taskkill).args(["/F", "/PID", &pid.to_string()]).output() {
            Ok(o) if o.status.success() => {}
            Ok(o) => problems.push(format!("taskkill /PID {pid}: {}", String::from_utf8_lossy(&o.stderr).trim())),
            Err(e) => problems.push(format!("could not run taskkill for PID {pid}: {e}")),
        }
    }
    if task {
        let _ = std::process::Command::new(schtasks()).args(["/end", "/tn", WATCHDOG_TASK]).output();
        match std::process::Command::new(schtasks()).args(["/delete", "/tn", WATCHDOG_TASK, "/f"]).output() {
            Ok(o) if o.status.success() => {}
            Ok(o) => problems.push(format!("schtasks /delete: {}", String::from_utf8_lossy(&o.stderr).trim())),
            Err(e) => problems.push(format!("could not run schtasks /delete: {e}")),
        }
    }
    if wrapper_there {
        if let Err(e) = std::fs::remove_file(&wrapper) {
            problems.push(format!("{wrapper} could not be removed: {e}"));
        }
    }

    let mut left: Vec<String> = Vec::new();
    match watchdog_task_installed() {
        Ok(false) => {}
        Ok(true) => left.push(format!("the task `{WATCHDOG_TASK}`")),
        Err(e) => left.push(format!("the task, which could not be checked ({e})")),
    }
    let after = watchdog_task_procs(&wrapper, &kill);
    match &after {
        Ok(f) => {
            left.extend(f.wrappers.iter().map(|(p, n)| format!("PID {p} ({n})")));
            left.extend(f.alive.iter().filter(|p| !f.wrappers.iter().any(|(w, _)| w == *p)).map(|p| format!("PID {p}")));
        }
        Err(e) => left.push(format!("what it was running, which could not be checked ({e})")),
    }
    if std::path::Path::new(&wrapper).exists() {
        left.push(wrapper.clone());
    }
    if !left.is_empty() {
        eprintln!("hemostat services: the uptime watchdog was NOT removed; still there: {}", h(&left.join(", ")));
        for p in &problems {
            eprintln!("  {}", h(p));
        }
        return EXIT_ENFORCER;
    }
    audit_or_warn(&format!("uninstall-watchdog: removed task {WATCHDOG_TASK} and stopped {}", if procs.is_empty() { "nothing (it was not running)".to_string() } else { procs.join(", ") }));
    println!("removed the uptime watchdog scheduled task (`{WATCHDOG_TASK}`) and stopped what it was running");
    if let Ok(f) = &after {
        strays(f);
    }
    EXIT_OK
}

pub(crate) fn audit(what: &str) -> std::io::Result<()> {
    use std::io::Write as _;

    let dir = crate::win_private::ensure(&[]).map_err(std::io::Error::other)?;
    let mut f = std::fs::OpenOptions::new().create(true).append(true).open(dir.join("fixes.log"))?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    f.write_all(format!("epoch={now} {what}\n").as_bytes())
}

pub(crate) fn audit_or_warn(what: &str) {
    if let Err(e) = audit(what) {
        eprintln!(
            "hemostat: this was NOT written to the fix log (%ProgramData%\\hemostat\\fixes.log): {e}\n  {}",
            crate::render::h(what)
        );
    }
}
