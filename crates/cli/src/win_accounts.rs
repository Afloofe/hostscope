#![allow(dead_code)]

use hemostat_sensor_win::accounts::{leaf, Account};

#[cfg(target_os = "windows")]
use crate::render::h;
#[cfg(target_os = "windows")]
use crate::{EXIT_DRYRUN, EXIT_ENFORCER, EXIT_OK, EXIT_POLICY, EXIT_USAGE};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Session {

    pub(crate) name: String,

    pub(crate) sid: String,
}

pub(crate) fn parse_whoami(out: &str) -> Option<Session> {
    let line = out.lines().map(str::trim).find(|l| !l.is_empty())?;
    let (name, sid) = line.rsplit_once(',')?;
    let unq = |s: &str| s.trim().trim_matches('"').trim().to_string();
    let (name, sid) = (unq(name), unq(sid));
    (sid.starts_with("S-1-") && sid.len() > 4 && !sid.contains(char::is_whitespace)).then_some(Session { name, sid })
}

pub(crate) fn is_session_account(target: &str, target_sid: Option<&str>, session: &Session) -> bool {
    match target_sid {
        Some(sid) => sid.eq_ignore_ascii_case(&session.sid),
        None => leaf(&session.name).eq_ignore_ascii_case(target),
    }
}

pub(crate) fn leaves_no_admin(target: &str, accounts: &[Account], session: &Session) -> bool {
    let is_target = |a: &&Account| a.name.eq_ignore_ascii_case(target);
    if !accounts.iter().filter(is_target).any(|a| a.enabled() && a.administrator) {
        return false;
    }
    if accounts.iter().any(|a| !a.name.eq_ignore_ascii_case(target) && a.enabled() && a.administrator) {
        return false;
    }
    let person = session.sid.starts_with("S-1-5-21-");
    let disabled_here = accounts.iter().any(|a| a.name.eq_ignore_ascii_case(leaf(&session.name)) && !a.enabled());
    !(person && !disabled_here)
}

pub(crate) fn rogue_among(accounts: &[Account], is_session: impl Fn(&str) -> bool) -> Vec<String> {
    accounts
        .iter()
        .filter(|a| a.enabled())
        .filter(|a| !hemostat_sensor_win::accounts::is_builtin(&a.name))
        .filter(|a| !crate::golden::is_legit(&a.name) && !crate::golden::is_protected(&a.name))
        .filter(|a| !is_session(&a.name))
        .map(|a| a.name.clone())
        .collect()
}

pub(crate) fn builtin_rid_refusal(sid: &str) -> Option<String> {
    let rid = hemostat_sensor_win::accounts::local_rid(sid, None)?;
    let builtin = match rid {
        500 => "Administrator",
        501 => "Guest",
        502 => "krbtgt",
        503 => "DefaultAccount",
        504 => "WDAGUtilityAccount",
        _ => return None,
    };
    Some(format!("its SID, {sid}, ends in relative id {rid}: it is the built-in {builtin}, whatever it is called now"))
}

pub(crate) fn net_user_command(user: &str, flag: &str) -> Option<String> {
    crate::win_respond::paste_refusal(user).is_none().then(|| format!("net user \"{user}\" {flag}"))
}

pub(crate) fn enable_undo(user: &str, sid: &str) -> String {
    match net_user_command(user, "/active:yes") {
        Some(cmd) => format!("{cmd}  (for SID {sid} only: check the name is still that account first)"),
        None => format!(
            "re-enable the account whose SID is {sid} by hand — no command is printed, as its name holds a character a \
             shell could read as something other than itself"
        ),
    }
}

#[cfg(target_os = "windows")]
pub(crate) fn session() -> Option<Session> {
    static SESSION: std::sync::OnceLock<Option<Session>> = std::sync::OnceLock::new();
    SESSION
        .get_or_init(|| {
            let sysroot = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_string());
            let out = std::process::Command::new(format!(r"{sysroot}\System32\whoami.exe"))
                .args(["/user", "/fo", "csv", "/nh"])
                .output()
                .ok()?;
            if !out.status.success() {
                return None;
            }
            parse_whoami(&String::from_utf8_lossy(&out.stdout))
        })
        .clone()
}

#[cfg(target_os = "windows")]
fn sid_of(name: &str) -> Result<Option<String>, String> {
    hemostat_sensor_win::accounts::sid_of(name).map_err(|rc| format!("`{name}` could not be resolved to a SID (error {rc})"))
}

#[cfg(target_os = "windows")]
pub(crate) fn rogue_locals() -> Vec<String> {
    if !crate::golden::active() {
        return Vec::new();
    }
    let r = hemostat_sensor_win::accounts::report();
    if !r.available {
        return Vec::new();
    }
    let me = session();
    rogue_among(&r.accounts, |name| {
        me.as_ref().is_some_and(|s| is_session_account(name, sid_of(name).ok().flatten().as_deref(), s))
    })
}

#[cfg(target_os = "windows")]
fn net(args: &[&str]) -> Result<String, String> {
    let sysroot = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_string());
    let exe = format!(r"{sysroot}\System32\net.exe");
    let out = std::process::Command::new(exe)
        .args(args)
        .output()
        .map_err(|e| format!("could not run net.exe: {e}"))?;
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    if out.status.success() {
        Ok(stdout)
    } else {
        Err(format!("{} {}", String::from_utf8_lossy(&out.stderr).trim(), stdout.trim()))
    }
}

#[cfg(target_os = "windows")]
fn is_active(user: &str) -> Option<bool> {
    let out = net(&["user", user]).ok()?;
    out.lines().find(|l| l.contains("Account active")).map(|l| l.contains("Yes"))
}

#[cfg(target_os = "windows")]
pub(crate) fn disable(args: &[String], _json: bool) -> u8 {
    let Some(i) = args.iter().position(|a| a == "--disable") else {
        eprintln!("hemostat account --disable <user> [--arm]: name the local user to disable");
        return EXIT_USAGE;
    };
    let Some(user) = args.get(i + 1).filter(|u| !u.starts_with("--")) else {
        eprintln!("hemostat account --disable <user> [--arm]: name the local user to disable");
        return EXIT_USAGE;
    };

    if crate::golden::is_protected(user) {
        eprintln!("hemostat account: refused — `{user}` is protected (whiteteam/datadog) and is never disabled");
        return EXIT_POLICY;
    }
    if hemostat_sensor_win::accounts::is_builtin(user) {
        eprintln!("hemostat account: refused — `{user}` is a built-in Windows account and is never disabled");
        return EXIT_POLICY;
    }

    let Some(me) = session() else {
        eprintln!(
            "hemostat account: refused — the account this session runs as could not be read (`whoami /user`), so \
             disabling `{user}` cannot be shown not to lock you out. Nothing was changed"
        );
        return EXIT_POLICY;
    };
    let target_sid = match sid_of(user) {
        Ok(sid) => sid,
        Err(e) => {
            eprintln!(
                "hemostat account: refused — {}, so it cannot be told from the account this session runs as. \
                 Nothing was changed",
                h(&e)
            );
            return EXIT_POLICY;
        }
    };

    let Some(sid) = target_sid else {
        eprintln!(
            "hemostat account: refused — `{}` names no account here (it resolves to no SID). Nothing was changed",
            h(user)
        );
        return EXIT_POLICY;
    };
    if let Some(why) = builtin_rid_refusal(&sid) {
        eprintln!("hemostat account: refused — `{}`: {}, and is never disabled. Nothing was changed", h(user), h(&why));
        return EXIT_POLICY;
    }
    if is_session_account(user, Some(&sid), &me) {
        eprintln!(
            "hemostat account: refused — `{user}` is the account this session runs as ({}). Disabling it keeps \
             this session and fails your next RDP, WinRM or SSH logon. Nothing was changed",
            h(&me.sid)
        );
        return EXIT_POLICY;
    }
    let report = hemostat_sensor_win::accounts::report();
    if !report.available {
        eprintln!(
            "hemostat account: refused — the local account list could not be read ({}), so whether `{user}` is \
             the last enabled administrator is unknown. Nothing was changed",
            h(report.reason.as_deref().unwrap_or("no reason given"))
        );
        return EXIT_POLICY;
    }

    let disable_cmd = net_user_command(user, "/active:no").unwrap_or_else(|| "net user, with its name in quotes".to_string());
    if leaves_no_admin(user, &report.accounts, &me) {
        eprintln!(
            "hemostat account: refused — `{user}` is the last enabled member of Administrators this host lists, and \
             this session ({}) is not an account that can log on as one, so disabling it could leave nobody able \
             to. If administrators log on through a group (Domain Admins), disable it by hand: {}. Nothing was \
             changed",
            h(&me.name),
            h(&disable_cmd)
        );
        return EXIT_POLICY;
    }

    let armed = args.iter().any(|a| a == "--arm");
    if !armed {
        println!("disable local user `{}`, SID {sid} ({})", h(user), h(&disable_cmd));
        if crate::golden::is_legit(user) {
            println!("  NOTE: `{user}` is on the packet roster — disable it only if it is compromised.");
        }
        println!("  undo: {}", h(&enable_undo(user, &sid)));
        println!("\nNothing was changed. Add --arm to apply.");
        return EXIT_DRYRUN;
    }
    match net(&["user", user, "/active:no"]) {
        Ok(_) => {
            if is_active(user) == Some(false) {

                let undo = enable_undo(user, &sid);
                crate::win_restore::audit_or_warn(&format!("account disable {user} (SID {sid}); undo: {undo}"));
                println!("disabled local user `{}`, SID {sid}", h(user));
                println!("  undo: {}", h(&undo));
                EXIT_OK
            } else {
                eprintln!("hemostat account: ran `net user {user} /active:no` but {user} is still active");
                EXIT_ENFORCER
            }
        }
        Err(e) => {
            eprintln!("hemostat account: `net user {user} /active:no` failed: {e}");
            EXIT_ENFORCER
        }
    }
}
