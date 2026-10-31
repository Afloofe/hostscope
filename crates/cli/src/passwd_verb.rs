use std::path::Path;

use hemostat_enforce_linux::pam_validate::{self, Probe};
use hemostat_sensor_linux::accounts::Account;

use crate::render::h;
use crate::{EXIT_DRYRUN, EXIT_ENFORCER, EXIT_NOT_BUILT, EXIT_OK, EXIT_PARTIAL, EXIT_POLICY, EXIT_USAGE};

const MIN_LEN: usize = 8;

const MAX_LEN: usize = 128;

fn candidates(accounts: &[Account]) -> Vec<&Account> {
    accounts
        .iter()
        .filter(|a| {
            crate::golden::LEGIT_USERS.contains(&a.name.as_str())
                && a.uid != 0
                && !crate::golden::is_protected(&a.name)
                && a.can_login()
        })
        .collect()
}

fn select<'a>(accounts: &'a [Account], named: Option<&[String]>) -> Result<Vec<&'a Account>, String> {
    let all = candidates(accounts);
    let Some(named) = named else { return Ok(all) };
    let mut out: Vec<&Account> = Vec::new();
    for n in named {
        if crate::golden::is_protected(n) {
            return Err(format!("`{n}` is protected by the packet (whiteteam, DataDog) and is never changed"));
        }
        let Some(a) = all.iter().find(|a| a.name == *n) else {
            let why = if crate::golden::LEGIT_USERS.contains(&n.as_str()) {
                if accounts.iter().any(|a| a.name == *n) {
                    "cannot log in here, or is root"
                } else {
                    "is not an account on this host"
                }
            } else if crate::golden::is_legit(n) {
                "differs in case from the packet's name for that user"
            } else {
                "is not one of the packet's users"
            };
            return Err(format!("`{n}` {why}"));
        };
        if !out.iter().any(|o| o.name == a.name) {
            out.push(a);
        }
    }
    if out.is_empty() {
        return Err("--users names nobody".into());
    }
    Ok(out)
}

fn password_problem(first: &str, second: &str) -> Option<String> {
    if first != second {
        return Some("the two entries differ".into());
    }
    let n = first.chars().count();
    if n < MIN_LEN {
        return Some(format!("it is shorter than {MIN_LEN} characters"));
    }
    if n > MAX_LEN {
        return Some(format!("it is longer than {MAX_LEN} characters"));
    }
    if first.chars().any(|c| c == ':' || c.is_control()) {
        return Some("it holds a ':' or a control character, which chpasswd cannot carry".into());
    }
    None
}

fn shadow_hash<'a>(shadow: &'a str, user: &str) -> Option<&'a str> {
    shadow.lines().find_map(|l| {
        let mut f = l.splitn(3, ':');
        if f.next() == Some(user) {
            f.next()
        } else {
            None
        }
    })
}

fn keep(probe: &Probe) -> bool {
    matches!(probe, Probe::Works)
}

fn named_users(args: &[String]) -> Option<Vec<String>> {
    let at = args.iter().position(|a| a == "--users")?;
    Some(
        args.get(at + 1)
            .map(|v| v.split(',').map(str::trim).filter(|s| !s.is_empty()).map(String::from).collect())
            .unwrap_or_default(),
    )
}

fn operator() -> Option<String> {
    std::env::var("SUDO_USER").ok().filter(|s| !s.is_empty() && s != "root")
}

fn read_hidden(prompt: &str) -> Result<String, String> {
    use std::io::{BufRead as _, Write as _};
    let tty = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .map_err(|e| format!("there is no terminal to ask on ({e}): run it from a console, or over `ssh -t`"))?;
    let stty = ["/usr/bin/stty", "/bin/stty"]
        .into_iter()
        .find(|p| Path::new(p).is_file())
        .ok_or("stty is not there to turn echo off")?;
    let set = |arg: &str| -> Result<(), String> {
        let input = tty.try_clone().map_err(|e| format!("the terminal: {e}"))?;
        let st = std::process::Command::new(stty)
            .arg(arg)
            .stdin(input)
            .status()
            .map_err(|e| format!("stty {arg}: {e}"))?;
        if st.success() {
            Ok(())
        } else {
            Err(format!("stty {arg} failed"))
        }
    };

    set("-echo")?;
    let mut out = &tty;
    if let Err(e) = write!(out, "{prompt}").and_then(|()| out.flush()) {
        let _ = set("echo");
        return Err(format!("the terminal: {e}"));
    }
    let mut line = String::new();
    let read = std::io::BufReader::new(&tty).read_line(&mut line);
    let echo = set("echo");
    let _ = writeln!(out);
    read.map_err(|e| format!("reading the password: {e}"))?;
    echo?;
    while line.ends_with(['\n', '\r']) {
        line.pop();
    }
    Ok(line)
}

fn wipe(s: String) {
    let mut b = s.into_bytes();
    b.iter_mut().for_each(|x| *x = 0);
    std::hint::black_box(&b);
}

fn pam_refusal() -> Option<String> {
    use crate::pam_verb::{Scanned, State};
    match crate::pam_verb::scan() {
        Ok(Scanned::Release { findings, .. }) => findings.iter().find_map(|f| match &f.state {
            State::Tampered { .. } => Some(format!(
                "{} is not the stock module, and chpasswd hands the new password to the PAM stack. \
                 Put it back first: hemostat remediate --restore-pam '{}' --arm",
                f.path, f.path
            )),
            _ => None,
        }),
        _ => None,
    }
}

pub(crate) fn passwd(args: &[String]) -> u8 {
    use hemostat_buildinfo::ActionClass;
    let armed = args.iter().any(|a| a == "--arm");
    if !crate::golden::active() {
        eprintln!(
            "hemostat passwd: REFUSED — it changes only the IRSeC packet's users; set HEMOSTAT_GOLDEN=1. \
             Nothing was changed"
        );
        return EXIT_POLICY;
    }
    if let Err(msg) = crate::remedy::require_built(ActionClass::CredRotate) {
        eprintln!("hemostat passwd: {msg}");
        return EXIT_NOT_BUILT;
    }
    let named = named_users(args);
    if named.as_ref().is_some_and(Vec::is_empty) {
        eprintln!("hemostat passwd: --users needs a comma-separated list of the packet's user names");
        return EXIT_USAGE;
    }
    let text = match hemostat_sensor_linux::saferead::read_text(Path::new("/etc/passwd")) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("hemostat passwd: /etc/passwd could not be read ({e}). Nothing was changed");
            return EXIT_ENFORCER;
        }
    };
    let accounts = hemostat_sensor_linux::accounts::parse_passwd(&text);
    let targets = match select(&accounts, named.as_deref()) {
        Ok(t) => t,
        Err(why) => {
            eprintln!("hemostat passwd: REFUSED — {}. Nothing was changed", h(&why));
            return EXIT_POLICY;
        }
    };
    if targets.is_empty() {
        println!("hemostat passwd: none of the packet's users is an account on this host; nothing to change");
        return EXIT_OK;
    }

    let me = operator();
    println!("One new password, typed once, for {} account(s) on this host:", targets.len());
    for a in &targets {
        let note = if me.as_deref() == Some(a.name.as_str()) {
            "   <- the account you came in as: you sign in with the new password from now on"
        } else {
            ""
        };
        println!("  {}{note}", h(&a.name));
    }
    println!("Never changed: root, whiteteam and the DataDog accounts.");
    println!("If the scoring engine logs in as one of these, its check fails until the white team has the new password.");
    if !armed {
        let users = named.map(|n| format!(" --users {}", n.join(","))).unwrap_or_default();
        println!();
        println!("Nothing was changed. To set it:  hemostat passwd{} --arm   (asks twice, hidden)", h(&users));
        return EXIT_DRYRUN;
    }

    let ticket = match crate::authz::armed_gate("passwd", ActionClass::CredRotate, armed, targets.len()) {
        Ok(t) => t,
        Err(code) => return code,
    };
    if let Some(why) = pam_refusal() {
        eprintln!("hemostat passwd: REFUSED — {}. Nothing was changed", h(&why));
        return EXIT_POLICY;
    }
    let shadow = match hemostat_sensor_linux::saferead::read_text(Path::new("/etc/shadow")) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("hemostat passwd: /etc/shadow could not be read ({e}); this needs root. Nothing was changed");
            return EXIT_ENFORCER;
        }
    };
    let first = match read_hidden("New password: ") {
        Ok(p) => p,
        Err(why) => {
            eprintln!("hemostat passwd: {}. Nothing was changed", h(&why));
            return EXIT_USAGE;
        }
    };
    let second = match read_hidden("Type it again: ") {
        Ok(p) => p,
        Err(why) => {
            wipe(first);
            eprintln!("hemostat passwd: {}. Nothing was changed", h(&why));
            return EXIT_USAGE;
        }
    };
    let problem = password_problem(&first, &second);
    wipe(second);
    if let Some(why) = problem {
        wipe(first);
        eprintln!("hemostat passwd: REFUSED — {why}. Nothing was changed");
        return EXIT_USAGE;
    }
    if let Err(code) = crate::authz::spend_armed("passwd", armed, ticket) {
        wipe(first);
        return code;
    }

    let (mut changed, mut failed) = (0usize, 0usize);
    for a in &targets {
        let name = a.name.as_str();
        let Some(old) = shadow_hash(&shadow, name) else {
            failed += 1;
            println!("  NOT changed  {}: it has no line in /etc/shadow", h(name));
            continue;
        };
        match pam_validate::set_and_prove(name, &first) {
            Ok(p) if keep(&p) => {
                changed += 1;
                println!("  changed      {}: {}", h(name), p.describe());
                crate::actions::audit_fix(&format!("passwd: a new password for {name}, proven by a test login"));
            }
            Ok(p) => {
                failed += 1;
                let back = put_back(name, old);
                println!("  NOT changed  {}: {} — {back}", h(name), p.describe());
            }
            Err(why) => {
                failed += 1;

                let moved = hemostat_sensor_linux::saferead::read_text(Path::new("/etc/shadow"))
                    .map(|t| shadow_hash(&t, name) != Some(old))
                    .unwrap_or(true);
                let back = if moved { put_back(name, old) } else { "its password is as it was".into() };
                println!("  NOT changed  {}: {} — {back}", h(name), h(&why));
            }
        }
    }
    wipe(first);
    println!();
    println!("{changed} changed, {failed} not changed.");
    if failed == 0 {
        EXIT_OK
    } else if changed > 0 {
        EXIT_PARTIAL
    } else {
        EXIT_ENFORCER
    }
}

fn put_back(user: &str, old: &str) -> String {
    match pam_validate::restore_hash(user, old) {
        Ok(()) => "the old password is back".into(),
        Err(e) => format!("the old password could NOT be put back ({}); set one by hand: passwd {user}", h(&e)),
    }
}
