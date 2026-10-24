use std::path::Path;

use hemostat_enforce_linux::strip::{self, LineRef, Offer, StripAuthority};
use hemostat_enforce_linux::{ApplyOptions, Outcome, ProtectSet, RemovalAction};

use crate::authz::{broker_admits, exit_for_refusal, loaded_sanction, presented_authority};
use crate::render::{h, jesc};
use crate::{repeated_flag_values, EXIT_AUTHZ, EXIT_DRYRUN, EXIT_ENFORCER, EXIT_FAILED, EXIT_OK, EXIT_POLICY, EXIT_USAGE};

pub(crate) fn dispatch(args: &[String], json: bool) -> Option<u8> {
    if args.iter().any(|a| a == "--lines") {
        return Some(lines(args, json));
    }
    if args.iter().any(|a| a == "--strip-line") {
        return Some(strip_line(args, json));
    }
    None
}

fn sh_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

pub(crate) fn command_for(o: &Offer) -> String {
    format!(
        "hemostat remediate --strip-line {}{}",
        sh_quote(&o.token()),
        if o.kind.is_auth() { " --auth" } else { "" }
    )
}

fn lines(args: &[String], json: bool) -> u8 {
    let paths = match repeated_flag_values(args, "--lines") {
        Ok(v) if !v.is_empty() => v,
        _ => {
            eprintln!("hemostat remediate: --lines needs a file, e.g. --lines /etc/crontab");
            return EXIT_USAGE;
        }
    };
    let mut code = EXIT_OK;
    let mut files: Vec<String> = Vec::new();
    for p in &paths {
        let path = Path::new(p);
        let offers = match strip::offers(path) {
            Ok(o) => o,
            Err(why) => {
                code = EXIT_FAILED;
                if json {
                    files.push(format!("{{\"path\":\"{}\",\"error\":\"{}\"}}", jesc(p), jesc(&why)));
                } else {
                    eprintln!("hemostat remediate: {}: {}", h(p), h(&why));
                }
                continue;
            }
        };
        let kind = offers.first().map_or_else(|| strip::FileKind::of(path), |o| Some(o.kind));
        if json {
            let rows: Vec<String> = offers
                .iter()
                .map(|o| {
                    format!(
                        "{{\"line\":{},\"text\":\"{}\",\"key\":{},\"token\":\"{}\"}}",
                        o.line.line_no,
                        jesc(&o.text),
                        o.key.as_deref().map_or_else(|| "null".into(), |k| format!("\"{}\"", jesc(k))),
                        jesc(&o.token())
                    )
                })
                .collect();
            files.push(format!(
                "{{\"path\":\"{}\",\"kind\":\"{}\",\"auth\":{},\"lines\":[{}]}}",
                jesc(p),
                jesc(kind.map_or("", strip::FileKind::label)),
                kind.is_some_and(strip::FileKind::is_auth),
                rows.join(",")
            ));
            continue;
        }
        println!(
            "  {} ({}) — {} line(s) you could choose. Nothing is chosen for you; each command is a dry run until --arm.",
            h(p),
            kind.map_or("?", strip::FileKind::label),
            offers.len()
        );
        for o in &offers {
            println!("  {:>5}  {}", o.line.line_no, h(&o.text));
            if let Some(k) = &o.key {
                println!("         key: {}", h(k));
            }
            println!("         {}", h(&command_for(o)));
        }
        println!();
    }
    if json {
        jprintln!("{{\"files\":[{}]}}", files.join(","));
    }
    code
}

fn strip_line(args: &[String], json: bool) -> u8 {
    let armed = args.iter().any(|a| a == "--arm");
    let token = match repeated_flag_values(args, "--strip-line").as_deref() {
        Ok([one]) => one.clone(),
        Ok(_) => {
            eprintln!("hemostat remediate: one --strip-line per run, so each line is its own decision");
            return EXIT_USAGE;
        }
        Err(_) => {
            eprintln!("hemostat remediate: --strip-line needs the token `--lines` printed");
            return EXIT_USAGE;
        }
    };
    let (path, line) = match LineRef::parse(&token) {
        Ok(v) => v,
        Err(why) => {
            eprintln!("hemostat remediate: {}", h(&why));
            return EXIT_USAGE;
        }
    };
    let named = match repeated_flag_values(args, "--operator-key") {
        Ok(v) => v,
        Err(flag) => {
            eprintln!("hemostat remediate: every {flag} needs a fingerprint (SHA256:…)");
            return EXIT_USAGE;
        }
    };
    let mut keys = match strip::parse_operator_keys(&named, std::env::var("HEMOSTAT_OPERATOR_KEY").ok().as_deref()) {
        Ok(k) => k,
        Err(why) => {
            eprintln!("hemostat remediate: {}", h(&why));
            return EXIT_USAGE;
        }
    };
    keys.extend(strip::session_key_fingerprints());
    let declared = match repeated_flag_values(args, "--protect") {
        Ok(v) => v,
        Err(flag) => {
            eprintln!("hemostat remediate: every {flag} needs a value");
            return EXIT_USAGE;
        }
    };
    let action = RemovalAction::StripLine {
        path: path.clone(),
        line,
        authority: StripAuthority {
            auth: args.iter().any(|a| a == "--auth"),
            operator_keys: keys,
            session_key_unknown: args.iter().any(|a| a == "--session-key-unknown"),
            last_admin_key: args.iter().any(|a| a == "--last-admin-key"),
        },
    };

    let neutralise = hemostat_buildinfo::ActionClass::PersistenceNeutralize;
    let class_code = hemostat_buildinfo::ActionClass::ALL
        .iter()
        .position(|a| *a == neutralise)
        .and_then(|i| u8::try_from(i).ok())
        .unwrap_or(hemostat_evcrypto::ticket::NO_CLASS);
    let (broker_auth, ticket) = match presented_authority(hemostat_evcrypto::ticket::Op::Action, class_code) {
        Ok(a) => a,
        Err(why) => {
            eprintln!("hemostat remediate: {}", h(&why));
            return EXIT_AUTHZ;
        }
    };
    let sanction = match loaded_sanction() {
        Ok(s) => s,
        Err(why) => {
            eprintln!("hemostat remediate: {}", h(&why));
            return EXIT_POLICY;
        }
    };
    let gaps = match broker_admits(&action, armed, broker_auth, &sanction, 1) {
        Ok(g) => g,
        Err((stage, why)) => {
            if json {
                jprintln!("{{\"state\":\"refused\",\"locus\":\"{}\",\"why\":\"{}\"}}", jesc(&path.to_string_lossy()), jesc(&why));
            } else {
                println!("  [REFUSED] {}\n        {}", h(&path.to_string_lossy()), h(&why));
            }
            return exit_for_refusal(stage);
        }
    };
    let gap_note: Vec<String> = gaps.iter().map(|u| format!("{} — {}", u.stage.token(), u.why)).collect();

    let (mut journal, journal_path) = if armed {
        match crate::remediate_verb::open_run_journal() {
            Ok((f, p)) => (Some(f), p),
            Err(code) => return code,
        }
    } else {
        (None, String::new())
    };
    if armed {
        if let Some(t) = ticket {
            if let Err(why) = t.spend() {
                eprintln!("hemostat remediate: {why}");
                drop(journal.take());
                let _ = std::fs::remove_file(&journal_path);
                return why.exit_code();
            }
        }
    }
    let protect = ProtectSet::gather().declaring_protected(declared);
    let opts = if armed { ApplyOptions::armed() } else { ApplyOptions::dry_run() };
    let outcome = action.apply(&opts, &protect);
    if !matches!(outcome, Outcome::Applied(_)) && armed {
        drop(journal.take());
        let _ = std::fs::remove_file(&journal_path);
    }
    let shown = path.to_string_lossy();
    let code = match &outcome {
        Outcome::Planned(p) => {
            if json {
                jprintln!(
                    "{{\"state\":\"planned\",\"locus\":\"{}\",\"would\":\"{}\",\"undo\":\"{}\"}}",
                    jesc(&shown),
                    jesc(&p.detail),
                    jesc(&p.undo)
                );
            } else {
                println!("  DRY RUN (nothing is changed)\n  [plan] {}", h(&p.summary));
                println!("        would: {}", h(&p.detail));
                println!("        undo:  {}", h(&p.undo));
                println!("  Re-run with --arm to apply.");
            }
            EXIT_DRYRUN
        }
        Outcome::Applied(rec) => {
            let journalled = crate::remediate_verb::append_record(journal.as_mut(), rec);

            let reload = crate::remediate_verb::reload_needed_for(&path);
            let note = crate::remediate_verb::reload_after_removal(reload.0, reload.1);
            let auth = strip::FileKind::of(&path).is_some_and(strip::FileKind::is_auth);
            if json {
                jprintln!(
                    "{{\"state\":\"applied\",\"locus\":\"{}\",\"did\":\"{}\",\"journal\":\"{}\",\"journalled\":{journalled},\"reload\":\"{}\"}}",
                    jesc(&shown),
                    jesc(&rec.did),
                    jesc(&journal_path),
                    jesc(note.as_deref().unwrap_or(""))
                );
            } else {
                println!("  [done] {}", h(&rec.did));
                if let Some(n) = &note {
                    println!("  {}", h(n));
                }
                println!("  undo journal: {}", h(&journal_path));
                println!(
                    "  reverse it with:  hemostat undo {}{}",
                    h(&journal_path),
                    if auth { " --auth" } else { "" }
                );
            }
            if journalled { EXIT_OK } else { EXIT_ENFORCER }
        }
        Outcome::Refused(r) => {
            if json {
                jprintln!("{{\"state\":\"refused\",\"locus\":\"{}\",\"why\":\"{}\"}}", jesc(&shown), jesc(&r.message));
            } else {
                println!("  [refused] {}", h(&r.message));
            }
            EXIT_POLICY
        }
        Outcome::Failed(f) => {
            if json {
                jprintln!("{{\"state\":\"failed\",\"locus\":\"{}\",\"why\":\"{}\"}}", jesc(&shown), jesc(&f.reason));
            } else {
                println!("  [FAILED] {}", h(&f.reason));
            }
            EXIT_ENFORCER
        }
    };
    if !json && !gap_note.is_empty() {
        println!("\n  broker stage(s) that did NOT run: {}", h(&gap_note.join("; ")));
    }
    code
}

#[derive(Debug, Clone)]
pub(crate) enum Suggestion {

    Line { severity: String, offer: Offer },

    List { severity: String, path: String },
}

const SUDO_QUOTES: &[&str] = &["grants password-free sudo: ", "disables the sudo password prompt: "];

pub(crate) fn suggestions(findings: &[hemostat_sensor_linux::triage::Finding]) -> Vec<Suggestion> {
    use hemostat_enforce_linux::persistence::{disposition, Disposition};
    use hemostat_sensor_linux::triage::Severity;
    let mut out: Vec<Suggestion> = Vec::new();
    let mut seen: Vec<String> = Vec::new();
    let mut add = |out: &mut Vec<Suggestion>, s: Suggestion| {
        let key = match &s {
            Suggestion::Line { offer, .. } => offer.token(),
            Suggestion::List { path, .. } => path.clone(),
        };
        if !seen.contains(&key) {
            seen.push(key);
            out.push(s);
        }
    };
    for f in findings {
        let path = Path::new(&f.locus);
        let Some(kind) = strip::FileKind::of(path) else { continue };

        let wanted = match kind {
            strip::FileKind::Shared => {
                f.severity >= Severity::Warn && matches!(disposition(f), Disposition::Advise(_))
            }
            strip::FileKind::AuthorizedKeys | strip::FileKind::SshCa => f.severity >= Severity::Note,
            _ => f.severity >= Severity::Warn,
        };
        if !wanted {
            continue;
        }
        let severity = f.severity.tag().to_string();
        match strip::offer_for(path, &f.what) {
            Some(offer) => add(&mut out, Suggestion::Line { severity, offer }),
            None if kind.is_auth() => add(&mut out, Suggestion::List { severity, path: f.locus.clone() }),
            None => {}
        }
    }
    for f in hemostat_sensor_linux::account_report().findings {
        let Some(quote) = SUDO_QUOTES.iter().find_map(|p| f.what.strip_prefix(p)) else { continue };
        let path = Path::new(&f.subject);
        if strip::FileKind::of(path).is_none() {
            continue;
        }
        let severity = format!("{:?}", f.severity).to_uppercase();
        match strip::offer_for(path, quote) {
            Some(offer) => add(&mut out, Suggestion::Line { severity, offer }),
            None => add(&mut out, Suggestion::List { severity, path: f.subject.clone() }),
        }
    }
    out
}

pub(crate) fn print_suggestion(s: &Suggestion) {
    match s {
        Suggestion::Line { severity, offer } => {
            println!(
                "  [{}] {} line {}: {}",
                h(severity),
                h(&offer.path.to_string_lossy()),
                offer.line.line_no,
                h(&offer.text)
            );
            println!("        {}", h(&command_for(offer)));
        }
        Suggestion::List { severity, path } => {
            println!("  [{}] {}", h(severity), h(path));
            println!("        hemostat remediate --lines {}   (choose the line yourself)", h(&sh_quote(path)));
        }
    }
}

pub(crate) fn suggestion_row(s: &Suggestion) -> String {
    match s {
        Suggestion::Line { severity, offer } => format!(
            "{{\"state\":\"strip-offer\",\"severity\":\"{}\",\"locus\":\"{}\",\"line\":{},\"text\":\"{}\",\"token\":\"{}\",\"auth\":{}}}",
            jesc(severity),
            jesc(&offer.path.to_string_lossy()),
            offer.line.line_no,
            jesc(&offer.text),
            jesc(&offer.token()),
            offer.kind.is_auth()
        ),
        Suggestion::List { severity, path } => format!(
            "{{\"state\":\"strip-list\",\"severity\":\"{}\",\"locus\":\"{}\"}}",
            jesc(severity),
            jesc(path)
        ),
    }
}
