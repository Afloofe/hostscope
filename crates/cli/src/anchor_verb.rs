use hemostat_enforce_linux::anchor::{self, AnchorRef, Offer};
use hemostat_enforce_linux::{ApplyOptions, Outcome, ProtectSet, RemovalAction};
use hemostat_sensor_linux::triage::Severity;

use crate::authz::{broker_admits, exit_for_refusal, loaded_sanction, presented_authority};
use crate::render::{h, jesc};
use crate::{repeated_flag_values, EXIT_AUTHZ, EXIT_DRYRUN, EXIT_ENFORCER, EXIT_OK, EXIT_POLICY, EXIT_USAGE};

pub(crate) fn dispatch(args: &[String], json: bool) -> Option<u8> {
    if args.iter().any(|a| a == "--anchors") {
        return Some(list(args, json));
    }
    if args.iter().any(|a| a == "--remove-anchor") {
        return Some(remove(args, json));
    }
    None
}

fn sh_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

pub(crate) fn command_for(o: &Offer) -> String {
    format!("hemostat remediate --remove-anchor {}", sh_quote(&o.token()))
}

pub(crate) struct Suggestion {
    pub(crate) severity: Severity,
    pub(crate) subject: String,
    pub(crate) locus: String,
    pub(crate) offer: Result<Offer, String>,
}

pub(crate) fn suggestions(r: &hemostat_sensor_linux::trust::Report) -> Vec<Suggestion> {
    r.findings
        .iter()
        .filter(|f| f.severity >= Severity::Warn && !f.subject.starts_with("TLS redirected") && f.subject != "store rebuild hook")
        .filter_map(|f| {
            let found = crate::trust_verb::anchor_for(r, f)?;
            Some(Suggestion {
                severity: f.severity,
                subject: f.subject.clone(),
                locus: f.locus.clone(),
                offer: found.and_then(anchor::offer_for_anchor),
            })
        })
        .collect()
}

pub(crate) fn print_suggestion(s: &Suggestion) {
    println!("  [{}] {} — {}", s.severity.tag(), h(&s.subject), h(&s.locus));
    match &s.offer {
        Ok(o) => println!("        {}", h(&command_for(o))),
        Err(why) => println!("        not offered: {}", h(why)),
    }
}

pub(crate) fn suggestion_row(s: &Suggestion) -> String {
    match &s.offer {
        Ok(o) => format!(
            "{{\"state\":\"anchor-offer\",\"severity\":\"{}\",\"subject\":\"{}\",\"locus\":\"{}\",\"token\":\"{}\",\"certificates_in_file\":{}}}",
            s.severity.tag(),
            jesc(&s.subject),
            jesc(&s.locus),
            jesc(&o.token()),
            o.blocks
        ),
        Err(why) => format!(
            "{{\"state\":\"anchor-advice\",\"severity\":\"{}\",\"subject\":\"{}\",\"locus\":\"{}\",\"why\":\"{}\"}}",
            s.severity.tag(),
            jesc(&s.subject),
            jesc(&s.locus),
            jesc(why)
        ),
    }
}

fn list(args: &[String], json: bool) -> u8 {
    let r = crate::trust_verb::linux_report(args);
    let s = suggestions(&r);
    if json {
        jprintln!("{{\"baseline\":\"{}\",\"anchors\":[{}]}}", jesc(&r.baseline), s.iter().map(suggestion_row).collect::<Vec<_>>().join(","));
        return crate::coverage::trust(&r).exit_code();
    }
    println!(
        "  trust anchors you could choose to remove — {} of them. Nothing is chosen for you; each command\n  \
         is a dry run until --arm. ({})",
        s.len(),
        h(&r.baseline)
    );
    for x in &s {
        print_suggestion(x);
    }
    crate::coverage::trust(&r).exit_code()
}

fn remove(args: &[String], json: bool) -> u8 {
    let armed = args.iter().any(|a| a == "--arm");
    let token = match repeated_flag_values(args, "--remove-anchor").as_deref() {
        Ok([one]) => one.clone(),
        Ok(_) => {
            eprintln!("hemostat remediate: one --remove-anchor per run, so each anchor is its own decision");
            return EXIT_USAGE;
        }
        Err(_) => {
            eprintln!("hemostat remediate: --remove-anchor needs the token `--anchors` printed");
            return EXIT_USAGE;
        }
    };
    let (path, which) = match AnchorRef::parse(&token) {
        Ok(v) => v,
        Err(why) => {
            eprintln!("hemostat remediate: {}", h(&why));
            return EXIT_USAGE;
        }
    };
    let declared = match repeated_flag_values(args, "--protect") {
        Ok(v) => v,
        Err(flag) => {
            eprintln!("hemostat remediate: every {flag} needs a value");
            return EXIT_USAGE;
        }
    };
    let action = RemovalAction::RemoveAnchor { path: path.clone(), anchor: which };

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
    let shown = path.to_string_lossy().into_owned();
    let gaps = match broker_admits(&action, armed, broker_auth, &sanction, 1) {
        Ok(g) => g,
        Err((stage, why)) => {
            if json {
                jprintln!("{{\"state\":\"refused\",\"locus\":\"{}\",\"why\":\"{}\"}}", jesc(&shown), jesc(&why));
            } else {
                println!("  [REFUSED] {}\n        {}", h(&shown), h(&why));
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

    let protect = ProtectSet::gather()
        .declaring_scored(crate::golden::scored_units_here())
        .declaring_protected(declared);
    let opts = if armed { ApplyOptions::armed() } else { ApplyOptions::dry_run() };
    let outcome = action.apply(&opts, &protect);
    if !matches!(outcome, Outcome::Applied(_)) && armed {
        drop(journal.take());
        let _ = std::fs::remove_file(&journal_path);
    }
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
                println!("{}", crate::render::wrap_why(&h(&p.detail), "        would: "));
                println!("{}", crate::render::wrap_why(&h(&p.undo), "        undo:  "));
                println!("  Re-run with --arm to apply.");
            }
            EXIT_DRYRUN
        }
        Outcome::Applied(rec) => {
            let journalled = crate::remediate_verb::append_record(journal.as_mut(), rec);
            if json {
                jprintln!(
                    "{{\"state\":\"applied\",\"locus\":\"{}\",\"did\":\"{}\",\"journal\":\"{}\",\"journalled\":{journalled}}}",
                    jesc(&shown),
                    jesc(&rec.did),
                    jesc(&journal_path)
                );
            } else {
                println!("{}", crate::render::wrap_why(&h(&rec.did), "  [done] "));
                println!("  undo journal: {}", h(&journal_path));
                println!("  reverse it with:  hemostat undo {}", h(&journal_path));
            }
            if journalled { EXIT_OK } else { EXIT_ENFORCER }
        }
        Outcome::Refused(r) => {
            if json {
                jprintln!("{{\"state\":\"refused\",\"locus\":\"{}\",\"why\":\"{}\"}}", jesc(&shown), jesc(&r.message));
            } else {
                println!("{}", crate::render::wrap_why(&h(&r.message), "  [refused] "));
            }
            EXIT_POLICY
        }
        Outcome::Failed(f) => {
            if json {
                jprintln!("{{\"state\":\"failed\",\"locus\":\"{}\",\"why\":\"{}\"}}", jesc(&shown), jesc(&f.reason));
            } else {
                println!("{}", crate::render::wrap_why(&h(&f.reason), "  [FAILED] "));
            }
            EXIT_ENFORCER
        }
    };
    if !json && !gap_note.is_empty() {
        println!("\n  broker stage(s) that did NOT run: {}", h(&gap_note.join("; ")));
    }
    code
}
