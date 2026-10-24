#[cfg(feature = "mod-enf-persistence")]
use crate::authz::{broker_admits, exit_for_refusal, loaded_sanction, presented_authority};

#[cfg(feature = "mod-enf-persistence")]
use crate::render::h;
use crate::render::jesc;
#[cfg(feature = "mod-enf-persistence")]
use crate::{
    repeated_flag_values, EXIT_AUTHZ, EXIT_DRYRUN, EXIT_ENFORCER, EXIT_POLICY,
};
use crate::{EXIT_FAILED, EXIT_OK, EXIT_USAGE};

#[cfg(all(target_os = "linux", feature = "mod-enf-persistence"))]
pub(crate) fn action_path(a: &hemostat_enforce_linux::RemovalAction) -> Option<std::path::PathBuf> {
    use hemostat_enforce_linux::RemovalAction as R;
    match a {
        R::DisablePersistence { path, .. }
        | R::QuarantineFile { path }
        | R::RemoveLdPreload { path, .. }
        | R::StopAndRemoveUnit { path, .. }
        | R::StripLine { path, .. }
        | R::RemoveAnchor { path, .. } => Some(path.clone()),
        _ => None,
    }
}

#[cfg(all(target_os = "linux", feature = "mod-enf-persistence"))]
pub(crate) fn remediate(args: &[String], json: bool) -> u8 {
    use hemostat_enforce_linux::persistence::{plan, Disposition};
    use hemostat_enforce_linux::{ApplyOptions, Outcome, ProtectSet};

    if let Some(code) = crate::strip_verb::dispatch(args, json) {
        return code;
    }

    if let Some(code) = crate::anchor_verb::dispatch(args, json) {
        return code;
    }
    let armed = args.iter().any(|a| a == "--arm");

    let allow_listeners: Vec<String> = match repeated_flag_values(args, "--allow-listener") {
        Ok(v) => v,
        Err(flag) => {
            eprintln!("hemostat remediate: every {flag} needs a value, e.g. {flag} 8080");
            return EXIT_USAGE;
        }
    };

    let declared: Vec<String> = match repeated_flag_values(args, "--protect") {
        Ok(v) => v,
        Err(flag) => {
            eprintln!(
                "hemostat remediate: every {flag} needs a value, e.g. {flag} \
                 scoring-agent.service"
            );
            return EXIT_USAGE;
        }
    };
    let report = hemostat_sensor_linux::persist::report();
    let candidates = plan(&report);
    let batch = bulk_targets(&candidates);

    let opts = if armed { ApplyOptions::armed() } else { ApplyOptions::dry_run() };

    let protect = ProtectSet::gather()
        .declaring_protected(declared.clone())
        .allowing_listeners(allow_listeners.clone());
    if !json {
        if !protect.declared_protected.is_empty() {
            println!(
                "  declared off-limits for this host: {}",
                protect.declared_protected.iter().cloned().collect::<Vec<_>>().join(", ")
            );
        }
        if !allow_listeners.is_empty() {
            println!("  listening-socket guard cleared by hand for: {}", allow_listeners.join(", "));
        }
        if !protect.declared_protected.is_empty() || !allow_listeners.is_empty() {
            println!();
        }
    }

    let (mut journal_file, mut journal_path) = if armed {
        match open_run_journal() {
            Ok((f, path)) => (Some(f), path),
            Err(code) => return code,
        }
    } else {
        (None, String::new())
    };

    let mut done: Vec<hemostat_enforce_linux::UndoRecord> = Vec::new();
    let mut removed_paths: Vec<std::path::PathBuf> = Vec::new();
    let mut touched_systemd = false;
    let mut touched_udev = false;
    let mut journal_broke = false;
    let mut planned = 0usize;
    let mut refused = 0usize;

    let mut refused_exit: Option<u8> = None;
    let mut failed = 0usize;
    let mut advised = 0usize;

    let mut broker_gaps: Vec<hemostat_broker::Unchecked> = Vec::new();

    let neutralise = hemostat_buildinfo::ActionClass::PersistenceNeutralize;
    let ticket_class = hemostat_buildinfo::ActionClass::ALL
        .iter()
        .position(|a| *a == neutralise)
        .and_then(|i| u8::try_from(i).ok())
        .unwrap_or(hemostat_evcrypto::ticket::NO_CLASS);
    let (authority, mut ticket) = match presented_authority(
        hemostat_evcrypto::ticket::Op::Action,
        ticket_class,
    ) {
        Ok(a) => a,
        Err(why) => {

            if json {
                jprintln!("{{\"error\":\"authorization\",\"why\":\"{}\"}}", jesc(&why));
            } else {
                eprintln!("hemostat remediate: {why}");
            }
            return EXIT_AUTHZ;
        }
    };

    let sanction = match loaded_sanction() {
        Ok(s) => s,
        Err(why) => {
            if json {
                jprintln!("{{\"error\":\"policy\",\"why\":\"{}\"}}", jesc(&why));
            } else {
                eprintln!("hemostat remediate: {why}");
            }
            return EXIT_POLICY;
        }
    };
    let mut rows: Vec<String> = Vec::new();

    if !json {
        println!(
            "persistence remediation — {}\n  {} of {} catalogue mechanisms established; {} finding(s)\n",
            if armed { "ARMED (the host is being changed)" } else { "DRY RUN (nothing is changed)" },
            report.established,
            report.total,
            report.findings.len()
        );
    }

    for c in &candidates {
        match &c.disposition {
            Disposition::Remove(action) => {

                let admitted = broker_admits(action, armed, authority, &sanction, batch);
                if let Ok(gaps) = &admitted {

                    for g in gaps {
                        if !broker_gaps.iter().any(|e: &hemostat_broker::Unchecked| {
                            e.stage == g.stage
                        }) {
                            broker_gaps.push(g.clone());
                        }
                    }
                }
                if let Err((stage, why)) = admitted {
                    refused += 1;

                    refused_exit = merge_refusal(refused_exit, exit_for_refusal(stage));
                    if json {
                        rows.push(format!(
                            "{{\"state\":\"refused\",\"mechanism\":\"{}\",\"locus\":\"{}\",\
                             \"severity\":\"{}\",\"why\":\"{}\"}}",
                            jesc(&c.mechanism),
                            jesc(&c.locus),
                            c.severity.tag(),
                            jesc(&why)
                        ));
                    } else {

                        print_why("REFUSED", c, &why);
                    }
                    continue;
                }

                if armed {
                    if let Some(t) = ticket.take() {
                        if let Err(why) = t.spend() {
                            eprintln!("hemostat remediate: {why}");
                            return why.exit_code();
                        }
                    }
                }
                let outcome = action.apply(&opts, &protect);
                match outcome {
                    Outcome::Planned(p) => {
                        planned += 1;
                        if json {
                            rows.push(planned_row(c, &p));
                        } else {
                            print_planned(c, &p);
                        }
                    }
                    Outcome::Applied(rec) => {
                        if json {
                            rows.push(applied_row(c, &rec));
                        } else {
                            println!("  [done] {}  {}", h(&c.mechanism), h(&rec.did));
                        }
                        journal_broke |= !append_record(journal_file.as_mut(), &rec);
                        if let Some(p) = action_path(action) {
                            let (systemd, udev) = reload_needed_for(&p);
                            touched_systemd |= systemd;
                            touched_udev |= udev;
                            removed_paths.push(p);
                        }
                        done.push(rec);
                        if journal_broke {
                            break;
                        }
                    }
                    Outcome::Refused(r) => {
                        refused += 1;

                        refused_exit = merge_refusal(refused_exit, EXIT_POLICY);
                        if json {
                            rows.push(why_row("refused", c, &r.message));
                        } else {
                            print_why("refused", c, &r.message);
                        }
                    }
                    Outcome::Failed(f) => {
                        failed += 1;
                        if json {
                            rows.push(why_row("failed", c, &f.reason));
                        } else {
                            print_why("FAILED", c, &f.reason);
                        }
                    }
                }
            }
            Disposition::Advise(why) => {
                advised += 1;
                if json {
                    rows.push(advise_row(c, why));
                } else {
                    print_advise(c, why);
                }
            }
            Disposition::Nothing => {}
        }
    }

    let systemd = hemostat_sensor_linux::enablement::report();
    let held = systemd_held(&systemd);
    for c in &held {
        advised += 1;
        if json {
            rows.push(advise_row(c, SYSTEMD_HELD_ADVICE));
        } else {
            print_advise(c, SYSTEMD_HELD_ADVICE);
        }
    }

    let systemd_unasked = crate::coverage::enablement(&systemd).gap().map(str::to_string);
    if !json {
        if let Some(why) = &systemd_unasked {
            println!("  systemd NOT fully asked, so a unit it holds may have no row above: {}", h(why));
        }
    }

    let lines = crate::strip_verb::suggestions(&report.findings);
    if !lines.is_empty() && !json {
        println!(
            "\n  single lines you can choose to strip instead (each a dry run until --arm; login and\n  \
             privilege files need --auth; nothing here is chosen for you):"
        );
    }
    for s in &lines {
        if json {
            rows.push(crate::strip_verb::suggestion_row(s));
        } else {
            crate::strip_verb::print_suggestion(s);
        }
    }

    let anchors = crate::anchor_verb::suggestions(&crate::trust_verb::linux_report(args));
    if !anchors.is_empty() && !json {
        println!(
            "\n  TLS trust anchors you can choose to remove (each a dry run until --arm; a store source is\n  \
             removed and the store rebuilt, a bundle-only one is taken out of the bundle):"
        );
    }
    for s in &anchors {
        if json {
            rows.push(crate::anchor_verb::suggestion_row(s));
        } else {
            crate::anchor_verb::print_suggestion(s);
        }
    }

    if armed && done.is_empty() {
        drop(journal_file.take());
        if !journal_path.is_empty() {
            std::fs::remove_file(&journal_path).ok();
            journal_path.clear();
        }
    }

    let reload_note = if armed {
        reload_after_removal(touched_systemd, touched_udev)
    } else {
        None
    };

    let mut still_removable = 0usize;
    if armed && !done.is_empty() && !journal_broke {
        let after = hemostat_sensor_linux::persist::report();
        still_removable = plan(&after)
            .iter()
            .filter(|c| c.disposition.is_actionable())
            .count();
    }

    let restorers = if armed {
        hemostat_enforce_linux::restore_watch::restorers_for(&removed_paths)
    } else {
        Vec::new()
    };

    if json {
        jprintln!(
            "{{\"armed\":{armed},\"established\":{},\"total\":{},\"applied\":{},\"planned\":{planned},\
             \"refused\":{refused},\"failed\":{failed},\"advise\":{advised},\
             \"still_removable\":{still_removable},\"systemd_held\":{},\"systemd_unasked\":{},\
             \"journal\":\"{}\",\"halted\":{journal_broke},\
             \"daemon_reload\":\"{}\",\"broker_unchecked\":[{}],\"items\":[{}]}}",
            report.established, report.total, done.len(), held.len(),
            systemd_unasked.as_deref().map_or_else(|| "null".to_string(), |w| format!("\"{}\"", jesc(w))),
            jesc(&journal_path),
            jesc(reload_note.as_deref().unwrap_or("")),
            broker_gaps
                .iter()
                .map(|u| format!(
                    "{{\"stage\":\"{}\",\"why\":\"{}\"}}",
                    jesc(u.stage.token()),
                    jesc(u.why)
                ))
                .collect::<Vec<_>>()
                .join(","),
            rows.join(",")
        );
    } else {
        println!();
        if armed {
            println!("  {} applied · {refused} refused · {failed} failed · {advised} left to you", done.len());
            if !done.is_empty() {
                if still_removable == 0 && held.is_empty() {
                    println!("  re-checked: no removable persistence remains.");
                } else if still_removable == 0 {
                    println!(
                        "  re-checked: no removable catalogue persistence remains; {} unit(s) \
                         systemd holds are left to you, above.",
                        held.len()
                    );
                } else {
                    println!(
                        "  re-checked: {still_removable} removable finding(s) REMAIN — re-run, or \
                         look at what refused above."
                    );
                }
            }
            if !restorers.is_empty() {
                println!(
                    "\n  WARNING — {} boot-time rule(s) would put back what was just removed:",
                    restorers.len()
                );
                for r in &restorers {
                    println!(
                        "    {} recreates {}",
                        h(&r.rule_file.display().to_string()),
                        h(&r.target.display().to_string())
                    );
                    println!("      {}", h(&r.line));
                }
                println!(
                    "    Removing the file is not enough while these stand: systemd-tmpfiles\n    \
                     replays them at every boot. Remove the rule too, then re-run."
                );
            }
            if let Some(note) = &reload_note {
                println!("  {note}");
            }
            if !journal_path.is_empty() && !done.is_empty() {
                println!("  undo journal: {journal_path}");
                println!("  reverse everything with:  hemostat undo {journal_path}");
            }
            if journal_broke {
                println!(
                    "  STOPPED EARLY — the undo journal became unwritable, so the run halted \
                     rather than change more of the host unrecorded."
                );
            }
        } else {
            println!("  {planned} removable · {refused} refused · {advised} left to you");
            println!("  Nothing was changed. Re-run with --arm to apply.");
        }

        if !broker_gaps.is_empty() {
            println!(
                "\n  {} broker stage(s) did NOT run on the actions above:",
                broker_gaps.len()
            );
            for u in &broker_gaps {
                println!("    {} — {}", u.stage.token(), h(u.why));
            }
            println!(
                "    Everything above passed the stages that ran. These are not among them,\n    \
                 so treat this as a gate with holes in it rather than as a clean gate."
            );
        }
    }

    if failed > 0 || journal_broke {
        EXIT_ENFORCER
    } else if let Some(code) = refused_exit {
        code
    } else if !armed && planned > 0 {
        EXIT_DRYRUN
    } else {
        EXIT_OK
    }
}

#[cfg(all(target_os = "linux", feature = "mod-enf-persistence"))]
fn bulk_targets(candidates: &[hemostat_enforce_linux::persistence::Candidate]) -> usize {
    candidates.iter().filter(|c| c.disposition.is_actionable()).count()
}

#[cfg(all(target_os = "linux", feature = "mod-enf-persistence"))]
fn merge_refusal(prev: Option<u8>, code: u8) -> Option<u8> {
    Some(match prev {
        None => code,
        Some(p) if p == code => code,
        Some(_) => EXIT_POLICY,
    })
}

#[cfg(all(target_os = "linux", feature = "mod-enf-persistence"))]
pub(crate) fn open_run_journal() -> Result<(std::fs::File, String), u8> {
    use hemostat_enforce_linux::{journal, DEFAULT_VAULT};
    use std::io::Write as _;

    let dir = std::path::Path::new(DEFAULT_VAULT);
    if let Err(e) = std::fs::create_dir_all(dir) {
        eprintln!(
            "hemostat remediate: cannot create the vault directory {}: {e}\n  Nothing was changed.",
            h(&dir.display().to_string())
        );
        return Err(1);
    }
    let path = journal::unique_path(dir);
    let mut f = std::fs::OpenOptions::new()
        .create_new(true)
        .append(true)
        .open(&path)
        .map_err(|e| {
            eprintln!(
                "hemostat remediate: cannot open the undo journal {}: {e}\n  Nothing was changed.",
                h(&path.display().to_string())
            );
            1_u8
        })?;

    writeln!(f, "{}", journal::HEADER)
        .and_then(|()| f.flush())
        .map_err(|e| {
            eprintln!(
                "hemostat remediate: cannot write the undo journal {}: {e}\n  Nothing was changed.",
                h(&path.display().to_string())
            );
            1_u8
        })?;
    Ok((f, path.display().to_string()))
}

#[cfg(all(target_os = "linux", feature = "mod-enf-persistence"))]
pub(crate) fn reload_after_removal(touched_systemd: bool, touched_udev: bool) -> Option<String> {
    let mut note: Option<String> = None;
    if touched_udev {
        if let Err(e) = hemostat_enforce_linux::udev_reload() {
            note = Some(format!(
                "udev was NOT reloaded ({e}) — run `udevadm control --reload-rules`, or the \
                 removed rules keep firing until the next boot"
            ));
        }
    }
    if touched_systemd {
        match hemostat_enforce_linux::daemon_reload() {

            Ok(()) => {
                if note.is_none() {
                    note = Some("systemd reloaded".into());
                }
            }
            Err(e) => {
                note = Some(format!(
                    "systemd was NOT reloaded ({e}) — run `systemctl daemon-reload` by hand, or \
                     the removed units stay loaded until the next reboot"
                ));
            }
        }
    }
    note
}

#[cfg(target_os = "linux")]
pub(crate) fn undo_verb(positional: &[&str], args: &[String], json: bool) -> u8 {
    use hemostat_enforce_linux::{journal, undo_with, ApplyOptions, Outcome};

    let auth = args.iter().any(|a| a == "--auth");

    let Some(path) = positional.get(1) else {
        eprintln!(
            "usage: hemostat undo <journal> [--auth]   (written by `hemostat remediate --arm`)\n\
             \n  Replays the journal in reverse, restoring each snapshot to where it came from.\n  \
             --auth also puts a stripped line back into a login or privilege file."
        );
        return EXIT_USAGE;
    };
    let text = match hemostat_sensor_linux::saferead::read_text(std::path::Path::new(path)) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("hemostat undo: cannot read {path}: {e}");
            return EXIT_FAILED;
        }
    };
    let records = match journal::decode(&text) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("hemostat undo: refusing to replay {path}: {e}");
            return EXIT_FAILED;
        }
    };

    match crate::authz::reversal_authority(hemostat_evcrypto::ticket::Op::Undo, true) {
        Ok(None) => {}
        Ok(Some(gap)) => eprintln!("hemostat undo: NOTE: {gap}"),
        Err((code, why)) => {
            eprintln!("hemostat undo: {why}");
            return code;
        }
    }

    let opts = ApplyOptions::armed();
    let mut ok = 0usize;
    let mut refused = 0usize;
    let mut failed = 0usize;
    let mut rows: Vec<String> = Vec::new();
    let mut outcomes: Vec<String> = Vec::new();
    for rec in records.iter().rev() {
        let outcome = undo_with(rec, &opts, auth);
        let (state, msg) = match &outcome {
            Outcome::Applied(r) => ("undone", r.did.clone()),
            Outcome::Planned(p) => ("planned", p.detail.clone()),
            Outcome::Refused(r) => ("refused", r.message.clone()),
            Outcome::Failed(f) => ("failed", f.reason.clone()),
        };
        match &outcome {
            Outcome::Applied(_) => ok += 1,

            Outcome::Planned(_) | Outcome::Refused(_) => refused += 1,
            Outcome::Failed(_) => failed += 1,
        }
        outcomes.push(format!("{state}\t{}\t{msg}", rec.did));
        if json {
            rows.push(format!(
                "{{\"state\":\"{state}\",\"was\":\"{}\",\"detail\":\"{}\"}}",
                jesc(&rec.did), jesc(&msg)
            ));
        } else {
            println!("  [{state}] {msg}");
        }
    }

    let recorded = record_replay(path, &outcomes);
    let bad = refused + failed;

    if json {
        jprintln!("{{\"journal\":\"{}\",\"undone\":{ok},\"problems\":{bad},\"items\":[{}]}}", jesc(path), rows.join(","));
    } else {
        println!("\n  {ok} undone · {bad} not undone");
        if bad == 0 {
            println!("  The journal has been fully replayed; it can be archived with the case.");
        }
    }
    if let Err(why) = &recorded {
        eprintln!("hemostat undo: the replay was not recorded: {why}");
    }
    undo_exit(failed, refused, recorded.is_ok())
}

fn undo_exit(failed: usize, refused: usize, recorded: bool) -> u8 {
    if failed > 0 {
        crate::EXIT_ENFORCER
    } else if !recorded {
        EXIT_FAILED
    } else if refused > 0 {
        crate::EXIT_POLICY
    } else {
        EXIT_OK
    }
}

pub(crate) fn record_replay(journal: &str, outcomes: &[String]) -> Result<std::path::PathBuf, String> {
    use std::io::Write as _;
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());

    let mut n = 0u32;
    let (path, mut f) = loop {
        let path = std::path::PathBuf::from(if n == 0 {
            format!("{journal}.replayed-{secs}")
        } else {
            format!("{journal}.replayed-{secs}-{n}")
        });
        match std::fs::OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(f) => break (path, f),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists && n < 999 => n += 1,
            Err(e) => return Err(format!("{}: {e}", path.display())),
        }
    };
    for line in outcomes {
        writeln!(f, "{line}").map_err(|e| format!("{}: {e}", path.display()))?;
    }
    f.sync_all().map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(path)
}

#[cfg(all(target_os = "linux", feature = "mod-enf-persistence"))]
fn planned_row(c: &hemostat_enforce_linux::persistence::Candidate, p: &hemostat_enforce_linux::Plan) -> String {
    format!(
        "{{\"state\":\"planned\",\"mechanism\":\"{}\",\"locus\":\"{}\",\
         \"severity\":\"{}\",\"would\":\"{}\",\"undo\":\"{}\",\"reversible\":{}}}",
        jesc(&c.mechanism),
        jesc(&c.locus),
        c.severity.tag(),
        jesc(&p.detail),
        jesc(&p.undo),
        p.reversible
    )
}

#[cfg(all(target_os = "linux", feature = "mod-enf-persistence"))]
fn print_planned(c: &hemostat_enforce_linux::persistence::Candidate, p: &hemostat_enforce_linux::Plan) {
    println!("  [{}] {}  {}", c.severity.tag(), h(&c.mechanism), h(&c.locus));
    println!("        found: {}", h(&c.what));
    println!("        would: {}", h(&p.detail));
    println!("        undo:  {}", h(&p.undo));
}

#[cfg(all(target_os = "linux", feature = "mod-enf-persistence"))]
fn applied_row(c: &hemostat_enforce_linux::persistence::Candidate, rec: &hemostat_enforce_linux::UndoRecord) -> String {
    format!(
        "{{\"state\":\"applied\",\"mechanism\":\"{}\",\"locus\":\"{}\",\
         \"severity\":\"{}\",\"did\":\"{}\",\"reversible\":{}}}",
        jesc(&c.mechanism),
        jesc(&c.locus),
        c.severity.tag(),
        jesc(&rec.did),
        rec.reversible
    )
}

#[cfg(all(target_os = "linux", feature = "mod-enf-persistence"))]
fn why_row(state: &str, c: &hemostat_enforce_linux::persistence::Candidate, why: &str) -> String {
    format!(
        "{{\"state\":\"{state}\",\"mechanism\":\"{}\",\"locus\":\"{}\",\"why\":\"{}\"}}",
        jesc(&c.mechanism),
        jesc(&c.locus),
        jesc(why)
    )
}

#[cfg(all(target_os = "linux", feature = "mod-enf-persistence"))]
fn print_why(tag: &str, c: &hemostat_enforce_linux::persistence::Candidate, why: &str) {
    println!("  [{tag}] {}  {}\n        {}", h(&c.mechanism), h(&c.locus), h(why));
}

#[cfg(all(target_os = "linux", feature = "mod-enf-persistence"))]
fn advise_row(c: &hemostat_enforce_linux::persistence::Candidate, why: &str) -> String {
    format!(
        "{{\"state\":\"advise\",\"mechanism\":\"{}\",\"locus\":\"{}\",\
         \"severity\":\"{}\",\"found\":\"{}\",\"why\":\"{}\"}}",
        jesc(&c.mechanism),
        jesc(&c.locus),
        c.severity.tag(),
        jesc(&c.what),
        jesc(why)
    )
}

#[cfg(all(target_os = "linux", feature = "mod-enf-persistence"))]
const SYSTEMD_HELD_ADVICE: &str =
    "systemd holds this unit and this run has no file of it to remove reversibly: a transient \
     unit's only file is systemd's own under /run, and one without a file or outside the swept \
     tree was never catalogued. Read it with `systemctl cat`, capture what it runs, then \
     `systemctl stop` it by hand — stopping a unit cannot be undone.";

#[cfg(all(target_os = "linux", feature = "mod-enf-persistence"))]
fn systemd_held(
    e: &hemostat_sensor_linux::enablement::Report,
) -> Vec<hemostat_enforce_linux::persistence::Candidate> {
    use hemostat_enforce_linux::persistence::{Candidate, Disposition};
    use hemostat_sensor_linux::triage::Severity;
    e.findings
        .iter()
        .filter(|f| f.severity >= Severity::Warn)
        .map(|f| Candidate {
            mechanism: f.subject.clone(),
            locus: f.locus.clone(),
            severity: f.severity,
            what: f.what.clone(),
            disposition: Disposition::Advise(SYSTEMD_HELD_ADVICE),
        })
        .collect()
}

#[cfg(all(target_os = "linux", feature = "mod-enf-persistence"))]
fn print_advise(c: &hemostat_enforce_linux::persistence::Candidate, why: &str) {
    println!("  [yours] {}  {}", h(&c.mechanism), h(&c.locus));
    println!("        found: {}", h(&c.what));
    println!("        {}", h(why));
}

#[cfg(all(target_os = "linux", feature = "mod-enf-persistence"))]
pub(crate) fn append_record(f: Option<&mut std::fs::File>, rec: &hemostat_enforce_linux::UndoRecord) -> bool {
    use hemostat_enforce_linux::{journal, DEFAULT_VAULT};
    use std::io::Write as _;
    let Some(f) = f else { return true };
    match f.write_all(journal::line(rec).as_bytes()).and_then(|()| f.flush()) {
        Ok(()) => true,
        Err(e) => {
            eprintln!(
                "hemostat remediate: the undo journal could not be appended to ({e}). Stopping \
                 here rather than changing more of the host with no way to record it — the \
                 snapshots so far are in {DEFAULT_VAULT}.",
            );
            false
        }
    }
}

#[cfg(all(target_os = "linux", feature = "mod-enf-persistence"))]
pub(crate) fn reload_needed_for(path: &std::path::Path) -> (bool, bool) {
    let p = path.to_string_lossy();
    (p.contains("/systemd/"), p.contains("/udev/rules.d/"))
}
