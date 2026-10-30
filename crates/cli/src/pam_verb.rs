use hemostat_enforce_linux::pam_validate::{self, AfterSwap, Probe};
use hemostat_enforce_linux::{ApplyOptions, Outcome, ProtectSet, RemovalAction};

use crate::authz::{broker_admits, exit_for_refusal, loaded_sanction, presented_authority};
use crate::pam_golden::{self, KnownModule};
use crate::render::{h, jesc};
use crate::{repeated_flag_values, EXIT_AUTHZ, EXIT_DRYRUN, EXIT_ENFORCER, EXIT_OK, EXIT_PARTIAL, EXIT_POLICY, EXIT_USAGE};

pub(crate) enum State {

    Clean,

    Tampered { on_disk: String },

    VersionMismatch { installed: Option<String> },

    Unreadable { why: String },
}

pub(crate) struct Finding {
    pub(crate) module: &'static KnownModule,
    pub(crate) state: State,
}

pub(crate) fn scan() -> Result<Vec<Finding>, String> {
    if !crate::golden::active() {
        return Ok(Vec::new());
    }
    let key = pam_golden::detect()?;
    let arch = pam_golden::host_arch();
    let mgr = hemostat_sensor_linux::pkg::manager();
    Ok(pam_golden::KNOWN
        .iter()
        .filter(|m| m.distro_id == key.id && m.version_id == key.version_id && m.arch == arch)
        .map(|m| {
            let installed = mgr.as_ref().and_then(|g| g.installed_version(m.pkg));
            if installed.as_deref() != Some(m.pkg_version) {
                return Finding { module: m, state: State::VersionMismatch { installed } };
            }
            let state = match hemostat_sensor_linux::saferead::sha256_of(std::path::Path::new(m.path)) {
                Ok(d) => {
                    let got = hex32(&d);
                    if got.eq_ignore_ascii_case(m.sha256) {
                        State::Clean
                    } else {
                        State::Tampered { on_disk: got }
                    }
                }
                Err(e) => State::Unreadable { why: e.to_string() },
            };
            Finding { module: m, state }
        })
        .collect())
}

fn hex32(b: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for x in b {
        s.push_str(&format!("{x:02x}"));
    }
    s
}

fn sh_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

fn restore_cmd(m: &KnownModule) -> String {
    format!("hemostat remediate --restore-pam {} --arm", sh_quote(m.path))
}

fn label_of(m: &KnownModule) -> String {
    let base = std::path::Path::new(m.path)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(m.path);
    format!("{base} ({} {})", m.pkg, m.pkg_version)
}

pub(crate) fn dispatch(args: &[String], json: bool) -> Option<u8> {
    if args.iter().any(|a| a == "--pam") {
        return Some(list(json));
    }
    if args.iter().any(|a| a == "--restore-pam") {
        return Some(restore(args, json));
    }
    None
}

fn list(json: bool) -> u8 {
    let findings = match scan() {
        Ok(f) => f,
        Err(why) => return distro_unknown(&why, json),
    };
    if json {
        let rows: Vec<String> = findings
            .iter()
            .map(|f| match &f.state {
                State::Clean => format!("{{\"path\":\"{}\",\"state\":\"clean\"}}", jesc(f.module.path)),
                State::Tampered { on_disk } => format!(
                    "{{\"path\":\"{}\",\"state\":\"tampered\",\"expected\":\"{}\",\"on_disk\":\"{}\"}}",
                    jesc(f.module.path),
                    jesc(f.module.sha256),
                    jesc(on_disk)
                ),
                State::VersionMismatch { installed } => format!(
                    "{{\"path\":\"{}\",\"state\":\"version-mismatch\",\"baked\":\"{}\",\"installed\":{}}}",
                    jesc(f.module.path),
                    jesc(f.module.pkg_version),
                    installed.as_deref().map_or("null".to_string(), |v| format!("\"{}\"", jesc(v)))
                ),
                State::Unreadable { why } => {
                    format!("{{\"path\":\"{}\",\"state\":\"unreadable\",\"why\":\"{}\"}}", jesc(f.module.path), jesc(why))
                }
            })
            .collect();
        jprintln!("{{\"pam_modules\":[{}]}}", rows.join(","));
        return EXIT_OK;
    }
    if findings.is_empty() {
        println!(
            "  No baked known-good PAM modules apply here (the golden baseline is off, or this is \
             not a pinned comp distro). Set HEMOSTAT_GOLDEN on a comp box."
        );
        return EXIT_OK;
    }
    let tampered = findings.iter().filter(|f| matches!(f.state, State::Tampered { .. })).count();
    println!(
        "  PAM modules checked against the distribution's stock build — {tampered} tampered. Each \
         restore is a dry run until --arm."
    );
    for f in &findings {
        match &f.state {
            State::Clean => println!("  [ok]       {} — matches stock", h(f.module.path)),
            State::Tampered { on_disk } => {
                println!("  [TAMPERED] {} — on-disk {}…, stock {}…", h(f.module.path), h(&on_disk[..16]), h(&f.module.sha256[..16]));
                println!("             {}", h(&restore_cmd(f.module)));
            }
            State::VersionMismatch { installed } => println!(
                "  [skip]     {} — installed {} is not the baked {}; restore from the package cache",
                h(f.module.path),
                h(installed.as_deref().unwrap_or("(not installed)")),
                h(f.module.pkg_version)
            ),
            State::Unreadable { why } => println!("  [warn]     {} — {}", h(f.module.path), h(why)),
        }
    }
    EXIT_OK
}

fn distro_unknown(why: &str, json: bool) -> u8 {
    if json {
        jprintln!("{{\"pam_modules\":[],\"distro_unknown\":\"{}\"}}", jesc(why));
    } else {
        println!(
            "  {} — no baked known-good PAM module can be matched to this host, so none was checked.",
            h(why)
        );
    }
    EXIT_PARTIAL
}

fn restore(args: &[String], json: bool) -> u8 {
    let armed = args.iter().any(|a| a == "--arm");
    let path = match repeated_flag_values(args, "--restore-pam").as_deref() {
        Ok([one]) => one.clone(),
        Ok(_) => {
            eprintln!("hemostat remediate: one --restore-pam per run, so each module is its own decision");
            return EXIT_USAGE;
        }
        Err(_) => {
            eprintln!("hemostat remediate: --restore-pam needs the module path `--pam` printed");
            return EXIT_USAGE;
        }
    };

    if !crate::golden::active() {
        eprintln!("hemostat remediate: --restore-pam needs HEMOSTAT_GOLDEN set (the baked known-good is comp-gated)");
        return EXIT_POLICY;
    }
    let key = match pam_golden::detect() {
        Ok(k) => k,
        Err(why) => {
            eprintln!("hemostat remediate: {}. Nothing was attempted", h(&why));
            return EXIT_POLICY;
        }
    };
    let arch = pam_golden::host_arch();
    let Some(m) = pam_golden::known_good_for(&key, arch, &path) else {
        eprintln!(
            "hemostat remediate: no baked known-good for {} on {} {} ({arch}). Nothing was attempted",
            h(&path),
            h(&key.id),
            h(&key.version_id)
        );
        return EXIT_USAGE;
    };

    let installed = hemostat_sensor_linux::pkg::manager().and_then(|g| g.installed_version(m.pkg));
    if installed.as_deref() != Some(m.pkg_version) {
        eprintln!(
            "hemostat remediate: refusing to restore {} — installed {} is {}, not the baked {}. \
             Writing our bytes could be the wrong build; restore from the package cache \
             (apt/dnf reinstall from /var/cache) instead. Nothing was changed",
            h(&path),
            h(m.pkg),
            h(installed.as_deref().unwrap_or("not installed")),
            h(m.pkg_version)
        );
        return EXIT_POLICY;
    }

    let declared = match repeated_flag_values(args, "--protect") {
        Ok(v) => v,
        Err(flag) => {
            eprintln!("hemostat remediate: every {flag} needs a value");
            return EXIT_USAGE;
        }
    };

    let action = RemovalAction::RestoreKnownGood {
        path: std::path::PathBuf::from(&path),
        content: m.bytes.to_vec(),
        want_sha256: m.sha256.to_string(),
        label: label_of(m),
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
                jprintln!("{{\"state\":\"refused\",\"locus\":\"{}\",\"why\":\"{}\"}}", jesc(&path), jesc(&why));
            } else {
                println!("  [REFUSED] {}\n        {}", h(&path), h(&why));
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

    let baseline = if armed { Some(pam_validate::probe()) } else { None };

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
                    jesc(&path),
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

            let gated = baseline.as_ref().is_some_and(Probe::can_gate);
            let post = if gated { Some(pam_validate::probe()) } else { None };

            let decision = match (&baseline, &post) {
                (Some(before), Some(after)) => pam_validate::after_swap(before, after),
                _ => AfterSwap::Ungated,
            };
            let before = baseline.as_ref().map(Probe::describe).unwrap_or_default();
            match decision {
                AfterSwap::RollBack => {
                    let note = post.as_ref().map(|p| p.describe()).unwrap_or_default();
                    let rollback = hemostat_enforce_linux::undo(rec, &ApplyOptions::armed());
                    let rolled_back = matches!(rollback, Outcome::Applied(_));

                    let kept_journal = !rolled_back && crate::remediate_verb::append_record(journal.as_mut(), rec);
                    drop(journal.take());
                    if !kept_journal {
                        let _ = std::fs::remove_file(&journal_path);
                    }
                    let rb = match &rollback {
                        Outcome::Applied(_) => "the module that was there before was put back; the box's auth is as it was before this run".to_string(),
                        other if kept_journal => format!(
                            "THE ROLLBACK DID NOT COMPLETE ({other:?}) — run `hemostat undo {journal_path}` NOW, or restore {path} by hand from the vault"
                        ),
                        other => format!("THE ROLLBACK DID NOT COMPLETE ({other:?}) — restore {path} by hand from the vault NOW"),
                    };

                    let still = if !rolled_back {
                        String::new()
                    } else {
                        let open = if matches!(baseline, Some(Probe::AcceptsAnyPassword)) {
                            format!(", and before the swap {before}")
                        } else {
                            String::new()
                        };
                        format!(
                            "WARNING: this box STILL RUNS THE MODULE IT HAD, the one marked \
                             tampered{open}. The stock build of {path} did not pass a live login \
                             here, so do not reinstall its package blind: look at the auth log and \
                             /etc/pam.d, then run --restore-pam again."
                        )
                    };
                    if json {
                        jprintln!(
                            "{{\"state\":\"rolled-back\",\"locus\":\"{}\",\"why\":\"{}\",\"rollback\":\"{}\",\"before_swap\":\"{}\",\"warning\":\"{}\"}}",
                            jesc(&path),
                            jesc(&note),
                            jesc(&rb),
                            jesc(&before),
                            jesc(&still)
                        );
                    } else {
                        println!("  [ROLLED BACK] {}", h(&path));
                        println!("        {} after the swap, so it was reverted.", h(&note));
                        println!("        {}", h(&rb));
                        if !still.is_empty() {
                            println!("{}", crate::render::wrap_why(&h(&still), "        "));
                        }
                    }
                    EXIT_ENFORCER
                }
                AfterSwap::Keep | AfterSwap::KeepStillOpen | AfterSwap::Ungated => {
                    let journalled = crate::remediate_verb::append_record(journal.as_mut(), rec);
                    if json {
                        let live = match decision {
                            AfterSwap::Keep => "passed",
                            AfterSwap::KeepStillOpen => "accepts-any-password",
                            AfterSwap::Ungated | AfterSwap::RollBack => "unavailable",
                        };
                        jprintln!(
                            "{{\"state\":\"applied\",\"locus\":\"{}\",\"did\":\"{}\",\"journal\":\"{}\",\"journalled\":{journalled},\"live_auth_test\":\"{live}\",\"before_swap\":\"{}\"}}",
                            jesc(&path),
                            jesc(&rec.did),
                            jesc(&journal_path),
                            jesc(&before)
                        );
                    } else {
                        println!("{}", crate::render::wrap_why(&h(&rec.did), "  [done] "));
                        let after = post.as_ref().map(Probe::describe).unwrap_or_default();
                        if decision == AfterSwap::Keep {
                            println!("        live auth test after the swap: {}.", h(&after));
                            if matches!(baseline, Some(Probe::AcceptsAnyPassword)) {
                                println!(
                                    "        before the swap, {}; the restored module refuses a wrong \
                                     password now.",
                                    h(&before)
                                );
                            }
                        } else if decision == AfterSwap::KeepStillOpen {

                            let warning = format!(
                                "WARNING: after the swap, as before it, {after}. The stock module is in \
                                 place and is kept (the swap made nothing worse), but this PAM stack \
                                 STILL LETS ANYONE IN: look at /etc/pam.d (su's stack and what it \
                                 includes) for the rest of it."
                            );
                            println!("{}", crate::render::wrap_why(&h(&warning), "        "));
                        } else if baseline.is_some() {

                            let why = if matches!(baseline, Some(Probe::Rejects)) {
                                " (a broken module does this, and so does an su policy that bars \
                                 unprivileged accounts, such as pam_wheel)"
                            } else {
                                ""
                            };
                            println!(
                                "        note: before the swap, {}{} — so it could not be the live \
                                 gate; relied on the version + digest + atomic guarantees.",
                                h(&before),
                                why
                            );
                        }
                        println!("  undo journal: {}", h(&journal_path));
                        println!("  reverse it with:  hemostat undo {}", h(&journal_path));
                    }
                    if journalled { EXIT_OK } else { EXIT_ENFORCER }
                }
            }
        }
        Outcome::Refused(r) => {
            if json {
                jprintln!("{{\"state\":\"refused\",\"locus\":\"{}\",\"why\":\"{}\"}}", jesc(&path), jesc(&r.message));
            } else {
                println!("{}", crate::render::wrap_why(&h(&r.message), "  [refused] "));
            }
            EXIT_POLICY
        }
        Outcome::Failed(f) => {
            if json {
                jprintln!("{{\"state\":\"failed\",\"locus\":\"{}\",\"why\":\"{}\"}}", jesc(&path), jesc(&f.reason));
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
