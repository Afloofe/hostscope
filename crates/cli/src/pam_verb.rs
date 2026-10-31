use hemostat_enforce_linux::pam_validate::{self, AfterSwap, Probe};
use hemostat_enforce_linux::{ApplyOptions, Outcome, ProtectSet, RemovalAction};

use crate::authz::{broker_admits, exit_for_refusal, loaded_sanction, presented_authority};
use crate::pam_golden::{self, DistroKey, KnownModule, Pick};
use crate::render::{h, jesc};
use crate::{repeated_flag_values, EXIT_AUTHZ, EXIT_DRYRUN, EXIT_ENFORCER, EXIT_OK, EXIT_PARTIAL, EXIT_POLICY, EXIT_USAGE};

pub(crate) enum State {

    Clean { build: &'static KnownModule },

    Tampered { build: &'static KnownModule, on_disk: String },

    VersionMismatch { pkg: &'static str, installed: Option<String>, baked: Vec<&'static str> },

    Ambiguous { why: String },

    Unreadable { build: &'static KnownModule, why: String },
}

pub(crate) struct Finding {

    pub(crate) path: &'static str,
    pub(crate) state: State,
}

pub(crate) enum Scanned {

    GoldenOff,

    Release { release: String, findings: Vec<Finding> },
}

pub(crate) fn scan() -> Result<Scanned, String> {
    if !crate::golden::active() {
        return Ok(Scanned::GoldenOff);
    }
    let key = pam_golden::detect()?;
    let arch = pam_golden::host_arch();
    let mgr = hemostat_sensor_linux::pkg::manager();
    let findings = judge(
        pam_golden::KNOWN,
        &key,
        arch,
        |pkg| mgr.as_ref().and_then(|g| g.installed_version(pkg)),
        |path| {
            hemostat_sensor_linux::saferead::sha256_of(std::path::Path::new(path))
                .map(|d| hex32(&d))
                .map_err(|e| e.to_string())
        },
    );
    Ok(Scanned::Release { release: release_of(&key, arch), findings })
}

fn release_of(key: &DistroKey, arch: &str) -> String {
    format!("{} {} {arch}", key.id, key.version_id)
}

fn nothing_baked_why(release: &str, table: &[KnownModule]) -> String {
    let mut baked: Vec<String> = Vec::new();
    for m in table {
        let r = format!("{} {} {}", m.distro_id, m.version_id, m.arch);
        if !baked.contains(&r) {
            baked.push(r);
        }
    }
    let baked = if baked.is_empty() { "none".to_string() } else { baked.join(", ") };
    format!(
        "nothing is baked for {release} (ID and VERSION_ID from /etc/os-release, and the CPU arch); \
         builds are baked for {baked}"
    )
}

fn judge(
    table: &'static [KnownModule],
    key: &DistroKey,
    arch: &str,
    installed_version: impl Fn(&str) -> Option<String>,
    digest: impl Fn(&str) -> Result<String, String>,
) -> Vec<Finding> {
    pam_golden::paths_for(table, key, arch)
        .into_iter()
        .filter_map(|path| {
            let state = match pam_golden::pick(table, key, arch, path, &installed_version)? {
                Pick::Build(build) => match digest(build.path) {
                    Ok(got) if got.eq_ignore_ascii_case(build.sha256) => State::Clean { build },
                    Ok(got) => State::Tampered { build, on_disk: got },
                    Err(why) => State::Unreadable { build, why },
                },
                Pick::NoBuild { pkg, installed, baked } => State::VersionMismatch { pkg, installed, baked },
                Pick::Ambiguous(why) => State::Ambiguous { why },
            };
            Some(Finding { path, state })
        })
        .collect()
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

fn restore_cmd(path: &str) -> String {
    format!("hemostat remediate --restore-pam {} --arm", sh_quote(path))
}

fn no_build_why(pkg: &str, installed: Option<&str>, baked: &[&str], release: &str) -> String {
    format!(
        "installed {pkg} {} is none of the builds baked for {release} ({})",
        installed.unwrap_or("(not installed, or its version could not be read)"),
        baked.join(", ")
    )
}

fn not_baked_why(path: &str, release: &str, baked_paths: &[&str]) -> String {
    let have = if baked_paths.is_empty() {
        "nothing is baked for it".to_string()
    } else {
        format!("baked for it: {}", baked_paths.join(", "))
    };
    format!("no baked known-good for {path} on {release} ({have})")
}

fn json_row(f: &Finding) -> String {
    let path = jesc(f.path);
    let judged = |b: &KnownModule| format!("\"pkg\":\"{}\",\"build\":\"{}\"", jesc(b.pkg), jesc(b.pkg_version));
    match &f.state {
        State::Clean { build } => format!("{{\"path\":\"{path}\",\"state\":\"clean\",{}}}", judged(build)),
        State::Tampered { build, on_disk } => format!(
            "{{\"path\":\"{path}\",\"state\":\"tampered\",{},\"expected\":\"{}\",\"on_disk\":\"{}\"}}",
            judged(build),
            jesc(build.sha256),
            jesc(on_disk)
        ),
        State::VersionMismatch { pkg, installed, baked } => format!(
            "{{\"path\":\"{path}\",\"state\":\"version-mismatch\",\"pkg\":\"{}\",\"baked\":\"{}\",\"baked_builds\":[{}],\"installed\":{}}}",
            jesc(pkg),
            jesc(&baked.join(", ")),
            baked.iter().map(|v| format!("\"{}\"", jesc(v))).collect::<Vec<_>>().join(","),
            installed.as_deref().map_or("null".to_string(), |v| format!("\"{}\"", jesc(v)))
        ),
        State::Ambiguous { why } => format!("{{\"path\":\"{path}\",\"state\":\"ambiguous\",\"why\":\"{}\"}}", jesc(why)),
        State::Unreadable { build, why } => {
            format!("{{\"path\":\"{path}\",\"state\":\"unreadable\",{},\"why\":\"{}\"}}", judged(build), jesc(why))
        }
    }
}

fn text_row(f: &Finding) -> String {
    match &f.state {
        State::Clean { build } => {
            format!("  [ok]       {} — matches stock {} {}", h(f.path), h(build.pkg), h(build.pkg_version))
        }
        State::Tampered { build, on_disk } => format!(
            "  [TAMPERED] {} — on-disk {}…, stock {}… ({} {})\n             {}",
            h(f.path),
            h(on_disk.get(..16).unwrap_or(on_disk)),
            h(build.sha256.get(..16).unwrap_or(build.sha256)),
            h(build.pkg),
            h(build.pkg_version),
            h(&restore_cmd(f.path))
        ),
        State::VersionMismatch { pkg, installed, baked } => crate::render::wrap_why(
            &h(&format!(
                "{} — {}; restore from the package cache",
                f.path,
                no_build_why(pkg, installed.as_deref(), baked, "this release")
            )),
            "  [skip]     ",
        ),
        State::Ambiguous { why } => format!("  [warn]     {} — {}; not checked", h(f.path), h(why)),
        State::Unreadable { why, .. } => format!("  [warn]     {} — {}", h(f.path), h(why)),
    }
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
    let (release, findings) = match scan() {
        Ok(Scanned::Release { release, findings }) => (release, findings),
        Ok(Scanned::GoldenOff) => return golden_off(json),
        Err(why) => return distro_unknown(&why, json),
    };
    if findings.is_empty() {
        return not_baked(&nothing_baked_why(&release, pam_golden::KNOWN), json);
    }
    if json {
        let rows: Vec<String> = findings.iter().map(json_row).collect();
        jprintln!("{{\"pam_modules\":[{}]}}", rows.join(","));
        return EXIT_OK;
    }
    println!("{}", summary_line(&findings));
    for f in &findings {
        println!("{}", text_row(f));
    }
    EXIT_OK
}

fn summary_line(findings: &[Finding]) -> String {
    let tampered = findings.iter().filter(|f| matches!(f.state, State::Tampered { .. })).count();
    let unchecked = findings.iter().filter(|f| !matches!(f.state, State::Clean { .. } | State::Tampered { .. })).count();
    let unchecked = if unchecked == 0 { String::new() } else { format!(", {unchecked} not checked") };
    format!(
        "  PAM modules checked against the distribution's stock build of the installed version — \
         {tampered} tampered{unchecked}. Each restore is a dry run until --arm."
    )
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

const GOLDEN_OFF: &str = "  The golden baseline is off (HEMOSTAT_GOLDEN is not set), so no PAM module was \
     checked: the baked known-good builds are for comp boxes alone. Set HEMOSTAT_GOLDEN on a comp box.";

fn golden_off(json: bool) -> u8 {
    if json {
        jprintln!("{{\"pam_modules\":[],\"golden\":false}}");
    } else {
        println!("{GOLDEN_OFF}");
    }
    EXIT_OK
}

fn not_baked(why: &str, json: bool) -> u8 {
    if json {
        jprintln!("{{\"pam_modules\":[],\"not_baked\":\"{}\"}}", jesc(why));
    } else {
        println!(
            "  {} — no baked known-good PAM module can be matched to this host, so none was checked.",
            h(why)
        );
    }
    EXIT_PARTIAL
}

fn unbaked_refusal(path: &str, release: &str, baked_paths: &[&str], table: &[KnownModule]) -> (u8, String) {
    if baked_paths.is_empty() {
        (EXIT_POLICY, format!("refusing to restore {path} — {}", nothing_baked_why(release, table)))
    } else {
        (EXIT_USAGE, not_baked_why(path, release, baked_paths))
    }
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
    let release = release_of(&key, arch);

    let mgr = hemostat_sensor_linux::pkg::manager();
    let picked = pam_golden::pick(pam_golden::KNOWN, &key, arch, &path, |pkg| {
        mgr.as_ref().and_then(|g| g.installed_version(pkg))
    });
    let m = match picked {
        Some(Pick::Build(m)) => m,
        None => {
            let baked_paths = pam_golden::paths_for(pam_golden::KNOWN, &key, arch);
            let (code, why) = unbaked_refusal(&path, &release, &baked_paths, pam_golden::KNOWN);
            eprintln!("hemostat remediate: {}. Nothing was attempted", h(&why));
            return code;
        }
        Some(Pick::NoBuild { pkg, installed, baked }) => {
            eprintln!(
                "hemostat remediate: refusing to restore {} — {}. Writing our bytes could be the \
                 wrong build; restore from the package cache (apt/dnf reinstall from /var/cache) \
                 instead. Nothing was changed",
                h(&path),
                h(&no_build_why(pkg, installed.as_deref(), &baked, &release))
            );
            return EXIT_POLICY;
        }
        Some(Pick::Ambiguous(why)) => {
            eprintln!("hemostat remediate: refusing to restore {} — {}. Nothing was changed", h(&path), h(&why));
            return EXIT_POLICY;
        }
    };

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

    let protect = ProtectSet::gather()
        .declaring_scored(crate::golden::scored_units_here())
        .declaring_protected(declared);
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

            let journalled = crate::remediate_verb::append_record(journal.as_mut(), rec);

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

                    let kept_journal = !rolled_back && journalled;
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
