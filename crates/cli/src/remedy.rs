#[cfg(all(target_os = "linux", feature = "mod-tui"))]
use crate::authz::{current_profile, loaded_sanction, presented_authority};
#[cfg(all(target_os = "linux", feature = "mod-tui"))]
use crate::views::journal_one;
#[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "windows"))]
use crate::MANIFEST;

#[cfg(all(target_os = "linux", feature = "mod-tui"))]
pub(crate) fn linux_remedy(
    source: &str,
    subject: &str,
    what: &str,
    locus: &str,
    sev: hemostat_tui::Sev,
) -> Option<hemostat_tui::Remedy> {
    use hemostat_tui::{Remedy, Risk, Sev};

    if subject == "/etc/ld.so.preload" || subject.ends_with("· /etc/ld.so.preload") {
        return Some(Remedy {
            what: "move /etc/ld.so.preload into the vault".into(),
            risk: Risk::Safe,
            note: "the file is absent on a stock server, so an empty preload list is the normal state. New processes stop loading the library immediately; ones already running keep it until they restart"
                .into(),
  undo: "hemostat undo <journal>, or move the file back out of /var/lib/hemostat/quarantine"
                .into(),
            id: "linux:ld-preload".into(),
        });
    }

    if source == "sysctl" {
        let key = subject.strip_prefix("sysctl · ").unwrap_or(subject);
        if let Some(c) = hemostat_sensor_linux::sysctlpolicy::CONTROLS
            .iter()
            .find(|c| c.keys.first() == Some(&key))
        {
            if matches!(c.auto, hemostat_sensor_linux::sysctlpolicy::Auto::Offer) {
                let n = c.keys.len();
                return Some(Remedy {
                    what: format!(
                        "set {} to {} (runtime + /etc/sysctl.d)",
                        if n == 1 { key.to_string() } else { format!("{n} keys") },
                        c.want
                    ),
                    risk: Risk::MayBreak,
                    note: format!(
                        "written one key at a time straight to /proc/sys — never `sysctl \
                         --system`, which reapplies the whole tree and would rewrite a couple \
                         of dozen unrelated keys. Each write is read back from the kernel, and \
                         if any key in the set fails the ones already changed are put back so \
                         it cannot end up half-applied. Cost: {}",
                        c.breaks
                    ),
                    undo: format!(
                        "write the previous value back to /proc/sys/{}, and delete its line \
                         from {}",
                        key.replace('.', "/"),
                        hemostat_sensor_linux::sysctlpolicy::DROP_IN
                    ),
                    id: format!("linux:sysctl:{key}"),
                });
            }
        }
    }

    if source == "sshd" {
        let spelling = subject.strip_prefix("sshd · ").unwrap_or(subject);
        if let Some(c) =
            hemostat_sensor_linux::sshd::CONTROLS.iter().find(|c| c.spelling == spelling)
        {
            let want = hemostat_sensor_linux::sshd::wanted_value(c);
            return Some(Remedy {
                what: format!("stage `{spelling} {want}` in a drop-in (no restart)"),
                risk: Risk::NeedsReload,
                note: format!(
                    "written to a 00- drop-in so it wins OpenSSH's first-value-wins ordering, \
                     then checked with `sshd -T`; if the value did not actually change it is \
                     rolled back and reported as not applied. The running daemon is NOT \
                     restarted. Cost when it does take effect: {}",
                    c.breaks
                ),
                undo: format!(
                    "delete /etc/ssh/sshd_config.d/{}",
                    hemostat_sensor_linux::sshd::DROP_IN
                ),
                id: format!("linux:sshd:{spelling}"),
            });
        }
    }

    if source == "accounts" && crate::golden::is_protected(subject) {
        return None;
    }

    if source == "accounts" && what.starts_with("has NO password") && subject != "root" {
        return Some(Remedy {
            what: format!(
                "lock `{subject}` so its empty password cannot be used (usermod -L, shell to \
                 nologin)"
            ),

            risk: Risk::MayBreak,
            note: "an empty password field authenticates anyone who tries it. Locking replaces \
                   the field with `!`, which nothing will ever match, and sets the shell to \
                   nologin so a key or an `su` cannot get in either. Nothing the account owns \
                   is touched, but the shell change is a change: the previous shell is printed \
                   when this is applied, and putting it back is part of the undo"
                .into(),
            undo: format!(
                "usermod -U {subject} -s <the shell printed when this was applied>, then set a \
                 password with passwd {subject}"
            ),
            id: format!("linux:lock-account:{subject}"),
        });
    }

    if source == "accounts" && what.starts_with("is a system account (uid ") {
        if let Some(group) = what.split('`').nth(1) {
            return Some(Remedy {
                what: format!("remove `{subject}` from the `{group}` group"),

                risk: Risk::MayBreak,
                note: format!(
                    "daemons are granted the privileges they need directly, so a service \
                     account in `{group}` is a route to root that nothing in the system \
                     depends on — usually. If this one turns out to be the exception, putting \
                     it back is one command, and the undo journal carries it. The account, its \
                     files and its running processes are not touched"
                ),
                undo: format!("gpasswd -a {subject} {group}"),
                id: format!("linux:group-drop:{subject}:{group}"),
            });
        }
    }

    if source == "accounts" && what.starts_with("uid 0") && subject != "root" {
        return Some(Remedy {
            what: format!("lock the account `{subject}` (usermod -L, shell to nologin)"),
            risk: Risk::MayBreak,
            note: "stops any login as this account and leaves everything it owns in place. If it turns out to be infrastructure rather than a backdoor, unlocking is one command — which is why this locks rather than deletes"
                .into(),
            undo: format!(
                "usermod -U {subject} -s <the shell printed when this was applied>"
            ),
            id: format!("linux:lock-account:{subject}"),
        });
    }

    if source == "suid"
        && matches!(sev, Sev::Critical | Sev::Warn)
        && (what.starts_with("is a SUID-root ") || what.starts_with("is a SUID+SGID-root "))
    {
        if let Some(path) = subject.split_once('`').and_then(|(_, rest)| rest.strip_suffix('`')) {
            return Some(Remedy {
                what: format!("clear the setuid bit on {path}"),
                risk: Risk::MayBreak,
                note: "the file stays exactly where it is and keeps its contents; it simply \
                       stops conferring root on whoever runs it. If it turns out to be a \
                       legitimate helper, something that needed it will start failing"
                    .into(),
                undo: format!("chmod u+s {path}"),
                id: format!("linux:unsetuid:{path}"),
            });
        }
    }

    if source == "persistence" && !locus.is_empty() {
        return persist_remedy(subject, locus, sev, |p| p.exists(), |p| {
            hemostat_sensor_linux::pkg::manager().is_some_and(|m| m.owns(p))
        })

        .or_else(|| strip_remedy(locus, what, sev));
    }

    if source == "trust" && matches!(sev, Sev::Critical | Sev::Warn) {
        if subject.starts_with("TLS redirected") {
            return strip_remedy(locus, what, sev);
        }

        return None;
    }

    if source == "accounts" {
        if let Some(quote) = sudo_grant_quote(what) {
            if sudoers_scope_of(subject, quote).is_some() {
                return None;
            }
            return strip_remedy(subject, quote, sev);
        }
    }

    None
}

#[cfg(all(target_os = "linux", feature = "mod-tui"))]
pub(crate) fn watchdog_remedy(seed: &[hemostat_sensor_linux::watchdog::Pinned]) -> Option<hemostat_tui::Remedy> {
    use hemostat_sensor_linux::watchdog::Pinned;
    use hemostat_tui::{Remedy, Risk};
    let list = Pinned::list(seed);

    let seed = Pinned::parse_list(&list)?;
    let pids: Vec<String> = seed.iter().map(|s| s.pid.to_string()).collect();
    Some(Remedy {
        what: format!("freeze and remove the whole group (pids {})", pids.join(", ")),
        risk: Risk::MayBreak,
        note: "every member is SIGSTOPped first, so none can restart another, and only \
               then killed. If any member is refused by the protect-set the whole action \
               is abandoned and the frozen ones are resumed — it is all of them or none. \
               A survivor is reported as a survivor rather than as a success"
            .into(),
        undo: "a killed process cannot be restarted from the journal. If the group is \
               frozen but not yet killed, hemostat undo <journal> resumes it"
            .into(),
        id: format!("linux:watchdog:{list}"),
    })
}

#[cfg(all(target_os = "linux", feature = "mod-tui"))]
fn sudo_grant_quote(what: &str) -> Option<&str> {
    ["grants password-free sudo: ", "disables the sudo password prompt: "]
        .iter()
        .find_map(|p| what.strip_prefix(p))
}

#[cfg(all(target_os = "linux", feature = "mod-tui"))]
fn sudoers_scope_of(
    path: &str,
    quoted: &str,
) -> Option<hemostat_enforce_linux::account::SudoersScope> {
    use hemostat_enforce_linux::account;
    let file = hemostat_sensor_linux::saferead::read_scan_target(std::path::Path::new(path))
        .unwrap_or_default();
    account::sudoers_scope(quoted, &file, &account::name_of_uid, &account::name_of_gid)
}

#[cfg(all(target_os = "linux", feature = "mod-tui"))]
pub(crate) fn out_of_scope_note(source: &str, subject: &str, what: &str) -> Option<String> {
    if source != "accounts" {
        return None;
    }
    if crate::golden::is_protected(subject) {
        return Some(format!(
            "OUT OF SCOPE, human-only: no fix is offered here and every account action refuses \
             it — {}",
            hemostat_enforce_linux::ProtectReason::OutOfScopeAccount.describe()
        ));
    }
    let scope = sudoers_scope_of(subject, sudo_grant_quote(what)?)?;
    Some(format!(
        "OUT OF SCOPE, human-only: the one-line strip is not offered, and `remediate \
         --strip-line` refuses it — {}",
        scope.describe()
    ))
}

#[cfg(all(target_os = "linux", feature = "mod-tui"))]
pub(crate) fn scoped_why(source: &str, subject: &str, what: &str, why: &str) -> String {
    match out_of_scope_note(source, subject, what) {
        Some(note) => format!("{why} — {note}"),
        None => why.to_string(),
    }
}

#[cfg(all(target_os = "linux", feature = "mod-tui"))]
fn persist_remedy(
    subject: &str,
    locus: &str,
    sev: hemostat_tui::Sev,
    exists: impl Fn(&std::path::Path) -> bool,
    packaged: impl Fn(&std::path::Path) -> bool,
) -> Option<hemostat_tui::Remedy> {
    use hemostat_enforce_linux::persistence::{disposition_with, Disposition};
    use hemostat_sensor_linux::triage::Severity;
    use hemostat_tui::{Remedy, Risk, Sev};
    let mech = subject.split(" · ").next().unwrap_or(subject);
    let severity = match sev {
        Sev::Critical => Severity::Critical,
        Sev::Warn => Severity::Warn,
        Sev::Note => Severity::Note,
    };
    let Disposition::Remove(action) = disposition_with(mech, locus, severity, exists, packaged) else {
        return None;
    };
    Some(Remedy {
        what: action.summary(),
        risk: Risk::MayBreak,
        note: "applied exactly as `hemostat remediate --arm` would apply it: the \
               protect-set still refuses ssh, the operator's own session and anything \
               declared critical, and the change is written to an undo journal"
            .into(),
        undo: "hemostat undo <journal> — the path is printed when it applies".into(),
        id: format!("linux:persist:{mech}:{locus}"),
    })
}

#[cfg(all(target_os = "linux", feature = "mod-tui"))]
fn strip_remedy(path: &str, quoted: &str, sev: hemostat_tui::Sev) -> Option<hemostat_tui::Remedy> {
    use hemostat_tui::{Remedy, Risk, Sev};
    if !matches!(sev, Sev::Critical | Sev::Warn) {
        return None;
    }
    let offer = hemostat_enforce_linux::strip::offer_for(std::path::Path::new(path), quoted)?;
    let auth = offer.kind.is_auth();
    Some(Remedy {
        what: format!("strip line {} from {}: `{}`", offer.line.line_no, path, offer.text),
        risk: Risk::MayBreak,
        note: if auth {
            format!(
                "{} is a login or privilege file. Only this line goes, matched by its hash; the file \
                 is snapshotted first and replaced atomically with its owner, mode and labels. \
                 sudoers must pass visudo, sshd must pass sshd -t (and is NOT reloaded), a PAM \
                 stack keeps an auth line, and the operator's own key is never removed",
                offer.kind.label()
            )
        } else {
            "only this line goes, matched by its hash and refused if the file changed since this \
             row was drawn; the whole file is snapshotted first and replaced atomically with its \
             owner, mode and labels"
                .into()
        },
        undo: format!("hemostat undo <journal>{}", if auth { " --auth" } else { "" }),
        id: format!("linux:{}:{}", if auth { "strip-auth" } else { "strip" }, offer.token()),
    })
}

#[cfg(all(target_os = "linux", feature = "mod-tui"))]
pub(crate) fn anchor_remedy(a: &hemostat_sensor_linux::trust::Anchor, sev: hemostat_tui::Sev) -> Option<hemostat_tui::Remedy> {
    use hemostat_tui::{Remedy, Risk, Sev};
    if !matches!(sev, Sev::Critical | Sev::Warn) {
        return None;
    }
    let offer = hemostat_enforce_linux::anchor::offer_for_anchor(a).ok()?;
    let locus = offer.path.display().to_string();
    let fp = a.cert.sha256_hex();
    let rebuilds = !matches!(offer.store, hemostat_enforce_linux::anchor::Store::Bundle);
    Some(Remedy {
        what: if offer.blocks == 1 {
            format!("move {locus} into the vault{}", if rebuilds { " and rebuild the trust store" } else { "" })
        } else {
            format!("take certificate {} of {} out of {locus}{}", offer.anchor.block + 1, offer.blocks, if rebuilds { " and rebuild the trust store" } else { "" })
        },
        risk: Risk::MayBreak,
        note: format!(
            "only this certificate goes, matched by its SHA-256 {} and refused if the file changed since this              row was drawn; the file is snapshotted first. {}Anything that relied on this CA — an internal              site, an enterprise proxy — stops validating",
            fp.chars().take(16).collect::<String>(),
            if rebuilds {
                "The store is then rebuilt with the distribution's own tool, which is refused if the rebuild would                  change any other certificate. "
            } else {
                "No source holds it, so nothing is rebuilt. "
            }
        ),
        undo: "hemostat undo <journal> — the file goes back and the store is rebuilt again".into(),
        id: format!("linux:anchor:{}", offer.token()),
    })
}

#[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "windows"))]
pub(crate) fn require_built(class: hemostat_buildinfo::ActionClass) -> Result<(), String> {
    if matches!(hemostat_modules::executor_for(class), hemostat_modules::Executor::NotInVariant) {
        return Err(hemostat_modules::refusal_message(class, MANIFEST.variant));
    }
    Ok(())
}

#[cfg(all(target_os = "linux", feature = "mod-tui"))]
pub(crate) fn remedy_classes(id: &str) -> Option<(Vec<hemostat_buildinfo::ActionClass>, usize)> {
    use hemostat_buildinfo::ActionClass as A;
    if id.starts_with("linux:sysctl:") {
        return Some((vec![A::Harden], 1));
    }
    if id.starts_with("linux:sshd:") {
        return Some((vec![A::Harden], 1));
    }
    if let Some(rest) = id.strip_prefix("linux:watchdog:") {

        let n = rest.split(',').filter(|p| !p.trim().is_empty()).count();
        return Some((vec![A::Kill, A::Suspend], n.max(1)));
    }
    if id == "linux:ld-preload" {
        return Some((vec![A::PersistenceNeutralize], 1));
    }
    if id.starts_with("linux:lock-account:") {
        return Some((vec![A::AccountDisable], 1));
    }
    if id.starts_with("linux:group-drop:") {
        return Some((vec![A::GroupDrop], 1));
    }
    if id.starts_with("linux:unsetuid:") {
        return Some((vec![A::Quarantine], 1));
    }
    if id.starts_with("linux:persist:") {
        return Some((vec![A::PersistenceNeutralize], 1));
    }
    if id.starts_with("linux:strip:") || id.starts_with("linux:strip-auth:") {
        return Some((vec![A::PersistenceNeutralize], 1));
    }
    if id.starts_with("linux:anchor:") {
        return Some((vec![A::PersistenceNeutralize], 1));
    }
    None
}

#[cfg(all(target_os = "linux", feature = "mod-tui"))]
pub(crate) fn broker_gate(id: &str) -> Result<String, String> {
    use hemostat_broker::{Decision, Origin, Request};
    use hs_core::mode::Mode;

    let Some((classes, targets)) = remedy_classes(id) else {
        return Err(format!(
            "no action class is registered for remedy `{id}`, so the Response Broker cannot judge it. Nothing was attempted"
        ));
    };

    let sanction = loaded_sanction()?;
    let mut gaps = Vec::new();

    let code = classes
        .first()
        .and_then(|c| hemostat_buildinfo::ActionClass::ALL.iter().position(|a| a == c))
        .and_then(|i| u8::try_from(i).ok())
        .unwrap_or(hemostat_evcrypto::ticket::NO_CLASS);
    let (authority, ticket) = presented_authority(hemostat_evcrypto::ticket::Op::Action, code)?;

    for class in classes {

        let req = Request {
            class,
            summary: id.to_string(),
            origin: Origin::Operator,
            targets,
            reboot_gated: false,
        };

        let built = require_built(class).is_ok();
        match hemostat_broker::decide_full(
            &req,
            Mode::Armed,
            current_profile(),
            built,
            authority,
            &sanction,
        ) {
            Decision::Refused { stage, reason, instead } => {
                let alt = instead.map_or_else(String::new, |a| {
                    format!(" Consider `{a}` instead, which is reversible.")
                });
                return Err(format!("refused at the {} stage: {reason}.{alt}", stage.token()));
            }
            Decision::Planned { .. } => {
                return Err(
                    "the broker planned this action rather than permitting it, which means the mode is not armed. Nothing was attempted"
                        .into(),
                )
            }

            Decision::Proceed { unchecked } => {
                for g in unchecked {
                    if !gaps.iter().any(|e: &hemostat_broker::Unchecked| e.stage == g.stage) {
                        gaps.push(g);
                    }
                }
            }
        }
    }

    if let Some(t) = ticket {
        t.spend().map_err(|e| e.to_string())?;
    }

    if gaps.is_empty() {
        return Ok(String::new());
    }

    let names: Vec<&str> = gaps.iter().map(|u| u.stage.token()).collect();
    let whys: Vec<&str> = gaps.iter().map(|u| u.why).collect();
    Ok(format!(
        " — NOTE: the broker could not perform its {} stage(s) ({}): {}",
        gaps.len(),
        names.join(", "),
        whys.join("; ")
    ))
}

#[cfg(all(target_os = "linux", feature = "mod-tui"))]
pub(crate) fn apply_remedy(id: &str) -> Result<String, String> {
    let note = broker_gate(id)?;
    let done = apply_remedy_inner(id)?;
    Ok(format!("{done}{note}"))
}

#[cfg(all(target_os = "linux", feature = "mod-tui"))]
fn record(rec: hemostat_enforce_linux::UndoRecord, removed: &[std::path::PathBuf]) -> String {

    let mut out = journal_one(&rec).unwrap_or_else(|warning| warning);

    let restorers = hemostat_enforce_linux::restore_watch::restorers_for(removed);
    if !restorers.is_empty() {
        let names: Vec<String> = restorers
            .iter()
            .map(|r| r.rule_file.display().to_string())
            .collect();
        out.push_str(&format!(
            " — WARNING: {} boot rule(s) would put this back at the next reboot ({}). \
             The re-scan cannot see this: the rule does not fire until then",
            restorers.len(),
            names.join(", ")
        ));
    }
    out
}

#[cfg(all(target_os = "linux", feature = "mod-tui"))]
pub(crate) fn apply_remedy_inner(id: &str) -> Result<String, String> {

    if let Some(key) = id.strip_prefix("linux:sysctl:") {
        return apply_sysctl(key);
    }
    if let Some(spelling) = id.strip_prefix("linux:sshd:") {
        return apply_sshd(spelling);
    }
    if let Some(rest) = id.strip_prefix("linux:watchdog:") {
        return apply_watchdog(rest);
    }
    if id == "linux:ld-preload" {
        return apply_ld_preload();
    }
    if let Some(user) = id.strip_prefix("linux:lock-account:") {
        return apply_lock_account(user);
    }
    if let Some(rest) = id.strip_prefix("linux:group-drop:") {
        return apply_group_drop(rest);
    }
    if let Some(path) = id.strip_prefix("linux:unsetuid:") {
        return apply_unsetuid(path);
    }
    if let Some(rest) = id.strip_prefix("linux:persist:") {
        return apply_persist(rest);
    }
    if let Some(token) = id.strip_prefix("linux:strip-auth:") {
        return apply_strip(token, true);
    }
    if let Some(token) = id.strip_prefix("linux:strip:") {
        return apply_strip(token, false);
    }
    if let Some(token) = id.strip_prefix("linux:anchor:") {
        return apply_anchor(token);
    }

    Err(format!("no remedy is registered for {id}"))
}

#[cfg(all(target_os = "linux", feature = "mod-tui"))]
fn apply_sysctl(key: &str) -> Result<String, String> {
    require_built(hemostat_buildinfo::ActionClass::Harden)?;
    let Some(c) = hemostat_sensor_linux::sysctlpolicy::CONTROLS
        .iter()
        .find(|c| c.keys.first() == Some(&key))
    else {
        return Err(format!("no kernel tunable control named {key}"));
    };
    let a = hemostat_sensor_linux::sysctlpolicy::apply(c)?;
    let was: Vec<String> =
        a.was.iter().map(|(k, v)| format!("{k} was {v}")).collect();
    let persisted = match (&a.persisted, &a.persist_error) {
        (true, _) => format!(" and recorded in {}", hemostat_sensor_linux::sysctlpolicy::DROP_IN),
        (false, Some(e)) => format!(
            " — but it could NOT be made to survive a reboot ({e}), so this reverts at the \
             next restart"
        ),
        (false, None) => String::new(),
    };

    let rec = hemostat_enforce_linux::UndoRecord {
        did: format!(
            "set {} key(s) to {} and read each back from the kernel{persisted}. Previously: {}",
            a.was.len(),
            a.now,
            was.join(", ")
        ),
        undo: hemostat_enforce_linux::UndoKind::RestoreSysctl { was: a.was.clone() },
        reversible: true,
    };
    Ok(record(rec, &[]))
}

#[cfg(all(target_os = "linux", feature = "mod-tui"))]
fn apply_sshd(spelling: &str) -> Result<String, String> {
    require_built(hemostat_buildinfo::ActionClass::Harden)?;
    let Some(c) = hemostat_sensor_linux::sshd::CONTROLS.iter().find(|c| c.spelling == spelling)
    else {
        return Err(format!("no SSH control named {spelling}"));
    };
    let want = hemostat_sensor_linux::sshd::wanted_value(c);
    let staged = hemostat_sensor_linux::sshd::stage(spelling, &want)?;

    let vault = std::path::Path::new(hemostat_enforce_linux::DEFAULT_VAULT);
    let did = format!(
        "staged `{}` in {} — `sshd -T` now reports {spelling} = {}. The RUNNING daemon is \
         unchanged; restart it yourself when ready",
        staged.line,
        staged.file.display(),
        staged.confirmed,
    );
    let undo = if staged.created {
        hemostat_enforce_linux::snapshot(&staged.file, &staged.body, vault).map(|v| {
            hemostat_enforce_linux::UndoKind::RemoveCreatedFile {
                vault: v,
                original: staged.file.clone(),
            }
        })
    } else {
        hemostat_enforce_linux::snapshot(
            &staged.file,
            staged.previous.as_deref().unwrap_or(""),
            vault,
        )
        .map(|v| hemostat_enforce_linux::UndoKind::RestoreFile {
            vault: v,
            original: staged.file.clone(),
            moved: false,
        })
    };
    match undo {
        Ok(undo) => Ok(record(
            hemostat_enforce_linux::UndoRecord { did, undo, reversible: true },
            &[],
        )),

        Err(e) => Ok(format!(
            "{did} — WARNING: no undo could be recorded ({e}), so reverse this by hand: {} {}",
            if staged.created { "delete" } else { "edit" },
            staged.file.display()
        )),
    }
}

#[cfg(all(target_os = "linux", feature = "mod-tui"))]
fn apply_watchdog(rest: &str) -> Result<String, String> {
    use hemostat_enforce_linux::{ApplyOptions, ProtectSet, journal};
    use hemostat_sensor_linux::watchdog::Pinned;

    require_built(hemostat_buildinfo::ActionClass::Kill)?;
    require_built(hemostat_buildinfo::ActionClass::Suspend)?;

    let Some(seed) = Pinned::parse_list(rest) else {
        return Err("the remedy id does not name the processes its row was drawn from (PID@START) — re-scan".into());
    };

    let procs = hemostat_sensor_linux::procfs::walk();
    let mut members: std::collections::BTreeSet<u32> = std::collections::BTreeSet::new();
    let mut units: Vec<String> = Vec::new();
    for pin in &seed {
        let Some(live) = procs.iter().find(|p| pin.is(p)) else {
            continue;
        };
        let unit = match hemostat_sensor_linux::watchdog::supervisor_of(live, &procs) {
            hemostat_sensor_linux::watchdog::Supervisor::Unit(u) => Some(u),
            _ => None,
        };
        let (m, u) = hemostat_sensor_linux::watchdog::group_for(live.pid, &procs, unit.as_deref());
        members.extend(m);
        units.extend(u);
    }
    if members.is_empty() {
        return Err("none of those processes is still running as the row named it (a pid reused since is another process) — re-scan".into());
    }

    let passwd = hemostat_sensor_linux::saferead::read_scan_target(std::path::Path::new("/etc/passwd"));
    if let Some(why) = hard_protected_member(&members, &procs, passwd.as_deref()) {
        return Err(format!("{why}, so the group is not taken; nothing was changed"));
    }
    units.sort();
    units.dedup();
    let group = hemostat_enforce_linux::group::Group {
        members: members.into_iter().collect(),
        units,
    };
    let protect = ProtectSet::gather();

    let mut appender =
        journal::Appender::new(std::path::Path::new(hemostat_enforce_linux::DEFAULT_VAULT));
    let mut journal_failed: Option<String> = None;
    let out = {
        let failed = &mut journal_failed;
        let ap = &mut appender;
        hemostat_enforce_linux::group::remove_journaling(
            &group,
            &ApplyOptions::armed(),
            &protect,
            &mut |rec| {
                if let Err(e) = ap.append(rec) {

                    failed.get_or_insert_with(|| e.to_string());
                }
            },
        )
    };

    let journalled = match (&journal_failed, appender.started()) {
        (Some(e), _) => format!(
            " — WARNING: the undo journal could not be written ({e}); any process this froze must be resumed by hand with `kill -CONT <pid>`"
        ),
        (None, true) => format!(" — undo: hemostat undo {}", appender.path().display()),
        (None, false) => String::new(),
    };

    let narration = out.steps.join("; ");
    match (out.removed, &out.aborted) {
        (_, Some(why)) => Err(format!("{why}. Steps: {narration}")),
        (true, None) => Ok(format!("group removed{journalled}. Steps: {narration}")),
        (false, None) => Err(format!(
            "the group was NOT fully removed — still alive: {:?}. Steps: {narration}{journalled}",
            out.survivors
        )),
    }
}

#[cfg(all(target_os = "linux", feature = "mod-tui"))]
pub(crate) fn hard_protected_member(
    members: &std::collections::BTreeSet<u32>,
    procs: &[hemostat_sensor_linux::procfs::ProcSnapshot],
    passwd: Option<&str>,
) -> Option<String> {
    let Some(passwd) = passwd else {
        return Some(
            "/etc/passwd could not be read, so whether a member runs as whiteteam or a DataDog account cannot be checked"
                .into(),
        );
    };
    for pid in members {
        let Some(p) = procs.iter().find(|p| p.pid == *pid) else {
            return Some(format!("pid {pid} is not in the process table this removal read, so whose it is cannot be checked"));
        };
        let held = passwd.lines().find_map(|l| {
            let mut f = l.split(':');
            let (name, _, uid) = (f.next()?, f.next()?, f.next()?);
            (uid.parse::<u32>().ok() == Some(p.uid) && crate::golden::is_protected(name)).then_some(name)
        });
        if let Some(name) = held {
            return Some(format!("pid {pid} runs as {name} (uid {}), an account the packet puts off-limits", p.uid));
        }
    }
    None
}

#[cfg(all(target_os = "linux", feature = "mod-tui"))]
fn apply_ld_preload() -> Result<String, String> {
    use hemostat_enforce_linux::{ApplyOptions, Outcome, ProtectSet, RemovalAction};
    require_built(hemostat_buildinfo::ActionClass::PersistenceNeutralize)?;
    let action = RemovalAction::RemoveLdPreload {
        path: std::path::PathBuf::from("/etc/ld.so.preload"),
        entry: None,
    };
    match action.apply(&ApplyOptions::armed(), &ProtectSet::gather()) {
        Outcome::Applied(rec) => {
            Ok(record(rec, &[std::path::PathBuf::from("/etc/ld.so.preload")]))
        }
        Outcome::Refused(r) => Err(r.message),
        Outcome::Failed(f) => Err(f.reason),
        Outcome::Planned(_) => Err("dry run returned a plan where an armed apply was asked for".into()),
    }
}

#[cfg(all(target_os = "linux", feature = "mod-tui"))]
fn lock_refusal(
    user: &str,
    protect: &hemostat_enforce_linux::ProtectSet,
    session_user: Option<&str>,
) -> Option<String> {

    if user == "root" || user.is_empty() {
        return Some("refusing to lock root".into());
    }

    if crate::golden::is_protected(user) {
        return Some(format!(
            "refusing to lock `{user}`: {}",
            hemostat_enforce_linux::ProtectReason::OutOfScopeAccount.describe()
        ));
    }

    if session_user == Some(user) {
        return Some(format!("refusing to lock `{user}`: it is the account running this session"));
    }

    let operator = hemostat_enforce_linux::account::uid_of(user)
        .is_some_and(|u| u != 0 && hemostat_enforce_linux::account::operator_uids().contains(&u));
    if operator {
        return Some(format!("refusing to lock `{user}`: it is the account running this session"));
    }
    protect
        .user_reason(user)
        .map(|r| format!("refusing to lock `{user}`: {}", r.describe()))
}

#[cfg(all(target_os = "linux", feature = "mod-tui"))]
fn apply_lock_account(user: &str) -> Result<String, String> {
    require_built(hemostat_buildinfo::ActionClass::AccountDisable)?;
    let protect = hemostat_enforce_linux::ProtectSet::gather();
    if let Some(why) = lock_refusal(user, &protect, std::env::var("SUDO_USER").ok().as_deref()) {
        return Err(why);
    }
    let usermod = ["/usr/sbin/usermod", "/sbin/usermod", "/usr/bin/usermod"]
        .iter()
        .map(std::path::PathBuf::from)
        .find(|p| p.exists())
        .ok_or_else(|| "usermod not found".to_string())?;

    let previous_shell = hemostat_sensor_linux::saferead::read_scan_target(std::path::Path::new("/etc/passwd"))
        .and_then(|t| {
            t.lines()
                .find(|l| l.split(':').next() == Some(user))
                .map(|l| l.split(':').nth(6).unwrap_or("").to_string())
        });

    let previous_locked = hemostat_enforce_linux::account::read_password_locked(user);

    let out = std::process::Command::new(&usermod)
        .args(["-L", "-s", "/usr/sbin/nologin", user])
        .env_clear()
        .output()
        .map_err(|e| format!("could not run usermod: {e}"))?;
    if out.status.success() {
        let mut did = match &previous_shell {
            Some(sh) if sh.is_empty() => format!(
                "locked `{user}` and set its shell to nologin (the field was empty, which is \
                 /bin/sh; `-s ''` puts it back)"
            ),
            Some(sh) => format!("locked `{user}` and set its shell to nologin (was {sh})"),

            None => format!(
                "locked `{user}` and set its shell to nologin — its previous shell could \
                 NOT be read, so the reversal cannot put one back. Check a backup of \
                 /etc/passwd before assuming one"
            ),
        };
        match previous_locked {
            Some(true) => did.push_str(
                ". Its password was already locked before this, so the undo leaves it locked",
            ),
            None => did.push_str(
                ". Whether its password was already locked could not be read, so the undo \
                 leaves it locked",
            ),
            Some(false) => {}
        }
        Ok(record(
            hemostat_enforce_linux::UndoRecord {
                did,
                undo: hemostat_enforce_linux::UndoKind::UnlockAccount {
                    user: user.to_string(),
                    shell: previous_shell,
                    was_locked: previous_locked,
                },
                reversible: true,
            },
            &[],
        ))
    } else {
        Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
    }
}

#[cfg(all(target_os = "linux", feature = "mod-tui"))]
fn apply_group_drop(rest: &str) -> Result<String, String> {
    use hemostat_enforce_linux::{ApplyOptions, Outcome, ProtectSet};
    require_built(hemostat_buildinfo::ActionClass::GroupDrop)?;
    let Some((user, group)) = rest.split_once(':') else {
        return Err(format!("malformed remedy id `linux:group-drop:{rest}`: expected <user>:<group>"));
    };

    let uid = hemostat_enforce_linux::account::uid_of(user).ok_or_else(|| {
        format!(
            "`{user}` is in the group but has no /etc/passwd entry, so its uid cannot be \
             read. The refusals that protect root and the operator are uid comparisons, \
             and this one cannot be made — remove the membership by hand after checking \
             who it belongs to: gpasswd -d {user} {group}"
        )
    })?;
    let action = hemostat_enforce_linux::account::AccountAction::GroupDrop {
        user: user.to_string(),
        uid,
        group: group.to_string(),
    };
    match hemostat_enforce_linux::account::apply(
        &action,
        &ApplyOptions::armed(),
        &hemostat_enforce_linux::account::operator_uids(),
        &ProtectSet::gather(),
    ) {
        Outcome::Applied(rec) => Ok(record(rec, &[])),
        Outcome::Refused(r) => Err(r.message),
        Outcome::Failed(f) => Err(f.reason),
        Outcome::Planned(_) => {
            Err("dry run returned a plan where an armed apply was asked for".into())
        }
    }
}

#[cfg(all(target_os = "linux", feature = "mod-tui"))]
fn apply_unsetuid(path: &str) -> Result<String, String> {
    require_built(hemostat_buildinfo::ActionClass::Quarantine)?;
    use std::os::unix::fs::PermissionsExt as _;
    let p = std::path::Path::new(path);

    let f = hemostat_enforce_linux::open_unredirected(p).map_err(|e| format!("{path}: {e}"))?;

    let md = f.metadata().map_err(|e| format!("{path}: {e}"))?;
    if !md.is_file() {
        return Err(format!("{path} is not a regular file"));
    }
    let mode = md.permissions().mode();
    if mode & 0o4000 == 0 {
        return Err(format!("{path} does not have the setuid bit set"));
    }
    let cleared = mode & !0o4000;
    f.set_permissions(std::fs::Permissions::from_mode(cleared))
        .map_err(|e| format!("could not change {path}: {e}"))?;

    let after = f
        .metadata()
        .map_err(|e| format!("{path}: changed, but could not be re-read to confirm: {e}"))?
        .permissions()
        .mode();
    if after & 0o4000 != 0 {
        return Err(format!(
            "{path}: the setuid bit is STILL SET after the change was accepted \
             ({:o}) — the filesystem or an LSM declined it. Nothing was fixed",
            after & 0o7777
        ));
    }
    Ok(record(
        hemostat_enforce_linux::UndoRecord {
            did: format!(
                "cleared the setuid bit on {path} ({:o} -> {:o}), confirmed by re-reading \
                 the file",
                mode & 0o7777,
                after & 0o7777
            ),

            undo: hemostat_enforce_linux::UndoKind::RestoreMode {
                path: p.to_path_buf(),
                mode: mode & 0o7777,
            },
            reversible: true,
        },
        &[],
    ))
}

#[cfg(all(target_os = "linux", feature = "mod-tui"))]
fn apply_strip(token: &str, auth: bool) -> Result<String, String> {
    use hemostat_enforce_linux::strip::{self, LineRef, StripAuthority};
    use hemostat_enforce_linux::{ApplyOptions, Outcome, ProtectSet, RemovalAction};
    require_built(hemostat_buildinfo::ActionClass::PersistenceNeutralize)?;
    let (path, line) = LineRef::parse(token)?;
    let mut keys = strip::parse_operator_keys(&[], std::env::var("HEMOSTAT_OPERATOR_KEY").ok().as_deref())?;
    keys.extend(strip::session_key_fingerprints());
    let action = RemovalAction::StripLine {
        path,
        line,
        authority: StripAuthority { auth, operator_keys: keys, ..StripAuthority::default() },
    };
    match action.apply(&ApplyOptions::armed(), &ProtectSet::gather()) {
        Outcome::Applied(rec) => Ok(record(rec, &[])),
        Outcome::Refused(r) => Err(r.message),
        Outcome::Failed(f) => Err(f.reason),
        Outcome::Planned(_) => Err("a dry run came back where an armed apply was asked for".into()),
    }
}

#[cfg(all(target_os = "linux", feature = "mod-tui"))]
fn apply_anchor(token: &str) -> Result<String, String> {
    use hemostat_enforce_linux::anchor::AnchorRef;
    use hemostat_enforce_linux::{ApplyOptions, Outcome, ProtectSet, RemovalAction};
    require_built(hemostat_buildinfo::ActionClass::PersistenceNeutralize)?;
    let (path, anchor) = AnchorRef::parse(token)?;
    let action = RemovalAction::RemoveAnchor { path, anchor };
    match action.apply(&ApplyOptions::armed(), &ProtectSet::gather()) {
        Outcome::Applied(rec) => Ok(record(rec, &[])),
        Outcome::Refused(r) => Err(r.message),
        Outcome::Failed(f) => Err(f.reason),
        Outcome::Planned(_) => Err("a dry run came back where an armed apply was asked for".into()),
    }
}

#[cfg(all(target_os = "linux", feature = "mod-tui"))]
fn apply_persist(rest: &str) -> Result<String, String> {
    use hemostat_enforce_linux::{ApplyOptions, Outcome, ProtectSet};
    require_built(hemostat_buildinfo::ActionClass::PersistenceNeutralize)?;
    use hemostat_enforce_linux::persistence::{plan, Disposition};
    let (_mech, locus) = rest.split_once(':').ok_or("malformed persistence remedy id")?;

    let Some(Disposition::Remove(action)) = plan(&hemostat_sensor_linux::persist::report())
        .into_iter()
        .find(|c| c.locus == locus)
        .map(|c| c.disposition)
    else {
        return Err(format!("{locus} is no longer something this policy will remove"));
    };

    match action.apply(&ApplyOptions::armed(), &ProtectSet::gather()) {
        Outcome::Applied(rec) => {
            let done = record(rec, &[std::path::PathBuf::from(locus)]);

            #[cfg(feature = "mod-enf-persistence")]
            if let Some(note) = crate::remediate_verb::action_path(&action).and_then(|p| {
                let (systemd, udev) = crate::remediate_verb::reload_needed_for(&p);
                crate::remediate_verb::reload_after_removal(systemd, udev)
            }) {
                return Ok(format!("{done} — {note}"));
            }
            Ok(done)
        }
        Outcome::Refused(r) => Err(r.message),
        Outcome::Failed(f) => Err(f.reason),
        Outcome::Planned(_) => Err("a dry run came back where an armed apply was asked for".into()),
    }
}

#[cfg(all(target_os = "windows", feature = "mod-tui"))]
pub(crate) fn windows_remedy(subject: &str) -> Option<hemostat_tui::Remedy> {
    use hemostat_sensor_win::posture::subject;
    use hemostat_tui::{Remedy, Risk};

    match subject {
        subject::WDIGEST => Some(Remedy {
            what: "set WDigest\\UseLogonCredential to 0".into(),
            risk: Risk::Safe,
            note: "restores the default since KB2871997; stops plaintext passwords being cached for new logons. Existing sessions keep theirs until they end"
                .into(),
            undo: "set the same value back to 1".into(),
            id: "win:wdigest-off".into(),
        }),
        subject::LSA_PROTECTION => Some(Remedy {
            what: "set Lsa\\RunAsPPL to 1 — by hand, not from this console".into(),

            risk: Risk::NeedsReboot,
            note: "takes effect at the next reboot, and a third-party authentication provider or smart-card driver that is not signed for PPL will stop loading into LSASS when it does. Value 1 also sets a UEFI lock on a Secure Boot host, so this console will not write it (design §6.9.1): run `reg add HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa /v RunAsPPL /t REG_DWORD /d 1 /f` yourself if you mean to"
                .into(),
            undo: "on a Secure Boot host, CANNOT be undone locally: the UEFI lock survives deleting the value and is removed only by LsaPplConfig.efi run from firmware with physical presence. Elsewhere, delete the value and reboot".into(),
            id: "win:lsa-ppl".into(),
        }),

        subject::DRIVER_BLOCKLIST => Some(Remedy {
            what: "set CI\\Config\\VulnerableDriverBlocklistEnable to 1".into(),
            risk: Risk::NeedsReboot,
            note: "enforced by Code Integrity in the kernel, not by Defender — this works \
                   with the antivirus off or replaced. It is the default on current \
                   Windows. It blocks drivers Microsoft has published as exploitable, so \
                   software that ships one of them (some anti-cheat, some old vendor \
                   tools) will stop loading its driver. Note that the switch is forced on \
                   and greyed out while memory integrity, Smart App Control or S mode is \
                   active, in which case writing this changes nothing"
                .into(),
            undo: "set the same value to 0 and reboot".into(),
            id: "win:driver-blocklist".into(),
        }),
        _ => None,
    }
}

#[cfg(all(target_os = "windows", feature = "mod-tui"))]
pub(crate) fn apply_remedy(id: &str) -> Result<String, String> {

    fn reg_set(path: &str, name: &str, value: u32) -> Result<String, String> {
        let out = std::process::Command::new("reg")
            .args(["add", path, "/v", name, "/t", "REG_DWORD", "/d", &value.to_string(), "/f"])
            .output()
            .map_err(|e| format!("could not run reg: {e}"))?;
        if out.status.success() {
            Ok(format!("{path}\\{name} = {value}"))
        } else {
            Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
        }
    }

    let profile = crate::authz::current_profile();
    let harden_built = !matches!(
        hemostat_modules::executor_for(hemostat_buildinfo::ActionClass::Harden),
        hemostat_modules::Executor::NotInVariant
    );
    let reboot_built = hemostat_modules::is_built(hemostat_buildinfo::ModuleId::HardenReboot);
    windows_remedy_decision(id, harden_built, reboot_built, profile, crate::MANIFEST.variant)?;
    let req = hemostat_broker::Request {
        class: hemostat_buildinfo::ActionClass::Harden,
        summary: id.to_string(),
        origin: hemostat_broker::Origin::Operator,
        targets: 1,

        reboot_gated: id == "win:driver-blocklist",
    };
    let gaps = match hemostat_broker::decide_full(
        &req,
        hs_core::mode::Mode::Armed,
        profile,
        harden_built,
        hemostat_broker::Authority::None,
        &hemostat_broker::Sanction::None,
    ) {
        hemostat_broker::Decision::Proceed { unchecked } => unchecked,
        hemostat_broker::Decision::Refused { stage, reason, .. } => {
            return Err(format!("refused at the {} stage: {reason}", stage.token()))
        }
        hemostat_broker::Decision::Planned { .. } => {
            return Err("the broker planned this rather than permitting it; nothing was written".into())
        }
    };
    let unperformed = if gaps.is_empty() {
        String::new()
    } else {
        format!(
            " (broker stages NOT performed: {})",
            gaps.iter().map(|u| u.stage.token()).collect::<Vec<_>>().join(", ")
        )
    };

    match id {
        "win:wdigest-off" => reg_set(
            r"HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest",
            "UseLogonCredential",
            0,
        ),
        "win:driver-blocklist" => reg_set(
            r"HKLM\SYSTEM\CurrentControlSet\Control\CI\Config",
            "VulnerableDriverBlocklistEnable",
            1,
        )
        .map(|s| format!("{s} — Code Integrity loads the blocklist at boot, so this needs a restart")),
        other => Err(format!("no remedy is registered for {other}")),
    }
    .map(|s| format!("{s}{unperformed}"))
}

#[cfg(any(test, all(target_os = "windows", feature = "mod-tui")))]
fn windows_remedy_decision(
    id: &str,
    harden_built: bool,
    reboot_built: bool,
    profile: hs_core::mode::Profile,
    variant: &str,
) -> Result<(), String> {
    use hemostat_buildinfo::{ActionClass, ModuleId};
    if id == "win:lsa-ppl" {
        return Err("not applied from the console: RunAsPPL=1 sets a UEFI lock on a Secure Boot \
                    host that cannot be removed without physical presence (design §6.9.1). \
                    If you mean it, run: reg add HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa \
                    /v RunAsPPL /t REG_DWORD /d 1 /f"
            .into());
    }
    if !harden_built {
        return Err(hemostat_modules::refusal_message(ActionClass::Harden, variant));
    }
    if id == "win:driver-blocklist" {
        if !reboot_built {
            return Err(hemostat_modules::module_refusal(ModuleId::HardenReboot, variant));
        }
        if profile == hs_core::mode::Profile::Ot {
            return Err("refused under the ot profile: this only takes effect after a reboot, \
                        and a plant host is not restarted on this tool's say-so (design §6.9.3)"
                .into());
        }
    }
    Ok(())
}
