use std::fs;
use std::path::{Path, PathBuf};

use crate::{bootparam, deceive, exec, fwallow};
use crate::guards::{identity_matches, read_proc_id, ProcId};
use crate::paths::move_file;
use crate::outcome::{
    ApplyOptions, Failure, Outcome, Plan, RefuseCause, Refusal, UndoKind, UndoRecord,
};
use crate::paths::{
    path_refusal, resolve_tool, run_tool,
};

fn undo_restore_mode(path: &Path, mode: u32, opts: &ApplyOptions) -> Outcome {
    use std::os::unix::fs::PermissionsExt as _;

    let want = mode & 0o7777;
    let f = match crate::paths::open_unredirected(path) {
        Ok(f) => f,
        Err(e) => {
            return Outcome::Failed(Failure {
                action: format!("restore mode on {}", path.display()),
                reason: e.to_string(),
            })
        }
    };
    let now = match f.metadata() {
        Ok(md) if md.is_file() => md.permissions().mode() & 0o7777,
        Ok(_) => {
            return Outcome::Failed(Failure {
                action: format!("restore mode on {}", path.display()),
                reason: "what is there now is not a regular file".into(),
            })
        }
        Err(e) => {
            return Outcome::Failed(Failure {
                action: format!("restore mode on {}", path.display()),
                reason: e.to_string(),
            })
        }
    };
    if now & !want != 0 || want & !now & !0o111 != 0 {
        return Outcome::Refused(Refusal {
            action: format!("restore mode {want:o} on {}", path.display()),
            cause: RefuseCause::InvalidTarget(
                "a mode beyond execute bits is never restored automatically".into(),
            ),
            message: format!(
                "not changing {} from {now:o} to {want:o} from the journal: that is more than \
                 putting execute bits back, and a set-id or write bit granted by a line in a \
                 file on the host being cleaned is a privilege escalation with an undo verb in \
                 front of it. Run it yourself once you are satisfied the record is genuine:\n  \
                 chmod {want:o} {}",
                path.display(),
                path.display()
            ),
            suggested_alternative: None,
        });
    }
    if !opts.armed {
        return Outcome::Planned(Plan {
            summary: format!("restore mode {want:o} on {}", path.display()),
            detail: format!("Set {} back to mode {want:o}.", path.display()),
            undo: "Clear the bits again.".into(),
            reversible: true,
            prefer_instead: None,
        });
    }
    if let Err(e) = f.set_permissions(fs::Permissions::from_mode(want)) {
        return Outcome::Failed(Failure {
            action: format!("restore mode on {}", path.display()),
            reason: e.to_string(),
        });
    }
    match f.metadata().map(|m| m.permissions().mode() & 0o7777) {
        Ok(now) if now == want => Outcome::Applied(UndoRecord {
            did: format!("restored mode {want:o} on {}", path.display()),
            undo: UndoKind::Irreversible {
                note: "the mode is back; change it again by hand if that was wrong".into(),
            },
            reversible: false,
        }),
        Ok(now) => Outcome::Failed(Failure {
            action: format!("restore mode on {}", path.display()),
            reason: format!(
                "the change was accepted but the file reads back as {now:o}, not {want:o} — the \
                 filesystem or an LSM declined it. Nothing was restored"
            ),
        }),
        Err(e) => Outcome::Failed(Failure {
            action: format!("restore mode on {}", path.display()),
            reason: format!("changed, but could not be re-read to confirm: {e}"),
        }),
    }
}

fn undo_unlock_account(
    user: &str,
    shell: Option<&str>,
    was_locked: Option<bool>,
    opts: &ApplyOptions,
) -> Outcome {

    if user.is_empty() || user == "root" {
        return Outcome::Refused(Refusal {
            action: format!("unlock {user}"),
            cause: RefuseCause::InvalidTarget("root is never locked or unlocked here".into()),
            message: "refusing to act on root".into(),
            suggested_alternative: None,
        });
    }

    let unlock = was_locked == Some(false);
    let mut args: Vec<String> = Vec::new();
    if unlock {
        args.push("-U".into());
    }
    if let Some(sh) = shell {
        args.push("-s".into());
        args.push(sh.to_string());
    }
    if args.is_empty() {

        return match was_locked {
            Some(true) if !opts.armed => Outcome::Planned(Plan {
                summary: format!("leave {user} locked"),
                detail: format!(
                    "Change nothing: {user}'s password was locked before this tool locked it, so \
                     it stays locked, and its previous shell was not recorded."
                ),
                undo: "Nothing to reverse.".into(),
                reversible: false,
                prefer_instead: None,
            }),
            Some(true) => Outcome::Applied(UndoRecord {
                did: format!(
                    "left `{user}` as it is: its password was locked before this tool locked it, \
                     so it stays locked, and its previous shell was not recorded, so it keeps \
                     whatever the lock left. Set one by hand"
                ),
                undo: UndoKind::Irreversible { note: "nothing was changed".into() },
                reversible: false,
            }),
            _ => Outcome::Refused(Refusal {
                action: format!("unlock {user}"),
                cause: RefuseCause::InvalidTarget("the prior lock state was not recorded".into()),
                message: format!(
                    "not unlocking {user} from this record: it records neither whether its \
                     password was locked before this tool locked it nor its previous shell, and \
                     unlocking a password someone had locked by hand hands it back. Nothing was \
                     changed. If it should log in again: usermod -U {user}, and set its shell \
                     with usermod -s"
                ),
                suggested_alternative: None,
            }),
        };
    }
    args.push(user.to_string());

    let Some(usermod) = ["/usr/sbin/usermod", "/sbin/usermod", "/usr/bin/usermod"]
        .iter()
        .map(PathBuf::from)
        .find(|p| p.exists())
    else {
        return Outcome::Failed(Failure {
            action: format!("unlock {user}"),
            reason: "usermod not found".into(),
        });
    };

    let kept_locked = match was_locked {
        Some(false) => None,
        Some(true) => Some("it was locked before this tool locked it".to_string()),
        None => Some(
            "whether it was locked before this tool locked it is not recorded (a journal from an \
             older build, or /etc/shadow unreadable at the lock), and unlocking one someone had \
             locked by hand hands it back"
                .to_string(),
        ),
    };

    if !opts.armed {
        return Outcome::Planned(Plan {
            summary: if kept_locked.is_some() {
                format!("put back {user}'s shell")
            } else {
                format!("unlock {user}")
            },
            detail: format!(
                "Run `{} {}`.{}",
                usermod.display(),

                args.iter()
                    .map(|a| if a.is_empty() { "''" } else { a.as_str() })
                    .collect::<Vec<_>>()
                    .join(" "),
                kept_locked
                    .as_deref()
                    .map(|why| format!(" Its password stays locked: {why}."))
                    .unwrap_or_default()
            ),
            undo: if kept_locked.is_some() {
                format!("Put nologin back with `usermod -s /usr/sbin/nologin {user}`.")
            } else {
                format!("Lock it again with `usermod -L {user}`.")
            },
            reversible: true,
            prefer_instead: None,
        });
    }

    let out = match std::process::Command::new(&usermod).args(&args).env_clear().output() {
        Ok(o) => o,
        Err(e) => {
            return Outcome::Failed(Failure {
                action: format!("unlock {user}"),
                reason: format!("could not run usermod: {e}"),
            })
        }
    };
    if !out.status.success() {
        return Outcome::Failed(Failure {
            action: format!("unlock {user}"),
            reason: String::from_utf8_lossy(&out.stderr).trim().to_string(),
        });
    }
    let shell_back = match shell {
        Some("") => "set its shell field back to empty, which is /bin/sh".to_string(),
        Some(sh) => format!("set its shell back to {sh}"),
        None => String::new(),
    };
    if let Some(why) = kept_locked {

        return match was_locked {
            Some(true) => Outcome::Applied(UndoRecord {
                did: format!("left `{user}`'s password locked and {shell_back}: {why}"),
                undo: UndoKind::Irreversible {
                    note: format!(
                        "put nologin back with `usermod -s /usr/sbin/nologin {user}` if that was wrong"
                    ),
                },
                reversible: false,
            }),

            _ => Outcome::Failed(Failure {
                action: format!("unlock {user}"),
                reason: format!(
                    "{shell_back} for `{user}`, but its password is still LOCKED: {why}. Run \
                     `usermod -U {user}` yourself if it should log in again"
                ),
            }),
        };
    }

    if crate::account::read_password_locked(user) == Some(true) {
        return Outcome::Failed(Failure {
            action: format!("unlock {user}"),
            reason: format!(
                "usermod ran, but `{user}`'s password still reads as locked{} — it had no \
                 password before the lock, and usermod will not unlock to an empty one. Set one \
                 with `passwd {user}`",
                if shell_back.is_empty() { String::new() } else { format!(" (it did {shell_back})") }
            ),
        });
    }
    Outcome::Applied(UndoRecord {
        did: match shell {
            Some(_) => format!("unlocked `{user}` and {shell_back}"),

            None => format!(
                "unlocked `{user}` — its previous shell was not recorded, so it still has \
                 whatever the lock left. Set one by hand"
            ),
        },
        undo: UndoKind::Irreversible {
            note: format!("re-lock with `usermod -L {user}` if that was wrong"),
        },
        reversible: false,
    })
}

pub const MAX_VAULT_BYTES: u64 = 256 * 1024 * 1024;

fn undo_remove_created_file(vault: &Path, original: &Path, opts: &ApplyOptions) -> Outcome {
    let written = match hemostat_sensor_linux::saferead::read_bytes(vault, MAX_VAULT_BYTES) {
        Ok(b) => b,
        Err(e) => {
            return Outcome::Failed(Failure {
                action: format!("remove {}", original.display()),
                reason: format!("the vault copy of what was written is unreadable: {e}"),
            })
        }
    };
    let current = match hemostat_sensor_linux::saferead::read_bytes(original, MAX_VAULT_BYTES) {
        Ok(b) => b,

        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Outcome::Applied(UndoRecord {
                did: format!("{} was already gone; nothing to remove", original.display()),
                undo: UndoKind::Irreversible {
                    note: format!("the file this would have removed is at {}", vault.display()),
                },
                reversible: false,
            })
        }
        Err(e) => {
            return Outcome::Failed(Failure {
                action: format!("remove {}", original.display()),
                reason: e.to_string(),
            })
        }
    };

    if current != written {
        return Outcome::Refused(Refusal {
            action: format!("remove {}", original.display()),
            cause: RefuseCause::InvalidTarget("the file changed since it was written".into()),
            message: format!(
                "refused to remove {}: its contents are not what this agent wrote, so \
                 somebody has edited it since. Removing it would destroy that edit. What we \
                 wrote is kept at {} — compare them and delete by hand",
                original.display(),
                vault.display()
            ),
            suggested_alternative: None,
        });
    }

    if !opts.armed {
        return Outcome::Planned(Plan {
            summary: format!("remove {}", original.display()),
            detail: format!(
                "Delete {} — unchanged since this agent created it.",
                original.display()
            ),
            undo: format!("Write the copy at {} back.", vault.display()),
            reversible: true,
            prefer_instead: None,
        });
    }
    if let Err(e) = fs::remove_file(original) {
        return Outcome::Failed(Failure {
            action: format!("remove {}", original.display()),
            reason: e.to_string(),
        });
    }
    Outcome::Applied(UndoRecord {
        did: format!("removed {}, which this agent had created", original.display()),
        undo: UndoKind::Irreversible {
            note: format!("a copy of what was removed is at {}", vault.display()),
        },
        reversible: false,
    })
}

fn undo_restore_sysctl(was: &[(String, String)], opts: &ApplyOptions) -> Outcome {
    use hemostat_sensor_linux::sysctlpolicy;

    if was.is_empty() {
        return Outcome::Failed(Failure {
            action: "restore kernel tunables".into(),
            reason: "the record names no keys".into(),
        });
    }

    if let Some((key, _)) =
        was.iter().find(|(k, _)| !sysctlpolicy::CONTROLS.iter().any(|c| c.keys.contains(&k.as_str())))
    {
        return Outcome::Refused(Refusal {
            action: "restore kernel tunables".into(),
            cause: RefuseCause::InvalidTarget("not a kernel tunable this tool hardens".into()),
            message: format!(
                "refused to replay this record: {key:?} is not one of the kernel tunables this \
                 tool hardens, so the record was not written by it. Nothing was changed"
            ),
            suggested_alternative: None,
        });
    }
    if !opts.armed {
        let list: Vec<String> = was.iter().map(|(k, v)| format!("{k}={v}")).collect();
        return Outcome::Planned(Plan {
            summary: format!("restore {} kernel tunable(s)", was.len()),
            detail: format!(
                "Write {} back and drop their lines from {}.",
                list.join(", "),
                sysctlpolicy::DROP_IN
            ),
            undo: "Re-apply the hardening.".into(),
            reversible: true,
            prefer_instead: None,
        });
    }

    let mut restored: Vec<String> = Vec::new();
    let mut problems: Vec<String> = Vec::new();
    for (key, old) in was {
        if let Err(e) = sysctlpolicy::write(key, old) {
            problems.push(e);
            continue;
        }

        match sysctlpolicy::read(key) {
            Some(now) if now == *old => restored.push(format!("{key}={old}")),
            Some(now) => problems.push(format!(
                "{key} was written as {old} but reads back as {now}; the kernel did not take it"
            )),
            None => problems.push(format!("{key} vanished while being written")),
        }
    }

    let keys: Vec<&str> = was.iter().map(|(k, _)| k.as_str()).collect();
    let persist_note = match sysctlpolicy::unpersist(&keys) {
        Ok(()) => String::new(),
        Err(e) => format!(
            " — but the boot-time record could NOT be cleared ({e}), so these values come \
             back at the next reboot"
        ),
    };

    if restored.is_empty() {
        return Outcome::Failed(Failure {
            action: "restore kernel tunables".into(),
            reason: format!("{}{persist_note}", problems.join("; ")),
        });
    }
    let partial = if problems.is_empty() {
        String::new()
    } else {
        format!(" — {} key(s) did NOT go back: {}", problems.len(), problems.join("; "))
    };
    Outcome::Applied(UndoRecord {
        did: format!(
            "restored {} and cleared their line(s) from {}{partial}{persist_note}",
            restored.join(", "),
            sysctlpolicy::DROP_IN
        ),
        undo: UndoKind::Irreversible {
            note: "the previous values are back; re-apply the hardening to change them again"
                .into(),
        },
        reversible: false,
    })
}

fn vault_of(kind: &UndoKind) -> Option<&Path> {
    match kind {
        UndoKind::RemoveCreatedFile { vault, .. }
        | UndoKind::RestoreBootParams { vault, .. }
        | UndoKind::RestoreFile { vault, .. }
        | UndoKind::RestoreUnit { vault, .. }
        | UndoKind::RestoreStripped { vault, .. }
        | UndoKind::RestoreAnchor { vault, .. } => Some(vault),
        _ => None,
    }
}

fn inside_vault(vault: &Path, vault_dir: &Path) -> bool {
    let (Ok(dir), Some(parent)) = (std::fs::canonicalize(vault_dir), vault.parent()) else {
        return false;
    };
    std::fs::canonicalize(parent).is_ok_and(|p| p.starts_with(&dir))
        && std::fs::symlink_metadata(vault).is_ok_and(|m| m.is_file())
}

pub fn undo(record: &UndoRecord, opts: &ApplyOptions) -> Outcome {
    undo_with(record, opts, false)
}

pub fn undo_with(record: &UndoRecord, opts: &ApplyOptions, allow_auth: bool) -> Outcome {
    if let Some(vault) = vault_of(&record.undo) {
        if !inside_vault(vault, &opts.vault_dir) {
            return Outcome::Refused(Refusal {
                action: record.did.clone(),
                cause: RefuseCause::InvalidTarget("the vault copy is outside the vault".into()),
                message: format!(
                    "refused: this record restores from {}, which is not a file inside the vault \
                     {}. A journal entry pointing elsewhere was not written by this tool",
                    vault.display(),
                    opts.vault_dir.display()
                ),
                suggested_alternative: None,
            });
        }
    }
    match &record.undo {
        UndoKind::RestoreMode { path, mode } => undo_restore_mode(path, *mode, opts),
        UndoKind::UnlockAccount { user, shell, was_locked } => {
            undo_unlock_account(user, shell.as_deref(), *was_locked, opts)
        }
        UndoKind::RemoveCreatedFile { vault, original } => {
            undo_remove_created_file(vault, original, opts)
        }
        UndoKind::RestoreSysctl { was } => undo_restore_sysctl(was, opts),
        UndoKind::RestoreStripped { vault, original, line_no, line_sha256, before, after, mode, uid, gid } => {
            crate::strip::undo(
                crate::strip::Recorded {
                    vault,
                    original,
                    line_no: *line_no,
                    line_sha256,
                    before,
                    after,
                    mode: *mode,
                    uid: *uid,
                    gid: *gid,
                },
                opts,
                allow_auth,
            )
        }
        UndoKind::RestoreAnchor { vault, original, cert_sha256, before, after, mode, uid, gid, rebuild, bundle_before } => {
            crate::anchor::undo(
                crate::anchor::Recorded {
                    vault,
                    original,
                    cert_sha256,
                    before,
                    after,
                    mode: *mode,
                    uid: *uid,
                    gid: *gid,
                    rebuild,
                    bundle_before,
                },
                opts,
            )
        }
        UndoKind::Irreversible { note } => Outcome::Refused(Refusal {
            action: format!("undo: {}", record.did),
            cause: RefuseCause::InvalidTarget("the action is irreversible".into()),
            message: note.clone(),
            suggested_alternative: None,
        }),
        UndoKind::Nothing => Outcome::Refused(Refusal {
            action: format!("undo: {}", record.did),
            cause: RefuseCause::InvalidTarget("the action recorded no reversal".into()),
            message: format!(
                "`{}` has no reversal to replay. It is on the journal so the run is auditable, \
                 not because this tool can put it back -- an ended session and a destroyed \
                 ticket both come back when the user authenticates again.",
                record.did
            ),
            suggested_alternative: None,
        }),

        UndoKind::UnmountExecBlock { path } => exec::undo_unmount(path, opts),
        UndoKind::RemoveCanary { path } => deceive::undo_remove(path, opts),
        UndoKind::RemoveNftAllow { family, table, chain, comment } => {
            fwallow::undo_allow(family, table, chain, comment, opts)
        }

        UndoKind::RestoreBootParams { vault, original, generator, output } => {
            match bootparam::detect() {
                bootparam::Bootloader::Grub { defaults, generator: g, output: o }
                    if defaults == *original && g == Path::new(generator) && o == *output =>
                {
                    bootparam::undo_restore(vault, original, generator, output, opts)
                }
                _ => Outcome::Refused(Refusal {
                    action: format!("undo: {}", record.did),
                    cause: RefuseCause::InvalidTarget(
                        "not this host's grub configuration".into(),
                    ),
                    message: format!(
                        "not restoring {} and running `{generator}` from the journal: they are \
                         not the defaults file and generator this host's bootloader detection \
                         finds now, and a program named by a file on the host being cleaned is \
                         not run as root on its say-so. Put it back yourself once you are \
                         satisfied the record is genuine: copy {} over {}, then regenerate {}",
                        original.display(),
                        vault.display(),
                        original.display(),
                        output.display()
                    ),
                    suggested_alternative: None,
                }),
            }
        }
        UndoKind::RejoinGroup { user, group } => Outcome::Refused(Refusal {
            action: format!("undo: {}", record.did),
            cause: RefuseCause::InvalidTarget("a group membership is never restored automatically".into()),
            message: format!(
                "not re-adding {user} to {group} from the journal: a group grant driven by a \
                 file on the host being cleaned is a privilege escalation with an undo verb in \
                 front of it. Run it yourself once you are satisfied the record is genuine:\n  \
                 gpasswd -a {user} {group}"
            ),
            suggested_alternative: None,
        }),
        UndoKind::RestorePasswordAge { user, last_change } => Outcome::Refused(Refusal {
            action: format!("undo: {}", record.did),
            cause: RefuseCause::InvalidTarget("a credential state is never restored automatically".into()),
            message: format!(
                "not clearing {user}'s forced password change from the journal: replaying it \
                 would let a rewritten record undo a rotation you meant to keep. Run it \
                 yourself if the record is genuine:\n  chage -d {last_change} {user}"
            ),
            suggested_alternative: None,
        }),
        UndoKind::ResumeProcess { pid, start_time } => {

            let current = read_proc_id(*pid);
            let expected = ProcId { start_time: *start_time, exe: None };
            if !identity_matches(&expected, current.as_ref()) {
                return Outcome::Refused(Refusal {
                    action: format!("resume pid {pid}"),
                    cause: RefuseCause::FrozenTargetMismatch {
                        expected: format!("starttime {start_time}"),
                        found: current
                            .map(|c| format!("starttime {}", c.start_time))
                            .unwrap_or_else(|| "the PID no longer exists".into()),
                    },
                    message: format!(
                        "refused to resume pid {pid}: its identity changed since it was suspended"
                    ),
                    suggested_alternative: None,
                });
            }
            if !opts.armed {
                return Outcome::Planned(Plan {
                    summary: format!("resume pid {pid}"),
                    detail: format!("Send SIGCONT to pid {pid} after re-checking its identity."),
                    undo: "Suspend it again if needed.".into(),
                    reversible: true,
                    prefer_instead: None,
                });
            }

            let rc = unsafe { libc::kill(*pid as libc::pid_t, libc::SIGCONT) };
            if rc == 0 {
                Outcome::Applied(UndoRecord {
                    did: format!("resumed pid {pid} (SIGCONT)"),
                    undo: UndoKind::Irreversible {
                        note: "resume is the undo; re-suspend to reverse".into(),
                    },
                    reversible: false,
                })
            } else {
                Outcome::Failed(Failure {
                    action: format!("resume pid {pid}"),
                    reason: format!("SIGCONT failed: {}", std::io::Error::last_os_error()),
                })
            }
        }
        UndoKind::UnmaskService { unit, was_active } => {
            if !opts.armed {
                return Outcome::Planned(Plan {
                    summary: format!("unmask {unit}"),
                    detail: match was_active {
                        Some(true) => format!(
                            "Run `systemctl unmask {unit}`, then `systemctl start {unit}`: it was \
                             running when it was masked."
                        ),
                        Some(false) => format!(
                            "Run `systemctl unmask {unit}`. It was not running when it was \
                             masked, so it is not started."
                        ),
                        None => format!(
                            "Run `systemctl unmask {unit}`. Whether it was running when it was \
                             masked was not recorded, so it is left stopped and reported as such."
                        ),
                    },
                    undo: format!("Re-mask with `systemctl mask --now {unit}`."),
                    reversible: true,
                    prefer_instead: None,
                });
            }
            let Some(systemctl) = resolve_tool(&["/usr/bin/systemctl", "/bin/systemctl"]) else {
                return Outcome::Failed(Failure {
                    action: format!("unmask {unit}"),
                    reason: "systemctl not found".into(),
                });
            };
            if let Err(reason) = run_tool(&systemctl, &["unmask", unit]) {
                return Outcome::Failed(Failure { action: format!("unmask {unit}"), reason });
            }

            let applied = |did: String| {
                Outcome::Applied(UndoRecord {
                    did,
                    undo: UndoKind::Irreversible { note: "unmask is the undo".into() },
                    reversible: false,
                })
            };
            match was_active {
                Some(false) => applied(format!(
                    "unmasked unit `{unit}` — it was not running when it was masked, so it was \
                     not started"
                )),
                None => Outcome::Failed(Failure {
                    action: format!("restart {unit}"),
                    reason: format!(
                        "`{unit}` was unmasked, but this journal does not record whether it was \
                         running when it was masked, so it is still stopped. `systemctl start \
                         {unit}` if it should be running"
                    ),
                }),
                Some(true) => match run_tool(&systemctl, &["start", unit]) {
                    Ok(()) => applied(format!("unmasked and started unit `{unit}`")),
                    Err(reason) => Outcome::Failed(Failure {
                        action: format!("restart {unit}"),
                        reason: format!(
                            "`{unit}` was unmasked, but `systemctl start {unit}` failed \
                             ({reason}); it is still stopped"
                        ),
                    }),
                },
            }
        }
        UndoKind::RestoreServiceState { unit, was_enabled, was_active } => {

            let disable = matches!(was_enabled, Some(false));
            let stop = matches!(was_active, Some(false));
            if !opts.armed {
                let mut steps = Vec::new();
                if disable {
                    steps.push(format!("`systemctl disable {unit}` (it was not enabled before)"));
                }
                if stop {
                    steps.push(format!("`systemctl stop {unit}` (it was not running before)"));
                }
                return Outcome::Planned(Plan {
                    summary: format!("restore prior state of {unit}"),
                    detail: if steps.is_empty() {
                        format!(
                            "Leave {unit} as it is: it was already enabled and running before \
                             the start, or that was not recorded, so there is nothing to undo."
                        )
                    } else {
                        format!("Run {}.", steps.join(", then "))
                    },
                    undo: format!("Re-apply with `systemctl enable --now {unit}`."),
                    reversible: true,
                    prefer_instead: None,
                });
            }
            if !disable && !stop {
                return Outcome::Applied(UndoRecord {
                    did: format!(
                        "left `{unit}` as it is: it was already enabled and running before the \
                         start, or that was not recorded"
                    ),
                    undo: UndoKind::Irreversible { note: "nothing was changed".into() },
                    reversible: false,
                });
            }
            let Some(systemctl) = resolve_tool(&["/usr/bin/systemctl", "/bin/systemctl"]) else {
                return Outcome::Failed(Failure {
                    action: format!("restore {unit}"),
                    reason: "systemctl not found".into(),
                });
            };

            if disable {
                if let Err(reason) = run_tool(&systemctl, &["disable", unit]) {
                    return Outcome::Failed(Failure { action: format!("disable {unit}"), reason });
                }
            }
            if stop {
                if let Err(reason) = run_tool(&systemctl, &["stop", unit]) {
                    return Outcome::Failed(Failure { action: format!("stop {unit}"), reason });
                }
            }
            Outcome::Applied(UndoRecord {
                did: format!("restored `{unit}` to its prior state"),
                undo: UndoKind::Irreversible { note: "re-run the start to re-apply".into() },
                reversible: false,
            })
        }
        UndoKind::RestoreFile { vault, original, moved } => {
            if let Some(r) = restore_refusal(vault, original, *moved) {
                return Outcome::Refused(r);
            }
            if !opts.armed {
                return Outcome::Planned(Plan {
                    summary: format!("restore {}", original.display()),
                    detail: format!(
                        "Restore {} from the vault copy {}.",
                        original.display(),
                        vault.display()
                    ),
                    undo: "Move/quarantine it again if needed.".into(),
                    reversible: true,
                    prefer_instead: None,
                });
            }
            match restore_from_vault(vault, original, *moved) {
                Ok(kept) => Outcome::Applied(UndoRecord {
                    did: format!(
                        "restored {} from the vault{}",
                        original.display(),
                        kept_note(kept.as_deref())
                    ),
                    undo: UndoKind::Irreversible { note: "restore is the undo".into() },
                    reversible: false,
                }),
                Err(reason) => {
                    Outcome::Failed(Failure { action: format!("restore {}", original.display()), reason })
                }
            }
        }
        UndoKind::RestoreUnit { vault, original, unit } => {
            if let Some(r) = restore_refusal(vault, original, true) {
                return Outcome::Refused(r);
            }
            if !opts.armed {
                return Outcome::Planned(Plan {
                    summary: format!("restore and re-enable `{unit}`"),
                    detail: format!(
                        "Restore {} from the vault copy {}, reload systemd, then \
                         `systemctl enable --now {unit}`.",
                        original.display(),
                        vault.display()
                    ),
                    undo: "Stop and remove it again if needed.".into(),
                    reversible: true,
                    prefer_instead: None,
                });
            }
            if let Err(reason) = restore_from_vault(vault, original, true) {
                return Outcome::Failed(Failure {
                    action: format!("restore {}", original.display()),
                    reason,
                });
            }

            let Some(systemctl) = resolve_tool(&["/usr/bin/systemctl", "/bin/systemctl"]) else {
                return Outcome::Failed(Failure {
                    action: format!("re-enable {unit}"),
                    reason: format!(
                        "{} was restored, but systemctl was not found, so `{unit}` is still \
                         disabled and stopped. Start it by hand.",
                        original.display()
                    ),
                });
            };

            if let Err(reason) = run_tool(&systemctl, &["daemon-reload"]) {
                return Outcome::Failed(Failure {
                    action: format!("re-enable {unit}"),
                    reason: format!(
                        "{} was restored, but `systemctl daemon-reload` failed ({reason}), so \
                         `{unit}` is still disabled and stopped.",
                        original.display()
                    ),
                });
            }
            match run_tool(&systemctl, &["enable", "--now", unit]) {
                Ok(()) => Outcome::Applied(UndoRecord {
                    did: format!(
                        "restored {} and re-enabled `{unit}`",
                        original.display()
                    ),
                    undo: UndoKind::Irreversible { note: "restore is the undo".into() },
                    reversible: false,
                }),
                Err(reason) => Outcome::Failed(Failure {
                    action: format!("re-enable {unit}"),
                    reason: format!(
                        "{} was restored, but `systemctl enable --now {unit}` failed ({reason}); \
                         the unit is on disk and still stopped.",
                        original.display()
                    ),
                }),
            }
        }
    }
}

fn restore_refusal(vault: &Path, original: &Path, moved: bool) -> Option<Refusal> {
    if let Some(reason) = path_refusal(original) {
        return Some(Refusal {
            action: format!("restore {}", original.display()),
            cause: RefuseCause::InvalidTarget(reason.clone()),
            message: format!("refused to restore {}: {reason}", original.display()),
            suggested_alternative: None,
        });
    }

    if !vault.exists() {
        return Some(Refusal {
            action: format!("restore {}", original.display()),
            cause: RefuseCause::InvalidTarget("the vault copy is gone".into()),
            message: format!(
                "refused to restore {}: its vault copy {} is not there",
                original.display(),
                vault.display()
            ),
            suggested_alternative: None,
        });
    }

    if moved && original.exists() {
        return Some(Refusal {
            action: format!("restore {}", original.display()),
            cause: RefuseCause::InvalidTarget("the destination is occupied".into()),
            message: format!(
                "refused to restore {}: something is already there, and it is not what was \
                 moved out. The vault copy is still at {} — compare them and place it by hand.",
                original.display(),
                vault.display()
            ),
            suggested_alternative: None,
        });
    }
    None
}

fn restore_from_vault(vault: &Path, original: &Path, moved: bool) -> Result<Option<PathBuf>, String> {
    if moved {
        move_file(vault, original).map(|_| None)
    } else {
        restore_in_place(vault, original)
    }
}

pub(crate) fn restore_in_place(vault: &Path, original: &Path) -> Result<Option<PathBuf>, String> {
    use std::io::Read as _;
    use std::os::unix::fs::MetadataExt as _;

    const LIVE_CAP: u64 = MAX_VAULT_BYTES;

    let body = hemostat_sensor_linux::saferead::read_bytes(vault, MAX_VAULT_BYTES)
        .map_err(|e| format!("restore failed reading the vault: {e}"))?;

    let pinned = crate::paths::pin_parent(original)
        .map_err(|e| format!("refused to restore {}: {e}", original.display()))?;

    let file = pinned.open(libc::O_RDONLY | libc::O_NONBLOCK, 0).map_err(|e| {
        format!(
            "refused to restore {}: it could not be opened without following a symlink \
             ({e}). A link where the file was is how a restore becomes an arbitrary write",
            original.display()
        )
    })?;

    let md = file.metadata().map_err(|e| format!("restore failed: {e}"))?;
    if !md.is_file() {
        return Err(format!(
            "refused to restore {}: what is there now is not a regular file",
            original.display()
        ));
    }
    if md.len() > LIVE_CAP {
        return Err(format!(
            "refused to restore {}: it is {} bytes now, past the {LIVE_CAP}-byte cap a restore \
             reads. Nothing was written; the vault copy is still at {}",
            original.display(),
            md.len(),
            vault.display()
        ));
    }
    let mut current = Vec::new();
    (&file)
        .take(LIVE_CAP + 1)
        .read_to_end(&mut current)
        .map_err(|e| format!("restore failed reading the live file: {e}"))?;
    if current.len() as u64 > LIVE_CAP {
        return Err(format!(
            "refused to restore {}: it grew past the {LIVE_CAP}-byte cap while being read",
            original.display()
        ));
    }

    let kept = if current != body {

        let kept = crate::strip::snapshot(
            &vault.with_extension("superseded"),
            &current,
            vault.parent().unwrap_or_else(|| Path::new(".")),
        )
        .map_err(|e| {
            format!(
                "refused to restore {}: its contents changed since the remediation and the \
                 copy that would be overwritten could not be kept ({e})",
                original.display()
            )
        })?;
        Some(kept)
    } else {
        None
    };

    let meta = crate::strip::Meta { mode: md.mode(), uid: md.uid(), gid: md.gid() };
    let read = crate::strip::sha256(&current);
    let live = crate::strip::Read { pinned, file, md, bytes: current };
    if let Err(e) = crate::strip::replace(&live, &body, meta, None, &read) {

        if let Some(k) = &kept {
            let _ = fs::remove_file(k);
        }
        return Err(format!(
            "restore of {} failed and it is unchanged: {e}. The vault copy is still at {}",
            original.display(),
            vault.display()
        ));
    }

    fs::remove_file(vault).map_err(|e| format!("restore failed clearing the vault: {e}"))?;
    Ok(kept)
}

pub(crate) fn kept_note(kept: Option<&Path>) -> String {
    kept.map(|k| format!("; what it held until now is kept at {}", k.display()))
        .unwrap_or_default()
}
