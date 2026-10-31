use std::fs;
use std::path::Path;

use crate::action::{ModuleSighting, ProcVerb, RemovalAction};
use crate::guards::remove_preload_entry;
use crate::guards::{identity_matches, is_infrastructure_process, ProcId, ProtectSet, TargetKind};
use crate::outcome::override_hint;
use crate::paths::{exe_suffix, sig_name, verb_word};
use crate::outcome::{
    ApplyOptions, Failure, Outcome, Plan, RefuseCause, Refusal, UndoKind,
    UndoRecord,
};
use crate::paths::{
    move_into_vault, path_refusal, pin_parent, resolve_tool, run_tool,
    run_tool_within, snapshot_into_vault, unit_active, unit_query, TOOL_LIMIT,
};

impl RemovalAction {

    pub fn summary(&self) -> String {
        match self {
            RemovalAction::KillProcess { pid, exe, .. } => {
                format!("kill pid {pid}{}", exe_suffix(exe))
            }
            RemovalAction::SuspendProcess { pid, exe, .. } => {
                format!("suspend pid {pid}{}", exe_suffix(exe))
            }
            RemovalAction::UnloadModule { name, seen } => match seen {
                ModuleSighting::Sysfs => format!("unload module `{name}`"),
                ModuleSighting::KernelListOnly => {
                    format!("unload HIDDEN module `{name}` (absent from /sys/module)")
                }
            },
            RemovalAction::MaskService { unit } => format!("mask unit `{unit}`"),
            RemovalAction::StartService { unit } => format!("enable and start unit `{unit}`"),
            RemovalAction::AllowInboundPort { port } => {
                format!("allow inbound tcp/{port} through the firewall")
            }
            RemovalAction::StopAndRemoveUnit { unit, path } => {
                format!("stop `{unit}` and remove {}", path.display())
            }
            RemovalAction::DisablePersistence { path, kind } => {
                format!("disable {} at {}", kind.label(), path.display())
            }
            RemovalAction::QuarantineFile { path } => {
                format!("quarantine {}", path.display())
            }
            RemovalAction::RemoveLdPreload { path, entry } => match entry {
                Some(e) => format!("remove `{e}` from {}", path.display()),
                None => format!("remove the preload file {}", path.display()),
            },
            RemovalAction::StripLine { path, line, .. } => {
                format!("strip line {} from {}", line.line_no, path.display())
            }
            RemovalAction::RemoveAnchor { path, anchor } => {
                format!("remove trust anchor {} from {}", crate::strip::hex(&anchor.cert_sha256), path.display())
            }
            RemovalAction::RestoreKnownGood { path, label, .. } => {
                format!("restore {} to known-good ({label})", path.display())
            }
        }
    }

    pub fn plan(&self) -> Plan {
        match self {
            RemovalAction::KillProcess { pid, start_time, exe } => Plan {
                summary: self.summary(),
                detail: format!(
                    "Send SIGKILL to pid {pid} (frozen identity: starttime {start_time}{}). \
                     Before signalling, /proc/{pid} is re-read and the signal is withheld if the \
                     starttime or exe no longer match — the PID may have been recycled.",
                    exe_suffix(exe)
                ),
                undo: "None. A killed process cannot be resumed; if it was a legitimate service, \
                       restart it from its unit. Prefer Suspend when the process is wanted as \
                       evidence."
                    .into(),
                reversible: false,
                prefer_instead: Some(format!(
                    "SuspendProcess {{ pid: {pid} }} — SIGSTOP is reversible and preserves the \
                     process and its memory for analysis"
                )),
            },
            RemovalAction::SuspendProcess { pid, start_time, exe } => Plan {
                summary: self.summary(),
                detail: format!(
                    "Send SIGSTOP to pid {pid} (frozen identity: starttime {start_time}{}), \
                     freezing it without destroying it. The same frozen-identity re-check as a \
                     kill runs immediately before signalling.",
                    exe_suffix(exe)
                ),
                undo: format!("Send SIGCONT to pid {pid} (re-checking its identity first)."),
                reversible: true,
                prefer_instead: None,
            },
            RemovalAction::UnloadModule { name, .. } => Plan {
                summary: self.summary(),
                detail: format!(
                    "Call `delete_module(\"{name}\", O_NONBLOCK)` directly — not `rmmod`, whose \
                     binary is a file something on a compromised host owns. Refused first if \
                     the module backs a live mount, a block device, a routed interface, or has \
                     loaded dependents. A module hidden from /sys/module is still unloadable by \
                     name: that is the case this verb exists for. Never forced — EBUSY is \
                     reported, because freeing module text while a hook still points into it is \
                     how a forced unload panics the host. Know what this runs: the kernel calls \
                     the module's OWN exit function before freeing it, so unloading a hostile \
                     module executes attacker-controlled code in ring 0 and trusts it to undo \
                     its own hooks. It may instead re-arm, unhook nothing, or panic the host on \
                     purpose. There is no interface that unloads a module without running it."
                ),
                undo: format!(
                    "Not automatic: reload with `insmod`/`modprobe {name}` from its .ko if the \
                     module was legitimate. Unloading a rootkit module is normally permanent, \
                     and unloading does NOT repair a kernel it already patched — inline hooks, \
                     a rewritten syscall table and moved ops-struct pointers all survive the \
                     module that installed them. Treat this as stopping the bleeding, and the \
                     host as one to rebuild."
                ),
                reversible: false,
                prefer_instead: None,
            },
            RemovalAction::MaskService { unit } => Plan {
                summary: self.summary(),
                detail: format!(
                    "Run `systemctl mask --now {unit}`: stop it now and symlink the unit to \
                     /dev/null so it cannot start again. Refused if {unit} is ssh/sshd or hosts \
                     the operator's own session."
                ),
                undo: format!(
                    "Run `systemctl unmask {unit}`, then `systemctl start {unit}` if it was running \
                     when it was masked."
                ),
                reversible: true,
                prefer_instead: None,
            },
            RemovalAction::StartService { unit } => Plan {
                summary: self.summary(),
                detail: format!(
                    "Run `systemctl enable --now {unit}`: start it now and enable it so it \
                     returns on boot. For bringing a declared service that is down back up; \
                     the unit name is validated and the change is journaled."
                ),
                undo: format!(
                    "Run `systemctl disable {unit}` if it was not enabled before, and \
                     `systemctl stop {unit}` if it was not running before."
                ),
                reversible: true,
                prefer_instead: None,
            },
            RemovalAction::AllowInboundPort { port } => Plan {
                summary: self.summary(),
                detail: format!(
                    "Insert `tcp dport {port} accept` at the top of the firewall's input-hook \
                     chain (comment `{}`), so the scorer can reach a scored service that is \
                     listening but blocked. Additive — it cannot lock anyone out; nftables only.",
                    crate::fwallow::marker(*port)
                ),
                undo: format!(
                    "Delete the firewall rule carrying comment `{}`.",
                    crate::fwallow::marker(*port)
                ),
                reversible: true,
                prefer_instead: None,
            },
            RemovalAction::StopAndRemoveUnit { unit, path } => Plan {
                summary: self.summary(),
                detail: format!(
                    "Run `systemctl disable --now {unit}` to stop it and clear its autostart, \
                     then snapshot {} into the quarantine vault and remove it. Masking is not \
                     used here: the unit file occupies the path a mask symlink would need. \
                     Refused if {unit} is ssh/sshd or hosts the operator's own session.",
                    path.display()
                ),
                undo: format!(
                    "Move the snapshot back from the vault, `systemctl daemon-reload`, then \
                     `systemctl enable --now {unit}`: the unit runs again. `hemostat undo` \
                     replays the whole journal, so every unit removed in the run comes back."
                ),
                reversible: true,
                prefer_instead: None,
            },
            RemovalAction::DisablePersistence { path, kind } => Plan {
                summary: self.summary(),
                detail: format!(
                    "Snapshot {} ({}) into the quarantine vault, then remove it from its live \
                     location so it no longer runs at boot/login.",
                    path.display(),
                    kind.label()
                ),
                undo: "Move the snapshot back from the vault to its original path.".into(),
                reversible: true,
                prefer_instead: None,
            },
            RemovalAction::QuarantineFile { path } => Plan {
                summary: self.summary(),
                detail: format!(
                    "Move {} into the quarantine vault, out of its live path but preserved for \
                     analysis. Refused for paths under /proc, /sys, /dev or the agent's own exe.",
                    path.display()
                ),
                undo: "Move the file back from the vault to its original path.".into(),
                reversible: true,
                prefer_instead: None,
            },
            RemovalAction::RemoveLdPreload { path, entry } => {
                let detail = match entry {
                    Some(e) => format!(
                        "Snapshot {} into the vault, then rewrite it without the line `{e}`.",
                        path.display()
                    ),
                    None => format!(
                        "Move {} into the vault — the file itself, with its owner, mode and \
                         timestamps — which is to remove the file entirely.",
                        path.display()
                    ),
                };
                Plan {
                    summary: self.summary(),
                    detail,
                    undo: match entry {
                        Some(_) => format!("Restore {} from the vault snapshot.", path.display()),
                        None => format!("Move the file back from the vault to {}.", path.display()),
                    },
                    reversible: true,
                    prefer_instead: None,
                }
            }
            RemovalAction::StripLine { path, line, .. } => {
                crate::strip::plan(path, line, self.summary())
            }
            RemovalAction::RemoveAnchor { path, anchor } => {
                crate::anchor::plan(path, anchor, self.summary())
            }
            RemovalAction::RestoreKnownGood { path, want_sha256, label, .. } => Plan {
                summary: self.summary(),
                detail: format!(
                    "Write the known-good {label} (sha256 {want_sha256}) over {}, atomically: a new \
                     file beside it with the same owner, mode, SELinux label and ACL, synced and \
                     renamed into place, so no login ever loads a partial module. The current file \
                     is snapshotted into the vault first.",
                    path.display()
                ),
                undo: format!("Restore {} from the vault snapshot (puts the current file back).", path.display()),
                reversible: true,
                prefer_instead: None,
            },
        }
    }

    pub fn apply(&self, opts: &ApplyOptions, protect: &ProtectSet) -> Outcome {
        match self {
            RemovalAction::KillProcess { pid, start_time, exe } => {
                self.apply_process(ProcVerb::Kill, *pid, *start_time, exe, opts, protect)
            }
            RemovalAction::SuspendProcess { pid, start_time, exe } => {
                self.apply_process(ProcVerb::Suspend, *pid, *start_time, exe, opts, protect)
            }
            RemovalAction::UnloadModule { name, seen } => {
                self.apply_unload(name, *seen, opts, protect)
            }
            RemovalAction::MaskService { unit } => self.apply_mask(unit, opts, protect),
            RemovalAction::StartService { unit } => self.apply_start(unit, opts, protect),
            RemovalAction::AllowInboundPort { port } => self.apply_allow_inbound(*port, opts, protect),
            RemovalAction::StopAndRemoveUnit { unit, path } => {
                self.apply_stop_and_remove(unit, path, opts, protect)
            }
            RemovalAction::DisablePersistence { path, .. } => {
                self.apply_move_out(path, opts, protect, true)
            }
            RemovalAction::QuarantineFile { path } => self.apply_move_out(path, opts, protect, false),
            RemovalAction::RemoveLdPreload { path, entry } => {
                self.apply_preload(path, entry.as_deref(), opts, protect)
            }
            RemovalAction::StripLine { path, line, authority } => {
                crate::strip::apply(self.summary(), path, line, authority, opts, protect)
            }
            RemovalAction::RemoveAnchor { path, anchor } => {
                crate::anchor::apply(self.summary(), path, anchor, opts, protect)
            }
            RemovalAction::RestoreKnownGood { path, content, want_sha256, label } => {
                self.apply_restore_known_good(path, content, want_sha256, label, opts, protect)
            }
        }
    }

    fn apply_process(
        &self,
        verb: ProcVerb,
        pid: u32,
        start_time: u64,
        exe: &Option<String>,
        opts: &ApplyOptions,
        protect: &ProtectSet,
    ) -> Outcome {

        let live = hemostat_sensor_linux::procfs::read_process(pid);
        let kind = match &live {
            None => TargetKind::Unreadable,
            Some(s) if s.exe.is_some() => TargetKind::Userland,

            Some(s) => match s.cmdline.as_deref() {
                None | Some("") => TargetKind::KernelThread,
                Some(_) => TargetKind::Unreadable,
            },
        };
        let current = live.map(|s| ProcId { start_time: s.starttime_ticks, exe: s.exe });

        let unit = hemostat_sensor_linux::saferead::read_scan_target(std::path::Path::new(&format!(
            "/proc/{pid}/cgroup"
        )))
        .and_then(|t| hemostat_sensor_linux::watchdog::unit_from_cgroup(&t));
        let declared = protect.declared_process_reason(
            current.as_ref().and_then(|c| c.exe.as_deref()),
            unit.as_deref(),
        );
        if let Some(reason) = protect.process_reason(pid, kind).or(declared) {

            return Outcome::Refused(Refusal {
                action: self.summary(),
                message: format!(
                    "refused to {} pid {pid}: {}",
                    verb_word(verb),
                    reason.describe()
                ),
                cause: RefuseCause::Protected(reason),
                suggested_alternative: None,
            });
        }

        match crate::account::owners_of(pid) {
            Ok(owners) => {
                if let Some((owner, reason)) = protect.owner_reason(&owners) {
                    return Outcome::Refused(Refusal {
                        action: self.summary(),
                        message: format!(
                            "refused to {} pid {pid}: it belongs to `{owner}` — {}",
                            verb_word(verb),
                            reason.describe()
                        ),
                        cause: RefuseCause::Protected(reason),
                        suggested_alternative: None,
                    });
                }
            }
            Err(why) => {
                return Outcome::Refused(Refusal {
                    action: self.summary(),
                    message: format!(
                        "refused to {} pid {pid}: the account it belongs to could not be \
                         established ({why}), so it cannot be shown not to be one HEMOSTAT \
                         never changes (the white team's, the DataDog agent's) or one declared \
                         off-limits — an account a directory serves looks exactly like this. \
                         Check `ps -o user,ruser -p {pid}` and act by hand if it is none of those",
                        verb_word(verb)
                    ),
                    cause: RefuseCause::UnverifiedProtectSet,
                    suggested_alternative: None,
                });
            }
        }

        if matches!(verb, ProcVerb::Kill) {
            let comm = hemostat_sensor_linux::saferead::read_scan_target(std::path::Path::new(
                &format!("/proc/{pid}/comm"),
            ))
            .map(|c| c.trim().to_string());
            let running = current.as_ref().and_then(|c| c.exe.as_deref());
            if let Some(reason) =
                protect.infrastructure_kill_reason(kill_guard_name(comm.as_deref(), running))
            {
                return Outcome::Refused(Refusal {
                    action: self.summary(),
                    message: format!("refused to kill pid {pid}: {}", reason.describe()),
                    cause: RefuseCause::Protected(reason),
                    suggested_alternative: Some(RemovalAction::SuspendProcess {
                        pid,
                        start_time,
                        exe: exe.clone(),
                    }),
                });
            }
        }

        if !protect.listener_map_complete {
            return Outcome::Refused(Refusal {
                action: self.summary(),
                message: format!(
                    "refused to {} pid {pid}: the listening-socket map is incomplete, so the \
                     service-listener guard cannot be trusted. Re-run as root.",
                    verb_word(verb)
                ),
                cause: RefuseCause::UnverifiedProtectSet,
                suggested_alternative: None,
            });
        }

        let expected = ProcId { start_time, exe: exe.clone() };
        if !identity_matches(&expected, current.as_ref()) {
            return Outcome::Refused(Refusal {
                action: self.summary(),
                cause: RefuseCause::FrozenTargetMismatch {
                    expected: format!("starttime {start_time}{}", exe_suffix(exe)),
                    found: match &current {
                        Some(c) => format!("starttime {}{}", c.start_time, exe_suffix(&c.exe)),
                        None => "the PID no longer exists".into(),
                    },
                },
                message: format!(
                    "refused to {} pid {pid}: its identity changed since it was selected — the \
                     PID has been recycled and now names a different process",
                    verb_word(verb)
                ),

                suggested_alternative: None,
            });
        }

        if !opts.armed {
            return Outcome::Planned(self.plan());
        }
        let sig = match verb {
            ProcVerb::Kill => libc::SIGKILL,
            ProcVerb::Suspend => libc::SIGSTOP,
        };

        let rc = unsafe { libc::kill(pid as libc::pid_t, sig) };
        if rc != 0 {
            let err = std::io::Error::last_os_error();
            return Outcome::Failed(Failure {
                action: self.summary(),
                reason: format!("kill({pid}, {}) failed: {err}", sig_name(sig)),
            });
        }
        let undo = match verb {
            ProcVerb::Kill => UndoRecord {
                did: format!("SIGKILL sent to pid {pid}{}", exe_suffix(exe)),
                undo: UndoKind::Irreversible {
                    note: format!(
                        "pid {pid} was killed; if it was a legitimate service, restart it from \
                         its unit"
                    ),
                },
                reversible: false,
            },
            ProcVerb::Suspend => UndoRecord {
                did: format!("SIGSTOP sent to pid {pid}{}", exe_suffix(exe)),
                undo: UndoKind::ResumeProcess { pid, start_time },
                reversible: true,
            },
        };
        Outcome::Applied(undo)
    }

    fn apply_unload(
        &self,
        name: &str,
        seen: ModuleSighting,
        opts: &ApplyOptions,
        protect: &ProtectSet,
    ) -> Outcome {
        if let Some(reason) = protect.declared_reason(name) {
            return Outcome::Refused(Refusal {
                action: self.summary(),
                message: format!("refused to unload `{name}`: {}", reason.describe()),
                cause: RefuseCause::Protected(reason),
                suggested_alternative: None,
            });
        }
        if name.is_empty() || name.contains('/') || name.contains(char::is_whitespace) {
            return Outcome::Refused(Refusal {
                action: self.summary(),
                cause: RefuseCause::InvalidTarget(format!("`{name}` is not a valid module name")),
                message: "refused: module name is empty or malformed".into(),
                suggested_alternative: None,
            });
        }

        if let Some(reason) = protect.modules.reason(name) {
            return Outcome::Refused(Refusal {
                action: self.summary(),
                message: format!("refused to unload `{name}`: {}", reason.describe()),
                cause: RefuseCause::InvalidTarget(format!(
                    "`{name}` is load-bearing on this host"
                )),
                suggested_alternative: None,
            });
        }

        if !protect.modules.complete {
            return Outcome::Refused(Refusal {
                action: self.summary(),
                message: format!(
                    "refused to unload `{name}`: the module protect-set could not be built \
                     (/proc or /sys unreadable), so nothing here can say whether this module \
                     is the one holding the disk up. Re-run as root"
                ),
                cause: RefuseCause::UnverifiedProtectSet,
                suggested_alternative: None,
            });
        }

        let listed = hemostat_sensor_linux::saferead::read_scan_target(Path::new("/proc/modules"));
        let sighting = sysfs_sighting(Path::new("/sys/module"), listed.as_deref(), name);
        let visible = sighting != SysfsSighting::Absent;
        if !visible && seen == ModuleSighting::Sysfs {

            return Outcome::Refused(Refusal {
                action: self.summary(),
                cause: RefuseCause::InvalidTarget(format!("no module `{name}` under /sys/module")),
                message: format!(
                    "refused to unload `{name}`: it is not present in /sys/module (already \
                     unloaded, or the name is wrong). If this module is hidden rather than \
                     absent, it has to be named from the kernel's own module list — `kwalk` \
                     recovers those"
                ),
                suggested_alternative: None,
            });
        }

        if sighting == SysfsSighting::BuiltIn && seen == ModuleSighting::Sysfs {
            return Outcome::Refused(Refusal {
                action: self.summary(),
                cause: RefuseCause::InvalidTarget(format!("`{name}` is built into the kernel")),
                message: format!(
                    "refused to unload `{name}`: it is built into the kernel — /sys/module/{name} \
                     has no `initstate` and /proc/modules does not list it — and `delete_module` \
                     cannot unload a built-in. Nothing short of a different kernel removes it"
                ),
                suggested_alternative: None,
            });
        }
        if !opts.armed {
            return Outcome::Planned(self.plan());
        }
        match Self::delete_module_syscall(name) {
            Ok(()) => Outcome::Applied(UndoRecord {
                did: format!(
                    "unloaded kernel module `{name}` via delete_module(2){}",
                    if visible { "" } else { " (it was hidden from /sys/module)" }
                ),
                undo: UndoKind::Irreversible {
                    note: format!(
                        "module `{name}` was unloaded; reload with modprobe/insmod from its .ko \
                         only if it was legitimate. The kernel ran that module's own exit \
                         function to do this, so a hostile module chose for itself whether to \
                         remove its hooks. Re-run the kernel-text and ops-pointer sweeps before \
                         calling this host clean"
                    ),
                },
                reversible: false,
            }),
            Err(reason) => Outcome::Failed(Failure { action: self.summary(), reason }),
        }
    }

    fn delete_module_syscall(name: &str) -> Result<(), String> {
        let Ok(c) = std::ffi::CString::new(name) else {
            return Err(format!("`{name}` contains a NUL byte and is not a module name"));
        };

        let rc = unsafe {
            libc::syscall(libc::SYS_delete_module, c.as_ptr(), libc::O_NONBLOCK)
        };
        if rc == 0 {
            return Ok(());
        }
        let e = std::io::Error::last_os_error();
        let raw = e.raw_os_error().unwrap_or(0);
        Err(match raw {
            libc::EBUSY => format!(
                "`{name}` is in use (EBUSY): its reference count is not zero, or something \
                 holds a pointer into it. Not forced — `rmmod -f` frees module text while a \
                 live pointer still points into it, which is how a forced unload panics a host, \
                 and a module that hooks is the kind most likely to be in that state"
            ),

            libc::ENOENT if Path::new(&format!("/sys/module/{name}/initstate")).exists() => format!(
                "the kernel reports no module `{name}` (ENOENT), but /sys/module/{name} is \
                 still there with its `initstate`. That pair is the signature of a module that ran \
                 `list_del(&THIS_MODULE->list)`: it is STILL LOADED and still hooked, it left \
                 the list `delete_module` resolves names through, and it kept its kobject. \
                 Nothing in userland can unload it — the only interface takes a name and the \
                 name no longer resolves. Reboot clears it; treat the running kernel as \
                 untrustworthy until then"
            ),
            libc::ENOENT if Path::new(&format!("/sys/module/{name}")).exists() => format!(
                "the kernel has no loadable module called `{name}` (ENOENT), and \
                 /sys/module/{name} has no `initstate`: that is a built-in, which \
                 `delete_module` never unloads. A loadable module that had both left the list \
                 and stripped its own `initstate` would look the same — `kwalk` and the taint \
                 cross-view are what tell those apart"
            ),
            libc::ENOENT => format!(
                "the kernel has no module called `{name}` (ENOENT), and /sys/module/{name} is \
                 not there either. Either it unloaded between the sweep and this call, or the \
                 name is wrong. A module that unlinked itself would still have its kobject; \
                 this has neither"
            ),
            libc::EPERM => "refused by the kernel (EPERM): CAP_SYS_MODULE is missing, or \
                 `kernel.modules_disabled=1` is set for this boot — in which case nothing can \
                 unload anything until reboot, including this"
                .to_string(),
            libc::EWOULDBLOCK => format!(
                "`{name}` is still initialising or exiting (EWOULDBLOCK); try again shortly"
            ),
            _ => format!("delete_module(`{name}`) failed: {e}"),
        })
    }

    fn apply_mask(&self, unit: &str, opts: &ApplyOptions, protect: &ProtectSet) -> Outcome {
        if let Some(reason) = protect.unit_reason(unit) {
            return Outcome::Refused(Refusal {
                action: self.summary(),
                message: format!(
                    "refused to mask `{unit}`: {}{}",
                    reason.describe(),
                    override_hint(&reason, unit)
                ),
                cause: RefuseCause::Protected(reason),
                suggested_alternative: None,
            });
        }
        if unit.is_empty() || unit.contains('/') || unit.contains(char::is_whitespace) {
            return Outcome::Refused(Refusal {
                action: self.summary(),
                cause: RefuseCause::InvalidTarget(format!("`{unit}` is not a valid unit name")),
                message: "refused: unit name is empty or malformed".into(),
                suggested_alternative: None,
            });
        }
        if !opts.armed {
            return Outcome::Planned(self.plan());
        }
        let Some(systemctl) = resolve_tool(&["/usr/bin/systemctl", "/bin/systemctl"]) else {
            return Outcome::Failed(Failure {
                action: self.summary(),
                reason: "systemctl not found at /usr/bin or /bin".into(),
            });
        };

        let was_active = std::process::Command::new(&systemctl)
            .args(["is-active", "--quiet", unit])
            .env_clear()
            .status()
            .ok()
            .map(|s| s.success());
        match run_tool(&systemctl, &["mask", "--now", unit]) {
            Ok(()) => Outcome::Applied(UndoRecord {
                did: format!("masked and stopped unit `{unit}`"),
                undo: UndoKind::UnmaskService { unit: unit.to_string(), was_active },
                reversible: true,
            }),
            Err(reason) => Outcome::Failed(Failure { action: self.summary(), reason }),
        }
    }

    fn apply_start(&self, unit: &str, opts: &ApplyOptions, _protect: &ProtectSet) -> Outcome {
        if unit.is_empty() || unit.contains('/') || unit.contains(char::is_whitespace) {
            return Outcome::Refused(Refusal {
                action: self.summary(),
                cause: RefuseCause::InvalidTarget(format!("`{unit}` is not a valid unit name")),
                message: "refused: unit name is empty or malformed".into(),
                suggested_alternative: None,
            });
        }
        if !opts.armed {
            return Outcome::Planned(self.plan());
        }
        let Some(systemctl) = resolve_tool(&["/usr/bin/systemctl", "/bin/systemctl"]) else {
            return Outcome::Failed(Failure {
                action: self.summary(),
                reason: "systemctl not found at /usr/bin or /bin".into(),
            });
        };
        self.enable_and_start(&systemctl, unit, TOOL_LIMIT)
    }

    pub(crate) fn enable_and_start(&self, systemctl: &Path, unit: &str, limit: std::time::Duration) -> Outcome {

        let was_enabled = unit_query(systemctl, "is-enabled", unit, limit);
        let was_active = unit_query(systemctl, "is-active", unit, limit);
        match run_tool_within(systemctl, &["enable", "--now", unit], limit) {
            Ok(()) => {

                if unit_active(systemctl, unit, limit) {
                    Outcome::Applied(UndoRecord {
                        did: format!("enabled and started unit `{unit}`"),
                        undo: UndoKind::RestoreServiceState {
                            unit: unit.to_string(),
                            was_enabled,
                            was_active,
                        },
                        reversible: true,
                    })
                } else {
                    Outcome::Failed(Failure {
                        action: self.summary(),
                        reason: format!(
                            "`systemctl enable --now {unit}` returned success but the unit is not \
                             active — it failed to start (see `journalctl -xeu {unit}`)"
                        ),
                    })
                }
            }
            Err(reason) => Outcome::Failed(Failure { action: self.summary(), reason }),
        }
    }

    fn apply_allow_inbound(&self, port: u16, opts: &ApplyOptions, _protect: &ProtectSet) -> Outcome {
        use crate::fwallow;

        let Some(nft) = fwallow::nft_path() else {
            return Outcome::Failed(Failure {
                action: self.summary(),
                reason: "nft not found at /usr/sbin, /sbin, /usr/bin or /bin — this opens a port \
                         on nftables (every IRSeC Linux box runs it). A pure iptables-legacy host \
                         is not supported here; add the accept by hand."
                    .into(),
            });
        };

        let ruleset = match fwallow::nft_capture(&nft, &["list", "ruleset"]) {
            Ok(t) => t,
            Err(e) => {
                return Outcome::Failed(Failure {
                    action: self.summary(),
                    reason: format!("could not read the firewall ruleset: {e}"),
                });
            }
        };
        let comment = fwallow::marker(port);

        if ruleset.lines().any(|l| fwallow::is_allow_rule(l, port)) {
            return Outcome::Refused(Refusal {
                action: self.summary(),
                cause: RefuseCause::InvalidTarget(format!("tcp/{port} is already allowed by mahoraga")),
                message: format!(
                    "tcp/{port} is already allowed by a mahoraga rule (comment `{comment}`); nothing to do"
                ),
                suggested_alternative: None,
            });
        }
        let Some(chain) = fwallow::input_hook_chain(&ruleset) else {
            return Outcome::Failed(Failure {
                action: self.summary(),
                reason: "could not find an input-hook base chain in `nft list ruleset` — the host \
                         may use iptables-legacy, or the ruleset could not be read (needs root). \
                         Add the accept by hand."
                    .into(),
            });
        };

        if let Some(why) = fwallow::chain_refusal(&chain.family, &chain.table, &chain.chain) {
            return Outcome::Failed(Failure {
                action: self.summary(),
                reason: format!(
                    "the input-hook chain in `nft list ruleset` is not one this tool hands to nft \
                     ({why}). Add the accept by hand."
                ),
            });
        }
        if !opts.armed {
            return Outcome::Planned(self.plan());
        }

        let dport = port.to_string();
        let quoted = format!("\"{comment}\"");
        let args = [
            "insert", "rule", chain.family.as_str(), chain.table.as_str(), chain.chain.as_str(),
            "tcp", "dport", dport.as_str(), "accept", "comment", quoted.as_str(),
        ];
        if let Err(e) = run_tool(&nft, &args) {
            return Outcome::Failed(Failure {
                action: self.summary(),
                reason: format!("nft insert failed: {e}"),
            });
        }

        let listing = fwallow::nft_capture(
            &nft,
            &["-a", "list", "chain", chain.family.as_str(), chain.table.as_str(), chain.chain.as_str()],
        )
        .unwrap_or_default();
        if !listing.lines().any(|l| fwallow::is_allow_rule(l, port)) {
            return Outcome::Failed(Failure {
                action: self.summary(),
                reason: format!(
                    "inserted the accept for tcp/{port} but could not find it afterward — the \
                     firewall did not take the change"
                ),
            });
        }
        Outcome::Applied(UndoRecord {
            did: format!("allowed inbound tcp/{port} through the firewall (comment `{comment}`)"),
            undo: UndoKind::RemoveNftAllow {
                family: chain.family,
                table: chain.table,
                chain: chain.chain,
                comment,
            },
            reversible: true,
        })
    }

    fn apply_stop_and_remove(
        &self,
        unit: &str,
        path: &Path,
        opts: &ApplyOptions,
        protect: &ProtectSet,
    ) -> Outcome {
        if let Some(reason) = protect.unit_reason(unit) {
            return Outcome::Refused(Refusal {
                action: self.summary(),
                message: format!(
                    "refused to stop `{unit}`: {}{}",
                    reason.describe(),
                    override_hint(&reason, unit)
                ),
                cause: RefuseCause::Protected(reason),
                suggested_alternative: None,
            });
        }
        if unit.is_empty() || unit.contains('/') || unit.contains(char::is_whitespace) {
            return Outcome::Refused(Refusal {
                action: self.summary(),
                cause: RefuseCause::InvalidTarget(format!("`{unit}` is not a valid unit name")),
                message: "refused: unit name is empty or malformed".into(),
                suggested_alternative: None,
            });
        }

        if let Some(refused) = self.move_out_refusal(path, protect) {
            return refused;
        }

        if fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink()) {
            let target = fs::read_link(path)
                .map_or_else(|_| "an unreadable target".to_string(), |t| t.display().to_string());
            return Outcome::Refused(Refusal {
                action: self.summary(),
                cause: RefuseCause::InvalidTarget("the unit file is a symlink".into()),
                message: format!(
                    "refused to stop `{unit}`: {} is a symlink to {target} (a unit installed with \
                     `systemctl link`), which `disable` would delete before it could be moved \
                     into the vault. Quarantine {target} and disable the unit by hand.",
                    path.display()
                ),
                suggested_alternative: None,
            });
        }

        if let Some(why) = crate::persistence::unit_file_refusal(unit, path) {
            return Outcome::Refused(Refusal {
                action: self.summary(),
                cause: RefuseCause::InvalidTarget("the file is not the unit's own definition".into()),
                message: format!("refused to stop `{unit}`: {why}. Nothing was stopped."),
                suggested_alternative: None,
            });
        }
        if !opts.armed {
            return Outcome::Planned(self.plan());
        }
        let Some(systemctl) = resolve_tool(&["/usr/bin/systemctl", "/bin/systemctl"]) else {
            return Outcome::Failed(Failure {
                action: self.summary(),
                reason: "systemctl not found at /usr/bin or /bin — refusing to remove the unit \
                         file while the running service cannot be stopped"
                    .into(),
            });
        };

        if let Err(reason) = crate::paths::ensure_vault(&opts.vault_dir) {
            return Outcome::Failed(Failure { action: self.summary(), reason });
        }

        if let Err(reason) = run_tool(&systemctl, &["disable", "--now", unit]) {
            return Outcome::Failed(Failure {
                action: self.summary(),
                reason: format!(
                    "could not stop `{unit}` ({reason}); the unit file was left in place rather \
                     than removed while the service is still running"
                ),
            });
        }

        match self.apply_move_out(path, opts, protect, true) {
            Outcome::Applied(rec) => {

                let _ = run_tool(&systemctl, &["reset-failed", unit]);
                match rec.undo {
                UndoKind::RestoreFile { vault, original, .. } => Outcome::Applied(UndoRecord {
                    did: format!(
                        "stopped and disabled `{unit}`, then moved {} into the vault",
                        original.display()
                    ),
                    undo: UndoKind::RestoreUnit { vault, original, unit: unit.to_string() },
                    reversible: true,
                }),
                other => Outcome::Applied(UndoRecord { undo: other, ..rec }),
                }
            }

            Outcome::Failed(f) => Outcome::Failed(Failure {
                reason: format!(
                    "{} — `{unit}` is already stopped and disabled; `systemctl enable --now \
                     {unit}` starts it again",
                    f.reason
                ),
                ..f
            }),

            Outcome::Refused(r) => Outcome::Refused(Refusal {
                message: format!(
                    "{} — but `{unit}` was already stopped and disabled; `systemctl enable \
                     --now {unit}` starts it again",
                    r.message
                ),
                ..r
            }),
            other => other,
        }
    }

    fn apply_move_out(
        &self,
        path: &Path,
        opts: &ApplyOptions,
        protect: &ProtectSet,
        _persistence: bool,
    ) -> Outcome {
        if let Some(refused) = self.move_out_refusal(path, protect) {
            return refused;
        }
        if !opts.armed {
            return Outcome::Planned(self.plan());
        }
        match move_into_vault(path, &opts.vault_dir) {
            Ok((vault, lost)) => Outcome::Applied(UndoRecord {

                did: if lost.is_empty() {
                    format!("moved {} into the vault at {}", path.display(), vault.display())
                } else {
                    format!(
                        "moved {} into the vault at {} — but the vault is on a different \
                         filesystem and this copy does NOT carry its {}. Read those from the \
                         evidence store, not from the file in the vault",
                        path.display(),
                        vault.display(),
                        lost.join(" or its ")
                    )
                },
                undo: UndoKind::RestoreFile {
                    vault,
                    original: path.to_path_buf(),
                    moved: true,
                },
                reversible: true,
            }),
            Err(reason) => Outcome::Failed(Failure { action: self.summary(), reason }),
        }
    }

    fn move_out_refusal(&self, path: &Path, protect: &ProtectSet) -> Option<Outcome> {

        if let Some(reason) = protect.path_reason(path) {
            return Some(Outcome::Refused(Refusal {
                action: self.summary(),
                message: format!("refused to move {}: {}", path.display(), reason.describe()),
                cause: RefuseCause::Protected(reason),
                suggested_alternative: None,
            }));
        }
        if let Some(reason) = path_refusal(path) {
            return Some(Outcome::Refused(Refusal {
                action: self.summary(),
                cause: RefuseCause::InvalidTarget(reason.clone()),
                message: format!("refused to move {}: {reason}", path.display()),
                suggested_alternative: None,
            }));
        }

        let pinned = match pin_parent(path) {
            Ok(p) => p,
            Err(reason) => {
                return Some(Outcome::Refused(Refusal {
                    action: self.summary(),
                    cause: RefuseCause::InvalidTarget(reason.clone()),
                    message: format!("refused to move {}: {reason}", path.display()),
                    suggested_alternative: None,
                }));
            }
        };

        match pinned.kind() {
            Ok(k) if k == libc::S_IFDIR => {
                return Some(Outcome::Refused(Refusal {
                    action: self.summary(),
                    cause: RefuseCause::InvalidTarget("the path is a directory".into()),
                    message: format!(
                        "refused to move {}: it is a directory, and moving it would take \
                         everything under it. Look inside and act on the entry, not the folder.",
                        path.display()
                    ),
                    suggested_alternative: None,
                }));
            }
            Ok(k) if k != libc::S_IFREG && k != libc::S_IFLNK => {
                return Some(Outcome::Refused(Refusal {
                    action: self.summary(),
                    cause: RefuseCause::InvalidTarget("not a regular file".into()),
                    message: format!(
                        "refused to move {}: it is neither a regular file nor a symlink",
                        path.display()
                    ),
                    suggested_alternative: None,
                }));
            }
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Some(Outcome::Refused(Refusal {
                    action: self.summary(),
                    cause: RefuseCause::InvalidTarget("the file does not exist".into()),
                    message: format!("refused: {} does not exist", path.display()),
                    suggested_alternative: None,
                }));
            }
            Err(e) => {
                return Some(Outcome::Refused(Refusal {
                    action: self.summary(),
                    cause: RefuseCause::InvalidTarget(format!("cannot be examined: {e}")),
                    message: format!("refused: {} could not be examined: {e}", path.display()),
                    suggested_alternative: None,
                }));
            }
        }
        None
    }

    fn apply_preload(
        &self,
        path: &Path,
        entry: Option<&str>,
        opts: &ApplyOptions,
        protect: &ProtectSet,
    ) -> Outcome {
        if let Some(reason) = protect.path_reason(path) {
            return Outcome::Refused(Refusal {
                action: self.summary(),
                message: format!("refused to edit {}: {}", path.display(), reason.describe()),
                cause: RefuseCause::Protected(reason),
                suggested_alternative: None,
            });
        }

        if let Some(reason) = path_refusal(path) {
            return Outcome::Refused(Refusal {
                action: self.summary(),
                cause: RefuseCause::InvalidTarget(reason.clone()),
                message: format!("refused to edit {}: {reason}", path.display()),
                suggested_alternative: None,
            });
        }

        let Some(e) = entry else {
            return self.apply_move_out(path, opts, protect, true);
        };

        let max = hemostat_sensor_linux::saferead::MAX_SCAN_BYTES;
        let text = match hemostat_sensor_linux::saferead::read_bytes(path, max)
            .map_err(|e| e.to_string())
            .and_then(|b| {
                String::from_utf8(b).map_err(|_| "it holds bytes that are not UTF-8".to_string())
            }) {
            Ok(t) => t,
            Err(why) => {
                return Outcome::Refused(Refusal {
                    action: self.summary(),
                    cause: RefuseCause::InvalidTarget(format!("{} cannot be edited exactly", path.display())),
                    message: format!(
                        "refused to edit {}: {why}, so the rest of it could not be written back \
                         exactly as it was. Edit it by hand, or remove the whole file",
                        path.display()
                    ),
                    suggested_alternative: None,
                });
            }
        };

        let (new_content, removed) = remove_preload_entry(&text, e);
        if !removed {
            return Outcome::Refused(Refusal {
                action: self.summary(),
                cause: RefuseCause::InvalidTarget(format!("`{e}` is not in {}", path.display())),
                message: format!("refused: `{e}` is not a live entry in {}", path.display()),
                suggested_alternative: None,
            });
        }
        if !opts.armed {
            return Outcome::Planned(self.plan());
        }

        let vault = match snapshot_into_vault(path, &text, &opts.vault_dir) {
            Ok(v) => v,
            Err(reason) => return Outcome::Failed(Failure { action: self.summary(), reason }),
        };
        match fs::write(path, &new_content) {
            Ok(()) => Outcome::Applied(UndoRecord {
                did: format!("removed `{e}` from {}", path.display()),
                undo: UndoKind::RestoreFile { vault, original: path.to_path_buf(), moved: false },
                reversible: true,
            }),
            Err(e) => Outcome::Failed(Failure {
                action: self.summary(),
                reason: format!("editing {} failed: {e} (a snapshot is in the vault)", path.display()),
            }),
        }
    }

    fn apply_restore_known_good(
        &self,
        path: &Path,
        content: &[u8],
        want_sha256: &str,
        label: &str,
        opts: &ApplyOptions,
        protect: &ProtectSet,
    ) -> Outcome {
        use std::os::unix::fs::MetadataExt as _;
        if let Some(reason) = protect.path_reason(path) {
            return Outcome::Refused(Refusal {
                action: self.summary(),
                message: format!("refused to restore {}: {}", path.display(), reason.describe()),
                cause: RefuseCause::Protected(reason),
                suggested_alternative: None,
            });
        }
        if let Some(reason) = path_refusal(path) {
            return Outcome::Refused(Refusal {
                action: self.summary(),
                cause: RefuseCause::InvalidTarget(reason.clone()),
                message: format!("refused to restore {}: {reason}", path.display()),
                suggested_alternative: None,
            });
        }

        let have = crate::strip::hex(&crate::strip::sha256(content));
        if !have.eq_ignore_ascii_case(want_sha256) {
            return Outcome::Refused(Refusal {
                action: self.summary(),
                cause: RefuseCause::InvalidTarget("the known-good bytes do not match their recorded digest".into()),
                message: format!(
                    "refused to restore {}: the supplied {label} bytes hash to {have}, not the \
                     expected {want_sha256}. Nothing was written",
                    path.display()
                ),
                suggested_alternative: None,
            });
        }

        let r = match crate::strip::read_for_restore(path) {
            Ok(r) => r,
            Err(why) => {
                return Outcome::Refused(Refusal {
                    action: self.summary(),
                    cause: RefuseCause::InvalidTarget(format!("{} cannot be restored: {why}", path.display())),
                    message: format!("refused to restore {}: {why}", path.display()),
                    suggested_alternative: None,
                })
            }
        };
        let current_sha = crate::strip::sha256(&r.bytes);

        if crate::strip::hex(&current_sha).eq_ignore_ascii_case(want_sha256) {
            return Outcome::Refused(Refusal {
                action: self.summary(),
                cause: RefuseCause::InvalidTarget("already the known-good bytes".into()),
                message: format!("{} already matches the known-good {label}; nothing to restore", path.display()),
                suggested_alternative: None,
            });
        }
        if !opts.armed {
            return Outcome::Planned(self.plan());
        }
        let meta = crate::strip::Meta { mode: r.md.mode(), uid: r.md.uid(), gid: r.md.gid() };

        let vault = match crate::strip::snapshot(path, &r.bytes, &opts.vault_dir) {
            Ok(v) => v,
            Err(why) => return Outcome::Failed(Failure { action: self.summary(), reason: why }),
        };

        if let Err(why) = crate::strip::replace(&r, content, meta, None, &current_sha) {
            let _ = fs::remove_file(&vault);
            return Outcome::Failed(Failure {
                action: self.summary(),
                reason: format!("{why}; {} is unchanged", path.display()),
            });
        }
        Outcome::Applied(UndoRecord {
            did: format!("restored {} to known-good ({label})", path.display()),
            undo: UndoKind::RestoreFile { vault, original: path.to_path_buf(), moved: false },
            reversible: true,
        })
    }
}

pub(crate) fn kill_guard_name<'a>(comm: Option<&'a str>, exe: Option<&'a str>) -> Option<&'a str> {
    let exe = exe.map(|e| e.strip_suffix(" (deleted)").unwrap_or(e));
    exe.filter(|e| is_infrastructure_process(e)).or(comm).or(exe)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SysfsSighting {

    Absent,

    Loadable,

    BuiltIn,
}

pub(crate) fn sysfs_sighting(sys_module: &Path, proc_modules: Option<&str>, name: &str) -> SysfsSighting {
    let dir = sys_module.join(name);
    if !dir.exists() {
        return SysfsSighting::Absent;
    }
    if dir.join("initstate").exists() {
        return SysfsSighting::Loadable;
    }
    match proc_modules {
        Some(text) if !text.lines().any(|l| l.split_whitespace().next() == Some(name)) => {
            SysfsSighting::BuiltIn
        }
        _ => SysfsSighting::Loadable,
    }
}
