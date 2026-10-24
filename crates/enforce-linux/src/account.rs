use crate::{ApplyOptions, Failure, Outcome, ProtectSet, RefuseCause, UndoKind, UndoRecord};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccountAction {

    SessionKill {

        user: String,

        uid: u32,
    },

    TicketPurge {

        user: String,

        uid: u32,
    },

    CredRotate {

        user: String,

        uid: u32,

        previous_last_change: Option<String>,
    },

    GroupDrop {

        user: String,

        uid: u32,

        group: String,
    },
}

impl AccountAction {

    pub fn user(&self) -> &str {
        match self {
            AccountAction::SessionKill { user, .. }
            | AccountAction::TicketPurge { user, .. }
            | AccountAction::CredRotate { user, .. }
            | AccountAction::GroupDrop { user, .. } => user,
        }
    }

    pub const fn uid(&self) -> u32 {
        match self {
            AccountAction::SessionKill { uid, .. }
            | AccountAction::TicketPurge { uid, .. }
            | AccountAction::CredRotate { uid, .. }
            | AccountAction::GroupDrop { uid, .. } => *uid,
        }
    }

    pub const fn changes_the_account(&self) -> bool {
        matches!(self, AccountAction::CredRotate { .. } | AccountAction::GroupDrop { .. })
    }
}

pub const FIRST_HUMAN_UID: u32 = 1000;

pub const LAST_HUMAN_UID: u32 = 60_000;

pub const fn is_a_human_login(uid: u32) -> bool {
    uid >= FIRST_HUMAN_UID && uid <= LAST_HUMAN_UID
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionMechanism {

    Loginctl,

    SignalSessions,
}

pub const fn judge_session_mechanism(logind_live: bool) -> SessionMechanism {
    if logind_live {
        SessionMechanism::Loginctl
    } else {
        SessionMechanism::SignalSessions
    }
}

pub fn logind_is_live() -> bool {
    std::path::Path::new("/run/systemd/sessions").is_dir()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcSession {

    pub pid: u32,

    pub uid: u32,

    pub sid: u32,

    pub tty: i32,
}

pub fn parse_stat_session(stat: &str) -> Option<(u32, i32)> {
    let close = stat.rfind(')')?;
    let rest: Vec<&str> = stat.get(close + 1..)?.split_whitespace().collect();

    let sid = rest.get(3)?.parse().ok()?;
    let tty = rest.get(4)?.parse().ok()?;
    Some((sid, tty))
}

pub fn login_session_ids(
    procs: &[ProcSession],
    target_uid: u32,
    operator_session_pids: &std::collections::BTreeSet<u32>,
) -> std::collections::BTreeSet<u32> {
    use std::collections::{BTreeMap, BTreeSet};

    let mut target_is_present: BTreeSet<u32> = BTreeSet::new();
    let mut human_owners: BTreeMap<u32, BTreeSet<u32>> = BTreeMap::new();
    let mut operator_is_in: BTreeSet<u32> = BTreeSet::new();

    for p in procs {
        if p.sid == 0 {
            continue;
        }
        if operator_session_pids.contains(&p.pid) {
            operator_is_in.insert(p.sid);
        }
        if p.tty == 0 {
            continue;
        }
        if p.uid == target_uid {
            target_is_present.insert(p.sid);
        }

        if is_a_human_login(p.uid) || p.uid == target_uid {
            human_owners.entry(p.sid).or_default().insert(p.uid);
        }
    }

    target_is_present
        .into_iter()
        .filter(|sid| !operator_is_in.contains(sid))
        .filter(|sid| {
            human_owners.get(sid).is_some_and(|owners| {
                owners.len() == 1 && owners.contains(&target_uid)
            })
        })
        .collect()
}

pub fn pids_in_sessions(
    procs: &[ProcSession],
    sids: &std::collections::BTreeSet<u32>,
) -> Vec<u32> {
    let mut out: Vec<u32> = procs
        .iter()
        .filter(|p| sids.contains(&p.sid) && p.pid > 1)
        .map(|p| p.pid)
        .collect();
    out.sort_unstable();
    out
}

pub fn read_proc_sessions() -> Vec<ProcSession> {
    let Ok(dir) = std::fs::read_dir("/proc") else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for entry in dir.flatten() {
        let Some(pid) = entry.file_name().to_str().and_then(|n| n.parse::<u32>().ok()) else {
            continue;
        };
        let base = entry.path();

        let Ok(stat) = std::fs::read(base.join("stat")) else {
            continue;
        };
        let Some((sid, tty)) = parse_stat_session(&String::from_utf8_lossy(&stat)) else {
            continue;
        };

        let Some(uid) = std::fs::read(base.join("status")).ok().and_then(|s| {
            String::from_utf8_lossy(&s).lines().find_map(|l| {
                l.strip_prefix("Uid:").and_then(|v| v.split_whitespace().next()?.parse().ok())
            })
        }) else {
            continue;
        };
        out.push(ProcSession { pid, uid, sid, tty });
    }
    out
}

pub fn own_session_id() -> u32 {
    std::fs::read_to_string("/proc/self/stat")
        .ok()
        .and_then(|s| parse_stat_session(&s))
        .map_or(0, |(sid, _)| sid)
}

pub fn uid_in_passwd(text: &str, user: &str) -> Option<u32> {
    text.lines().find_map(|l| {
        let mut f = l.split(':');
        let name = f.next()?;
        let _pw = f.next()?;
        let uid = f.next()?;
        (name == user).then(|| uid.parse().ok())?
    })
}

pub fn uid_of(user: &str) -> Option<u32> {
    uid_in_passwd(&hemostat_sensor_linux::saferead::read_scan_target(std::path::Path::new("/etc/passwd"))?, user)
}

pub fn last_change_in_shadow(text: &str, user: &str) -> Option<String> {
    text.lines()
        .filter_map(|l| {
            let mut f = l.split(':');
            let name = f.next()?;
            let _hash = f.next()?;
            let last = f.next()?;
            (name == user).then(|| last.to_string())
        })
        .find(|v| !v.is_empty())
}

pub fn read_last_change(user: &str) -> Option<String> {
    last_change_in_shadow(&hemostat_sensor_linux::saferead::read_scan_target(std::path::Path::new("/etc/shadow"))?, user)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum How {

    Run(Vec<String>),

    SignalLoginSessions {

        uid: u32,
    },

    PurgeCcaches {

        uid: u32,
    },
}

impl How {

    pub fn describe(&self) -> String {
        match self {
            How::Run(argv) => argv.join(" "),
            How::SignalLoginSessions { uid } => format!(
                "signal every process in uid {uid}'s login sessions, read from /proc \
                 (no logind on this host)"
            ),
            How::PurgeCcaches { uid } => format!(
                "destroy each credential cache belonging to uid {uid} by name, in /tmp and \
                 /run/user/{uid}"
            ),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountPlan {

    pub summary: String,

    pub needs_operator: bool,

    pub how: How,
}

impl AccountPlan {

    pub fn command(&self) -> Option<&[String]> {
        match &self.how {
            How::Run(argv) => Some(argv),
            How::SignalLoginSessions { .. } | How::PurgeCcaches { .. } => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountRefusal {

    pub rule: &'static str,

    pub because: String,
}

pub fn check(
    action: &AccountAction,
    operator_uids: &[u32],
    protect: &ProtectSet,
    session_via: SessionMechanism,
) -> Result<AccountPlan, AccountRefusal> {
    if action.uid() == 0 {
        return Err(AccountRefusal {
            rule: "never-root",
            because: "this would act on uid 0. On a host whose other access is SSH keys nobody \
                      has verified, disabling root is how an engagement ends with nobody able to \
                      log in"
                .into(),
        });
    }
    if operator_uids.contains(&action.uid()) {
        return Err(AccountRefusal {
            rule: "never-the-operator",
            because: format!(
                "{} is the account running this agent — the login it was started from, or the \
                 one that ran sudo, su or doas to start it. A containment that locks the \
                 responder out of a compromised host has not contained anything. If the \
                 adversary holds this account too, run this from a different login",
                action.user()
            ),
        });
    }
    if let Some(reason) = protect.user_reason(action.user()) {
        return Err(AccountRefusal {
            rule: "protect-set",
            because: format!("{}: {}", action.user(), reason.describe()),
        });
    }
    if matches!(action, AccountAction::CredRotate { .. }) && !is_a_human_login(action.uid()) {
        return Err(AccountRefusal {
            rule: "service-account",
            because: format!(
                "uid {} is outside the human login range {FIRST_HUMAN_UID}-{LAST_HUMAN_UID}, so \
                 this is a service account. Expiring its password does not inconvenience an \
                 adversary using it — nobody logs into it — and does break whatever it exists for",
                action.uid()
            ),
        });
    }

    let (summary, how) = match action {
        AccountAction::SessionKill { user, uid } => (
            format!("end every login session belonging to {user}"),
            match session_via {
                SessionMechanism::Loginctl => How::Run(vec![
                    "loginctl".into(),
                    "terminate-user".into(),
                    user.clone(),
                ]),
                SessionMechanism::SignalSessions => How::SignalLoginSessions { uid: *uid },
            },
        ),
        AccountAction::TicketPurge { user, uid } => (
            format!("destroy {user}'s Kerberos credential caches"),
            How::PurgeCcaches { uid: *uid },
        ),
        AccountAction::CredRotate { user, .. } => (
            format!("force {user} to set a new password at next login"),
            How::Run(vec!["passwd".into(), "--expire".into(), user.clone()]),
        ),
        AccountAction::GroupDrop { user, group, .. } => (
            format!("remove {user} from the {group} group"),
            How::Run(vec!["gpasswd".into(), "-d".into(), user.clone(), group.clone()]),
        ),
    };

    Ok(AccountPlan { summary, needs_operator: action.changes_the_account(), how })
}

pub fn undo_for(action: &AccountAction) -> Option<UndoKind> {
    match action {
        AccountAction::SessionKill { .. } | AccountAction::TicketPurge { .. } => None,
        AccountAction::CredRotate { user, previous_last_change, .. } => {
            previous_last_change.as_ref().map(|last_change| UndoKind::RestorePasswordAge {
                user: user.clone(),
                last_change: last_change.clone(),
            })
        }
        AccountAction::GroupDrop { user, group, .. } => Some(UndoKind::RejoinGroup {
            user: user.clone(),
            group: group.clone(),
        }),
    }
}

pub fn apply(
    action: &AccountAction,
    opts: &ApplyOptions,
    operator_uids: &[u32],
    protect: &ProtectSet,
) -> Outcome {
    let plan = match check(action, operator_uids, protect, judge_session_mechanism(logind_is_live()))
    {
        Ok(p) => p,
        Err(r) => {
            return Outcome::Refused(crate::Refusal {
                action: format!("{} on {}", r.rule, action.user()),
                cause: RefuseCause::InvalidTarget(r.rule.to_string()),
                message: r.because,

                suggested_alternative: None,
            });
        }
    };

    if !opts.armed {
        let reversible = undo_for(action).is_some();
        return Outcome::Planned(crate::Plan {
            summary: plan.summary.clone(),
            detail: format!("would: {}", plan.how.describe()),
            undo: match undo_for(action) {
                Some(UndoKind::RejoinGroup { user, group }) => {
                    format!("gpasswd -a {user} {group}")
                }
                Some(UndoKind::RestorePasswordAge { user, last_change }) => {
                    format!("chage -d {last_change} {user}")
                }
                _ => "nothing to reverse — the user recovers by authenticating again".into(),
            },
            reversible,
            prefer_instead: None,
        });
    }

    let done = match &plan.how {
        How::Run(argv) => run(argv).map(|()| plan.summary.clone()),
        How::SignalLoginSessions { uid } => signal_login_sessions(*uid, protect),
        How::PurgeCcaches { uid } => purge_ccaches(*uid),
    };

    match done {
        Ok(did) => Outcome::Applied(UndoRecord {
            did,
            undo: undo_for(action).unwrap_or(UndoKind::Nothing),
            reversible: undo_for(action).is_some(),
        }),
        Err(reason) => Outcome::Failed(Failure { action: plan.summary, reason }),
    }
}

fn signal_login_sessions(uid: u32, protect: &ProtectSet) -> Result<String, String> {
    let procs = read_proc_sessions();
    if procs.is_empty() {
        return Err("could not read /proc, so no session could be identified, let alone ended"
            .to_string());
    }
    let sids = login_session_ids(&procs, uid, &protect.session_pids);
    if sids.is_empty() {

        return Ok(format!("uid {uid} had no login session to end{}", still_running(uid, &sids)));
    }
    let pids = pids_in_sessions(&procs, &sids);

    let mut killed = 0_usize;
    let mut failed: Vec<String> = Vec::new();
    for pid in &pids {

        let rc = unsafe { libc::kill(*pid as libc::pid_t, libc::SIGKILL) };
        if rc == 0 {
            killed += 1;
        } else {
            let e = std::io::Error::last_os_error();
            if e.raw_os_error() != Some(libc::ESRCH) {
                failed.push(format!("{pid} ({e})"));
            }
        }
    }

    let sessions = sids.iter().map(u32::to_string).collect::<Vec<_>>().join(", ");
    if failed.is_empty() {
        let mut out = format!(
            "ended uid {uid}'s login session(s) {sessions}: killed {killed} of {} processes \
             (the rest had already exited)",
            pids.len()
        );
        out.push_str(&still_running(uid, &sids));
        Ok(out)
    } else {

        Err(format!(
            "session {sessions} was only partly ended: killed {killed} of {}, but these \
             refused: {}",
            pids.len(),
            failed.join("; ")
        ))
    }
}

fn still_running(uid: u32, ended: &std::collections::BTreeSet<u32>) -> String {
    survivors_note(uid, ended, &read_proc_sessions(), |pid| {
        std::fs::read(format!("/proc/{pid}/comm"))
            .map_or_else(|_| "?".into(), |c| String::from_utf8_lossy(&c).trim().to_string())
    })
}

pub(crate) fn survivors_note(
    uid: u32,
    ended: &std::collections::BTreeSet<u32>,
    procs: &[ProcSession],
    comm: impl Fn(u32) -> String,
) -> String {
    let (daemons, shared): (Vec<&ProcSession>, Vec<&ProcSession>) = procs
        .iter()
        .filter(|p| p.uid == uid && !ended.contains(&p.sid) && p.pid > 1)
        .partition(|p| p.tty == 0);
    let name = |ps: &[&ProcSession]| {
        ps.iter().map(|p| format!("{} ({})", p.pid, comm(p.pid))).collect::<Vec<_>>().join(", ")
    };
    let mut out = String::new();
    if !daemons.is_empty() {
        out.push_str(&format!(
            " — NOTE: uid {uid} still has {} process(es) running outside any login session, \
             which this did NOT touch: {}. They hold no terminal, so they are daemons rather \
             than logins — a user-level service manager among them can still start things \
             without anyone logging in. Contain those with a kill if they should not be there",
            daemons.len(),
            name(&daemons)
        ));
    }
    if !shared.is_empty() {
        out.push_str(&format!(
            " — NOTE: uid {uid} also holds a terminal in {} process(es) this did NOT touch: {}. \
             They sit in a session shared with another login or with the one this agent was \
             started from — a `sudo -u` or `su` shell inside somebody else's terminal — and \
             ending that session would end that login too. Contain those with a kill if they \
             should not be there",
            shared.len(),
            name(&shared)
        ));
    }
    out
}

pub fn ccaches_for(names: &[String], uid: u32) -> Vec<String> {
    let exact = format!("krb5cc_{uid}");
    let member = format!("krb5cc_{uid}_");
    names
        .iter()
        .filter(|n| **n == exact || n.starts_with(&member))
        .cloned()
        .collect()
}

fn ccache_dirs(uid: u32) -> [std::path::PathBuf; 2] {
    [std::path::PathBuf::from("/tmp"), std::path::PathBuf::from(format!("/run/user/{uid}"))]
}

fn purge_ccaches(uid: u32) -> Result<String, String> {
    let kdestroy = ["/usr/bin/kdestroy", "/bin/kdestroy"]
        .iter()
        .map(std::path::PathBuf::from)
        .find(|p| p.exists());

    let mut destroyed: Vec<String> = Vec::new();
    let mut failed: Vec<String> = Vec::new();
    let mut unreadable: Vec<String> = Vec::new();

    for dir in ccache_dirs(uid) {
        let names: Vec<String> = match std::fs::read_dir(&dir) {
            Ok(entries) => entries
                .flatten()
                .filter_map(|e| e.file_name().to_str().map(str::to_string))
                .collect(),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => {
                unreadable.push(format!("{} ({e})", dir.display()));
                continue;
            }
        };
        for name in ccaches_for(&names, uid) {
            let path = dir.join(&name);

            let done = match &kdestroy {
                Some(k) => run(&[
                    k.display().to_string(),
                    "-c".into(),
                    format!("FILE:{}", path.display()),
                ]),
                None => std::fs::remove_file(&path)
                    .map_err(|e| format!("could not unlink {}: {e}", path.display())),
            };
            match done {
                Ok(()) => destroyed.push(path.display().to_string()),
                Err(reason) => failed.push(reason),
            }
        }
    }

    let invisible = concat!(
        "KEYRING and KCM caches keep no file, so they cannot be enumerated from here and were ",
        "not touched — if this realm uses one, the ticket is still live for the rest of its ",
        "lifetime"
    );

    if !failed.is_empty() {
        return Err(format!(
            "{} of uid {uid}'s credential cache(s) could not be destroyed: {}. {invisible}",
            failed.len(),
            failed.join("; ")
        ));
    }
    let mut out = if destroyed.is_empty() {
        format!("uid {uid} had no credential cache on disk")
    } else {
        format!(
            "destroyed {} credential cache(s) belonging to uid {uid}: {}",
            destroyed.len(),
            destroyed.join(", ")
        )
    };
    if !unreadable.is_empty() {
        out.push_str(&format!(
            " — but {} could not be read, so this is a PARTIAL result",
            unreadable.join(", ")
        ));
    }
    out.push_str(" — ");
    out.push_str(invisible);
    Ok(out)
}

fn run(argv: &[String]) -> Result<(), String> {
    let Some(name) = argv.first() else {
        return Err("no command".into());
    };
    let exe = ["/usr/bin", "/usr/sbin", "/bin", "/sbin"]
        .iter()
        .map(|d| std::path::PathBuf::from(d).join(name))
        .find(|p| p.exists())
        .ok_or_else(|| {
            format!(
                "{name} was not found in /usr/bin, /usr/sbin, /bin or /sbin. It is deliberately \
                 not looked for on $PATH: a planted one that exits 0 would have this report a \
                 change it never made"
            )
        })?;

    let out = std::process::Command::new(&exe)
        .args(argv.get(1..).unwrap_or_default())
        .env_clear()
        .env("LC_ALL", "C")
        .output()
        .map_err(|e| format!("could not run {}: {e}", exe.display()))?;

    if out.status.success() {
        Ok(())
    } else {
        let err = String::from_utf8_lossy(&out.stderr);
        Err(format!(
            "{} exited {}: {}",
            exe.display(),
            out.status.code().unwrap_or(-1),
            if err.trim().is_empty() { "no stderr" } else { err.trim() }
        ))
    }
}

pub fn operator_uids() -> Vec<u32> {
    operator_uids_from(
        std::fs::read_to_string("/proc/self/loginuid").ok().as_deref(),
        &std::fs::read_to_string("/proc/self/cgroup").unwrap_or_default(),
        &std::fs::read_to_string("/proc/self/status").unwrap_or_default(),
        |k| std::env::var(k).ok(),
        uid_of,
    )
}

pub(crate) fn operator_uids_from(
    loginuid: Option<&str>,
    cgroup: &str,
    status: &str,
    var: impl Fn(&str) -> Option<String>,
    uid_of: impl Fn(&str) -> Option<u32>,
) -> Vec<u32> {
    let mut out = std::collections::BTreeSet::new();

    out.extend(loginuid.and_then(|t| t.trim().parse::<u32>().ok()).filter(|u| *u != u32::MAX));
    out.extend(login_slice_uid(cgroup));
    for k in ["SUDO_UID", "PKEXEC_UID"] {
        out.extend(var(k).and_then(|v| v.parse::<u32>().ok()));
    }
    out.extend(var("DOAS_USER").and_then(|u| uid_of(&u)));
    out.extend(status.lines().find_map(|l| {
        l.strip_prefix("Uid:").and_then(|v| v.split_whitespace().next()?.parse::<u32>().ok())
    }));
    out.into_iter().collect()
}

pub(crate) fn login_slice_uid(cgroup: &str) -> Option<u32> {
    cgroup.lines().find_map(|line| {
        line.splitn(3, ':').nth(2)?.split('/').find_map(|c| {
            c.strip_prefix("user-")?.strip_suffix(".slice")?.parse().ok()
        })
    })
}
