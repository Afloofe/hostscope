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

    Lock {

        user: String,

        uid: u32,

        prior_shell: Option<String>,

        prior_locked: Option<bool>,
    },
}

impl AccountAction {

    pub fn user(&self) -> &str {
        match self {
            AccountAction::SessionKill { user, .. }
            | AccountAction::TicketPurge { user, .. }
            | AccountAction::CredRotate { user, .. }
            | AccountAction::GroupDrop { user, .. }
            | AccountAction::Lock { user, .. } => user,
        }
    }

    pub const fn uid(&self) -> u32 {
        match self {
            AccountAction::SessionKill { uid, .. }
            | AccountAction::TicketPurge { uid, .. }
            | AccountAction::CredRotate { uid, .. }
            | AccountAction::GroupDrop { uid, .. }
            | AccountAction::Lock { uid, .. } => *uid,
        }
    }

    pub const fn changes_the_account(&self) -> bool {
        matches!(
            self,
            AccountAction::CredRotate { .. } | AccountAction::GroupDrop { .. } | AccountAction::Lock { .. }
        )
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

pub fn name_in_passwd(text: &str, uid: u32) -> Option<String> {
    id_name(text, uid)
}

pub fn name_in_group(text: &str, gid: u32) -> Option<String> {
    id_name(text, gid)
}

fn id_name(text: &str, id: u32) -> Option<String> {
    text.lines().find_map(|l| {
        let mut f = l.split(':');
        let name = f.next()?;
        let _pw = f.next()?;
        let n = f.next()?.parse::<u32>().ok()?;
        (n == id && !name.is_empty()).then(|| name.to_string())
    })
}

pub fn name_of_uid(uid: u32) -> Option<String> {
    name_in_passwd(&hemostat_sensor_linux::saferead::read_scan_target(std::path::Path::new("/etc/passwd"))?, uid)
}

pub fn name_of_gid(gid: u32) -> Option<String> {
    name_in_group(&hemostat_sensor_linux::saferead::read_scan_target(std::path::Path::new("/etc/group"))?, gid)
}

pub(crate) fn status_uids(status: &str) -> Option<(u32, u32)> {
    let mut v = status.lines().find_map(|l| l.strip_prefix("Uid:"))?.split_whitespace();
    let real = v.next()?.parse().ok()?;
    let effective = v.next()?.parse().ok()?;
    Some((real, effective))
}

pub(crate) fn login_uid(text: &str) -> Option<u32> {
    text.trim().parse::<u32>().ok().filter(|u| *u != u32::MAX)
}

pub(crate) fn owner_names(passwd: &str, uids: &[u32]) -> Result<Vec<String>, u32> {
    let mut out: Vec<String> = Vec::new();
    for &uid in uids {
        let name = name_in_passwd(passwd, uid).ok_or(uid)?;
        if !out.contains(&name) {
            out.push(name);
        }
    }
    Ok(out)
}

pub(crate) fn owners_of(pid: u32) -> Result<Vec<String>, String> {
    use hemostat_sensor_linux::saferead::{read_proc, read_scan_target, MAX_PROC_BYTES};
    let (status, _) = read_proc(std::path::Path::new(&format!("/proc/{pid}/status")), MAX_PROC_BYTES)
        .map_err(|e| format!("/proc/{pid}/status could not be read ({e})"))?;
    let (real, effective) = status_uids(&String::from_utf8_lossy(&status))
        .ok_or_else(|| format!("/proc/{pid}/status names no uid"))?;
    let login = read_proc(std::path::Path::new(&format!("/proc/{pid}/loginuid")), 64)
        .ok()
        .and_then(|(b, _)| login_uid(&String::from_utf8_lossy(&b)));
    let passwd = read_scan_target(std::path::Path::new("/etc/passwd"))
        .ok_or_else(|| "/etc/passwd could not be read".to_string())?;
    let mut uids = vec![real, effective];
    uids.extend(login);
    owner_names(&passwd, &uids).map_err(|uid| format!("uid {uid} has no entry in /etc/passwd"))
}

pub fn read_shell(user: &str) -> Option<String> {
    shell_in_passwd(
        &hemostat_sensor_linux::saferead::read_scan_target(std::path::Path::new("/etc/passwd"))?,
        user,
    )
}

pub(crate) fn shell_in_passwd(text: &str, user: &str) -> Option<String> {
    text.lines().find_map(|l| {
        let mut f = l.split(':');
        if f.next()? != user {
            return None;
        }

        f.nth(5).map(str::to_string)
    })
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

pub fn password_locked_in_shadow(text: &str, user: &str) -> Option<bool> {
    text.lines().find_map(|l| {
        let mut f = l.split(':');
        let name = f.next()?;
        let hash = f.next()?;
        (name == user).then(|| hash.starts_with('!'))
    })
}

pub fn read_password_locked(user: &str) -> Option<bool> {
    password_locked_in_shadow(
        &hemostat_sensor_linux::saferead::read_scan_target(std::path::Path::new("/etc/shadow"))?,
        user,
    )
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

    if hs_core::accounts::is_hard_protected(action.user()) {
        return Err(AccountRefusal {
            rule: "out-of-scope-account",
            because: format!(
                "{}: {}",
                action.user(),
                crate::ProtectReason::OutOfScopeAccount.describe()
            ),
        });
    }
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
    if matches!(action, AccountAction::CredRotate { .. } | AccountAction::Lock { .. }) && !is_a_human_login(action.uid()) {
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
        AccountAction::Lock { user, .. } => (
            format!("lock the login {user}: disable its password and set its shell to nologin"),
            How::Run(vec![
                "usermod".into(),
                "-L".into(),
                "-s".into(),
                "/usr/sbin/nologin".into(),
                user.clone(),
            ]),
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
        AccountAction::Lock { user, prior_shell, prior_locked, .. } => Some(UndoKind::UnlockAccount {
            user: user.clone(),
            shell: prior_shell.clone(),
            was_locked: *prior_locked,
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

    if let AccountAction::SessionKill { uid, .. } = action {
        let procs = read_proc_sessions();
        let mut ended =
            pids_in_sessions(&procs, &login_session_ids(&procs, *uid, &protect.session_pids));
        if matches!(plan.how, How::Run(_)) {
            let cgroups: Vec<(u32, String)> = procs
                .iter()
                .map(|p| {
                    let cg = hemostat_sensor_linux::saferead::read_scan_target(std::path::Path::new(
                        &format!("/proc/{}/cgroup", p.pid),
                    ));
                    (p.pid, cg.unwrap_or_default())
                })
                .collect();
            ended.extend(pids_in_user_slice(&cgroups, *uid));
            ended.sort_unstable();
            ended.dedup();
        }
        let passwd =
            hemostat_sensor_linux::saferead::read_scan_target(std::path::Path::new("/etc/passwd"));
        let held = passwd.as_deref().map(|text| protected_among(&procs, &ended, text, protect));
        let why = match held {
            None => Some("/etc/passwd could not be read, so who else is running in its sessions \
                          cannot be told"
                .to_string()),
            Some(Some((pid, name))) => Some(format!(
                "pid {pid} in its login session belongs to `{name}`, and {}",
                protect.user_reason(&name).map_or("", |r| r.describe())
            )),
            Some(None) => None,
        };
        if let Some(why) = why {
            return Outcome::Refused(crate::Refusal {
                action: format!("end the sessions of {}", action.user()),
                cause: RefuseCause::InvalidTarget("a protected account runs in the session".into()),
                message: format!(
                    "refused to end {}'s sessions: {why}. Ending a session ends everyone in it; \
                     end it by hand once that is dealt with",
                    action.user()
                ),
                suggested_alternative: None,
            });
        }
    }

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
                Some(UndoKind::UnlockAccount { user, shell, was_locked }) => {
                    let set_shell = match shell.as_deref() {
                        Some(s) if !s.is_empty() => format!(" -s {s}"),
                        _ => String::new(),
                    };
                    match was_locked {
                        Some(false) => format!("usermod -U{set_shell} {user}"),

                        Some(true) if set_shell.is_empty() => format!(
                            "nothing: {user}'s password was locked before this lock, so it stays locked"
                        ),
                        Some(true) => format!(
                            "usermod{set_shell} {user} — its password was locked before this lock, \
                             so it stays locked"
                        ),
                        None => format!(
                            "usermod{set_shell} {user}, leaving its password locked: whether it was \
                             locked before could not be read. `usermod -U {user}` by hand if it \
                             should log in"
                        ),
                    }
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

pub(crate) fn protected_among(
    procs: &[ProcSession],
    pids: &[u32],
    passwd: &str,
    protect: &ProtectSet,
) -> Option<(u32, String)> {
    pids.iter().find_map(|&pid| {
        let p = procs.iter().find(|p| p.pid == pid)?;
        let name = name_in_passwd(passwd, p.uid)?;
        protect.user_reason(&name).map(|_| (pid, name))
    })
}

pub(crate) fn pids_in_user_slice(cgroups: &[(u32, String)], uid: u32) -> Vec<u32> {
    let mut out: Vec<u32> = cgroups
        .iter()
        .filter(|(pid, cg)| *pid > 1 && login_slice_uid(cg) == Some(uid))
        .map(|(pid, _)| *pid)
        .collect();
    out.sort_unstable();
    out
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SudoersScope {

    Protected(String),

    Unresolved(String),
}

impl SudoersScope {

    pub fn describe(&self) -> String {
        match self {
            SudoersScope::Protected(name) => format!(
                "the line is `{name}`'s, and {}",
                crate::ProtectReason::OutOfScopeAccount.describe()
            ),
            SudoersScope::Unresolved(token) => format!(
                "the line names `{token}`, which this cannot resolve to an account — an alias \
                 defined in another sudoers file, a netgroup, or an id with no entry — so it \
                 cannot be shown not to be the white team's or the DataDog agent's. Read it \
                 and edit it by hand with visudo"
            ),
        }
    }
}

const MAX_ALIAS_DEPTH: usize = 8;

pub fn sudoers_scope(
    line: &str,
    file: &str,
    uid_name: &dyn Fn(u32) -> Option<String>,
    gid_name: &dyn Fn(u32) -> Option<String>,
) -> Option<SudoersScope> {
    let body = sudoers_code(line).trim();
    let lists: Vec<String> = if let Some(rest) = body.strip_prefix("Defaults") {

        vec![leading_list(rest.strip_prefix(':')?)]
    } else if let Some(defs) = keyword(body, "User_Alias") {
        alias_definitions(defs).into_iter().map(|(_, members)| members.to_string()).collect()
    } else if ["Runas_Alias", "Host_Alias", "Cmnd_Alias", "Cmd_Alias"]
        .iter()
        .any(|k| keyword(body, k).is_some())
        || body.starts_with('@')
        || body.is_empty()
    {
        return None;
    } else {
        vec![leading_list(body)]
    };
    let aliases = user_aliases(file);
    let mut unresolved: Option<String> = None;
    for list in &lists {
        if let Some(name) = protected_in(list, &aliases, uid_name, gid_name, 0, &mut unresolved) {
            return Some(SudoersScope::Protected(name));
        }
    }
    unresolved.map(SudoersScope::Unresolved)
}

fn protected_in(
    list: &str,
    aliases: &std::collections::BTreeMap<String, String>,
    uid_name: &dyn Fn(u32) -> Option<String>,
    gid_name: &dyn Fn(u32) -> Option<String>,
    depth: usize,
    unresolved: &mut Option<String>,
) -> Option<String> {
    fn note(slot: &mut Option<String>, t: &str) {
        slot.get_or_insert_with(|| t.to_string());
    }
    for raw in list.split(',') {

        let t = raw.trim().trim_start_matches(|c: char| c == '!' || c.is_whitespace());
        let t = t.trim_matches('"');
        if t.is_empty() || t == "ALL" {
            continue;
        }
        let name = if let Some(g) = t.strip_prefix("%:") {
            if g.starts_with('#') {
                note(unresolved, t);
                continue;
            }
            g.to_string()
        } else if let Some(gid) = t.strip_prefix("%#") {
            match gid.parse::<u32>().ok().and_then(gid_name) {
                Some(g) => g,
                None => {
                    note(unresolved, t);
                    continue;
                }
            }
        } else if let Some(g) = t.strip_prefix('%') {
            g.to_string()
        } else if let Some(uid) = t.strip_prefix('#') {
            match uid.parse::<u32>().ok().and_then(uid_name) {
                Some(u) => u,
                None => {
                    note(unresolved, t);
                    continue;
                }
            }
        } else if t.starts_with('+') {
            note(unresolved, t);
            continue;
        } else if is_alias_name(t) {
            match aliases.get(t) {
                Some(members) if depth < MAX_ALIAS_DEPTH => {
                    if let Some(p) = protected_in(members, aliases, uid_name, gid_name, depth + 1, unresolved) {
                        return Some(p);
                    }
                    continue;
                }
                _ => {
                    note(unresolved, t);
                    continue;
                }
            }
        } else {
            t.to_string()
        };
        if hs_core::accounts::is_hard_protected(&name) {
            return Some(name);
        }
    }
    None
}

fn sudoers_code(line: &str) -> &str {
    let b = line.as_bytes();
    for (i, c) in line.char_indices() {
        if c == '#' && !b.get(i + 1).is_some_and(u8::is_ascii_digit) {
            return line.get(..i).unwrap_or_default();
        }
    }
    line
}

fn keyword<'a>(body: &'a str, word: &str) -> Option<&'a str> {
    body.strip_prefix(word).filter(|rest| rest.starts_with(char::is_whitespace))
}

fn leading_list(s: &str) -> String {
    let mut out = String::new();
    let mut blank = false;
    for c in s.trim_start().chars() {
        if c.is_whitespace() {
            blank = true;
            continue;
        }
        if blank && c != ',' && !out.ends_with(',') {
            break;
        }
        blank = false;
        out.push(c);
    }
    out
}

fn is_alias_name(t: &str) -> bool {
    let mut c = t.chars();
    c.next().is_some_and(|f| f.is_ascii_uppercase())
        && c.all(|x| x.is_ascii_uppercase() || x.is_ascii_digit() || x == '_')
}

fn alias_definitions(defs: &str) -> Vec<(&str, &str)> {
    let mut parts = Vec::new();
    let mut start = 0;
    let b = defs.as_bytes();
    for (i, c) in defs.char_indices() {
        if c == ':' && (i == 0 || b.get(i - 1) != Some(&b'%')) {
            parts.push(defs.get(start..i).unwrap_or_default());
            start = i + 1;
        }
    }
    parts.push(defs.get(start..).unwrap_or_default());
    parts
        .into_iter()
        .filter_map(|p| p.split_once('='))
        .map(|(n, m)| (n.trim(), m.trim()))
        .collect()
}

fn user_aliases(file: &str) -> std::collections::BTreeMap<String, String> {
    let mut out = std::collections::BTreeMap::new();
    let mut logical = String::new();
    for raw in file.lines() {
        let code = sudoers_code(raw).trim_end();
        let (part, continued) = match code.strip_suffix('\\') {
            Some(p) => (p, true),
            None => (code, false),
        };
        logical.push_str(part);
        logical.push(' ');
        if continued {
            continue;
        }
        let line = std::mem::take(&mut logical);
        if let Some(defs) = keyword(line.trim(), "User_Alias") {
            for (name, members) in alias_definitions(defs) {
                out.insert(name.to_string(), members.to_string());
            }
        }
    }
    out
}
