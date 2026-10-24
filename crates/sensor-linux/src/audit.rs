use std::fs;
use std::path::Path;

use crate::triage::{rank, Finding, Severity};

const NETLINK_AUDIT: i32 = 9;

const AUDIT_GET: u16 = 1000;

const NLMSG_ERROR: u16 = 2;

const AUDIT_LIST_RULES: u16 = 1013;

const NLMSG_DONE: u16 = 3;

const RULE_DATA_LEN: usize = 4 * (3 + 64 * 4 + 1);

const MAX_LISTED_RULES: usize = 65_536;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Status {

    pub enabled: u32,

    pub failure: u32,

    pub pid: u32,

    pub rate_limit: u32,

    pub backlog_limit: u32,

    pub lost: u32,

    pub backlog: u32,
}

impl Status {

    pub const fn immutable(&self) -> bool {
        self.enabled == 2
    }

    pub const fn has_a_collector(&self) -> bool {
        self.pid != 0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StatusError {

    NoSocket(String),

    Refused(String),

    Malformed(String),
}

impl StatusError {

    pub fn message(&self) -> String {
        match self {
            StatusError::NoSocket(e) => format!(
                "the audit netlink socket could not be opened ({e}). On a kernel built without \
                 CONFIG_AUDIT there is nothing to ask; otherwise this needs root or \
                 CAP_AUDIT_CONTROL. Either way the audit posture below is UNKNOWN, not clean"
            ),
            StatusError::Refused(e) => format!(
                "the kernel refused the audit request ({e}). This needs CAP_AUDIT_CONTROL in \
                 the initial pid namespace, which root has and a container usually does not. \
                 The audit posture is UNKNOWN, not clean"
            ),
            StatusError::Malformed(e) => format!(
                "the kernel's audit status reply could not be read ({e}). Nothing about the \
                 audit posture has been established"
            ),
        }
    }
}

pub fn status() -> Result<Status, StatusError> {
    let fd = request(AUDIT_GET)?;
    let mut buf = [0_u8; 1024];
    let n = fd.recv(&mut buf)?;
    parse_status_reply(buf.get(..n).unwrap_or_default())
}

struct Request(i32);

impl Drop for Request {
    fn drop(&mut self) {

        unsafe { libc::close(self.0) };
    }
}

impl Request {

    fn recv(&self, buf: &mut [u8]) -> Result<usize, StatusError> {

        let n = unsafe { libc::recv(self.0, buf.as_mut_ptr().cast::<libc::c_void>(), buf.len(), 0) };
        if n < 0 {
            return Err(StatusError::Refused(std::io::Error::last_os_error().to_string()));
        }
        Ok(usize::try_from(n).unwrap_or(0))
    }
}

fn request(kind: u16) -> Result<Request, StatusError> {

    let fd = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW | libc::SOCK_CLOEXEC, NETLINK_AUDIT) };
    if fd < 0 {
        return Err(StatusError::NoSocket(std::io::Error::last_os_error().to_string()));
    }
    let fd = Request(fd);

    let mut req = [0_u8; 16];
    req[0..4].copy_from_slice(&16_u32.to_ne_bytes());
    req[4..6].copy_from_slice(&kind.to_ne_bytes());
    req[6..8].copy_from_slice(&(libc::NLM_F_REQUEST as u16).to_ne_bytes());
    req[8..12].copy_from_slice(&1_u32.to_ne_bytes());
    req[12..16].copy_from_slice(&0_u32.to_ne_bytes());

    let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    addr.nl_family = u16::try_from(libc::AF_NETLINK).unwrap_or(16);

    let sent = unsafe {
        libc::sendto(
            fd.0,
            req.as_ptr().cast::<libc::c_void>(),
            req.len(),
            0,
            std::ptr::addr_of!(addr).cast::<libc::sockaddr>(),
            u32::try_from(std::mem::size_of::<libc::sockaddr_nl>()).unwrap_or(12),
        )
    };
    if sent < 0 {
        return Err(StatusError::Refused(std::io::Error::last_os_error().to_string()));
    }

    let tv = libc::timeval { tv_sec: 3, tv_usec: 0 };

    unsafe {
        libc::setsockopt(
            fd.0,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            std::ptr::addr_of!(tv).cast::<libc::c_void>(),
            u32::try_from(std::mem::size_of::<libc::timeval>()).unwrap_or(16),
        );
    }
    Ok(fd)
}

pub fn loaded_rules() -> Result<usize, StatusError> {
    let fd = request(AUDIT_LIST_RULES)?;

    let mut buf = vec![0_u8; 64 * 1024];
    let mut count = 0;
    while count <= MAX_LISTED_RULES {
        let n = fd.recv(&mut buf)?;
        if parse_rule_list(buf.get(..n).unwrap_or_default(), &mut count)? {
            return Ok(count);
        }
    }
    Err(StatusError::Malformed(format!(
        "the kernel listed more than {MAX_LISTED_RULES} rules without ending the list"
    )))
}

fn parse_rule_list(buf: &[u8], count: &mut usize) -> Result<bool, StatusError> {
    let bytes = |o: usize| -> Option<[u8; 4]> { buf.get(o..o.checked_add(4)?)?.try_into().ok() };
    let mut off = 0_usize;
    while off < buf.len() {
        let len = bytes(off).map(u32::from_ne_bytes).and_then(|l| usize::try_from(l).ok());
        let end = len.and_then(|l| off.checked_add(l).filter(|e| l >= 16 && *e <= buf.len()));
        let (Some(len), Some(end)) = (len, end) else {
            return Err(StatusError::Malformed(format!(
                "a rule-list message at offset {off} of {} does not fit its datagram",
                buf.len()
            )));
        };
        let kind = bytes(off + 4).map_or(0, |b| u16::from_ne_bytes([b[0], b[1]]));
        match kind {
            NLMSG_DONE => return Ok(true),
            NLMSG_ERROR => {
                let errno = bytes(off + 16).map_or(0, i32::from_ne_bytes);
                if errno != 0 {
                    let e = std::io::Error::from_raw_os_error(errno.wrapping_neg());
                    return Err(StatusError::Refused(e.to_string()));
                }
            }
            AUDIT_LIST_RULES => {
                if len - 16 < RULE_DATA_LEN {
                    return Err(StatusError::Malformed(format!(
                        "a rule of {} bytes, short of the {RULE_DATA_LEN} every rule carries",
                        len - 16
                    )));
                }
                *count += 1;
            }
            _ => {}
        }

        off = end.checked_add(3).map_or(buf.len(), |e| e & !3);
    }
    Ok(false)
}

pub fn parse_status_reply(buf: &[u8]) -> Result<Status, StatusError> {
    if buf.len() < 16 {
        return Err(StatusError::Malformed(format!("{} bytes, less than a header", buf.len())));
    }
    let kind = u16::from_ne_bytes([buf[4], buf[5]]);
    if kind == NLMSG_ERROR {

        let errno = if buf.len() >= 20 {
            i32::from_ne_bytes([buf[16], buf[17], buf[18], buf[19]])
        } else {
            0
        };
        if errno == 0 {

            return Err(StatusError::Malformed(
                "the kernel acknowledged the request without returning a status".into(),
            ));
        }
        let e = std::io::Error::from_raw_os_error(-errno);
        return Err(StatusError::Refused(e.to_string()));
    }
    let payload = buf.get(16..).unwrap_or_default();
    if payload.len() < 32 {
        return Err(StatusError::Malformed(format!(
            "the status payload is {} bytes, short of the 32 this reads",
            payload.len()
        )));
    }
    let word = |i: usize| {
        let o = i * 4;
        u32::from_ne_bytes([payload[o], payload[o + 1], payload[o + 2], payload[o + 3]])
    };

    Ok(Status {
        enabled: word(1),
        failure: word(2),
        pid: word(3),
        rate_limit: word(4),
        backlog_limit: word(5),
        lost: word(6),
        backlog: word(7),
    })
}

pub const RULE_DIRS: &[&str] = &["/etc/audit/rules.d"];

pub const RULE_FILE: &str = "/etc/audit/audit.rules";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {

    pub line: String,

    pub key: Option<String>,
}

pub fn parse_rules(text: &str) -> Vec<Rule> {
    let mut out = Vec::new();
    for raw in text.lines() {
        let line = raw.trim();
        if !matches!(line.split_whitespace().next(), Some("-a" | "-A" | "-w")) {
            continue;
        }
        let mut key = None;
        let toks: Vec<&str> = line.split_whitespace().collect();
        for (i, t) in toks.iter().enumerate() {
            if *t == "-k" || *t == "--key" {
                key = toks.get(i + 1).map(|k| (*k).to_string());
            } else if let Some(k) = t.strip_prefix("key=") {
                key = Some(k.to_string());
            }
        }
        out.push(Rule { line: line.to_string(), key });
    }
    out
}

pub const WANTED: &[(&str, &str, &str)] = &[
    (
        "/etc/passwd",
        "account changes",
        "who added the account, and when. Without it the account's existence is all you have",
    ),
    (
        "/etc/shadow",
        "credential changes",
        "whether a password was set rather than the account merely created",
    ),
    (
        "/etc/sudoers",
        "privilege grants",
        "who granted the sudo rule you are looking at",
    ),
    (
        "/var/log/audit",
        "audit log tampering",
        "whether the log you are reading has been edited",
    ),
    (
        "execve",
        "command execution",
        "what was run. This is the rule whose absence is felt most: without it an incident is \
         reconstructed from artefacts rather than from actions",
    ),
    (
        "init_module",
        "kernel module loads",
        "whether a rootkit LKM was loaded, and by whom",
    ),
];

pub fn uncovered(rules: &[Rule]) -> Vec<(&'static str, &'static str, &'static str)> {
    WANTED
        .iter()
        .filter(|(needle, _, _)| {
            !rules.iter().any(|r| !suppresses(r) && r.line.contains(needle))
        })
        .copied()
        .collect()
}

fn suppresses(r: &Rule) -> bool {
    let mut t = r.line.split_whitespace();
    matches!(t.next(), Some("-a" | "-A"))
        && t.next().is_some_and(|actions| actions.split(',').any(|a| a == "never"))
}

fn merge_rules(into: &mut Vec<Rule>, text: &str) {
    for r in parse_rules(text) {
        if !into.iter().any(|have| have.line == r.line) {
            into.push(r);
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct Report {

    pub findings: Vec<Finding>,

    pub status: Option<Status>,

    pub status_error: Option<String>,

    pub rules: Vec<Rule>,

    pub loaded: Option<usize>,

    pub unreadable: Vec<String>,
}

impl Report {

    pub const fn complete(&self) -> bool {
        self.status.is_some()
    }
}

fn read_rules(rep: &mut Report) {
    let mut texts: Vec<String> = Vec::new();
    for dir in RULE_DIRS {
        match fs::read_dir(dir) {
            Ok(entries) => {
                let mut files: Vec<_> = entries
                    .flatten()
                    .map(|e| e.path())
                    .filter(|p| p.extension().is_some_and(|x| x == "rules"))
                    .collect();
                files.sort();
                for f in files {
                    match crate::saferead::read_text(&f) {
                        Ok(t) => texts.push(t),
                        Err(e) => rep.unreadable.push(format!("{} ({e})", f.display())),
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => rep.unreadable.push(format!("{dir} ({e})")),
        }
    }
    if Path::new(RULE_FILE).is_file() {
        match crate::saferead::read_text(Path::new(RULE_FILE)) {
            Ok(t) => texts.push(t),
            Err(e) => rep.unreadable.push(format!("{RULE_FILE} ({e})")),
        }
    }
    for t in &texts {
        merge_rules(&mut rep.rules, t);
    }
}

pub fn report() -> Report {
    let mut rep = Report::default();
    read_rules(&mut rep);

    match status() {
        Ok(s) => {
            rep.status = Some(s);
            match loaded_rules() {
                Ok(n) => rep.loaded = Some(n),
                Err(e) => rep.findings.push(Finding::flag(
                    Severity::Warn,
                    "audit",
                    "loaded rules UNKNOWN",
                    "the kernel would not list the rules it holds",
                    format!(
                        "{} The coverage below is read from the files, which say what the host \
                         is meant to record — not what the kernel is recording",
                        e.message()
                    ),
                )),
            }

            let held: &[Rule] = if rep.loaded == Some(0) { &[] } else { &rep.rules };
            rep.findings.extend(judge(&s, held));
            rep.findings.extend(judge_loaded(&s, rep.loaded, rep.rules.len()));
        }
        Err(e) => {
            rep.status_error = Some(e.message());
            rep.findings.push(Finding::flag(
                Severity::Warn,
                "audit",
                "status UNKNOWN",
                "the kernel's audit state could not be read",
                e.message(),
            ));
        }
    }

    if !rep.unreadable.is_empty() {
        rep.findings.push(Finding::flag(
            Severity::Warn,
            "audit",
            format!("{} rule file(s) unreadable", rep.unreadable.len()),
            "part of the audit configuration could not be read",
            format!(
                "the coverage below is computed from the rules that COULD be read, so it \
                 overstates what is missing: {}",
                rep.unreadable.join(", ")
            ),
        ));
    }

    rank(&mut rep.findings);
    rep
}

pub fn judge_loaded(s: &Status, loaded: Option<usize>, on_disk: usize) -> Vec<Finding> {
    let Some(held) = loaded else { return Vec::new() };
    if s.enabled == 0 || held >= on_disk {
        return Vec::new();
    }
    if held == 0 {
        return vec![Finding::flag(
            Severity::Critical,
            "audit",
            "loaded=0",
            format!("the kernel holds NO audit rules, while the files define {on_disk}"),
            "the files in /etc/audit say what this host records, and the kernel is recording \
             none of it. `auditctl -D` does exactly this in one command and leaves the files \
             untouched, which is why it is an intruder's first move. The coverage notes here \
             are the kernel's, not the files'",
        )];
    }
    vec![Finding::flag(
        Severity::Warn,
        "audit",
        format!("loaded={held}"),
        format!("the kernel holds {held} audit rule(s), while the files define {on_disk}"),
        "some of what the files say is audited is not loaded — removed at runtime (`auditctl \
         -d`), or never loaded because it failed to. The coverage notes here are read from the \
         files and so overstate what is recorded; `auditctl -l` lists what is",
    )]
}

pub fn judge(s: &Status, rules: &[Rule]) -> Vec<Finding> {
    let mut f = Vec::new();

    if s.enabled == 0 {
        f.push(Finding::flag(
            Severity::Critical,
            "audit",
            "enabled=0",
            "the kernel audit subsystem is switched off",
            "no audit records are being generated at all. Anything in /var/log/audit predates \
             this being turned off, and nothing has been recorded since. `auditctl -e 1` turns \
             it back on, and the fact that it was off is itself worth explaining",
        ));
    } else if !s.immutable() {
        f.push(Finding::flag(
            Severity::Note,
            "audit",
            "enabled=1 (not locked)",
            "auditing is on, and the rules can still be removed without a reboot",
            "`-e 2` locks the rule set until the next boot. Without it, `auditctl -D` removes \
             every rule in one command, leaves the files in /etc/audit/rules.d untouched, and \
             the host looks configured while recording nothing",
        ));
    }

    if s.enabled != 0 && !s.has_a_collector() {
        f.push(Finding::flag(
            Severity::Critical,
            "audit",
            "pid=0",
            "records are being generated and NOTHING is collecting them",
            "the kernel has no registered audit daemon. The unit may well show as active — a \
             daemon that has deregistered, been killed, or was started in a namespace leaves \
             exactly this state. Every record produced since is gone",
        ));
    }

    if s.lost > 0 {
        f.push(Finding::flag(
            if s.lost > 1000 { Severity::Critical } else { Severity::Warn },
            "audit",
            format!("lost={}", s.lost),
            format!("the kernel has dropped {} audit record(s)", s.lost),
            "the audit log has holes in it, and they are where the host was busiest — which \
             during an intrusion is when it mattered. Treat an absence of events in this log as \
             unproven rather than as evidence of absence. A larger backlog_limit is the fix \
             before the next incident; for this one, the gap is already in the record",
        ));
    }
    if s.backlog_limit > 0 && s.backlog * 2 > s.backlog_limit {
        f.push(Finding::flag(
            Severity::Warn,
            "audit",
            format!("backlog={}/{}", s.backlog, s.backlog_limit),
            "the audit queue is more than half full",
            "records are being produced faster than they are collected. When it fills, the \
             kernel starts losing them, and the loss is silent unless somebody reads the lost \
             counter",
        ));
    }
    if s.failure == 0 && s.enabled != 0 {
        f.push(Finding::flag(
            Severity::Note,
            "audit",
            "failure=0",
            "the kernel stays silent when it cannot deliver a record",
            "failure mode 0 means a delivery failure produces nothing at all — not even a \
             kernel message. Mode 1 at least leaves a trace in dmesg that the audit trail \
             broke",
        ));
    }

    if s.enabled != 0 {
        for (needle, what, why) in uncovered(rules) {
            f.push(Finding::flag(
                Severity::Note,
                "audit",
                format!("no rule for {needle}"),
                format!("{what} are not audited"),
                format!("you will not be able to establish {why}"),
            ));
        }
        let unkeyed = rules.iter().filter(|r| r.key.is_none()).count();
        if unkeyed > 0 {
            f.push(Finding::flag(
                Severity::Note,
                "audit",
                format!("{unkeyed} rule(s) with no key"),
                "some rules produce records nobody will find",
                "`ausearch -k <key>` is how this log is actually queried. A rule with no `-k` \
                 still records, into a stream measured in gigabytes, with no handle to pull it \
                 back out by",
            ));
        }
    }

    f
}
