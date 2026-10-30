use crate::posture::{Finding, Severity};
use crate::provenance::{self, Dating};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Channel {

    pub name: &'static str,

    pub carries: &'static str,

    pub min_useful: u64,

    pub default_enabled: bool,
}

pub const CHANNELS: &[Channel] = &[
    Channel {
        name: "Security",
        carries: "logons, privilege use, and process creation — the spine of any host \
                  investigation",
        min_useful: 128 * 1024 * 1024,
        default_enabled: true,
    },
    Channel {
        name: "System",
        carries: "service installation, driver loads, and the 104 record that says another \
                  channel was cleared",
        min_useful: 32 * 1024 * 1024,
        default_enabled: true,
    },
    Channel {
        name: "Application",
        carries: "what applications recorded about themselves, including the ones an intruder \
                  installed",
        min_useful: 32 * 1024 * 1024,
        default_enabled: true,
    },
    Channel {
        name: "Microsoft-Windows-PowerShell/Operational",
        carries: "script block logging — the contents of what PowerShell actually ran, which \
                  is the only record of a fileless payload",
        min_useful: 64 * 1024 * 1024,
        default_enabled: true,
    },
    Channel {
        name: "Microsoft-Windows-Sysmon/Operational",
        carries: "whatever Sysmon was configured to record. Absent on a host with no Sysmon, \
                  which is a gap rather than a fault",
        min_useful: 128 * 1024 * 1024,
        default_enabled: true,
    },
    Channel {
        name: "Microsoft-Windows-TaskScheduler/Operational",
        carries: "scheduled task registration and execution — the audit trail for the most \
                  common persistence mechanism on Windows",
        min_useful: 16 * 1024 * 1024,

        default_enabled: false,
    },
    Channel {
        name: "Microsoft-Windows-WinRM/Operational",
        carries: "remote shell sessions over WinRM, which is how lateral movement arrives on a \
                  managed estate and leaves no process-creation trace on the source",
        min_useful: 16 * 1024 * 1024,
        default_enabled: true,
    },
];

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ChannelState {

    pub name: String,

    pub enabled: bool,

    pub max_size: Option<u64>,

    pub retention: Retention,

    pub file_bytes: Option<u64>,

    pub record_ids: Vec<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Retention {

    #[default]
    Overwrite,

    ArchiveAndRotate,

    StopWhenFull,

    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Gap {

    pub after: u64,

    pub before: u64,
}

impl Gap {

    pub const fn missing(&self) -> u64 {
        self.before.saturating_sub(self.after).saturating_sub(1)
    }
}

pub fn gaps_in(ids: &[u64]) -> Vec<Gap> {
    let mut sorted: Vec<u64> = ids.to_vec();
    sorted.sort_unstable();
    sorted
        .windows(2)

        .filter(|w| w[1] - w[0] > 1)
        .map(|w| Gap { after: w[0], before: w[1] })
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ProcessAuditing {

    pub creation_audited: Option<bool>,

    pub creation_unread: Option<String>,

    pub command_line_included: Option<bool>,

    pub changes: Option<Vec<PolicyChange>>,

    pub changes_unread: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyChange {

    pub record_id: u64,

    pub at: Option<i64>,

    pub who: Option<String>,

    pub changes: Option<String>,
}

pub fn describe_policy_changes(raw: &str) -> String {
    raw.split(',')
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .map(|t| match t {
            "%%8448" => "Success removed".to_string(),
            "%%8449" => "Success added".to_string(),
            "%%8450" => "Failure removed".to_string(),
            "%%8451" => "Failure added".to_string(),
            other => other.to_string(),
        })
        .collect::<Vec<_>>()
        .join(", ")
}

pub fn judge_process_auditing(p: &ProcessAuditing, security: &Dating) -> Vec<Finding> {
    let mut f = Vec::new();
    match p.creation_audited {
        Some(false) => f.push(judge_auditing_off(p, security)),
        None => f.push(Finding {
            severity: Severity::Warn,
            subject: "Audit Process Creation: unknown".into(),
            what: format!(
                "the audit policy could not be read{}",
                p.creation_unread.as_ref().map_or(String::new(), |w| format!(": {w}"))
            ),
            why: "whether this host records process creation is UNDETERMINED. Do not read an absence \
             of 4688 records as an absence of execution until this is established".into(),
            fix: None,
        }),
        Some(true) => {}
    }
    if p.creation_audited == Some(true) {
        match p.command_line_included {
            Some(false) => f.push(Finding {
            severity: Severity::Warn,
            subject: "ProcessCreationIncludeCmdLine_Enabled: off".into(),
            what: "4688 records name the executable but not what it was told to do: the value \
                   is 0, or not configured, which is how Windows ships"
                .into(),
            why: "every record will say `powershell.exe` ran and none will say what it ran. For \
                 an intruder using only tools already on the host, the command line IS the \
                 payload, and this setting is the difference between an investigation and a \
                 list of process names".into(),
            fix: None,
        }),
            None => f.push(Finding {
            severity: Severity::Note,
            subject: "ProcessCreationIncludeCmdLine_Enabled: unknown".into(),
            what: "whether 4688 records carry command lines could not be read: the \
                   Policies\\System\\Audit key exists and would not give up its value"
                .into(),
            why: "check this before relying on 4688 content; the policy is per-machine and off \
                 by default".into(),
            fix: None,
        }),
            Some(true) => {}
        }
    }
    f
}

fn judge_auditing_off(p: &ProcessAuditing, security: &Dating) -> Finding {
    let fix = Some("auditpol /set /subcategory:\"Process Creation\" /success:enable".to_string());
    let lost = "there is no record of what ran on this host, and no configuration change now \
                recovers the past. Reconstruct execution from artefacts — prefetch, AmCache, \
                ShimCache, scheduled tasks — and treat 'nothing suspicious in the Security log' \
                as a statement about logons only";
    let changed: Vec<(&PolicyChange, String)> = p
        .changes
        .iter()
        .flatten()
        .filter_map(|c| {
            let placed = match c.at {
                Some(at) => security.predates(c.record_id, at).map(|_| ()),
                None => Err("its time did not render".into()),
            };
            placed.err().map(|why| (c, why))
        })
        .collect();
    if let Some((c, why)) = changed.last() {
        return Finding {
            severity: Severity::Critical,
            subject: "Audit Process Creation: off, and changed on this host".into(),
            what: format!(
                "4719 record {}{}{}: the Process Creation audit policy was changed ({}){}",
                c.record_id,
                c.at.map_or(String::new(), |at| format!(" at {}", provenance::utc(at))),
                c.who.as_ref().map_or(String::new(), |w| format!(" by {w}")),
                c.changes.as_deref().map_or_else(|| "changes not rendered".into(), describe_policy_changes),
                if changed.len() > 1 { format!(", one of {} such records", changed.len()) } else { String::new() }
            ),
            why: format!(
                "Windows ships Process Creation off, but this is not the shipped default: \
                 somebody changed the subcategory and it is off now. Switching off the record \
                 of what ran is what an intruder does before running things. {lost}. The change \
                 is not dated before this installation: {why}"
            ),
            fix,
        };
    }
    let (subject, searched) = match (&p.changes, &p.changes_unread) {
        (Some(_), _) => (
            "Audit Process Creation: off (as Windows ships it)",
            "No 4719 in the surviving Security records changed the subcategory on this host, \
             so nothing shows anybody turned it off; a Security log cleared or rolled over \
             since would have taken that record with it"
                .to_string(),
        ),
        (None, why) => (
            "Audit Process Creation: off",
            format!(
                "Windows ships it off, but the Security log could NOT be searched for a 4719 \
                 that would show somebody turned it off{}",
                why.as_ref().map_or(String::new(), |w| format!(" ({w})"))
            ),
        ),
    };
    Finding {
        severity: Severity::Warn,
        subject: subject.into(),
        what: "no 4688 records are being written".into(),
        why: format!("{lost}. {searched}"),
        fix,
    }
}

pub fn judge_channel(c: &ChannelState, spec: Option<&Channel>) -> Vec<Finding> {
    let mut f = Vec::new();
    let carries = spec.map_or("records this host produced", |s| s.carries);

    if !c.enabled && spec.is_some_and(|s| !s.default_enabled) {
        f.push(Finding {
            severity: Severity::Warn,
            subject: format!("{}: off (as Windows ships it)", c.name),
            what: "the channel is not recording, which is its default".into(),
            why: format!(
                "Windows ships this channel off, so it being off says nothing about anybody \
                 having turned it off — and cannot show whether somebody did. It carries \
                 {carries}, and there is none of that on this host: reconstruct it from what \
                 else recorded it, or from what is configured now"
            ),
            fix: None,
        });
        return f;
    }
    if !c.enabled {
        f.push(Finding {
            severity: Severity::Critical,
            subject: format!("{}: disabled", c.name),
            what: "the channel is switched off and is recording nothing".into(),
            why: format!(
                "this channel carries {carries}. A disabled channel produces no records at all, \
                 and nothing in Event Viewer distinguishes that from a quiet host"
            ),
            fix: None,
        });

        return f;
    }

    if let (Some(max), Some(s)) = (c.max_size, spec) {
        if max < s.min_useful {
            f.push(Finding {
            severity: Severity::Warn,
            subject: format!("{}: MaxSize {} MB", c.name, max / (1024 * 1024)),
            what: "the channel is small enough to roll over inside an investigation window".into(),
            why: format!(
                    "below about {} MB this channel overwrites itself faster than an incident \
                     takes to notice. It carries {carries}. Shrinking a log is also the quietest \
                     way to destroy one: it needs no tool, writes no event of its own, and the \
                     records are gone by the time anybody looks",
                    s.min_useful / (1024 * 1024)
                ),
            fix: None,
        });
        }
    }

    if let (Some(max), Some(on_disk)) = (c.max_size, c.file_bytes) {
        if max > 0 && on_disk * 10 >= max * 9 && c.retention == Retention::Overwrite {
            f.push(Finding {
            severity: Severity::Warn,
            subject: format!("{}: {}% full, overwriting", c.name, on_disk * 100 / max.max(1)),
            what: "the channel is at its ceiling and is discarding its oldest records now".into(),
            why: "whatever this channel held at the start of the retained window is already \
                 gone. Copy the .evtx off this host before anything else generates events".into(),
            fix: None,
        });
        }
    }

    if c.retention == Retention::StopWhenFull {
        f.push(Finding {
            severity: Severity::Warn,
            subject: format!("{}: stops when full", c.name),
            what: "the channel may have stopped recording at some point nobody noticed".into(),
            why: "nothing is lost, but nothing new is gained either. If this channel filled during \
             the intrusion, its last record is the moment it filled and not the moment the \
             intrusion ended".into(),
            fix: None,
        });
    }

    let gaps = gaps_in(&c.record_ids);
    if !gaps.is_empty() {
        let missing: u64 = gaps.iter().map(Gap::missing).sum();
        let first = gaps.first().map_or(String::new(), |g| format!("{}..{}", g.after, g.before));
        f.push(Finding {
            severity: Severity::Critical,
            subject: format!("{}: {} gap(s), {missing} record(s) missing", c.name, gaps.len()),
            what: "record ids are not contiguous".into(),
            why: format!(
                "the Event Log service assigns EventRecordID in strict order with no gaps, so a \
                 hole means records were removed from the file after it wrote them — the \
                 technique for deleting individual records rather than clearing the channel. \
                 First hole at {first}. One caveat worth checking before concluding tampering: \
                 a backup-and-clear rollover also leaves a discontinuity, but at a file \
                 boundary rather than in the middle of a run"
            ),
            fix: None,
        });
    }

    f
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClearEvent {

    pub event_id: u32,

    pub channel: String,

    pub when: String,

    pub who: Option<String>,

    pub cleared: Option<String>,

    pub computer: Option<String>,

    pub genuine: bool,

    pub record_id: u64,

    pub at: Option<i64>,
}

pub const CLEAR_EVENT_IDS: &[u32] = &[1102, 104];

pub const CLEAR_CHANNELS: &[&str] = &["Security", "System"];

pub fn clearer(sid: Option<&str>, user: Option<&str>, domain: Option<&str>) -> Option<String> {
    let name = match (domain.filter(|d| !d.is_empty()), user.filter(|u| !u.is_empty())) {
        (Some(d), Some(u)) => Some(format!("{d}\\{u}")),
        (None, Some(u)) => Some(u.to_string()),
        _ => None,
    };
    match (name, sid.filter(|s| !s.is_empty())) {
        (Some(n), Some(s)) => Some(format!("{n} ({s})")),
        (Some(n), None) => Some(n),
        (None, Some(s)) => Some(s.to_string()),
        (None, None) => None,
    }
}

pub fn same_computer(record: &str, this: &str) -> bool {
    let first = |s: &str| s.split('.').next().unwrap_or(s).to_ascii_lowercase();
    first(record) == first(this)
}

pub fn judge_clear(e: &ClearEvent, system: &Dating, security: &Dating, this: Option<&str>) -> Finding {
    let who = e.who.as_ref().map_or(String::new(), |w| format!(" by {w}"));
    let own = if e.channel == "Security" { security } else { system };
    let other = if e.channel == "Security" { system } else { security };
    let placed = (|| {
        if !e.genuine {
            return Err("it was not written by the Event Log service's own provider, so it is \
                        somebody's record of a clear rather than the service's"
                .to_string());
        }
        let at = e.at.ok_or("its time did not render, so nothing dates it")?;
        let c = own.predates(e.record_id, at)?;
        if let Dating::Undated(why) = other {
            return Err(format!(
                "its own channel places it before the clone first booted, but the other log a \
                 clear is checked against cannot be dated: {why}"
            ));
        }
        match (e.computer.as_deref(), this) {
            (Some(rec), Some(this)) if same_computer(rec, this) => Err(format!(
                "it was written under this host's own computer name, {rec}. Sysprep's clears \
                 carry the image's name, which specialize replaces"
            )),
            (Some(rec), Some(this)) => Ok((c, format!("{rec}, where this host is {this}"))),
            _ => Err("the computer name it was written under could not be compared with this \
                      host's"
                .to_string()),
        }
    })();
    let cleared = match (e.event_id, &e.cleared) {
        (104, Some(ch)) => format!("the {ch} log was cleared"),
        (104, None) => "a log was cleared".to_string(),
        _ => format!("the {} log was cleared", e.channel),
    };
    match placed {
        Ok((c, names)) => Finding {
            severity: Severity::Warn,
            subject: format!("{} cleared ({}) — likely image preparation", e.channel, e.when),
            what: format!(
                "event {} — {cleared}{who}, before this clone first booted, while the image it \
                 was cloned from was prepared",
                e.event_id
            ),
            why: format!(
                "sysprep clears the event logs as it generalizes an image, and every clone boots \
                 with that record in its log. This one is dated before the clone's first boot, \
                 numbered before it in {}, with System and Security agreeing on every boot \
                 since, and written under the image's computer name ({names}). {} {}",
                e.channel,
                c.evidence(),
                provenance::FAKEABLE
            ),
            fix: None,
        },
        Err(why) => Finding {
            severity: Severity::Critical,
            subject: format!("{} cleared ({})", e.channel, e.when),
            what: if e.event_id == 104 {
                format!("event 104 — {cleared}{who}, as recorded in {}", e.channel)
            } else {
                format!("event {} — {cleared}{who}", e.event_id)
            },
            why: format!(
                "nothing on a healthy host clears an event log. Everything the channel held \
                 before this record is gone and cannot be recovered from the live log — a \
                 volume shadow copy or a backup taken before this timestamp is the only place \
                 it still exists. Note the timestamp: it is the moment the account above \
                 decided the record mattered. It is not dated before this installation, as \
                 sysprep's clears are: {why}"
            ),
            fix: None,
        },
    }
}

#[derive(Debug, Clone, Default)]
pub struct Sweep {

    pub channels: Vec<ChannelState>,

    pub unreadable: Vec<(String, String)>,

    pub clears: Vec<ClearEvent>,

    pub clears_checked: bool,

    pub capped: Vec<String>,

    pub auditing: ProcessAuditing,

    pub dating: Vec<(String, Dating)>,

    pub computer: Option<String>,

    pub enumerated: bool,

    pub findings: Vec<Finding>,
}

impl Sweep {

    pub fn complete(&self) -> bool {
        self.unreadable.is_empty() && self.enumerated && self.clears_checked && self.capped.is_empty()
    }

    pub fn coverage(&self) -> String {
        let mut s = format!("read {} channel(s)", self.channels.len());
        if !self.clears_checked {
            s.push_str(
                " — the logs were NOT searched for a clearing event (1102, 104), so an absence \
                 of a cleared-log finding below means nothing",
            );
        }
        if !self.capped.is_empty() {
            s.push_str(&format!(
                " — record enumeration stopped at {MAX_RECORDS_PER_CHANNEL} on {}, so only the \
                 newest records there were checked for deletions",
                self.capped.join(", ")
            ));
        }
        if !self.enumerated {
            s.push_str(
                " — record ids were NOT enumerated, so this sweep did not look for deleted \
                 records at all. An absence of gap findings below means nothing",
            );
        }
        if !self.clears.is_empty() && (!self.enumerated || self.capped.iter().any(|c| CLEAR_CHANNELS.contains(&c.as_str()))) {
            s.push_str(
                " — the clears below were NOT dated against this installation, because System \
                 and Security were not read whole (a quick sweep, or a capped channel), so every \
                 one is Critical, sysprep's own included",
            );
        }
        if !self.unreadable.is_empty() {
            s.push_str(&format!(
                " — {} channel(s) could NOT be read, and anything in them is outside this \
                 result: {}",
                self.unreadable.len(),
                self.unreadable
                    .iter()
                    .map(|(c, why)| format!("{c} ({why})"))
                    .collect::<Vec<_>>()
                    .join("; ")
            ));
        }
        s
    }
}

pub fn judge(s: &Sweep) -> Vec<Finding> {
    let mut f = Vec::new();
    let undated = Dating::default();
    let dating = |ch: &str| s.dating.iter().find(|(c, _)| c == ch).map_or(&undated, |(_, d)| d);
    for e in &s.clears {
        f.push(judge_clear(e, dating("System"), dating("Security"), s.computer.as_deref()));
    }
    for c in &s.channels {
        let spec = CHANNELS.iter().find(|k| k.name == c.name);
        f.extend(judge_channel(c, spec));
    }
    f.extend(judge_process_auditing(&s.auditing, dating("Security")));

    for spec in CHANNELS {
        if spec.name.contains("Sysmon") {
            continue;
        }
        if !s.channels.iter().any(|c| c.name == spec.name)
            && !s.unreadable.iter().any(|(n, _)| n == spec.name)
        {
            f.push(Finding {
            severity: Severity::Note,
            subject: format!("{}: not present", spec.name),
            what: "this channel was not found on the host".into(),
            why: format!(
                    "it carries {}. Its absence may be ordinary for this Windows edition, or \
                     may be the channel having been removed",
                    spec.carries
                ),
            fix: None,
        });
        }
    }
    f
}

#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
const CHANNEL_KEY: &str = r"SYSTEM\CurrentControlSet\Services\EventLog";

#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
const WEVT_KEY: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels";

#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
pub(crate) const CMDLINE_KEY: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit";

#[cfg(target_os = "windows")]
pub(crate) enum ChannelConfig {

    Found(bool, Option<u64>, Retention),

    Absent,

    Unreadable(u32),
}

#[cfg(target_os = "windows")]
pub(crate) fn read_channel_config(name: &str) -> ChannelConfig {
    use windows_sys::Win32::Foundation::ERROR_FILE_NOT_FOUND;

    let classic = format!(r"{CHANNEL_KEY}\{name}");
    let wevt = format!(r"{WEVT_KEY}\{name}");

    let wevt_values = crate::reg::hklm_values_read(&wevt);
    let classic_values = crate::reg::hklm_values_read(&classic);
    let key = if crate::reg::hklm_dword(&wevt, "Enabled").is_some()
        || wevt_values.as_ref().is_ok_and(|v| !v.is_empty())
    {
        wevt
    } else if classic_values.as_ref().is_ok_and(|v| !v.is_empty()) {
        classic
    } else {

        return match (wevt_values, classic_values) {
            (Err(a), Err(b)) if a == ERROR_FILE_NOT_FOUND && b == ERROR_FILE_NOT_FOUND => {
                ChannelConfig::Absent
            }
            (Err(rc), _) | (_, Err(rc)) => ChannelConfig::Unreadable(rc),
            _ => ChannelConfig::Absent,
        };
    };

    let enabled = crate::reg::hklm_dword(&key, "Enabled").is_none_or(|v| v != 0);
    let max_size = crate::reg::hklm_dword(&key, "MaxSize").map(u64::from);
    let retention = match crate::reg::hklm_dword(&key, "Retention") {

        Some(0) => {
            if crate::reg::hklm_dword(&key, "AutoBackupLogFiles").is_some_and(|v| v != 0) {
                Retention::ArchiveAndRotate
            } else {
                Retention::Overwrite
            }
        }
        Some(0xFFFF_FFFF) => Retention::StopWhenFull,
        Some(_) => Retention::Overwrite,
        None => Retention::Unknown,
    };
    ChannelConfig::Found(enabled, max_size, retention)
}

pub fn evtx_name(channel: &str) -> String {
    format!("{}.evtx", channel.replace('/', "%4"))
}

pub fn parse_guid(s: &str) -> Option<u128> {
    let hex: String = s.trim().trim_start_matches('{').trim_end_matches('}').chars().filter(|c| *c != '-').collect();
    if hex.len() != 32 {
        return None;
    }
    u128::from_str_radix(&hex, 16).ok()
}

pub fn parse_uint(s: &str) -> Option<u64> {
    let t = s.trim();
    match t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        Some(hex) => u64::from_str_radix(hex, 16).ok(),
        None => t.parse().ok(),
    }
}

pub fn from_provider(provider: Option<u128>, want: u128) -> bool {
    provider == Some(want)
}

#[cfg(target_os = "windows")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Value {

    Absent,

    Uint(u64),

    Text(String),

    Time(i64),

    Guid(u128),
}

#[cfg(target_os = "windows")]
impl Value {
    pub(crate) fn text(&self) -> Option<&str> {
        if let Self::Text(t) = self { Some(t) } else { None }
    }

    pub(crate) fn uint(&self) -> Option<u64> {
        match self {
            Self::Uint(n) => Some(*n),
            Self::Text(t) => parse_uint(t),
            _ => None,
        }
    }
    fn time(&self) -> Option<i64> {
        if let Self::Time(t) = self { Some(*t) } else { None }
    }
    fn guid(&self) -> Option<u128> {
        match self {
            Self::Guid(g) => Some(*g),
            Self::Text(t) => parse_guid(t),
            _ => None,
        }
    }
}

#[cfg(target_os = "windows")]
pub(crate) struct Rendered {

    pub(crate) id: u64,

    pub(crate) at: Option<i64>,

    pub(crate) provider: Option<u128>,

    computer: Option<String>,

    extra: Vec<Value>,
}

#[cfg(target_os = "windows")]
impl Rendered {

    fn mark(&self) -> Option<provenance::Mark> {
        self.at.map(|at| provenance::Mark { seq: self.id, at })
    }

    pub(crate) fn extra(&self, i: usize) -> &Value {
        self.extra.get(i).unwrap_or(&Value::Absent)
    }
}

#[cfg(target_os = "windows")]
fn read_record_ids(channel: &str, cap: usize) -> Result<Vec<Rendered>, String> {
    read_records(channel, "*", cap, &[])
}

#[cfg(target_os = "windows")]
const ANCHOR_CAP: usize = 20_000;

#[cfg(target_os = "windows")]
fn kernel_general(event_id: u32, extra: &[&str]) -> Option<Vec<Rendered>> {
    let r = read_records(
        "System",
        &format!("*[System[Provider[@Name='Microsoft-Windows-Kernel-General'] and (EventID={event_id})]]"),
        ANCHOR_CAP,
        extra,
    )
    .ok()?;
    if r.len() >= ANCHOR_CAP {
        return None;
    }
    Some(r.into_iter().filter(|r| from_provider(r.provider, provenance::KERNEL_GENERAL)).collect())
}

#[cfg(target_os = "windows")]
pub fn boot_records() -> Option<Vec<provenance::Mark>> {
    kernel_general(12, &[])?.iter().map(Rendered::mark).collect()
}

#[cfg(target_os = "windows")]
pub fn clock_changes() -> Option<Vec<provenance::Step>> {
    kernel_general(
        1,
        &["Event/EventData/Data[@Name='NewTime']", "Event/EventData/Data[@Name='OldTime']"],
    )?
    .iter()
    .map(|r| Some(provenance::Step { seq: r.id, new: r.extra(0).time()?, old: r.extra(1).time()? }))
    .collect()
}

#[cfg(target_os = "windows")]
pub fn security_startups() -> Option<Vec<provenance::Mark>> {
    let r = read_records("Security", "*[System[(EventID=4608)]]", ANCHOR_CAP, &[]).ok()?;
    if r.len() >= ANCHOR_CAP {
        return None;
    }
    r.iter()
        .filter(|r| from_provider(r.provider, provenance::SECURITY_AUDITING))
        .map(Rendered::mark)
        .collect()
}

pub const DEFENDER_PROVIDER: u128 = 0x11cd_958a_c507_4ef3_b3f2_5fd9_dfbd_2c78;

#[cfg(target_os = "windows")]
pub fn defender_updates() -> Result<Vec<crate::usn::DefenderUpdate>, String> {
    const CHANNEL: &str = "Microsoft-Windows-Windows Defender/Operational";
    let mut out = Vec::new();
    for event_id in [2000_u32, 2001, 2002, 2003] {
        let r = read_records(
            CHANNEL,
            &format!(
                "*[System[Provider[@Name='Microsoft-Windows-Windows Defender'] and (EventID={event_id})]]"
            ),
            ANCHOR_CAP,
            &["Event/EventData/Data[@Name='SID']"],
        )?;
        for e in r.iter().filter(|e| from_provider(e.provider, DEFENDER_PROVIDER)) {
            let (Some(at), Some(sid)) = (e.at, e.extra(0).text()) else { continue };
            out.push(crate::usn::DefenderUpdate {
                event_id,
                record: e.id,
                at,
                sid: sid.to_string(),
                temp: profile_temp(sid),
            });
        }
    }
    Ok(out)
}

pub const DIAGNOSIS_SCRIPTED_PROVIDER: u128 = 0xe1dd_7e52_621d_44e3_a1ad_0370_c2b2_5946;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiagnosticEvent {

    pub event_id: u32,

    pub record: u64,

    pub at: i64,

    pub pid: Option<u64>,

    pub sid: Option<String>,

    pub data: Option<String>,
}

pub fn pair_diagnostic_runs(mut events: Vec<DiagnosticEvent>) -> Vec<crate::usn::DiagnosticRun> {
    events.sort_by_key(|e| e.record);
    let mut out: Vec<crate::usn::DiagnosticRun> = Vec::new();
    for (i, e) in events.iter().enumerate() {
        if e.event_id != 101 {
            continue;
        }
        let Some(path) = e.data.clone() else { continue };
        let end = events.iter().skip(i + 1).filter(|n| n.pid.is_some() && n.pid == e.pid).find(|n| {
            n.event_id == 101 || n.event_id == 104
        });
        let end = end.filter(|n| n.event_id == 104 && n.at >= e.at);
        out.push(crate::usn::DiagnosticRun {
            record: e.record,
            started: e.at,
            finished: end.map(|n| n.at),
            package_path: path,
            package_id: end.and_then(|n| n.data.clone()),
            sid: e.sid.clone(),
            temp: None,
            package_files: None,
        });
    }
    out
}

#[cfg(target_os = "windows")]
pub fn diagnostic_runs() -> Result<Vec<crate::usn::DiagnosticRun>, String> {
    const CHANNEL: &str = "Microsoft-Windows-Diagnosis-Scripted/Operational";
    let mut events = Vec::new();
    for (event_id, data) in [(101_u32, "PackagePath"), (104, "PackageId")] {
        let r = read_records(
            CHANNEL,
            &format!("*[System[(EventID={event_id})]]"),
            ANCHOR_CAP,
            &[
                "Event/System/Execution/@ProcessID",
                "Event/System/Security/@UserID",
                &format!("Event/EventData/Data[@Name='{data}']"),
            ],
        )?;
        for e in r.iter().filter(|e| from_provider(e.provider, DIAGNOSIS_SCRIPTED_PROVIDER)) {
            let Some(at) = e.at else { continue };
            events.push(DiagnosticEvent {
                event_id,
                record: e.id,
                at,
                pid: e.extra(0).uint(),
                sid: e.extra(1).text().map(str::to_string),
                data: e.extra(2).text().map(str::to_string),
            });
        }
    }
    let mut runs = pair_diagnostic_runs(events);

    let root = std::env::var("SystemRoot").ok();
    let mut listed: std::collections::BTreeMap<String, Option<Vec<String>>> = std::collections::BTreeMap::new();
    for r in &mut runs {
        r.temp = r.sid.as_deref().and_then(profile_temp);
        let Some(dir) = root.as_deref().and_then(|root| package_dir(&r.package_path, root).ok()) else {
            continue;
        };
        let key = dir.to_ascii_lowercase();
        if !listed.contains_key(&key) && listed.len() < MAX_PACKAGES {
            listed.insert(key.clone(), package_files(&dir));
        }
        r.package_files = listed.get(&key).cloned().flatten();
    }
    Ok(runs)
}

pub const MAX_PACKAGES: usize = 64;

pub const MAX_PACKAGE_NAMES: usize = 4096;

pub fn package_dir(path: &str, system_root: &str) -> Result<String, String> {
    let root = crate::localpath::local(system_root).map_err(|why| format!("%SystemRoot% is {system_root}: {why}"))?;
    let diagnostics = format!(r"{}\diagnostics", root.trim_end_matches('\\'));
    let dir = crate::localpath::local(path)?;
    if crate::localpath::within(&dir, &diagnostics) {
        Ok(dir)
    } else {
        Err(format!("it is not below {diagnostics}, where Windows keeps its diagnostic packages"))
    }
}

#[cfg(target_os = "windows")]
fn package_files(dir: &str) -> Option<Vec<String>> {
    match crate::localpath::vet(dir) {
        Ok(Some((_, md))) if md.is_dir() => {}
        _ => return None,
    }
    let mut out = Vec::new();

    let mut seen = 0_usize;
    for e in std::fs::read_dir(dir).ok()?.flatten() {

        let kind = e.file_type().ok()?;
        seen += 1;
        if kind.is_symlink() || seen > MAX_PACKAGE_NAMES {
            return None;
        }
        if kind.is_dir() {
            for f in std::fs::read_dir(e.path()).ok()?.flatten() {
                seen += 1;
                if f.file_type().ok()?.is_symlink() || seen > MAX_PACKAGE_NAMES {
                    return None;
                }
                out.push(f.file_name().to_string_lossy().to_ascii_lowercase());
            }
        } else {
            out.push(e.file_name().to_string_lossy().to_ascii_lowercase());
        }
    }
    Some(out)
}

#[cfg(target_os = "windows")]
fn profile_temp(sid: &str) -> Option<String> {
    let key = format!(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\{sid}");
    let image = crate::reg::hklm_values(&key)
        .into_iter()
        .find(|(n, _)| n.eq_ignore_ascii_case("ProfileImagePath"))
        .map(|(_, v)| v)?;
    expand_profile(&image, &std::env::var("SystemRoot").ok()?, &std::env::var("SystemDrive").ok()?)
        .map(|p| format!(r"{p}\AppData\Local\Temp"))
}

pub fn expand_profile(image: &str, root: &str, drive: &str) -> Option<String> {
    let mut out = String::new();
    let mut rest = image;
    while let Some(i) = rest.find('%') {
        out.push_str(rest.get(..i)?);
        let after = rest.get(i + 1..)?;
        let j = after.find('%')?;
        match after.get(..j)?.to_ascii_lowercase().as_str() {
            "systemroot" => out.push_str(root),
            "systemdrive" => out.push_str(drive),
            _ => return None,
        }
        rest = after.get(j + 1..)?;
    }
    out.push_str(rest);
    Some(out)
}

#[cfg(target_os = "windows")]
pub(crate) fn read_records(
    channel: &str,
    xpath: &str,
    cap: usize,
    extra: &[&str],
) -> Result<Vec<Rendered>, String> {
    use windows_sys::Win32::Foundation::{GetLastError, ERROR_NO_MORE_ITEMS};
    use windows_sys::Win32::System::EventLog::{
        EvtClose, EvtNext, EvtQuery, EvtQueryChannelPath, EvtQueryReverseDirection, EVT_HANDLE,
    };

    let path = wide(channel);

    let query = wide(xpath);

    let handle: EVT_HANDLE = unsafe {
        EvtQuery(
            0,
            path.as_ptr(),
            query.as_ptr(),
            EvtQueryChannelPath | EvtQueryReverseDirection,
        )
    };
    if handle == 0 {

        return Err(format!("EvtQuery failed ({})", unsafe { GetLastError() }));
    }

    let (ctx, want) = match render_context(extra) {
        Ok(c) => c,
        Err(e) => {

            unsafe { EvtClose(handle) };
            return Err(e);
        }
    };

    let mut out: Vec<Rendered> = Vec::new();
    let mut batch: [EVT_HANDLE; 64] = [0; 64];
    let mut failed = None;
    loop {
        let mut returned: u32 = 0;

        let ok = unsafe {
            EvtNext(
                handle,
                batch.len() as u32,
                batch.as_mut_ptr(),
                0,
                0,
                std::ptr::addr_of_mut!(returned),
            )
        };
        if ok == 0 {

            let e = unsafe { GetLastError() };
            if e != ERROR_NO_MORE_ITEMS {
                failed = Some(format!("EvtNext failed ({e})"));
            }
            break;
        }
        for h in batch.iter().take(returned as usize) {
            if let Some(r) = render(ctx, *h, want) {
                out.push(r);
            }

            unsafe { EvtClose(*h) };
        }
        if returned == 0 || out.len() >= cap {
            break;
        }
    }

    unsafe {
        EvtClose(ctx);
        EvtClose(handle);
    }
    failed.map_or(Ok(out), Err)
}

#[cfg(target_os = "windows")]
pub(crate) fn render_context(
    extra: &[&str],
) -> Result<(windows_sys::Win32::System::EventLog::EVT_HANDLE, usize), String> {
    use windows_sys::Win32::Foundation::GetLastError;
    use windows_sys::Win32::System::EventLog::{EvtCreateRenderContext, EvtRenderContextValues};

    let fixed = [
        "Event/System/EventRecordID",
        "Event/System/TimeCreated/@SystemTime",
        "Event/System/Provider/@Guid",
        "Event/System/Computer",
    ];
    let wides: Vec<Vec<u16>> = fixed.iter().chain(extra).map(|p| wide(p)).collect();
    let paths: Vec<*const u16> = wides.iter().map(|w| w.as_ptr()).collect();

    let ctx = unsafe { EvtCreateRenderContext(paths.len() as u32, paths.as_ptr(), EvtRenderContextValues) };
    if ctx == 0 {

        return Err(format!("EvtCreateRenderContext failed ({})", unsafe { GetLastError() }));
    }
    Ok((ctx, paths.len()))
}

#[cfg(target_os = "windows")]
pub(crate) fn render(
    ctx: windows_sys::Win32::System::EventLog::EVT_HANDLE,
    event: windows_sys::Win32::System::EventLog::EVT_HANDLE,
    want: usize,
) -> Option<Rendered> {
    use windows_sys::Win32::Foundation::{GetLastError, ERROR_INSUFFICIENT_BUFFER};
    use windows_sys::Win32::System::EventLog::{
        EvtRender, EvtRenderEventValues, EvtVarTypeUInt64, EVT_VARIANT,
    };

    let mut buf = vec![0_u64; 128];
    let mut used: u32 = 0;
    let mut props: u32 = 0;
    for _ in 0..2 {
        let bytes = u32::try_from(buf.len() * 8).unwrap_or(u32::MAX);

        let ok = unsafe {
            EvtRender(
                ctx,
                event,
                EvtRenderEventValues,
                bytes,
                buf.as_mut_ptr().cast(),
                std::ptr::addr_of_mut!(used),
                std::ptr::addr_of_mut!(props),
            )
        };
        if ok != 0 {
            break;
        }

        if unsafe { GetLastError() } != ERROR_INSUFFICIENT_BUFFER {
            return None;
        }
        buf = vec![0_u64; (used as usize).div_ceil(8)];
        props = 0;
    }
    if (props as usize) < want || buf.len() * 8 < want * std::mem::size_of::<EVT_VARIANT>() {
        return None;
    }
    let base = buf.as_ptr().cast::<EVT_VARIANT>();

    let value = |i: usize| unsafe { variant(&std::ptr::read_unaligned(base.add(i))) };

    let id = unsafe { std::ptr::read_unaligned(base) };
    if id.Type != EvtVarTypeUInt64 as u32 {
        return None;
    }

    let id = unsafe { id.Anonymous.UInt64Val };
    Some(Rendered {
        id,
        at: value(1).time(),
        provider: value(2).guid(),
        computer: value(3).text().map(str::to_string),
        extra: (4..want).map(value).collect(),
    })
}

#[cfg(target_os = "windows")]
unsafe fn variant(v: &windows_sys::Win32::System::EventLog::EVT_VARIANT) -> Value {
    use windows_sys::Win32::System::EventLog::{
        EvtVarTypeByte, EvtVarTypeFileTime, EvtVarTypeGuid, EvtVarTypeHexInt32,
        EvtVarTypeHexInt64, EvtVarTypeSid, EvtVarTypeSizeT, EvtVarTypeString, EvtVarTypeSysTime,
        EvtVarTypeUInt16, EvtVarTypeUInt32, EvtVarTypeUInt64,
    };

    match v.Type as i32 {
        t if t == EvtVarTypeFileTime => {

            i64::try_from(unsafe { v.Anonymous.FileTimeVal }).map_or(Value::Absent, Value::Time)
        }
        t if t == EvtVarTypeSysTime => {

            let p = unsafe { v.Anonymous.SysTimeVal };
            if p.is_null() {
                return Value::Absent;
            }

            let st = unsafe { std::ptr::read_unaligned(p) };
            provenance::filetime_from_parts(
                i64::from(st.wYear),
                i64::from(st.wMonth),
                i64::from(st.wDay),
                i64::from(st.wHour),
                i64::from(st.wMinute),
                i64::from(st.wSecond),
                i64::from(st.wMilliseconds),
            )
            .map_or(Value::Absent, Value::Time)
        }
        t if t == EvtVarTypeGuid => {

            let p = unsafe { v.Anonymous.GuidVal };
            if p.is_null() {
                return Value::Absent;
            }

            let g = unsafe { std::ptr::read_unaligned(p) };
            Value::Guid(
                (u128::from(g.data1) << 96)
                    | (u128::from(g.data2) << 80)
                    | (u128::from(g.data3) << 64)
                    | u128::from(u64::from_be_bytes(g.data4)),
            )
        }
        t if t == EvtVarTypeString => {

            let p = unsafe { v.Anonymous.StringVal };

            unsafe { wide_z(p) }.map_or(Value::Absent, Value::Text)
        }

        t if t == EvtVarTypeSid => unsafe { sid_string(v.Anonymous.SidVal) }.map_or(Value::Absent, Value::Text),

        t if t == EvtVarTypeByte => Value::Uint(u64::from(unsafe { v.Anonymous.ByteVal })),

        t if t == EvtVarTypeUInt16 => Value::Uint(u64::from(unsafe { v.Anonymous.UInt16Val })),
        t if t == EvtVarTypeUInt32 || t == EvtVarTypeHexInt32 => {

            Value::Uint(u64::from(unsafe { v.Anonymous.UInt32Val }))
        }
        t if t == EvtVarTypeUInt64 || t == EvtVarTypeHexInt64 => {

            Value::Uint(unsafe { v.Anonymous.UInt64Val })
        }

        t if t == EvtVarTypeSizeT => Value::Uint(unsafe { v.Anonymous.SizeTVal } as u64),
        _ => Value::Absent,
    }
}

#[cfg(target_os = "windows")]
unsafe fn wide_z(p: *const u16) -> Option<String> {
    if p.is_null() {
        return None;
    }
    let mut n = 0;

    while unsafe { *p.add(n) } != 0 {
        n += 1;
    }

    Some(String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(p, n) }))
}

#[cfg(target_os = "windows")]
unsafe fn sid_string(sid: windows_sys::Win32::Security::PSID) -> Option<String> {
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;

    if sid.is_null() {
        return None;
    }
    let mut out: windows_sys::core::PWSTR = std::ptr::null_mut();

    if unsafe { ConvertSidToStringSidW(sid, std::ptr::addr_of_mut!(out)) } == 0 || out.is_null() {
        return None;
    }

    let s = unsafe { wide_z(out) };

    unsafe { LocalFree(out.cast()) };
    s
}

pub const PROCESS_CREATION_GUID: u128 = 0x0cce_922b_69ae_11d9_bed3_5050_5450_3030;

#[cfg(target_os = "windows")]
static PROCESS_CREATION: windows_sys::core::GUID =
    windows_sys::core::GUID::from_u128(PROCESS_CREATION_GUID);

#[cfg(target_os = "windows")]
pub(crate) fn command_line_policy() -> Option<bool> {
    crate::procexec::cmdline_policy(
        crate::reg::hklm_values_read(CMDLINE_KEY),
        crate::reg::hklm_dword(CMDLINE_KEY, crate::procexec::CMDLINE_VALUE),
    )
}

#[cfg(target_os = "windows")]
pub(crate) fn read_process_creation_audit() -> Result<bool, String> {
    use windows_sys::Win32::Foundation::GetLastError;
    use windows_sys::Win32::Security::Authentication::Identity::{
        AuditFree, AuditQuerySystemPolicy, AUDIT_POLICY_INFORMATION, POLICY_AUDIT_EVENT_SUCCESS,
    };

    crate::modules::with_privilege("SeSecurityPrivilege", |privileged| {
        let mut info: *mut AUDIT_POLICY_INFORMATION = std::ptr::null_mut();

        let ok = unsafe {
            AuditQuerySystemPolicy(
                std::ptr::addr_of!(PROCESS_CREATION),
                1,
                std::ptr::addr_of_mut!(info),
            )
        };
        if !ok || info.is_null() {

            let e = unsafe { GetLastError() };
            return Err(format!(
                "AuditQuerySystemPolicy failed (error {e}){}",
                if privileged { "" } else { ", and SeSecurityPrivilege could not be enabled" }
            ));
        }

        let bits = unsafe { (*info).AuditingInformation };

        unsafe { AuditFree(info.cast()) };
        Ok(bits & POLICY_AUDIT_EVENT_SUCCESS as u32 != 0)
    })
}

#[cfg(target_os = "windows")]
pub fn policy_readings() -> Vec<(String, Result<String, String>)> {
    let mut out = vec![(
        "audit/process-creation".to_string(),
        read_process_creation_audit().map(|on| if on { "audited" } else { "not-audited" }.to_string()),
    )];
    out.push((
        "audit/command-line".to_string(),
        match command_line_policy() {
            Some(on) => Ok(if on { "on" } else { "off" }.to_string()),
            None => Err("the Policies\\System\\Audit key exists and its value could not be read".to_string()),
        },
    ));
    for spec in CHANNELS {
        let v = match read_channel_config(spec.name) {
            ChannelConfig::Found(enabled, max, retention) => Ok(format!(
                "enabled={} max={} retention={retention:?}",
                u8::from(enabled),
                max.map_or_else(|| "unread".to_string(), |m| m.to_string())
            )),
            ChannelConfig::Absent => Ok("absent".to_string()),
            ChannelConfig::Unreadable(rc) => Err(format!("its keys could not be read (error {rc})")),
        };
        out.push((format!("evtlog/{}", spec.name), v));
    }
    out
}

#[cfg(not(target_os = "windows"))]
pub fn policy_readings() -> Vec<(String, Result<String, String>)> {
    Vec::new()
}

#[cfg(target_os = "windows")]
fn read_process_creation_changes() -> Result<Vec<PolicyChange>, String> {
    const CAP: usize = 4096;
    let records = read_records(
        "Security",
        "*[System[(EventID=4719)]]",
        CAP,
        &[
            "Event/EventData/Data[@Name='SubcategoryGuid']",
            "Event/EventData/Data[@Name='AuditPolicyChanges']",
            "Event/EventData/Data[@Name='SubjectUserName']",
            "Event/EventData/Data[@Name='SubjectDomainName']",
        ],
    )?;
    if records.len() >= CAP {
        return Err(format!("more than {CAP} audit policy changes, and not all were read"));
    }
    Ok(records
        .iter()
        .filter(|r| from_provider(r.provider, provenance::SECURITY_AUDITING))
        .filter(|r| r.extra(0).guid() == Some(PROCESS_CREATION_GUID))
        .map(|r| PolicyChange {
            record_id: r.id,
            at: r.at,
            who: clearer(None, r.extra(2).text(), r.extra(3).text()),
            changes: r.extra(1).text().map(str::to_string),
        })
        .collect())
}

#[cfg(target_os = "windows")]
fn computer_name() -> Option<String> {
    use windows_sys::Win32::System::SystemInformation::{ComputerNameDnsHostname, GetComputerNameExW};

    let mut buf = [0_u16; 256];
    let mut n = buf.len() as u32;

    if unsafe { GetComputerNameExW(ComputerNameDnsHostname, buf.as_mut_ptr(), std::ptr::addr_of_mut!(n)) } == 0 {
        return None;
    }
    buf.get(..n as usize).map(String::from_utf16_lossy).filter(|s| !s.is_empty())
}

#[cfg(target_os = "windows")]
pub(crate) fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

pub const MAX_RECORDS_PER_CHANNEL: usize = 200_000;

#[cfg(target_os = "windows")]
pub fn sweep(enumerate: bool) -> Sweep {
    let mut s = Sweep { enumerated: enumerate, ..Default::default() };

    let mut marked: Vec<(&str, Vec<provenance::Mark>, bool)> = Vec::new();

    for spec in CHANNELS {
        let (enabled, max_size, retention) = match read_channel_config(spec.name) {
            ChannelConfig::Found(e, m, r) => (e, m, r),

            ChannelConfig::Absent => continue,

            ChannelConfig::Unreadable(rc) => {
                s.unreadable.push((
                    spec.name.to_string(),
                    format!(
                        "neither channel key could be read (error {rc}), so whether this \
                         channel exists or what it is configured to do was not established"
                    ),
                ));
                continue;
            }
        };
        let file = std::path::Path::new(r"C:\Windows\System32\winevt\Logs").join(evtx_name(spec.name));
        let file_bytes = std::fs::metadata(&file).ok().map(|m| m.len());

        let mut record_ids = Vec::new();
        if enumerate && enabled {
            match read_record_ids(spec.name, MAX_RECORDS_PER_CHANNEL) {
                Ok(records) => {
                    let capped = records.len() >= MAX_RECORDS_PER_CHANNEL;
                    if capped {
                        s.capped.push(spec.name.to_string());
                    }
                    if CLEAR_CHANNELS.contains(&spec.name) {
                        let marks: Vec<provenance::Mark> =
                            records.iter().filter_map(Rendered::mark).collect();
                        marked.push((spec.name, marks, !capped));
                    }
                    record_ids = records.into_iter().map(|r| r.id).collect();
                }
                Err(why) => s.unreadable.push((spec.name.to_string(), why)),
            }
        }
        s.channels.push(ChannelState {
            name: spec.name.to_string(),
            enabled,
            max_size,
            retention,
            file_bytes,
            record_ids,
        });
    }

    let mut searched = 0;
    for (event_id, channel) in [(1102_u32, "Security"), (104_u32, "System")] {
        let extra = [
            "Event/UserData/LogFileCleared/SubjectUserSid",
            "Event/UserData/LogFileCleared/SubjectUserName",
            "Event/UserData/LogFileCleared/SubjectDomainName",
            "Event/UserData/LogFileCleared/Channel",
            "Event/System/Security/@UserID",
        ];
        match read_records(channel, &format!("*[System[(EventID={event_id})]]"), 64, &extra) {
            Ok(records) => {
                searched += 1;
                s.clears.extend(records.into_iter().map(|r| ClearEvent {
                    event_id,
                    channel: channel.to_string(),
                    when: r.at.map_or_else(
                        || format!("record {}", r.id),
                        |at| format!("{}, record {}", provenance::utc(at), r.id),
                    ),
                    who: clearer(r.extra(0).text(), r.extra(1).text(), r.extra(2).text())
                        .or_else(|| r.extra(4).text().map(str::to_string)),
                    cleared: r.extra(3).text().map(str::to_string),
                    computer: r.computer.clone(),
                    genuine: from_provider(r.provider, provenance::EVENTLOG),
                    record_id: r.id,
                    at: r.at,
                }));
            }
            Err(why) => s.unreadable.push((
                format!("{channel} (clear events)"),
                format!("could not search for event {event_id}: {why}"),
            )),
        }
    }
    s.clears_checked = searched == 2;

    let audit = read_process_creation_audit();
    let changes = read_process_creation_changes();
    s.auditing = ProcessAuditing {
        creation_audited: audit.as_ref().ok().copied(),
        creation_unread: audit.err(),
        command_line_included: command_line_policy(),
        changes: changes.as_ref().ok().cloned(),
        changes_unread: changes.err(),
    };
    s.computer = computer_name();

    let to_date = !s.clears.is_empty() || s.auditing.changes.as_ref().is_some_and(|c| !c.is_empty());
    if to_date {
        let install = provenance::install(&provenance::anchors());
        s.dating = CLEAR_CHANNELS
            .iter()
            .map(|ch| {
                let log = if *ch == "Security" { provenance::Log::Security } else { provenance::Log::System };
                let dating = match marked.iter().find(|(c, _, _)| c == ch) {
                    Some((_, marks, whole)) => provenance::chronology(
                        marks,
                        &install,
                        log,
                        if *whole {
                            Ok(())
                        } else {
                            Err(format!(
                                "{ch}'s enumeration stopped at {MAX_RECORDS_PER_CHANNEL} records, \
                                 so its oldest records, which a clear is dated against, were not \
                                 read"
                            ))
                        },
                    ),
                    None => Dating::Undated(
                        "this channel's records were not read (a quick sweep, or the read \
                         failed), so its own order cannot place the install"
                            .into(),
                    ),
                };
                ((*ch).to_string(), dating)
            })
            .collect();
    }

    s.findings = judge(&s);
    s
}

#[cfg(not(target_os = "windows"))]
pub fn sweep(_enumerate: bool) -> Sweep {
    Sweep {
        unreadable: vec![(
            "all".into(),
            "this build does not run on Windows, so no channel was read".into(),
        )],
        ..Default::default()
    }
}
