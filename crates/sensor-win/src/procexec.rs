use hs_core::event::{fields, FieldMap, FieldName, FieldValue};
use hs_core::{Event, EventKind, Origin, Provenance, Stamp};
use hs_core::time::{BootId, MonoTime, WallTime};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Source {

    Security4688,

    Sysmon1,
}

impl Source {

    pub const ALL: [Source; 2] = [Source::Sysmon1, Source::Security4688];

    pub const fn channel(self) -> &'static str {
        match self {
            Source::Security4688 => "Security",
            Source::Sysmon1 => "Microsoft-Windows-Sysmon/Operational",
        }
    }

    pub const fn event_id(self) -> u16 {
        match self {
            Source::Security4688 => 4688,
            Source::Sysmon1 => 1,
        }
    }

    pub const fn name(self) -> &'static str {
        match self {
            Source::Security4688 => "Security 4688",
            Source::Sysmon1 => "Sysmon 1",
        }
    }

    pub const fn provenance(self) -> Provenance {
        match self {
            Source::Security4688 => Provenance::EventLog(4688),
            Source::Sysmon1 => Provenance::Sysmon(1),
        }
    }

    pub const fn provider(self) -> u128 {
        match self {
            Source::Security4688 => crate::provenance::SECURITY_AUDITING,
            Source::Sysmon1 => SYSMON_PROVIDER,
        }
    }
}

pub const SYSMON_PROVIDER: u128 = 0x5770_385f_c22a_43e0_bf4c_06f5_698f_fbd9;

pub const MAPPING: &[(FieldName, Option<&str>, Option<&str>)] = &[
    (fields::IMAGE, Some("NewProcessName"), Some("Image")),
    (fields::COMMAND_LINE, Some("CommandLine"), Some("CommandLine")),
    (fields::PARENT_IMAGE, Some("ParentProcessName"), Some("ParentImage")),
    (fields::PARENT_COMMAND_LINE, None, Some("ParentCommandLine")),
    (fields::USER, Some("TargetUserSid/Name, else SubjectUserSid/Name"), Some("User")),
    (fields::INTEGRITY_LEVEL, Some("MandatoryLabel"), Some("IntegrityLevel")),
    (fields::PROCESS_ID, Some("NewProcessId"), Some("ProcessId")),
    (fields::PARENT_PROCESS_ID, Some("ProcessId"), Some("ParentProcessId")),
];

#[must_use]
pub fn origin_of(source: Source, field: FieldName) -> Option<&'static str> {
    MAPPING.iter().find(|(f, _, _)| *f == field).and_then(|(_, a, b)| match source {
        Source::Security4688 => *a,
        Source::Sysmon1 => *b,
    })
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Raw4688 {

    pub record_id: u64,

    pub version: Option<u64>,

    pub time: Option<i64>,

    pub new_process_name: Option<String>,

    pub command_line: Option<String>,

    pub parent_process_name: Option<String>,

    pub new_process_id: Option<u64>,

    pub process_id: Option<u64>,

    pub subject_sid: Option<String>,

    pub subject_name: Option<String>,

    pub subject_domain: Option<String>,

    pub target_sid: Option<String>,

    pub target_name: Option<String>,

    pub target_domain: Option<String>,

    pub mandatory_label: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RawSysmon1 {

    pub record_id: u64,

    pub version: Option<u64>,

    pub time: Option<i64>,

    pub image: Option<String>,

    pub command_line: Option<String>,

    pub parent_image: Option<String>,

    pub parent_command_line: Option<String>,

    pub process_id: Option<u64>,

    pub parent_process_id: Option<u64>,

    pub user: Option<String>,

    pub integrity_level: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcStart {

    pub source: Source,

    pub record_id: u64,

    pub version: Option<u64>,

    pub time: Option<i64>,

    pub image: Option<String>,

    pub command_line: Option<String>,

    pub parent_image: Option<String>,

    pub parent_command_line: Option<String>,

    pub user: Option<String>,

    pub integrity: Option<String>,

    pub pid: Option<u64>,

    pub ppid: Option<u64>,

    pub lacks: Vec<(FieldName, &'static str)>,
}

fn present(v: Option<&String>) -> Option<String> {
    v.map(|s| s.trim()).filter(|s| !s.is_empty() && *s != "-").map(str::to_string)
}

#[must_use]
pub fn integrity_word(label: &str) -> String {
    let word = match label.trim().to_ascii_uppercase().as_str() {
        "S-1-16-0" => "Untrusted",
        "S-1-16-4096" => "Low",
        "S-1-16-8192" => "Medium",
        "S-1-16-8448" => "MediumPlus",
        "S-1-16-12288" => "High",
        "S-1-16-16384" => "System",
        "S-1-16-20480" => "Protected",
        _ => return label.trim().to_string(),
    };
    word.to_string()
}

fn well_known(sid: &str) -> Option<&'static str> {
    match sid.trim().to_ascii_uppercase().as_str() {
        "S-1-5-18" => Some(r"NT AUTHORITY\SYSTEM"),
        "S-1-5-19" => Some(r"NT AUTHORITY\LOCAL SERVICE"),
        "S-1-5-20" => Some(r"NT AUTHORITY\NETWORK SERVICE"),
        _ => None,
    }
}

fn account(sid: Option<&String>, domain: Option<&String>, name: Option<&String>) -> Option<String> {
    if let Some(n) = sid.and_then(|s| well_known(s)) {
        return Some(n.to_string());
    }
    match (present(domain), present(name)) {
        (Some(d), Some(n)) => Some(format!(r"{d}\{n}")),
        (None, Some(n)) => Some(n),
        _ => present(sid),
    }
}

#[must_use]
pub fn user_4688(r: &Raw4688) -> Option<String> {
    let target_set = present(r.target_sid.as_ref()).is_some_and(|s| s != "S-1-0-0");
    if target_set {
        account(r.target_sid.as_ref(), r.target_domain.as_ref(), r.target_name.as_ref())
    } else {
        account(r.subject_sid.as_ref(), r.subject_domain.as_ref(), r.subject_name.as_ref())
    }
}

#[must_use]
pub fn from_4688(r: &Raw4688, cmdline_policy: Option<bool>) -> ProcStart {
    let v = r.version;
    let mut lacks: Vec<(FieldName, &'static str)> = Vec::new();

    let command_line = present(r.command_line.as_ref());
    if command_line.is_none() {
        lacks.push((
            fields::COMMAND_LINE,
            match (v, cmdline_policy) {
                (Some(0), _) => "4688 version 0 has no CommandLine field",
                (_, Some(false)) => {
                    "ProcessCreationIncludeCmdLine_Enabled is off, so 4688 writes an empty \
                     CommandLine"
                }
                (_, Some(true)) => {
                    "this record's CommandLine is empty: it was written while \
                     ProcessCreationIncludeCmdLine_Enabled was off"
                }
                (_, None) => {
                    "this record's CommandLine is empty, and whether \
                     ProcessCreationIncludeCmdLine_Enabled is set could not be read"
                }
            },
        ));
    }
    let parent_image = present(r.parent_process_name.as_ref());
    if parent_image.is_none() {
        lacks.push((
            fields::PARENT_IMAGE,
            if v.is_some_and(|v| v < 2) {
                "4688 before version 2 (Windows 10, Server 2016) has no ParentProcessName"
            } else {
                "this record's ParentProcessName is empty"
            },
        ));
    }
    lacks.push((fields::PARENT_COMMAND_LINE, "4688 does not record the parent's command line"));
    let integrity = present(r.mandatory_label.as_ref()).map(|l| integrity_word(&l));
    if integrity.is_none() {
        lacks.push((
            fields::INTEGRITY_LEVEL,
            if v.is_some_and(|v| v < 2) {
                "4688 before version 2 has no MandatoryLabel"
            } else {
                "this record's MandatoryLabel is empty"
            },
        ));
    }
    let image = present(r.new_process_name.as_ref());
    if image.is_none() {
        lacks.push((fields::IMAGE, "this record's NewProcessName is empty"));
    }
    let user = user_4688(r);
    if user.is_none() {
        lacks.push((fields::USER, "this record names no subject or target account"));
    }
    if r.new_process_id.is_none() {
        lacks.push((fields::PROCESS_ID, "this record's NewProcessId did not render"));
    }
    if r.process_id.is_none() {
        lacks.push((fields::PARENT_PROCESS_ID, "this record's ProcessId did not render"));
    }

    ProcStart {
        source: Source::Security4688,
        record_id: r.record_id,
        version: v,
        time: r.time,
        image,
        command_line,
        parent_image,
        parent_command_line: None,
        user,
        integrity,
        pid: r.new_process_id,
        ppid: r.process_id,
        lacks,
    }
}

#[must_use]
pub fn from_sysmon1(r: &RawSysmon1) -> ProcStart {
    let mut lacks: Vec<(FieldName, &'static str)> = Vec::new();
    let mut take = |field: FieldName, v: Option<&String>| {
        let got = present(v);
        if got.is_none() {
            lacks.push((field, "this Sysmon record's value is empty or `-`"));
        }
        got
    };
    let image = take(fields::IMAGE, r.image.as_ref());
    let command_line = take(fields::COMMAND_LINE, r.command_line.as_ref());
    let parent_image = take(fields::PARENT_IMAGE, r.parent_image.as_ref());
    let parent_command_line = take(fields::PARENT_COMMAND_LINE, r.parent_command_line.as_ref());
    let user = take(fields::USER, r.user.as_ref());
    let integrity = take(fields::INTEGRITY_LEVEL, r.integrity_level.as_ref());
    if r.process_id.is_none() {
        lacks.push((fields::PROCESS_ID, "this Sysmon record's ProcessId did not render"));
    }
    if r.parent_process_id.is_none() {
        lacks.push((fields::PARENT_PROCESS_ID, "this Sysmon record's ParentProcessId did not render"));
    }
    ProcStart {
        source: Source::Sysmon1,
        record_id: r.record_id,
        version: r.version,
        time: r.time,
        image,
        command_line,
        parent_image,
        parent_command_line,
        user,
        integrity,
        pid: r.process_id,
        ppid: r.parent_process_id,
        lacks,
    }
}

pub const SAME_START_TICKS: i64 = 2 * 10_000_000;

#[must_use]
pub fn merge(sysmon: Vec<ProcStart>, security: Vec<ProcStart>) -> (Vec<ProcStart>, usize) {
    use std::collections::HashMap;
    let mut seen: HashMap<(u64, String), Vec<i64>> = HashMap::new();
    for s in &sysmon {
        if let (Some(pid), Some(img), Some(t)) = (s.pid, s.image.as_ref(), s.time) {
            seen.entry((pid, img.to_lowercase())).or_default().push(t);
        }
    }
    let mut out = sysmon;
    let mut dropped = 0;
    for s in security {
        let dup = match (s.pid, s.image.as_ref(), s.time) {
            (Some(pid), Some(img), Some(t)) => seen
                .get(&(pid, img.to_lowercase()))
                .is_some_and(|ts| ts.iter().any(|u| (u - t).abs() <= SAME_START_TICKS)),
            _ => false,
        };
        if dup {
            dropped += 1;
        } else {
            out.push(s);
        }
    }
    (out, dropped)
}

pub const CMDLINE_VALUE: &str = "ProcessCreationIncludeCmdLine_Enabled";

#[must_use]
pub fn cmdline_policy(values: Result<Vec<(String, String)>, u32>, dword: Option<u32>) -> Option<bool> {

    const NOT_FOUND: u32 = 2;
    if let Some(v) = dword {
        return Some(v != 0);
    }
    match values {
        Err(NOT_FOUND) => Some(false),
        Ok(v) if !v.iter().any(|(n, _)| n.eq_ignore_ascii_case(CMDLINE_VALUE)) => Some(false),
        _ => None,
    }
}

const FILETIME_UNIX: i64 = 116_444_736_000_000_000;

#[must_use]
pub fn unix_nanos(filetime: Option<i64>) -> i64 {
    filetime.map_or(0, |ft| ft.saturating_sub(FILETIME_UNIX).saturating_mul(100))
}

impl ProcStart {

    #[must_use]
    pub fn to_event(&self, seq: u64, boot: BootId, origin: Origin) -> Event {
        let mut f = FieldMap::new();
        let mut text = |name: FieldName, v: &Option<String>| {
            if let Some(s) = v {
                f.insert(name, FieldValue::Str(s.clone()));
            }
        };
        text(fields::IMAGE, &self.image);
        text(fields::COMMAND_LINE, &self.command_line);
        text(fields::USER, &self.user);
        if let Some(p) = self.pid {
            f.insert(fields::PROCESS_ID, FieldValue::U64(p));
        }
        if let Some(p) = self.ppid {
            f.insert(fields::PARENT_PROCESS_ID, FieldValue::U64(p));
        }
        let mut text = |name: FieldName, v: &Option<String>| {
            if let Some(s) = v {
                f.insert(name, FieldValue::Str(s.clone()));
            }
        };
        text(fields::PARENT_IMAGE, &self.parent_image);
        text(fields::PARENT_COMMAND_LINE, &self.parent_command_line);
        text(fields::INTEGRITY_LEVEL, &self.integrity);
        Event {
            seq,
            stamp: Stamp {
                mono: MonoTime::from_nanos(0),
                wall: WallTime::from_nanos(unix_nanos(self.time)),
                boot,
            },
            origin,
            lane: EventKind::ProcessCreate.default_lane(),
            kind: EventKind::ProcessCreate,
            provenance: self.source.provenance(),
            fields: f,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReadState {

    Read,

    Absent(String),

    NotBuilt(String),

    Failed(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceRead {

    pub source: Source,

    pub state: ReadState,

    pub records: usize,

    pub foreign: usize,

    pub capped: bool,

    pub span: Option<(i64, i64)>,

    pub lacks: Vec<(FieldName, &'static str, usize)>,
}

impl SourceRead {

    #[must_use]
    pub fn unread(source: Source, state: ReadState) -> Self {
        Self { source, state, records: 0, foreign: 0, capped: false, span: None, lacks: Vec::new() }
    }

    pub fn tally(&mut self, starts: &[ProcStart]) {
        self.records = starts.len();
        let times: Vec<i64> = starts.iter().filter_map(|s| s.time).collect();
        self.span = times.iter().min().zip(times.iter().max()).map(|(a, b)| (*a, *b));
        let mut lacks: Vec<(FieldName, &'static str, usize)> = Vec::new();
        for s in starts {
            for (f, why) in &s.lacks {
                match lacks.iter_mut().find(|(g, w, _)| g == f && w == why) {
                    Some(slot) => slot.2 += 1,
                    None => lacks.push((*f, why, 1)),
                }
            }
        }
        self.lacks = lacks;
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Collection {

    pub starts: Vec<ProcStart>,

    pub sources: Vec<SourceRead>,

    pub merged: usize,
}

impl Collection {

    #[must_use]
    pub fn failures(&self) -> Vec<String> {
        self.sources
            .iter()
            .filter_map(|s| match &s.state {
                ReadState::Failed(why) => Some(format!("{}: {why}", s.source.name())),
                _ => None,
            })
            .collect()
    }
}

pub const READ_CAP: usize = 50_000;

#[cfg(target_os = "windows")]
pub(crate) const PATHS_4688: [&str; 13] = [
    "Event/System/Version",
    "Event/EventData/Data[@Name='NewProcessName']",
    "Event/EventData/Data[@Name='CommandLine']",
    "Event/EventData/Data[@Name='ParentProcessName']",
    "Event/EventData/Data[@Name='NewProcessId']",
    "Event/EventData/Data[@Name='ProcessId']",
    "Event/EventData/Data[@Name='SubjectUserSid']",
    "Event/EventData/Data[@Name='SubjectUserName']",
    "Event/EventData/Data[@Name='SubjectDomainName']",
    "Event/EventData/Data[@Name='TargetUserSid']",
    "Event/EventData/Data[@Name='TargetUserName']",
    "Event/EventData/Data[@Name='TargetDomainName']",
    "Event/EventData/Data[@Name='MandatoryLabel']",
];

#[cfg(target_os = "windows")]
pub(crate) const PATHS_SYSMON1: [&str; 9] = [
    "Event/System/Version",
    "Event/EventData/Data[@Name='Image']",
    "Event/EventData/Data[@Name='CommandLine']",
    "Event/EventData/Data[@Name='ParentImage']",
    "Event/EventData/Data[@Name='ParentCommandLine']",
    "Event/EventData/Data[@Name='ProcessId']",
    "Event/EventData/Data[@Name='ParentProcessId']",
    "Event/EventData/Data[@Name='User']",
    "Event/EventData/Data[@Name='IntegrityLevel']",
];

pub fn xpath(source: Source) -> String {
    format!("*[System[(EventID={})]]", source.event_id())
}

#[cfg(target_os = "windows")]
pub(crate) fn raw_4688(r: &crate::evtlog::Rendered) -> Raw4688 {
    let t = |i: usize| r.extra(i).text().map(str::to_string);
    Raw4688 {
        record_id: r.id,
        version: r.extra(0).uint(),
        time: r.at,
        new_process_name: t(1),
        command_line: t(2),
        parent_process_name: t(3),
        new_process_id: r.extra(4).uint(),
        process_id: r.extra(5).uint(),
        subject_sid: t(6),
        subject_name: t(7),
        subject_domain: t(8),
        target_sid: t(9),
        target_name: t(10),
        target_domain: t(11),
        mandatory_label: t(12),
    }
}

#[cfg(target_os = "windows")]
pub(crate) fn raw_sysmon1(r: &crate::evtlog::Rendered) -> RawSysmon1 {
    let t = |i: usize| r.extra(i).text().map(str::to_string);
    RawSysmon1 {
        record_id: r.id,
        version: r.extra(0).uint(),
        time: r.at,
        image: t(1),
        command_line: t(2),
        parent_image: t(3),
        parent_command_line: t(4),
        process_id: r.extra(5).uint(),
        parent_process_id: r.extra(6).uint(),
        user: t(7),
        integrity_level: t(8),
    }
}

#[cfg(target_os = "windows")]
fn read_source(
    source: Source,
    paths: &[&str],
    cap: usize,
) -> Result<(Vec<crate::evtlog::Rendered>, usize), String> {
    let all = crate::evtlog::read_records(source.channel(), &xpath(source), cap, paths)?;
    let total = all.len();
    let own: Vec<_> =
        all.into_iter().filter(|r| crate::evtlog::from_provider(r.provider, source.provider())).collect();
    let foreign = total - own.len();
    Ok((own, foreign))
}

#[cfg(target_os = "windows")]
fn read_4688(cap: usize) -> (Vec<ProcStart>, SourceRead) {
    let source = Source::Security4688;
    let audited = crate::evtlog::read_process_creation_audit();
    let policy = crate::evtlog::command_line_policy();
    let (rendered, foreign) = match read_source(source, &PATHS_4688, cap) {
        Ok(r) => r,
        Err(why) => return (Vec::new(), SourceRead::unread(source, ReadState::Failed(why))),
    };
    let starts: Vec<ProcStart> = rendered.iter().map(|r| from_4688(&raw_4688(r), policy)).collect();
    let mut read = SourceRead::unread(source, ReadState::Read);
    read.foreign = foreign;
    read.capped = rendered.len() >= cap;
    read.tally(&starts);
    if starts.is_empty() {
        read.state = match audited {
            Ok(false) => ReadState::Absent(
                "Process Creation is not audited, so Security holds no 4688. \
                 `auditpol /set /subcategory:{0CCE922B-69AE-11D9-BED3-505054503030} /success:enable` \
                 turns it on"
                    .into(),
            ),
            Ok(true) => ReadState::Absent("Process Creation is audited and Security holds no 4688".into()),
            Err(why) => ReadState::Failed(format!(
                "Security holds no 4688, and whether Process Creation is audited could not be read: {why}"
            )),
        };
    }
    (starts, read)
}

#[cfg(target_os = "windows")]
fn read_sysmon1(cap: usize) -> (Vec<ProcStart>, SourceRead) {
    use crate::evtlog::ChannelConfig;
    let source = Source::Sysmon1;
    match crate::evtlog::read_channel_config(source.channel()) {
        ChannelConfig::Absent => {
            return (
                Vec::new(),
                SourceRead::unread(source, ReadState::Absent("Sysmon is not installed: its channel does not exist".into())),
            )
        }
        ChannelConfig::Unreadable(rc) => {
            return (
                Vec::new(),
                SourceRead::unread(
                    source,
                    ReadState::Failed(format!("whether Sysmon's channel exists could not be read (error {rc})")),
                ),
            )
        }
        ChannelConfig::Found(false, _, _) => {
            return (
                Vec::new(),
                SourceRead::unread(source, ReadState::Failed("Sysmon's channel exists and is disabled".into())),
            )
        }
        ChannelConfig::Found(true, _, _) => {}
    }
    let (rendered, foreign) = match read_source(source, &PATHS_SYSMON1, cap) {
        Ok(r) => r,
        Err(why) => return (Vec::new(), SourceRead::unread(source, ReadState::Failed(why))),
    };
    let starts: Vec<ProcStart> = rendered.iter().map(|r| from_sysmon1(&raw_sysmon1(r))).collect();
    let mut read = SourceRead::unread(source, ReadState::Read);
    read.foreign = foreign;
    read.capped = rendered.len() >= cap;
    read.tally(&starts);
    if starts.is_empty() {
        read.state = ReadState::Absent(
            "Sysmon's channel holds no event 1: its configuration does not record process starts, \
             or none were written since the channel last rolled over"
                .into(),
        );
    }
    (starts, read)
}

#[cfg(target_os = "windows")]
pub fn collect(security: Result<(), String>, sysmon: Result<(), String>, cap: usize) -> Collection {
    let (s_starts, s_read) = match sysmon {
        Ok(()) => read_sysmon1(cap),
        Err(why) => (Vec::new(), SourceRead::unread(Source::Sysmon1, ReadState::NotBuilt(why))),
    };
    let (a_starts, a_read) = match security {
        Ok(()) => read_4688(cap),
        Err(why) => (Vec::new(), SourceRead::unread(Source::Security4688, ReadState::NotBuilt(why))),
    };
    let (starts, merged) = merge(s_starts, a_starts);
    Collection { starts, sources: vec![s_read, a_read], merged }
}

#[cfg(not(target_os = "windows"))]
pub fn collect(_security: Result<(), String>, _sysmon: Result<(), String>, _cap: usize) -> Collection {
    let why = || ReadState::Failed("this build does not run on Windows, so no channel was read".into());
    Collection {
        starts: Vec::new(),
        sources: Source::ALL.iter().map(|s| SourceRead::unread(*s, why())).collect(),
        merged: 0,
    }
}
