use std::collections::BTreeMap;

use crate::posture::{Finding, Severity};
use crate::provenance::{self, Chronology, Dating, Install, Mark};

pub mod reason {

    pub const DATA_OVERWRITE: u32 = 0x0000_0001;

    pub const DATA_EXTEND: u32 = 0x0000_0002;

    pub const DATA_TRUNCATION: u32 = 0x0000_0004;

    pub const FILE_CREATE: u32 = 0x0000_0100;

    pub const FILE_DELETE: u32 = 0x0000_0200;

    pub const SECURITY_CHANGE: u32 = 0x0000_0800;

    pub const RENAME_OLD_NAME: u32 = 0x0000_1000;

    pub const RENAME_NEW_NAME: u32 = 0x0000_2000;

    pub const STREAM_CHANGE: u32 = 0x0020_0000;

    pub const CLOSE: u32 = 0x8000_0000;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {

    pub usn: i64,

    pub file_ref: u64,

    pub parent_ref: u64,

    pub timestamp: i64,

    pub reason: u32,

    pub attributes: u32,

    pub name: String,
}

impl Record {

    pub fn looks_executable(&self) -> bool {
        const RUNS: &[&str] = &[
            ".exe", ".dll", ".sys", ".scr", ".com", ".ps1", ".bat", ".cmd", ".vbs", ".js",
            ".wsf", ".hta", ".jar", ".msi", ".cpl", ".ocx",
        ];
        let lower = self.name.to_ascii_lowercase();
        RUNS.iter().any(|e| lower.ends_with(e))
    }
}

pub fn describe_reason(mask: u32) -> String {
    let mut parts: Vec<&str> = Vec::new();
    for (bit, word) in [
        (reason::FILE_CREATE, "created"),
        (reason::FILE_DELETE, "deleted"),
        (reason::RENAME_OLD_NAME, "renamed from"),
        (reason::RENAME_NEW_NAME, "renamed to"),
        (reason::DATA_OVERWRITE, "overwritten"),
        (reason::DATA_EXTEND, "extended"),
        (reason::DATA_TRUNCATION, "truncated"),
        (reason::SECURITY_CHANGE, "permissions changed"),
        (reason::STREAM_CHANGE, "alternate data stream changed"),
    ] {
        if mask & bit != 0 {
            parts.push(word);
        }
    }
    if parts.is_empty() {
        return format!("reason {mask:#010x}");
    }
    parts.join(", ")
}

pub fn parse_records(buf: &[u8]) -> Vec<Record> {
    const PREFIX: usize = 8;
    const MIN: usize = 60;
    let mut out = Vec::new();
    let mut at = PREFIX;
    while at + MIN <= buf.len() {
        let rec = &buf[at..];
        let len = u32::from_le_bytes([rec[0], rec[1], rec[2], rec[3]]) as usize;
        if len < MIN || at + len > buf.len() {
            break;
        }
        let r = &rec[..len];
        let major = u16::from_le_bytes([r[4], r[5]]);
        if major != 2 {

            at += len;
            continue;
        }
        let u64_at = |o: usize| {
            u64::from_le_bytes([r[o], r[o+1], r[o+2], r[o+3], r[o+4], r[o+5], r[o+6], r[o+7]])
        };
        let i64_at = |o: usize| u64_at(o) as i64;
        let u32_at = |o: usize| u32::from_le_bytes([r[o], r[o+1], r[o+2], r[o+3]]);
        let u16_at = |o: usize| u16::from_le_bytes([r[o], r[o+1]]);

        let name_len = u16_at(56) as usize;
        let name_off = u16_at(58) as usize;
        let name = if name_off >= MIN && name_off + name_len <= len && name_len.is_multiple_of(2) {
            let (pairs, _odd) = r[name_off..name_off + name_len].as_chunks::<2>();
            let units: Vec<u16> = pairs.iter().copied().map(u16::from_le_bytes).collect();
            String::from_utf16_lossy(&units)
        } else {
            String::new()
        };

        out.push(Record {
            file_ref: u64_at(8),
            parent_ref: u64_at(16),
            usn: i64_at(24),
            timestamp: i64_at(32),
            reason: u32_at(40),
            attributes: u32_at(52),
            name,
        });
        at += len;
    }
    out
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Lifecycle {

    CreatedThenDeleted,

    Created,

    Deleted,

    Renamed {

        from: String,

        to: String,
    },

    Modified,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileStory {

    pub file_ref: u64,

    pub name: String,

    pub lifecycle: Lifecycle,

    pub first_usn: i64,

    pub last_usn: i64,

    pub last_at: i64,

    pub first_at: i64,

    pub parent_ref: u64,

    pub origin_ref: u64,

    pub reasons: u32,
}

pub fn stories(records: &[Record]) -> Vec<FileStory> {
    let mut by_ref: BTreeMap<u64, Vec<&Record>> = BTreeMap::new();
    for r in records {
        by_ref.entry(r.file_ref).or_default().push(r);
    }

    let mut out = Vec::new();
    for (file_ref, mut rs) in by_ref {
        rs.sort_by_key(|r| r.usn);
        let reasons = rs.iter().fold(0_u32, |a, r| a | r.reason);
        let created = reasons & reason::FILE_CREATE != 0;
        let deleted = reasons & reason::FILE_DELETE != 0;

        let old_name = rs
            .iter()
            .find(|r| r.reason & reason::RENAME_OLD_NAME != 0)
            .map(|r| r.name.clone());
        let new_name = rs
            .iter()
            .find(|r| r.reason & reason::RENAME_NEW_NAME != 0)
            .map(|r| r.name.clone());

        let lifecycle = match (created, deleted, &old_name, &new_name) {
            (true, true, _, _) => Lifecycle::CreatedThenDeleted,
            (true, false, _, _) => Lifecycle::Created,
            (false, true, _, _) => Lifecycle::Deleted,
            (false, false, Some(f), Some(t)) => {
                Lifecycle::Renamed { from: f.clone(), to: t.clone() }
            }
            _ => Lifecycle::Modified,
        };

        let name = rs
            .iter()
            .rev()
            .find(|r| !r.name.is_empty())
            .map_or_else(String::new, |r| r.name.clone());

        out.push(FileStory {
            file_ref,
            name,
            lifecycle,
            first_usn: rs.first().map_or(0, |r| r.usn),
            last_usn: rs.last().map_or(0, |r| r.usn),
            last_at: rs.iter().map(|r| r.timestamp).max().unwrap_or(0),
            first_at: rs.iter().map(|r| r.timestamp).min().unwrap_or(0),
            parent_ref: rs.last().map_or(0, |r| r.parent_ref),
            origin_ref: rs.first().map_or(0, |r| r.parent_ref),
            reasons,
        });
    }
    out
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct JournalData {

    pub journal_id: u64,

    pub first_usn: i64,

    pub next_usn: i64,

    pub lowest_valid_usn: i64,

    pub maximum_size: u64,

    pub allocation_delta: u64,
}

impl JournalData {

    pub const fn span(&self) -> i64 {
        self.next_usn.saturating_sub(self.first_usn)
    }
}

pub const MIN_USEFUL_JOURNAL: u64 = 32 * 1024 * 1024;

pub const JOURNAL_FIRST_RECORD: i64 = 24 * 3600 * provenance::TICK;

const PLAUSIBLE_ID: i64 = provenance::filetime_from_unix(978_307_200);

pub fn journal_predates_install<'a>(
    j: &JournalData,
    dating: &'a Dating,
) -> Result<(i64, &'a Chronology), String> {
    let created = i64::try_from(j.journal_id).unwrap_or(i64::MAX);
    let Dating::Dated(c) = dating else {
        return dating.predates(0, created).map(|c| (created, c));
    };
    if created < PLAUSIBLE_ID {
        return Err(format!(
            "the journal id read as a time is {}, which is not a plausible creation time. Reading \
             the id as one is observed NTFS behaviour rather than documented, so an id that does \
             not look like a time dates nothing",
            provenance::utc(created)
        ));
    }
    if created > c.earliest.at + provenance::BOOT_SLACK
        || c.earliest.at - created > JOURNAL_FIRST_RECORD
    {
        return Err(format!(
            "the journal id read as a time is {} and its oldest record is dated {}. A journal \
             is created just before its first record, so the id is not dating this journal",
            provenance::utc(created),
            provenance::utc(c.earliest.at)
        ));
    }
    dating.predates(c.earliest.seq, created.max(c.earliest.at)).map(|c| (created, c))
}

pub fn judge_journal(volume: &str, j: Option<&JournalData>, dating: &Dating) -> Vec<Finding> {
    let Some(j) = j else {
        return vec![Finding {
            severity: Severity::Critical,
            subject: format!("usn:{volume}"),
            what: "the change journal is not active on this volume".into(),
            why: "nothing is recording creates, deletes or renames here, so the question \"what \
                  was deleted\" cannot be answered for this volume at all — not by this tool and \
                  not by any other. A journal that is off on a system volume is unusual enough \
                  to explain: `fsutil usn deleteJournal /D` turns it off in one command and is \
                  a standard step for an intruder who has finished"
                .into(),
            fix: Some(format!("fsutil usn createJournal m=32000000 a=8000000 {volume}")),
        }];
    };

    let mut f = Vec::new();

    if j.first_usn == 0 && j.next_usn > 0 {
        f.push(match journal_predates_install(j, dating) {
            Ok((created, c)) => Finding {
                severity: Severity::Warn,
                subject: format!("usn:{volume} — likely image preparation"),
                what: format!(
                    "the journal's history starts at USN 0 because it was created at {}, before \
                     this clone first booted, while the image it was cloned from was prepared",
                    provenance::utc(created)
                ),
                why: format!(
                    "the journal id, read as a time, is when the journal was created. It is older \
                     than this installation, the oldest record agrees with it, and the journal's \
                     own numbering puts that record before the clone's first boot. So this is \
                     likely the image's journal carried into the clone, not one deleted since. \
                     {} {}",
                    c.evidence(),
                    provenance::FAKEABLE
                ),
                fix: None,
            },
            Err(why) => Finding {
                severity: Severity::Critical,
                subject: format!("usn:{volume}"),
                what: format!(
                    "the journal's history starts at USN 0 — it holds {} bytes of change and \
                     nothing before it",
                    j.span()
                ),
                why: format!(
                    "a journal recreated from scratch starts at zero. On a volume that has been \
                     in use for any length of time that means the previous journal was deleted, \
                     which is `fsutil usn deleteJournal /D` and takes a second. The answer to \
                     \"what was deleted on this volume\" was itself deleted; check the journal \
                     id against any earlier collection from this host. Nothing places it \
                     before this installation, as a sysprepped image's journal would be: {why}"
                ),
                fix: None,
            },
        });
    }

    if j.maximum_size > 0 && j.maximum_size < MIN_USEFUL_JOURNAL {
        f.push(Finding {
            severity: Severity::Warn,
            subject: format!("usn:{volume}"),
            what: format!(
                "the journal is capped at {} MB, below the {} MB default",
                j.maximum_size / (1024 * 1024),
                MIN_USEFUL_JOURNAL / (1024 * 1024)
            ),
            why: "a small journal wraps in minutes on a busy volume, which destroys history \
                  just as effectively as deleting it and leaves no obvious trace of having been \
                  done. Whatever happened before the wrap is gone"
                .into(),
            fix: Some(format!("fsutil usn createJournal m=32000000 a=8000000 {volume}")),
        });
    }

    f
}

fn windows_own_churn(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();

    if lower.starts_with("__psscriptpolicytest_") {
        return true;
    }

    if lower.ends_with("provider.dll") {
        return true;
    }

    matches!(
        lower.as_str(),
        "dismhost.exe" | "dismcore.dll" | "dismcoreps.dll" | "dismprov.dll" | "servicingcommon.dll"
    )
}

pub fn judge_story(s: &FileStory) -> Option<Finding> {
    judge_story_against(s, &Dating::default())
}

pub fn judge_story_against(s: &FileStory, dating: &Dating) -> Option<Finding> {
    judge_dated(s, dating).map(|(f, _)| f)
}

fn judge_dated(s: &FileStory, dating: &Dating) -> Option<(Finding, bool)> {

    if windows_own_churn(&s.name) {
        return None;
    }
    let mut f = judge_lifecycle(s)?;
    let mut dated = false;
    match dating.predates(u64::try_from(s.last_usn).unwrap_or(u64::MAX), s.last_at) {
        Ok(c) => {
            dated = true;
            f.severity = f.severity.min(Severity::Warn);
            f.subject = format!("{} — likely image preparation", f.subject);
            f.what = format!(
                "{}, at {}, before this clone first booted, while the image it was cloned from \
                 was prepared",
                f.what,
                provenance::utc(s.last_at)
            );
            f.why = format!(
                "building and generalizing an image installs and services Windows, which \
                 creates and deletes executables by the hundred. Every record of this file is \
                 dated before the clone's first boot, and the journal's own numbering puts it \
                 before that boot as well. {} {}",
                c.evidence(),
                provenance::FAKEABLE
            );
        }
        Err(why) if f.severity == Severity::Critical => {
            let sep = if f.why.ends_with('.') { " " } else { ". " };
            f.why = format!("{}{sep}It is not dated before this installation: {why}", f.why);
        }
        Err(_) => {}
    }
    Some((f, dated))
}

fn judge_lifecycle(s: &FileStory) -> Option<Finding> {
    match &s.lifecycle {
        Lifecycle::CreatedThenDeleted if s.name.to_ascii_lowercase().ends_with(".exe")
            || executable_name(&s.name) =>
        {
            Some(Finding {
                severity: Severity::Critical,
                subject: format!("usn:{}", s.name),
                what: format!(
                    "`{}` was created and then deleted inside the journal window (USN {}..{})",
                    s.name, s.first_usn, s.last_usn
                ),
                why: "a file that runs, appears and disappears is the shape of a payload that \
                      cleans up after itself. There is nothing left on disk to hash, verify or \
                      look up — this record is the only evidence it existed. The parent \
                      directory reference is in the record if you need to place it"
                    .into(),
                fix: None,
            })
        }
        Lifecycle::Deleted if executable_name(&s.name) => Some(Finding {
            severity: Severity::Warn,
            subject: format!("usn:{}", s.name),
            what: format!("`{}` was deleted (USN {})", s.name, s.last_usn),
            why: "it existed before this journal window began, so how it got there is outside \
                  what this can answer. Worth placing against the timeline: a deletion during \
                  the intrusion window is cleanup, and the same deletion a month earlier is \
                  housekeeping"
                .into(),
            fix: None,
        }),
        _ => None,
    }
}

pub fn executable_name(name: &str) -> bool {
    Record {
        usn: 0,
        file_ref: 0,
        parent_ref: 0,
        timestamp: 0,
        reason: 0,
        attributes: 0,
        name: name.to_string(),
    }
    .looks_executable()
}

#[derive(Debug, Clone, Default)]
pub struct Sweep {

    pub volume: String,

    pub journal: Option<JournalData>,

    pub error: Option<String>,

    pub stories: Vec<FileStory>,

    pub records_read: usize,

    pub read: Option<(i64, i64)>,

    pub truncated: bool,

    pub dating: Dating,

    pub defender: Vec<DefenderUpdate>,

    pub defender_unread: Option<String>,

    pub diagnostics: Vec<DiagnosticRun>,

    pub diagnostics_unread: Option<String>,

    pub system_root: Option<String>,

    pub parents: BTreeMap<u64, String>,

    pub present: BTreeMap<u64, String>,

    pub findings: Vec<Finding>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DefenderUpdate {

    pub event_id: u32,

    pub record: u64,

    pub at: i64,

    pub sid: String,

    pub temp: Option<String>,
}

pub const UPDATE_SLACK: i64 = 10 * 10_000_000;

pub fn defender_update_for<'a>(
    s: &FileStory,
    parent: Option<&str>,
    updates: &'a [DefenderUpdate],
) -> Option<&'a DefenderUpdate> {
    let norm = |p: &str| p.trim_start_matches(r"\\?\").trim_end_matches('\\').to_ascii_lowercase();
    let parent = norm(parent?);
    updates.iter().find(|u| {
        u.at >= s.first_at.saturating_sub(UPDATE_SLACK)
            && u.at <= s.last_at.saturating_add(UPDATE_SLACK)
            && u.temp.as_deref().is_some_and(|t| norm(t) == parent)
    })
}

pub fn attribute_to_defender(f: &mut Finding, s: &FileStory, parent: &str, u: &DefenderUpdate) -> bool {
    if f.severity < Severity::Critical || s.lifecycle != Lifecycle::CreatedThenDeleted {
        return false;
    }
    f.severity = Severity::Warn;
    f.subject = format!("{} — likely a Defender update", f.subject);
    f.what = format!(
        "{}, in {parent}, in the same seconds as the Defender update it recorded at {} \
         (event {}, record {}, as {})",
        f.what,
        provenance::utc(u.at),
        u.event_id,
        u.record,
        u.sid
    );
    f.why = format!(
        "Defender's updater unpacks each update package into the temp directory of the account \
         it runs as, runs it and deletes it, and records the attempt in its Operational channel. \
         Here that record names {sid}, this file was in {sid}'s temp directory, and the two are \
         within {slack} s of each other. The name is not what lowered this: a file of any name \
         in that directory with no update beside it stays Critical. It is a Warn and not \
         nothing because an administrator can produce the same pair — start a signature update \
         and drop and run a payload there in the same moment — so on a host somebody untrusted \
         administers, read it as one",
        sid = u.sid,
        slack = UPDATE_SLACK / 10_000_000
    );
    true
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiagnosticRun {

    pub record: u64,

    pub started: i64,

    pub finished: Option<i64>,

    pub package_path: String,

    pub package_id: Option<String>,

    pub sid: Option<String>,

    pub temp: Option<String>,

    pub package_files: Option<Vec<String>>,
}

pub const DIAG_SLACK: i64 = 10 * 10_000_000;

pub fn is_sdiag_dir(name: &str) -> bool {
    let Some(g) = name.get(..6).filter(|p| p.eq_ignore_ascii_case("SDIAG_")).and(name.get(6..)) else {
        return false;
    };
    g.len() == 36
        && g.char_indices().all(|(i, c)| if matches!(i, 8 | 13 | 18 | 23) { c == '-' } else { c.is_ascii_hexdigit() })
}

fn norm_path(p: &str) -> String {
    p.trim_start_matches(r"\\?\").trim_end_matches('\\').to_ascii_lowercase()
}

pub fn diagnostic_run_for<'a>(
    s: &FileStory,
    stories: &[FileStory],
    parents: &BTreeMap<u64, String>,
    system_root: Option<&str>,
    runs: &'a [DiagnosticRun],
) -> Option<(&'a DiagnosticRun, String)> {
    let root = norm_path(system_root?);
    let dir = stories.iter().find(|d| d.file_ref == s.parent_ref)?;
    if dir.lifecycle != Lifecycle::CreatedThenDeleted || !is_sdiag_dir(&dir.name) {
        return None;
    }
    let holder = parents.get(&dir.parent_ref)?;
    let holder_n = norm_path(holder);
    let name = s.name.to_ascii_lowercase();
    let run = runs.iter().find(|r| {
        let lo = r.started.saturating_sub(DIAG_SLACK);
        let hi = r.finished.unwrap_or(r.started).saturating_add(DIAG_SLACK);
        let inside = |st: &FileStory| st.first_at >= lo && st.last_at <= hi;
        let temp_ok = holder_n == format!(r"{root}\temp")
            || r.temp.as_deref().is_some_and(|t| norm_path(t) == holder_n);
        let package_ok = norm_path(&r.package_path).starts_with(&format!(r"{root}\diagnostics\"));
        let named = r.package_files.as_ref().is_some_and(|f| f.contains(&name));
        inside(s) && inside(dir) && temp_ok && package_ok && named
    })?;
    Some((run, format!(r"{}\{}", holder.trim_start_matches(r"\\?\").trim_end_matches('\\'), dir.name)))
}

pub fn attribute_to_diagnostic(f: &mut Finding, s: &FileStory, folder: &str, run: &DiagnosticRun) -> bool {
    if f.severity < Severity::Critical || s.lifecycle != Lifecycle::CreatedThenDeleted {
        return false;
    }
    f.severity = Severity::Warn;
    f.subject = format!("{} — likely a Windows scripted diagnostic", f.subject);
    f.what = format!(
        "{}, in {folder}, during the scripted diagnostic run of {} recorded at {}{} \
         (Diagnosis-Scripted event 101, record {}{})",
        f.what,
        run.package_path,
        provenance::utc(run.started),
        run.finished.map_or_else(String::new, |e| format!(" to {}", provenance::utc(e))),
        run.record,
        run.sid.as_deref().map_or_else(String::new, |s| format!(", as {s}"))
    );
    f.why = format!(
        "the scripted diagnostic engine copies a package from %SystemRoot%\\diagnostics into a new \
         SDIAG_<guid> directory in a temp directory, runs its scripts and deletes the directory, \
         and records the run in its Operational channel. Here the journal shows this file and \
         that directory created and deleted inside the recorded run (within {slack} s), the \
         directory's parent is a temp directory the engine uses, and a file of this name is in \
         the package the run names. No one of those lowered this: a script of the same name \
         anywhere else, or outside a recorded run, stays Critical. It is a Warn and not nothing \
         because an administrator can start a diagnostic and drop a script into that directory \
         in the same second",
        slack = DIAG_SLACK / 10_000_000
    );
    true
}

pub fn successor_candidates<'a>(s: &FileStory, idx: &StoryIndex<'a>) -> Vec<&'a FileStory> {
    if s.lifecycle != Lifecycle::Deleted {
        return Vec::new();
    }
    let Some(old_dir) = idx.by_ref.get(&s.parent_ref) else { return Vec::new() };
    if !matches!(old_dir.lifecycle, Lifecycle::Deleted | Lifecycle::CreatedThenDeleted) || old_dir.origin_ref == 0 {
        return Vec::new();
    }
    let home = old_dir.origin_ref;
    idx.created_named(&s.name)
        .iter()
        .copied()
        .filter(|n| n.file_ref != s.file_ref && n.first_usn < s.last_usn)
        .filter(|n| {
            idx.by_ref.get(&n.parent_ref).is_some_and(|d| {
                d.lifecycle == Lifecycle::Created && d.file_ref != old_dir.file_ref && d.parent_ref == home
            })
        })
        .collect()
}

pub fn successor_for<'a, 'p>(
    s: &FileStory,
    idx: &StoryIndex<'a>,
    present: &'p BTreeMap<u64, String>,
) -> Option<(&'a FileStory, &'p str)> {
    successor_candidates(s, idx)
        .into_iter()
        .find_map(|n| present.get(&n.file_ref).map(|p| (n, p.as_str())))
}

pub struct StoryIndex<'a> {

    pub by_ref: BTreeMap<u64, &'a FileStory>,

    created: BTreeMap<String, Vec<&'a FileStory>>,
}

impl<'a> StoryIndex<'a> {

    pub fn new(stories: &'a [FileStory]) -> Self {
        let mut created: BTreeMap<String, Vec<&FileStory>> = BTreeMap::new();
        for st in stories.iter().filter(|st| st.lifecycle == Lifecycle::Created && executable_name(&st.name)) {
            created.entry(st.name.to_ascii_lowercase()).or_default().push(st);
        }
        StoryIndex { by_ref: stories.iter().map(|st| (st.file_ref, st)).collect(), created }
    }

    fn created_named(&self, name: &str) -> &[&'a FileStory] {
        self.created.get(&name.to_ascii_lowercase()).map_or(&[], Vec::as_slice)
    }
}

pub fn attribute_to_successor(f: &mut Finding, s: &FileStory, successor: &FileStory, at: &str) -> bool {
    if f.severity != Severity::Warn || s.lifecycle != Lifecycle::Deleted {
        return false;
    }
    let at = at.trim_start_matches(r"\\?\");
    f.severity = Severity::Note;
    f.subject = format!("{} — replaced by a newer copy", f.subject);
    f.what = format!(
        "{}, with the directory it was in; a file of the same name was created earlier, in a new \
         directory beside that one, and is there now: {at} (USN {})",
        f.what, successor.first_usn
    );
    f.why = format!(
        "side-by-side servicing replaces a file by directory: ngen recompiling a native image, \
         the GAC and versioned application directories write the new copy into a new directory \
         beside the old one and then remove the old directory. The journal shows that here: \
         this file's directory was deleted, and a file of this name was created before it went \
         in a sibling directory that is still there. The copy that replaced it is on disk at \
         {at}, where the filesystem sweeps can read, hash and verify it. The name did not \
         lower this: a file deleted from a directory that stays, or with no successor beside \
         it, is still a Warn. It is a Note and not nothing because an administrator can stage \
         the same shape"
    );
    true
}

impl Sweep {

    pub const fn complete(&self) -> bool {
        self.error.is_none() && self.journal.is_some() && !self.truncated
    }

    pub fn coverage(&self) -> String {
        match (&self.journal, &self.error) {
            (_, Some(e)) => format!(
                "{}: the change journal could NOT be read ({e}), so nothing about deleted files \
                 on this volume has been established",
                self.volume
            ),
            (None, None) => format!(
                "{}: no change journal is active, so what was deleted here cannot be answered \
                 by anything",
                self.volume
            ),
            (Some(j), None) => {

                let (from, to) = self.read.unwrap_or((j.first_usn, j.next_usn));
                let mut s = format!(
                    "{}: read {} record(s) covering USN {}..{to}",
                    self.volume,
                    self.records_read,
                    from.max(j.first_usn)
                );
                if self.truncated && from > j.first_usn {
                    s.push_str(&format!(
                        " — the journal holds more than one read walks, so this read took its \
                         newest end: records OLDER than USN {from}, back to {}, were NOT examined",
                        j.first_usn
                    ));
                }
                if self.truncated && to < j.next_usn {
                    s.push_str(&format!(
                        " — the read stopped at its bound before the end of the journal, so \
                         records NEWER than USN {to} were NOT examined"
                    ));
                }
                s
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fold {

    ImageVanished,

    ImageDeleted,

    Defender,

    Diagnostic,

    Replaced,
}

impl Fold {

    const fn text(self) -> (&'static str, &'static str) {
        match self {
            Fold::ImageVanished => (
                "executables created and deleted — likely image preparation",
                "each created and then deleted inside the journal window, every record of it dated \
                 before this clone first booted",
            ),
            Fold::ImageDeleted => (
                "executables deleted — likely image preparation",
                "each existed before the journal window and was deleted before this clone first \
                 booted",
            ),
            Fold::Defender => (
                "update packages — likely a Defender update",
                "each created and deleted in the temp directory of the account a Defender update \
                 ran as, within seconds of the update Defender recorded",
            ),
            Fold::Diagnostic => (
                "diagnostic scripts — likely a Windows scripted diagnostic",
                "each unpacked, run and deleted inside a scripted diagnostic run the engine recorded",
            ),
            Fold::Replaced => (
                "executables deleted — replaced by a newer copy",
                "each deleted with its directory after a file of the same name was created in a new \
                 directory beside it, which is on disk now",
            ),
        }
    }
}

struct Member<'a> {
    finding: Finding,
    story: &'a FileStory,
    tie: Option<String>,
}

fn fold_row(kind: Fold, members: &[Member<'_>]) -> Option<Finding> {
    let first = members.first()?;
    let (subject, each) = kind.text();
    let mut names: Vec<(&str, usize)> = Vec::new();
    for m in members {
        match names.iter_mut().find(|(n, _)| n.eq_ignore_ascii_case(&m.story.name)) {
            Some(slot) => slot.1 += 1,
            None => names.push((&m.story.name, 1)),
        }
    }
    let listed = names
        .iter()
        .map(|(n, c)| if *c > 1 { format!("{n} ×{c}") } else { (*n).to_string() })
        .collect::<Vec<_>>()
        .join(", ");
    let mut ties: Vec<&str> = Vec::new();
    for t in members.iter().filter_map(|m| m.tie.as_deref()) {
        if !ties.contains(&t) {
            ties.push(t);
        }
    }
    let from = members.iter().map(|m| m.story.first_at).min().unwrap_or(0);
    let to = members.iter().map(|m| m.story.last_at).max().unwrap_or(0);
    Some(Finding {
        severity: members.iter().map(|m| m.finding.severity).max().unwrap_or(first.finding.severity),
        subject: format!("usn:{subject}"),
        what: format!(
            "{} file(s) under {} name(s), {each}, between {} and {}: {listed}{}",
            members.len(),
            names.len(),
            provenance::utc(from),
            provenance::utc(to),
            if ties.is_empty() { String::new() } else { format!(". Tied by: {}", ties.join("; ")) }
        ),
        why: format!(
            "every one of these was lowered by its own evidence, the same kind for each, and it is \
             one row because of that and not because of how many there are: a file of the same \
             shape without that evidence is a row of its own. The reasoning, for the first of \
             them ({}): {}",
            first.story.name, first.finding.why
        ),
        fix: None,
    })
}

pub fn judge(s: &Sweep) -> Vec<Finding> {
    let partial;
    let dating = match whole_read(s) {
        Ok(()) => &s.dating,
        Err(why) => {
            partial = Dating::Undated(why);
            &partial
        }
    };
    let mut f = judge_journal(&s.volume, s.journal.as_ref(), dating);

    let idx = StoryIndex::new(&s.stories);
    let mut seen: Vec<(Finding, usize)> = Vec::new();
    let mut folds: Vec<(Fold, Vec<Member<'_>>)> = Vec::new();
    for st in &s.stories {
        let Some((mut finding, dated)) = judge_dated(st, dating) else { continue };
        let mut fold = dated.then_some(if st.lifecycle == Lifecycle::CreatedThenDeleted {
            Fold::ImageVanished
        } else {
            Fold::ImageDeleted
        });
        let mut tie = None;
        let parent = s.parents.get(&st.parent_ref).map(String::as_str);
        if let (Some(p), Some(u)) = (parent, defender_update_for(st, parent, &s.defender)) {
            if attribute_to_defender(&mut finding, st, p, u) {
                fold = Some(Fold::Defender);
                tie = Some(format!("event {} record {} at {}", u.event_id, u.record, provenance::utc(u.at)));
            }
        }
        if finding.severity == Severity::Critical {
            if let Some((run, folder)) =
                diagnostic_run_for(st, &s.stories, &s.parents, s.system_root.as_deref(), &s.diagnostics)
            {
                if attribute_to_diagnostic(&mut finding, st, &folder, run) {
                    fold = Some(Fold::Diagnostic);
                    tie = Some(format!("{} run, record {}", run.package_path, run.record));
                }
            }
        }
        if !dated {
            if let Some((successor, at)) = successor_for(st, &idx, &s.present) {
                if attribute_to_successor(&mut finding, st, successor, at) {
                    fold = Some(Fold::Replaced);
                }
            }
        }
        if let Some(kind) = fold {
            let m = Member { finding, story: st, tie };
            match folds.iter_mut().find(|(k, _)| *k == kind) {
                Some((_, ms)) => ms.push(m),
                None => folds.push((kind, vec![m])),
            }
        } else if let Some(slot) =
            seen.iter_mut().find(|(k, _)| k.severity == finding.severity && k.subject == finding.subject)
        {
            slot.1 += 1;
        } else {
            seen.push((finding, 1));
        }
    }

    f.extend(seen.into_iter().map(|(mut finding, n)| {
        if n > 1 {

            finding.what = format!(
                "{} — and {} more time(s) in this window, under different file references",
                finding.what,
                n - 1
            );
        }
        finding
    }));

    for (kind, mut ms) in folds {
        if ms.len() == 1 {
            f.extend(ms.pop().map(|m| m.finding));
        } else {
            f.extend(fold_row(kind, &ms));
        }
    }
    f
}

pub fn whole_read(s: &Sweep) -> Result<(), String> {
    if let Some(e) = &s.error {
        return Err(format!("the read of the journal stopped ({e})"));
    }
    let (Some(j), Some((from, to))) = (&s.journal, s.read) else {
        return Err("the journal was not read".into());
    };
    if from > j.first_usn {
        return Err(format!(
            "the read began at USN {from}, not at the journal's oldest record ({}), so the records \
             the clone's first boot is placed against were not all read",
            j.first_usn
        ));
    }
    if s.truncated || to < j.next_usn {
        return Err(format!(
            "the read stopped at USN {to} before the end of the journal ({}), so this boot was \
             not read in full",
            j.next_usn
        ));
    }
    Ok(())
}

pub fn date(records: &[Record], install: &Result<Install, String>) -> Dating {
    let marks: Vec<Mark> = records
        .iter()
        .filter_map(|r| Some(Mark { seq: u64::try_from(r.usn).ok()?, at: r.timestamp }))
        .collect();
    provenance::chronology(&marks, install, provenance::Log::Journal, Ok(()))
}

pub const MAX_JOURNAL_BYTES: usize = 64 * 1024 * 1024;

const JOURNAL_PAGE: i64 = 4096;

pub fn read_window(j: &JournalData, cap: usize) -> (i64, bool) {
    let cap = i64::try_from(cap).unwrap_or(i64::MAX);
    if j.span() <= cap {
        return (j.lowest_valid_usn, false);
    }
    let start = (j.next_usn.saturating_sub(cap) / JOURNAL_PAGE * JOURNAL_PAGE).max(j.first_usn);
    (start, start > j.first_usn)
}

const JOURNAL_ENTRY_DELETED: i32 = 1181;

pub fn retry_from_oldest(
    j: &JournalData,
    from: i64,
    records_read: usize,
    failed: Option<&std::io::Error>,
) -> bool {
    from > j.first_usn
        && records_read == 0
        && failed.is_some_and(|e| e.raw_os_error() != Some(JOURNAL_ENTRY_DELETED))
}

pub fn next_usn_prefix(buf: &[u8]) -> Option<i64> {
    buf.get(..8)?.try_into().ok().map(i64::from_le_bytes)
}

pub fn stopped_because(e: &std::io::Error, records_read: usize) -> String {

    if e.raw_os_error() == Some(JOURNAL_ENTRY_DELETED) {
        format!(
            "the journal wrapped past the record this read started from ({e}); records older \
             than the wrap are gone"
        )
    } else {
        format!("reading the journal failed after {records_read} record(s): {e}")
    }
}

#[cfg(target_os = "windows")]
const CHUNK: usize = 64 * 1024;

#[cfg(target_os = "windows")]
fn open_volume(volume: &str) -> Result<windows_sys::Win32::Foundation::HANDLE, String> {
    use windows_sys::Win32::Foundation::{GetLastError, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
    };
    use windows_sys::Win32::Foundation::GENERIC_READ;

    let path: Vec<u16> = format!(r"\\.\{}", volume.trim_end_matches('\\'))
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    let h = unsafe {
        CreateFileW(
            path.as_ptr(),
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            std::ptr::null(),
            OPEN_EXISTING,
            0,
            std::ptr::null_mut(),
        )
    };
    if h == INVALID_HANDLE_VALUE {

        let e = unsafe { GetLastError() };
        return Err(format!(
            "could not open the volume device (error {e}). The change journal FSCTLs are \
             volume-level and need Administrator; an ordinary user cannot open \\\\.\\{volume} \
             at all, which is a refusal rather than an empty journal"
        ));
    }
    Ok(h)
}

#[cfg(target_os = "windows")]
fn query_journal(
    h: windows_sys::Win32::Foundation::HANDLE,
) -> Result<Option<JournalData>, String> {
    use windows_sys::Win32::Foundation::GetLastError;
    use windows_sys::Win32::System::Ioctl::{FSCTL_QUERY_USN_JOURNAL, USN_JOURNAL_DATA_V0};
    use windows_sys::Win32::System::IO::DeviceIoControl;

    const NOT_ACTIVE: u32 = 1179;
    const DELETE_IN_PROGRESS: u32 = 1178;

    let mut data = USN_JOURNAL_DATA_V0::default();
    let mut returned: u32 = 0;

    let ok = unsafe {
        DeviceIoControl(
            h,
            FSCTL_QUERY_USN_JOURNAL,
            std::ptr::null(),
            0,
            std::ptr::addr_of_mut!(data).cast(),
            u32::try_from(std::mem::size_of::<USN_JOURNAL_DATA_V0>()).unwrap_or(0),
            std::ptr::addr_of_mut!(returned),
            std::ptr::null_mut(),
        )
    };
    if ok == 0 {

        let e = unsafe { GetLastError() };
        if e == NOT_ACTIVE || e == DELETE_IN_PROGRESS {
            return Ok(None);
        }
        return Err(format!("FSCTL_QUERY_USN_JOURNAL failed ({e})"));
    }
    Ok(Some(JournalData {
        journal_id: data.UsnJournalID,
        first_usn: data.FirstUsn,
        next_usn: data.NextUsn,
        lowest_valid_usn: data.LowestValidUsn,
        maximum_size: data.MaximumSize,
        allocation_delta: data.AllocationDelta,
    }))
}

#[cfg(target_os = "windows")]
fn read_journal(
    h: windows_sys::Win32::Foundation::HANDLE,
    j: &JournalData,
    from: i64,
    bound: usize,
) -> (Vec<Record>, i64, Option<std::io::Error>) {
    use windows_sys::Win32::System::Ioctl::{FSCTL_READ_USN_JOURNAL, READ_USN_JOURNAL_DATA_V0};
    use windows_sys::Win32::System::IO::DeviceIoControl;

    let mut out: Vec<Record> = Vec::new();
    let mut read_bytes = 0_usize;
    let mut start = from;
    let mut buf = vec![0_u8; CHUNK];

    loop {
        let req = READ_USN_JOURNAL_DATA_V0 {
            StartUsn: start,

            ReasonMask: u32::MAX,
            ReturnOnlyOnClose: 0,

            Timeout: 0,
            BytesToWaitFor: 0,
            UsnJournalID: j.journal_id,
        };
        let mut returned: u32 = 0;

        let ok = unsafe {
            DeviceIoControl(
                h,
                FSCTL_READ_USN_JOURNAL,
                std::ptr::addr_of!(req).cast(),
                u32::try_from(std::mem::size_of::<READ_USN_JOURNAL_DATA_V0>()).unwrap_or(0),
                buf.as_mut_ptr().cast(),
                u32::try_from(buf.len()).unwrap_or(0),
                std::ptr::addr_of_mut!(returned),
                std::ptr::null_mut(),
            )
        };

        if ok == 0 {
            return (out, start, Some(std::io::Error::last_os_error()));
        }
        let got = (returned as usize).min(buf.len());
        let answer = buf.get(..got).unwrap_or_default();

        let Some(next) = next_usn_prefix(answer) else { break };

        if got <= 8 {
            start = start.max(next);
            break;
        }
        read_bytes += got;
        out.extend(parse_records(answer));

        if next <= start {
            break;
        }
        start = next;
        if read_bytes >= bound {
            break;
        }
    }
    (out, start, None)
}

#[cfg(target_os = "windows")]
fn path_of_id(volume: windows_sys::Win32::Foundation::HANDLE, file_ref: u64) -> Option<String> {
    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Storage::FileSystem::{
        FileIdType, GetFinalPathNameByHandleW, OpenFileById, FILE_FLAG_BACKUP_SEMANTICS,
        FILE_ID_DESCRIPTOR, FILE_ID_DESCRIPTOR_0, FILE_NAME_NORMALIZED, FILE_READ_ATTRIBUTES,
        FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, VOLUME_NAME_DOS,
    };
    let id = FILE_ID_DESCRIPTOR {
        dwSize: core::mem::size_of::<FILE_ID_DESCRIPTOR>() as u32,
        Type: FileIdType,
        Anonymous: FILE_ID_DESCRIPTOR_0 { FileId: i64::from_ne_bytes(file_ref.to_ne_bytes()) },
    };

    let h = unsafe {
        OpenFileById(
            volume,
            &id,
            FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            core::ptr::null(),
            FILE_FLAG_BACKUP_SEMANTICS,
        )
    };
    if h == INVALID_HANDLE_VALUE || h.is_null() {
        return None;
    }
    let mut buf = vec![0_u16; 1024];

    let n = unsafe {
        GetFinalPathNameByHandleW(
            h,
            buf.as_mut_ptr(),
            buf.len() as u32,
            FILE_NAME_NORMALIZED | VOLUME_NAME_DOS,
        )
    };

    unsafe { CloseHandle(h) };
    let n = n as usize;
    (n > 0 && n < buf.len()).then(|| String::from_utf16_lossy(buf.get(..n).unwrap_or_default()))
}

#[cfg(target_os = "windows")]
pub fn journal_id(volume: &str) -> Result<Option<u64>, String> {
    use windows_sys::Win32::Foundation::CloseHandle;
    let h = open_volume(volume)?;
    let j = query_journal(h);

    unsafe { CloseHandle(h) };
    j.map(|j| j.map(|j| j.journal_id))
}

#[cfg(not(target_os = "windows"))]
pub fn journal_id(_volume: &str) -> Result<Option<u64>, String> {
    Err("this binary was not built for Windows".into())
}

#[cfg(target_os = "windows")]
pub fn sweep(volume: &str) -> Sweep {
    use windows_sys::Win32::Foundation::CloseHandle;

    let mut s = Sweep { volume: volume.to_string(), ..Default::default() };

    let h = match open_volume(volume) {
        Ok(h) => h,
        Err(e) => {
            s.error = Some(e);
            s.findings = judge(&s);
            return s;
        }
    };

    match query_journal(h) {
        Ok(Some(j)) => {
            s.journal = Some(j);
            let (mut from, mut skips_older) = read_window(&j, MAX_JOURNAL_BYTES);

            let (mut records, mut to, mut stopped) =
                read_journal(h, &j, from, 2 * MAX_JOURNAL_BYTES);

            if retry_from_oldest(&j, from, records.len(), stopped.as_ref()) {
                from = j.first_usn;
                skips_older = false;
                (records, to, stopped) = read_journal(h, &j, from, MAX_JOURNAL_BYTES);
            }
            s.records_read = records.len();
            s.read = Some((from, to));
            s.truncated = skips_older || to < j.next_usn;

            s.error = stopped.map(|e| stopped_because(&e, records.len()));
            s.stories = stories(&records);
            s.dating = date(&records, &provenance::install(&provenance::anchors()));

            let by_ref: BTreeMap<u64, &FileStory> = s.stories.iter().map(|st| (st.file_ref, st)).collect();
            let mut want: Vec<u64> = Vec::new();
            for st in &s.stories {
                let candidate = st.lifecycle == Lifecycle::CreatedThenDeleted
                    && judge_lifecycle(st).is_some_and(|f| f.severity == Severity::Critical);
                if candidate {
                    want.push(st.parent_ref);
                    if let Some(dir) = by_ref.get(&st.parent_ref).filter(|d| is_sdiag_dir(&d.name)) {
                        want.push(dir.parent_ref);
                    }
                }
            }
            for r in want {
                if let std::collections::btree_map::Entry::Vacant(slot) = s.parents.entry(r) {
                    if let Some(path) = path_of_id(h, r) {
                        slot.insert(path);
                    }
                }
            }

            let idx = StoryIndex::new(&s.stories);
            for st in s.stories.iter().filter(|st| st.lifecycle == Lifecycle::Deleted) {
                if judge_lifecycle(st).is_none() {
                    continue;
                }
                for n in successor_candidates(st, &idx) {
                    if let std::collections::btree_map::Entry::Vacant(slot) = s.present.entry(n.file_ref) {
                        if let Some(path) = path_of_id(h, n.file_ref) {
                            slot.insert(path);
                        }
                    }
                }
            }
            match crate::evtlog::defender_updates() {
                Ok(u) => s.defender = u,
                Err(e) => s.defender_unread = Some(e),
            }
            s.system_root = std::env::var("SystemRoot").ok();
            match crate::evtlog::diagnostic_runs() {
                Ok(r) => s.diagnostics = r,
                Err(e) => s.diagnostics_unread = Some(e),
            }
        }
        Ok(None) => {}
        Err(e) => s.error = Some(e),
    }

    unsafe { CloseHandle(h) };
    s.findings = judge(&s);
    s
}

#[cfg(not(target_os = "windows"))]
pub fn sweep(volume: &str) -> Sweep {
    Sweep {
        volume: volume.to_string(),
        error: Some("this build does not run on Windows, so no journal was read".into()),
        ..Default::default()
    }
}
