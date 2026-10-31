use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::triage::{rank, Coverage, Finding, Severity};

use super::catalogue::CATALOGUE;
use super::Category;
use super::dialects::{
    apt_hook_commands, directives, payload_of, sshd_directive, truncate, unknown_nss_modules,
};
use super::places::suspicious_location;
use super::shapes::{beacon_shape, suspicion, tmpfiles_suspicion};
use super::walk::{boot_time, dead_link, distinct_files, files_in_all, mtime, per_user_files, presence, home_dirs_with_gap, read_scan_target_bounded, tree_under_all, DeadLink, Presence};
use super::{Mechanism, Observation, Probe, Report};

pub(super) const UNIT_FILES: &[&str] =
    &["systemd-system", "systemd-dropins", "systemd-user", "systemd-user-system", "systemd-timers"];

pub(super) fn scan_file(
    m: &Mechanism,
    path: &Path,
    boot: Option<u64>,
    vouch: &mut dyn FnMut(&Path) -> Option<String>,
    findings: &mut Vec<Finding>,
) -> bool {
    let display = path.display().to_string();

    match dead_link(path) {
        Some(DeadLink::Masked) => {
            findings.push(Finding::info(m.id, display, "masked — a link to /dev/null, which runs nothing"));
            return true;
        }
        Some(DeadLink::Dangling(to)) => {
            findings.push(Finding::flag(
                Severity::Note,
                m.id,
                display,
                format!("a link to {}, which does not exist", to.display()),
                "an entry pointing at something that is gone runs nothing today. It is what a \
                 package removed without purging leaves behind, and also what an entry whose \
                 payload was deleted — or will be put back — looks like",
            ));
            return true;
        }
        Some(DeadLink::Directory(to)) => {
            findings.push(directory_link(m, path, display, &to));
            return true;
        }
        None => {}
    }
    let Some((text, truncated)) = read_scan_target_bounded(path) else {
        return false;
    };

    if truncated {
        findings.push(Finding::flag(
            Severity::Warn,
            m.id,
            display.clone(),
            "only the first 4 MiB of this file was examined",
            "the file is larger than the scan cap, so the checks below cover its beginning \
             and say nothing about the rest. A persistence entry appended past the cap is \
             a known way to sit behind it; read the whole file by hand",
        ));
    }

    if let Some(why) = suspicious_location(&display) {
        findings.push(Finding::flag(
            Severity::Critical,
            m.id,
            display.clone(),
            "a persistence entry in an unexpected place",
            why,
        ));
    }

    if let (Some(b), Some(m_at)) = (boot, mtime(path)) {
        if m_at > b {
            let age = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs().saturating_sub(m_at))
                .unwrap_or(0);
            findings.push(Finding::flag(
                Severity::Note,
                m.id,
                display.clone(),
                format!("modified {age}s ago, after this host booted"),
                "a persistence file written since boot is a lead: it is what a change made \
                 during the incident looks like. A package update looks the same, so \
                 corroborate before acting",
            ));
        }
    }

    let folded;
    let lines = if UNIT_FILES.contains(&m.id) {
        folded = crate::services::logical_lines(&text).join("\n");
        directives(&folded)
    } else {
        directives(&text)
    };
    let mut flagged = false;

    let mut judged: Vec<Finding> = Vec::new();
    for line in &lines {

        if m.id == "tmpfiles-d" {
            break;
        }

        if m.id == "ld-preload" {
            break;
        }

        if m.id == "pkg-hooks" {
            break;
        }
        let Some(payload) = payload_of(line) else { continue };
        if let Some(why) = suspicion(payload) {
            flagged = true;
            judged.push(Finding::flag(
                Severity::Critical,
                m.id,
                display.clone(),
                truncate(line, 160),
                why,
            ));
            continue;
        }

        if let Some(why) = beacon_shape(payload) {
            flagged = true;
            judged.push(Finding::flag(
                Severity::Warn,
                m.id,
                display.clone(),
                truncate(line, 160),
                why,
            ));
        }
    }

    if m.id == "ld-preload" {
        for line in &lines {
            flagged = true;
            findings.push(Finding::flag(
                Severity::Critical,
                m.id,
                display.clone(),
                format!("forces every dynamically-linked process to load {}", truncate(line, 120)),
                "a global LD_PRELOAD is the install point for a userland rootkit, and the file \
                 is normally absent on a server — any entry is presumed hostile until explained",
            ));
        }
    }

    if m.id == "nsswitch" {
        for line in &lines {
            for module in unknown_nss_modules(line) {
                flagged = true;
                findings.push(Finding::flag(
                    Severity::Warn,
                    m.id,
                    display.clone(),
                    format!(
                        "names an NSS module nothing recognises: `{module}` — every process \
                         resolving a user, group or host will dlopen libnss_{module}.so"
                    ),
                    "a module here is loaded into most processes on the box, several of them \
                     root, and unlike LD_PRELOAD it needs no environment variable to survive a \
                     reboot. Enterprise integrations do add modules, so confirm this one was \
                     installed on purpose and that libnss_<name>.so comes from a package — a \
                     lead, not a verdict",
                ));
            }
        }
    }

    if m.id == "tmpfiles-d" {
        for line in &lines {
            if let Some(why) = tmpfiles_suspicion(&display, line) {
                flagged = true;
                findings.push(Finding::flag(
                    Severity::Critical,
                    m.id,
                    display.clone(),
                    truncate(line, 160),
                    why,
                ));
            }
        }
    }

    if matches!(m.id, "sshd-config" | "sshd-config-d") {
        for line in &lines {
            let mut parts = line.splitn(2, char::is_whitespace);
            let Some(key) = parts.next() else { continue };
            let value = parts.next().unwrap_or("").trim();

            let (key, value) = match key.split_once('=') {
                Some((k, v)) if value.is_empty() => (k, v),
                _ => (key, value),
            };
            if let Some((sev, what, why)) = sshd_directive(key, value) {
                flagged = true;
                findings.push(Finding::flag(sev, m.id, display.clone(), what, why));
            }
        }
    }

    if m.id == "pkg-hooks" {
        for line in &lines {
            let cmds = apt_hook_commands(line);
            let payloads: Vec<&str> = if cmds.is_empty() {
                payload_of(line).into_iter().collect()
            } else {
                cmds.iter().map(String::as_str).collect()
            };
            for cmd in payloads {
                if let Some(why) = suspicion(cmd) {
                    flagged = true;
                    judged.push(Finding::flag(
                        Severity::Critical,
                        m.id,
                        display.clone(),
                        truncate(line, 160),
                        why,
                    ));
                } else if let Some(why) = beacon_shape(cmd) {
                    flagged = true;
                    judged.push(Finding::flag(
                        Severity::Warn,
                        m.id,
                        display.clone(),
                        truncate(line, 160),
                        why,
                    ));
                }
            }
        }
    }

    if !judged.is_empty() && m.category != Category::Auth {
        if let Some(pkg) = vouch(path) {
            let unchanged = read_scan_target_bounded(path)
                .is_some_and(|(again, cut)| cut == truncated && again == text);
            if unchanged {
                judged = judged.into_iter().map(|f| vouched(f, &pkg)).collect();
            }
        }
    }
    findings.append(&mut judged);

    if !flagged && !lines.is_empty() {
        findings.push(inventory_finding(m.category, m.id, &display, lines.len()));
    }
    true
}

pub(super) fn inventory_finding(
    category: Category,
    id: &'static str,
    display: &str,
    entries: usize,
) -> Finding {
    if category == Category::Auth {
        return Finding::flag(
            Severity::Note,
            id,
            display.to_string(),
            format!("{entries} entr(y/ies) — read them"),
            "an entry here grants access directly, and nothing in this sweep can tell one an \
             administrator added from one an intruder did. It is never offered for removal for \
             that reason, which is also why it has to be read rather than counted",
        );
    }
    Finding::info(id, display.to_string(), format!("{entries} directive line(s)"))
}

pub(super) fn directory_link(m: &Mechanism, path: &Path, display: String, to: &Path) -> Finding {
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or_default();

    let target = match path.canonicalize() {
        Ok(real) if real != to => format!("{} ({})", to.display(), real.display()),
        _ => to.display().to_string(),
    };
    if let Some((reader, why)) = reads_directory_named(m.id, name) {
        return Finding::flag(
            Severity::Warn,
            m.id,
            display,
            format!("a link to the directory {target}, which {reader}"),
            why,
        );
    }
    Finding::flag(
        Severity::Note,
        m.id,
        display,
        format!("a link to the directory {target}"),
        "a directory is not an entry here: what reads this place takes the files in it and \
         passes over a directory, so nothing behind this link runs from here, and it is not a \
         path this sweep was refused. It is named because a link is put there by someone — one \
         back to `.` or a parent is a way to send a recursive reader in circles",
    )
}

pub(super) fn reads_directory_named(mech_id: &str, name: &str) -> Option<(&'static str, &'static str)> {
    const UNIT_SUFFIXES: &[&str] = &[
        ".service", ".socket", ".device", ".mount", ".automount", ".swap", ".target", ".path",
        ".timer", ".slice", ".scope",
    ];
    let named = |suffixes: &[&str]| suffixes.iter().any(|s| name.len() > s.len() && name.ends_with(s));
    if UNIT_FILES.contains(&mech_id) && named(&[".d", ".wants", ".requires", ".upholds"]) {
        return Some((
            "systemd follows and reads as part of the unit it is named for",
            "systemd follows a link with this name, so what is behind it is loaded as part of \
             that unit as if it were here, and a package does not ship one. Read what it points at",
        ));
    }
    if UNIT_FILES.contains(&mech_id) && named(UNIT_SUFFIXES) {
        return Some((
            "systemd takes for the unit of that name, and cannot load",
            "an entry with a unit's name in a unit directory is that unit to systemd, so a \
             directory here is a unit that fails to load — and a unit of the same name further \
             along the search path, the package's own, is shadowed by it. Read what it points at, \
             and whether a unit by that name should be running",
        ));
    }
    if mech_id == "sshd-config-d" && named(&[".conf"]) {
        return Some((
            "sshd's `Include` of sshd_config.d/*.conf reads as configuration",
            "sshd reads every name its Include pattern matches as configuration, and a directory \
             is not one: what sshd makes of it at its next start is not something to find out \
             then. Read what it points at, and test the configuration with `sshd -t`",
        ));
    }
    if mech_id == "networkmanager-dispatcher" && ["pre-up.d", "pre-down.d", "no-wait.d"].contains(&name) {
        return Some((
            "NetworkManager's dispatcher runs the scripts in",
            "the dispatcher follows a link with this name and runs what is behind it as root on \
             every interface change, and a package does not ship one. Read what it points at",
        ));
    }
    if mech_id == "systemd-linger" {
        return Some((
            "logind takes, like any entry here, as that account lingering",
            "a lingering account's user services start at boot and keep running with nobody \
             logged in, and `loginctl enable-linger` writes an empty file here, never a link. \
             Read what that account runs",
        ));
    }
    None
}

pub(super) fn vouched(f: Finding, package: &str) -> Finding {
    Finding {
        severity: Severity::Note,
        why: format!(
            "{} — but the package manager says this file is exactly as `{package}` shipped it, \
             so the line is the package's own rather than one added to it, and nothing is \
             offered for removal. That answer comes from the host's own package database, which \
             root can rewrite: if this line is not in the package's copy, the database was \
             altered too",
            f.why
        ),
        ..f
    }
}

pub(super) fn rerun_advice(elevated: bool) -> &'static str {
    if elevated {
        "This sweep already ran as root, so re-running will not reach the paths that refused: a \
         path that is not a regular file (a FIFO, socket or device is never opened), a mount that \
         did not answer, or a security module's rule refuses even root. Look at each by hand"
    } else {
        "Re-run as root"
    }
}

pub(super) fn verdict(any_path_existed: bool, any_read: bool, entries: usize, refused: usize) -> Coverage {
    if !any_path_existed {

        Coverage::NotPresent
    } else if !any_read {

        Coverage::Unreadable
    } else if refused > 0 {

        Coverage::Partial
    } else if entries > 0 {
        Coverage::Populated
    } else {
        Coverage::Clean
    }
}

pub fn report() -> Report {
    let boot = boot_time();
    let (homes, homes_gap) = home_dirs_with_gap();
    let elevated = crate::kernposture::euid() == Some(0);

    let mut vouching = crate::pkg::Vouching::default();
    let mut findings = Vec::new();
    let mut observations = Vec::new();

    let mut budget = 20_000usize;

    for m in CATALOGUE {
        let mut entries = 0usize;
        let mut refused = Vec::new();
        let mut any_path_existed = false;
        let mut any_read = false;

        let targets: Vec<PathBuf> = match m.probe {
            Probe::Files(paths) => distinct_files(paths),
            Probe::FilesIn(dirs) => {
                let walked = files_in_all(dirs);
                any_path_existed |= walked.any_existed;
                any_read |= walked.any_read;
                refused.extend(walked.refused);
                walked.files
            }
            Probe::TreeUnder(dirs) => {
                let walked = tree_under_all(dirs, &mut budget);
                any_path_existed |= walked.any_existed;
                any_read |= walked.any_read;
                refused.extend(walked.refused);
                walked.files
            }
            Probe::PerUser(rels) => {

                if let Some(gap) = &homes_gap {
                    any_path_existed = true;
                    refused.push(gap.clone());
                }
                let walked = per_user_files(rels, &homes);
                any_path_existed |= walked.any_existed;
                any_read |= walked.any_read;
                refused.extend(walked.refused);
                walked.files
            }
        };

        for path in targets {
            match presence(&path) {
                Presence::Absent => continue,
                Presence::Unknown => {
                    any_path_existed = true;
                    refused.push(path.display().to_string());
                    continue;
                }
                Presence::Present => {}
            }
            any_path_existed = true;
            if scan_file(m, &path, boot, &mut |p| vouching.vouches_for(p), &mut findings) {
                any_read = true;
                entries += 1;
            } else {
                refused.push(path.display().to_string());
            }
        }

        let coverage = verdict(any_path_existed, any_read, entries, refused.len());

        if coverage == Coverage::Unreadable {
            findings.push(Finding::flag(
                Severity::Warn,
                m.id,
                refused.first().cloned().unwrap_or_else(|| m.name.to_string()),
                "exists but could not be read",
                format!(
                    "this mechanism is NOT clean, it is unchecked. {}; until then treat this \
                     surface as unexamined",
                    rerun_advice(elevated)
                ),
            ));
        }

        if coverage == Coverage::Partial {
            let n = refused.len();
            findings.push(Finding::flag(
                Severity::Warn,
                m.id,
                refused.first().cloned().unwrap_or_else(|| m.name.to_string()),
                format!("read in part: {n} path(s) refused"),
                format!(
                    "the paths that refused are unexamined, not clean, and what was found in \
                     the rest says nothing about them. {}; until then treat this mechanism as \
                     searched only where it let us look",
                    rerun_advice(elevated)
                ),
            ));
        }

        observations.push(Observation {
            id: m.id,
            name: m.name,
            category: m.category,
            coverage,
            entries,
            refused,
        });
    }

    let established = observations.iter().filter(|o| o.coverage.established()).count();
    let total = observations.len();
    dedupe(&mut findings);
    rank(&mut findings);
    Report { observations, findings, established, total }
}

pub(super) fn dedupe(findings: &mut Vec<Finding>) {
    let mut seen = std::collections::BTreeSet::new();
    findings.retain(|f| seen.insert((f.locus.clone(), f.what.clone())));
}
