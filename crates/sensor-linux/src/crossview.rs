use std::fs;

use crate::rootkit::{Finding, Severity};

#[derive(Debug, Clone, Default)]
pub struct Report {

    pub findings: Vec<Finding>,

    pub available: bool,

    pub reason: Option<String>,

    pub raw_sockets: usize,

    pub packet_sockets: usize,

    pub loadavg_total: Option<u64>,

    pub tasks_seen: usize,

    pub io_uring_holders: usize,
}

fn count_raw_rows(text: &str) -> usize {
    text.lines()
        .skip(1)
        .filter(|l| !l.trim().is_empty())
        .count()
}

fn count_packet_rows(text: &str) -> usize {
    text.lines()
        .filter(|l| {
            let t = l.trim();
            !t.is_empty() && !t.starts_with("sk ") && !t.starts_with("sk\t")
        })
        .count()
}

fn hidepid_of(mountinfo: &str) -> Option<String> {
    for line in mountinfo.lines() {

        let mut fields = line.split(" - ");
        let (before, after) = (fields.next()?, fields.next()?);
        let mount_point = before.split_whitespace().nth(4)?;
        if mount_point != "/proc" {
            continue;
        }

        let super_opts = after.split_whitespace().nth(2)?;
        for opt in super_opts.split(',') {
            if let Some(v) = opt.strip_prefix("hidepid=") {
                return Some(v.to_string());
            }
        }
    }
    None
}

fn kernel_task_total() -> Option<u64> {
    crate::saferead::read_kernel_text("/proc/loadavg").ok().and_then(|s| loadavg_total(&s))
}

fn loadavg_total(text: &str) -> Option<u64> {
    let field = text.split_whitespace().nth(3)?;
    field.split('/').nth(1)?.parse().ok()
}

fn enumerate_tasks() -> usize {
    let Ok(dir) = fs::read_dir("/proc") else {
        return 0;
    };
    let mut n = 0usize;
    for entry in dir.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if name.bytes().all(|b| b.is_ascii_digit()) {
            match fs::read_dir(format!("/proc/{name}/task")) {
                Ok(t) => n += t.flatten().count(),

                Err(_) => n += 1,
            }
        }
    }
    n
}

fn task_view_blind(
    nested_pid_ns: bool,
    hidepid: Option<&str>,
    euid: Option<u32>,
) -> Option<&'static str> {
    if nested_pid_ns {
        return Some(
            "this process is in a non-root PID namespace, so /proc lists only its own tasks \
             while /proc/loadavg counts every thread on the host",
        );
    }
    if hidepid.is_some_and(|h| h != "0" && h != "off") && euid != Some(0) {
        return Some(
            "/proc is mounted with hidepid and this run is not root, so other users' tasks are \
             hidden from the walk while /proc/loadavg still counts them",
        );
    }
    None
}

fn hidden_task_finding(kernel_total: u64, seen: usize, margin: u64) -> Option<Finding> {
    let missing = kernel_total.saturating_sub(seen as u64);
    if missing <= margin {
        return None;
    }
    Some(Finding {
        severity: Severity::Warn,
        subject: "hidden tasks (loadavg cross-view)".into(),
        what: format!(
            "the kernel reports {kernel_total} threads but a /proc walk enumerated only {seen} \
             ({missing} more than can be seen, past a {margin}-thread race margin)"
        ),
        why: "the kernel's own thread counter exceeds what /proc lists, which is the shape of a \
              task hidden by DKOM — a rootkit that unlinked a task from the list /proc walks but \
              left it counted (the red team's KernelKraken hides processes this way). A lead, not \
              proof: a burst of short-lived threads can widen the gap momentarily; re-run to \
              confirm it is stable, and hunt the task with the kernel-level view"
            .into(),
    })
}

fn io_uring_holders_from(links: &[(u32, Vec<String>)]) -> Vec<u32> {
    let mut out = Vec::new();
    for (pid, targets) in links {
        if targets.iter().any(|t| t.contains("anon_inode:[io_uring]")) {
            out.push(*pid);
        }
    }
    out
}

fn read_fd_links() -> Vec<(u32, Vec<String>)> {
    let mut out = Vec::new();
    let Ok(dir) = fs::read_dir("/proc") else {
        return out;
    };
    for entry in dir.flatten() {
        let name = entry.file_name();
        let Some(pid) = name.to_str().and_then(|n| n.parse::<u32>().ok()) else {
            continue;
        };
        let Ok(fds) = fs::read_dir(format!("/proc/{pid}/fd")) else {
            continue;
        };
        let mut targets = Vec::new();
        for fd in fds.flatten() {
            if let Ok(t) = fs::read_link(fd.path()) {
                targets.push(t.to_string_lossy().into_owned());
            }
        }
        if !targets.is_empty() {
            out.push((pid, targets));
        }
    }
    out
}

fn skip_findings(skipped: &[(&str, &str)]) -> Vec<Finding> {
    skipped
        .iter()
        .map(|(check, why)| Finding {
            severity: Severity::Note,
            subject: format!("{check} cross-view skipped"),
            what: format!("the {check} check did not run"),
            why: format!(
                "{why}. This is 'could not look', not 'nothing there' — the other cross-views \
                 in this report say nothing about what this one would have seen"
            ),
        })
        .collect()
}

pub fn report() -> Report {
    let mut report = Report::default();
    let mut findings = Vec::new();
    let mut skipped: Vec<(&str, &str)> = Vec::new();

    let mut net_read = false;
    for path in ["/proc/net/raw", "/proc/net/raw6"] {
        if let Ok(t) = crate::saferead::read_kernel_text(path) {
            net_read = true;
            report.raw_sockets += count_raw_rows(&t);
        }
    }
    if let Ok(t) = crate::saferead::read_kernel_text("/proc/net/packet") {
        net_read = true;
        report.packet_sockets = count_packet_rows(&t);
    }
    if !net_read {
        skipped.push((
            "raw / AF_PACKET sockets",
            "/proc/net/raw, /proc/net/raw6 and /proc/net/packet were all unreadable",
        ));
    }
    if net_read {
        report.available = true;
        if report.packet_sockets > 0 {
            findings.push(Finding {
                severity: Severity::Warn,
                subject: "AF_PACKET socket(s)".into(),
                what: format!(
                    "{} AF_PACKET socket(s) open (/proc/net/packet), which `overview` does not read",
                    report.packet_sockets
                ),
                why: "a raw AF_PACKET socket reads frames off the wire without a listening TCP \
                      port or an established connection — the shape of watershell-style C2 that \
                      the tcp/udp socket view is blind to. Legitimate users exist (dhcp clients, \
                      tcpdump, container networking), so confirm the owning process; an \
                      unexpected one on a server is the finding"
                    .into(),
            });
        }
        if report.raw_sockets > 0 {
            findings.push(Finding {
                severity: Severity::Note,
                subject: "raw socket(s)".into(),
                what: format!("{} SOCK_RAW socket(s) open (/proc/net/raw)", report.raw_sockets),
                why: "raw sockets are the ping/traceroute family and are usually benign, but they \
                      are a channel `overview` does not enumerate; noted so a responder can \
                      reconcile them against expected processes"
                    .into(),
            });
        }
    }

    let mut hidepid = None;
    match crate::saferead::read_kernel_text("/proc/self/mountinfo") {
        Err(_) => skipped.push(("hidepid", "/proc/self/mountinfo was unreadable")),
        Ok(mi) => {
            report.available = true;
            hidepid = hidepid_of(&mi);
            if let Some(level) = &hidepid {
                if level == "2" || level == "invisible" {
                    findings.push(Finding {
                        severity: Severity::Note,
                        subject: "hidepid on /proc".into(),
                        what: format!("/proc is mounted hidepid={level}"),
                        why: "with hidepid=2 the process cross-views cannot see other users' \
                              processes, so a clean result from them is not coverage — re-run as \
                              root to see the whole process table"
                            .into(),
                    });
                }
            }
        }
    }

    let blind = task_view_blind(
        crate::kwalk::in_nested_pid_namespace(),
        hidepid.as_deref(),
        crate::kernposture::euid(),
    );
    if let Some(why) = blind {
        skipped.push(("hidden-task cross-view", why));
    } else if let Some(total) = kernel_task_total() {
        report.available = true;
        report.loadavg_total = Some(total);

        let seen = enumerate_tasks();
        report.tasks_seen = seen;
        let total2 = kernel_task_total().unwrap_or(total);
        let kernel = total.min(total2);
        if let Some(f) = hidden_task_finding(kernel, seen, 24) {
            findings.push(f);
        }
    } else {
        skipped.push((
            "hidden-task cross-view",
            "/proc/loadavg was unreadable or its thread total could not be parsed",
        ));
    }

    let links = read_fd_links();
    if links.is_empty() {
        skipped.push((
            "io_uring",
            "no /proc/*/fd link could be read — this needs root to see other users' descriptors",
        ));
    }
    if !links.is_empty() {
        report.available = true;
        let holders = io_uring_holders_from(&links);
        report.io_uring_holders = holders.len();
        if !holders.is_empty() {
            let sample = holders.iter().take(8).map(u32::to_string).collect::<Vec<_>>().join(", ");
            findings.push(Finding {
                severity: Severity::Note,
                subject: "io_uring in use".into(),
                what: format!(
                    "{} process(es) hold an io_uring fd: {sample}",
                    holders.len()
                ),
                why: "io_uring performs file and network I/O without the read/write/openat/connect \
                      syscalls the hook scans watch, so an implant using it evades those checks. \
                      Legitimate high-performance services use it too; noted so a responder can \
                      confirm the holders are expected"
                    .into(),
            });
        }
    }

    findings.extend(skip_findings(&skipped));

    if !report.available {
        report.reason = Some("/proc/net, /proc/loadavg and /proc/self/mountinfo were all unreadable".into());
    }
    findings.sort_by_key(|f| std::cmp::Reverse(f.severity));
    report.findings = findings;
    report
}
