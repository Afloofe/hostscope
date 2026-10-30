use std::io::{BufRead as _, BufReader, Read};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{channel, Receiver, TryRecvError};
use std::time::{Duration, Instant};

use hemostat_tui::verbs::registry::REGISTRY;
use hemostat_tui::verbs::{Outcome, Platform, RunRequest, Running, TicketEnv, VerbHost, VerbItem, Verbs};

use crate::{modules, MANIFEST};

#[cfg(target_os = "linux")]
use crate::authz::TICKET_ENV;

#[cfg(not(target_os = "linux"))]
const TICKET_ENV: &str = "HEMOSTAT_TICKET";

#[cfg(any(target_os = "freebsd", test))]
const CHILD_ENV: &[&str] = &[
    "HEMOSTAT_PROFILE",
    "HEMOSTAT_ENGAGEMENT_ID",
    "HEMOSTAT_UNIT",
    "HEMOSTAT_POLICY",
    "HEMOSTAT_EPOCH_FLOOR",
    "HEMOSTAT_NONCE_LOG",
    "HEMOSTAT_ALLOWLIST",
    "HEMOSTAT_MANIFEST",
    "HEMOSTAT_CRASH_DIR",
    "HEMOSTAT_GOOFKIT_MAGIC",
    "HEMOSTAT_GOLDEN",
    "HEMOSTAT_TEAM",
    "HEMOSTAT_ROLE",
    "HEMOSTAT_MOUSE",
    "HEMOSTAT_TICKET",
    "HEMOSTAT_ENGAGEMENT_PUBKEY",
    "HEMOSTAT_RESPONDER_PUBKEY",
    "HEMOSTAT_RECOVERY_PUBKEY",
    "HEMOSTAT_SEAL_PUBKEY",
    "HEMOSTAT_SNAPSHOT_PUBKEY",
    "HEMOSTAT_MANIFEST_PUBKEY",
    "HEMOSTAT_READ_PUBKEY",
    "HEMOSTAT_OPERATOR_KEY",
    "HEMOSTAT_ENGAGEMENT_KEY",
    "HEMOSTAT_RESPONDER_KEY",
    "HEMOSTAT_RECOVERY_KEY",
    "HEMOSTAT_RECOVERY_KEY_FILE",
    "HEMOSTAT_MANIFEST_KEY",
    "HEMOSTAT_MANIFEST_KEY_FILE",
    "HEMOSTAT_COLLECTOR",
    "HEMOSTAT_COLLECTOR_KEY",
    "HEMOSTAT_LINK_KEY",
    "SUDO_USER",
    "SUDO_UID",
    "SUDO_GID",
    "SSH_CONNECTION",
    "SSH_CLIENT",
    "SSH_TTY",
    "SSH_USER_AUTH",
    "PATH",
    "HOME",
    "USER",
    "LOGNAME",
    "SHELL",
    "TERM",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "TZ",
    "TMPDIR",
];

pub(crate) fn this_platform() -> Platform {
    if cfg!(target_os = "windows") {
        Platform::Windows
    } else if cfg!(target_os = "freebsd") {
        Platform::FreeBsd
    } else {
        Platform::Linux
    }
}

pub(crate) fn verbs(platform: Platform) -> Verbs {
    Verbs { items: items(platform), host: Box::new(Host::new()) }
}

#[cfg(all(target_os = "linux", feature = "mod-collector"))]
pub(crate) fn verbs_with(platform: Platform, preset: &[(&'static str, String)]) -> Verbs {
    let mut items = items(platform);
    for it in &mut items {
        it.preset = preset.iter().filter(|(n, _)| it.spec.fields.iter().any(|f| f.name == *n)).cloned().collect();
    }
    Verbs { items, host: Box::new(Host::new()) }
}

pub(crate) fn items(platform: Platform) -> Vec<VerbItem> {
    let help = help_paragraphs();
    REGISTRY
        .iter()
        .filter(|s| s.platforms.contains(&platform) || s.platforms.contains(&Platform::Portable))
        .map(|spec| VerbItem { spec, disabled: disabled(spec.needs), help: help_for(&help, spec.name), preset: Vec::new() })
        .collect()
}

fn disabled(needs: &[&str]) -> Option<String> {
    for name in needs {
        match MANIFEST.modules.iter().find(|m| m.id.feature() == *name) {
            Some(m) if MANIFEST.is_built(m.id) => {}
            Some(m) => return Some(modules::module_refusal(m.id, MANIFEST.variant)),
            None => return Some(format!("{name}: not a module this build knows, so nothing behind it is here")),
        }
    }
    None
}

pub(crate) fn help_paragraphs() -> Vec<(String, String)> {
    let text = crate::usage_text();
    let verbs = text.split_once("VERBS:\n").map_or("", |(_, v)| v);
    let mut out: Vec<(String, String)> = Vec::new();
    for line in verbs.lines() {
        let entry = line.strip_prefix("    ").filter(|r| !r.starts_with(' ') && !r.is_empty());
        if let Some(rest) = entry {
            let mut words = rest.split_whitespace();
            let first = words.next().unwrap_or_default();
            let name = if first == "fw" { format!("fw {}", words.next().unwrap_or_default()) } else { first.to_string() };
            let desc: Vec<&str> = words.collect();
            out.push((name, desc.join(" ")));
        } else if let Some((_, para)) = out.last_mut() {
            para.push(' ');
            para.push_str(line.trim());
        }
    }
    out
}

fn help_for(help: &[(String, String)], name: &str) -> String {
    help.iter()
        .filter(|(n, _)| name == n || name.starts_with(&format!("{n} ")))
        .max_by_key(|(n, _)| n.len())
        .map(|(_, p)| p.trim().to_string())
        .unwrap_or_default()
}

pub(crate) fn label(code: Option<i32>) -> String {
    match code {
        Some(0) => "exit 0 · ran".into(),
        Some(1) => "exit 1 · FAILED: the operation did not complete".into(),
        Some(2) => "exit 2 · usage error: nothing was run".into(),
        Some(3) => "exit 3 · authorization DENIED: the ticket was refused, nothing was applied".into(),
        Some(4) => "exit 4 · policy REFUSAL: outside the engagement's scope, nothing was applied".into(),
        Some(5) => "exit 5 · DRY RUN: the plan printed and nothing was applied".into(),
        Some(6) => "exit 6 · the ENFORCER FAILED: attempted and did NOT take effect. NOT contained".into(),
        Some(7) => "exit 7 · DID NOT RUN in full: a partial result, not a clean one".into(),
        Some(8) => "exit 8 · NOT-BUILT: this variant does not contain the module the verb needs".into(),
        Some(c) => format!("exit {c}"),
        None => "ended by a signal, with no exit code".into(),
    }
}

struct Host {

    exe: Result<PathBuf, String>,
    inherited: Option<String>,
}

impl Host {
    fn new() -> Self {
        let exe = if cfg!(target_os = "linux") {
            Ok(PathBuf::from("/proc/self/exe"))
        } else {
            std::env::current_exe().map_err(|e| {
                format!(
                    "this image's own path could not be read ({e}), so no verb is started: a bare \
                     `hemostat` would be found on PATH, which on this host may not be this image"
                )
            })
        };
        Host { exe, inherited: std::env::var(TICKET_ENV).ok() }
    }
}

impl VerbHost for Host {
    fn start(&mut self, req: &RunRequest) -> Result<Box<dyn Running>, String> {
        let exe = self.exe.as_ref().map_err(Clone::clone)?;
        let mut cmd = Command::new(exe);
        cmd.args(&req.argv).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());

        #[cfg(target_os = "freebsd")]
        {
            cmd.env_clear();
            for name in CHILD_ENV {
                if let Some(v) = std::env::var_os(name) {
                    cmd.env(name, v);
                }
            }
        }
        match &req.ticket {
            TicketEnv::Inherit => {}
            TicketEnv::Unset => {
                cmd.env_remove(TICKET_ENV);
            }
            TicketEnv::Set(p) => {
                cmd.env(TICKET_ENV, p);
            }
        }
        let mut child = cmd.spawn().map_err(|e| format!("{} could not be started: {e}", exe.display()))?;
        let (tx, rx) = channel();
        let mut readers = 0;
        if let Some(out) = child.stdout.take() {
            readers += 1;
            reader(out, tx.clone());
        }
        if let Some(err) = child.stderr.take() {
            readers += 1;
            reader(err, tx);
        }
        Ok(Box::new(Run { child, rx, open: readers, exited: None }))
    }

    fn choices(&mut self, key: &str) -> Vec<String> {
        choices(key)
    }

    fn inherited_ticket(&self) -> Option<String> {
        self.inherited.clone()
    }
}

enum Msg {
    Line(String),
    Eof,
}

fn reader<R: Read + Send + 'static>(r: R, tx: std::sync::mpsc::Sender<Msg>) {
    std::thread::spawn(move || {
        let mut r = BufReader::new(r);
        let mut buf = Vec::new();
        loop {
            buf.clear();
            match r.read_until(b'\n', &mut buf) {
                Ok(0) | Err(_) => break,
                Ok(_) => {
                    let line = String::from_utf8_lossy(&buf).trim_end_matches(['\n', '\r']).to_string();
                    if tx.send(Msg::Line(line)).is_err() {
                        return;
                    }
                }
            }
        }
        let _ = tx.send(Msg::Eof);
    });
}

const DRAIN: Duration = Duration::from_millis(500);

struct Run {
    child: Child,
    rx: Receiver<Msg>,
    open: usize,
    exited: Option<(Option<i32>, Instant)>,
}

impl Running for Run {
    fn poll(&mut self) -> (Vec<String>, Option<Outcome>) {
        let mut lines = Vec::new();
        loop {
            match self.rx.try_recv() {
                Ok(Msg::Line(l)) => lines.push(l),
                Ok(Msg::Eof) => self.open = self.open.saturating_sub(1),
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    self.open = 0;
                    break;
                }
            }
        }
        if self.exited.is_none() {
            if let Ok(Some(st)) = self.child.try_wait() {
                self.exited = Some((st.code(), Instant::now()));
            }
        }
        let done = match self.exited {
            Some((code, at)) if self.open == 0 || at.elapsed() >= DRAIN => Some(Outcome {
                code,
                label: label(code),
                plan_ok: matches!(code, Some(c) if c == i32::from(crate::EXIT_OK) || c == 5),
            }),
            _ => None,
        };
        (lines, done)
    }

    fn stop(&mut self) {
        let _ = self.child.kill();
    }
}

fn choices(key: &str) -> Vec<String> {
    let mut out: Vec<String> = match key {
        "class" => hemostat_buildinfo::ActionClass::ALL.iter().map(|c| c.name().to_string()).collect(),
        "ticket" => files_here(|n| n.contains("ticket")),
        "store" => {
            let mut v: Vec<String> = default_stores().iter().map(|s| s.to_string()).collect();
            v.extend(dirs_here());
            v
        }
        "manifest" => files_here(|n| n.contains("manifest")),
        "rules" => ["rules/sigma", "rules/yara", "rules"]
            .iter()
            .filter(|p| std::path::Path::new(p).is_dir())
            .map(|p| p.to_string())
            .collect(),
        _ => platform_choices(key),
    };
    out.dedup();
    out
}

fn default_stores() -> &'static [&'static str] {
    if cfg!(target_os = "windows") {
        &[r"C:\ProgramData\hemostat\snapshot", "hemostat-evidence"]
    } else if cfg!(target_os = "freebsd") {
        &["/root/hemostat/snapshot", "/root/hemostat/fw-rules"]
    } else {
        &["hemostat-evidence", "/var/lib/hemostat/snapshot", "/var/lib/hemostat/acquired", "hemostat-collector"]
    }
}

fn names_in(dir: &str) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(dir)
        .map(|rd| rd.filter_map(Result::ok).filter_map(|e| e.file_name().into_string().ok()).collect())
        .unwrap_or_default();
    v.sort();
    v
}

fn files_here(want: impl Fn(&str) -> bool) -> Vec<String> {
    names_in(".").into_iter().filter(|n| want(n) && std::path::Path::new(n).is_file()).collect()
}

fn dirs_here() -> Vec<String> {
    names_in(".").into_iter().filter(|n| !n.starts_with('.') && std::path::Path::new(n).is_dir()).collect()
}

#[cfg(target_os = "linux")]
fn platform_choices(key: &str) -> Vec<String> {
    use hemostat_sensor_linux::saferead;
    use std::path::Path;

    let first_words = |path: &str, sep: char| -> Vec<String> {
        saferead::read_text(Path::new(path))
            .map(|t| t.lines().filter_map(|l| l.split(sep).next()).filter(|s| !s.is_empty()).map(str::to_string).collect())
            .unwrap_or_default()
    };
    match key {
        "pid" => {
            let mut pids: Vec<u32> = names_in("/proc").iter().filter_map(|n| n.parse().ok()).collect();
            pids.sort_unstable_by(|a, b| b.cmp(a));
            pids.into_iter()
                .filter_map(|p| {
                    let (comm, _) = saferead::read_proc(Path::new(&format!("/proc/{p}/comm")), 64).ok()?;

                    let (cmd, _) = saferead::read_proc(Path::new(&format!("/proc/{p}/cmdline")), 1).ok()?;
                    (!cmd.is_empty()).then(|| format!("{p}  {}", String::from_utf8_lossy(&comm).trim()))
                })
                .collect()
        }
        "journal" => {
            let dir = hemostat_enforce_linux::DEFAULT_VAULT;
            let mut v: Vec<String> = names_in(dir)
                .into_iter()
                .filter(|n| n.starts_with("undo-") && n.ends_with(".tsv"))
                .map(|n| format!("{dir}/{n}"))
                .collect();
            v.reverse();
            v
        }
        "user" => first_words("/etc/passwd", ':'),
        "group" => first_words("/etc/group", ':'),
        "kmod" => saferead::read_kernel_text("/proc/modules")
            .map(|t| t.lines().filter_map(|l| l.split(' ').next()).map(str::to_string).collect())
            .unwrap_or_default(),
        "boot-param" => hemostat_enforce_linux::bootparam::CATALOGUE.iter().map(|p| p.spelling.to_string()).collect(),
        "unit" => {
            let mut v: Vec<String> = Vec::new();
            for d in ["/etc/systemd/system", "/run/systemd/system", "/lib/systemd/system"] {
                v.extend(names_in(d).into_iter().filter(|n| n.ends_with(".service") || n.ends_with(".timer")));
            }
            v
        }
        _ => Vec::new(),
    }
}

#[cfg(target_os = "freebsd")]
fn platform_choices(key: &str) -> Vec<String> {
    match key {
        "block-id" => names_in("/root/hemostat/containment")
            .into_iter()
            .filter_map(|n| n.strip_suffix(".tsv").map(str::to_string))
            .collect(),
        _ => Vec::new(),
    }
}

#[cfg(not(any(target_os = "linux", target_os = "freebsd")))]
fn platform_choices(_: &str) -> Vec<String> {
    Vec::new()
}
