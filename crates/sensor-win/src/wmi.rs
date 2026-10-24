use crate::posture::{Finding, Severity};

pub const EXECUTING_CONSUMERS: &[&str] =
    &["CommandLineEventConsumer", "ActiveScriptEventConsumer"];

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Consumer {

    pub class: String,

    pub name: String,

    pub command: String,
}

const LOUD: &[(&str, &str)] = &[
    ("powershell", "PowerShell"),
    ("pwsh", "PowerShell"),
    ("cmd.exe", "the command interpreter"),
    ("cscript", "the script host"),
    ("wscript", "the script host"),
    ("mshta", "the HTML application host"),
    ("rundll32", "rundll32"),
    ("regsvr32", "regsvr32"),
    ("certutil", "certutil"),
    ("bitsadmin", "bitsadmin"),
];

const ENCODED: &[&str] = &["-enc", "-e ", "frombase64string", "-w hidden", "-windowstyle hidden",
    "downloadstring", "iex", "invoke-expression", "-nop", "-noprofile"];

#[derive(Debug, Clone, PartialEq, Eq)]
enum Shape {

    Encoded { label: &'static str, encoded: Vec<&'static str> },

    Interpreter { label: &'static str },

    Plain,
}

fn classify(c: &Consumer) -> Option<Shape> {
    if !EXECUTING_CONSUMERS.iter().any(|k| k.eq_ignore_ascii_case(&c.class)) {
        return None;
    }
    let cmd = c.command.to_ascii_lowercase();
    let interpreter = LOUD.iter().find(|(needle, _)| cmd.contains(needle));
    let encoded: Vec<&str> = ENCODED.iter().copied().filter(|e| cmd.contains(e)).collect();
    Some(match interpreter {
        Some((_, label)) if !encoded.is_empty() => Shape::Encoded { label, encoded },
        Some((_, label)) => Shape::Interpreter { label },
        None => Shape::Plain,
    })
}

fn shown_name(c: &Consumer) -> &str {
    if c.name.is_empty() { "(unnamed)" } else { &c.name }
}

pub fn judge(c: &Consumer) -> Option<Finding> {

    match classify(c)? {
        Shape::Encoded { label, encoded } => Some(Finding {
            severity: Severity::Critical,
            subject: format!("wmi:{}", c.class),
            what: format!(
                "a persistent WMI consumer {} runs {label} with {}: {}",
                shown_name(c),
                encoded.join(", "),
                c.command
            ),
            why: "a WMI event subscription writes nothing to the filesystem and creates no \
                  registry autorun, so a sweep of either cannot see it, and the payload runs as \
                  SYSTEM whenever the filter fires. An interpreter with an encoded argument is \
                  the shape of the technique rather than of monitoring. This came from the \
                  repository, which retains deleted objects — so it may be live, or it may be \
                  one that existed and was removed. Both are findings; they need different \
                  next steps"
                .into(),
            fix: Some(
                "first establish whether it is live: `Get-WmiObject -Namespace root\\subscription \
                 -Class CommandLineEventConsumer`. If it is there, capture the filter, consumer \
                 and binding before removing any of them, and remove the binding FIRST or the \
                 consumer is re-bound. If it is NOT there, this is the residue of a subscription \
                 somebody already deleted, which is evidence of both the persistence and the \
                 cleanup"
                    .into(),
            ),
        }),

        Shape::Interpreter { label } => Some(Finding {
            severity: Severity::Warn,
            subject: format!("wmi:{}", c.class),
            what: format!(
                "a persistent WMI consumer {} runs {label}: {}",
                shown_name(c),
                c.command
            ),
            why: "WMI subscriptions run as SYSTEM and leave no file or registry autorun. Most \
                  legitimate ones invoke a management agent, not an interpreter"
                .into(),
            fix: Some("check what filter is bound to this consumer and what it fires on".into()),
        }),

        Shape::Plain => Some(Finding {
            severity: Severity::Warn,
            subject: format!("wmi:{}", c.class),
            what: format!(
                "a persistent WMI consumer {} is registered: {}",
                shown_name(c),
                if c.command.is_empty() { "(no command recovered)" } else { &c.command }
            ),
            why: "persistent WMI consumers survive reboots, run as SYSTEM, and appear in no \
                  filesystem or registry sweep"
                .into(),
            fix: None,
        }),
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LiveConsumer {

    pub namespace: String,

    pub consumer: Consumer,

    pub relpath: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LiveFilter {

    pub namespace: String,

    pub name: String,

    pub relpath: String,

    pub query: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LiveBinding {

    pub namespace: String,

    pub filter: String,

    pub consumer: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Subscriptions {

    pub consumers: Vec<LiveConsumer>,

    pub filters: Vec<LiveFilter>,

    pub bindings: Vec<LiveBinding>,
}

pub fn object_key(own_namespace: &str, path: &str) -> (String, String) {
    let p = path.trim();
    let p = match p.strip_prefix("\\\\") {

        Some(rest) => rest.split_once('\\').map_or(rest, |(_, r)| r),
        None => p,
    };
    let stop = p.find(['.', '=']).unwrap_or(p.len());
    match p.find(':') {
        Some(colon) if colon < stop => (
            p.get(..colon).unwrap_or_default().to_ascii_lowercase(),
            p.get(colon + 1..).unwrap_or_default().to_ascii_lowercase(),
        ),
        _ => (own_namespace.to_ascii_lowercase(), p.to_ascii_lowercase()),
    }
}

pub fn bound_filters<'a>(s: &'a Subscriptions, c: &LiveConsumer) -> Vec<&'a LiveFilter> {
    let me = object_key(&c.namespace, &c.relpath);
    s.bindings
        .iter()
        .filter(|b| object_key(&b.namespace, &b.consumer) == me)
        .filter_map(|b| {
            let want = object_key(&b.namespace, &b.filter);
            s.filters.iter().find(|f| object_key(&f.namespace, &f.relpath) == want)
        })
        .collect()
}

pub fn judge_live(c: &LiveConsumer, filters: &[&LiveFilter]) -> Option<Finding> {
    let shape = classify(&c.consumer)?;
    let cc = &c.consumer;
    let when = if filters.is_empty() {
        "bound to NO filter, so it does not fire now".to_string()
    } else {
        let f: Vec<String> =
            filters.iter().map(|f| format!("{} (`{}`)", f.name, f.query)).collect();
        format!("fires on {}", f.join("; "))
    };
    let (severity, what, why) = match shape {
        Shape::Encoded { label, encoded } => (
            Severity::Critical,
            format!(
                "a live WMI consumer {} in {} runs {label} with {}: {} — {when}",
                shown_name(cc),
                c.namespace,
                encoded.join(", "),
                cc.command
            ),
            "a WMI event subscription writes nothing to the filesystem and creates no registry \
             autorun, so a sweep of either cannot see it, and the payload runs as SYSTEM \
             whenever the filter fires. An interpreter with an encoded argument is the shape of \
             the technique rather than of monitoring. Read from WMI itself, so it exists now",
        ),
        Shape::Interpreter { label } => (
            Severity::Warn,
            format!(
                "a live WMI consumer {} in {} runs {label}: {} — {when}",
                shown_name(cc),
                c.namespace,
                cc.command
            ),
            "WMI subscriptions run as SYSTEM and leave no file or registry autorun. Most \
             legitimate ones invoke a management agent, not an interpreter",
        ),
        Shape::Plain => (
            Severity::Warn,
            format!(
                "a live WMI consumer {} in {} runs {} — {when}",
                shown_name(cc),
                c.namespace,
                if cc.command.is_empty() { "(no command set)" } else { &cc.command }
            ),
            "persistent WMI consumers survive reboots, run as SYSTEM, and appear in no \
             filesystem or registry sweep",
        ),
    };
    Some(Finding {
        severity,
        subject: format!("wmi:{}:{}", cc.class, cc.name),
        what,
        why: why.into(),
        fix: Some(format!(
            "capture all three objects first (`Get-CimInstance -Namespace {ns} -ClassName \
             __FilterToConsumerBinding`, `... {class}`, `... __EventFilter`), then remove the \
             binding FIRST — a consumer removed while still bound can be re-bound — then the \
             consumer and its filter",
            ns = c.namespace,
            class = cc.class
        )),
    })
}

pub fn is_live(repo: &Consumer, live: &Subscriptions) -> bool {
    let r = repo.command.trim().to_ascii_lowercase();
    !r.is_empty()
        && live.consumers.iter().any(|l| {
            let c = l.consumer.command.trim().to_ascii_lowercase();
            !c.is_empty() && (c.contains(&r) || r.contains(&c))
        })
}

pub fn judge_residue(c: &Consumer) -> Option<Finding> {
    let f = judge(c)?;
    Some(Finding {
        severity: f.severity,
        subject: format!("wmi-residue:{}", c.class),
        what: format!("NOT live, only in the repository: {}", f.what),
        why: "WMI reports no such consumer now, and the repository keeps what WMI deletes, so \
              this is what is left of a subscription somebody removed. It is not running. It is \
              evidence of the persistence and of its removal, and nothing but the repository \
              still holds it"
            .into(),
        fix: Some(
            "date it: Microsoft-Windows-WMI-Activity/Operational records subscription activity \
             (5861 for a binding), and an intruder who removed theirs before leaving was here \
             before that. Copy OBJECTS.DATA before anything compacts it"
                .into(),
        ),
    })
}

pub fn strings_in(window: &[u8], min_len: usize, max_len: usize) -> Vec<String> {
    let mut out = Vec::new();

    let mut cur = String::new();
    let mut i = 0;
    while i + 1 < window.len() {
        let c = u16::from_le_bytes([window[i], window[i + 1]]);
        match char::from_u32(u32::from(c)) {
            Some(ch) if ch.is_ascii_graphic() || ch == ' ' || ch == '\\' => {
                if cur.len() < max_len {
                    cur.push(ch);
                }
            }
            _ => {
                if cur.len() >= min_len {
                    out.push(core::mem::take(&mut cur));
                } else {
                    cur.clear();
                }
            }
        }
        i += 2;
    }
    if cur.len() >= min_len {
        out.push(cur);
    }

    let mut cur = String::new();
    for b in window {
        let ch = *b as char;
        if ch.is_ascii_graphic() || ch == ' ' {
            if cur.len() < max_len {
                cur.push(ch);
            }
        } else {
            if cur.len() >= min_len {
                out.push(core::mem::take(&mut cur));
            } else {
                cur.clear();
            }
        }
    }
    if cur.len() >= min_len {
        out.push(cur);
    }

    out.sort();
    out.dedup();
    out
}

pub fn likely_command(strings: &[String]) -> String {
    const MARKERS: &[&str] =
        &[".exe", ".ps1", ".vbs", ".js", ".bat", ".cmd", "powershell", "cmd /c", "http"];
    strings
        .iter()
        .filter(|s| {
            let l = s.to_ascii_lowercase();
            MARKERS.iter().any(|m| l.contains(m))
        })

        .filter(|s| !s.starts_with("__") && !EXECUTING_CONSUMERS.contains(&s.as_str()))
        .filter(|s| !is_class_definition_artefact(s))
        .max_by_key(|s| s.len())
        .cloned()
        .unwrap_or_default()
}

pub fn is_class_definition_artefact(s: &str) -> bool {
    let l = s.to_ascii_lowercase();
    l.contains("mofresourcename")
        || l.contains(".mof")
        || l.contains(".dll[")
        || l.contains("[mof")

        || (l.ends_with(".dll") && !l.contains(' '))
}

pub const MAX_REPOSITORY_BYTES: u64 = 256 * 1024 * 1024;

const WINDOW: usize = 4096;

pub const REPOSITORY: &str = r"C:\Windows\System32\wbem\Repository\OBJECTS.DATA";

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Report {

    pub consumers: Vec<Consumer>,

    pub findings: Vec<Finding>,

    pub unreadable: bool,

    pub scanned: usize,

    pub live: Option<Subscriptions>,

    pub live_gaps: Vec<String>,

    pub residue: Vec<Consumer>,
}

impl Report {

    pub fn complete(&self) -> bool {
        !self.unreadable && self.live.is_some() && self.live_gaps.is_empty()
    }

    pub fn executing(&self) -> usize {
        self.live.as_ref().map_or(0, |l| {
            l.consumers
                .iter()
                .filter(|c| EXECUTING_CONSUMERS.iter().any(|k| k.eq_ignore_ascii_case(&c.consumer.class)))
                .count()
        })
    }
}

pub fn combine(r: &mut Report) {
    r.findings.clear();
    r.residue.clear();
    match &r.live {
        Some(live) => {
            for c in &live.consumers {
                let filters = bound_filters(live, c);
                if let Some(f) = judge_live(c, &filters) {
                    r.findings.push(f);
                }
            }
            r.residue = r.consumers.iter().filter(|c| !is_live(c, live)).cloned().collect();
            r.findings.extend(r.residue.iter().filter_map(judge_residue));
        }

        None => r.findings.extend(r.consumers.iter().filter_map(judge)),
    }
}

#[cfg(target_os = "windows")]
pub fn scan() -> Report {
    let mut r = Report::default();
    repository(&mut r);
    match live::query(LIVE_NAMESPACES) {
        Ok((subs, gaps)) => {
            r.live = Some(subs);
            r.live_gaps = gaps;
        }
        Err(why) => r.live_gaps.push(why),
    }
    combine(&mut r);
    r
}

#[cfg(target_os = "windows")]
pub fn live_query() -> Result<(Subscriptions, Vec<String>), String> {
    live::query(LIVE_NAMESPACES)
}

#[cfg(not(target_os = "windows"))]
pub fn live_query() -> Result<(Subscriptions, Vec<String>), String> {
    Err("this build does not run on Windows, so nothing was read".into())
}

pub const LIVE_NAMESPACES: &[&str] = &["ROOT\\subscription", "ROOT\\default"];

#[cfg(target_os = "windows")]
fn repository(r: &mut Report) {
    let Ok(md) = std::fs::metadata(REPOSITORY) else {
        r.unreadable = true;
        return;
    };
    if md.len() > MAX_REPOSITORY_BYTES {
        r.unreadable = true;
        return;
    }
    let Ok(bytes) = std::fs::read(REPOSITORY) else {
        r.unreadable = true;
        return;
    };
    r.scanned = bytes.len();
    r.consumers = consumers_in(&bytes);
}

#[cfg(not(target_os = "windows"))]
pub fn scan() -> Report {
    Report {
        unreadable: true,
        live_gaps: vec!["this build does not run on Windows, so nothing was read".into()],
        ..Default::default()
    }
}

pub const LIVE_SCRIPT: &str = r#"
$ErrorActionPreference = 'Stop'
function HsHex($v) { if ($null -eq $v) { return '' }; -join ([Text.Encoding]::UTF8.GetBytes([string]$v) | ForEach-Object { $_.ToString('x2') }) }
foreach ($ns in @('ROOT\subscription', 'ROOT\default')) {
  try {
    foreach ($o in @(Get-WmiObject -Namespace $ns -Class __EventConsumer)) {
      $cmd = $o.CommandLineTemplate
      if (-not $cmd) { $cmd = $o.ExecutablePath }
      if (-not $cmd) { $cmd = $o.ScriptText }
      if (-not $cmd) { $cmd = $o.ScriptFileName }
      "C`t$(HsHex $ns)`t$(HsHex $o.__CLASS)`t$(HsHex $o.Name)`t$(HsHex $o.__RELPATH)`t$(HsHex $cmd)"
    }
    foreach ($o in @(Get-WmiObject -Namespace $ns -Class __EventFilter)) {
      "F`t$(HsHex $ns)`t$(HsHex $o.Name)`t$(HsHex $o.__RELPATH)`t$(HsHex $o.Query)"
    }
    foreach ($o in @(Get-WmiObject -Namespace $ns -Class __FilterToConsumerBinding)) {
      "B`t$(HsHex $ns)`t$(HsHex $o.Filter)`t$(HsHex $o.Consumer)"
    }
    "N`t$(HsHex $ns)"
  } catch {
    if ("$($_.Exception.ErrorCode)" -eq 'InvalidNamespace') { "X`t$(HsHex $ns)" }
    else { "E`t$(HsHex $ns)`t$(HsHex $_.Exception.Message)" }
  }
}
'END'
"#;

pub const MAX_LIVE_OUTPUT: usize = 4 * 1024 * 1024;

pub fn encoded_command(script: &str) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let bytes: Vec<u8> = script.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [chunk.first().copied().unwrap_or(0), chunk.get(1).copied().unwrap_or(0), chunk.get(2).copied().unwrap_or(0)];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for (i, shift) in [18, 12, 6, 0].into_iter().enumerate() {
            if i <= chunk.len() {
                out.push(char::from(A[((n >> shift) & 63) as usize]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

fn unhex(h: &str) -> Option<String> {
    if !h.len().is_multiple_of(2) {
        return None;
    }
    let bytes: Option<Vec<u8>> = (0..h.len())
        .step_by(2)
        .map(|i| h.get(i..i + 2).and_then(|b| u8::from_str_radix(b, 16).ok()))
        .collect();
    String::from_utf8(bytes?).ok()
}

pub fn parse_live(out: &str, namespaces: &[&str]) -> Result<(Subscriptions, Vec<String>), String> {
    let mut subs = Subscriptions::default();
    let mut gaps = Vec::new();
    let mut closed: Vec<String> = Vec::new();
    let mut ended = false;

    for (n, line) in out.lines().map(|l| l.trim_end_matches('\r')).filter(|l| !l.is_empty()).enumerate() {
        if ended {
            return Err(format!("line {} follows END", n + 1));
        }
        if line == "END" {
            ended = true;
            continue;
        }
        let fields: Vec<&str> = line.split('\t').collect();
        let bad = || format!("line {} is not one the script writes", n + 1);
        let text: Vec<String> =
            fields.iter().skip(1).map(|f| unhex(f)).collect::<Option<_>>().ok_or_else(bad)?;
        let t = |i: usize| text.get(i).cloned().unwrap_or_default();
        match (fields.first().copied(), text.len()) {
            (Some("C"), 5) => subs.consumers.push(LiveConsumer {
                namespace: t(0),
                consumer: Consumer { class: t(1), name: t(2), command: t(4) },
                relpath: t(3),
            }),
            (Some("F"), 4) => subs.filters.push(LiveFilter {
                namespace: t(0),
                name: t(1),
                relpath: t(2),
                query: t(3),
            }),
            (Some("B"), 3) => {
                subs.bindings.push(LiveBinding { namespace: t(0), filter: t(1), consumer: t(2) });
            }
            (Some("N" | "X"), 1) => closed.push(t(0)),
            (Some("E"), 2) => {
                gaps.push(format!("{}: {}", t(0), t(1)));
                closed.push(t(0));
            }
            _ => return Err(bad()),
        }
    }
    if !ended {
        return Err("the output stopped before END".into());
    }
    for ns in namespaces {
        if !closed.iter().any(|c| c.eq_ignore_ascii_case(ns)) {
            return Err(format!("{ns} was never reported on"));
        }
    }
    Ok((subs, gaps))
}

#[cfg(target_os = "windows")]
mod live {
    use super::{encoded_command, parse_live, Subscriptions, LIVE_SCRIPT, MAX_LIVE_OUTPUT};
    use std::io::Read as _;
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    const LIMIT: Duration = Duration::from_secs(60);

    pub(super) fn query(namespaces: &[&str]) -> Result<(Subscriptions, Vec<String>), String> {
        let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
        let exe = format!(r"{root}\System32\WindowsPowerShell\v1.0\powershell.exe");
        match crate::authenticode::verify(&exe) {
            crate::authenticode::Trust::Valid => {}
            other => {
                return Err(format!(
                    "{exe} was not started: its signature did not verify ({})",
                    other.token()
                ))
            }
        }
        let mut child = Command::new(&exe)
            .args(["-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand"])
            .arg(encoded_command(LIVE_SCRIPT))
            .env_clear()
            .env("SystemRoot", &root)
            .env("windir", &root)
            .env("SystemDrive", root.get(..2).unwrap_or("C:"))
            .env("TEMP", format!(r"{root}\Temp"))
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| format!("{exe} could not be started: {e}"))?;

        let mut stdout = child.stdout.take().ok_or("no stdout from the child")?;
        let reader = std::thread::spawn(move || {
            let mut buf = Vec::new();
            let r = (&mut stdout).take(MAX_LIVE_OUTPUT as u64 + 1).read_to_end(&mut buf);
            r.map(|_| buf)
        });
        let start = Instant::now();
        let status = loop {
            match child.try_wait() {
                Ok(Some(st)) => break st,
                Ok(None) if start.elapsed() < LIMIT => std::thread::sleep(Duration::from_millis(50)),
                Ok(None) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(format!("{exe} did not finish within {} s", LIMIT.as_secs()));
                }
                Err(e) => return Err(format!("{exe} could not be waited on: {e}")),
            }
        };
        let out = reader
            .join()
            .map_err(|_| "the child's output could not be read".to_string())?
            .map_err(|e| format!("the child's output could not be read: {e}"))?;
        if out.len() > MAX_LIVE_OUTPUT {
            return Err(format!("{exe} wrote more than {MAX_LIVE_OUTPUT} bytes"));
        }
        if !status.success() {
            return Err(format!("{exe} exited {status}"));
        }
        let text = String::from_utf8(out).map_err(|_| format!("{exe} wrote output that is not UTF-8"))?;
        parse_live(&text, namespaces).map_err(|e| format!("{exe}'s output did not parse: {e}"))
    }
}

pub fn consumers_in(bytes: &[u8]) -> Vec<Consumer> {
    let mut out = Vec::new();
    for class in EXECUTING_CONSUMERS {

        for needle in [class.as_bytes().to_vec(), utf16_bytes(class)] {
            let mut from = 0usize;

            while out.len() < 256 {
                let Some(rel) = find(bytes.get(from..).unwrap_or_default(), &needle) else {
                    break;
                };
                let at = from + rel;
                let lo = at.saturating_sub(WINDOW);
                let hi = (at + WINDOW).min(bytes.len());
                let window = bytes.get(lo..hi).unwrap_or_default();
                let strings = strings_in(window, 6, 1024);
                let command = likely_command(&strings);

                if !command.is_empty() {
                    out.push(Consumer {
                        class: (*class).to_string(),
                        name: String::new(),
                        command,
                    });
                }
                from = at + needle.len();
            }
        }
    }

    out.sort_by(|a, b| (&a.class, &a.command).cmp(&(&b.class, &b.command)));
    out.dedup();
    out
}

fn utf16_bytes(s: &str) -> Vec<u8> {
    s.chars().flat_map(|c| (c as u16).to_le_bytes()).collect()
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}
