#![allow(dead_code)]

use crate::render::h;
#[cfg(target_os = "windows")]
use crate::{EXIT_DRYRUN, EXIT_ENFORCER, EXIT_OK, EXIT_POLICY, EXIT_USAGE};

pub(crate) const NAMESPACE: &str = "ROOT\\subscription";

pub(crate) const ENV_NAME: &str = "HEMOSTAT_WMI_NAME";

pub(crate) const ENV_STATE: &str = "HEMOSTAT_WMI_STATE";

pub(crate) const ENV_REMOVE: &str = "HEMOSTAT_WMI_REMOVE";

pub(crate) const MAX_OUTPUT: usize = 8 * 1024 * 1024;

pub(crate) const MAX_ENV: usize = 32_000;

pub(crate) fn wmi_is_protected(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    ["datadog", "ddagent", "dd-agent"].iter().any(|p| n.contains(p))
}

const QUOTE_CLASS: &[char] = &[
    '\'', '\u{2018}', '\u{2019}', '\u{201A}', '\u{201B}', '"', '\u{201C}', '\u{201D}',
    '\u{201E}', '\u{201F}', '`', '$',
];

pub(crate) fn name_refusal(name: &str) -> Option<String> {
    if let Some(c) = name.chars().find(|c| c.is_control()) {
        return Some(format!("the name holds a control character (U+{:04X})", u32::from(c)));
    }
    if let Some(c) = name.chars().find(|c| QUOTE_CLASS.contains(c)) {
        return Some(format!(
            "the name holds a quote-class character (U+{:04X}), which PowerShell reads as a \
             quote, an escape or an expansion",
            u32::from(c)
        ));
    }
    None
}

macro_rules! state_script {
    () => {
        r##"$ErrorActionPreference = 'Stop'
function HsHex($v) {
  if ($null -eq $v) { return '' }
  [BitConverter]::ToString([Text.Encoding]::UTF8.GetBytes([string]$v)).Replace('-', '').ToLowerInvariant()
}
function HsState {
  $ns = 'ROOT\subscription'
  $n = [string]$env:HEMOSTAT_WMI_NAME
  $rows = [System.Collections.Generic.List[string]]::new()
  foreach ($o in @(Get-WmiObject -Namespace $ns -Class __EventConsumer)) {
    if (-not [string]::Equals([string]$o.Name, $n, [StringComparison]::Ordinal)) { continue }
    $r = HsHex $o.__RELPATH
    $rows.Add("C`t$(HsHex $o.__CLASS)`t$r`t$(HsHex $o.Name)`t$(HsHex ($o.psbase.GetText('Mof')))")
    foreach ($p in @($o.psbase.Properties)) { $rows.Add("P`t$r`t$(HsHex $p.Name)`t$(HsHex $p.Value)") }
  }
  foreach ($o in @(Get-WmiObject -Namespace $ns -Class __FilterToConsumerBinding)) {
    $rows.Add("B`t$(HsHex $o.__RELPATH)`t$(HsHex $o.Filter)`t$(HsHex $o.Consumer)`t$(HsHex ($o.psbase.GetText('Mof')))")
  }
  foreach ($o in @(Get-WmiObject -Namespace $ns -Class __EventFilter)) {
    $rows.Add("F`t$(HsHex $o.__RELPATH)`t$(HsHex $o.Name)`t$(HsHex $o.Query)`t$(HsHex $o.QueryLanguage)`t$(HsHex $o.EventNamespace)`t$(HsHex ($o.psbase.GetText('Mof')))")
  }
  $rows.Sort([StringComparer]::Ordinal)
  $rows.ToArray()
}
"##
    };
}

pub(crate) const DESCRIBE_SCRIPT: &str = concat!(
    state_script!(),
    r##"try { foreach ($l in @(HsState)) { $l } } catch { "E`t$(HsHex $_.Exception.Message)" }
'END'
"##
);

pub(crate) const REMOVE_SCRIPT: &str = concat!(
    state_script!(),
    r##"try {
  $doc = [string]::Join("`n", [string[]]@(HsState))
  $sha = [Security.Cryptography.SHA256]::Create()
  $digest = [BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($doc))).Replace('-', '').ToLowerInvariant()
  if ($digest -cne [string]$env:HEMOSTAT_WMI_STATE) {
    'CHANGED'
  } else {
    $class = @{ 'B' = '__FilterToConsumerBinding'; 'C' = '__EventConsumer'; 'F' = '__EventFilter' }
    $want = @(([string]$env:HEMOSTAT_WMI_REMOVE).Split(',') | Where-Object { $_ })
    $stop = $false
    foreach ($t in $want) {
      if ($stop) { break }
      $hex = $t.Substring(1)
      try {
        $hit = @(Get-WmiObject -Namespace 'ROOT\subscription' -Class ($class[$t.Substring(0, 1)]) | Where-Object { (HsHex $_.__RELPATH) -ceq $hex })
        if ($hit.Count -ne 1) { throw "$($hit.Count) objects have this path, not one" }
        $hit[0] | Remove-WmiObject
      } catch {
        "FAIL`t$hex`t$(HsHex $_.Exception.Message)"
        $stop = $true
      }
    }
    foreach ($t in $want) {
      $hex = $t.Substring(1)
      $left = @(Get-WmiObject -Namespace 'ROOT\subscription' -Class ($class[$t.Substring(0, 1)]) | Where-Object { (HsHex $_.__RELPATH) -ceq $hex })
      if ($left.Count -eq 0) { "GONE`t$hex" } else { "LEFT`t$hex" }
    }
  }
} catch { "E`t$(HsHex $_.Exception.Message)" }
'END'
"##
);

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct WmiConsumer {

    pub(crate) class: String,

    pub(crate) relpath: String,

    pub(crate) name: String,

    pub(crate) mof: String,

    pub(crate) relpath_hex: String,

    pub(crate) token: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct WmiProp {

    pub(crate) consumer: String,

    pub(crate) name: String,

    pub(crate) value: String,

    pub(crate) token: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct WmiBinding {

    pub(crate) relpath: String,

    pub(crate) filter: String,

    pub(crate) consumer: String,

    pub(crate) mof: String,

    pub(crate) relpath_hex: String,

    pub(crate) token: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct WmiFilter {

    pub(crate) relpath: String,

    pub(crate) name: String,

    pub(crate) query: String,

    pub(crate) language: String,

    pub(crate) event_namespace: String,

    pub(crate) mof: String,

    pub(crate) relpath_hex: String,

    pub(crate) token: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Described {

    pub(crate) consumers: Vec<WmiConsumer>,

    pub(crate) props: Vec<WmiProp>,

    pub(crate) bindings: Vec<WmiBinding>,

    pub(crate) filters: Vec<WmiFilter>,

    pub(crate) state: String,
}

fn is_lower_hex(x: &str) -> bool {
    x.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn unhex(x: &str) -> Option<String> {
    if !x.len().is_multiple_of(2) || !is_lower_hex(x) {
        return None;
    }
    let bytes: Option<Vec<u8>> = (0..x.len())
        .step_by(2)
        .map(|i| x.get(i..i + 2).and_then(|b| u8::from_str_radix(b, 16).ok()))
        .collect();
    String::from_utf8(bytes?).ok()
}

fn script_lines(out: &str) -> impl Iterator<Item = &str> {
    out.strip_prefix('\u{feff}')
        .unwrap_or(out)
        .lines()
        .map(|l| l.trim_end_matches('\r'))
        .filter(|l| !l.is_empty())
}

pub(crate) fn parse_described(out: &str) -> Result<Described, String> {
    let mut d = Described::default();
    let mut body: Vec<&str> = Vec::new();
    let mut ended = false;
    for (n, line) in script_lines(out).enumerate() {
        if ended {
            return Err(format!("line {} follows END", n + 1));
        }
        if line == "END" {
            ended = true;
            continue;
        }
        let bad = || format!("line {} is not one the script writes", n + 1);
        let (kind, rest) = line.split_once('\t').ok_or_else(bad)?;
        let hex: Vec<&str> = rest.split('\t').collect();
        let text: Vec<String> = hex.iter().map(|f| unhex(f)).collect::<Option<_>>().ok_or_else(bad)?;
        let t = |i: usize| text.get(i).cloned().unwrap_or_default();
        let x = |i: usize| hex.get(i).map(|s| (*s).to_string()).unwrap_or_default();
        let token = format!("{kind}:{}", hex.join(","));
        match (kind, text.len()) {
            ("C", 4) => d.consumers.push(WmiConsumer {
                class: t(0),
                relpath: t(1),
                name: t(2),
                mof: t(3),
                relpath_hex: x(1),
                token,
            }),
            ("P", 3) => d.props.push(WmiProp { consumer: t(0), name: t(1), value: t(2), token }),
            ("B", 4) => d.bindings.push(WmiBinding {
                relpath: t(0),
                filter: t(1),
                consumer: t(2),
                mof: t(3),
                relpath_hex: x(0),
                token,
            }),
            ("F", 6) => d.filters.push(WmiFilter {
                relpath: t(0),
                name: t(1),
                query: t(2),
                language: t(3),
                event_namespace: t(4),
                mof: t(5),
                relpath_hex: x(0),
                token,
            }),
            ("E", 1) => return Err(format!("WMI answered with an error: {}", t(0))),
            _ => return Err(bad()),
        }
        body.push(line);
    }
    if !ended {
        return Err("the output stopped before END".into());
    }
    if d.props.iter().any(|p| !d.consumers.iter().any(|c| c.relpath == p.consumer)) {
        return Err("a property row names a consumer the script did not list".into());
    }
    d.state = crate::win_binvault::sha256_hex(body.join("\n").as_bytes());
    Ok(d)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Refusal {

    NotFound,

    Ambiguous(Vec<String>),

    Protected {

        object: String,

        field: String,
    },
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Plan {

    pub(crate) consumer: WmiConsumer,

    pub(crate) props: Vec<WmiProp>,

    pub(crate) bindings: Vec<WmiBinding>,

    pub(crate) filters: Vec<WmiFilter>,

    pub(crate) kept: Vec<(String, String)>,

    pub(crate) state: String,
}

#[cfg(any(test, target_os = "windows"))]
pub(crate) fn plan(d: &Described, name: &str) -> Result<Plan, Refusal> {
    use hemostat_sensor_win::wmi::object_key;
    let named: Vec<&WmiConsumer> = d.consumers.iter().filter(|c| c.name == name).collect();
    let consumer = match named.as_slice() {
        [] => return Err(Refusal::NotFound),
        [one] => (*one).clone(),
        many => return Err(Refusal::Ambiguous(many.iter().map(|c| c.relpath.clone()).collect())),
    };
    let me = object_key(NAMESPACE, &consumer.relpath);
    let (ours, others): (Vec<&WmiBinding>, Vec<&WmiBinding>) =
        d.bindings.iter().partition(|b| object_key(NAMESPACE, &b.consumer) == me);
    let mut seen: Vec<(String, String)> = Vec::new();
    let mut filters: Vec<WmiFilter> = Vec::new();
    let mut kept: Vec<(String, String)> = Vec::new();
    for b in &ours {
        let want = object_key(NAMESPACE, &b.filter);
        if seen.contains(&want) {
            continue;
        }
        seen.push(want.clone());
        match d.filters.iter().find(|f| object_key(NAMESPACE, &f.relpath) == want) {
            None => kept.push((b.filter.clone(), format!("not a filter in {NAMESPACE}"))),
            Some(f) => match others.iter().find(|o| object_key(NAMESPACE, &o.filter) == want) {
                Some(o) => kept.push((f.relpath.clone(), format!("still bound by {}", o.relpath))),
                None => filters.push(f.clone()),
            },
        }
    }
    let props = d.props.iter().filter(|p| p.consumer == consumer.relpath).cloned().collect();
    let plan = Plan {
        consumer,
        props,
        bindings: ours.into_iter().cloned().collect(),
        filters,
        kept,
        state: d.state.clone(),
    };
    match protected(&plan) {
        Some(refusal) => Err(refusal),
        None => Ok(plan),
    }
}

fn protected(p: &Plan) -> Option<Refusal> {
    let c = &p.consumer;
    let mut checks: Vec<(&str, String, &str)> = Vec::new();
    for (field, v) in [("name", &c.name), ("class", &c.class), ("path", &c.relpath), ("definition", &c.mof)] {
        checks.push((c.relpath.as_str(), field.to_string(), v.as_str()));
    }
    checks.extend(p.props.iter().map(|x| (c.relpath.as_str(), format!("property {}", x.name), x.value.as_str())));
    for b in &p.bindings {
        for (field, v) in [("path", &b.relpath), ("filter", &b.filter), ("consumer", &b.consumer), ("definition", &b.mof)] {
            checks.push((b.relpath.as_str(), field.to_string(), v.as_str()));
        }
    }
    for f in &p.filters {
        for (field, v) in [
            ("path", &f.relpath),
            ("name", &f.name),
            ("query", &f.query),
            ("query language", &f.language),
            ("event namespace", &f.event_namespace),
            ("definition", &f.mof),
        ] {
            checks.push((f.relpath.as_str(), field.to_string(), v.as_str()));
        }
    }
    checks
        .into_iter()
        .find(|(_, _, v)| wmi_is_protected(v))
        .map(|(object, field, _)| Refusal::Protected { object: object.to_string(), field })
}

pub(crate) fn removal_targets(p: &Plan) -> Vec<String> {
    let mut t: Vec<String> = p.bindings.iter().map(|b| format!("B{}", b.relpath_hex)).collect();
    t.push(format!("C{}", p.consumer.relpath_hex));
    t.extend(p.filters.iter().map(|f| format!("F{}", f.relpath_hex)));
    t
}

pub(crate) fn record_line(p: &Plan) -> String {
    let mut s = format!("remove-wmi v1 state={}", p.state);
    for t in std::iter::once(&p.consumer.token)
        .chain(p.props.iter().map(|x| &x.token))
        .chain(p.bindings.iter().map(|x| &x.token))
        .chain(p.filters.iter().map(|x| &x.token))
    {
        s.push(' ');
        s.push_str(t);
    }
    s.push_str(&format!(
        " -- {} `{}` in {NAMESPACE}, {} binding(s), {} filter(s): every property and MOF, hex of UTF-8",
        h(&p.consumer.class),
        h(&p.consumer.name),
        p.bindings.len(),
        p.filters.len()
    ));
    s
}

pub(crate) type RecordRows = Vec<(char, Vec<String>)>;

pub(crate) fn parse_record(line: &str) -> Result<(String, RecordRows), String> {
    let mut it = line.split(' ');
    if it.next() != Some("remove-wmi") || it.next() != Some("v1") {
        return Err("not a remove-wmi v1 record".into());
    }
    let state = it
        .next()
        .and_then(|t| t.strip_prefix("state="))
        .filter(|s| s.len() == 64 && is_lower_hex(s))
        .ok_or("the record has no state digest")?
        .to_string();
    let mut rows = Vec::new();
    for tok in it {
        if tok == "--" {
            break;
        }
        let bad = || format!("`{}` is not a record token", h(tok));
        let (kind, fields) = tok.split_once(':').ok_or_else(bad)?;
        let (k, want) = match kind {
            "C" => ('C', 4),
            "P" => ('P', 3),
            "B" => ('B', 4),
            "F" => ('F', 6),
            _ => return Err(bad()),
        };
        let text: Vec<String> = fields.split(',').map(unhex).collect::<Option<_>>().ok_or_else(bad)?;
        if text.len() != want {
            return Err(bad());
        }
        rows.push((k, text));
    }
    Ok((state, rows))
}

pub(crate) fn plan_rows(p: &Plan) -> RecordRows {
    let c = &p.consumer;
    let mut rows = vec![('C', vec![c.class.clone(), c.relpath.clone(), c.name.clone(), c.mof.clone()])];
    rows.extend(p.props.iter().map(|x| ('P', vec![x.consumer.clone(), x.name.clone(), x.value.clone()])));
    rows.extend(
        p.bindings
            .iter()
            .map(|b| ('B', vec![b.relpath.clone(), b.filter.clone(), b.consumer.clone(), b.mof.clone()])),
    );
    rows.extend(p.filters.iter().map(|f| {
        (
            'F',
            vec![
                f.relpath.clone(),
                f.name.clone(),
                f.query.clone(),
                f.language.clone(),
                f.event_namespace.clone(),
                f.mof.clone(),
            ],
        )
    }));
    rows
}

pub(crate) fn record_reads_back(p: &Plan, record: &str) -> bool {
    parse_record(record).is_ok_and(|(state, rows)| state == p.state && rows == plan_rows(p))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Removal {

    Changed,

    Ran {

        gone: Vec<String>,

        left: Vec<String>,

        failed: Option<(String, String)>,
    },
}

impl Removal {

    pub(crate) fn complete(&self) -> bool {
        matches!(self, Removal::Ran { left, failed: None, .. } if left.is_empty())
    }
}

pub(crate) fn parse_removal(out: &str, targets: &[String]) -> Result<Removal, String> {
    let wanted: Vec<&str> = targets.iter().map(|t| t.get(1..).unwrap_or_default()).collect();
    let mut seen: Vec<&str> = Vec::new();
    let (mut gone, mut left, mut failed) = (Vec::new(), Vec::new(), None);
    let (mut changed, mut ended) = (false, false);
    for (n, line) in script_lines(out).enumerate() {
        if ended {
            return Err(format!("line {} follows END", n + 1));
        }
        let bad = || format!("line {} is not one the removal writes", n + 1);
        let mut f = line.split('\t');
        match (f.next(), f.next(), f.next(), f.next()) {
            (Some("END"), None, None, None) => ended = true,
            (Some("CHANGED"), None, None, None) => changed = true,
            (Some("E"), Some(m), None, None) => {
                return Err(format!("the removal stopped: {}", unhex(m).ok_or_else(bad)?));
            }
            (Some(k @ ("GONE" | "LEFT")), Some(x), None, None) => {
                if !wanted.contains(&x) || seen.contains(&x) {
                    return Err(bad());
                }
                seen.push(x);
                let rel = unhex(x).ok_or_else(bad)?;
                if k == "GONE" {
                    gone.push(rel);
                } else {
                    left.push(rel);
                }
            }
            (Some("FAIL"), Some(x), Some(m), None) => {
                if !wanted.contains(&x) || failed.is_some() {
                    return Err(bad());
                }
                failed = Some((unhex(x).ok_or_else(bad)?, unhex(m).ok_or_else(bad)?));
            }
            _ => return Err(bad()),
        }
    }
    if !ended {
        return Err("the removal's output stopped before END".into());
    }
    if changed {
        return if seen.is_empty() && failed.is_none() {
            Ok(Removal::Changed)
        } else {
            Err("the removal said the objects changed and reported on them too".into())
        };
    }
    if seen.len() != wanted.len() {
        return Err(format!("the removal reported on {} of {} objects", seen.len(), wanted.len()));
    }
    Ok(Removal::Ran { gone, left, failed })
}

pub(crate) fn result_line(state: &str, r: &Result<Removal, String>) -> String {
    match r {
        Ok(Removal::Changed) => format!("remove-wmi v1 result state={state} changed: nothing was removed"),
        Ok(Removal::Ran { gone, left, failed }) => format!(
            "remove-wmi v1 result state={state} gone={} left={} failed={}",
            gone.len(),
            left.len(),
            usize::from(failed.is_some())
        ),
        Err(_) => format!("remove-wmi v1 result state={state} unknown: the removal did not report back"),
    }
}

const SHOWN: &[&str] =
    &["CommandLineTemplate", "ExecutablePath", "WorkingDirectory", "ScriptingEngine", "ScriptFileName", "ScriptText"];

pub(crate) fn plan_lines(p: &Plan) -> Vec<String> {
    let c = &p.consumer;
    let mut out = vec![
        format!("remove WMI subscription `{}` ({NAMESPACE})", h(&c.name)),
        format!("  consumer: {} ({})", h(&c.relpath), h(&c.class)),
    ];
    let mut runs = false;
    for key in SHOWN {
        let Some(v) = p.props.iter().find(|x| x.name == *key).map(|x| x.value.as_str()) else { continue };
        if v.trim().is_empty() {
            continue;
        }
        runs = true;
        match v.lines().count() {
            n if n > 1 => out.push(format!("    {key} ({n} lines): {}", h(v))),
            _ => out.push(format!("    {key}: {}", h(v))),
        }
    }
    if !runs {
        out.push("    (no command line or script: it runs nothing this verb can show)".into());
    }
    if p.bindings.is_empty() {

        out.push(format!(
            "  0 bindings to remove: none in {NAMESPACE} references it (a binding in another \
             namespace, which this verb does not read, may still fire it until the consumer is gone)"
        ));
    } else {
        out.push(format!("  {} binding(s) to remove:", p.bindings.len()));
        out.extend(p.bindings.iter().map(|b| format!("    {}", h(&b.relpath))));
    }
    if p.filters.is_empty() {
        out.push("  0 filters to remove".into());
    } else {
        out.push(format!("  {} filter(s) to remove (no other binding uses them):", p.filters.len()));
        out.extend(p.filters.iter().map(|f| format!("    {}  query: {}", h(&f.relpath), h(&f.query))));
    }
    if !p.kept.is_empty() {
        out.push(format!("  {} filter(s) kept:", p.kept.len()));
        out.extend(p.kept.iter().map(|(f, why)| format!("    {}  ({})", h(f), h(why))));
    }
    out.push(
        "  NOT one-command reversible: every property of these objects, and their MOF, is written to \
         the fix log (%ProgramData%\\hemostat\\fixes.log) before anything is removed, and nothing is \
         removed if that write fails."
            .into(),
    );
    out
}

pub(crate) fn is_armed(args: &[String], name: &str) -> bool {
    args.iter().filter(|a| a.as_str() == "--arm").count() > usize::from(name == "--arm")
}

#[cfg(any(test, target_os = "windows"))]
pub(crate) fn ps_invocation(script: &str, root: &str, inputs: &[(&str, &str)]) -> (Vec<String>, Vec<(String, String)>) {
    let mut args: Vec<String> =
        ["-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand"].iter().map(|s| (*s).to_string()).collect();
    args.push(hemostat_sensor_win::wmi::encoded_command(script));
    let mut env = vec![
        ("SystemRoot".to_string(), root.to_string()),
        ("windir".to_string(), root.to_string()),
        ("SystemDrive".to_string(), root.get(..2).unwrap_or("C:").to_string()),
        ("TEMP".to_string(), format!(r"{root}\Temp")),
    ];
    env.extend(inputs.iter().map(|(k, v)| ((*k).to_string(), (*v).to_string())));
    (args, env)
}

#[cfg(any(test, target_os = "windows"))]
fn read_capped(mut r: impl std::io::Read, cap: usize) -> std::io::Result<(Vec<u8>, bool)> {
    use std::io::Read as _;
    let mut buf = Vec::new();
    (&mut r).take(u64::try_from(cap).unwrap_or(u64::MAX)).read_to_end(&mut buf)?;
    let more = std::io::copy(&mut r, &mut std::io::sink())? > 0;
    Ok((buf, more))
}

#[cfg(target_os = "windows")]
const DESCRIBE_LIMIT: std::time::Duration = std::time::Duration::from_secs(60);

#[cfg(target_os = "windows")]
const REMOVE_LIMIT: std::time::Duration = std::time::Duration::from_secs(120);

#[cfg(target_os = "windows")]
const MAX_STDERR: usize = 64 * 1024;

#[cfg(target_os = "windows")]
fn run_ps(script: &str, inputs: &[(&str, &str)], limit: std::time::Duration) -> Result<String, String> {
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
    let exe = format!(r"{root}\System32\WindowsPowerShell\v1.0\powershell.exe");
    let trust = hemostat_sensor_win::authenticode::verify(&exe);
    if !trust.is_valid() {
        return Err(format!("{exe} was not started: its signature did not verify ({})", trust.token()));
    }
    let (args, env) = ps_invocation(script, &root, inputs);
    let mut child = Command::new(&exe)
        .args(&args)
        .env_clear()
        .envs(env)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("{exe} could not be started: {e}"))?;
    let stop = |child: &mut std::process::Child, why: String| {
        let _ = child.kill();
        let _ = child.wait();
        Err(why)
    };
    let (Some(stdout), Some(stderr)) = (child.stdout.take(), child.stderr.take()) else {
        return stop(&mut child, "the child's output could not be read".into());
    };
    let out = std::thread::Builder::new().spawn(move || read_capped(stdout, MAX_OUTPUT));
    let err = std::thread::Builder::new().spawn(move || read_capped(stderr, MAX_STDERR));
    let (Ok(out), Ok(err)) = (out, err) else {
        return stop(&mut child, "the child's output could not be read".into());
    };
    let start = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(st)) => break st,
            Ok(None) if start.elapsed() < limit => std::thread::sleep(Duration::from_millis(50)),
            Ok(None) => return stop(&mut child, format!("{exe} did not finish within {} s and was stopped", limit.as_secs())),
            Err(e) => return stop(&mut child, format!("{exe} could not be waited on: {e}")),
        }
    };
    let (out, more) = out
        .join()
        .map_err(|_| "the child's output could not be read".to_string())?
        .map_err(|e| format!("the child's output could not be read: {e}"))?;
    let err = err.join().ok().and_then(Result::ok).map(|(b, _)| b).unwrap_or_default();
    if more {
        return Err(format!("{exe} wrote more than {MAX_OUTPUT} bytes"));
    }
    if !status.success() {
        return Err(format!("{exe} exited {status}: {}", String::from_utf8_lossy(&err).trim()));
    }
    String::from_utf8(out).map_err(|_| format!("{exe} wrote output that is not UTF-8"))
}

#[cfg(target_os = "windows")]
pub(crate) fn remove_wmi(args: &[String], name: &str, _json: bool) -> u8 {
    const V: &str = "hemostat remediate --remove-wmi";
    if name.trim().is_empty() {
        eprintln!("{V} <name> [--arm]: name the WMI event consumer");
        return EXIT_USAGE;
    }
    if let Some(why) = name_refusal(name) {
        eprintln!("{V}: refused — {why}. Nothing was run; remove this subscription by hand.");
        return EXIT_POLICY;
    }
    if wmi_is_protected(name) {
        eprintln!("{V}: refused — `{}` is a DataDog consumer (protected, packet rule 14)", h(name));
        return EXIT_POLICY;
    }

    let d = match run_ps(DESCRIBE_SCRIPT, &[(ENV_NAME, name)], DESCRIBE_LIMIT).and_then(|o| parse_described(&o)) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("{V}: {NAMESPACE} could not be read, so nothing was removed: {}", h(&e));
            return EXIT_ENFORCER;
        }
    };
    let p = match plan(&d, name) {
        Ok(p) => p,
        Err(Refusal::NotFound) => {
            eprintln!(
                "{V}: no WMI event consumer in {NAMESPACE} is named exactly `{}` (case and all; \
                 root\\default is not handled by this verb)",
                h(name)
            );
            return EXIT_POLICY;
        }
        Err(Refusal::Ambiguous(paths)) => {
            let paths: Vec<String> = paths.iter().map(|x| h(x)).collect();
            eprintln!(
                "{V}: refused — {} consumers are named `{}`, one per class: {}. Remove the one \
                 you mean by hand.",
                paths.len(),
                h(name),
                paths.join(", ")
            );
            return EXIT_POLICY;
        }
        Err(Refusal::Protected { object, field }) => {
            eprintln!(
                "{V}: refused — {} would be removed and its {} mentions DataDog (protected, \
                 packet rule 14). If it is the red team's, remove it by hand.",
                h(&object),
                h(&field)
            );
            return EXIT_POLICY;
        }
    };
    for line in plan_lines(&p) {
        println!("{line}");
    }
    if !is_armed(args, name) {
        println!("\nNothing was changed. Add --arm to apply.");
        return EXIT_DRYRUN;
    }
    let targets = removal_targets(&p);
    let target_env = targets.join(",");
    if [name, target_env.as_str()].iter().any(|v| v.encode_utf16().count() > MAX_ENV) {
        eprintln!("{V}: refused — these object paths are too long to hand to PowerShell; nothing was removed");
        return EXIT_POLICY;
    }

    let record = record_line(&p);
    if !record_reads_back(&p, &record) {
        eprintln!("{V}: the record of this removal does not read back, so nothing was removed");
        return EXIT_ENFORCER;
    }
    if let Err(e) = crate::win_restore::audit(&record) {
        eprintln!(
            "{V}: the fix log could not be written ({e}), so nothing was removed: that record is \
             this removal's only undo"
        );
        return EXIT_ENFORCER;
    }
    let inputs = [(ENV_NAME, name), (ENV_STATE, p.state.as_str()), (ENV_REMOVE, target_env.as_str())];
    let result = run_ps(REMOVE_SCRIPT, &inputs, REMOVE_LIMIT).and_then(|o| parse_removal(&o, &targets));
    let code = match &result {
        Ok(r) if r.complete() => {
            println!(
                "removed WMI subscription `{}`: the consumer, {} binding(s) and {} filter(s), each read back gone",
                h(name),
                p.bindings.len(),
                p.filters.len()
            );
            println!("  its definition is recorded in the fix log (WMI has no one-command undo)");
            EXIT_OK
        }
        Ok(Removal::Changed) => {
            eprintln!(
                "{V}: {NAMESPACE} changed between the look and the removal, so nothing was removed. \
                 Run it again."
            );
            EXIT_ENFORCER
        }
        Ok(Removal::Ran { left, failed, .. }) => {
            if let Some((at, why)) = failed {
                eprintln!("{V}: the removal stopped at {}: {}", h(at), h(why));
            }
            for l in left {
                eprintln!("  still there: {}", h(l));
            }
            eprintln!("  the definition of every object is in the fix log");
            EXIT_ENFORCER
        }
        Err(e) => {
            eprintln!(
                "{V}: the removal did not report back ({}). What is left is unknown: run the dry \
                 run again to see. The definition of every object is in the fix log.",
                h(e)
            );
            EXIT_ENFORCER
        }
    };
    crate::win_restore::audit_or_warn(&result_line(&p.state, &result));
    code
}
