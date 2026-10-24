use std::collections::BTreeSet;

use hs_core::severity::Severity;
use sha2::{Digest as _, Sha256};

use crate::configxml::{self, Config};
use crate::tools::{Invocation, Output, Runner, Tool};

pub const FILTER_INC_SHA256: &str = "dcce7af227f710be7b83b2015c20bebbfada16f78b70c166ff46648ce149da79";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Range {

    pub name: &'static str,

    pub lo: u32,

    pub hi: u32,

    pub from: &'static str,
}

pub const RANGES: [Range; 6] = [
    Range { name: "a rule filter.inc generates", lo: 1_000_000_000, hi: 1_009_999_999, from: "TRACKER_DEFAULT, L122" },
    Range { name: "a negated-destination route rule", lo: 10_000_000, hi: 10_999_999, from: "NEGATE_TRACKER_DEFAULT, L123" },
    Range { name: "the anti-lockout rule", lo: 10_000, hi: 10_999, from: "ANTILOCKOUT_TRACKER_START/END, L124" },
    Range { name: "a bogon network block", lo: 11_000, hi: 11_999, from: "BOGONS_TRACKER_START/END, L126" },
    Range { name: "a private network block", lo: 12_000, hi: 12_999, from: "RFC1918_TRACKER_START/END, L128" },
    Range { name: "a captive portal rule", lo: 13_000, hi: 13_999, from: "CAPTIVEPORTAL_TRACKER_START/END, L130" },
];

pub fn fixed_range(id: u32) -> Option<&'static Range> {
    RANGES.iter().find(|r| (r.lo..=r.hi).contains(&id))
}

pub const ALWAYS_EMPTY: [&str; 3] = ["userrules", "natearly", "natrules"];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Feature {

    OpenVpn,

    IpsecMobile,

    TftpProxy,

    Upnp,

    CaptivePortal,
}

impl Feature {

    pub fn label(self) -> &'static str {
        match self {
            Feature::OpenVpn => "an OpenVPN server",
            Feature::IpsecMobile => "IPsec mobile clients",
            Feature::TftpProxy => "the TFTP proxy",
            Feature::Upnp => "UPnP & NAT-PMP",
            Feature::CaptivePortal => "a captive portal zone",
        }
    }

    pub fn enabled(self, c: &Config) -> bool {
        let r = c.root();
        match self {
            Feature::OpenVpn => r.get("openvpn").is_some_and(|o| o.all("openvpn-server").any(|s| !s.has("disable"))),
            Feature::IpsecMobile => r.get("ipsec").is_some_and(|i| i.all("phase1").any(|p| p.has("mobile") && !p.has("disabled"))),
            Feature::TftpProxy => r.text_at("system/tftpinterface").is_some_and(|t| !t.is_empty()),
            Feature::Upnp => r.text_at("installedpackages/miniupnpd/config/enable") == Some("on"),
            Feature::CaptivePortal => r.get("captiveportal").is_some_and(|cp| cp.children.iter().any(|z| z.has("enable"))),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnchorKind {

    AlwaysEmpty,

    Feature(Feature, bool),

    Declared,

    Undeclared,
}

pub fn anchor_kind(path: &str, config: Option<&Config>, declared: &BTreeSet<String>) -> AnchorKind {
    let top = path.split('/').next().unwrap_or(path);
    if ALWAYS_EMPTY.contains(&top) {
        return AnchorKind::AlwaysEmpty;
    }
    let feature = match top {
        "openvpn" => Some(Feature::OpenVpn),
        "ipsec" => Some(Feature::IpsecMobile),
        "tftp-proxy" => Some(Feature::TftpProxy),
        "miniupnpd" => Some(Feature::Upnp),
        t if t.starts_with("cpzoneid_") => Some(Feature::CaptivePortal),
        _ => None,
    };
    if let Some(f) = feature {
        return AnchorKind::Feature(f, config.is_some_and(|c| f.enabled(c)));
    }

    let covered = declared.iter().any(|d| {
        let d = d.strip_suffix("/*").unwrap_or(d);
        path == d || path.strip_prefix(d).is_some_and(|rest| rest.starts_with('/'))
    });
    if covered {
        AnchorKind::Declared
    } else {
        AnchorKind::Undeclared
    }
}

pub const CONFIG_PATH: &str = configxml::CONFIG_PATH;

pub const RULES_DEBUG: &str = "/tmp/rules.debug";

pub const FILTER_DIRTY: &str = "/var/run/filter.dirty";

pub const MAX_FILE: u64 = configxml::MAX_BYTES;

pub const MAX_ANCHORS: usize = 512;

pub const MAX_TABLES: usize = 1024;

pub fn pfctl_key(args: &[&str]) -> String {
    let mut k = String::from("pfctl");
    for a in args {
        k.push(' ');
        k.push_str(a);
    }
    k
}

pub const MAIN: [&[&str]; 6] = [
    &["-sr", "-vv"],
    &["-sn", "-vv"],
    &["-s", "ether", "-vv"],
    &["-sA", "-v"],
    &["-sT"],
    &["-si"],
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Set {

    Filter,

    Nat,

    Ether,
}

impl Set {

    pub fn args(self, anchor: Option<&str>) -> Vec<String> {
        let mut v = Vec::new();
        if let Some(a) = anchor {
            v.push("-a".to_string());
            v.push(a.to_string());
        }
        let tail: &[&str] = match self {
            Set::Filter => &["-sr", "-vv"],
            Set::Nat => &["-sn", "-vv"],
            Set::Ether => &["-s", "ether", "-vv"],
        };
        v.extend(tail.iter().map(|s| (*s).to_string()));
        v
    }

    pub fn key(self, anchor: Option<&str>) -> String {
        let a = self.args(anchor);
        pfctl_key(&a.iter().map(String::as_str).collect::<Vec<_>>())
    }

    pub fn label(self) -> &'static str {
        match self {
            Set::Filter => "filter",
            Set::Nat => "NAT",
            Set::Ether => "ether",
        }
    }

    const ALL: [Set; 3] = [Set::Filter, Set::Nat, Set::Ether];
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Got {

    Ran(Output),

    Read(Vec<u8>),

    Absent,

    Failed(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Source {

    pub key: String,

    pub got: Got,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Collected {

    pub sources: Vec<Source>,

    pub tools: Vec<(String, String)>,

    pub gaps: Vec<String>,
}

impl Collected {

    pub fn get(&self, key: &str) -> Option<&Got> {
        self.sources.iter().find(|s| s.key == key).map(|s| &s.got)
    }
}

pub type ReadFile<'a> = dyn FnMut(&str) -> Result<Option<Vec<u8>>, String> + 'a;

fn run(r: &mut dyn Runner, args: &[&str]) -> Got {
    match r.run(&Invocation::new(Tool::Pfctl, args)) {
        Ok(o) => Got::Ran(o),
        Err(e) => Got::Failed(e.to_string()),
    }
}

pub fn collect(r: &mut dyn Runner, read: &mut ReadFile<'_>) -> Collected {
    let mut c = Collected::default();
    for args in MAIN {
        let got = run(r, args);
        c.sources.push(Source { key: pfctl_key(args), got });
    }
    let anchors = match c.get(&pfctl_key(&["-sA", "-v"])) {
        Some(Got::Ran(o)) if o.success() => parse_anchor_list(&o.text()),
        _ => Vec::new(),
    };
    if anchors.len() > MAX_ANCHORS {
        c.gaps.push(format!(
            "pf lists {} anchors; the first {MAX_ANCHORS} were walked and the rest were not",
            anchors.len()
        ));
    }
    for a in anchors.iter().take(MAX_ANCHORS) {
        if anchor_name_ok(a).is_err() {
            continue;
        }
        for set in Set::ALL {
            let args = set.args(Some(a));
            let got = run(r, &args.iter().map(String::as_str).collect::<Vec<_>>());
            c.sources.push(Source { key: set.key(Some(a)), got });
        }
    }
    let tables = match c.get(&pfctl_key(&["-sT"])) {
        Some(Got::Ran(o)) if o.success() => o.text().lines().map(str::trim).filter(|l| !l.is_empty()).map(str::to_string).collect(),
        _ => Vec::<String>::new(),
    };
    if tables.len() > MAX_TABLES {
        c.gaps.push(format!("pf lists {} tables; the first {MAX_TABLES} were listed", tables.len()));
    }
    for t in tables.iter().take(MAX_TABLES) {
        if !table_name_ok(t) {
            continue;
        }
        let args = ["-t", t.as_str(), "-T", "show"];
        let got = run(r, &args);
        c.sources.push(Source { key: pfctl_key(&args), got });
    }
    for path in [CONFIG_PATH, RULES_DEBUG, FILTER_DIRTY] {
        let got = match read(path) {
            Ok(Some(b)) => Got::Read(b),
            Ok(None) => Got::Absent,
            Err(e) => Got::Failed(e),
        };
        c.sources.push(Source { key: path.to_string(), got });
    }
    c
}

pub fn anchor_name_ok(name: &str) -> Result<(), String> {
    let ok = !name.is_empty()
        && name.len() < 1024
        && !name.starts_with('-')
        && name.bytes().all(|b| b.is_ascii_graphic() && b != b'"' && b != b'\\');
    if ok {
        Ok(())
    } else {
        Err(format!("an anchor name pfctl printed that cannot be named back to it: {:?}", name.chars().take(80).collect::<String>()))
    }
}

pub fn table_name_ok(name: &str) -> bool {
    !name.is_empty() && name.len() < 32 && !name.starts_with('-') && name.bytes().all(|b| b.is_ascii_graphic())
}

pub fn parse_anchor_list(text: &str) -> Vec<String> {
    text.lines().map(str::trim).filter(|l| !l.is_empty()).map(str::to_string).collect()
}

pub const KIND: &str = "pfsense-fw-rules";

pub const SCOPE: u32 = 1;

pub const CHUNK: usize = 3 * 1024 * 1024;

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

pub fn records(c: &Collected) -> Vec<Vec<u8>> {
    let mut out = vec![[b"k".as_slice(), KIND.as_bytes()].concat(), format!("v{SCOPE}").into_bytes()];
    for s in &c.sources {
        let (tag, status, body, stderr): (u8, String, &[u8], Option<&[u8]>) = match &s.got {
            Got::Ran(o) => (b'o', o.status.map_or("-".into(), |v| v.to_string()), &o.stdout, Some(&o.stderr)),
            Got::Read(b) => (b'f', "-".into(), b, None),
            Got::Absent => (b'a', "-".into(), &[], None),
            Got::Failed(why) => (b'x', "-".into(), why.as_bytes(), None),
        };
        let mut h = b"H".to_vec();
        h.extend_from_slice(s.key.as_bytes());
        h.push(0);
        h.push(tag);
        h.push(0);
        h.extend_from_slice(status.as_bytes());
        h.push(0);
        h.extend_from_slice(body.len().to_string().as_bytes());
        h.push(0);
        h.extend_from_slice(hex(&Sha256::digest(body)).as_bytes());
        out.push(h);
        out.extend(body.chunks(CHUNK).map(|p| [b"B".as_slice(), p].concat()));
        if let Some(e) = stderr {
            out.push([b"E".as_slice(), e].concat());
        }
    }
    for (t, d) in &c.tools {
        out.push([b"T".as_slice(), t.as_bytes(), b"\0", d.as_bytes()].concat());
    }
    for g in &c.gaps {
        out.push([b"g".as_slice(), g.as_bytes()].concat());
    }
    out
}

pub fn from_records<'a>(recs: impl IntoIterator<Item = &'a [u8]>) -> Result<Collected, String> {
    struct Open {
        key: String,
        tag: u8,
        status: Option<i32>,
        len: usize,
        sha: String,
        body: Vec<u8>,
        stderr: Option<Vec<u8>>,
    }
    fn finish(o: Open, c: &mut Collected) -> Result<(), String> {
        if o.body.len() != o.len || hex(&Sha256::digest(&o.body)) != o.sha {
            return Err(format!("{}: the sealed body does not match its own header", o.key));
        }
        let got = match o.tag {
            b'o' => Got::Ran(Output { status: o.status, stdout: o.body, stderr: o.stderr.unwrap_or_default() }),
            b'f' => Got::Read(o.body),
            b'a' => Got::Absent,
            b'x' => Got::Failed(String::from_utf8_lossy(&o.body).into_owned()),
            _ => return Err(format!("{}: a source of a kind this build does not know", o.key)),
        };
        c.sources.push(Source { key: o.key, got });
        Ok(())
    }
    let mut c = Collected::default();
    let (mut kind, mut scope) = (None, None);
    let mut open: Option<Open> = None;
    for r in recs {
        let Some((&t, rest)) = r.split_first() else { return Err("an empty record".into()) };
        match t {
            b'k' => kind = Some(String::from_utf8_lossy(rest).into_owned()),
            b'v' => scope = std::str::from_utf8(rest).ok().and_then(|s| s.parse::<u32>().ok()),
            b'H' => {
                if let Some(o) = open.take() {
                    finish(o, &mut c)?;
                }
                let f: Vec<&[u8]> = rest.split(|b| *b == 0).collect();
                let [key, tag, status, len, sha] = f.as_slice() else { return Err("a malformed source header".into()) };
                let text = |b: &[u8]| String::from_utf8_lossy(b).into_owned();
                open = Some(Open {
                    key: text(key),
                    tag: *tag.first().ok_or("a source header with no tag")?,
                    status: text(status).parse().ok(),
                    len: text(len).parse().map_err(|_| "a source header with no length")?,
                    sha: text(sha),
                    body: Vec::new(),
                    stderr: None,
                });
            }
            b'B' => open.as_mut().ok_or("a body before its header")?.body.extend_from_slice(rest),
            b'E' => open.as_mut().ok_or("stderr before its header")?.stderr = Some(rest.to_vec()),
            b'T' => {
                let mut f = rest.splitn(2, |b| *b == 0);
                let (n, d) = (f.next().unwrap_or_default(), f.next().unwrap_or_default());
                c.tools.push((String::from_utf8_lossy(n).into_owned(), String::from_utf8_lossy(d).into_owned()));
            }
            b'g' => c.gaps.push(String::from_utf8_lossy(rest).into_owned()),
            _ => return Err("a record of a kind this build does not know".into()),
        }
    }
    if let Some(o) = open.take() {
        finish(o, &mut c)?;
    }
    if kind.as_deref() != Some(KIND) {
        return Err(format!("this is not a fw rules store (kind {})", kind.as_deref().unwrap_or("none")));
    }
    match scope {
        Some(s) if s <= SCOPE => Ok(c),
        Some(s) => Err(format!("the store was written by a newer build (scope {s}, this one {SCOPE})")),
        None => Err("the store has no scope record".into()),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PfRule {

    pub set: Set,

    pub index: u32,

    pub text: String,

    pub action: String,

    pub ridentifier: Result<Option<u32>, String>,

    pub calls: Option<String>,

    pub inserted: Option<String>,

    pub packets: Option<u64>,
}

impl PfRule {

    pub fn decides(&self) -> bool {
        self.set == Set::Filter && matches!(self.action.as_str(), "pass" | "block" | "match")
    }

    pub fn shown(&self) -> String {
        match &self.inserted {
            Some(i) => format!("{} [inserted by {i}]", self.text),
            None => self.text.clone(),
        }
    }
}

fn words(text: &str) -> Result<Vec<(bool, &str)>, String> {
    let mut out = Vec::new();
    let mut rest = text;
    loop {
        rest = rest.trim_start();
        if rest.is_empty() {
            return Ok(out);
        }
        if let Some(q) = rest.strip_prefix('"') {
            let end = q.find('"').ok_or("an unterminated quote")?;
            out.push((true, q.get(..end).unwrap_or_default()));
            rest = q.get(end + 1..).unwrap_or_default();

            if !(rest.is_empty() || rest.starts_with(' ')) {
                return Err("a quote inside a quoted string".into());
            }
        } else {
            let end = rest.find([' ', '"']).unwrap_or(rest.len());
            if rest.get(end..).is_some_and(|r| r.starts_with('"')) {
                return Err("a quote inside a word".into());
            }
            out.push((false, rest.get(..end).unwrap_or_default()));
            rest = rest.get(end..).unwrap_or_default();
        }
    }
}

fn rule_from(set: Set, index: u32, text: &str) -> PfRule {
    let w = words(text);
    fn bare<'t>(w: &[(bool, &'t str)], i: usize) -> Option<&'t str> {
        w.get(i).filter(|(q, _)| !q).map(|(_, s)| *s)
    }
    let (action, calls, ridentifier) = match &w {
        Ok(w) => {
            let first = if set == Set::Ether && bare(w, 0) == Some("ether") { 1 } else { 0 };
            let action = bare(w, first).unwrap_or_default().to_string();
            let calls = if action.ends_with("anchor") {
                w.get(first + 1).filter(|(q, _)| *q).map(|(_, s)| (*s).to_string())
            } else {
                None
            };
            let ids: Vec<&str> = w
                .windows(2)
                .filter(|p| matches!(p, [(false, "ridentifier"), (false, _)]))
                .filter_map(|p| p.get(1).map(|(_, s)| *s))
                .collect();
            let rid = match ids.as_slice() {
                [] => Ok(None),
                [one] => one.parse::<u32>().map(Some).map_err(|_| format!("ridentifier {one:?} is not a number")),
                _ => Err("more than one ridentifier".into()),
            };
            (action, calls, rid)
        }
        Err(e) => (text.split(' ').next().unwrap_or_default().to_string(), None, Err(e.clone())),
    };
    PfRule { set, index, text: text.to_string(), action, ridentifier, calls, inserted: None, packets: None }
}

fn number_after(s: &str, label: &str) -> Option<u64> {
    let at = s.find(label)? + label.len();
    s.get(at..)?.split_whitespace().next()?.parse().ok()
}

pub fn parse_rules(text: &str, set: Set) -> Result<Vec<PfRule>, String> {
    let mut out: Vec<PfRule> = Vec::new();
    let mut depth = 0usize;
    let mut next = 0u32;
    for (n, line) in text.lines().enumerate() {
        let at = || format!("line {}: {:?}", n + 1, line.chars().take(120).collect::<String>());
        let t = line.trim_start();
        if t.is_empty() {
            continue;
        }
        if t == "}" {
            depth = depth.checked_sub(1).ok_or_else(|| format!("{} closes a brace never opened", at()))?;
            continue;
        }
        if t.starts_with('[') && t.ends_with(']') {
            if depth == 0 {
                let r = out.last_mut().ok_or_else(|| format!("{} comes before any rule", at()))?;
                if let Some(i) = t.find("Inserted: ") {
                    let s = t.get(i + "Inserted: ".len()..).unwrap_or_default();
                    let who: Vec<&str> = s.split_whitespace().take(4).collect();
                    if let [u, uid, p, pid] = who.as_slice() {
                        if *u == "uid" && *p == "pid" {
                            r.inserted = Some(format!("uid {uid} pid {pid}"));
                        }
                    }
                }
                if t.contains("Evaluations:") {
                    r.packets = number_after(t, "Packets:");
                }
            }
            continue;
        }
        let Some(h) = t.strip_prefix('@') else { return Err(format!("{} is not a rule or a counter", at())) };
        let (num, body) = h.split_once(' ').ok_or_else(|| format!("{} has no rule after its number", at()))?;
        let idx: u32 = num.parse().map_err(|_| format!("{} has no rule number", at()))?;
        let opens = body.ends_with(" {");
        if depth == 0 {
            if idx != next && idx != 0 {
                return Err(format!("{} is out of order (expected @{next} or @0)", at()));
            }
            next = idx + 1;
            out.push(rule_from(set, idx, body.strip_suffix(" {").unwrap_or(body)));
        }
        if opens {
            depth += 1;
        }
    }
    if depth != 0 {
        return Err("an inline anchor's brace is never closed".into());
    }
    Ok(out)
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Generated {

    pub ridentifiers: BTreeSet<u32>,

    pub anchors: BTreeSet<String>,

    pub tables: BTreeSet<String>,
}

pub fn scan_generated(text: &str) -> Generated {
    let mut g = Generated::default();
    for line in text.lines() {
        let l = line.trim();
        if l.starts_with('#') {
            continue;
        }
        let toks: Vec<&str> = l.split_whitespace().collect();
        for p in toks.windows(2) {
            if let [a, b] = p {
                if *a == "ridentifier" {
                    if let Ok(n) = b.parse::<u32>() {
                        g.ridentifiers.insert(n);
                    }
                }
                if matches!(*a, "anchor" | "nat-anchor" | "rdr-anchor" | "binat-anchor") {
                    if let Some(name) = b.strip_prefix('"').and_then(|s| s.strip_suffix('"')) {
                        g.anchors.insert(name.to_string());
                    }
                }
            }
        }
        let mut rest = l;
        while let Some(i) = rest.find('<') {
            let after = rest.get(i + 1..).unwrap_or_default();
            match after.find('>') {
                Some(j) => {
                    let name = after.get(..j).unwrap_or_default();
                    let name = name.split(':').next().unwrap_or(name);
                    if table_name_ok(name) {
                        g.tables.insert(name.to_string());
                    }
                    rest = after.get(j + 1..).unwrap_or_default();
                }
                None => break,
            }
        }
    }
    g
}

pub fn pf_enabled(si: &str) -> Option<bool> {
    let l = si.lines().find_map(|l| l.trim_start().strip_prefix("Status: "))?;
    if l.starts_with("Enabled") {
        Some(true)
    } else if l.starts_with("Disabled") {
        Some(false)
    } else {
        None
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {

    pub severity: Severity,

    pub subject: String,

    pub what: String,

    pub why: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnchorRow {

    pub path: String,

    pub kind: AnchorKind,

    pub rules: usize,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Summary {

    pub pf_enabled: Option<bool>,

    pub filter_rules: usize,

    pub from_config: usize,

    pub generated: usize,

    pub nat_rules: usize,

    pub ether_rules: usize,

    pub anchors: Vec<AnchorRow>,

    pub tables: usize,

    pub config_trackers: usize,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Judged {

    pub findings: Vec<Finding>,

    pub gaps: Vec<String>,

    pub summary: Summary,
}

const MAX_SHOWN: usize = 12;

fn listing(c: &Collected, key: &str, anchored: bool, gaps: &mut Vec<String>) -> Option<String> {
    match c.get(key) {
        None => {
            gaps.push(format!("{key} was not collected"));
            None
        }
        Some(Got::Ran(o)) if o.success() => Some(o.text()),
        Some(Got::Ran(o)) => {
            let err = String::from_utf8_lossy(&o.stderr);

            if anchored && (err.contains("No such file or directory") || err.contains("not found")) {
                return Some(String::new());
            }
            gaps.push(format!("{key} exited {:?}: {}", o.status, err.trim()));
            None
        }
        Some(Got::Failed(why)) => {
            gaps.push(format!("{key}: {why}"));
            None
        }
        Some(Got::Read(_) | Got::Absent) => {
            gaps.push(format!("{key}: sealed as a file, not a listing"));
            None
        }
    }
}

fn rules_of(c: &Collected, set: Set, anchor: Option<&str>, j: &mut Judged) -> Vec<PfRule> {
    let key = set.key(anchor);
    let Some(text) = listing(c, &key, anchor.is_some(), &mut j.gaps) else { return Vec::new() };
    match parse_rules(&text, set) {
        Ok(r) => r,
        Err(e) => {
            j.findings.push(Finding {
                severity: Severity::Warn,
                subject: key.clone(),
                what: format!("the listing does not read as pfctl prints rules: {e}"),
                why: "pfSense writes nothing that pfctl lists this way, and a rule whose label carries a \
                      line break could hide behind one. Read the raw listing in the sealed store"
                    .into(),
            });
            j.gaps.push(format!("{key} could not be parsed, so its rules were not judged"));
            Vec::new()
        }
    }
}

fn file<'c>(c: &'c Collected, path: &str) -> Result<Option<&'c [u8]>, String> {
    match c.get(path) {
        Some(Got::Read(b)) => Ok(Some(b)),
        Some(Got::Absent) => Ok(None),
        Some(Got::Failed(why)) => Err(why.clone()),
        Some(Got::Ran(_)) => Err("sealed as a listing, not a file".into()),
        None => Err("not collected".into()),
    }
}

fn shown(rules: &[&PfRule]) -> String {
    let mut s: Vec<String> = rules.iter().take(MAX_SHOWN).map(|r| format!("{} @{} {}", r.set.label(), r.index, r.shown())).collect();
    if rules.len() > MAX_SHOWN {
        s.push(format!("… and {} more", rules.len() - MAX_SHOWN));
    }
    s.join("\n")
}

pub fn judge(c: &Collected) -> Judged {
    let mut j = Judged::default();
    j.gaps.extend(c.gaps.iter().cloned());

    let config = match file(c, CONFIG_PATH) {
        Ok(Some(b)) => match configxml::parse(b) {
            Ok(cfg) => Some(cfg),
            Err(e) => {
                j.gaps.push(format!("{CONFIG_PATH} was refused ({e}), so no rule could be matched to it"));
                None
            }
        },
        Ok(None) => {
            j.gaps.push(format!("{CONFIG_PATH} is not there, so no rule could be matched to it"));
            None
        }
        Err(e) => {
            j.gaps.push(format!("{CONFIG_PATH}: {e}, so no rule could be matched to it"));
            None
        }
    };
    let trackers: BTreeSet<u32> = config
        .as_ref()
        .map(|cfg| cfg.rules().iter().filter(|r| !r.disabled).filter_map(|r| r.tracker.as_deref()?.parse().ok()).collect())
        .unwrap_or_default();
    j.summary.config_trackers = trackers.len();

    let generated = match file(c, RULES_DEBUG) {
        Ok(Some(b)) => Some(scan_generated(&String::from_utf8_lossy(b))),
        Ok(None) => {
            j.findings.push(Finding {
                severity: Severity::Warn,
                subject: RULES_DEBUG.into(),
                what: "the file pfSense loads its ruleset from is not there".into(),
                why: "every filter reload writes it, so a box that has booted always has one; without it the \
                      running ruleset cannot be compared with what pfSense generated"
                    .into(),
            });
            j.gaps.push(format!("{RULES_DEBUG} is missing, so the anchors and tables it declares are unknown"));
            None
        }
        Err(e) => {
            j.gaps.push(format!("{RULES_DEBUG}: {e}"));
            None
        }
    };
    let dirty = matches!(file(c, FILTER_DIRTY), Ok(Some(_)));

    if let Some(si) = listing(c, &pfctl_key(&["-si"]), false, &mut j.gaps) {
        j.summary.pf_enabled = pf_enabled(&si);
        if j.summary.pf_enabled == Some(false) {
            j.findings.push(Finding {
                severity: Severity::Critical,
                subject: "pf".into(),
                what: "pf is disabled: no rule below is being enforced".into(),
                why: "pfSense never runs with pf off; `pfctl -d` turns the firewall into a router that \
                      passes everything. `pfctl -e` turns it back on; find out who turned it off first"
                    .into(),
            });
        }
    }

    let main = rules_of(c, Set::Filter, None, &mut j);
    let mut foreign: Vec<&PfRule> = Vec::new();
    let mut unreadable: Vec<&PfRule> = Vec::new();
    let mut ungenerated: Vec<&PfRule> = Vec::new();
    let mut unmatched_no_config: Vec<&PfRule> = Vec::new();
    for r in main.iter().filter(|r| r.decides()) {
        j.summary.filter_rules += 1;
        match &r.ridentifier {
            Err(_) => unreadable.push(r),
            Ok(Some(id)) if trackers.contains(id) => {
                j.summary.from_config += 1;
                if generated.as_ref().is_some_and(|g| !g.ridentifiers.contains(id)) {
                    ungenerated.push(r);
                }
            }
            Ok(Some(id)) if fixed_range(*id).is_some() => {
                j.summary.generated += 1;
                if generated.as_ref().is_some_and(|g| !g.ridentifiers.contains(id)) {
                    ungenerated.push(r);
                }
            }
            Ok(_) if config.is_none() => unmatched_no_config.push(r),
            Ok(_) => foreign.push(r),
        }
    }
    let pending = if dirty {
        " The GUI has filter changes that are not applied yet (/var/run/filter.dirty): a rule deleted \
         and not yet applied also looks like this, so apply them and run this again before acting."
    } else {
        ""
    };
    for r in &foreign {
        let id = match r.ridentifier {
            Ok(Some(n)) => format!("ridentifier {n}"),
            _ => "no ridentifier".into(),
        };
        j.findings.push(Finding {
            severity: Severity::Critical,
            subject: format!("filter rule @{}", r.index),
            what: format!("{id}: {}", r.shown()),
            why: format!(
                "pfSense loads every rule it writes with the rule's tracker from config.xml or one of its own \
                 fixed ranges (filter.inc); this one has neither, so it was loaded from somewhere else. \
                 It is sealed with the listing; the next filter reload removes it.{pending}"
            ),
        });
    }
    for r in &unreadable {
        j.findings.push(Finding {
            severity: Severity::Critical,
            subject: format!("filter rule @{}", r.index),
            what: r.shown(),
            why: format!(
                "its text cannot be read unambiguously ({}): pfSense strips quotes from every label it \
                 writes (fix_rule_label), so this rule is not one of pfSense's",
                r.ridentifier.as_ref().err().map_or("", String::as_str)
            ),
        });
    }
    if !unmatched_no_config.is_empty() {
        j.findings.push(Finding {
            severity: Severity::Warn,
            subject: "filter rules".into(),
            what: shown(&unmatched_no_config),
            why: "these rules' ridentifiers are not pfSense's own, and config.xml was not read, so whether \
                  they are the config's rules could not be checked"
                .into(),
        });
    }
    if !ungenerated.is_empty() {
        j.findings.push(Finding {
            severity: Severity::Warn,
            subject: "filter rules not in rules.debug".into(),
            what: shown(&ungenerated),
            why: format!(
                "their ridentifiers are accounted for, but {RULES_DEBUG} — the file pfSense generated and \
                 loaded last — has none of them, so the running ruleset is not the one pfSense last \
                 loaded. A filter reload (Status > Filter Reload) would put pfSense's back.{pending}"
            ),
        });
    }

    let nat = rules_of(c, Set::Nat, None, &mut j);
    j.summary.nat_rules = nat.iter().filter(|r| r.calls.is_none()).count();
    let ether = rules_of(c, Set::Ether, None, &mut j);
    j.summary.ether_rules = ether.len();
    let cp_on = config.as_ref().is_some_and(|cfg| Feature::CaptivePortal.enabled(cfg));
    if !ether.is_empty() && !cp_on {
        let refs: Vec<&PfRule> = ether.iter().collect();
        j.findings.push(Finding {
            severity: if config.is_some() { Severity::Critical } else { Severity::Warn },
            subject: "ether rules".into(),
            what: shown(&refs),
            why: "pfSense writes layer-2 rules only for a captive portal zone (captiveportal.inc), and no \
                  zone is enabled in config.xml, so these came from somewhere else"
                .into(),
        });
    }

    let empty = BTreeSet::new();
    let declared = generated.as_ref().map_or(&empty, |g| &g.anchors);
    let anchors = listing(c, &pfctl_key(&["-sA", "-v"]), false, &mut j.gaps).map(|t| parse_anchor_list(&t)).unwrap_or_default();
    for a in anchors.iter().take(MAX_ANCHORS) {
        if let Err(e) = anchor_name_ok(a) {
            j.findings.push(Finding {
                severity: Severity::Critical,
                subject: "anchors".into(),
                what: e,
                why: "pfSense names its anchors in plain words; this one could not be listed, so whatever \
                      it holds was not seen"
                    .into(),
            });
            j.gaps.push("an anchor with an unusable name was not walked".into());
            continue;
        }
        let kind = anchor_kind(a, config.as_ref(), declared);
        let rules: Vec<PfRule> = Set::ALL.iter().flat_map(|s| rules_of(c, *s, Some(a), &mut j)).collect();
        j.summary.anchors.push(AnchorRow { path: a.clone(), kind: kind.clone(), rules: rules.len() });
        if rules.is_empty() {
            continue;
        }
        let all: Vec<&PfRule> = rules.iter().collect();
        match kind {
            AnchorKind::AlwaysEmpty | AnchorKind::Undeclared | AnchorKind::Feature(_, false) => {
                let why = match &kind {
                    AnchorKind::AlwaysEmpty => format!(
                        "pfSense declares this anchor and never fills it (filter.inc): a rule here was loaded \
                         by hand with `pfctl -a`, is in neither config.xml nor rules.debug, and is evaluated \
                         inside the main ruleset. It is sealed with the listing; `pfctl -a '{a}' -F all` \
                         removes it"
                    ),
                    AnchorKind::Feature(f, _) => format!(
                        "pfSense fills this anchor only for {}, which config.xml does not have on, so nothing \
                         of pfSense's put these rules here",
                        f.label()
                    ),
                    _ => "no anchor pfSense writes is called this, and rules.debug does not declare it: the \
                          rules were loaded from outside pfSense"
                        .to_string(),
                };
                j.findings.push(Finding {
                    severity: if config.is_none() && matches!(kind, AnchorKind::Feature(..)) { Severity::Warn } else { Severity::Critical },
                    subject: format!("anchor {a}"),
                    what: shown(&all),
                    why,
                });
            }
            AnchorKind::Feature(f, true) => {
                j.findings.push(Finding {
                    severity: Severity::Warn,
                    subject: format!("anchor {a}"),
                    what: shown(&all),
                    why: format!(
                        "{} is on, and its daemon puts rules here as clients use it; read them, because \
                         nothing ties them to config.xml",
                        f.label()
                    ),
                });
            }
            AnchorKind::Declared => {
                let odd: Vec<&PfRule> = rules
                    .iter()
                    .filter(|r| r.decides())
                    .filter(|r| match r.ridentifier {
                        Ok(Some(id)) => !trackers.contains(&id) && fixed_range(id).is_none(),
                        _ => true,
                    })
                    .collect();
                if !odd.is_empty() {
                    j.findings.push(Finding {
                        severity: if config.is_some() { Severity::Critical } else { Severity::Warn },
                        subject: format!("anchor {a}"),
                        what: shown(&odd),
                        why: "rules.debug declares this anchor, but these rules in it carry a ridentifier that \
                              is in neither config.xml nor pfSense's fixed ranges"
                            .into(),
                    });
                }
            }
        }
    }

    if let Some(t) = listing(c, &pfctl_key(&["-sT"]), false, &mut j.gaps) {
        let tables: Vec<&str> = t.lines().map(str::trim).filter(|l| !l.is_empty()).collect();
        j.summary.tables = tables.len();
        let aliases: BTreeSet<String> = config
            .as_ref()
            .and_then(|cfg| cfg.root().get("aliases"))
            .map(|a| a.all("alias").filter_map(|x| x.text_at("name")).map(str::to_string).collect())
            .unwrap_or_default();
        if let Some(g) = &generated {
            let odd: Vec<&str> = tables
                .iter()
                .copied()
                .filter(|t| !g.tables.contains(*t) && !aliases.contains(*t) && !t.starts_with("__automatic_"))
                .collect();
            if !odd.is_empty() {
                j.findings.push(Finding {
                    severity: Severity::Warn,
                    subject: "tables".into(),
                    what: odd.iter().take(MAX_SHOWN).copied().collect::<Vec<_>>().join(", "),
                    why: "rules.debug does not declare these and no alias is called this; every filter reload \
                          deletes such tables (filter.inc), so they were made since the last one. A table \
                          matters only to a rule that names it — see the rules above"
                        .into(),
                });
            }
        }
    }

    j.findings.sort_by_key(|f| std::cmp::Reverse(f.severity));
    j
}
