use std::path::Path;

use hemostat_evcrypto::manifest::Manifest;
use hemostat_sensor_freebsd::configxml::{Config, Element};
use hemostat_sensor_freebsd::pfrules::{self, Set};
use hemostat_sensor_freebsd::tools::{Invocation, Runner, Tool};

use crate::Enrolled;

#[derive(Debug, Clone)]
pub struct Gathered {

    pub rules: Result<String, String>,

    pub tables: Result<String, String>,

    pub limits: Result<String, String>,

    pub carp_allow: Result<String, String>,

    pub ifconfig: Result<String, String>,
}

pub(crate) fn text(r: &mut dyn Runner, inv: Invocation) -> Result<String, String> {
    let what = format!("{} {}", inv.tool(), inv.args().join(" "));
    match r.run(&inv) {
        Ok(o) if o.success() => Ok(o.text()),
        Ok(o) => Err(format!("{what} exited {:?}: {}", o.status, String::from_utf8_lossy(&o.stderr).trim())),
        Err(e) => Err(format!("{what}: {e}")),
    }
}

pub fn gather(r: &mut dyn Runner) -> Gathered {
    Gathered {
        rules: text(r, Invocation::new(Tool::Pfctl, &["-sr", "-vv"])),
        tables: text(r, Invocation::new(Tool::Pfctl, &["-vvsTables"])),
        limits: text(r, Invocation::new(Tool::Pfctl, &["-sm"])),
        carp_allow: text(r, Invocation::new(Tool::Sysctl, &["-n", "net.inet.carp.allow"])),
        ifconfig: text(r, Invocation::new(Tool::Ifconfig, &["-a"])),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IncFile {

    pub path: String,

    pub sha256: Result<[u8; 32], String>,
}

#[cfg(unix)]
pub fn hash_incs(root: &Path) -> Result<Vec<IncFile>, String> {
    let dir = root.join("etc/inc");
    let rd = std::fs::read_dir(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let mut out = Vec::new();
    for ent in rd {
        let ent = ent.map_err(|e| format!("{}: {e}", dir.display()))?;
        let name = ent.file_name().to_string_lossy().into_owned();
        if !name.ends_with(".inc") {
            continue;
        }
        let sha256 = hemostat_sensor_freebsd::saferead::sha256_of(&ent.path()).map_err(|e| e.to_string());
        out.push(IncFile { path: format!("/etc/inc/{name}"), sha256 });
    }
    if out.len() > 4096 {
        return Err(format!("{} holds {} .inc files, which is not a pfSense install", dir.display(), out.len()));
    }
    for p in PEAR_INC {
        let at = root.join(p.trim_start_matches('/'));
        let sha256 = hemostat_sensor_freebsd::saferead::sha256_of(&at).map_err(|e| e.to_string());
        out.push(IncFile { path: p.to_string(), sha256 });
    }
    out.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(out)
}

pub const PEAR_INC: [&str; 7] = [
    "/usr/local/share/pear/Auth/RADIUS.php",
    "/usr/local/share/pear/Net/IPv6.php",
    "/usr/local/share/pear/PEAR.php",
    "/usr/local/share/pear/XML/RPC2/Backend.php",
    "/usr/local/share/pear/XML/RPC2/Client.php",
    "/usr/local/share/pear/XML/RPC2/ClientHelper.php",
    "/usr/local/share/pear/XML/RPC2/Exception.php",
];

pub const REQUIRED_INC: [&str; 5] =
    ["/etc/inc/globals.inc", "/etc/inc/config.inc", "/etc/inc/config.lib.inc", "/etc/inc/util.inc", "/etc/inc/filter.inc"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Check {

    pub what: &'static str,

    pub result: Result<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Preflight {

    pub checks: Vec<Check>,

    pub entries: Option<usize>,
}

impl Preflight {

    pub fn passed(&self) -> bool {
        !self.checks.is_empty() && self.checks.iter().all(|c| c.result.is_ok())
    }

    pub fn refusal(&self) -> Option<&Check> {
        self.checks.iter().find(|c| c.result.is_err())
    }
}

fn bare_words(text: &str) -> Vec<&str> {
    let mut out = Vec::new();
    for (i, part) in text.split('"').enumerate() {
        if i % 2 == 0 {
            out.extend(part.split_whitespace());
        }
    }
    out
}

fn is_table(w: &str, name: &str) -> bool {
    let Some(inner) = w.strip_prefix('<').and_then(|s| s.strip_suffix('>')) else { return false };
    let t = inner.split_once(':').map_or(inner, |(t, n)| if n.bytes().all(|b| b.is_ascii_digit()) { t } else { "" });
    t == name
}

fn alias_element<'a>(c: &'a Config, name: &str) -> Vec<&'a Element> {
    c.root().child("aliases").map(|a| a.all("alias").filter(|e| e.text_at("name") == Some(name)).collect()).unwrap_or_default()
}

fn check_alias(c: &Config, e: &Enrolled) -> Result<String, String> {
    let name = e.alias.name();
    match alias_element(c, name).as_slice() {
        [] => Err(format!("no alias {name} in config.xml. HEMOSTAT never creates one: make it in the GUI, type network, before the engagement")),
        [a] => {
            let ty = a.text_at("type").unwrap_or("");
            if ty != "network" {
                return Err(format!(
                    "{name} is of type {ty:?}, not network. A host alias is re-resolved and a URL \
                     alias refetched, so an entry added to either can be rewritten under it"
                ));
            }
            let n = a.text_at("address").unwrap_or("").split_whitespace().count();
            Ok(format!("{name}, type network, {n} entries in config.xml"))
        }
        many => Err(format!("{} aliases are named {name}; which one pf loads is not knowable here", many.len())),
    }
}

fn check_rule(c: &Config, rules: &Result<String, String>, e: &Enrolled) -> Result<String, String> {
    let name = e.alias.name();
    let side = e.alias.side();
    let mine: Vec<_> = c
        .rules()
        .into_iter()
        .filter(|r| r.tracker.as_deref().and_then(|t| t.parse::<u32>().ok()) == Some(e.tracker))
        .collect();
    let r = match mine.as_slice() {
        [] => {
            return Err(format!(
                "no rule in config.xml has the enrolled tracker {}. Either it was never made, or \
                 the rule blocking {name} has been replaced by another",
                e.tracker
            ))
        }
        [r] => r,
        _ => return Err(format!("{} rules carry tracker {}; the enrolled rule is not one rule", mine.len(), e.tracker)),
    };
    let mut wrong = Vec::new();
    if r.disabled {
        wrong.push("disabled".to_string());
    }
    if !matches!(r.kind.as_str(), "block" | "reject") {
        wrong.push(format!("a {} rule, not block", r.kind));
    }
    if r.floating && !r.quick {
        wrong.push("floating and not quick, so a later pass overrides it".into());
    }
    if !r.fields.iter().any(|(k, _)| k == "log") {
        wrong.push("not logged, so fw verdict has nothing to show for it".into());
    }
    let ep = if side == "destination" { &r.destination } else { &r.source };
    if ep.address.as_deref() != Some(name) || ep.not {
        wrong.push(format!("its {side} is {}, not {name}", ep.render()));
    }
    if !wrong.is_empty() {
        return Err(format!("the enrolled rule (tracker {}) is {}", e.tracker, wrong.join("; ")));
    }

    let text = rules.as_ref().map_err(|e| format!("the loaded ruleset could not be read: {e}"))?;
    let loaded = pfrules::parse_rules(text, Set::Filter).map_err(|e| format!("pfctl -sr -vv did not read as pfctl prints it: {e}"))?;
    let ours: Vec<_> = loaded.iter().filter(|p| p.ridentifier == Ok(Some(e.tracker))).collect();
    if ours.is_empty() {
        return Err(format!(
            "config.xml has the rule, but pf is running no rule with ridentifier {}: the filter \
             was not reloaded since it was made, or something replaced the ruleset",
            e.tracker
        ));
    }
    let word = if side == "destination" { "to" } else { "from" };
    for p in &ours {
        let w = bare_words(&p.text);
        let on_side = w.windows(2).any(|x| matches!(x, [k, t] if *k == word && is_table(t, name)));
        if p.action != "block" || !w.contains(&"quick") || !w.iter().any(|x| *x == "log" || x.starts_with("log(")) || !on_side {
            return Err(format!("pf's rule @{} with ridentifier {} is not `block … log quick … {word} <{name}>`: {}", p.index, e.tracker, p.text));
        }
    }
    Ok(format!("tracker {}: block, quick, logged, {side} {name}; pf runs {} rule(s) for it", e.tracker, ours.len()))
}

fn check_antilockout(c: &Config, rules: &Result<String, String>) -> Result<String, String> {
    if c.root().has("system/webgui/noantilockout") {
        return Err("the anti-lockout rule is disabled (system/webgui/noantilockout). With it off, a block can cut the LAN off the GUI and SSH".into());
    }
    let text = rules.as_ref().map_err(|e| format!("the loaded ruleset could not be read: {e}"))?;
    let loaded = pfrules::parse_rules(text, Set::Filter).map_err(|e| format!("pfctl -sr -vv did not read as pfctl prints it: {e}"))?;
    let n = loaded
        .iter()
        .filter(|p| p.action == "pass")
        .filter(|p| matches!(p.ridentifier, Ok(Some(id)) if pfrules::fixed_range(id).is_some_and(|r| r.name == "the anti-lockout rule")))
        .count();
    if n == 0 {
        return Err("pf is running no anti-lockout rule, although config.xml does not disable it".into());
    }
    Ok(format!("{n} anti-lockout pass rule(s) loaded"))
}

pub fn parse_tables(text: &str) -> Result<Vec<(String, String, usize)>, String> {
    let mut out: Vec<(String, String, usize)> = Vec::new();
    for line in text.lines() {
        if line.trim().is_empty() {
            continue;
        }
        if !line.starts_with(char::is_whitespace) {
            let mut w = line.split_whitespace();
            match (w.next(), w.next(), w.next()) {
                (Some(f), Some(n), None) if f.len() == 7 => out.push((n.to_string(), f.to_string(), 0)),
                _ => return Err(format!("not a table line: {line:?}")),
            }
        } else if let Some(n) = line.trim().strip_prefix("Addresses:") {
            let last = out.last_mut().ok_or("an address count before any table")?;
            last.2 = n.trim().parse().map_err(|_| format!("not a count: {line:?}"))?;
        }
    }
    Ok(out)
}

pub fn table_entries_limit(text: &str) -> Option<usize> {
    text.lines().find_map(|l| l.strip_prefix("table-entries")?.trim().strip_prefix("hard limit")?.trim().parse().ok())
}

fn check_table(g: &Gathered, e: &Enrolled) -> (Result<String, String>, Option<usize>) {
    let name = e.alias.name();
    let tables = match g.tables.as_ref().map_err(Clone::clone).and_then(|t| parse_tables(t)) {
        Ok(t) => t,
        Err(why) => return (Err(format!("the pf tables could not be read: {why}")), None),
    };
    let Some(limit) = g.limits.as_ref().ok().and_then(|t| table_entries_limit(t)) else {
        return (Err("pf's table-entries limit could not be read from pfctl -sm".into()), None);
    };
    let Some((_, flags, n)) = tables.iter().find(|(t, _, _)| t == name) else {
        return (Err(format!("pf has no table {name}: the alias is not loaded")), None);
    };
    if !flags.contains('a') || !flags.contains('r') {
        return (Err(format!("pf's table {name} is {flags}: not active and referenced by a rule")), Some(*n));
    }
    let total: usize = tables.iter().map(|t| t.2).sum();
    if total.saturating_add(1) > limit {
        return (Err(format!("pf holds {total} table entries against a hard limit of {limit}; one more would fail")), Some(*n));
    }
    (Ok(format!("{name} holds {n}; all tables {total} of {limit}")), Some(*n))
}

pub fn carp_states(text: &str) -> Vec<(u32, String)> {
    text.lines()
        .filter_map(|l| {
            let mut w = l.split_whitespace();
            (w.next()? == "carp:").then_some(())?;
            let state = w.next()?.to_string();
            (w.next()? == "vhid").then_some(())?;
            Some((w.next()?.parse().ok()?, state))
        })
        .collect()
}

fn check_carp(c: &Config, carp_allow: &Result<String, String>, ifconfig: &Result<String, String>) -> Result<String, String> {
    let vips = c
        .root()
        .child("virtualip")
        .map(|v| v.all("vip").filter(|x| x.text_at("mode") == Some("carp")).count())
        .unwrap_or(0);
    if vips == 0 {
        return Ok("no CARP VIP is configured: not part of a pair".into());
    }
    match carp_allow.as_ref().map(|s| s.trim().to_string()) {
        Ok(v) if v == "0" => return Ok(format!("{vips} CARP VIP(s) configured, CARP disabled (net.inet.carp.allow=0): not acting as a backup")),
        Ok(_) => {}
        Err(e) => return Err(format!("{vips} CARP VIP(s) are configured and CARP's state could not be read: {e}")),
    }
    let text = ifconfig.as_ref().map_err(|e| format!("{vips} CARP VIP(s) are configured and CARP is on, and ifconfig could not be read: {e}"))?;
    let states = carp_states(text);
    if states.is_empty() {
        return Err(format!(
            "{vips} CARP VIP(s) are configured and CARP is on, but ifconfig shows no vhid: which node \
             is master cannot be told, so it is refused rather than risk acting on the backup"
        ));
    }
    let not_master: Vec<String> = states.iter().filter(|(_, s)| s != "MASTER").map(|(v, s)| format!("vhid {v} {s}")).collect();
    if !not_master.is_empty() {
        return Err(format!(
            "this node is not the CARP master ({}): the primary's XMLRPC sync overwrites the alias \
             here. Act on the primary",
            not_master.join(", ")
        ));
    }
    Ok(format!("CARP master for {} vhid(s)", states.len()))
}

fn check_inc(inc: &Result<Vec<IncFile>, String>, manifest: Option<&Manifest>) -> Result<String, String> {
    let m = manifest.ok_or("no signed manifest, so no .inc file can be shown to be vendor")?;
    let files = inc.as_ref().map_err(|e| format!("/etc/inc could not be listed: {e}"))?;
    for req in REQUIRED_INC.iter().chain(PEAR_INC.iter()) {
        if !files.iter().any(|f| f.path == *req) {
            return Err(format!("{req} is missing"));
        }
    }
    let mut bad = Vec::new();
    for f in files {
        match &f.sha256 {
            Err(why) => bad.push(format!("{} could not be hashed ({why})", f.path)),
            Ok(d) => match m.is_vendor(&f.path, d) {
                Some(true) => {}
                Some(false) => bad.push(format!("{} is not the vendor's", f.path)),
                None => bad.push(format!("{} is not in the manifest", f.path)),
            },
        }
    }
    if !bad.is_empty() {
        let more = bad.len().saturating_sub(4);
        let shown: Vec<String> = bad.into_iter().take(4).collect();
        return Err(format!(
            "{}{}. The confirm step runs pfSense's own PHP, and would run this",
            shown.join("; "),
            if more > 0 { format!(" (+{more} more)") } else { String::new() }
        ));
    }
    Ok(format!("{} files (/etc/inc/*.inc and {} PEAR), every one vendor", files.len(), PEAR_INC.len()))
}

pub fn judge_kill(g: &Gathered, config: &Result<Config, String>) -> Preflight {
    let c = match config {
        Ok(c) => c,
        Err(why) => {
            return Preflight {
                checks: vec![Check { what: "config.xml", result: Err(format!("config.xml could not be read: {why}")) }],
                entries: None,
            }
        }
    };
    Preflight {
        checks: vec![
            Check { what: "anti-lockout", result: check_antilockout(c, &g.rules) },
            Check { what: "carp", result: check_carp(c, &g.carp_allow, &g.ifconfig) },
        ],
        entries: None,
    }
}

pub fn judge(
    g: &Gathered,
    config: &Result<Config, String>,
    inc: &Result<Vec<IncFile>, String>,
    manifest: Option<&Manifest>,
    e: &Enrolled,
) -> Preflight {
    let c = match config {
        Ok(c) => c,
        Err(why) => {
            return Preflight {
                checks: vec![Check { what: "config.xml", result: Err(format!("config.xml could not be read: {why}")) }],
                entries: None,
            }
        }
    };
    let (table, entries) = check_table(g, e);
    Preflight {
        checks: vec![
            Check { what: "alias", result: check_alias(c, e) },
            Check { what: "rule", result: check_rule(c, &g.rules, e) },
            Check { what: "anti-lockout", result: check_antilockout(c, &g.rules) },
            Check { what: "table", result: table },
            Check { what: "carp", result: check_carp(c, &g.carp_allow, &g.ifconfig) },
            Check { what: "inc", result: check_inc(inc, manifest) },
        ],
        entries,
    }
}
