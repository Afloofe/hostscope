use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Sev {

    Info,

    Note,

    Warn,

    Critical,
}

impl Sev {

    pub const fn token(self) -> &'static str {
        match self {
            Sev::Info => "info",
            Sev::Note => "note",
            Sev::Warn => "warn",
            Sev::Critical => "critical",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Item {

    pub id: String,

    pub source: String,

    pub severity: Sev,

    pub subject: String,

    pub locus: String,

    pub what: String,

    pub known: Vec<Entity>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Entity {

    Pid(u32),

    Path(String),

    User(String),

    Unit(String),

    Address(String),
}

impl Entity {

    pub fn describe(&self) -> String {
        match self {
            Entity::Pid(p) => format!("pid {p}"),
            Entity::Path(p) => p.clone(),
            Entity::User(u) => format!("user {u}"),
            Entity::Unit(u) => format!("unit {u}"),
            Entity::Address(a) => format!("address {a}"),
        }
    }
}

pub const HUB_FRACTION: f64 = 0.5;

pub const HUB_FLOOR: usize = 8;

pub const NEVER_MERGE_USERS: &[&str] = &["root", "SYSTEM", "NT AUTHORITY\\SYSTEM"];

const NEVER_MERGE_DIRS: &[&str] = &[
    "/usr/bin", "/usr/sbin", "/bin", "/sbin", "/usr/lib", "/lib", "/etc", "/var", "/tmp",
    "/usr/local/bin", "/opt", "/home", "/root", "/proc", "/sys", "/run",
];

const NEVER_MERGE_ADDRESSES: &[&str] =
    &["0.0.0.0", "127.0.0.1", "0.0.0.0/0", "255.255.255.255"];

pub fn entities_in(item: &Item) -> BTreeSet<Entity> {
    let mut out: BTreeSet<Entity> = item.known.iter().cloned().collect();
    extract_into(&item.locus, &mut out);

    extract_into(&item.what, &mut out);
    for name in cued_users(&item.what) {
        if !NEVER_MERGE_USERS.iter().any(|u| u.eq_ignore_ascii_case(&name)) {
            out.insert(Entity::User(name));
        }
    }
    out
}

const USER_CUES: &[&str] = &["as", "user"];

const USER_CUE_PAIRS: &[(&str, &str)] = &[
    ("owned", "by"),
    ("run", "by"),
    ("belonging", "to"),
    ("belongs", "to"),
    ("invoked", "by"),
];

const NOT_A_LOGIN: &[&str] = &[
    "a", "an", "the", "its", "it", "his", "her", "their", "our", "this", "that", "these",
    "those", "one", "any", "each", "every", "no", "not", "pid", "uid", "gid", "well", "if",
    "though", "long", "soon", "far", "much", "many", "such", "part",
];

fn cued_users(text: &str) -> Vec<String> {
    let words: Vec<&str> = text.split_whitespace().collect();
    let mut out = Vec::new();
    let word_at = |i: usize| -> String {
        words
            .get(i)
            .map(|w| w.trim_matches(|c: char| !c.is_ascii_alphabetic()).to_ascii_lowercase())
            .unwrap_or_default()
    };
    for (i, _) in words.iter().enumerate() {
        let cue = word_at(i);
        let single = USER_CUES.contains(&cue.as_str());
        let paired = i > 0
            && USER_CUE_PAIRS
                .iter()
                .any(|(first, second)| *second == cue && *first == word_at(i - 1));
        if !single && !paired {
            continue;
        }
        let Some(next) = words.get(i + 1) else { continue };
        let name = next.trim_matches(|c: char| {
            !(c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '$')
        });
        if name.is_empty() || name.len() > 32 {
            continue;
        }

        if name.chars().all(|c| c.is_ascii_digit())
            || next.starts_with('/')
            || name.contains('.')
            || NOT_A_LOGIN.iter().any(|w| w.eq_ignore_ascii_case(name))
        {
            continue;
        }
        out.push(name.to_string());
    }
    out
}

fn extract_into(text: &str, out: &mut BTreeSet<Entity>) {
    let t = text.trim();
    if t.is_empty() {
        return;
    }
    for pid in pids_in(t) {
        out.insert(Entity::Pid(pid));
    }

    if let Ok(p) = t.parse::<u32>() {
        out.insert(Entity::Pid(p));
    }
    for word in t.split(|c: char| c.is_whitespace() || c == ',' || c == '`' || c == '\'') {
        let w = word.trim_matches(|c: char| c == '.' || c == ':' || c == ';' || c == ')' || c == '(');
        if w.is_empty() {
            continue;
        }
        if w.starts_with('/') && w.len() > 1 {
            if !NEVER_MERGE_DIRS.contains(&w) {
                out.insert(Entity::Path(w.to_string()));
            }
            continue;
        }
        if w.ends_with(".service") || w.ends_with(".timer") || w.ends_with(".socket") {
            out.insert(Entity::Unit(w.to_string()));
            continue;
        }
        if looks_like_address(w) {

            let host = w.split(':').next().unwrap_or(w);
            if !NEVER_MERGE_ADDRESSES.contains(&host) {
                out.insert(Entity::Address(host.to_string()));
            }
        }
    }
}

fn pids_in(text: &str) -> Vec<u32> {
    let mut out = Vec::new();
    let words: Vec<&str> = text.split_whitespace().collect();
    for (i, w) in words.iter().enumerate() {
        if w.eq_ignore_ascii_case("pid") {
            if let Some(n) = words.get(i + 1) {
                if let Ok(p) = n.trim_matches(|c: char| !c.is_ascii_digit()).parse::<u32>() {
                    out.push(p);
                }
            }
        }
    }
    out
}

fn looks_like_address(w: &str) -> bool {
    let host = w.split(':').next().unwrap_or(w);
    let parts: Vec<&str> = host.split('.').collect();
    parts.len() == 4
        && parts.iter().all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()))
        && parts.iter().all(|p| p.parse::<u16>().is_ok_and(|n| n <= 255))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cluster {

    pub items: Vec<String>,

    pub shared: Vec<Entity>,

    pub severity: Sev,

    pub sources: BTreeSet<String>,
}

impl Cluster {

    pub fn is_cross_sweep(&self) -> bool {
        self.sources.len() > 1
    }

    pub fn headline(&self) -> String {
        let what = if self.shared.is_empty() {
            "the same thing".to_string()
        } else {
            self.shared.iter().take(3).map(Entity::describe).collect::<Vec<_>>().join(", ")
        };
        format!(
            "{} finding(s) from {} sweep(s) about {what}",
            self.items.len(),
            self.sources.len()
        )
    }
}

#[derive(Debug, Clone, Default)]
pub struct Correlation {

    pub clusters: Vec<Cluster>,

    pub singletons: Vec<String>,

    pub hubs: Vec<(Entity, usize)>,
}

impl Correlation {

    pub fn coverage(&self) -> String {
        let mut s = format!(
            "{} cluster(s), {} finding(s) that stand alone",
            self.clusters.len(),
            self.singletons.len()
        );
        if !self.hubs.is_empty() {
            s.push_str(&format!(
                " — {} entity(ies) were mentioned by too much of the sweep to link anything and \
                 were NOT used to merge: {}",
                self.hubs.len(),
                self.hubs
                    .iter()
                    .map(|(e, n)| format!("{} ({n} findings)", e.describe()))
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        s
    }
}

pub fn correlate(items: &[Item]) -> Correlation {
    let mut out = Correlation::default();
    if items.is_empty() {
        return out;
    }

    let mut mentions: BTreeMap<Entity, Vec<usize>> = BTreeMap::new();
    let per_item: Vec<BTreeSet<Entity>> = items.iter().map(entities_in).collect();
    for (i, set) in per_item.iter().enumerate() {
        for e in set {
            mentions.entry(e.clone()).or_default().push(i);
        }
    }

    #[allow(clippy::cast_precision_loss)]
    let ceiling = (items.len() as f64 * HUB_FRACTION).ceil() as usize;
    let mut merging: BTreeMap<&Entity, &Vec<usize>> = BTreeMap::new();
    for (e, who) in &mentions {
        if who.len() < 2 {
            continue;
        }
        if items.len() >= HUB_FLOOR && who.len() > ceiling {
            out.hubs.push((e.clone(), who.len()));
            continue;
        }

        if let Entity::User(u) = e {
            if NEVER_MERGE_USERS.iter().any(|n| n.eq_ignore_ascii_case(u)) {
                continue;
            }
        }
        merging.insert(e, who);
    }

    let mut parent: Vec<usize> = (0..items.len()).collect();
    fn find(parent: &mut [usize], mut x: usize) -> usize {
        while parent[x] != x {
            parent[x] = parent[parent[x]];
            x = parent[x];
        }
        x
    }
    for who in merging.values() {
        let first = who[0];
        for other in who.iter().skip(1) {
            let (a, b) = (find(&mut parent, first), find(&mut parent, *other));
            if a != b {
                parent[a] = b;
            }
        }
    }

    let mut groups: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
    for i in 0..items.len() {
        let root = find(&mut parent, i);
        groups.entry(root).or_default().push(i);
    }
    for members in groups.values() {
        if members.len() < 2 {
            out.singletons.push(items[members[0]].id.clone());
            continue;
        }

        let mut shared: Vec<Entity> = Vec::new();
        for (e, who) in &merging {
            if who.iter().filter(|i| members.contains(i)).count() >= 2 {
                shared.push((*e).clone());
            }
        }
        shared.sort();
        let severity = members.iter().map(|i| items[*i].severity).max().unwrap_or(Sev::Info);
        let sources: BTreeSet<String> =
            members.iter().map(|i| items[*i].source.clone()).collect();
        out.clusters.push(Cluster {
            items: members.iter().map(|i| items[*i].id.clone()).collect(),
            shared,
            severity,
            sources,
        });
    }

    out.clusters.sort_by(|a, b| {
        b.severity.cmp(&a.severity).then(b.items.len().cmp(&a.items.len()))
    });
    out.hubs.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    out.singletons.sort();
    out
}
