use std::io::Write as _;
use std::path::{Path, PathBuf};

use hemostat_evfmt::tsvjournal::{decode_pairs, encode_pairs, esc, unesc};
use hemostat_sensor_freebsd::configxml::Config;
use hs_core::cidr::Cidr;

use crate::Alias;

pub const HEADER: &str = "# hemostat pf containment journal v1";

pub const DIR: &str = "/root/hemostat/containment";

pub fn marker(nonce8: &str) -> String {
    format!("HEMOSTAT {nonce8}")
}

pub fn block_description(cidr: &Cidr, nonce8: &str) -> String {
    format!("HEMOSTAT block {cidr} {nonce8}")
}

pub fn lift_description(cidr: &Cidr, nonce8: &str) -> String {
    format!("HEMOSTAT lift {cidr} {nonce8}")
}

pub fn valid_id(s: &str) -> bool {
    s.len() == 8 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub fn id_of(nonce: &[u8; 16]) -> String {
    nonce.iter().take(4).map(|b| format!("{b:02x}")).collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UndoKind {

    Lift,

    Nothing,
}

impl UndoKind {

    pub const fn token(self) -> &'static str {
        match self {
            UndoKind::Lift => "lift",
            UndoKind::Nothing => "nothing",
        }
    }

    fn parse(s: &str) -> Option<UndoKind> {
        match s {
            "lift" => Some(UndoKind::Lift),
            "nothing" => Some(UndoKind::Nothing),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {

    Block,

    StateKill,
}

impl Class {

    pub const fn token(self) -> &'static str {
        match self {
            Class::Block => "PerimeterBlock",
            Class::StateKill => "PerimeterStateKill",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Intent {

    pub id: String,

    pub at: u64,

    pub class: Class,

    pub alias: Alias,

    pub cidr: Cidr,

    pub existed: bool,

    pub tracker: u32,

    pub deadline: u64,

    pub undo: UndoKind,

    pub host: String,

    pub protect: Vec<Cidr>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {

    pub intent: Intent,

    pub live: bool,

    pub watcher: Option<u32>,

    pub confirmed: Option<String>,

    pub lifted: Option<String>,

    pub killed: Option<Vec<(String, String)>>,

    pub failed: Vec<(String, String)>,

    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {

    Intent,

    Existed,

    Live,

    Confirmed,

    Lifted,

    Killed,
}

impl State {

    pub const fn token(self) -> &'static str {
        match self {
            State::Intent => "intent-only",
            State::Existed => "existed",
            State::Live => "live",
            State::Confirmed => "confirmed",
            State::Lifted => "lifted",
            State::Killed => "killed",
        }
    }
}

impl Entry {

    pub fn state(&self) -> State {
        if self.lifted.is_some() {
            State::Lifted
        } else if self.killed.is_some() {
            State::Killed
        } else if self.intent.existed {
            State::Existed
        } else if self.confirmed.is_some() {
            State::Confirmed
        } else if self.live {
            State::Live
        } else {
            State::Intent
        }
    }

    pub fn marker(&self) -> String {
        marker(&self.intent.id)
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

fn pairs(p: &[(&str, String)]) -> String {
    encode_pairs(&p.iter().map(|(k, v)| ((*k).to_string(), v.clone())).collect::<Vec<_>>())
}

pub fn line(kind: &str, id: &str, at: u64, p: &[(&str, String)]) -> String {
    format!("{}\t{}\t{at}\t{}", esc(kind), esc(id), esc(&pairs(p)))
}

pub fn intent_line(i: &Intent) -> String {
    line(
        "intent",
        &i.id,
        i.at,
        &[
            ("class", i.class.token().to_string()),
            ("alias", i.alias.name().to_string()),
            ("cidr", i.cidr.to_string()),
            ("nonce8", i.id.clone()),
            ("existed", if i.existed { "1" } else { "0" }.to_string()),
            ("tracker", i.tracker.to_string()),
            ("deadline", i.deadline.to_string()),
            ("undo", i.undo.token().to_string()),
            ("host", i.host.clone()),
            ("protect", i.protect.iter().map(ToString::to_string).collect::<Vec<_>>().join(",")),
        ],
    )
}

fn get<'a>(p: &'a [(String, String)], k: &str) -> Option<&'a str> {
    p.iter().find(|(x, _)| x == k).map(|(_, v)| v.as_str())
}

pub fn parse(text: &str) -> Result<Entry, String> {
    let mut entry: Option<Entry> = None;
    for (n, l) in hemostat_evfmt::tsvjournal::records(text, HEADER, "a containment journal")? {
        let f: Vec<&str> = l.split('\t').collect();
        let [kind, id, at, rest] = f.as_slice() else {
            return Err(format!("line {n}: {} fields, not 4", f.len()));
        };
        let (kind, id) = (unesc(kind), unesc(id));
        if !valid_id(&id) {
            return Err(format!("line {n}: {id:?} is not an id"));
        }
        let at: u64 = at.parse().map_err(|_| format!("line {n}: {at:?} is not a time"))?;
        let p = decode_pairs(&unesc(rest));
        let need = |k: &str| get(&p, k).ok_or_else(|| format!("line {n}: {kind} has no {k}"));
        if kind == "intent" {
            if entry.is_some() {
                return Err(format!("line {n}: a second intent"));
            }
            let class = match need("class")? {
                "PerimeterBlock" => Class::Block,
                "PerimeterStateKill" => Class::StateKill,
                c => return Err(format!("line {n}: class {c:?} is not a perimeter class")),
            };
            let alias = Alias::from_name(need("alias")?)
                .ok_or_else(|| format!("line {n}: {:?} is not an enrolled alias", get(&p, "alias")))?;
            let cidr = Cidr::parse(need("cidr")?).map_err(|e| format!("line {n}: {e}"))?;
            if need("nonce8")? != id {
                return Err(format!("line {n}: the nonce8 is not the id"));
            }
            let existed = match need("existed")? {
                "0" => false,
                "1" => true,
                x => return Err(format!("line {n}: existed={x:?}")),
            };
            let tracker = need("tracker")?.parse().map_err(|_| format!("line {n}: tracker is not a number"))?;
            let deadline = need("deadline")?.parse().map_err(|_| format!("line {n}: deadline is not a time"))?;
            let undo = UndoKind::parse(need("undo")?).ok_or_else(|| format!("line {n}: undo is not lift or nothing"))?;
            if (class == Class::Block) != (undo == UndoKind::Lift) {
                return Err(format!("line {n}: a {} is not undone by {}", class.token(), undo.token()));
            }
            let protect = need("protect")?
                .split(',')
                .filter(|x| !x.is_empty())
                .map(|x| Cidr::parse(x).map_err(|e| format!("line {n}: protect {e}")))
                .collect::<Result<Vec<_>, _>>()?;
            entry = Some(Entry {
                intent: Intent {
                    id,
                    at,
                    class,
                    alias,
                    cidr,
                    existed,
                    tracker,
                    deadline,
                    undo,
                    host: need("host")?.to_string(),
                    protect,
                },
                live: false,
                watcher: None,
                confirmed: None,
                lifted: None,
                killed: None,
                failed: Vec::new(),
                notes: Vec::new(),
            });
            continue;
        }
        let e = entry.as_mut().ok_or_else(|| format!("line {n}: {kind} before the intent"))?;
        if e.intent.id != id {
            return Err(format!("line {n}: id {id} in the journal of {}", e.intent.id));
        }
        match kind.as_str() {
            "live" => e.live = true,
            "watch" => e.watcher = get(&p, "pid").and_then(|s| s.parse().ok()),
            "confirmed" => e.confirmed = Some(need("rev")?.to_string()),
            "lifted" => e.lifted = Some(need("by")?.to_string()),
            "killed" => e.killed = Some(p.clone()),
            "note" => e.notes.push(need("what")?.to_string()),
            "failed" => e.failed.push((need("step")?.to_string(), need("why")?.to_string())),
            k => return Err(format!("line {n}: {k:?} is not a journal line")),
        }
    }
    entry.ok_or_else(|| "the journal holds no intent".to_string())
}

#[derive(Debug, Clone)]
pub struct Journals {
    dir: PathBuf,
}

#[derive(Debug)]
pub struct Held {
    _file: std::fs::File,
}

impl Journals {

    pub fn at(dir: impl Into<PathBuf>) -> Journals {
        Journals { dir: dir.into() }
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn path(&self, id: &str) -> PathBuf {
        self.dir.join(format!("{id}.tsv"))
    }

    pub fn ids(&self) -> Result<Vec<String>, String> {
        let rd = match std::fs::read_dir(&self.dir) {
            Ok(rd) => rd,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(format!("{}: {e}", self.dir.display())),
        };
        let mut out = Vec::new();
        for ent in rd {
            let ent = ent.map_err(|e| format!("{}: {e}", self.dir.display()))?;
            let name = ent.file_name().to_string_lossy().into_owned();
            if let Some(id) = name.strip_suffix(".tsv").filter(|i| valid_id(i)) {
                out.push(id.to_string());
            }
        }
        out.sort();
        Ok(out)
    }

    pub fn scan(&self) -> (Vec<Entry>, Vec<String>) {
        let mut out = Vec::new();
        let mut bad = Vec::new();
        match self.ids() {
            Ok(ids) => {
                for id in ids {
                    match self.read(&id) {
                        Ok(e) => out.push(e),
                        Err(why) => bad.push(why),
                    }
                }
            }
            Err(why) => bad.push(why),
        }
        (out, bad)
    }

    pub fn hold(&self, id: &str) -> Result<Held, String> {
        if !valid_id(id) {
            return Err(format!("{id:?} is not an id"));
        }
        hemostat_sensor_freebsd::store::create_private(&self.dir).map_err(|e| format!("{}: {e}", self.dir.display()))?;
        let p = self.dir.join(format!("{id}.lock"));
        let f = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&p)
            .map_err(|e| format!("{}: {e}", p.display()))?;
        f.lock().map_err(|e| format!("{}: {e}", p.display()))?;
        Ok(Held { _file: f })
    }

    pub fn read(&self, id: &str) -> Result<Entry, String> {
        if !valid_id(id) {
            return Err(format!("{id:?} is not an id"));
        }
        let p = self.path(id);
        let text = hemostat_sensor_freebsd::saferead::read_text(&p).map_err(|e| format!("{}: {e}", p.display()))?;
        parse(&text).map_err(|e| format!("{}: {e}", p.display()))
    }

    pub fn begin(&self, i: &Intent) -> Result<(), String> {
        if !valid_id(&i.id) {
            return Err(format!("{:?} is not an id", i.id));
        }
        hemostat_sensor_freebsd::store::create_private(&self.dir).map_err(|e| format!("{}: {e}", self.dir.display()))?;
        let p = self.path(&i.id);
        let mut f = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&p)
            .map_err(|e| format!("{}: {e}", p.display()))?;
        writeln!(f, "{HEADER}\n{}", intent_line(i)).map_err(|e| format!("{}: {e}", p.display()))?;
        f.sync_all().map_err(|e| format!("{}: {e}", p.display()))?;
        std::fs::File::open(&self.dir).and_then(|d| d.sync_all()).map_err(|e| format!("{}: {e}", self.dir.display()))
    }

    pub fn append(&self, id: &str, kind: &str, p: &[(&str, String)]) -> Result<(), String> {
        let path = self.path(id);
        if !path.is_file() {
            return Err(format!("{} does not exist; a line goes after its intent", path.display()));
        }
        let mut f = std::fs::OpenOptions::new().append(true).open(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        writeln!(f, "{}", line(kind, id, now_secs(), p)).map_err(|e| format!("{}: {e}", path.display()))?;
        f.sync_data().map_err(|e| format!("{}: {e}", path.display()))
    }
}

pub fn open_block<'a>(entries: &'a [Entry], alias: Alias, cidr: &Cidr) -> Option<&'a Entry> {
    entries.iter().find(|e| {
        e.intent.class == Class::Block
            && e.intent.alias == alias
            && e.intent.cidr == *cidr
            && matches!(e.state(), State::Intent | State::Live | State::Confirmed)
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InConfig {

    Absent,

    Present(String),

    Unknown(String),
}

pub fn in_config(c: &Config, alias: Alias, cidr: &Cidr) -> InConfig {
    let Some(aliases) = c.root().child("aliases") else { return InConfig::Unknown("config.xml has no aliases".into()) };
    let found: Vec<_> = aliases.all("alias").filter(|a| a.text_at("name") == Some(alias.name())).collect();
    let [a] = found.as_slice() else {
        return InConfig::Unknown(format!("{} alias(es) named {}", found.len(), alias.name()));
    };
    let addrs: Vec<&str> = a.text_at("address").unwrap_or("").split_whitespace().collect();
    let details: Vec<&str> = a.text_at("detail").unwrap_or("").split("||").collect();
    let want = cidr.to_string();
    match addrs.iter().position(|x| *x == want || Cidr::parse(x).is_ok_and(|c| c == *cidr)) {
        None => InConfig::Absent,
        Some(i) => InConfig::Present(details.get(i).map_or(String::new(), |d| (*d).to_string())),
    }
}

pub fn table_entries(show: &str) -> Vec<Cidr> {
    show.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .filter_map(|l| Cidr::parse(l.trim_start_matches('!').trim()).ok())
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Facts {

    pub in_table: bool,

    pub config: InConfig,
}

#[derive(Debug)]
pub enum Judged {

    Lift(crate::cmd::Replayed),

    Leave(String),

    Done(String),
}

pub fn judge_lift(e: &Entry, f: &Facts) -> Judged {
    let i = &e.intent;
    if i.undo != UndoKind::Lift {
        return Judged::Leave(format!("{}: {} — nothing can be undone", i.class.token(), e.state().token()));
    }
    if i.existed {
        return Judged::Leave(format!(
            "{} was in {} before HEMOSTAT acted (existed=1): it is not HEMOSTAT's to lift",
            i.cidr,
            i.alias.name()
        ));
    }
    if let Some(by) = &e.lifted {
        return Judged::Done(format!("lifted already (by {by})"));
    }
    let ours = e.marker();
    let config = match &f.config {
        InConfig::Unknown(why) => return Judged::Leave(format!("config.xml could not be judged ({why}), so nothing is lifted")),
        InConfig::Present(d) if *d == ours => true,
        InConfig::Present(d) => {
            return Judged::Leave(format!(
                "config.xml lists {} in {} under {:?}, not {ours:?}: someone else holds it there, and \
                 HEMOSTAT lifts only its own",
                i.cidr,
                i.alias.name(),
                d
            ))
        }
        InConfig::Absent => false,
    };
    if !config && !f.in_table {
        let was = e.state().token();
        return Judged::Done(format!("{was}: in neither the table nor config.xml, so there is nothing to lift"));
    }
    Judged::Lift(crate::cmd::Replayed::judged(i.alias, i.cidr, i.id.clone(), config))
}

#[derive(Debug)]
pub enum Confirm {

    Go(crate::cmd::Confirmable),

    Already(String),

    Refused(String),
}

pub fn judge_confirm(e: &Entry, f: &Facts, now: u64) -> Confirm {
    let i = &e.intent;
    if i.class != Class::Block {
        return Confirm::Refused(format!("{} has nothing to confirm", i.class.token()));
    }
    if let Some(rev) = &e.confirmed {
        return Confirm::Already(rev.clone());
    }
    match e.state() {
        State::Existed => return Confirm::Refused(format!("{} was in {} before HEMOSTAT; there is nothing of HEMOSTAT's to confirm", i.cidr, i.alias.name())),
        State::Lifted => return Confirm::Refused(format!("lifted (by {}): a lifted block is not confirmed; block it again", e.lifted.as_deref().unwrap_or("?"))),
        State::Intent => return Confirm::Refused("the block never went live (only its intent was written), so there is nothing to confirm".into()),
        _ => {}
    }
    if now >= i.deadline {
        return Confirm::Refused(format!(
            "the deadline passed {} s ago: the watcher lifts it, and confirming now would race it. Block it again",
            now - i.deadline
        ));
    }
    if !f.in_table {
        return Confirm::Refused(format!(
            "{} is no longer in pf's table {} (a filter reload or another hand removed it): confirming would \
             write a block that was not live. Block it again",
            i.cidr,
            i.alias.name()
        ));
    }
    match &f.config {
        InConfig::Unknown(why) => Confirm::Refused(format!("config.xml could not be judged: {why}")),
        InConfig::Present(d) if *d != e.marker() => Confirm::Refused(format!(
            "config.xml already lists {} in {} under {d:?}: not HEMOSTAT's to confirm",
            i.cidr,
            i.alias.name()
        )),
        _ => Confirm::Go(crate::cmd::Confirmable::judged(i.alias, i.cidr, i.id.clone())),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lost {

    pub id: String,

    pub alias: Alias,

    pub cidr: Cidr,

    pub what: String,
}

pub fn recheck(entries: &[Entry], c: &Config, table: &dyn Fn(Alias) -> Option<String>) -> Vec<Lost> {
    let mut out = Vec::new();
    for e in entries.iter().filter(|e| e.state() == State::Confirmed) {
        let i = &e.intent;
        let mut missing = Vec::new();
        match in_config(c, i.alias, &i.cidr) {
            InConfig::Present(d) if d == e.marker() => {}
            InConfig::Present(d) => missing.push(format!("config.xml holds it under {d:?}, not {:?}", e.marker())),
            InConfig::Absent => missing.push("config.xml's alias no longer lists it".to_string()),
            InConfig::Unknown(why) => missing.push(format!("config.xml's alias could not be read ({why})")),
        }
        match table(i.alias) {
            Some(t) if table_entries(&t).contains(&i.cidr) => {}
            Some(_) => missing.push(format!("pf's table {} no longer holds it", i.alias.name())),
            None => {}
        }
        if !missing.is_empty() {
            out.push(Lost { id: i.id.clone(), alias: i.alias, cidr: i.cidr, what: missing.join("; ") });
        }
    }
    out
}
