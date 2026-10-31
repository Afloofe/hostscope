use hemostat_broker::perimeter::Allowed;
use hemostat_sensor_freebsd::configxml::Config;
use hemostat_sensor_freebsd::tools::{Invocation, Output, Runner, Tool};
use hs_core::cidr::Cidr;

use crate::cmd::{test_address, WriteCommand};
use crate::journal::{self, Confirm, Facts, InConfig, Intent, Judged, Journals};
use crate::Alias;

fn show(r: &mut dyn Runner, alias: Alias) -> Result<String, String> {
    crate::preflight::text(r, Invocation::new(Tool::Pfctl, &["-t", alias.name(), "-T", "show"]))
}

fn tests(r: &mut dyn Runner, alias: Alias, cidr: &Cidr) -> Result<bool, String> {
    let a = test_address(cidr);
    match r.run(&Invocation::new(Tool::Pfctl, &["-t", alias.name(), "-T", "test", &a])) {
        Ok(o) => Ok(o.success()),
        Err(e) => Err(format!("pfctl -T test {a}: {e}")),
    }
}

fn in_table(r: &mut dyn Runner, alias: Alias, cidr: &Cidr) -> Result<bool, String> {
    Ok(journal::table_entries(&show(r, alias)?).contains(cidr))
}

fn lists_table(tables: &str, alias: Alias) -> bool {
    tables.lines().any(|l| l.split_whitespace().any(|w| w == alias.name()))
}

fn shown(r: &mut dyn Runner, alias: Alias, cidr: &Cidr) -> Result<Option<bool>, String> {
    let inv = Invocation::new(Tool::Pfctl, &["-t", alias.name(), "-T", "show"]);
    let what = format!("{} {}", inv.tool(), inv.args().join(" "));
    let failed = match r.run(&inv) {
        Ok(o) if o.success() => return Ok(Some(journal::table_entries(&o.text()).contains(cidr))),
        Ok(o) => format!("{what} exited {:?}: {}", o.status, String::from_utf8_lossy(&o.stderr).trim()),
        Err(e) => return Err(format!("{what}: {e}")),
    };
    match crate::preflight::text(r, Invocation::new(Tool::Pfctl, &["-sTables"])) {
        Ok(tables) if !lists_table(&tables, alias) => Ok(None),
        Ok(_) => Err(format!("{failed}, and pfctl -sTables lists {}: the table is loaded and did not read", alias.name())),
        Err(e) => Err(format!("{failed}, and whether pf has the table loaded could not be read: {e}")),
    }
}

fn listed(r: &mut dyn Runner, alias: Alias, cidr: &Cidr) -> Result<bool, String> {
    Ok(shown(r, alias, cidr)?.unwrap_or(false))
}

fn ran(what: &str, out: Result<Output, hemostat_sensor_freebsd::tools::RunError>) -> Result<Output, String> {
    match out {
        Ok(o) if o.success() => Ok(o),
        Ok(o) => Err(format!(
            "{what} exited {:?}: {}",
            o.status,
            String::from_utf8_lossy(&o.stderr).trim().chars().take(400).collect::<String>()
        )),
        Err(e) => Err(format!("{what}: {e}")),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PhpDone {

    pub already: bool,

    pub rev: String,

    pub included: Vec<String>,
}

pub fn php_result(out: &Output) -> Result<PhpDone, String> {
    let text = out.text();
    let mut done: Option<PhpDone> = None;
    let mut included = Vec::new();
    for l in text.lines() {
        let Some(rest) = l.strip_prefix("HEMOSTAT ") else { continue };
        let mut w = rest.split_whitespace();
        match w.next() {
            Some("refused") => return Err(format!("alias.php refused: {}", rest.trim_start_matches("refused").trim())),
            Some(k @ ("ok" | "already")) => {
                let rev = w.find_map(|x| x.strip_prefix("rev=")).unwrap_or_default().to_string();
                done = Some(PhpDone { already: k == "already", rev, included: Vec::new() });
            }
            Some("included") => included.push(rest.trim_start_matches("included").trim().to_string()),
            _ => {}
        }
    }
    let stderr = String::from_utf8_lossy(&out.stderr);
    match (done, out.success()) {
        (Some(mut d), true) => {
            d.included = included;
            Ok(d)
        }
        (_, _) => Err(format!(
            "alias.php exited {:?} without saying it was done: {}",
            out.status,
            stderr.lines().filter(|l| l.contains("rror")).take(3).collect::<Vec<_>>().join(" | ")
        )),
    }
}

pub fn unverified_includes(d: &PhpDone, verified: &[String]) -> Vec<String> {
    d.included.iter().filter(|f| f.as_str() != "Standard input code" && !verified.contains(f)).cloned().collect()
}

pub const BOOTING: &str = "/var/run/booting";

pub fn refuse_while_booting(booting: bool) -> Result<(), String> {
    if booting {
        return Err(format!(
            "pfSense is still booting ({BOOTING} exists): rc.bootup reloads the filter from the config.xml \
             it read at start, and would silently undo this write. Wait until the boot finishes"
        ));
    }
    Ok(())
}

pub fn refuse_duplicate(j: &Journals, alias: Alias, cidr: &Cidr, follow: &str) -> Result<(), String> {
    let (entries, bad) = j.scan();
    if let Some(e) = journal::open_block(&entries, alias, cidr) {
        let id = &e.intent.id;
        return Err(format!(
            "{cidr} in {} already has HEMOSTAT block {id} ({}). One HEMOSTAT block per CIDR, so replay \
             can always tell whose entry it is: `hemostat fw confirm {id} --arm{follow}` keeps that one, \
             `hemostat undo {id}{follow}` lifts it",
            alias.name(),
            e.state().token()
        ));
    }
    if !bad.is_empty() {
        return Err(format!(
            "a containment journal does not read, and it may be a block of this CIDR: {}",
            bad.join("; ")
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Applied {

    Live,

    Existed(String),
}

pub fn apply(
    r: &mut dyn Runner,
    j: &Journals,
    allowed: Allowed,
    mut intent: Intent,
    config: &Config,
    follow: &str,
) -> Result<Applied, String> {
    let (alias, cidr) = (intent.alias, intent.cidr);
    let table = in_table(r, alias, &cidr)?;
    let conf = match journal::in_config(config, alias, &cidr) {
        InConfig::Unknown(why) => return Err(format!("config.xml's alias could not be read: {why}")),
        c => c,
    };
    refuse_duplicate(j, alias, &cidr, follow)?;
    intent.existed = table || conf != InConfig::Absent;
    let id = intent.id.clone();
    j.begin(&intent)?;
    if intent.existed {
        let why = format!(
            "{cidr} is already in {} ({}): not HEMOSTAT's, nothing added",
            alias.name(),
            if table { "pf's table" } else { "config.xml" }
        );
        j.append(&id, "note", &[("what", why.clone())])?;
        return Ok(Applied::Existed(why));
    }
    let w = WriteCommand::block(allowed, alias, &cidr)?;
    let what = w.describe().to_string();
    if let Err(why) = ran(&what, w.run(r)) {
        j.append(&id, "failed", &[("step", "add".into()), ("why", why.clone())])?;
        return Err(why);
    }
    let shown = in_table(r, alias, &cidr);
    let tested = tests(r, alias, &cidr);
    match (shown, tested) {
        (Ok(true), Ok(true)) => {
            j.append(&id, "live", &[("test", "ok".into())])?;
            Ok(Applied::Live)
        }
        (s, t) => {
            let why = format!("after the add, -T show {s:?} and -T test {t:?}: not provably live");
            j.append(&id, "failed", &[("step", "test".into()), ("why", why.clone())])?;
            Err(why)
        }
    }
}

pub fn facts(r: &mut dyn Runner, alias: Alias, cidr: &Cidr, config: &Result<Config, String>) -> Result<Facts, String> {
    Ok(loaded_facts(r, alias, cidr, config)?.0)
}

fn loaded_facts(r: &mut dyn Runner, alias: Alias, cidr: &Cidr, config: &Result<Config, String>) -> Result<(Facts, bool), String> {
    let table = shown(r, alias, cidr)?;
    let config = match config {
        Ok(c) => journal::in_config(c, alias, cidr),
        Err(why) => InConfig::Unknown(why.clone()),
    };
    Ok((Facts { in_table: table.unwrap_or(false), config }, table.is_some()))
}

pub fn held(config: &Result<Config, String>, e: &journal::Entry, follow: &str) -> Option<String> {
    let (alias, cidr, id) = (e.intent.alias.name(), e.intent.cidr, &e.intent.id);
    let found = match config {
        Ok(c) => journal::in_config(c, e.intent.alias, &cidr),
        Err(why) => InConfig::Unknown(why.clone()),
    };
    match found {
        InConfig::Absent => None,
        InConfig::Present(d) if d == e.marker() => Some(format!(
            "config.xml holds {cidr} in {alias} under {d:?}, so the block is persistent: it outlives filter \
             reloads, reboots and its deadline, and the watcher does not lift it. `hemostat undo {id}{follow}` \
             lifts it"
        )),
        InConfig::Present(d) => Some(format!(
            "config.xml lists {cidr} in {alias} under {d:?}, not HEMOSTAT's marker, so neither the watcher nor \
             `undo` lifts it: whoever wrote it there holds it"
        )),
        InConfig::Unknown(why) => Some(format!(
            "config.xml could not be read to show it does not hold {cidr} ({why}), and until it can the watcher \
             does not lift the block. `hemostat fw status{follow}` shows pf's table; `hemostat undo {id}{follow}` \
             lifts it once config.xml reads"
        )),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Confirmed {

    Done {

        rev: String,

        unverified: Vec<String>,
    },

    Already(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unconfirmed {

    Live(String),

    Held(String),
}

impl Unconfirmed {

    pub fn why(&self) -> &str {
        match self {
            Unconfirmed::Live(w) | Unconfirmed::Held(w) => w,
        }
    }
}

fn left(j: &Journals, e: &journal::Entry, step: &str, why: String, config: &Result<Config, String>, follow: &str) -> Unconfirmed {
    match held(config, e, follow) {
        None => Unconfirmed::Live(why),
        Some(h) => {
            let _ = j.append(&e.intent.id, "note", &[("what", format!("confirm stopped at {step}: {h}"))]);
            Unconfirmed::Held(format!("{why}. {h}"))
        }
    }
}

pub fn would_confirm(
    r: &mut dyn Runner,
    j: &Journals,
    id: &str,
    now: u64,
    read_config: &dyn Fn() -> Result<Config, String>,
    follow: &str,
) -> Result<Option<String>, Unconfirmed> {
    let mut ro = crate::cmd::ReadOnly::new(r);
    let e = j.read(id).map_err(Unconfirmed::Held)?;
    let config = read_config();
    let refused = |why: String| match held(&config, &e, follow) {
        None => Unconfirmed::Live(why),
        Some(h) => Unconfirmed::Held(format!("{why}. {h}")),
    };
    let f = facts(&mut ro, e.intent.alias, &e.intent.cidr, &config).map_err(&refused)?;
    match journal::judge_confirm(&e, &f, now) {
        Confirm::Go(_) => Ok(None),
        Confirm::Already(rev) => Ok(Some(rev)),
        Confirm::Refused(why) => Err(refused(why)),
    }
}

#[allow(clippy::too_many_arguments)]
pub fn confirm(
    r: &mut dyn Runner,
    j: &Journals,
    id: &str,
    now: u64,
    read_config: &dyn Fn() -> Result<Config, String>,
    seal: &mut dyn FnMut() -> Result<(), String>,
    verified: &[String],
    follow: &str,
) -> Result<Confirmed, Unconfirmed> {
    let e = j.read(id).map_err(|why| {
        Unconfirmed::Held(format!(
            "{why}. The journal did not read, so neither the watcher nor `undo` can act on this block from it: \
             `hemostat fw status{follow}` shows what pf's table holds"
        ))
    })?;
    let (alias, cidr) = (e.intent.alias, e.intent.cidr);

    let config = read_config();
    let f = facts(r, alias, &cidr, &config).map_err(|why| left(j, &e, "facts", why, &config, follow))?;
    let k = match journal::judge_confirm(&e, &f, now) {
        Confirm::Go(k) => k,
        Confirm::Already(rev) => return Ok(Confirmed::Already(rev)),
        Confirm::Refused(why) => return Err(left(j, &e, "judge", why, &config, follow)),
    };

    let fail = |step: &str, why: String| -> Unconfirmed {
        let _ = j.append(id, "failed", &[("step", step.to_string()), ("why", why.clone())]);
        left(j, &e, step, why, &read_config(), follow)
    };
    seal().map_err(|why| fail("seal", format!("the evidence could not be sealed, so nothing was written: {why}")))?;
    let w = WriteCommand::confirm(&k);
    let what = w.describe().to_string();
    let out = w.run(r).map_err(|e| fail("confirm", format!("{what}: {e}")))?;
    let done = php_result(&out).map_err(|why| fail("confirm", why))?;
    let unverified = unverified_includes(&done, verified);
    if !unverified.is_empty() {
        let _ = j.append(id, "note", &[("what", format!("alias.php included files preflight had not verified: {}", unverified.join(" ")))]);
    }

    let w = WriteCommand::readd(&k);
    let what = w.describe().to_string();
    ran(&what, w.run(r)).map_err(|why| fail("readd", why))?;
    match (in_table(r, alias, &cidr), tests(r, alias, &cidr)) {
        (Ok(true), Ok(true)) => {}
        (s, t) => return Err(fail("readd", format!("after the re-add, -T show {s:?} and -T test {t:?}"))),
    }

    let c = read_config().map_err(|why| fail("prove", format!("config.xml did not read back: {why}")))?;
    match journal::in_config(&c, alias, &cidr) {
        InConfig::Present(d) if d == e.marker() => {}
        other => return Err(fail("prove", format!("config.xml on disk does not hold {cidr} under {:?}: {other:?}", e.marker()))),
    }
    let rev = c.revision().ok_or_else(|| fail("prove", "config.xml on disk has no revision".into()))?;
    let want = journal::block_description(&cidr, id);
    if !done.already && !rev.description.ends_with(&want) {
        return Err(fail("prove", format!("config.xml's revision is {:?}, not HEMOSTAT's {want:?}", rev.description)));
    }

    j.append(id, "confirmed", &[("rev", rev.time.clone())])
        .map_err(|why| fail("journal", format!("config.xml was written and proven, and the journal's confirmed line was not: {why}")))?;
    Ok(Confirmed::Done { rev: rev.time, unverified })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Lifted {

    Done {

        config: bool,

        table: bool,
    },

    Covered,

    Left(String),

    Nothing(String),
}

#[allow(clippy::too_many_arguments)]
pub fn lift(
    r: &mut dyn Runner,
    j: &Journals,
    id: &str,
    by: &str,
    config_writes: bool,
    read_config: &dyn Fn() -> Result<Config, String>,
    seal: &mut dyn FnMut() -> Result<(), String>,
    follow: &str,
) -> Result<Lifted, String> {
    let e = j.read(id)?;
    let (alias, cidr) = (e.intent.alias, e.intent.cidr);
    let fail = |step: &str, why: String| -> String {
        let _ = j.append(id, "failed", &[("step", step.to_string()), ("why", why.clone())]);
        why
    };

    let (f, loaded) = loaded_facts(r, alias, &cidr, &read_config()).map_err(|why| fail("facts", why))?;
    let rep = match journal::judge_lift(&e, &f) {
        Judged::Lift(rep) => rep,
        Judged::Leave(why) => return Ok(Lifted::Left(why)),
        Judged::Done(why) => {

            if e.lifted.is_none() && matches!(e.state(), journal::State::Intent | journal::State::Live | journal::State::Confirmed) {
                j.append(id, "lifted", &[("by", by.to_string())])?;
                j.append(id, "note", &[("what", format!("{by}: {why}"))])?;
            }
            return Ok(Lifted::Nothing(why));
        }
    };
    if let Some(w) = WriteCommand::unconfig(&rep) {
        if !config_writes {
            return Ok(Lifted::Left(format!(
                "config.xml holds {cidr} under {:?}: a confirm wrote it, so it is not the watcher's to lift. \
                 `hemostat undo {id}{follow}` lifts it",
                e.marker()
            )));
        }
        seal().map_err(|why| fail("seal", format!("the evidence could not be sealed, so config.xml was not written: {why}")))?;
        let what = w.describe().to_string();
        let out = w.run(r).map_err(|e| fail("unconfig", format!("{what}: {e}")))?;
        php_result(&out).map_err(|why| fail("unconfig", why))?;
        let c = read_config().map_err(|why| fail("unconfig", format!("config.xml did not read back: {why}")))?;
        if journal::in_config(&c, alias, &cidr) != InConfig::Absent {
            return Err(fail("unconfig", format!("config.xml on disk still lists {cidr} in {}", alias.name())));
        }
    }

    let table = match shown(r, alias, &cidr).map_err(|why| fail("delete", why))? {
        Some(true) => {
            let w = WriteCommand::lift(&rep);
            let what = w.describe().to_string();
            ran(&what, w.run(r)).map_err(|why| fail("delete", why))?;
            true
        }
        Some(false) | None => loaded,
    };
    if listed(r, alias, &cidr).map_err(|why| fail("prove", why))? {
        return Err(fail("prove", format!("-T show still lists {cidr} after the delete")));
    }
    let covered = tests(r, alias, &cidr).map_err(|why| fail("prove", why))?;
    j.append(id, "lifted", &[("by", by.to_string())])?;
    if !table {
        let _ = j.append(id, "note", &[("what", unloaded(alias, &cidr, rep.config()))]);
    }
    if covered {
        let _ = j.append(id, "note", &[("what", format!("-T test {} still matches after the lift: another entry in {} covers it", test_address(&cidr), alias.name()))]);
        return Ok(Lifted::Covered);
    }
    Ok(Lifted::Done { config: rep.config(), table })
}

pub fn unloaded(alias: Alias, cidr: &Cidr, config: bool) -> String {
    let name = alias.name();
    if config {
        format!(
            "pf had no table {name} loaded (its rule disabled or deleted), so there was nothing in pf to delete; \
             {cidr} is out of config.xml's {name}, so the rule loads the alias without it once it is back"
        )
    } else {
        format!("pf had no table {name} loaded any more (its rule disabled or deleted), so nothing of {cidr} was left in pf to delete")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WatchStep {

    Wait(u64),

    Due,

    Stop(String),
}

pub const LIFT_TRIES: u32 = 15;

pub fn lift_retry_after(failed: u32) -> Option<u64> {
    (failed > 0 && failed < LIFT_TRIES).then(|| 2u64.saturating_pow(failed).min(60))
}

pub fn watch_step(e: &journal::Entry, now: u64) -> WatchStep {
    use journal::State;
    match e.state() {
        State::Confirmed => return WatchStep::Stop(format!("confirmed at revision {}", e.confirmed.as_deref().unwrap_or("?"))),
        State::Lifted => return WatchStep::Stop(format!("lifted already (by {})", e.lifted.as_deref().unwrap_or("?"))),
        State::Existed => return WatchStep::Stop("it existed before HEMOSTAT; nothing of HEMOSTAT's to lift".into()),
        State::Killed => return WatchStep::Stop("a state kill has nothing to lift".into()),
        State::Intent | State::Live => {}
    }
    match e.intent.deadline.checked_sub(now) {
        Some(0) | None => WatchStep::Due,
        Some(left) => WatchStep::Wait(left.min(5)),
    }
}
