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

pub fn refuse_duplicate(j: &Journals, alias: Alias, cidr: &Cidr) -> Result<(), String> {
    let (entries, bad) = j.scan();
    if let Some(e) = journal::open_block(&entries, alias, cidr) {
        let id = &e.intent.id;
        return Err(format!(
            "{cidr} in {} already has HEMOSTAT block {id} ({}). One HEMOSTAT block per CIDR, so replay \
             can always tell whose entry it is: `hemostat fw confirm {id}` keeps that one, `hemostat undo \
             {id}` lifts it",
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
) -> Result<Applied, String> {
    let (alias, cidr) = (intent.alias, intent.cidr);
    let table = in_table(r, alias, &cidr)?;
    let conf = match journal::in_config(config, alias, &cidr) {
        InConfig::Unknown(why) => return Err(format!("config.xml's alias could not be read: {why}")),
        c => c,
    };
    refuse_duplicate(j, alias, &cidr)?;
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
    Ok(Facts {
        in_table: in_table(r, alias, cidr)?,
        config: match config {
            Ok(c) => journal::in_config(c, alias, cidr),
            Err(why) => InConfig::Unknown(why.clone()),
        },
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Confirmed {

    Done {

        rev: String,

        unverified: Vec<String>,
    },

    Already(String),
}

pub fn confirm(
    r: &mut dyn Runner,
    j: &Journals,
    id: &str,
    now: u64,
    read_config: &dyn Fn() -> Result<Config, String>,
    seal: &mut dyn FnMut() -> Result<(), String>,
    verified: &[String],
) -> Result<Confirmed, String> {
    let e = j.read(id)?;
    let (alias, cidr) = (e.intent.alias, e.intent.cidr);

    let f = facts(r, alias, &cidr, &read_config())?;
    let k = match journal::judge_confirm(&e, &f, now) {
        Confirm::Go(k) => k,
        Confirm::Already(rev) => return Ok(Confirmed::Already(rev)),
        Confirm::Refused(why) => return Err(why),
    };
    let fail = |step: &str, why: String| -> String {
        let _ = j.append(id, "failed", &[("step", step.to_string()), ("why", why.clone())]);
        why
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
    j.append(id, "confirmed", &[("rev", rev.time.clone())])?;
    Ok(Confirmed::Done { rev: rev.time, unverified })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Lifted {

    Done {

        config: bool,
    },

    Covered,

    Left(String),

    Nothing(String),
}

pub fn lift(
    r: &mut dyn Runner,
    j: &Journals,
    id: &str,
    by: &str,
    config_writes: bool,
    read_config: &dyn Fn() -> Result<Config, String>,
    seal: &mut dyn FnMut() -> Result<(), String>,
) -> Result<Lifted, String> {
    let e = j.read(id)?;
    let (alias, cidr) = (e.intent.alias, e.intent.cidr);
    let f = facts(r, alias, &cidr, &read_config())?;
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
    let fail = |step: &str, why: String| -> String {
        let _ = j.append(id, "failed", &[("step", step.to_string()), ("why", why.clone())]);
        why
    };
    if let Some(w) = WriteCommand::unconfig(&rep) {
        if !config_writes {
            return Ok(Lifted::Left(format!(
                "config.xml holds {cidr} under {:?}: a confirm wrote it, so it is not the watcher's to lift. \
                 `hemostat undo {id}` lifts it",
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
    if in_table(r, alias, &cidr).map_err(|why| fail("delete", why))? {
        let w = WriteCommand::lift(&rep);
        let what = w.describe().to_string();
        ran(&what, w.run(r)).map_err(|why| fail("delete", why))?;
    }
    if in_table(r, alias, &cidr).map_err(|why| fail("prove", why))? {
        return Err(fail("prove", format!("-T show still lists {cidr} after the delete")));
    }
    let covered = tests(r, alias, &cidr).map_err(|why| fail("prove", why))?;
    j.append(id, "lifted", &[("by", by.to_string())])?;
    if covered {
        let _ = j.append(id, "note", &[("what", format!("-T test {} still matches after the lift: another entry in {} covers it", test_address(&cidr), alias.name()))]);
        return Ok(Lifted::Covered);
    }
    Ok(Lifted::Done { config: rep.config() })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WatchStep {

    Wait(u64),

    Due,

    Stop(String),
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
