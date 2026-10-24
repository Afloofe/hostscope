use hemostat_broker::perimeter::Allowed;
use hemostat_sensor_freebsd::telemetry::states::{self, State};
use hemostat_sensor_freebsd::tools::{Invocation, Runner, Tool};
use hs_core::cidr::Cidr;

use crate::cmd::WriteCommand;
use crate::journal::{Intent, Journals};
use crate::Alias;

pub fn matches(s: &State, alias: Alias, cidr: &Cidr) -> bool {
    let ends = match alias {
        Alias::Out => [Some(s.dst), s.dst_orig],
        Alias::In => [Some(s.src), s.src_orig],
    };
    ends.iter().flatten().any(|e| cidr.contains(&e.addr))
}

pub fn blocks(text: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for line in text.lines() {
        if line.trim().is_empty() {
            continue;
        }
        if line.starts_with(char::is_whitespace) {
            if let Some(last) = out.last_mut() {
                last.push('\n');
                last.push_str(line);
            }
        } else {
            out.push(line.to_string());
        }
    }
    out
}

pub fn matching(text: &str, alias: Alias, cidr: &Cidr) -> Vec<String> {
    blocks(text)
        .into_iter()
        .filter(|b| states::parse(b).states.first().is_some_and(|s| matches(s, alias, cidr)))
        .collect()
}

pub fn listing(r: &mut dyn Runner) -> Result<String, String> {
    crate::preflight::text(r, Invocation::new(Tool::Pfctl, &["-ss", "-vv"]))
}

pub fn killed_count(stderr: &str) -> Option<u64> {
    stderr.lines().find_map(|l| l.trim().strip_prefix("killed ")?.split_whitespace().next()?.parse().ok())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Killed {

    pub matched: usize,

    pub killed: Option<u64>,

    pub remaining: usize,
}

pub fn kill(r: &mut dyn Runner, j: &Journals, allowed: Allowed, intent: Intent, matched: usize, store: &str) -> Result<Killed, String> {
    let (alias, cidr, id) = (intent.alias, intent.cidr, intent.id.clone());
    j.begin(&intent)?;
    let w = WriteCommand::statekill(allowed, alias, &cidr)?;
    let what = w.describe().to_string();
    let out = match w.run(r) {
        Ok(o) if o.success() => o,
        Ok(o) => {
            let why = format!("{what} exited {:?}: {}", o.status, String::from_utf8_lossy(&o.stderr).trim());
            j.append(&id, "failed", &[("step", "kill".into()), ("why", why.clone())])?;
            return Err(why);
        }
        Err(e) => {
            let why = format!("{what}: {e}");
            j.append(&id, "failed", &[("step", "kill".into()), ("why", why.clone())])?;
            return Err(why);
        }
    };
    let killed = killed_count(&String::from_utf8_lossy(&out.stderr));
    let remaining = match listing(r) {
        Ok(t) => matching(&t, alias, &cidr).len(),
        Err(why) => {
            j.append(&id, "failed", &[("step", "recount".into()), ("why", why.clone())])?;
            return Err(format!("killed, but the states could not be listed again: {why}"));
        }
    };
    j.append(
        &id,
        "killed",
        &[
            ("matched", matched.to_string()),
            ("killed", killed.map_or("?".into(), |k| k.to_string())),
            ("remaining", remaining.to_string()),
            ("store", store.to_string()),
        ],
    )?;
    Ok(Killed { matched, killed, remaining })
}
