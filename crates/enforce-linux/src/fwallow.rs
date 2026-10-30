use std::path::PathBuf;
use std::process::Command;

use crate::outcome::{ApplyOptions, Failure, Outcome, Plan, RefuseCause, Refusal, UndoKind, UndoRecord};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NftChain {

    pub family: String,

    pub table: String,

    pub chain: String,
}

pub fn marker(port: u16) -> String {
    format!("mahoraga-allow-{port}")
}

pub fn marker_port(comment: &str) -> Option<u16> {
    let port: u16 = comment.strip_prefix("mahoraga-allow-")?.parse().ok()?;
    (port > 0 && marker(port) == comment).then_some(port)
}

pub fn is_allow_rule(line: &str, port: u16) -> bool {
    let toks: Vec<&str> = line.split_whitespace().collect();
    let quoted = format!("\"{}\"", marker(port));
    let dport = port.to_string();
    toks.windows(2).any(|w| w == ["comment", quoted.as_str()])
        && toks.windows(4).any(|w| w == ["tcp", "dport", dport.as_str(), "accept"])
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Found {

    Absent,

    One(u64),

    Ambiguous {

        rules: usize,

        handles: Vec<u64>,
    },
}

pub fn find_allow(listing: &str, port: u16) -> Found {
    let rules: Vec<Option<u64>> =
        listing.lines().filter(|l| is_allow_rule(l, port)).map(handle_of).collect();
    match rules.as_slice() {
        [] => Found::Absent,
        [Some(h)] => Found::One(*h),
        _ => Found::Ambiguous { rules: rules.len(), handles: rules.iter().flatten().copied().collect() },
    }
}

fn handle_of(line: &str) -> Option<u64> {
    let toks: Vec<&str> = line.split_whitespace().collect();
    toks.windows(3).find_map(|w| match w {
        ["#", "handle", n] => n.parse().ok(),
        _ => None,
    })
}

const FAMILIES: [&str; 6] = ["ip", "ip6", "inet", "arp", "bridge", "netdev"];

const MAX_NAME: usize = 255;

pub fn chain_refusal(family: &str, table: &str, chain: &str) -> Option<String> {
    if !FAMILIES.contains(&family) {
        return Some(format!("{family:?} is not an nft address family"));
    }
    let name_ok = |s: &str| {
        s.len() <= MAX_NAME
            && s.chars().next().is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
            && s.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
    };
    if !name_ok(table) {
        return Some(format!("{table:?} is not a table name nft reads as one word"));
    }
    if !name_ok(chain) {
        return Some(format!("{chain:?} is not a chain name nft reads as one word"));
    }
    None
}

pub fn input_hook_chain(ruleset: &str) -> Option<NftChain> {
    let mut family = String::new();
    let mut table = String::new();
    let mut chain = String::new();
    for line in ruleset.lines() {
        let toks: Vec<&str> = line.split_whitespace().collect();
        if toks.first() == Some(&"table") && toks.len() >= 3 {
            family = toks[1].to_string();
            table = toks[2].trim_end_matches('{').to_string();
            chain.clear();
        } else if toks.first() == Some(&"chain") && toks.len() >= 2 {
            chain = toks[1].trim_end_matches('{').to_string();
        }

        if toks.first() == Some(&"type") && toks.windows(2).any(|w| w == ["hook", "input"]) {
            if !family.is_empty() && !table.is_empty() && !chain.is_empty() {
                return Some(NftChain { family, table, chain });
            }
        }
    }
    None
}

pub(crate) fn nft_path() -> Option<PathBuf> {
    crate::paths::resolve_tool(&["/usr/sbin/nft", "/sbin/nft", "/usr/bin/nft", "/bin/nft"])
}

pub(crate) fn nft_capture(nft: &std::path::Path, args: &[&str]) -> Result<String, String> {
    let out = Command::new(nft)
        .args(args)
        .env_clear()
        .env("LC_ALL", "C")
        .output()
        .map_err(|e| format!("could not run nft: {e}"))?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    } else {
        let code = out.status.code().map_or_else(|| "signal".into(), |c| c.to_string());
        Err(format!("nft exited {code}: {}", String::from_utf8_lossy(&out.stderr).trim()))
    }
}

pub fn undo_allow(
    family: &str,
    table: &str,
    chain: &str,
    comment: &str,
    opts: &ApplyOptions,
) -> Outcome {
    let refuse = |why: String| {
        Outcome::Refused(Refusal {
            action: format!("remove the firewall allow (comment {comment:?})"),
            cause: RefuseCause::InvalidTarget("not a firewall allow this tool added".into()),
            message: format!(
                "refused to replay this record: {why}, so it was not written by this tool. \
                 Nothing was run and the firewall is unchanged"
            ),
            suggested_alternative: None,
        })
    };
    let Some(port) = marker_port(comment) else {
        return refuse(format!("its comment {comment:?} is not `mahoraga-allow-<port>`"));
    };
    if let Some(why) = chain_refusal(family, table, chain) {
        return refuse(why);
    }
    let summary = format!("remove the firewall allow (comment `{comment}`)");
    let Some(nft) = nft_path() else {
        return Outcome::Failed(Failure {
            action: summary,
            reason: "nft not found; cannot remove the firewall allow".into(),
        });
    };
    let listing = match nft_capture(&nft, &["-a", "list", "chain", family, table, chain]) {
        Ok(t) => t,
        Err(e) => {
            return Outcome::Failed(Failure {
                action: summary,
                reason: format!("could not list the chain to find the rule: {e}"),
            });
        }
    };
    let handle = match find_allow(&listing, port) {
        Found::One(h) => h,
        Found::Absent => {
            return Outcome::Applied(UndoRecord {
                did: format!("firewall allow (comment `{comment}`) was already absent"),
                undo: UndoKind::Nothing,
                reversible: false,
            })
        }
        Found::Ambiguous { rules, handles } => {
            let named: Vec<String> = handles.iter().map(u64::to_string).collect();
            return Outcome::Refused(Refusal {
                action: summary,
                cause: RefuseCause::InvalidTarget("not exactly one rule matches".into()),
                message: format!(
                    "refused to delete anything: {rules} rule(s) in `{family} {table} {chain}` \
                     are `tcp dport {port} accept` with comment `{comment}` (handles: {}), and \
                     this deletes one rule by its handle only when exactly one is there — which \
                     one this tool added is not something to guess with a delete. Look with \
                     `nft -a list chain {family} {table} {chain}` and remove the right one with \
                     `nft delete rule {family} {table} {chain} handle <N>`",
                    if named.is_empty() { "none readable".to_string() } else { named.join(", ") }
                ),
                suggested_alternative: None,
            });
        }
    };
    if !opts.armed {
        return Outcome::Planned(Plan {
            summary,
            detail: format!(
                "Delete rule handle {handle} in `{family} {table} {chain}` (carries `{comment}`)."
            ),
            undo: "re-add the allow if needed".into(),
            reversible: true,
            prefer_instead: None,
        });
    }
    let h = handle.to_string();
    match crate::paths::run_tool(&nft, &["delete", "rule", family, table, chain, "handle", h.as_str()]) {
        Ok(()) => Outcome::Applied(UndoRecord {
            did: format!("removed the firewall allow (comment `{comment}`, handle {handle})"),
            undo: UndoKind::Nothing,
            reversible: false,
        }),
        Err(e) => Outcome::Failed(Failure { action: summary, reason: format!("nft delete failed: {e}") }),
    }
}
