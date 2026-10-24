use std::process::Command;

use hs_core::Trust;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {

    Nftables,

    IptablesLegacy,
}

#[derive(Debug, Clone)]
pub struct Report {

    pub backend: Option<Backend>,

    pub input_policy: Option<String>,

    pub rule_count: usize,

    pub accepting_ports: Vec<u16>,

    pub sample: String,

    pub trust: Trust,

    pub unreadable: Option<String>,
}

impl Default for Report {
    fn default() -> Self {
        Report {
            backend: None,
            input_policy: None,
            rule_count: 0,
            accepting_ports: Vec::new(),
            sample: String::new(),
            trust: Trust::Syscall,
            unreadable: None,
        }
    }
}

fn nft_input_chain_state(prev: bool, line: &str) -> bool {

    if line.contains("hook input") {
        return true;
    }
    if line.contains("hook output")
        || line.contains("hook forward")
        || line.contains("hook prerouting")
        || line.contains("hook postrouting")
    {
        return false;
    }
    if line.starts_with('}') {
        return false;
    }
    if line.split_whitespace().next() == Some("chain") {
        return false;
    }
    prev
}

fn input_path_rules(text: &str) -> Vec<&str> {
    use std::collections::{HashMap, HashSet};

    let mut chains: Vec<((String, String), Vec<&str>)> = Vec::new();
    let mut index: HashMap<(String, String), usize> = HashMap::new();
    let mut roots: Vec<(String, String)> = Vec::new();
    let (mut table, mut depth, mut open): (String, i32, Option<(usize, i32)>) =
        (String::new(), 0, None);
    for line in text.lines() {
        let l = line.trim();
        let toks: Vec<&str> = l.split_whitespace().collect();
        match toks.first().copied() {

            Some("table") if open.is_none() => {
                table = toks.get(1..).unwrap_or(&[]).join(" ").trim_end_matches('{').trim().to_string();
            }
            Some("chain") if open.is_none() => {
                let name = toks.get(1).map_or("", |n| n.trim_end_matches('{').trim_matches('"'));
                let key = (table.clone(), name.to_string());
                chains.push((key.clone(), vec![l]));

                index.entry(key).or_insert(chains.len() - 1);
                open = Some((chains.len() - 1, depth));
            }

            Some(t) if open.is_none() && t.starts_with('*') => table = t.to_string(),
            Some("-A") => {
                let key = (table.clone(), toks.get(1).copied().unwrap_or_default().to_string());
                if key.1 == "INPUT" && !roots.contains(&key) {
                    roots.push(key.clone());
                }
                match index.get(&key).and_then(|&i| chains.get_mut(i)) {
                    Some((_, lines)) => lines.push(l),
                    None => {
                        index.insert(key.clone(), chains.len());
                        chains.push((key, vec![l]));
                    }
                }
            }
            _ => {
                if let Some((i, _)) = open {
                    if let Some((_, lines)) = chains.get_mut(i) {
                        lines.push(l);
                    }
                }
            }
        }
        if let Some((i, _)) = open {
            if l.contains("hook input") {
                if let Some((k, _)) = chains.get(i) {
                    roots.push(k.clone());
                }
            }
        }
        depth += i32::try_from(l.matches('{').count()).unwrap_or(0);
        depth -= i32::try_from(l.matches('}').count()).unwrap_or(0);
        if open.is_some_and(|(_, d)| depth <= d) {
            open = None;
        }
    }

    let mut reached: HashSet<(String, String)> = HashSet::new();
    let mut queue = roots;
    while let Some(key) = queue.pop() {
        if reached.contains(&key) {
            continue;
        }
        let Some((_, lines)) = index.get(&key).and_then(|&i| chains.get(i)) else { continue };
        for l in lines {
            let toks: Vec<&str> = l.split_whitespace().collect();
            for w in toks.windows(2) {
                if let [verb, target] = w {
                    if matches!(*verb, "jump" | "goto" | "-j" | "-g") {
                        let t = target.trim_matches(|c| matches!(c, ',' | '}' | ';' | '"'));
                        queue.push((key.0.clone(), t.to_string()));
                    }
                }
            }
        }
        reached.insert(key);
    }
    chains
        .iter()
        .filter(|(k, _)| reached.contains(k))
        .flat_map(|(_, lines)| lines.iter().copied())
        .collect()
}

fn dport_operand(toks: &[&str], at: usize) -> Vec<u16> {
    if at > 0 && toks.get(at - 1) == Some(&"!") {
        return Vec::new();
    }
    let Some(first) = toks.get(at + 1) else { return Vec::new() };
    if first.starts_with('!') {
        return Vec::new();
    }
    let words: Vec<&str> = if first.starts_with('{') {
        let rest = toks.get(at + 1..).unwrap_or(&[]);
        let end = rest.iter().position(|t| t.contains('}')).map_or(rest.len(), |e| e + 1);
        rest.get(..end).unwrap_or(rest).to_vec()
    } else {
        vec![*first]
    };
    words
        .iter()
        .flat_map(|w| w.split(','))
        .map(|p| p.trim_matches(|c| matches!(c, '{' | '}')))
        .filter_map(|p| p.parse::<u16>().ok())
        .filter(|p| *p != 0)
        .collect()
}

fn accepting_ports(text: &str) -> Vec<u16> {
    let mut ports = Vec::new();
    for l in input_path_rules(text) {
        let toks: Vec<&str> = l.split_whitespace().collect();
        let accepts = toks.contains(&"accept") || toks.windows(2).any(|w| w == ["-j", "ACCEPT"]);
        if !accepts {
            continue;
        }
        let Some(at) = toks.iter().position(|t| matches!(*t, "dport" | "--dport" | "--dports")) else {
            continue;
        };
        for p in dport_operand(&toks, at) {
            if !ports.contains(&p) {
                ports.push(p);
            }
        }
    }
    ports.sort_unstable();
    ports
}

fn input_policy(text: &str) -> Option<String> {
    let mut in_input = false;
    for line in text.lines() {
        let l = line.trim();
        in_input = nft_input_chain_state(in_input, l);
        let toks: Vec<&str> = l.split_whitespace().collect();

        if in_input {
            if let Some(i) = toks.iter().position(|t| *t == "policy") {
                if let Some(v) = toks.get(i + 1) {
                    let v = v.trim_end_matches(';');
                    if matches!(v, "accept" | "drop") {
                        return Some(v.to_string());
                    }
                }
            }
        }

        if toks.first() == Some(&":INPUT") {
            if let Some(v) = toks.get(1) {
                if matches!(*v, "ACCEPT" | "DROP") {
                    return Some(v.to_ascii_lowercase());
                }
            }
        }
    }
    None
}

enum RunOutcome {

    Ok(String),

    Refused(String),

    NotInstalled,
}

const NFT_PATHS: &[&str] = &["/usr/sbin/nft", "/sbin/nft", "/usr/bin/nft", "/bin/nft"];
const IPTABLES_SAVE_PATHS: &[&str] =
    &["/usr/sbin/iptables-save", "/sbin/iptables-save", "/usr/bin/iptables-save", "/bin/iptables-save"];

fn run(candidates: &[&str], args: &[&str]) -> RunOutcome {
    let Some(exe) = crate::netpolicy::tool(candidates) else {
        return RunOutcome::NotInstalled;
    };
    match Command::new(exe).args(args).env_clear().env("LC_ALL", "C").output() {
        Ok(out) if out.status.success() => {
            RunOutcome::Ok(String::from_utf8_lossy(&out.stdout).into_owned())
        }
        Ok(out) => {
            let code = out.status.code().map_or_else(|| "signal".into(), |c| c.to_string());
            let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
            let detail = if stderr.is_empty() {
                format!("exit {code}")
            } else {
                format!("exit {code}: {stderr}")
            };
            RunOutcome::Refused(detail)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => RunOutcome::NotInstalled,

        Err(e) => RunOutcome::Refused(e.to_string()),
    }
}

fn build_report(backend: Backend, text: &str) -> Report {
    let rule_count = text
        .lines()
        .filter(|l| {
            let t = l.trim();
            !t.is_empty() && !t.starts_with('#') && (t.contains("accept") || t.contains("drop")
                || t.contains("-j ") || t.contains("reject"))
        })
        .count();
    let sample: String = text.lines().take(40).collect::<Vec<_>>().join("\n");
    Report {
        backend: Some(backend),
        input_policy: input_policy(text),
        rule_count,
        accepting_ports: accepting_ports(text),
        sample,
        trust: Trust::Syscall,
        unreadable: None,
    }
}

pub fn report() -> Report {
    let nft = run(NFT_PATHS, &["list", "ruleset"]);
    if let RunOutcome::Ok(text) = &nft {
        let from_nft = build_report(Backend::Nftables, text);
        if from_nft.rule_count > 0 {
            return from_nft;
        }

        if let RunOutcome::Ok(ipt_text) = &run(IPTABLES_SAVE_PATHS, &[]) {
            let from_ipt = build_report(Backend::IptablesLegacy, ipt_text);
            if from_ipt.rule_count > 0 {
                return from_ipt;
            }
        }
        return from_nft;
    }
    let ipt = run(IPTABLES_SAVE_PATHS, &[]);
    if let RunOutcome::Ok(text) = &ipt {
        return build_report(Backend::IptablesLegacy, text);
    }

    Report { unreadable: Some(unread_reason(&nft, &ipt)), ..Report::default() }
}

fn unread_reason(nft: &RunOutcome, ipt: &RunOutcome) -> String {
    match (nft, ipt) {
        (RunOutcome::Refused(d), _) => {
            format!("nft is installed but did not return the ruleset ({d}) — re-run as root")
        }
        (_, RunOutcome::Refused(d)) => {
            format!("iptables-save is installed but did not return the ruleset ({d}) — re-run as root")
        }
        _ => "neither nft nor iptables-save is in /usr/sbin, /sbin, /usr/bin or /bin, so no \
              ruleset was read. That is not a host without a firewall: the kernel's ruleset is \
              unread, and `hemostat snapshot` reads it over netlink"
            .to_string(),
    }
}
