use std::collections::{BTreeSet, HashMap, HashSet};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reach {

    Open,

    Blocked(String),

    Unknown(String),
}

const MAX_DEPTH: usize = 64;

const MAX_STEPS: usize = 1_000_000;

const MAX_IFACES: usize = 32;

const PROBE_FLAGS: u8 = 0x02;

type Ranges = Vec<(u16, u16)>;

#[derive(Debug, Clone, Default)]
pub(crate) struct Ruleset {
    chains: Vec<Chain>,

    index: HashMap<(String, String), usize>,

    sets: HashMap<(String, String), Option<Ranges>>,

    bases: Vec<usize>,

    broken: Option<String>,
}

#[derive(Debug, Clone)]
struct Chain {

    table: String,
    name: String,
    base: Option<Base>,
    rules: Vec<Rule>,
}

#[derive(Debug, Clone)]
struct Base {

    policy: Option<bool>,
    devices: Devices,

    bridged: bool,

    label: String,
}

#[derive(Debug, Clone)]
enum Devices {
    All,
    Only(Vec<String>),

    Unread,
}

#[derive(Debug, Clone)]
struct Rule {

    text: String,

    conds: Vec<Cond>,
    effect: Effect,
}

#[derive(Debug, Clone)]
enum Cond {

    Always,

    Never,

    Maybe,

    Port(Ports),

    Iface { names: Vec<String>, negated: bool },
}

#[derive(Debug, Clone)]
enum Ports {

    Ranges { ranges: Vec<(u16, u16)>, negated: bool },

    Named { name: String, negated: bool },

    Either { ranges: Vec<(u16, u16)>, negated: bool },
}

#[derive(Debug, Clone)]
enum Effect {

    Continue,
    Accept,

    Drop,
    Return,
    Jump(String),
    Goto(String),

    PortMap(Vec<(Vec<(u16, u16)>, Effect)>),

    IfaceMap(Vec<(Vec<String>, Effect)>),

    Unknown(String),
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum Ifc {
    Is(String),
    Not(BTreeSet<String>),
}

type States = BTreeSet<Ifc>;

#[derive(Default)]
struct Flow {

    live: States,

    accepted: States,

    returned: States,
}

pub(crate) fn both(first: Reach, second: Reach) -> Reach {
    match (first, second) {
        (Reach::Open, Reach::Open) => Reach::Open,
        (Reach::Unknown(why), Reach::Blocked(by)) | (Reach::Blocked(by), Reach::Unknown(why)) => {
            Reach::Unknown(format!("{why} — and {by} drops it"))
        }
        (Reach::Unknown(why), _) | (_, Reach::Unknown(why)) => Reach::Unknown(why),
        (Reach::Blocked(by), _) | (_, Reach::Blocked(by)) => Reach::Blocked(by),
    }
}

impl Ruleset {

    pub(crate) fn tcp_reach(&self, port: u16) -> Reach {
        if let Some(why) = &self.broken {
            return Reach::Unknown(why.clone());
        }
        let mut w = Walk { rs: self, port, steps: 0, stack: Vec::new(), drops: 0, blocked: None, unknown: None };
        let mut states: States = BTreeSet::from([Ifc::Not(BTreeSet::from(["lo".to_string()]))]);
        for &b in &self.bases {
            let Some(base) = self.chains.get(b).and_then(|c| c.base.as_ref()) else { continue };
            let (inside, outside) = match &base.devices {
                Devices::All => (states.clone(), States::new()),
                Devices::Only(devs) => split_iface(&states, devs, false),
                Devices::Unread => (states.clone(), states.clone()),
            };
            let drops_before = w.drops;
            let (accepted, returned) = w.chain(b, inside);
            let mut passed = accepted;
            if !returned.is_empty() {
                match base.policy {
                    Some(true) => passed.extend(returned),
                    Some(false) => w.block(format!("the default policy (drop) of {}", base.label)),
                    None => w.unknown(format!("the default policy of {} was not printed", base.label)),
                }
            }
            passed.extend(outside);
            if base.bridged {

                if w.drops > drops_before {
                    w.unknown(format!(
                        "{} drops it, and as a bridge-family chain it applies only if this host bridges the packet",
                        base.label
                    ));
                }
                passed = states.clone();
            }
            states = passed;
            if w.unknown.is_some() {
                break;
            }
        }
        if let Some(why) = w.unknown {
            return Reach::Unknown(why);
        }
        match (w.blocked, states.is_empty()) {
            (None, false) => Reach::Open,
            (Some(by), true) => Reach::Blocked(by),
            (Some(by), false) => Reach::Unknown(format!(
                "{by} drops some of these connections and lets others through: whether the \
                 scorer's gets through turns on where it comes from (its address, its interface \
                 or its rate)"
            )),
            (None, true) => Reach::Unknown("no way through the ruleset was found, and no rule was seen to drop it".into()),
        }
    }

    fn find(&self, table: &str, chain: &str) -> Option<usize> {
        self.index.get(&(table.to_string(), chain.to_string())).copied()
    }

    fn push_chain(&mut self, table: &str, name: &str) -> usize {
        if let Some(i) = self.find(table, name) {
            return i;
        }
        self.chains.push(Chain { table: table.to_string(), name: name.to_string(), base: None, rules: Vec::new() });
        let i = self.chains.len().saturating_sub(1);
        self.index.insert((table.to_string(), name.to_string()), i);
        i
    }
}

struct Walk<'a> {
    rs: &'a Ruleset,
    port: u16,
    steps: usize,

    stack: Vec<usize>,

    drops: usize,

    blocked: Option<String>,

    unknown: Option<String>,
}

impl Walk<'_> {
    fn unknown(&mut self, why: String) {
        if self.unknown.is_none() {
            self.unknown = Some(why);
        }
    }

    fn block(&mut self, by: String) {
        self.drops = self.drops.saturating_add(1);
        if self.blocked.is_none() {
            self.blocked = Some(by);
        }
    }

    fn label(&self, c: usize) -> String {
        self.rs
            .chains
            .get(c)
            .map_or_else(String::new, |ch| format!("{} chain {}", ch.table.trim_start_matches('*'), ch.name))
    }

    fn chain(&mut self, c: usize, input: States) -> (States, States) {
        let rs = self.rs;
        let Some(chain) = rs.chains.get(c) else {
            self.unknown("a chain the ruleset does not contain".into());
            return (States::new(), States::new());
        };
        if self.stack.contains(&c) {
            self.unknown(format!("{} jumps back into itself", self.label(c)));
            return (States::new(), States::new());
        }
        if self.stack.len() >= MAX_DEPTH {
            self.unknown(format!("jumps nest deeper than {MAX_DEPTH} chains at {}", self.label(c)));
            return (States::new(), States::new());
        }
        self.stack.push(c);
        let mut flow = Flow { live: input, ..Flow::default() };
        for rule in &chain.rules {
            if flow.live.is_empty() || self.unknown.is_some() {
                break;
            }
            self.steps = self.steps.saturating_add(1);
            if self.steps > MAX_STEPS {
                self.unknown(format!("the ruleset is too large to follow (more than {MAX_STEPS} rule visits)"));
                break;
            }
            let (hit, miss) = self.split(&chain.table, rule, std::mem::take(&mut flow.live));
            flow.live = miss;
            if !hit.is_empty() {
                self.effect(c, rule, &rule.effect, hit, &mut flow);
            }
        }
        self.stack.pop();
        let Flow { live, accepted, mut returned } = flow;
        returned.extend(live);
        (accepted, returned)
    }

    fn effect(&mut self, c: usize, rule: &Rule, eff: &Effect, hit: States, flow: &mut Flow) {
        match eff {
            Effect::Continue => flow.live.extend(hit),
            Effect::Accept => flow.accepted.extend(hit),
            Effect::Drop => {
                let by = format!("`{}` in {}", rule.text, self.label(c));
                self.block(by);
            }
            Effect::Return => flow.returned.extend(hit),
            Effect::Jump(target) | Effect::Goto(target) => {
                let table = self.rs.chains.get(c).map(|ch| ch.table.clone()).unwrap_or_default();
                match self.rs.find(&table, target) {
                    Some(t) => {
                        let (a, r) = self.chain(t, hit);
                        flow.accepted.extend(a);

                        if matches!(eff, Effect::Jump(_)) {
                            flow.live.extend(r);
                        } else {
                            flow.returned.extend(r);
                        }
                    }
                    None => self.unknown(format!(
                        "`{}` in {} goes to chain `{target}`, which the ruleset does not contain",
                        rule.text,
                        self.label(c)
                    )),
                }
            }
            Effect::PortMap(entries) => match entries.iter().find(|(keys, _)| in_ranges(keys, self.port)) {
                Some((_, e)) => self.effect(c, rule, e, hit, flow),
                None => flow.live.extend(hit),
            },
            Effect::IfaceMap(entries) => {
                let mut rest = hit;
                for (names, e) in entries {
                    let (on, off) = split_iface(&rest, names, false);
                    rest = off;
                    if !on.is_empty() {
                        self.effect(c, rule, e, on, flow);
                    }
                }
                flow.live.extend(rest);
            }
            Effect::Unknown(why) => {
                let msg = format!("`{}` in {}: {why}", rule.text, self.label(c));
                self.unknown(msg);
            }
        }
    }

    fn split(&self, table: &str, rule: &Rule, states: States) -> (States, States) {
        let mut hit = states;
        let mut miss = States::new();
        for cond in &rule.conds {
            if hit.is_empty() {
                break;
            }
            let (on, off) = match cond {
                Cond::Always => (hit, States::new()),
                Cond::Never => (States::new(), hit),
                Cond::Maybe => (hit.clone(), hit),
                Cond::Port(p) => match self.port_hit(table, p) {
                    Some(true) => (hit, States::new()),
                    Some(false) => (States::new(), hit),
                    None => (hit.clone(), hit),
                },
                Cond::Iface { names, negated } => split_iface(&hit, names, *negated),
            };
            hit = on;
            miss.extend(off);
        }
        (hit, miss)
    }

    fn port_hit(&self, table: &str, p: &Ports) -> Option<bool> {
        match p {
            Ports::Ranges { ranges, negated } => Some(in_ranges(ranges, self.port) != *negated),
            Ports::Named { name, negated } => {
                let set = self.rs.sets.get(&(table.to_string(), name.clone()))?.as_ref()?;
                Some(in_ranges(set, self.port) != *negated)
            }
            Ports::Either { ranges, negated } => in_ranges(ranges, self.port).then_some(!*negated),
        }
    }
}

fn in_ranges(ranges: &[(u16, u16)], port: u16) -> bool {
    ranges.iter().any(|&(lo, hi)| lo <= port && port <= hi)
}

fn split_iface(states: &States, names: &[String], negated: bool) -> (States, States) {
    let mut on = States::new();
    let mut off = States::new();
    for st in states {
        match st {
            Ifc::Is(n) => {
                if names.contains(n) {
                    on.insert(st.clone());
                } else {
                    off.insert(st.clone());
                }
            }
            Ifc::Not(seen) => {
                for x in names {
                    if !seen.contains(x) {
                        on.insert(Ifc::Is(x.clone()));
                    }
                }
                let mut more = seen.clone();
                for x in names {
                    if more.len() < MAX_IFACES {
                        more.insert(x.clone());
                    }
                }
                off.insert(Ifc::Not(more));
            }
        }
    }
    if negated {
        (off, on)
    } else {
        (on, off)
    }
}

fn shown(text: &str) -> String {
    let t = text.trim();
    if t.chars().count() > 160 {
        let mut s: String = t.chars().take(157).collect();
        s.push_str("...");
        s
    } else {
        t.to_string()
    }
}

fn brace_delta(line: &str) -> i64 {
    let (mut d, mut quoted, mut escaped) = (0i64, false, false);
    for c in line.chars() {
        if quoted {
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                quoted = false;
            }
            continue;
        }
        match c {
            '"' => quoted = true,
            '{' => d = d.saturating_add(1),
            '}' => d = d.saturating_sub(1),
            _ => {}
        }
    }
    d
}

fn port_num(w: &str) -> Option<u16> {
    let w = w.trim();
    if let Some(hex) = w.strip_prefix("0x") {
        return u16::from_str_radix(hex, 16).ok();
    }
    if let Ok(p) = w.parse::<u16>() {
        return Some(p);
    }
    Some(match w {
        "ftp-data" => 20,
        "ftp" => 21,
        "ssh" => 22,
        "telnet" => 23,
        "smtp" => 25,
        "domain" => 53,
        "http" | "www" | "www-http" => 80,
        "pop3" => 110,
        "sunrpc" => 111,
        "imap" | "imap2" => 143,
        "ldap" => 389,
        "https" => 443,
        "microsoft-ds" => 445,
        "submission" => 587,
        "ldaps" => 636,
        "imaps" => 993,
        "pop3s" => 995,
        "ms-sql-s" => 1433,
        "mysql" => 3306,
        "ms-wbt-server" => 3389,
        "postgresql" => 5432,
        "wsman" => 5985,
        "wsmans" => 5986,
        "ircd" => 6667,
        "http-alt" | "webcache" => 8080,
        _ => return None,
    })
}

fn port_range(w: &str, sep: char) -> Option<(u16, u16)> {
    match w.split_once(sep) {
        Some((a, b)) => {
            let lo = if a.is_empty() { 0 } else { port_num(a)? };
            let hi = if b.is_empty() { u16::MAX } else { port_num(b)? };
            (lo <= hi).then_some((lo, hi))
        }
        None => port_num(w).map(|p| (p, p)),
    }
}

fn port_ranges<'w>(words: impl IntoIterator<Item = &'w str>, sep: char) -> Option<Vec<(u16, u16)>> {
    words.into_iter().map(|w| port_range(w, sep)).collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Addr {

    Any,
    Loopback,
    Multicast,
    Broadcast,

    Some,
}

fn addr_class(w: &str) -> Addr {
    let (ip, len) = match w.split_once('/') {
        Some((a, l)) => match l.parse::<u8>() {
            Ok(l) if l <= 32 => (a, l),
            _ => return Addr::Some,
        },
        None => (w, 32),
    };
    let Ok(ip) = ip.parse::<std::net::Ipv4Addr>() else { return Addr::Some };
    if len == 0 {
        return Addr::Any;
    }
    let o = ip.octets();
    if len >= 8 && o.first() == Some(&127) {
        Addr::Loopback
    } else if len >= 4 && o.first().is_some_and(|f| (224..=239).contains(f)) {
        Addr::Multicast
    } else if len == 32 && ip == std::net::Ipv4Addr::BROADCAST {
        Addr::Broadcast
    } else {
        Addr::Some
    }
}

fn is_tcp(w: &str) -> bool {
    let n = match w.strip_prefix("0x") {
        Some(hex) => u8::from_str_radix(hex, 16).ok(),
        None => w.parse::<u8>().ok(),
    };
    w.eq_ignore_ascii_case("tcp") || n == Some(6)
}

fn flag_bits<'w>(words: impl IntoIterator<Item = &'w str>) -> Option<u8> {
    let mut bits = 0u8;
    for w in words {
        for part in w.split('|').filter(|p| !p.is_empty()) {
            bits |= match part.to_ascii_lowercase().as_str() {
                "fin" => 0x01,
                "syn" => 0x02,
                "rst" => 0x04,
                "psh" => 0x08,
                "ack" => 0x10,
                "urg" => 0x20,
                "ecn" | "ece" => 0x40,
                "cwr" => 0x80,
                "all" => 0x3f,
                "none" => 0,
                p => match p.strip_prefix("0x") {
                    Some(hex) => u8::from_str_radix(hex, 16).ok()?,
                    None => p.parse::<u8>().ok()?,
                },
            };
        }
    }
    Some(bits)
}

fn definite(holds: Option<bool>, negated: bool) -> Cond {
    match holds.map(|h| h != negated) {
        Some(true) => Cond::Always,
        Some(false) => Cond::Never,
        None => Cond::Maybe,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Tok {

    W(String),

    Q(String),
    Open,
    Close,
    LPar,
    RPar,
    Comma,
}

fn tokens(s: &str) -> Vec<Tok> {
    fn flush(word: &mut String, out: &mut Vec<Tok>) {
        if !word.is_empty() {
            out.push(Tok::W(std::mem::take(word)));
        }
    }
    let mut out = Vec::new();
    let mut word = String::new();
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        match c {
            '"' => {
                flush(&mut word, &mut out);
                let mut q = String::new();
                while let Some(c) = chars.next() {
                    match c {
                        '\\' => q.extend(chars.next()),
                        '"' => break,
                        c => q.push(c),
                    }
                }
                out.push(Tok::Q(q));
            }
            c if c.is_whitespace() || c == ';' => flush(&mut word, &mut out),
            '{' | '}' | '(' | ')' | ',' => {
                flush(&mut word, &mut out);
                out.push(match c {
                    '{' => Tok::Open,
                    '}' => Tok::Close,
                    '(' => Tok::LPar,
                    ')' => Tok::RPar,
                    _ => Tok::Comma,
                });
            }
            c => word.push(c),
        }
    }
    flush(&mut word, &mut out);
    out
}

fn word(toks: &[Tok], i: usize) -> Option<&str> {
    match toks.get(i) {
        Some(Tok::W(w)) => Some(w.as_str()),
        _ => None,
    }
}

fn text_at(toks: &[Tok], i: usize) -> Option<&str> {
    match toks.get(i) {
        Some(Tok::W(w) | Tok::Q(w)) => Some(w.as_str()),
        _ => None,
    }
}

fn skip(toks: &[Tok], i: usize) -> usize {
    let (open, close) = match toks.get(i) {
        Some(Tok::Open) => (Tok::Open, Tok::Close),
        Some(Tok::LPar) => (Tok::LPar, Tok::RPar),
        _ => return i.saturating_add(1),
    };
    let mut depth = 0usize;
    let mut j = i;
    while let Some(t) = toks.get(j) {
        if *t == open {
            depth = depth.saturating_add(1);
        } else if *t == close {
            depth = depth.saturating_sub(1);
            if depth == 0 {
                return j.saturating_add(1);
            }
        }
        j = j.saturating_add(1);
    }
    j
}

fn group(toks: &[Tok], i: usize) -> Option<(Vec<Vec<Tok>>, usize)> {
    if toks.get(i) != Some(&Tok::Open) {
        return None;
    }
    let end = skip(toks, i);
    let inner = toks.get(i.saturating_add(1)..end.saturating_sub(1)).unwrap_or(&[]);
    let mut items: Vec<Vec<Tok>> = vec![Vec::new()];
    let mut depth = 0usize;
    for t in inner {
        match t {
            Tok::Open | Tok::LPar => depth = depth.saturating_add(1),
            Tok::Close | Tok::RPar => depth = depth.saturating_sub(1),
            Tok::Comma if depth == 0 => {
                items.push(Vec::new());
                continue;
            }
            _ => {}
        }
        if let Some(last) = items.last_mut() {
            last.push(t.clone());
        }
    }
    items.retain(|it| !it.is_empty());
    Some((items, end))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Sel {

    DPort,

    TcpFlags,

    NotOurs,

    L4,

    NfProto,

    EtherType,
    IpVersion,
    Saddr,
    Daddr,

    Iif,
    PktType,
    CtState,
    CtStatus,
    CtDirection,

    FibDaddrType,

    Other,
}

fn selector(toks: &[Tok], i: usize) -> Option<(Sel, usize)> {
    let w = word(toks, i)?;
    let one = i.saturating_add(1);
    let two = i.saturating_add(2);
    let next = word(toks, one);
    Some(match w {
        "tcp" => match next? {
            "dport" => (Sel::DPort, two),
            "flags" => (Sel::TcpFlags, two),
            "option" => return None,
            _ => (Sel::Other, two),
        },
        "th" => match next? {
            "dport" => (Sel::DPort, two),
            _ => (Sel::Other, two),
        },
        "udp" | "udplite" | "sctp" | "dccp" | "icmp" | "icmpv6" | "igmp" | "ah" | "esp" | "comp" | "gre" | "arp"
        | "ip6" | "hbh" | "frag" | "dst" | "mh" | "srh" | "exthdr" | "vxlan" | "geneve" | "gretap" => {
            (Sel::NotOurs, two)
        }

        "rt" => match next? {
            "classid" | "nexthop" | "mtu" | "ipsec" => (Sel::Other, two),
            _ => (Sel::NotOurs, two),
        },
        "ip" => match next? {
            "protocol" => (Sel::L4, two),
            "saddr" => (Sel::Saddr, two),
            "daddr" => (Sel::Daddr, two),
            "version" => (Sel::IpVersion, two),
            "option" => return None,
            _ => (Sel::Other, two),
        },
        "ether" => match next? {
            "type" => (Sel::EtherType, two),
            _ => (Sel::Other, two),
        },
        "vlan" => (Sel::Other, two),
        "meta" => match next? {
            "l4proto" => (Sel::L4, two),
            "nfproto" => (Sel::NfProto, two),
            "protocol" => (Sel::EtherType, two),
            "iif" | "iifname" => (Sel::Iif, two),
            "pkttype" => (Sel::PktType, two),
            _ => (Sel::Other, two),
        },
        "iif" | "iifname" => (Sel::Iif, one),
        "pkttype" => (Sel::PktType, one),
        "oif" | "oifname" | "iiftype" | "oiftype" | "mark" | "skuid" | "skgid" | "rtclassid" | "ibrname" | "obrname"
        | "ibriport" | "obriport" | "iifgroup" | "oifgroup" | "cpu" | "cgroup" | "ibrpvid" | "ibrvproto" => {
            (Sel::Other, one)
        }
        "ct" => match next? {
            "state" => (Sel::CtState, two),
            "status" => (Sel::CtStatus, two),
            "direction" => (Sel::CtDirection, two),
            "l3proto" => (Sel::NfProto, two),
            "protocol" => (Sel::L4, two),
            "original" | "reply" => match word(toks, two)? {
                "ip" | "ip6" => (Sel::Other, i.saturating_add(4)),
                _ => (Sel::Other, i.saturating_add(3)),
            },
            _ => (Sel::Other, two),
        },
        "fib" => {

            let mut j = one;
            let mut flags = Vec::new();
            while let Some(f) = word(toks, j).filter(|f| matches!(*f, "saddr" | "daddr" | "mark" | "iif" | "oif")) {
                flags.push(f);
                j = j.saturating_add(1);
                if word(toks, j) == Some(".") {
                    j = j.saturating_add(1);
                } else {
                    break;
                }
            }
            let result = word(toks, j)?;
            if !matches!(result, "type" | "oif" | "oifname") || flags.is_empty() {
                return None;
            }
            let sel = if flags == ["daddr"] && result == "type" { Sel::FibDaddrType } else { Sel::Other };
            (sel, j.saturating_add(1))
        }
        "socket" => match next? {
            "cgroupv2" => (Sel::Other, i.saturating_add(4)),
            _ => (Sel::Other, two),
        },
        "osf" => match next? {
            "name" | "version" => (Sel::Other, two),
            _ => return None,
        },
        _ => return None,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Op {

    Eq,
    Ne,
    Lt,
    Gt,
    Le,
    Ge,
}

fn op_of(w: &str) -> Option<Op> {
    Some(match w {
        "==" | "eq" => Op::Eq,
        "!=" | "ne" => Op::Ne,
        "<" | "lt" => Op::Lt,
        ">" | "gt" => Op::Gt,
        "<=" | "le" => Op::Le,
        ">=" | "ge" => Op::Ge,
        _ => return None,
    })
}

#[derive(Debug, Clone)]
enum Value {

    Words { words: Vec<String>, concat: bool },

    Set(Vec<Vec<Tok>>),

    Named(String),

    Paren(Vec<String>),
}

impl Value {

    fn words(&self) -> Option<Vec<String>> {
        match self {
            Value::Words { words, concat: false } => Some(words.clone()),
            Value::Set(items) => items
                .iter()
                .map(|it| match it.as_slice() {
                    [Tok::W(w) | Tok::Q(w)] => Some(w.clone()),
                    _ => None,
                })
                .collect(),
            _ => None,
        }
    }
}

fn value(toks: &[Tok], i: usize) -> Option<(Value, usize)> {
    match toks.get(i)? {
        Tok::Open => {
            let (items, end) = group(toks, i)?;
            Some((Value::Set(items), end))
        }
        Tok::LPar => {
            let end = skip(toks, i);
            let inner = toks.get(i.saturating_add(1)..end.saturating_sub(1)).unwrap_or(&[]);
            let words = inner
                .iter()
                .filter_map(|t| match t {
                    Tok::W(w) if w != "|" => Some(w.clone()),
                    _ => None,
                })
                .collect();
            Some((Value::Paren(words), end))
        }
        Tok::W(w) if w.starts_with('@') => Some((Value::Named(w.trim_start_matches('@').to_string()), i.saturating_add(1))),
        Tok::W(w) | Tok::Q(w) => {
            let mut words = vec![w.clone()];
            let mut concat = false;
            let mut j = i.saturating_add(1);
            loop {
                let joiner = match toks.get(j) {
                    Some(Tok::Comma) => true,
                    Some(Tok::W(d)) if d == "|" => true,
                    Some(Tok::W(d)) if d == "." => {
                        concat = true;
                        true
                    }
                    _ => false,
                };
                match (joiner, text_at(toks, j.saturating_add(1))) {
                    (true, Some(n)) => {
                        words.push(n.to_string());
                        j = j.saturating_add(2);
                    }
                    _ => break,
                }
            }
            Some((Value::Words { words, concat }, j))
        }
        _ => None,
    }
}

enum Expr {
    Cond(Cond),

    Stmt,

    Map(Effect),
}

fn nft_expr(toks: &[Tok], i: usize) -> Option<(Expr, usize)> {
    let w = word(toks, i)?;
    let one = i.saturating_add(1);
    match w {
        "counter" => {
            let mut j = one;
            while word(toks, j).is_some_and(|k| matches!(k, "packets" | "bytes" | "name")) {
                j = j.saturating_add(2);
            }
            Some((Expr::Stmt, j))
        }
        "log" => {
            let mut j = one;
            loop {
                match word(toks, j) {
                    Some("prefix" | "level" | "group" | "snaplen" | "queue-threshold") => j = j.saturating_add(2),
                    Some("flags") => {
                        j = j.saturating_add(1);
                        while word(toks, j).is_some_and(|f| matches!(f, "all" | "tcp" | "ip" | "skuid" | "ether" | "sequence" | "options"))
                            || toks.get(j) == Some(&Tok::Comma)
                        {
                            j = j.saturating_add(1);
                        }
                    }
                    _ => break,
                }
            }
            Some((Expr::Stmt, j))
        }
        "comment" => Some((Expr::Stmt, i.saturating_add(2))),

        "limit" | "quota" => {
            let mut j = one;
            while let Some(k) = word(toks, j) {
                let rate_word = k.contains('/')
                    || k.parse::<u64>().is_ok()
                    || matches!(k, "rate" | "over" | "until" | "burst" | "packets" | "bytes" | "kbytes" | "mbytes" | "used");
                if !rate_word {
                    break;
                }
                j = j.saturating_add(1);
            }
            Some((Expr::Cond(Cond::Maybe), j))
        }
        "meter" => {
            let mut j = one;
            while toks.get(j).is_some_and(|t| *t != Tok::Open) {
                j = j.saturating_add(1);
            }
            Some((Expr::Cond(Cond::Maybe), skip(toks, j)))
        }

        "add" | "update" | "delete" if word(toks, one).is_some_and(|n| n.starts_with('@')) => {
            let at = i.saturating_add(2);
            let end = skip(toks, at);
            let element = toks.get(at..end).unwrap_or(&[]);
            let stateful = element.iter().any(|t| matches!(t, Tok::W(w) if matches!(w.as_str(), "limit" | "quota" | "count" | "over")));
            Some((if stateful { Expr::Cond(Cond::Maybe) } else { Expr::Stmt }, end))
        }
        "xt" if word(toks, one) == Some("match") => Some((Expr::Cond(Cond::Maybe), i.saturating_add(3))),
        "meta" | "ct" if word(toks, i.saturating_add(2)) == Some("set") => {

            let key = word(toks, one)?;
            let harmless = match w {
                "meta" => matches!(key, "mark" | "nftrace" | "priority" | "secmark"),
                _ => matches!(key, "mark" | "helper" | "zone" | "label" | "event" | "timeout" | "expectation" | "secmark"),
            };
            if !harmless {
                return None;
            }
            let v = i.saturating_add(3);
            let end = match word(toks, v) {
                Some("meta" | "ct") => v.saturating_add(2),
                _ => skip(toks, v),
            };
            Some((Expr::Stmt, end))
        }
        _ => nft_match(toks, i),
    }
}

fn nft_match(toks: &[Tok], i: usize) -> Option<(Expr, usize)> {
    let (first, mut j) = selector(toks, i)?;
    let mut sels = vec![first];
    while word(toks, j) == Some(".") {
        let (s, k) = selector(toks, j.saturating_add(1))?;
        sels.push(s);
        j = k;
    }

    if sels.contains(&Sel::NotOurs) {
        return Some((Expr::Cond(Cond::Never), toks.len()));
    }
    if word(toks, j) == Some("vmap") {
        let effect = match sels.as_slice() {
            [sel] => vmap(*sel, toks, j.saturating_add(1))?,
            _ => Effect::Unknown("a verdict map on more than one field".into()),
        };
        return Some((Expr::Map(effect), toks.len()));
    }
    if word(toks, j) == Some("map") {
        return None;
    }

    let mut mask_op: Option<Value> = None;
    let mut other_bitwise = false;
    if word(toks, j).is_some_and(|b| matches!(b, "&" | "|" | "^" | "<<" | ">>")) {
        other_bitwise = word(toks, j) != Some("&");
        let (operand, k) = value(toks, j.saturating_add(1))?;
        j = k;
        mask_op = Some(operand);
    }
    let op = word(toks, j).and_then(op_of);
    if op.is_some() {
        j = j.saturating_add(1);
    }
    let (val, k) = value(toks, j)?;
    j = k;
    let mut slash: Option<Value> = None;
    if word(toks, j) == Some("/") {
        let (m, k) = value(toks, j.saturating_add(1))?;
        slash = Some(m);
        j = k;
    }
    let cond = match sels.as_slice() {
        [sel] if !other_bitwise => judge(*sel, op, mask_op.as_ref(), &val, slash.as_ref()),
        _ => Cond::Maybe,
    };
    Some((Expr::Cond(cond), j))
}

fn judge(sel: Sel, op: Option<Op>, mask: Option<&Value>, val: &Value, slash: Option<&Value>) -> Cond {
    if sel == Sel::TcpFlags {
        return tcp_flags(op, mask, val, slash);
    }
    if mask.is_some() || slash.is_some() {
        return Cond::Maybe;
    }
    let negated = op == Some(Op::Ne);
    if sel == Sel::DPort {
        return dport(op.unwrap_or(Op::Eq), val);
    }
    if !matches!(op, None | Some(Op::Eq | Op::Ne)) {
        return Cond::Maybe;
    }
    if sel == Sel::Iif {
        return match val.words() {
            Some(names) if names.iter().all(|n| !n.contains('*') && !n.is_empty() && n.parse::<u32>().is_err()) => {
                Cond::Iface { names, negated }
            }
            _ => Cond::Maybe,
        };
    }
    let Some(words) = val.words() else { return Cond::Maybe };
    let any = |f: fn(&str) -> bool| words.iter().any(|w| f(w));
    let all = |f: fn(&str) -> bool| words.iter().all(|w| f(w));
    let holds = match sel {
        Sel::L4 => Some(any(is_tcp)),
        Sel::NfProto => {
            if any(|w| w == "ipv4") {
                Some(true)
            } else if all(|w| w == "ipv6") {
                Some(false)
            } else {
                None
            }
        }
        Sel::EtherType => {
            if any(|w| matches!(w, "ip" | "0x0800")) {
                Some(true)
            } else if all(|w| matches!(w, "ip6" | "arp" | "0x86dd" | "0x0806")) {
                Some(false)
            } else {
                None
            }
        }
        Sel::IpVersion => Some(any(|w| w == "4")),
        Sel::Saddr => {
            let classes: Vec<Addr> = words.iter().map(|w| addr_class(w)).collect();
            if classes.contains(&Addr::Any) {
                Some(true)
            } else if classes.iter().all(|c| *c == Addr::Loopback) {
                Some(false)
            } else {
                None
            }
        }
        Sel::Daddr => {
            let classes: Vec<Addr> = words.iter().map(|w| addr_class(w)).collect();
            if classes.contains(&Addr::Any) {
                Some(true)
            } else if classes.iter().all(|c| matches!(c, Addr::Loopback | Addr::Multicast | Addr::Broadcast)) {
                Some(false)
            } else {
                None
            }
        }
        Sel::PktType => {
            if any(|w| matches!(w, "host" | "unicast")) {
                Some(true)
            } else if all(|w| matches!(w, "broadcast" | "multicast" | "other")) {
                Some(false)
            } else {
                None
            }
        }
        Sel::CtState => {
            if all(|w| matches!(w, "new" | "established" | "related" | "invalid" | "untracked")) {
                Some(any(|w| w == "new"))
            } else {
                None
            }
        }

        Sel::CtStatus => {
            if all(|w| matches!(w, "dnat" | "snat" | "expected" | "seen-reply" | "assured")) {
                Some(false)
            } else {
                None
            }
        }
        Sel::CtDirection => {
            if all(|w| w == "original") {
                Some(true)
            } else if all(|w| w == "reply") {
                Some(false)
            } else {
                None
            }
        }

        Sel::FibDaddrType => {
            if any(|w| w == "local") {
                Some(true)
            } else if all(|w| {
                matches!(
                    w,
                    "unicast" | "broadcast" | "anycast" | "multicast" | "blackhole" | "unreachable" | "prohibit" | "throw"
                        | "nat" | "xresolve" | "unspec"
                )
            }) {
                Some(false)
            } else {
                None
            }
        }
        Sel::DPort | Sel::TcpFlags | Sel::Iif | Sel::NotOurs | Sel::Other => None,
    };
    definite(holds, negated)
}

fn dport(op: Op, val: &Value) -> Cond {
    let negated = op == Op::Ne;
    if let Value::Named(name) = val {
        return match op {
            Op::Eq | Op::Ne => Cond::Port(Ports::Named { name: name.clone(), negated }),
            _ => Cond::Maybe,
        };
    }
    let Some(words) = val.words() else { return Cond::Maybe };
    let ranges = match op {
        Op::Eq | Op::Ne => port_ranges(words.iter().map(String::as_str), '-'),
        _ => match words.as_slice() {
            [w] => port_num(w).and_then(|p| match op {
                Op::Lt => p.checked_sub(1).map(|h| vec![(0, h)]).or(Some(Vec::new())),
                Op::Le => Some(vec![(0, p)]),
                Op::Gt => p.checked_add(1).map(|l| vec![(l, u16::MAX)]).or(Some(Vec::new())),
                Op::Ge => Some(vec![(p, u16::MAX)]),
                Op::Eq | Op::Ne => None,
            }),
            _ => None,
        },
    };
    match ranges {
        Some(ranges) => Cond::Port(Ports::Ranges { ranges, negated }),
        None => Cond::Maybe,
    }
}

fn tcp_flags(op: Option<Op>, mask: Option<&Value>, val: &Value, slash: Option<&Value>) -> Cond {
    let words_of = |v: &Value| -> Option<Vec<String>> {
        match v {
            Value::Paren(words) => Some(words.clone()),
            other => other.words(),
        }
    };
    let Some(want) = words_of(val).and_then(|w| flag_bits(w.iter().map(String::as_str))) else { return Cond::Maybe };
    let negated = op == Some(Op::Ne);
    let masked = match (mask, slash) {
        (Some(m), None) | (None, Some(m)) => {
            match words_of(m).and_then(|w| flag_bits(w.iter().map(String::as_str))) {
                Some(b) => Some(PROBE_FLAGS & b),
                None => return Cond::Maybe,
            }
        }
        (Some(_), Some(_)) => return Cond::Maybe,
        (None, None) => None,
    };
    let holds = match (masked, op) {
        (Some(m), Some(Op::Eq | Op::Ne) | None) => Some(m == want),
        (None, Some(Op::Eq | Op::Ne)) => Some(PROBE_FLAGS == want),

        (None, None) if want.count_ones() == 1 => Some((PROBE_FLAGS & want) != 0),
        _ => None,
    };
    definite(holds, negated)
}

fn vmap(sel: Sel, toks: &[Tok], i: usize) -> Option<Effect> {
    if word(toks, i).is_some_and(|w| w.starts_with('@')) {
        return Some(Effect::Unknown("a named verdict map, not read".into()));
    }
    let (items, _) = group(toks, i)?;
    let mut entries: Vec<(Value, Effect)> = Vec::new();
    for it in &items {
        let colon = it.iter().position(|t| matches!(t, Tok::W(w) if w == ":"));
        let (key, verdict) = match colon {
            Some(c) => (it.get(..c).unwrap_or(&[]), it.get(c.saturating_add(1)..).unwrap_or(&[])),
            None => return Some(Effect::Unknown("a verdict map this does not read".into())),
        };
        let key = match key {
            [Tok::W(w) | Tok::Q(w)] => Value::Words { words: vec![w.clone()], concat: false },
            [Tok::Open, ..] => match group(key, 0) {
                Some((g, _)) => Value::Set(g),
                None => return Some(Effect::Unknown("a verdict map this does not read".into())),
            },
            _ => return Some(Effect::Unknown("a verdict map this does not read".into())),
        };
        let effect = match nft_verdict(verdict, 0) {
            Some(e) => e,
            None => Effect::Unknown("a verdict map entry this does not read".into()),
        };
        entries.push((key, effect));
    }
    Some(match sel {
        Sel::DPort => {
            let mut map = Vec::new();
            for (key, effect) in entries {
                match key.words().and_then(|w| port_ranges(w.iter().map(String::as_str), '-')) {
                    Some(r) => map.push((r, effect)),
                    None => return Some(Effect::Unknown("a port verdict map with a key this does not read".into())),
                }
            }
            Effect::PortMap(map)
        }
        Sel::Iif => {
            let mut map = Vec::new();
            for (key, effect) in entries {
                match key.words().filter(|n| n.iter().all(|n| !n.contains('*'))) {
                    Some(names) => map.push((names, effect)),
                    None => return Some(Effect::Unknown("an interface verdict map with a key this does not read".into())),
                }
            }
            Effect::IfaceMap(map)
        }
        Sel::L4 | Sel::NfProto | Sel::EtherType | Sel::IpVersion | Sel::PktType | Sel::CtState | Sel::CtDirection => {

            for (key, effect) in entries {
                match judge(sel, None, None, &key, None) {
                    Cond::Always => return Some(effect),
                    Cond::Never => {}
                    _ => return Some(Effect::Unknown("a verdict map this cannot settle".into())),
                }
            }
            Effect::Continue
        }
        _ => Effect::Unknown("a verdict map keyed on something the scorer's packet does not settle".into()),
    })
}

fn nft_verdict(toks: &[Tok], i: usize) -> Option<Effect> {
    Some(match word(toks, i)? {
        "accept" => Effect::Accept,
        "drop" | "reject" => Effect::Drop,
        "continue" => Effect::Continue,
        "return" => Effect::Return,
        "jump" => Effect::Jump(text_at(toks, i.saturating_add(1))?.to_string()),
        "goto" => Effect::Goto(text_at(toks, i.saturating_add(1))?.to_string()),
        "queue" => Effect::Unknown("hands it to a userspace program (queue)".into()),
        "dnat" | "redirect" => Effect::Unknown("rewrites its destination, so it may not reach this port".into()),

        "snat" | "masquerade" => Effect::Accept,
        "notrack" => Effect::Unknown("switches connection tracking off for it (notrack)".into()),
        "tproxy" | "fwd" | "synproxy" => Effect::Unknown("sends it somewhere this does not follow".into()),
        "xt" if word(toks, i.saturating_add(1)) == Some("target") => {
            Effect::Unknown("an iptables target nft cannot show".into())
        }
        _ => return None,
    })
}

fn nft_rule(text: &str) -> Rule {
    let toks = tokens(text);
    let mut conds = Vec::new();
    let mut unread: Option<String> = None;
    let mut i = 0usize;
    while let Some(t) = toks.get(i) {
        if let Some(effect) = nft_verdict(&toks, i) {
            if unread.is_some() {
                conds.push(Cond::Maybe);
            }
            return Rule { text: shown(text), conds, effect };
        }
        if unread.is_some() {

            i = skip(&toks, i);
            continue;
        }
        match nft_expr(&toks, i) {
            Some((Expr::Cond(c), next)) => {
                let never = matches!(c, Cond::Never);
                conds.push(c);
                if never {
                    return Rule { text: shown(text), conds, effect: Effect::Continue };
                }
                i = next;
            }
            Some((Expr::Stmt, next)) => i = next,
            Some((Expr::Map(effect), _)) => return Rule { text: shown(text), conds, effect },
            None => {
                unread = Some(match t {
                    Tok::W(w) | Tok::Q(w) => w.clone(),
                    _ => "a bracket".into(),
                });
                i = skip(&toks, i);
            }
        }
    }
    let effect = match unread {
        Some(w) => Effect::Unknown(format!("a rule this does not read (at `{w}`)")),
        None => Effect::Continue,
    };
    Rule { text: shown(text), conds, effect }
}

fn hook_line(line: &str) -> (Option<String>, Option<Vec<String>>, Option<bool>) {
    let toks = tokens(line);
    let (mut hook, mut devices, mut policy) = (None, None, None);
    let mut i = 0usize;
    while let Some(t) = toks.get(i) {
        let next = i.saturating_add(1);
        match t {
            Tok::W(w) if w == "hook" => hook = word(&toks, next).map(str::to_string),
            Tok::W(w) if w == "device" => devices = text_at(&toks, next).map(|d| vec![d.to_string()]),
            Tok::W(w) if w == "devices" => {
                let at = if word(&toks, next) == Some("=") { next.saturating_add(1) } else { next };
                devices = group(&toks, at).map(|(items, _)| {
                    items
                        .iter()
                        .filter_map(|it| match it.as_slice() {
                            [Tok::W(d) | Tok::Q(d)] => Some(d.clone()),
                            _ => None,
                        })
                        .collect()
                });
            }
            Tok::W(w) if w == "policy" => {
                policy = match word(&toks, next) {
                    Some("accept") => Some(true),
                    Some("drop") => Some(false),
                    _ => None,
                }
            }
            _ => {}
        }
        i = next;
    }
    (hook, devices, policy)
}

pub(crate) fn parse_nft(text: &str) -> Ruleset {
    enum Block {
        None,
        Chain(usize),
        Set(String),
        Other,
    }
    let mut rs = Ruleset::default();
    let mut table = String::new();
    let mut dormant: HashSet<String> = HashSet::new();

    let mut hooks: Vec<(usize, String)> = Vec::new();
    let mut block = Block::None;
    let mut set_buf = String::new();
    let mut pending: Option<String> = None;
    let mut depth = 0i64;

    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || (line.starts_with('#') && pending.is_none()) {
            continue;
        }
        let before = depth;
        depth = depth.saturating_add(brace_delta(line));

        if let Some(mut r) = pending.take() {
            r.push(' ');
            r.push_str(line);
            if depth > 2 {
                pending = Some(r);
            } else if let Block::Chain(c) = &block {
                if let Some(ch) = rs.chains.get_mut(*c) {
                    ch.rules.push(nft_rule(&r));
                }
            }
        } else {
            let toks: Vec<&str> = line.split_whitespace().collect();
            let first = toks.first().copied().unwrap_or("");
            match before {
                0 => {
                    if first == "table" {
                        let family = toks.get(1).copied().unwrap_or("");
                        let name = toks.get(2).copied().unwrap_or("").trim_end_matches('{').trim_matches('"');
                        table = format!("{family} {name}");
                    }
                }
                1 => {
                    block = match first {
                        "chain" => {
                            let name = toks.get(1).copied().unwrap_or("").trim_end_matches('{').trim_matches('"');
                            let c = rs.push_chain(&table, name);
                            if line.contains(" hook ") {
                                hooks.push((c, line.to_string()));
                            }
                            Block::Chain(c)
                        }
                        "set" | "map" => {
                            set_buf.clear();
                            set_buf.push_str(line);
                            Block::Set(toks.get(1).copied().unwrap_or("").trim_matches('"').to_string())
                        }
                        "flags" => {
                            if line.contains("dormant") {
                                dormant.insert(table.clone());
                            }
                            Block::None
                        }
                        _ => Block::Other,
                    };
                }
                _ => match &block {
                    Block::Chain(c) if before == 2 => {
                        let c = *c;
                        match first {
                            "}" | "comment" => {}
                            "type" | "policy" => hooks.push((c, line.to_string())),
                            _ if depth > 2 => pending = Some(line.to_string()),
                            _ => {
                                if let Some(ch) = rs.chains.get_mut(c) {
                                    ch.rules.push(nft_rule(line));
                                }
                            }
                        }
                    }
                    Block::Set(_) => {
                        set_buf.push(' ');
                        set_buf.push_str(line);
                    }
                    _ => {}
                },
            }
        }
        if depth <= 1 {
            if let Block::Set(name) = &block {
                let elements = set_elements(&set_buf);
                rs.sets.insert((table.clone(), name.clone()), elements);
            }
            if before >= 2 || !matches!(block, Block::Chain(_)) || depth < 1 {
                block = Block::None;
            }
        }
        if depth <= 0 {
            depth = 0;
            table.clear();
            block = Block::None;
        }
    }
    if pending.is_some() || depth != 0 {
        rs.broken = Some("the ruleset text ends inside a block: it is incomplete, so none of it is relied on".into());
    }

    let mut bases: Vec<(u8, usize)> = Vec::new();
    for (c, line) in hooks {
        let (hook, devices, policy) = hook_line(&line);
        let Some(ch) = rs.chains.get_mut(c) else { continue };
        let fam = ch.table.split_whitespace().next().unwrap_or("").to_string();
        match hook {
            Some(hook) => {
                let place = match (fam.as_str(), hook.as_str()) {
                    ("inet" | "netdev", "ingress") => Some((0, false)),
                    ("ip" | "inet", "prerouting") => Some((1, false)),
                    ("ip" | "inet", "input") => Some((2, false)),
                    ("bridge", "prerouting") => Some((1, true)),
                    ("bridge", "input") => Some((2, true)),
                    _ => None,
                };
                if dormant.contains(&ch.table) {
                    continue;
                }
                if let Some((rank, bridged)) = place {
                    let devices = match (hook.as_str(), devices) {
                        ("ingress", Some(d)) if !d.is_empty() => Devices::Only(d),
                        ("ingress", _) => Devices::Unread,
                        _ => Devices::All,
                    };
                    let label = format!("{} chain {} ({hook} hook)", ch.table, ch.name);
                    let prior = ch.base.as_ref().and_then(|b| b.policy);
                    ch.base = Some(Base { policy: policy.or(prior), devices, bridged, label });
                    bases.push((rank, c));
                }
            }

            None => {
                if let Some(b) = ch.base.as_mut() {
                    b.policy = b.policy.or(policy);
                }
            }
        }
    }
    bases.sort_by_key(|&(rank, _)| rank);
    bases.dedup_by_key(|&mut (_, c)| c);
    rs.bases = bases.into_iter().map(|(_, c)| c).collect();
    rs
}

fn set_elements(block: &str) -> Option<Vec<(u16, u16)>> {
    let toks = tokens(block);
    let at = toks.iter().position(|t| matches!(t, Tok::W(w) if w == "elements"))?;
    let open = toks.iter().skip(at).position(|t| *t == Tok::Open)?.saturating_add(at);
    let (items, _) = group(&toks, open)?;
    let words: Option<Vec<String>> = items
        .iter()
        .map(|it| match it.as_slice() {
            [Tok::W(w)] => Some(w.clone()),
            _ => None,
        })
        .collect();
    port_ranges(words?.iter().map(String::as_str), '-')
}

const IPT_BASES: &[(&str, &str)] = &[
    ("*raw", "PREROUTING"),
    ("*mangle", "PREROUTING"),
    ("*nat", "PREROUTING"),
    ("*mangle", "INPUT"),
    ("*filter", "INPUT"),
    ("*security", "INPUT"),
    ("*nat", "INPUT"),
];

const IPT_PLAIN_MODULES: &[&str] = &["tcp", "udp", "udplite", "multiport", "state", "conntrack", "comment", "addrtype", "pkttype", "icmp"];

fn ipt_words(line: &str) -> Vec<(String, bool)> {
    let mut out = Vec::new();
    let mut word = String::new();
    let mut chars = line.chars();
    while let Some(c) = chars.next() {
        match c {
            '"' => {
                if !word.is_empty() {
                    out.push((std::mem::take(&mut word), false));
                }
                let mut q = String::new();
                while let Some(c) = chars.next() {
                    match c {
                        '\\' => q.extend(chars.next()),
                        '"' => break,
                        c => q.push(c),
                    }
                }
                out.push((q, true));
            }
            c if c.is_whitespace() => {
                if !word.is_empty() {
                    out.push((std::mem::take(&mut word), false));
                }
            }
            c => word.push(c),
        }
    }
    if !word.is_empty() {
        out.push((word, false));
    }
    out
}

fn ipt_rule(line: &str, user_chains: &HashSet<String>) -> Rule {
    let words = ipt_words(line);
    let limited_iface = words.iter().any(|(w, q)| !q && w.starts_with("--limit-iface"));
    let plain = |i: usize| -> Option<&str> { words.get(i).filter(|(_, q)| !q).map(|(w, _)| w.as_str()) };
    let any = |i: usize| -> Option<&str> { words.get(i).map(|(w, _)| w.as_str()) };
    let mut conds = Vec::new();
    let mut effect = Effect::Continue;
    let mut neg = false;

    let mut i = words.iter().position(|(w, q)| !q && w == "-A").map_or(0, |a| a.saturating_add(2));
    while let Some((w, quoted)) = words.get(i) {
        let w = w.as_str();
        i = i.saturating_add(1);
        if *quoted {
            conds.push(Cond::Maybe);
            neg = false;
            continue;
        }
        if w == "!" {
            neg = true;
            continue;
        }
        match w {
            "-p" | "--protocol" => {
                let v = any(i).unwrap_or("");
                i = i.saturating_add(1);
                conds.push(definite(Some(is_tcp(v) || matches!(v, "all" | "0")), neg));
            }
            "-s" | "--source" | "--src" => {
                let v = any(i).unwrap_or("");
                i = i.saturating_add(1);
                let classes: Vec<Addr> = v.split(',').map(addr_class).collect();
                let holds = if classes.contains(&Addr::Any) {
                    Some(true)
                } else if classes.iter().all(|c| *c == Addr::Loopback) {
                    Some(false)
                } else {
                    None
                };
                conds.push(definite(holds, neg));
            }
            "-d" | "--destination" | "--dst" => {
                let v = any(i).unwrap_or("");
                i = i.saturating_add(1);
                let classes: Vec<Addr> = v.split(',').map(addr_class).collect();
                let holds = if classes.contains(&Addr::Any) {
                    Some(true)
                } else if classes.iter().all(|c| matches!(c, Addr::Loopback | Addr::Multicast | Addr::Broadcast)) {
                    Some(false)
                } else {
                    None
                };
                conds.push(definite(holds, neg));
            }
            "-i" | "--in-interface" => {
                let v = any(i).unwrap_or("").to_string();
                i = i.saturating_add(1);
                conds.push(if v.is_empty() || v.ends_with('+') {
                    Cond::Maybe
                } else {
                    Cond::Iface { names: vec![v], negated: neg }
                });
            }
            "-o" | "--out-interface" => {
                i = i.saturating_add(1);
                conds.push(Cond::Maybe);
            }
            "-f" | "--fragment" => conds.push(definite(Some(false), neg)),
            "-m" | "--match" => {
                let m = any(i).unwrap_or("");
                i = i.saturating_add(1);
                if !IPT_PLAIN_MODULES.contains(&m) {
                    conds.push(Cond::Maybe);
                }
            }
            "-j" | "--jump" => {
                let target = any(i).unwrap_or("");
                let opts: Vec<&str> = words.iter().skip(i.saturating_add(1)).map(|(w, _)| w.as_str()).collect();
                effect = ipt_target(target, &opts, user_chains);
                break;
            }
            "-g" | "--goto" => {
                effect = match any(i) {
                    Some(t) if user_chains.contains(t) => Effect::Goto(t.to_string()),
                    Some(t) => Effect::Unknown(format!("a goto to `{t}`, which the ruleset does not contain")),
                    None => Effect::Unknown("a goto with no chain".into()),
                };
                break;
            }
            "-c" | "--set-counters" => i = i.saturating_add(2),
            o if o.starts_with("--") => {
                let mut vals: Vec<&str> = Vec::new();
                while let Some(v) = plain(i).filter(|v| !v.starts_with('-') && *v != "!").or_else(|| {

                    words.get(i).filter(|(_, q)| *q).map(|(v, _)| v.as_str())
                }) {
                    vals.push(v);
                    i = i.saturating_add(1);
                }
                if let Some(c) = ipt_option(o, &vals, neg, limited_iface) {
                    conds.push(c);
                }
            }
            _ => conds.push(Cond::Maybe),
        }
        neg = false;
    }
    Rule { text: shown(line), conds, effect }
}

fn ipt_option(o: &str, vals: &[&str], neg: bool, limited_iface: bool) -> Option<Cond> {
    let first = vals.first().copied().unwrap_or("");
    let list = || first.split(',').filter(|w| !w.is_empty());
    Some(match o {
        "--dport" | "--destination-port" | "--dports" | "--destination-ports" | "--ctorigdstport" => {
            match port_ranges(list(), ':') {
                Some(ranges) if !first.is_empty() => Cond::Port(Ports::Ranges { ranges, negated: neg }),
                _ => Cond::Maybe,
            }
        }
        "--ports" => match port_ranges(list(), ':') {
            Some(ranges) if !first.is_empty() => Cond::Port(Ports::Either { ranges, negated: neg }),
            _ => Cond::Maybe,
        },
        "--state" | "--ctstate" => {
            let words: Vec<String> = list().map(str::to_ascii_lowercase).collect();

            if !words.is_empty()
                && words.iter().all(|w| {
                    matches!(w.as_str(), "new" | "established" | "related" | "invalid" | "untracked" | "snat" | "dnat")
                })
            {
                definite(Some(words.iter().any(|w| w == "new")), neg)
            } else {
                Cond::Maybe
            }
        }
        "--ctproto" => definite(Some(is_tcp(first)), neg),
        "--ctstatus" => {
            let words: Vec<String> = list().map(str::to_ascii_lowercase).collect();
            if !words.is_empty() && words.iter().all(|w| matches!(w.as_str(), "expected" | "seen_reply" | "assured")) {
                definite(Some(false), neg)
            } else {
                Cond::Maybe
            }
        }
        "--dst-type" if !limited_iface => {
            let words: Vec<String> = list().map(str::to_ascii_uppercase).collect();
            if words.iter().any(|w| w == "LOCAL") {
                definite(Some(true), neg)
            } else if !words.is_empty()
                && words.iter().all(|w| {
                    matches!(
                        w.as_str(),
                        "UNICAST" | "BROADCAST" | "ANYCAST" | "MULTICAST" | "BLACKHOLE" | "UNREACHABLE" | "PROHIBIT" | "THROW" | "NAT" | "XRESOLVE" | "UNSPEC"
                    )
                })
            {
                definite(Some(false), neg)
            } else {
                Cond::Maybe
            }
        }
        "--src-type" if !limited_iface => {
            let words: Vec<String> = list().map(str::to_ascii_uppercase).collect();
            if words.iter().any(|w| w == "UNICAST") {
                definite(Some(true), neg)
            } else if !words.is_empty() && words.iter().all(|w| matches!(w.as_str(), "LOCAL" | "BROADCAST" | "MULTICAST" | "ANYCAST")) {
                definite(Some(false), neg)
            } else {
                Cond::Maybe
            }
        }
        "--limit-iface-in" | "--limit-iface-out" | "--comment" => return None,
        "--pkt-type" => match first.to_ascii_lowercase().as_str() {
            "unicast" | "host" => definite(Some(true), neg),
            "broadcast" | "multicast" | "other" => definite(Some(false), neg),
            _ => Cond::Maybe,
        },
        "--tcp-flags" => match vals {
            [mask, comp] => match (flag_bits(mask.split(',')), flag_bits(comp.split(','))) {
                (Some(m), Some(c)) => definite(Some((PROBE_FLAGS & m) == c), neg),
                _ => Cond::Maybe,
            },
            _ => Cond::Maybe,
        },

        "--syn" => definite(Some(true), neg),
        _ => Cond::Maybe,
    })
}

fn ipt_target(t: &str, opts: &[&str], user_chains: &HashSet<String>) -> Effect {
    match t {
        "ACCEPT" => Effect::Accept,
        "DROP" | "REJECT" => Effect::Drop,
        "RETURN" => Effect::Return,
        "QUEUE" | "NFQUEUE" => Effect::Unknown(format!("hands it to a userspace program (-j {t})")),
        _ if user_chains.contains(t) => Effect::Jump(t.to_string()),
        "LOG" | "NFLOG" | "ULOG" | "MARK" | "CONNMARK" | "SECMARK" | "CONNSECMARK" | "CLASSIFY" | "DSCP" | "TOS" | "TTL"
        | "HL" | "TCPMSS" | "TCPOPTSTRIP" | "CHECKSUM" | "AUDIT" | "TRACE" | "IDLETIMER" | "LED" | "RATEEST" | "SET"
        | "TEE" | "HMARK" | "ECN" => Effect::Continue,
        "CT" if !opts.contains(&"--notrack") => Effect::Continue,
        "CT" | "NOTRACK" => Effect::Unknown("switches connection tracking off for it (notrack)".into()),
        "DNAT" | "REDIRECT" | "NETMAP" => {
            Effect::Unknown(format!("rewrites its destination (-j {t}), so it may not reach this port"))
        }
        "SNAT" | "MASQUERADE" => Effect::Accept,
        "" => Effect::Unknown("a jump with no target".into()),
        _ => Effect::Unknown(format!("-j {t}, a target this does not read")),
    }
}

pub(crate) fn parse_iptables(text: &str) -> Ruleset {
    let mut rs = Ruleset::default();

    let mut table = "*filter".to_string();
    let mut policies: HashMap<(String, String), Option<bool>> = HashMap::new();
    let mut user: HashMap<String, HashSet<String>> = HashMap::new();
    let mut lines: Vec<(String, String, String)> = Vec::new();

    let mut open = false;
    for raw in text.lines() {
        let l = raw.trim();
        if l == "COMMIT" {
            open = false;
            continue;
        }
        if l.is_empty() || l.starts_with('#') {
            continue;
        }
        if l.starts_with('*') {
            table = l.split_whitespace().next().unwrap_or(l).to_string();
            open = true;
            continue;
        }
        if let Some(decl) = l.strip_prefix(':') {
            let mut it = decl.split_whitespace();
            let name = it.next().unwrap_or("").to_string();
            let policy = match it.next() {
                Some("ACCEPT") => Some(true),
                Some("DROP") => Some(false),
                _ => None,
            };
            user.entry(table.clone()).or_default().insert(name.clone());
            policies.insert((table.clone(), name.clone()), policy);
            rs.push_chain(&table, &name);
            continue;
        }

        let l = match l.strip_prefix('[') {
            Some(rest) => rest.split_once(']').map_or(l, |(_, r)| r.trim()),
            None => l,
        };
        if let Some(rest) = l.strip_prefix("-A ") {
            let chain = rest.split_whitespace().next().unwrap_or("").to_string();
            user.entry(table.clone()).or_default().insert(chain.clone());
            rs.push_chain(&table, &chain);
            lines.push((table.clone(), chain, l.to_string()));
        }
    }
    if open {
        rs.broken = Some("the iptables-save text ends inside a table: it is incomplete, so none of it is relied on".into());
    }
    let empty = HashSet::new();
    for (t, chain, line) in lines {
        let rule = ipt_rule(&line, user.get(&t).unwrap_or(&empty));
        if let Some(c) = rs.find(&t, &chain).and_then(|c| rs.chains.get_mut(c)) {
            c.rules.push(rule);
        }
    }
    for (t, chain) in IPT_BASES {
        let Some(c) = rs.find(t, chain) else { continue };
        let policy = policies.get(&((*t).to_string(), (*chain).to_string())).copied().flatten();
        if let Some(ch) = rs.chains.get_mut(c) {
            let label = format!("{} chain {}", t.trim_start_matches('*'), chain);
            ch.base = Some(Base { policy, devices: Devices::All, bridged: false, label });
            rs.bases.push(c);
        }
    }
    rs
}
