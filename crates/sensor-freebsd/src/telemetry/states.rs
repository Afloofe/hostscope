use std::net::IpAddr;

use super::filterlog::{proto, Dir};

pub const MAX_STATES: usize = 2_000_000;

pub const MAX_LINE: usize = 512;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Endpoint {

    pub addr: IpAddr,

    pub port: Option<u16>,
}

impl core::fmt::Display for Endpoint {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match (self.addr, self.port) {
            (IpAddr::V4(a), Some(p)) => write!(f, "{a}:{p}"),
            (IpAddr::V6(a), Some(p)) => write!(f, "[{a}]:{p}"),
            (a, None) => write!(f, "{a}"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct State {

    pub iface: String,

    pub proto: Option<u8>,

    pub proto_name: String,

    pub dir: Dir,

    pub src: Endpoint,

    pub src_orig: Option<Endpoint>,

    pub dst: Endpoint,

    pub dst_orig: Option<Endpoint>,

    pub state: String,

    pub age: Option<u64>,

    pub expires: Option<u64>,

    pub pkts: Option<(u64, u64)>,

    pub bytes: Option<(u64, u64)>,

    pub rule: Option<u32>,

    pub origif: Option<String>,

    pub creator: Option<String>,
}

impl State {

    pub fn initiator(&self) -> Endpoint {
        self.src_orig.unwrap_or(self.src)
    }

    pub fn responder(&self) -> Endpoint {
        self.dst
    }

    pub fn sent(&self) -> Option<bool> {
        self.pkts.map(|(a, _)| a > 0)
    }

    pub fn answered(&self) -> Option<bool> {
        self.pkts.map(|(_, b)| b > 0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Table {

    pub states: Vec<State>,

    pub unread: usize,

    pub truncated: bool,
}

fn endpoint(s: &str) -> Option<Endpoint> {

    if let Some(open) = s.find('[') {
        let port = s.get(open + 1..)?.strip_suffix(']')?;
        let addr: std::net::Ipv6Addr = s.get(..open)?.parse().ok()?;
        return Some(Endpoint { addr: IpAddr::V6(addr), port: Some(port.parse().ok()?) });
    }
    if let Ok(a) = s.parse::<IpAddr>() {
        return Some(Endpoint { addr: a, port: None });
    }
    let (a, p) = s.rsplit_once(':')?;
    let addr: std::net::Ipv4Addr = a.parse().ok()?;
    Some(Endpoint { addr: IpAddr::V4(addr), port: Some(p.parse().ok()?) })
}

fn paren(s: &str) -> Option<&str> {
    s.strip_prefix('(')?.strip_suffix(')')
}

fn header(line: &str) -> Option<State> {
    let t: Vec<&str> = line.split_whitespace().collect();
    let get = |i: usize| t.get(i).copied();
    let iface = get(0)?;
    let proto_name = get(1)?;
    if iface.len() > 16 || proto_name.len() > 16 {
        return None;
    }
    let mut i = 2;
    let first = endpoint(get(i)?)?;
    i += 1;
    let first_orig = match get(i).and_then(paren) {
        Some(p) => {
            i += 1;
            Some(endpoint(p)?)
        }
        None => None,
    };
    let dir = match get(i)? {
        "->" => Dir::Out,
        "<-" => Dir::In,
        _ => return None,
    };
    i += 1;
    let second = endpoint(get(i)?)?;
    i += 1;
    let second_orig = match get(i).and_then(paren) {
        Some(p) => {
            i += 1;
            Some(endpoint(p)?)
        }
        None => None,
    };
    let state = get(i)?;
    if t.len() != i + 1 || state.len() > 32 || !state.contains(':') {
        return None;
    }
    let (src, src_orig, dst, dst_orig) = match dir {
        Dir::Out => (first, first_orig, second, second_orig),
        _ => (second, second_orig, first, first_orig),
    };
    Some(State {
        iface: iface.to_string(),
        proto: proto::parse(proto_name),
        proto_name: proto_name.to_string(),
        dir,
        src,
        src_orig,
        dst,
        dst_orig,
        state: state.to_string(),
        age: None,
        expires: None,
        pkts: None,
        bytes: None,
        rule: None,
        origif: None,
        creator: None,
    })
}

fn hms(s: &str) -> Option<u64> {
    let mut it = s.split(':');
    let h: u64 = it.next()?.parse().ok()?;
    let m: u64 = it.next()?.parse().ok()?;
    let sec: u64 = it.next()?.parse().ok()?;
    if it.next().is_some() || m > 59 || sec > 59 {
        return None;
    }
    h.checked_mul(3600)?.checked_add(m * 60 + sec)
}

fn pair(s: &str) -> Option<(u64, u64)> {
    let (a, b) = s.split_once(':')?;
    Some((a.parse().ok()?, b.parse().ok()?))
}

fn counters(s: &mut State, line: &str) {
    for part in line.split(", ") {
        if let Some(v) = part.strip_prefix("age ") {
            s.age = hms(v);
        } else if let Some(v) = part.strip_prefix("expires in ") {
            s.expires = hms(v);
        } else if let Some(v) = part.strip_suffix(" pkts") {
            s.pkts = pair(v);
        } else if let Some(v) = part.strip_suffix(" bytes") {
            s.bytes = pair(v);
        } else if let Some(v) = part.strip_prefix("rule ") {
            s.rule = v.parse().ok();
        }
    }
}

pub fn parse(text: &str) -> Table {
    let mut t = Table::default();

    let mut keeping = false;
    for line in text.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let indented = line.starts_with(' ') || line.starts_with('\t');
        if line.len() > MAX_LINE {
            if !indented {
                t.unread += 1;
                keeping = false;
            }
            continue;
        }
        if !indented {
            if t.states.len() >= MAX_STATES {
                t.truncated = true;
                break;
            }
            match header(line) {
                Some(s) => {
                    t.states.push(s);
                    keeping = true;
                }
                None => {
                    t.unread += 1;
                    keeping = false;
                }
            }
            continue;
        }
        if !keeping {
            continue;
        }
        let Some(cur) = t.states.last_mut() else { continue };
        let d = line.trim();
        if d.starts_with("age ") {
            counters(cur, d);
        } else if let Some(i) = d.strip_prefix("origif: ") {
            if i.len() <= 16 && i.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_') {
                cur.origif = Some(i.to_string());
            }
        } else if d.starts_with("id: ") {
            if let Some(c) = d.split_whitespace().skip_while(|w| *w != "creatorid:").nth(1) {
                if c.len() <= 16 && c.bytes().all(|b| b.is_ascii_hexdigit()) {
                    cur.creator = Some(c.to_ascii_lowercase());
                }
            }
        }

    }
    t
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PfRule {

    pub nr: u32,

    pub action: String,

    pub logs: bool,

    pub label: Option<String>,

    pub tracker: Option<String>,

    pub own_timeouts: bool,
}

fn rule_words(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quoted = false;
    for c in line.chars() {
        match c {
            '"' => {
                if quoted {
                    out.push(std::mem::take(&mut cur));
                }
                quoted = !quoted;
            }
            ' ' | '\t' if !quoted => {
                if !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
            }
            c => cur.push(c),
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

pub fn parse_rules(text: &str) -> Vec<PfRule> {
    let mut out = Vec::new();
    for line in text.lines() {
        let Some(rest) = line.strip_prefix('@') else { continue };
        if line.len() > 4096 {
            continue;
        }
        let w = rule_words(rest);
        let (Some(nr), Some(action)) = (w.first().and_then(|n| n.parse::<u32>().ok()), w.get(1)) else { continue };
        if !matches!(action.as_str(), "pass" | "block" | "match") {
            continue;
        }
        let after = |key: &str| w.iter().position(|x| x == key).and_then(|i| w.get(i + 1)).cloned();
        out.push(PfRule {
            nr,
            action: action.clone(),
            logs: w.iter().any(|x| x == "log"),
            label: after("label").map(|l| l.strip_prefix("USER_RULE: ").map(str::to_string).unwrap_or(l)),
            tracker: after("ridentifier").filter(|t| t.len() <= 64),
            own_timeouts: w.iter().any(|x| {
                let x = x.trim_start_matches('(');
                ["tcp.", "udp.", "icmp.", "other.", "adaptive."].iter().any(|p| x.starts_with(p))
            }),
        });
    }
    out
}
