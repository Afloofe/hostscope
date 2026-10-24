use std::collections::BTreeMap;
use std::net::IpAddr;

pub const MAX_LEASES: usize = 65_536;

pub const MAX_STRING: usize = 4096;

pub const MAX_DEPTH: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Server {

    Isc,

    Kea,
}

impl Server {

    pub fn label(self) -> &'static str {
        match self {
            Server::Isc => "isc",
            Server::Kea => "kea",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lease {

    pub addr: IpAddr,

    pub mac: Option<String>,

    pub hostname: Option<String>,

    pub active: bool,

    pub ends: Option<String>,

    pub server: Server,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Leases {

    pub leases: Vec<Lease>,

    pub unread: usize,

    pub truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Tok {
    Word(String),
    Str(String),
    Open,
    Close,
    Semi,
}

fn tokens(text: &str) -> Result<Vec<Tok>, String> {
    let b = text.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while let Some(&c) = b.get(i) {
        match c {
            b' ' | b'\t' | b'\r' | b'\n' => i += 1,
            b'#' => {
                while b.get(i).is_some_and(|c| *c != b'\n') {
                    i += 1;
                }
            }
            b'{' => {
                out.push(Tok::Open);
                i += 1;
            }
            b'}' => {
                out.push(Tok::Close);
                i += 1;
            }
            b';' => {
                out.push(Tok::Semi);
                i += 1;
            }
            b'"' => {
                i += 1;
                let mut s: Vec<u8> = Vec::new();
                loop {
                    let Some(&c) = b.get(i) else { return Err("a string that never ends".into()) };
                    i += 1;
                    match c {
                        b'"' => break,
                        b'\\' => {
                            let Some(&n) = b.get(i) else { return Err("a string that never ends".into()) };
                            if (b'0'..=b'7').contains(&n) {
                                let oct = b.get(i..i + 3).ok_or("a short octal escape")?;
                                let v = std::str::from_utf8(oct).ok().and_then(|o| u8::from_str_radix(o, 8).ok());
                                s.push(v.ok_or("a bad octal escape")?);
                                i += 3;
                            } else {
                                s.push(n);
                                i += 1;
                            }
                        }
                        c => s.push(c),
                    }
                    if s.len() > MAX_STRING {
                        return Err("a string over the cap".into());
                    }
                }
                out.push(Tok::Str(String::from_utf8_lossy(&s).into_owned()));
            }
            _ => {
                let start = i;
                while b.get(i).is_some_and(|c| !matches!(c, b' ' | b'\t' | b'\r' | b'\n' | b'{' | b'}' | b';' | b'"')) {
                    i += 1;
                }
                let w = text.get(start..i).ok_or("a word that is not text")?;
                if w.len() > MAX_STRING {
                    return Err("a word over the cap".into());
                }
                out.push(Tok::Word(w.to_string()));
            }
        }
    }
    Ok(out)
}

type Stmt = Vec<Tok>;

type Block = (Vec<Stmt>, Vec<(Stmt, Vec<Stmt>)>, usize);

fn block(t: &[Tok], mut i: usize, depth: usize) -> Result<Block, String> {
    if depth > MAX_DEPTH {
        return Err("nested deeper than is read".into());
    }
    let mut stmts = Vec::new();
    let mut nested = Vec::new();
    let mut cur: Stmt = Vec::new();
    loop {
        match t.get(i) {
            None => return Err("a block that never closes".into()),
            Some(Tok::Close) => {
                if !cur.is_empty() {
                    return Err("a statement with no `;`".into());
                }
                return Ok((stmts, nested, i + 1));
            }
            Some(Tok::Semi) => {
                stmts.push(std::mem::take(&mut cur));
                i += 1;
            }
            Some(Tok::Open) => {
                let (inner, _, next) = block(t, i + 1, depth + 1)?;
                nested.push((std::mem::take(&mut cur), inner));
                i = next;
            }
            Some(tok) => {
                cur.push(tok.clone());
                i += 1;
            }
        }
    }
}

fn word(t: &Tok) -> Option<&str> {
    match t {
        Tok::Word(w) => Some(w),
        _ => None,
    }
}

fn words(s: &Stmt) -> Vec<&str> {
    s.iter()
        .map(|t| match t {
            Tok::Word(w) | Tok::Str(w) => w.as_str(),
            _ => "",
        })
        .collect()
}

fn apply(lease: &mut Lease, stmts: &[Stmt]) {
    for s in stmts {
        match words(s).as_slice() {
            ["binding", "state", st] => lease.active = *st == "active",
            ["ends", rest @ ..] => lease.ends = Some(rest.join(" ")),
            ["hardware", "ethernet", mac] => lease.mac = Some(mac.to_ascii_lowercase()),
            ["client-hostname", name] => lease.hostname = Some((*name).to_string()),
            _ => {}
        }
    }
}

pub fn parse_isc(text: &str) -> Leases {
    let mut out = Leases::default();
    let t = match tokens(text) {
        Ok(t) => t,
        Err(_) => {
            out.unread = 1;
            return out;
        }
    };
    let mut last: BTreeMap<IpAddr, Lease> = BTreeMap::new();
    let mut i = 0;
    let mut head: Stmt = Vec::new();
    let new = |addr| Lease { addr, mac: None, hostname: None, active: false, ends: None, server: Server::Isc };
    while let Some(tok) = t.get(i) {
        match tok {
            Tok::Semi => {
                head.clear();
                i += 1;
            }
            Tok::Close => {
                out.unread += 1;
                head.clear();
                i += 1;
            }
            Tok::Open => {
                let (stmts, nested, next) = match block(&t, i + 1, 1) {
                    Ok(x) => x,
                    Err(_) => {
                        out.unread += 1;
                        break;
                    }
                };
                i = next;
                let h = std::mem::take(&mut head);
                let kind = h.first().and_then(word);
                let mut found = Vec::new();
                match (kind, h.get(1).and_then(word).and_then(|a| a.parse::<IpAddr>().ok())) {
                    (Some("lease"), Some(addr)) => {
                        let mut l = new(addr);
                        apply(&mut l, &stmts);
                        found.push(l);
                    }
                    (Some("lease"), None) => out.unread += 1,

                    (Some("ia-na" | "ia-ta" | "ia-pd"), _) => {
                        for (nh, body) in &nested {
                            let w = words(nh);
                            match (w.first(), w.get(1).and_then(|a| a.split('/').next()).and_then(|a| a.parse::<IpAddr>().ok())) {
                                (Some(&("iaaddr" | "iaprefix")), Some(addr)) => {
                                    let mut l = new(addr);
                                    apply(&mut l, body);
                                    found.push(l);
                                }
                                _ => out.unread += 1,
                            }
                        }
                    }
                    _ => {}
                }
                for l in found {
                    if last.len() >= MAX_LEASES && !last.contains_key(&l.addr) {
                        out.truncated = true;
                        continue;
                    }
                    last.insert(l.addr, l);
                }
            }
            other => {
                head.push(other.clone());
                i += 1;
            }
        }
    }
    out.leases = last.into_values().collect();
    out
}

fn kea_unescape(s: &str) -> String {
    s.replace("&#x2c", ",")
}

pub fn parse_kea(text: &str) -> Leases {
    let mut out = Leases::default();
    let mut lines = text.lines();
    let Some(header) = lines.next() else { return out };
    let cols: Vec<&str> = header.split(',').collect();
    let at = |name: &str| cols.iter().position(|c| *c == name);
    let (Some(a_at), Some(exp_at), Some(life_at), Some(st_at)) =
        (at("address"), at("expire"), at("valid_lifetime"), at("state"))
    else {
        out.unread = 1;
        return out;
    };
    let mac_at = at("hwaddr");
    let host_at = at("hostname");
    let mut last: BTreeMap<IpAddr, Lease> = BTreeMap::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        if line.len() > MAX_STRING {
            out.unread += 1;
            continue;
        }
        let f: Vec<&str> = line.split(',').collect();
        if f.len() != cols.len() {
            out.unread += 1;
            continue;
        }
        let get = |i: usize| f.get(i).copied().unwrap_or("");
        let Ok(addr) = get(a_at).parse::<IpAddr>() else {
            out.unread += 1;
            continue;
        };
        let life: u64 = get(life_at).parse().unwrap_or(0);
        let nonempty = |i: Option<usize>| i.map(get).filter(|s| !s.is_empty()).map(kea_unescape);
        let lease = Lease {
            addr,
            mac: nonempty(mac_at).map(|m| m.to_ascii_lowercase()),
            hostname: nonempty(host_at),
            active: get(st_at) == "0" && life > 0,
            ends: Some(get(exp_at).to_string()).filter(|s| !s.is_empty()),
            server: Server::Kea,
        };
        if last.len() >= MAX_LEASES && !last.contains_key(&addr) {
            out.truncated = true;
            continue;
        }
        last.insert(addr, lease);
    }
    out.leases = last.into_values().collect();
    out
}
