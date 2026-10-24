use std::collections::BTreeMap;
use std::net::IpAddr;

use crate::libxo::{self, Value};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proc {

    pub ppid: u32,

    pub comm: String,
}

pub const KINFO_PROC_SIZE: usize = 1088;

const KI_PID: usize = 72;

const KI_PPID: usize = 76;

const KI_COMM: usize = 447;
const COMMLEN: usize = 20;

pub const MAX_ENTRIES: usize = 200_000;

fn le_u32(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(at..at + 4)?.try_into().ok()?))
}

pub fn kinfo_procs(b: &[u8]) -> Result<BTreeMap<u32, Proc>, String> {
    if b.is_empty() {
        return Err("sysctl kern.proc.all printed nothing".into());
    }
    if !b.len().is_multiple_of(KINFO_PROC_SIZE) {
        return Err(format!("sysctl kern.proc.all: {} bytes, not a whole number of {KINFO_PROC_SIZE}-byte kinfo_proc records", b.len()));
    }
    let mut out = BTreeMap::new();
    for (i, rec) in b.as_chunks::<KINFO_PROC_SIZE>().0.iter().enumerate().take(MAX_ENTRIES) {
        let size = le_u32(rec, 0).unwrap_or(0) as usize;
        if size != KINFO_PROC_SIZE {
            return Err(format!("sysctl kern.proc.all: record {i} says it is {size} bytes, not {KINFO_PROC_SIZE}: another kernel's layout"));
        }
        let pid = le_u32(rec, KI_PID).ok_or("a short kinfo_proc")?;
        let ppid = le_u32(rec, KI_PPID).ok_or("a short kinfo_proc")?;
        let comm = rec.get(KI_COMM..KI_COMM + COMMLEN).unwrap_or_default();
        let comm = comm.split(|&c| c == 0).next().unwrap_or_default();
        out.entry(pid).or_insert_with(|| Proc { ppid, comm: String::from_utf8_lossy(comm).into_owned() });
    }
    Ok(out)
}

pub fn ps(text: &str) -> (BTreeMap<u32, Proc>, usize) {
    let mut out = BTreeMap::new();
    let mut unread = 0;
    for line in text.lines().take(MAX_ENTRIES) {
        if line.trim().is_empty() {
            continue;
        }
        let mut it = line.split_whitespace();
        let row = (|| {
            let pid = it.next()?.parse::<u32>().ok()?;
            let ppid = it.next()?.parse::<u32>().ok()?;
            let _state = it.next()?;
            let comm = it.collect::<Vec<_>>().join(" ");
            Some((pid, Proc { ppid, comm }))
        })();
        match row {
            Some((pid, p)) => {
                out.insert(pid, p);
            }
            None => unread += 1,
        }
    }
    (out, unread)
}

pub fn procstat_basic(json: &str) -> Result<BTreeMap<u32, Proc>, String> {
    Ok(crate::posture::parse::basics(json)?
        .into_iter()
        .map(|(pid, b)| (pid, Proc { ppid: b.ppid, comm: b.command }))
        .collect())
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Sock {

    pub proto: String,

    pub laddr: String,

    pub lport: String,

    pub faddr: String,

    pub fport: String,

    pub state: String,
}

impl Sock {

    pub fn is_listener(&self) -> bool {
        if self.lport == "*" || self.lport.is_empty() {
            return false;
        }
        if self.proto.starts_with("tcp") {
            self.state == "LISTEN"
        } else {
            self.proto.starts_with("udp") && self.faddr == "*"
        }
    }

    pub fn key(&self) -> String {
        format!("{} {}:{}", self.proto, self.laddr, self.lport)
    }
}

fn split_end(s: &str, sep: char) -> Option<(String, String)> {
    let (a, p) = s.rsplit_once(sep)?;
    let a = a.strip_prefix('[').and_then(|x| x.strip_suffix(']')).unwrap_or(a);
    Some((a.to_ascii_lowercase(), p.to_string()))
}

pub fn netstat(text: &str) -> Result<(Vec<Sock>, usize), String> {
    let mut lines = text.lines();
    if !lines.next().is_some_and(|l| l.starts_with("Active Internet connections")) {
        return Err("netstat: the first line is not the one netstat -an prints".into());
    }
    let mut out = Vec::new();
    let mut unread = 0;
    for line in lines.take(MAX_ENTRIES) {
        if line.starts_with("Active ") {
            break;
        }
        let t: Vec<&str> = line.split_whitespace().collect();
        let Some(proto) = t.first() else { continue };
        if *proto == "Proto" {
            continue;
        }
        if !(proto.starts_with("tcp") || proto.starts_with("udp")) {

            continue;
        }
        let row = (|| {
            let (laddr, lport) = split_end(t.get(3)?, '.')?;
            let (faddr, fport) = split_end(t.get(4)?, '.').or_else(|| (*t.get(4)? == "*.*").then(|| ("*".into(), "*".into())))?;
            let state = t.get(5).map_or(String::new(), |s| (*s).to_string());
            Some(Sock { proto: (*proto).to_string(), laddr, lport, faddr, fport, state })
        })();
        match row {
            Some(s) => out.push(s),
            None => unread += 1,
        }
    }
    Ok((out, unread))
}

pub fn sockstat(text: &str) -> Result<(Vec<Sock>, usize), String> {
    let (rows, mut unread) = crate::posture::parse::sockstat(text)?;
    let mut out = Vec::new();
    for r in rows {
        let (Some((laddr, lport)), Some((faddr, fport))) = (split_end(&r.local, ':'), split_end(&r.foreign, ':')) else {
            unread += 1;
            continue;
        };
        let state = if r.proto.starts_with("tcp") {
            if faddr == "*" { "LISTEN" } else { "ESTABLISHED" }
        } else {
            ""
        };
        out.push(Sock { proto: r.proto, laddr, lport, faddr, fport, state: state.to_string() });
    }
    Ok((out, unread))
}

pub fn ifconfig_addrs(text: &str) -> Vec<IpAddr> {
    let mut v: Vec<IpAddr> = text
        .lines()
        .filter_map(|l| {
            let mut t = l.split_whitespace();
            let fam = t.next()?;
            if fam != "inet" && fam != "inet6" {
                return None;
            }
            let a = t.next()?;
            a.split('%').next()?.parse().ok()
        })
        .collect();
    v.sort();
    v.dedup();
    v
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Environ {

    pub command: String,

    pub vars: Vec<String>,
}

pub fn environments(json: &str) -> Result<BTreeMap<u32, Environ>, String> {
    let doc = libxo::parse(json)?;
    let table = doc
        .get("procstat")
        .and_then(|p| p.get("environment"))
        .and_then(Value::as_object)
        .ok_or("procstat -ae: no \"procstat\".\"environment\" object in the document")?;
    let mut out = BTreeMap::new();
    for (key, p) in table {
        let pid = p
            .get("process_id")
            .and_then(Value::as_u64)
            .and_then(|n| u32::try_from(n).ok())
            .ok_or_else(|| format!("procstat -ae: entry {key:?} has no process_id"))?;
        if key != &pid.to_string() {
            return Err(format!("procstat -ae: entry {key:?} carries pid {pid}"));
        }
        let command = p.get("command").and_then(Value::as_str).unwrap_or("").to_string();
        let vars = match p.get("environment") {
            None => Vec::new(),
            Some(Value::Array(a)) => a.iter().filter_map(Value::as_str).map(str::to_string).collect(),
            Some(_) => return Err(format!("procstat -ae: pid {pid}'s environment is not a list")),
        };
        out.insert(pid, Environ { command, vars });
    }
    Ok(out)
}

pub fn sysctl_e(text: &str) -> BTreeMap<String, String> {
    text.lines()
        .filter_map(|l| l.split_once('='))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect()
}

pub fn kld_modules(text: &str) -> Vec<String> {
    let mut v = Vec::new();
    for line in text.lines() {
        if !line.starts_with("\t\t") {
            continue;
        }
        let mut t = line.split_whitespace();
        if t.next().is_some_and(|id| id.parse::<u32>().is_ok()) {
            if let Some(name) = t.next() {
                v.push(name.to_string());
                if let Some((_, short)) = name.rsplit_once('/') {
                    v.push(short.to_string());
                }
            }
        }
    }
    v.sort();
    v.dedup();
    v
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LdMention {

    pub line: usize,

    pub name: String,

    pub comment: bool,

    pub text: String,
}

pub fn ld_mentions(bytes: &[u8], lines: bool) -> Vec<LdMention> {
    let mut out = Vec::new();
    let pieces: Vec<&[u8]> = if lines { bytes.split(|&b| b == b'\n').collect() } else { vec![bytes] };
    for (i, l) in pieces.iter().enumerate() {
        let mut j = 0;
        while let Some(off) = l.get(j..).and_then(|r| r.windows(3).position(|w| w == b"LD_")) {
            let at = j + off;
            let before = at.checked_sub(1).and_then(|k| l.get(k)).copied();
            let word = |c: u8| c.is_ascii_alphanumeric() || c == b'_';
            let end = l.get(at + 3..).map_or(at + 3, |r| at + 3 + r.iter().take_while(|&&c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == b'_').count());
            if !before.is_some_and(word) && end > at + 3 {
                let text = String::from_utf8_lossy(l).trim().chars().take(160).collect::<String>();
                out.push(LdMention {
                    line: if lines { i + 1 } else { 0 },
                    name: String::from_utf8_lossy(l.get(at..end).unwrap_or_default()).into_owned(),
                    comment: lines && text.starts_with('#'),
                    text: if lines { text } else { String::new() },
                });
            }
            j = end.max(at + 3);
        }
    }
    out
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LdClass {

    Inject,

    Path,

    Other,
}

pub fn ld_class(name: &str) -> LdClass {
    let n = name.strip_prefix("LD_32_").map_or(name.to_string(), |r| format!("LD_{r}"));
    match n.as_str() {
        "LD_PRELOAD" | "LD_PRELOAD_FDS" | "LD_LIBMAP" | "LD_ELF_HINTS_PATH" | "LD_LIBRARY_PATH_FDS" => LdClass::Inject,
        "LD_LIBRARY_PATH" | "LD_LIBRARY_PATH_RPATH" => LdClass::Path,
        _ => LdClass::Other,
    }
}
