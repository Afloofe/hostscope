use std::collections::BTreeMap;

use crate::libxo::{self, Value};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcBinary {

    pub pid: u32,

    pub command: String,

    pub path: Option<String>,

    pub nameless: bool,
}

pub fn binaries(json: &str) -> Result<Vec<ProcBinary>, String> {
    let doc = libxo::parse(json)?;
    let table = section(&doc, "binary")?;
    let mut out = Vec::new();
    for (key, p) in table {
        if p.as_object().is_some_and(|m| m.is_empty()) {
            let pid = key.parse::<u32>().map_err(|_| format!("procstat -ab: an empty entry keyed {key:?}"))?;
            out.push(ProcBinary { pid, command: String::new(), path: None, nameless: true });
            continue;
        }
        let pid = pid_of(key, p)?;
        let command = p.get("command").and_then(Value::as_str).unwrap_or("").to_string();
        let path = match p.get("pathname").and_then(Value::as_str) {
            None => return Err(format!("procstat -ab: pid {pid} has no pathname field")),
            Some("-" | "") => None,
            Some(s) => Some(s.to_string()),
        };
        out.push(ProcBinary { pid, command, path, nameless: false });
    }
    out.sort_by_key(|p| p.pid);
    Ok(out)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcBasic {

    pub pid: u32,

    pub ppid: u32,

    pub command: String,
}

pub fn basics(json: &str) -> Result<BTreeMap<u32, ProcBasic>, String> {
    let doc = libxo::parse(json)?;
    let table = section(&doc, "basic")?;
    let mut out = BTreeMap::new();
    for (key, p) in table {
        let pid = pid_of(key, p)?;
        let ppid = p
            .get("parent_process_id")
            .and_then(Value::as_u64)
            .and_then(|n| u32::try_from(n).ok())
            .ok_or_else(|| format!("procstat -a: pid {pid} has no parent_process_id"))?;
        let command = p.get("command").and_then(Value::as_str).unwrap_or("").to_string();
        out.insert(pid, ProcBasic { pid, ppid, command });
    }
    Ok(out)
}

fn section<'a>(doc: &'a Value, name: &str) -> Result<&'a BTreeMap<String, Value>, String> {
    doc.get("procstat")
        .and_then(|p| p.get(name))
        .and_then(Value::as_object)
        .ok_or_else(|| format!("procstat: no \"procstat\".\"{name}\" object in the document"))
}

fn pid_of(key: &str, p: &Value) -> Result<u32, String> {
    let pid = p
        .get("process_id")
        .and_then(Value::as_u64)
        .and_then(|n| u32::try_from(n).ok())
        .ok_or_else(|| format!("procstat: entry {key:?} has no process_id"))?;

    if key != pid.to_string() {
        return Err(format!("procstat: entry {key:?} carries pid {pid}"));
    }
    Ok(pid)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TextVnode {

    pub pid: u32,

    pub mount: String,

    pub inum: u64,

    pub size: u64,
}

pub fn fstat_text(text: &str) -> (BTreeMap<u32, TextVnode>, usize) {
    let mut out = BTreeMap::new();
    let mut unread = 0;
    for line in text.lines() {
        let t: Vec<&str> = line.split_whitespace().collect();
        let Some(i) = t.iter().enumerate().skip(2).find_map(|(i, w)| (*w == "text").then_some(i)) else {
            continue;
        };
        let pid = t.get(i - 1).and_then(|p| p.parse::<u32>().ok());
        let n = t.len();
        let row = (|| {
            let pid = pid?;
            if n < i + 6 {
                return None;
            }
            let inum = t.get(n - 4)?.parse().ok()?;
            let size = t.get(n - 2)?.parse().ok()?;
            let mount = t.get(i + 1..n - 4)?.join(" ");
            Some(TextVnode { pid, mount, inum, size })
        })();
        match row {
            Some(r) => {
                out.insert(r.pid, r);
            }
            None if pid.is_some() => unread += 1,
            None => {}
        }
    }
    (out, unread)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Socket {

    pub user: String,

    pub command: String,

    pub pid: Option<u32>,

    pub proto: String,

    pub local: String,

    pub foreign: String,
}

impl Socket {

    pub fn local_port(&self) -> Option<&str> {
        self.local.rsplit_once(':').map(|(_, p)| p).filter(|p| *p != "*" && !p.is_empty())
    }

    pub fn is_listener(&self) -> bool {
        self.foreign == "*:*" && self.local_port().is_some()
    }
}

pub fn sockstat(text: &str) -> Result<(Vec<Socket>, usize), String> {
    let mut lines = text.lines();
    let header = lines.next().unwrap_or("");
    if !header.starts_with("USER") || !header.contains("LOCAL ADDRESS") {
        return Err("sockstat: the header line is not the one sockstat prints".into());
    }
    let mut out = Vec::new();
    let mut unread = 0;
    for line in lines {
        let t: Vec<&str> = line.split_whitespace().collect();
        let n = t.len();
        if n == 0 {
            continue;
        }
        if n < 7 {
            unread += 1;
            continue;
        }
        let get = |i: usize| t.get(i).copied().unwrap_or("");
        let pid = match get(n - 5) {
            "?" => None,
            p => match p.parse::<u32>() {
                Ok(p) => Some(p),
                Err(_) => {
                    unread += 1;
                    continue;
                }
            },
        };
        out.push(Socket {
            user: get(0).to_string(),
            command: t.get(1..n - 5).map(|c| c.join(" ")).unwrap_or_default(),
            pid,
            proto: get(n - 3).to_string(),
            local: get(n - 2).to_string(),
            foreign: get(n - 1).to_string(),
        });
    }
    Ok((out, unread))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Kld {

    pub id: u32,

    pub name: String,

    pub path: Option<String>,
}

pub fn kldstat(text: &str) -> Result<(Vec<Kld>, usize), String> {
    let mut lines = text.lines();
    let header = lines.next().unwrap_or("");
    if !header.split_whitespace().take(3).eq(["Id", "Refs", "Address"]) {
        return Err("kldstat: the header line is not the one kldstat prints".into());
    }
    let mut out = Vec::new();
    let mut unread = 0;
    for line in lines {

        if line.starts_with('\t') || line.trim().is_empty() {
            continue;
        }
        let t: Vec<&str> = line.split_whitespace().collect();
        let is_file = t.get(2).is_some_and(|a| a.starts_with("0x"));
        let row = (|| {
            if !is_file {
                return None;
            }
            let id = t.first()?.parse().ok()?;
            let name = (*t.get(4)?).to_string();
            let rest = line.split_once(&format!(" {name}")).map(|(_, r)| r.trim()).unwrap_or("");
            let path = rest
                .strip_prefix('(')
                .and_then(|r| r.strip_suffix(')'))
                .filter(|p| !p.is_empty())
                .map(str::to_string);
            Some(Kld { id, name, path })
        })();
        match row {
            Some(k) => out.push(k),
            None => unread += 1,
        }
    }
    Ok((out, unread))
}

pub fn pidfile(bytes: &[u8]) -> Option<u32> {
    let text = std::str::from_utf8(bytes).ok()?;
    let pid: u32 = text.split_whitespace().next()?.parse().ok()?;
    (pid > 0).then_some(pid)
}
