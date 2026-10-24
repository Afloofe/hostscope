use std::net::IpAddr;

use crate::libxo::{self, Value};

pub const MAX_ENTRIES: usize = 65_536;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Neighbour {

    pub addr: IpAddr,

    pub mac: Option<String>,

    pub iface: String,

    pub permanent: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Table {

    pub entries: Vec<Neighbour>,

    pub unread: usize,
}

fn mac(s: &str) -> Option<String> {
    let parts: Vec<&str> = s.split(':').collect();
    let ok = parts.len() == 6 && parts.iter().all(|p| (1..=2).contains(&p.len()) && p.bytes().all(|b| b.is_ascii_hexdigit()));
    ok.then(|| parts.iter().map(|p| format!("{:0>2}", p.to_ascii_lowercase())).collect::<Vec<_>>().join(":"))
}

fn table(json: &str, top: &str, list: &str, addr_key: &str) -> Result<Table, String> {
    let doc = libxo::parse(json)?;
    let items = match doc.get(top).and_then(|t| t.get(list)) {
        Some(Value::Array(a)) => a.as_slice(),

        None if doc.get(top).is_some() => &[],
        _ => return Err(format!("{top}: no {list} in the document")),
    };
    let mut t = Table::default();
    for e in items.iter().take(MAX_ENTRIES) {
        let addr = e
            .get(addr_key)
            .and_then(Value::as_str)
            .map(|a| a.split('%').next().unwrap_or(a))
            .and_then(|a| a.parse::<IpAddr>().ok());
        let iface = e.get("interface").and_then(Value::as_str).filter(|i| i.len() <= 16);
        match (addr, iface) {
            (Some(addr), Some(iface)) => t.entries.push(Neighbour {
                addr,
                mac: e.get("mac-address").and_then(Value::as_str).and_then(mac),
                iface: iface.to_string(),
                permanent: matches!(e.get("permanent"), Some(Value::Bool(true))),
            }),
            _ => t.unread += 1,
        }
    }
    t.unread += items.len().saturating_sub(MAX_ENTRIES);
    Ok(t)
}

pub fn parse_arp(json: &str) -> Result<Table, String> {
    table(json, "arp", "arp-cache", "ip-address")
}

pub fn parse_ndp(json: &str) -> Result<Table, String> {
    table(json, "ndp", "neighbor-cache", "address")
}
