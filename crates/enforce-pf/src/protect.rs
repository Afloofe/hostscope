use std::net::IpAddr;

use hemostat_broker::perimeter::Protect;
use hemostat_sensor_freebsd::configxml::Config;
use hemostat_sensor_freebsd::libxo::{self, Value};
use hemostat_sensor_freebsd::posture::parse as posture;
use hemostat_sensor_freebsd::tools::{Invocation, Runner, Tool};
use hs_core::cidr::Cidr;

use crate::preflight::text;
use crate::Enrolled;

pub const WIDEST_V4: u8 = 24;

pub const WIDEST_V6: u8 = 56;

#[derive(Debug, Clone)]
pub struct Gathered {

    pub sockets: Result<String, String>,

    pub interfaces: Result<String, String>,

    pub routes: Result<String, String>,
}

pub fn gather(r: &mut dyn Runner) -> Gathered {
    Gathered {
        sockets: text(r, Invocation::new(Tool::Sockstat, &["-46c"])),
        interfaces: text(r, Invocation::new(Tool::Netstat, &["-i", "-n", "--libxo", "json"])),
        routes: text(r, Invocation::new(Tool::Netstat, &["-rn", "--libxo", "json"])),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {

    pub range: Cidr,

    pub what: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Protected {

    pub entries: Vec<Entry>,

    pub gaps: Vec<String>,
}

impl Protected {
    fn add(&mut self, range: Cidr, what: impl Into<String>) {
        if !self.entries.iter().any(|e| e.range == range) {
            self.entries.push(Entry { range, what: what.into() });
        }
    }

    fn addr(&mut self, s: &str, what: &str) {
        if let Some(a) = parse_addr(s) {
            self.add(Cidr::host(a), what);
        }
    }
}

pub fn parse_addr(s: &str) -> Option<IpAddr> {
    let s = s.trim().trim_start_matches('[').trim_end_matches(']');
    let s = s.split_once('%').map_or(s, |(a, _)| a);
    let a: IpAddr = s.parse().ok()?;
    Some(match a {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(a, IpAddr::V4),
        v4 => v4,
    })
}

fn sock_addr(s: &str) -> Option<IpAddr> {
    let (a, _port) = s.rsplit_once(':')?;
    parse_addr(a)
}

pub fn fixed() -> Vec<Entry> {
    [
        ("127.0.0.0/8", "loopback"),
        ("::1/128", "loopback"),
        ("169.254.0.0/16", "IPv4 link-local"),
        ("fe80::/10", "IPv6 link-local"),
    ]
    .iter()
    .filter_map(|(c, w)| Cidr::parse(c).ok().map(|range| Entry { range, what: (*w).to_string() }))
    .collect()
}

fn strings_named<'a>(v: &'a Value, name: &str, out: &mut Vec<&'a str>) {
    match v {
        Value::Object(m) => {
            for (k, x) in m {
                if k == name {
                    if let Some(s) = x.as_str() {
                        out.push(s);
                    }
                }
                strings_named(x, name, out);
            }
        }
        Value::Array(a) => a.iter().for_each(|x| strings_named(x, name, out)),
        _ => {}
    }
}

fn mgmt_ports(c: Option<&Config>) -> Vec<String> {
    let mut p: Vec<String> = vec!["22".into(), "80".into(), "443".into()];
    if let Some(c) = c {
        for path in ["system/ssh/port", "system/webgui/port"] {
            if let Some(v) = c.root().text_at(path).filter(|v| !v.is_empty()) {
                p.push(v.to_string());
            }
        }
    }
    p
}

pub fn collect(
    g: &Gathered,
    config: Option<&Config>,
    resolv: &Result<String, String>,
    ssh_connection: Option<&str>,
    e: &Enrolled,
) -> Protected {
    let mut p = Protected::default();
    for f in fixed() {
        p.add(f.range, f.what);
    }

    if let Some(a) = ssh_connection.and_then(|s| s.split_whitespace().next()).and_then(parse_addr) {
        p.add(Cidr::host(a), "the management peer running this command ($SSH_CONNECTION)");
    }
    let ports = mgmt_ports(config);
    match &g.sockets {
        Ok(t) => match posture::sockstat(t) {
            Ok((socks, _)) => {
                for s in socks {
                    let local_port = s.local.rsplit_once(':').map(|(_, p)| p.to_string()).unwrap_or_default();
                    let mgmt = matches!(s.command.as_str(), "sshd" | "nginx") || ports.contains(&local_port);
                    if mgmt {
                        if let Some(a) = sock_addr(&s.foreign) {
                            let who = if s.command == "?" { format!("port {local_port}") } else { s.command.clone() };
                            p.add(Cidr::host(a), format!("a live management peer ({who}, sockstat)"));
                        }
                    }
                }
            }
            Err(why) => p.gaps.push(format!("the socket table did not read as sockstat prints it ({why})")),
        },
        Err(why) => p.gaps.push(format!("the live management peers could not be read: {why}")),
    }

    match g.interfaces.as_ref().map_err(Clone::clone).and_then(|t| libxo::parse(t)) {
        Ok(v) => {
            let mut a = Vec::new();
            strings_named(&v, "address", &mut a);
            for s in a {
                p.addr(s, "an interface address");
            }
        }
        Err(why) => p.gaps.push(format!("the interface addresses could not be read: {why}")),
    }

    match g.routes.as_ref().map_err(Clone::clone).and_then(|t| libxo::parse(t)) {
        Ok(v) => {
            let mut a = Vec::new();
            strings_named(&v, "gateway", &mut a);
            for s in a {
                p.addr(s, "a gateway in the routing table");
            }
        }
        Err(why) => p.gaps.push(format!("the routing table could not be read: {why}")),
    }

    match config {
        Some(c) => {
            if let Some(ifs) = c.root().child("interfaces") {
                for i in &ifs.children {
                    for k in ["ipaddr", "ipaddrv6"] {
                        if let Some(v) = i.text_at(k) {
                            p.addr(v, &format!("the {} interface address (config.xml)", i.name));
                        }
                    }
                }
            }
            if let Some(v) = c.root().child("virtualip") {
                for vip in v.all("vip") {
                    if let Some(s) = vip.text_at("subnet") {
                        let mode = vip.text_at("mode").unwrap_or("vip");
                        p.addr(s, &format!("a {mode} VIP (config.xml)"));
                    }
                }
            }
            if let Some(gw) = c.root().child("gateways") {
                for g in gw.all("gateway_item") {
                    if let Some(s) = g.text_at("gateway") {
                        p.addr(s, &format!("gateway {} (config.xml)", g.text_at("name").unwrap_or("?")));
                    }
                }
            }
            if let Some(sys) = c.root().child("system") {
                for d in sys.all("dnsserver") {
                    p.addr(&d.text, "a DNS server (config.xml)");
                }
            }
        }
        None => p.gaps.push("config.xml could not be read, so its interfaces, VIPs, gateways and DNS servers are unknown".into()),
    }
    match resolv {
        Ok(t) => {
            for l in t.lines() {
                let mut w = l.split_whitespace();
                if w.next() == Some("nameserver") {
                    if let Some(a) = w.next() {
                        p.addr(a, "a DNS server (/etc/resolv.conf)");
                    }
                }
            }
        }
        Err(why) => p.gaps.push(format!("/etc/resolv.conf could not be read: {why}")),
    }

    for r in &e.protect {
        p.add(*r, "an enrolled --protect range");
    }
    p
}

pub fn judge(cidr: &Cidr, p: &Protected) -> Protect {
    if cidr.is_everything() {
        return Protect::Refused(format!("{cidr} is every address: blocking it is cutting the firewall off"));
    }
    let widest = if cidr.is_v4() { WIDEST_V4 } else { WIDEST_V6 };
    if cidr.prefix() < widest {
        return Protect::Refused(format!(
            "{cidr} is wider than /{widest}. A block that wide needs dual control, which is not \
             built, so it is refused; block the narrower ranges you mean"
        ));
    }
    if !p.gaps.is_empty() {
        return Protect::Refused(format!(
            "the protect-set is incomplete, so this cannot be shown to cover no management peer, \
             interface or server: {}",
            p.gaps.join("; ")
        ));
    }
    let hits: Vec<String> = p
        .entries
        .iter()
        .filter(|e| cidr.overlaps(&e.range))
        .map(|e| format!("{} ({})", e.range, e.what))
        .collect();
    if hits.is_empty() {
        return Protect::Clear;
    }
    let more = hits.len().saturating_sub(6);
    let shown: Vec<String> = hits.into_iter().take(6).collect();
    Protect::Refused(format!(
        "{cidr} covers {}{}",
        shown.join(", "),
        if more > 0 { format!(" and {more} more") } else { String::new() }
    ))
}
