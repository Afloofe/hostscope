use std::collections::BTreeMap;
use std::net::IpAddr;

use crate::telemetry::filterlog::{proto, Action, Dir};
use crate::telemetry::states::{Endpoint, State};
use crate::telemetry::{tail, Evidence};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Verdict {

    Left,

    Blocked,

    Unknown,
}

impl Verdict {

    pub fn label(self) -> &'static str {
        match self {
            Verdict::Left => "LEFT",
            Verdict::Blocked => "BLOCKED",
            Verdict::Unknown => "UNKNOWN",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Query {

    pub dst: IpAddr,

    pub port: Option<u16>,

    pub proto: Option<u8>,

    pub src: Option<IpAddr>,
}

impl Query {

    pub fn parse(s: &str, src: Option<&str>) -> Result<Query, String> {
        let bad = || format!("{s:?} is not ADDR[:PORT][/PROTO]");
        let (target, proto) = match s.rsplit_once('/') {
            Some((t, p)) => (t, Some(proto::parse(p).ok_or_else(bad)?)),
            None => (s, None),
        };
        let (dst, port) = if let Some(rest) = target.strip_prefix('[') {
            let (a, p) = rest.split_once(']').ok_or_else(bad)?;
            let port = match p.strip_prefix(':') {
                Some(p) => Some(p.parse::<u16>().map_err(|_| bad())?),
                None if p.is_empty() => None,
                None => return Err(bad()),
            };
            (a.parse::<std::net::Ipv6Addr>().map_err(|_| bad())?.into(), port)
        } else if let Ok(a) = target.parse::<IpAddr>() {
            (a, None)
        } else {
            let (a, p) = target.rsplit_once(':').ok_or_else(bad)?;
            (a.parse::<std::net::Ipv4Addr>().map_err(|_| bad())?.into(), Some(p.parse::<u16>().map_err(|_| bad())?))
        };
        if port.is_some() && proto.is_some_and(|p| p != proto::TCP && p != proto::UDP) {
            return Err(format!("{s:?}: only TCP and UDP have ports"));
        }
        let src = src.map(|s| s.parse::<IpAddr>().map_err(|_| format!("--src {s:?} is not an address"))).transpose()?;
        Ok(Query { dst, port, proto, src })
    }

    fn admits(&self, p: u8, src: IpAddr, dst: IpAddr, dport: Option<u16>) -> bool {
        dst == self.dst
            && self.proto.is_none_or(|q| q == p)
            && self.src.is_none_or(|q| q == src)
            && self.port.is_none_or(|q| has_ports(p) && dport == Some(q))
    }
}

impl core::fmt::Display for Query {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match (self.dst, self.port) {
            (IpAddr::V6(a), Some(p)) => write!(f, "[{a}]:{p}")?,
            (a, Some(p)) => write!(f, "{a}:{p}")?,
            (a, None) => write!(f, "{a}")?,
        }
        if let Some(p) = self.proto {
            write!(f, "/{}", proto::name(p))?;
        }
        Ok(())
    }
}

fn has_ports(p: u8) -> bool {
    p == proto::TCP || p == proto::UDP
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FlowKey {

    pub proto: Option<u8>,

    pub src: Option<IpAddr>,

    pub dst: IpAddr,

    pub dport: Option<u16>,
}

impl core::fmt::Display for FlowKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let p = self.proto.map_or("any".to_string(), proto::name);
        let s = self.src.map_or("*".to_string(), |s| s.to_string());
        match (self.dst, self.dport) {
            (IpAddr::V6(d), Some(port)) => write!(f, "{p} {s} -> [{d}]:{port}"),
            (d, Some(port)) => write!(f, "{p} {s} -> {d}:{port}"),
            (d, None) => write!(f, "{p} {s} -> {d}"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowVerdict {

    pub key: FlowKey,

    pub verdict: Verdict,

    pub basis: Vec<String>,

    pub from_firewall: bool,

    pub who: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DestVerdict {

    pub query: Query,

    pub verdict: Verdict,

    pub flows: Vec<FlowVerdict>,

    pub limits: Vec<String>,

    pub suspect: Vec<String>,
}

#[derive(Default)]
struct Tally {
    wan_out: Vec<String>,
    wan_out_sent: usize,
    passed_in: Vec<String>,
    pass_out_lines: BTreeMap<(String, String), Span>,
    pass_in_lines: BTreeMap<(String, String), Span>,
    block_lines: BTreeMap<(String, Dir, String), Span>,
    other_states: Vec<String>,
}

#[derive(Clone)]
struct Span {
    n: usize,
    first: String,
    last: String,
}

fn bump<K: Ord>(m: &mut BTreeMap<K, Span>, k: K, ts: &str) {
    match m.entry(k) {
        std::collections::btree_map::Entry::Vacant(v) => {
            v.insert(Span { n: 1, first: ts.to_string(), last: ts.to_string() });
        }
        std::collections::btree_map::Entry::Occupied(mut o) => {
            let s = o.get_mut();
            s.n += 1;
            s.last = ts.to_string();
        }
    }
}

fn span_text(s: &Span) -> String {
    if s.n == 1 {
        format!("1 line at {}", s.first)
    } else {
        format!("{} lines, {} to {}", s.n, s.first, s.last)
    }
}

fn iface_text(ev: &Evidence, dev: &str) -> String {
    match ev.ifnames.get(dev) {
        Some(n) => format!("{dev} ({n})"),
        None => dev.to_string(),
    }
}

fn rule_text(ev: &Evidence, tracker: &str) -> String {
    match ev.rule(tracker) {
        Some(r) if !r.descr.is_empty() => format!("tracker {tracker}, {:?}", r.descr),
        _ => format!("tracker {tracker}, a rule neither config.xml nor the loaded set names"),
    }
}

fn state_text(ev: &Evidence, s: &State) -> String {
    let nat = s.src_orig.map_or(String::new(), |o| format!(" ({o})"));
    let on = s.origif.as_deref().map_or_else(|| iface_text(ev, &s.iface), |o| iface_text(ev, o));
    let pk = s.pkts.map_or(String::new(), |(a, b)| format!(", {a}:{b} pkts"));
    let age = s.age.map_or(String::new(), |a| format!(", {a} s old"));
    let rule = s.rule.and_then(|n| ev.rules.get(&n)).and_then(|r| r.label.clone()).map_or(String::new(), |l| format!(", rule {l:?}"));
    format!("state {}{nat} {} {} {} on {on}{pk}{age}{rule}", s.src, if s.dir == Dir::Out { "->" } else { "<-" }, s.dst, s.state)
}

fn forwardable(ev: &Evidence, dst: IpAddr) -> bool {
    let local = match dst {
        IpAddr::V4(a) => a.is_loopback() || a.is_link_local() || a.is_multicast() || a.is_broadcast() || a.is_unspecified(),
        IpAddr::V6(a) => a.is_loopback() || a.is_multicast() || a.is_unspecified() || (a.segments()[0] & 0xffc0) == 0xfe80,
    };
    !local && !ev.own.contains(&dst)
}

fn leaves_wan(ev: &Evidence, s: &State) -> bool {
    s.dir == Dir::Out
        && match &s.origif {
            Some(o) => ev.is_wan(o),
            None => ev.is_wan(&s.iface) || s.src_orig.is_some(),
        }
}

fn who(ev: &Evidence, addr: IpAddr) -> Option<String> {
    let n = ev.neighbours.iter().find(|n| n.addr == addr);
    let l = ev.leases.iter().find(|l| l.addr == addr);
    let mut parts = Vec::new();
    if let Some(n) = n {
        parts.push(format!("{} on {} (neighbour table)", n.mac.as_deref().unwrap_or("incomplete"), iface_text(ev, &n.iface)));
    }
    if let Some(l) = l {
        let host = l.hostname.as_deref().map_or(String::new(), |h| format!(" {h:?}"));
        let state = if l.active { "" } else { ", not active" };
        parts.push(format!("{} lease{host} {}{state}", l.server.label(), l.mac.as_deref().unwrap_or("no MAC")));
        if let (Some(nm), Some(lm)) = (n.and_then(|n| n.mac.as_deref()), l.mac.as_deref()) {
            if nm != lm {
                parts.push(format!("the lease's MAC {lm} is not the one answering for the address ({nm}): a conflict or a spoof"));
            }
        }
    }
    (!parts.is_empty()).then(|| parts.join("; "))
}

pub fn limits(ev: &Evidence) -> Vec<String> {
    let mut out = Vec::new();
    match ev.ring.span() {
        Some((a, b)) => out.push(format!("filter.log read from {a} to {b}: {} lines, {} held", ev.lines, ev.ring.len())),
        None => out.push(format!("filter.log gave no line this build reads ({} read)", ev.lines)),
    }
    let (evicted, first) = ev.ring.evicted();
    if evicted > 0 {
        out.push(format!(
            "{evicted} older lines (from {}) were dropped by the ring's cap of {}",
            first.unwrap_or("?"),
            ev.ring.capacity()
        ));
    }
    if !ev.unread_history.is_empty() {

        let bytes: u64 = ev.unread_history.iter().fold(0u64, |n, (_, b)| n.saturating_add(*b));
        let names: Vec<&str> = ev.unread_history.iter().map(|(p, _)| p.rsplit('/').next().unwrap_or(p)).collect();
        out.push(format!(
            "{} older rotation(s) are compressed and were not read ({}, {bytes} bytes): history before the oldest line \
             above is there",
            names.len(),
            names.join(", ")
        ));
    }
    if matches!(ev.continuity, tail::Continuity::Rotated) {
        out.push(ev.continuity.describe(ev.cursor.as_ref()));
    }
    let silent = ev.silent_passes();
    if !silent.is_empty() {

        let mut named: Vec<String> = silent
            .iter()
            .filter(|r| r.tracker.as_deref().is_some_and(|t| ev.rule(t).is_some_and(|n| n.from_config)))
            .filter_map(|r| r.label.clone())
            .collect();
        named.sort();
        named.dedup();
        let shown: Vec<String> = named.iter().take(3).map(|l| format!("{l:?}")).collect();
        out.push(format!(
            "{} loaded pass rule(s) do not log{}: what they pass leaves no line, only a state while it lives",
            silent.len(),
            if shown.is_empty() { String::new() } else { format!(", among them {}", shown.join(", ")) }
        ));
    }
    if ev.states.is_none() {
        out.push("the state table was not read, so no flow could be shown to have left by its state".into());
    }
    out
}

pub fn verdict(ev: &Evidence, q: &Query) -> DestVerdict {
    let mut tallies: BTreeMap<FlowKey, Tally> = BTreeMap::new();
    for e in ev.ring.iter() {
        let l = &e.line;
        let dport = if has_ports(l.proto) { l.dport } else { None };
        if !q.admits(l.proto, l.src, l.dst, dport) {
            continue;
        }
        let key = FlowKey { proto: Some(l.proto), src: Some(l.src), dst: l.dst, dport };
        let t = tallies.entry(key).or_default();
        match (l.action, l.dir) {
            (Action::Pass, Dir::Out) if ev.is_wan(&l.iface) => bump(&mut t.pass_out_lines, (l.iface.clone(), l.tracker.clone()), &l.ts),
            (Action::Pass, Dir::In) if !ev.is_wan(&l.iface) && forwardable(ev, l.dst) => bump(&mut t.pass_in_lines, (l.iface.clone(), l.tracker.clone()), &l.ts),
            (Action::Block, d) => bump(&mut t.block_lines, (l.iface.clone(), d, l.tracker.clone()), &l.ts),
            _ => {}
        }
    }
    for s in ev.states.iter().flatten() {
        let Some(p) = s.proto else { continue };
        let init = s.initiator();
        let dport = if has_ports(p) { s.dst.port } else { None };
        if !q.admits(p, init.addr, s.dst.addr, dport) {
            continue;
        }
        let key = FlowKey { proto: Some(p), src: Some(init.addr), dst: s.dst.addr, dport };
        let t = tallies.entry(key).or_default();
        let text = state_text(ev, s);
        if leaves_wan(ev, s) {
            if s.sent() != Some(false) {
                t.wan_out_sent += 1;
            }
            let unanswered = if s.answered() == Some(false) { " — nothing came back" } else { "" };
            t.wan_out.push(format!("{text}{unanswered}"));
        } else if s.dir == Dir::In && !s.origif.as_deref().is_some_and(|o| ev.is_wan(o)) && forwardable(ev, s.dst.addr) {
            t.passed_in.push(text);
        } else {
            t.other_states.push(text);
        }
    }

    let mut flows: Vec<FlowVerdict> = tallies
        .into_iter()
        .map(|(key, t)| {
            let mut basis = Vec::new();
            let blocked_out = t.block_lines.keys().any(|(_, d, _)| *d == Dir::Out);
            let verdict = if t.wan_out_sent > 0 || !t.pass_out_lines.is_empty() {
                Verdict::Left
            } else if (!t.passed_in.is_empty() || !t.pass_in_lines.is_empty()) && !blocked_out {
                basis.push("passed in, and pfSense's own outbound rule passes what no floating rule stops; nothing blocked it on the way out".into());
                Verdict::Left
            } else if !t.block_lines.is_empty() {
                Verdict::Blocked
            } else {
                Verdict::Unknown
            };
            basis.extend(t.wan_out);
            for ((i, tr), s) in &t.pass_out_lines {
                basis.push(format!("pass out on {}: {}, {}", iface_text(ev, i), span_text(s), rule_text(ev, tr)));
            }
            basis.extend(t.passed_in);
            for ((i, tr), s) in &t.pass_in_lines {
                basis.push(format!("pass in on {}: {}, {}", iface_text(ev, i), span_text(s), rule_text(ev, tr)));
            }
            for ((i, d, tr), s) in &t.block_lines {
                basis.push(format!("block {} on {}: {}, {}", d.label(), iface_text(ev, i), span_text(s), rule_text(ev, tr)));
            }
            basis.extend(t.other_states);
            if verdict == Verdict::Unknown && basis.is_empty() {
                basis.push("no state and no log line".into());
            }
            let from_firewall = key.src.is_some_and(|s| ev.own.contains(&s) || s.is_loopback());
            FlowVerdict { key, verdict, basis, from_firewall, who: key.src.and_then(|s| who(ev, s)) }
        })
        .collect();

    if flows.is_empty() && (q.port.is_some() || q.proto.is_some() || q.src.is_some()) {
        let proto = q.proto.or(None);
        let key = FlowKey { proto, src: q.src, dst: q.dst, dport: q.port };
        flows.push(FlowVerdict {
            key,
            verdict: Verdict::Unknown,
            basis: vec!["no live state and no log line for it".into()],
            from_firewall: q.src.is_some_and(|s| ev.own.contains(&s)),
            who: q.src.and_then(|s| who(ev, s)),
        });
    }
    flows.sort_by(|a, b| a.verdict.cmp(&b.verdict).then(a.key.cmp(&b.key)));
    let verdict = flows.iter().map(|f| f.verdict).min().unwrap_or(Verdict::Unknown);
    DestVerdict { query: *q, verdict, flows, limits: limits(ev), suspect: ev.suspect.clone() }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowRow {

    pub action: Action,

    pub iface: String,

    pub dir: Dir,

    pub proto: u8,

    pub src: IpAddr,

    pub dst: IpAddr,

    pub dport: Option<u16>,

    pub tracker: String,

    pub count: usize,

    pub new: usize,

    pub first: String,

    pub last: String,
}

pub fn flow_rows(ev: &Evidence, dst: Option<IpAddr>) -> Vec<FlowRow> {
    type Key = (Action, String, Dir, u8, IpAddr, IpAddr, Option<u16>, String);
    let mut m: BTreeMap<Key, FlowRow> = BTreeMap::new();
    for e in ev.ring.iter() {
        let l = &e.line;
        if dst.is_some_and(|d| d != l.dst) {
            continue;
        }
        let dport = if has_ports(l.proto) { l.dport } else { None };
        let k = (l.action, l.iface.clone(), l.dir, l.proto, l.src, l.dst, dport, l.tracker.clone());
        let row = m.entry(k).or_insert_with(|| FlowRow {
            action: l.action,
            iface: l.iface.clone(),
            dir: l.dir,
            proto: l.proto,
            src: l.src,
            dst: l.dst,
            dport,
            tracker: l.tracker.clone(),
            count: 0,
            new: 0,
            first: l.ts.clone(),
            last: l.ts.clone(),
        });
        row.count += 1;
        row.new += usize::from(e.new);
        row.last = l.ts.clone();
    }
    let mut rows: Vec<FlowRow> = m.into_values().collect();
    rows.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| b.last.cmp(&a.last)));
    rows
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutRow {

    pub key: FlowKey,

    pub state: String,

    pub from_firewall: bool,

    pub who: Option<String>,
}

pub fn leaving(ev: &Evidence, dst: Option<IpAddr>) -> Vec<OutRow> {
    let mut out = Vec::new();
    for s in ev.states.iter().flatten() {
        if !leaves_wan(ev, s) || dst.is_some_and(|d| d != s.dst.addr) {
            continue;
        }
        let Some(p) = s.proto else { continue };
        let init = s.initiator();
        let key = FlowKey { proto: Some(p), src: Some(init.addr), dst: s.dst.addr, dport: if has_ports(p) { s.dst.port } else { None } };
        out.push(OutRow {
            key,
            state: state_text(ev, s),
            from_firewall: s.src_orig.is_none() && (ev.own.contains(&init.addr) || init.addr.is_loopback()),
            who: who(ev, init.addr),
        });
    }
    out
}

pub fn identity_conflicts(ev: &Evidence) -> Vec<String> {
    let mut out = Vec::new();
    for l in ev.leases.iter().filter(|l| l.active) {
        let Some(lm) = l.mac.as_deref() else { continue };
        if let Some(n) = ev.neighbours.iter().find(|n| n.addr == l.addr) {
            if let Some(nm) = n.mac.as_deref() {
                if nm != lm {
                    out.push(format!("{}: the {} lease names {lm}, the neighbour table {nm} on {}", l.addr, l.server.label(), n.iface));
                }
            }
        }
    }
    out
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Standing {

    Contradiction,

    Unknown,

    Accounted,
}

impl Standing {

    pub fn label(self) -> &'static str {
        match self {
            Standing::Contradiction => "CONTRADICTION",
            Standing::Unknown => "UNKNOWN",
            Standing::Accounted => "accounted",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoxFlow {

    pub standing: Standing,

    pub proto: u8,

    pub local: Endpoint,

    pub peer: Endpoint,

    pub inbound: bool,

    pub state: String,

    pub basis: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct BoxOwned {

    pub flows: Vec<BoxFlow>,

    pub limits: Vec<String>,
}

impl BoxOwned {

    pub fn count(&self, s: Standing) -> usize {
        self.flows.iter().filter(|f| f.standing == s).count()
    }
}

fn sock_end(s: &str) -> Option<(Option<IpAddr>, Option<u16>)> {
    let (a, p) = s.rsplit_once(':')?;
    let port = if p == "*" { None } else { Some(p.parse().ok()?) };
    let addr = if a == "*" {
        None
    } else {
        let a = a.split('%').next().unwrap_or(a);
        Some(unmap(a.parse().ok()?))
    };
    Some((addr, port))
}

fn unmap(a: IpAddr) -> IpAddr {
    match a {
        IpAddr::V6(v) => v.to_ipv4_mapped().map_or(a, IpAddr::V4),
        v4 => v4,
    }
}

fn matches_end(want: Endpoint, got: (Option<IpAddr>, Option<u16>), wild_ok: bool) -> bool {
    let (a, p) = got;
    let addr_ok = match a {
        Some(a) => a == unmap(want.addr),
        None => wild_ok,
    };
    let port_ok = match p {
        Some(p) => Some(p) == want.port,
        None => wild_ok && want.port.is_none(),
    };
    addr_ok && port_ok
}

pub fn own_addresses(ev: &Evidence) -> Vec<IpAddr> {
    let mut v: Vec<IpAddr> = ev.own.clone();
    v.extend(ev.neighbours.iter().filter(|n| n.permanent).map(|n| n.addr));
    v.sort();
    v.dedup();
    v
}

pub fn box_owned(ev: &Evidence) -> BoxOwned {
    let mut out = BoxOwned::default();
    let Some(states) = &ev.states else {
        out.limits.push("the state table was not read, so no state could be matched to a socket".into());
        return out;
    };
    let socks = match &ev.sockets {
        Ok(s) => Some(s.as_slice()),
        Err(e) => {
            out.limits.push(format!("the box's sockets were not read ({e}): no state with an end on it is a CONTRADICTION"));
            None
        }
    };
    let own = own_addresses(ev);
    let is_own = |a: IpAddr| own.contains(&a) || a.is_loopback();
    let mut creators: Vec<&str> = states.iter().filter_map(|s| s.creator.as_deref()).collect();
    creators.sort_unstable();
    creators.dedup();
    if creators.len() > 1 {
        out.limits.push(format!(
            "the table holds states from {} pf instances (creatorid {}): a pfsync peer's states have their sockets on the peer, so none is a CONTRADICTION",
            creators.len(),
            creators.join(", ")
        ));
    }
    let lag = ev.sockets_lag_ms;
    if socks.is_some() && lag.is_none() {
        out.limits.push("when sockstat ran against pfctl is not recorded, so no state can be shown to predate it".into());
    }
    for s in states {
        let Some(p) = s.proto else { continue };
        if !has_ports(p) {
            continue;
        }
        let init = s.initiator();

        let (local, peer, inbound) = if is_own(init.addr) {
            (init, s.dst_orig.unwrap_or(s.dst), false)
        } else if s.dst_orig.is_none() && s.src_orig.is_none() && is_own(s.dst.addr) {
            (s.dst, s.src, true)
        } else {
            continue;
        };
        if is_own(peer.addr) {
            continue;
        }
        let text = state_text(ev, s);
        let tcp = p == proto::TCP;
        let found = socks.map(|ss| {
            let proto_ok = |x: &crate::posture::parse::Socket| x.proto.starts_with(if tcp { "tcp" } else { "udp" });
            let exact = ss.iter().filter(|x| proto_ok(x)).find(|x| {
                sock_end(&x.local).is_some_and(|l| matches_end(local, l, !tcp))
                    && sock_end(&x.foreign).is_some_and(|f| matches_end(peer, f, !tcp) || (!tcp && f == (None, None)))
            });
            let listener = ss.iter().filter(|x| proto_ok(x) && x.is_listener()).find(|x| {
                sock_end(&x.local).is_some_and(|(a, port)| port == local.port && a.is_none_or(|a| a == unmap(local.addr)))
            });
            (exact.cloned(), listener.cloned())
        });
        let owner = |x: &crate::posture::parse::Socket| {
            let pid = x.pid.map_or("?".to_string(), |p| p.to_string());
            format!("{} (pid {pid}, {}) {} {}", x.command, x.user, x.local, x.foreign)
        };
        let (standing, basis) = match found {
            None => (Standing::Unknown, "the box's sockets were not read".to_string()),
            Some((Some(x), _)) => (Standing::Accounted, format!("held by {}", owner(&x))),
            Some((None, l)) if !tcp => (
                Standing::Unknown,
                match l {
                    Some(l) => format!("UDP; {} is bound to its port", owner(&l)),
                    None => "UDP: no socket is bound to it now, and a UDP socket closes without a trace while its state lives on".into(),
                },
            ),
            Some((None, _)) if s.state != "ESTABLISHED:ESTABLISHED" => {
                (Standing::Unknown, format!("no socket holds it, and it is {}: its socket may already be closed", s.state))
            }
            Some((None, Some(l))) if inbound => (
                Standing::Unknown,
                format!("no socket holds it, but {} listens on its port: a connection still in the accept queue has no descriptor", owner(&l)),
            ),
            Some((None, _)) => {
                let old = match (s.age, lag) {
                    (Some(a), Some(l)) => a.saturating_mul(1000) > l.saturating_add(1000),
                    _ => false,
                };
                let ours = creators.len() <= 1;
                if old && ours {
                    (
                        Standing::Contradiction,
                        format!(
                            "no socket on the box holds it: sockstat, run {} ms before pfctl -ss finished, lists no TCP socket {local} <-> {peer}, \
                             and the state is {} s old and still ESTABLISHED. A connection the firewall itself is party to that its own \
                             socket table does not show",
                            lag.unwrap_or(0),
                            s.age.unwrap_or(0)
                        ),
                    )
                } else {
                    let why = if !ours {
                        "no socket holds it, and the table is a pfsync pair's: it may be the peer's".to_string()
                    } else {
                        "no socket holds it, but it is too new to have been there when sockstat looked".to_string()
                    };
                    (Standing::Unknown, why)
                }
            }
        };
        out.flows.push(BoxFlow { standing, proto: p, local, peer, inbound, state: text, basis });
    }
    out.flows.sort_by(|a, b| a.standing.cmp(&b.standing).then(a.local.cmp(&b.local)).then(a.peer.cmp(&b.peer)));
    out
}
