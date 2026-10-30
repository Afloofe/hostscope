#![cfg_attr(not(feature = "mod-collector"), allow(dead_code))]

use std::collections::BTreeSet;
use std::net::IpAddr;

use hemostat_sensor_freebsd::telemetry::filterlog::proto;
use hemostat_sensor_freebsd::telemetry::states::{Endpoint, State};
use hemostat_sensor_freebsd::telemetry::Evidence;
use hemostat_sensor_freebsd::verdict::{self, BoxOwned, Standing};
use hemostat_sensor_linux::flowexport::{unmap, HostFlows, HostSocket};

use crate::render::{h, hex32, jesc};

pub(crate) const DEFAULT_SKEW: u64 = 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Grade {

    Contradiction,

    Unknown,

    Agreement,
}

impl Grade {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Grade::Contradiction => "CONTRADICTION",
            Grade::Unknown => "UNKNOWN",
            Grade::Agreement => "agreement",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Joined {
    pub(crate) grade: Grade,

    pub(crate) flow: String,
    pub(crate) basis: Vec<String>,

    pub(crate) class: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Clock {

    pub(crate) fw_now: u64,

    pub(crate) host_now: u64,

    pub(crate) skew: u64,

    pub(crate) offset: i64,

    pub(crate) floor: Option<i64>,

    pub(crate) unmeasured: Option<String>,
}

impl Clock {

    pub(crate) fn violated(&self) -> bool {
        self.floor.is_some_and(|f| f > i64::try_from(self.skew).unwrap_or(i64::MAX))
    }
}

#[derive(Debug, Clone)]
pub(crate) struct Report {

    pub(crate) host_on_fw: Vec<String>,

    pub(crate) flows: Vec<Joined>,

    pub(crate) box_owned: BoxOwned,

    pub(crate) host_only: Vec<String>,

    pub(crate) unknowns: Vec<String>,
    pub(crate) clock: Clock,
}

impl Report {
    pub(crate) fn count(&self, g: Grade) -> usize {
        self.flows.iter().filter(|f| f.grade == g).count()
    }

    pub(crate) fn contradictions(&self) -> usize {
        self.count(Grade::Contradiction) + self.box_owned.count(Standing::Contradiction)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Claim {
    Host(String),
    Twice(String),
}

fn claim(ev: &Evidence, host: &HostFlows, addr: IpAddr, elsewhere: &BTreeSet<IpAddr>) -> Option<Claim> {
    let c = claim_here(ev, host, addr)?;
    Some(match c {
        Claim::Host(why) if elsewhere.contains(&addr) => Claim::Twice(format!(
            "{why}, and another host's flow export holds {addr}: a lease that moved, or an address two machines answer for"
        )),
        c => c,
    })
}

fn claim_here(ev: &Evidence, host: &HostFlows, addr: IpAddr) -> Option<Claim> {

    let shared = match addr {
        IpAddr::V4(a) => a.is_loopback() || a.is_unspecified() || a.is_multicast() || a.is_broadcast(),
        IpAddr::V6(a) => a.is_loopback() || a.is_unspecified() || a.is_multicast(),
    };
    if shared {
        return None;
    }
    let macs = host.macs();
    let neighbour = ev.neighbours.iter().find(|n| n.addr == addr && n.mac.is_some());
    let nmac = neighbour.and_then(|n| n.mac.as_deref());
    if host.addrs.contains(&addr) {
        return Some(match nmac {
            Some(m) if !macs.contains(m) => Claim::Twice(format!(
                "the host holds {addr}, and the firewall's neighbour table puts it at {m}, which is none of the host's MACs"
            )),
            _ => Claim::Host(format!("the host holds {addr}")),
        });
    }
    if let Some(m) = nmac.filter(|m| macs.contains(m)) {
        return Some(Claim::Host(format!("the firewall's neighbour table puts {addr} at the host's MAC {m}")));
    }
    let lease = ev.leases.iter().find(|l| l.addr == addr && l.mac.as_deref().is_some_and(|m| macs.contains(m)))?;
    let now = if lease.active { "a lease" } else { "an expired lease" };
    if let Some(m) = nmac {

        return Some(Claim::Twice(format!(
            "{now} gave {addr} to the host's MAC {}, and the firewall's neighbour table now puts it at {m}: the lease moved",
            lease.mac.as_deref().unwrap_or("")
        )));
    }
    Some(Claim::Host(format!(
        "{now} gave {addr} to the host's MAC {} (the host no longer holds it: DHCP churn)",
        lease.mac.as_deref().unwrap_or("")
    )))
}

fn proto_name(p: u8) -> &'static str {
    if p == proto::TCP {
        "tcp"
    } else {
        "udp"
    }
}

fn ep(a: IpAddr, p: u16) -> String {
    Endpoint { addr: a, port: Some(p) }.to_string()
}

struct Flow<'a> {
    proto: u8,
    init: Endpoint,
    dst: Endpoint,
    states: Vec<&'a State>,
}

impl Flow<'_> {
    fn key(&self) -> String {
        format!("{} {} -> {}", proto_name(self.proto), self.init, self.dst)
    }

    fn established(&self) -> bool {
        self.states.iter().any(|s| s.state == "ESTABLISHED:ESTABLISHED")
    }

    fn age(&self) -> Option<u64> {
        self.states.iter().filter_map(|s| s.age).max()
    }

    fn idle(&self, ev: &Evidence) -> Result<u64, String> {
        let t = ev.timeouts.as_ref().map_err(|e| format!("pf's timeouts were not read ({e})"))?;
        let n = ev.states.as_ref().map_or(0, |s| s.len() as u64);
        self.states
            .iter()
            .filter(|s| s.state == "ESTABLISHED:ESTABLISHED")
            .filter_map(|s| {
                let own = s.rule.and_then(|r| ev.rules.get(&r)).is_some_and(|r| r.own_timeouts);
                t.idle(self.proto, &s.state, s.expires, n, own)
            })
            .min()
            .ok_or_else(|| "its expiry does not say when it last carried a packet (a rule with its own timeout, or no expiry printed)".into())
    }
}

fn within(a: IpAddr, (net, len): (IpAddr, u8)) -> bool {
    match (a, net) {
        (IpAddr::V4(a), IpAddr::V4(n)) => {
            let mask = if len == 0 { 0 } else { u32::MAX << (32 - u32::from(len.min(32))) };
            (u32::from(a) & mask) == (u32::from(n) & mask)
        }
        _ => false,
    }
}

fn local_scope(a: IpAddr) -> bool {
    match a {
        IpAddr::V4(v) => v.is_loopback() || v.is_link_local() || v.is_unspecified() || v.is_multicast() || v.is_broadcast(),
        IpAddr::V6(v) => v.is_loopback() || v.is_unspecified() || v.is_multicast() || (v.segments()[0] & 0xffc0) == 0xfe80,
    }
}

fn sock_text(s: &HostSocket) -> String {
    let ns = s.netns.as_deref().map_or(String::new(), |n| format!(" in network namespace {n}"));
    let who = s.owner.as_deref().unwrap_or("no owner found");
    let remote = s.remote.map_or("*".to_string(), |r| ep(r, s.rport));
    format!("{} {} -> {} {}{ns}, {who}", s.proto, ep(s.local, s.lport), remote, s.state)
}

fn before(now: Option<i64>, secs: u64) -> Option<i64> {
    now?.checked_sub(i64::try_from(secs).ok()?)
}

pub(crate) fn correlate(ev: &Evidence, host: &HostFlows, skew: u64, offset: i64, elsewhere: &BTreeSet<IpAddr>) -> Report {

    let fw_now = i64::try_from(ev.now).ok();
    let hn = i64::try_from(host.now).ok().and_then(|n| n.checked_add(offset));
    let mut unmeasured = match (fw_now, hn) {
        (None, _) => Some(format!("the firewall's capture time ({}) is not a time this can compare", ev.now)),
        (_, None) => Some(format!("the host's sweep time ({}, moved {offset:+} s) is not a time this can compare", host.now)),
        _ => None,
    };
    let mut unknowns = Vec::new();

    let mut seen: BTreeSet<IpAddr> = BTreeSet::new();
    for s in ev.states.iter().flatten() {
        seen.insert(s.initiator().addr);
    }
    seen.extend(ev.neighbours.iter().map(|n| n.addr));
    seen.extend(ev.leases.iter().map(|l| l.addr));
    let mut host_on_fw = Vec::new();
    let mut ours: BTreeSet<IpAddr> = BTreeSet::new();
    let mut twice: BTreeSet<IpAddr> = BTreeSet::new();
    for a in seen {
        match claim(ev, host, a, elsewhere) {
            Some(Claim::Host(why)) => {
                ours.insert(a);
                host_on_fw.push(why);
            }
            Some(Claim::Twice(why)) => {
                twice.insert(a);
                unknowns.push(format!("{why}: its flows are judged as no one's"));
            }
            None => {}
        }
    }
    if ours.is_empty() {
        unknowns.push(
            "nothing in the firewall's view is this host's: none of its addresses or MACs appear in the states, the \
             neighbour tables or the leases. Is this the right pair of exports?"
                .into(),
        );
    }

    let mut flows: Vec<Flow<'_>> = Vec::new();
    for s in ev.states.iter().flatten() {
        let Some(p) = s.proto.filter(|p| *p == proto::TCP || *p == proto::UDP) else { continue };
        let init = s.initiator();
        if !ours.contains(&init.addr) || init.port.is_none() || s.dst.port.is_none() {
            continue;
        }
        let dst = s.dst;
        match flows.iter_mut().find(|f| f.proto == p && f.init == init && f.dst == dst) {
            Some(f) => f.states.push(s),
            None => flows.push(Flow { proto: p, init, dst, states: vec![s] }),
        }
    }

    let mut used = vec![false; host.sockets.len()];

    let mut matched: Vec<Option<(usize, String, bool)>> = vec![None; flows.len()];
    let conns = host.conntrack.as_ref().ok();
    let to = |s: &HostSocket, f: &Flow<'_>| {
        s.proto == proto_name(f.proto) && s.remote.map(unmap) == Some(unmap(f.dst.addr)) && Some(s.rport) == f.dst.port
    };

    for (fi, f) in flows.iter().enumerate() {
        if let Some(si) = host.sockets.iter().enumerate().position(|(i, s)| {
            !used[i] && to(s, f) && Some(s.lport) == f.init.port && unmap(s.local) == unmap(f.init.addr)
        }) {
            used[si] = true;
            matched[fi] = Some((si, "the host's socket".into(), true));
        }
    }

    for (fi, f) in flows.iter().enumerate() {
        if matched[fi].is_some() {
            continue;
        }
        let Some(c) = conns.and_then(|cs| {
            cs.iter().find(|c| {
                c.proto == proto_name(f.proto)
                    && unmap(c.reply.0) == unmap(f.dst.addr)
                    && Some(c.reply.1) == f.dst.port
                    && unmap(c.reply.2) == unmap(f.init.addr)
                    && Some(c.reply.3) == f.init.port
            })
        }) else {
            continue;
        };
        if let Some(si) = host.sockets.iter().enumerate().position(|(i, s)| {
            !used[i] && to(s, f) && s.lport == c.orig.1 && unmap(s.local) == unmap(c.orig.0)
        }) {
            used[si] = true;
            matched[fi] = Some((si, format!("translated by the host's own NAT from {} (its conntrack entry), the host's socket", ep(c.orig.0, c.orig.1)), true));
        }
    }

    for (fi, f) in flows.iter().enumerate() {
        if matched[fi].is_some() {
            continue;
        }

        let live = |s: &HostSocket| matches!(s.state.as_str(), "ESTABLISHED" | "SYN_SENT" | "SYN_RECV");
        let same_port = host.sockets.iter().enumerate().position(|(i, s)| !used[i] && live(s) && to(s, f) && Some(s.lport) == f.init.port);
        let any_port = || host.sockets.iter().enumerate().position(|(i, s)| !used[i] && live(s) && to(s, f));
        if let Some(si) = same_port.or_else(any_port) {
            used[si] = true;
            let how = match host.sockets.get(si) {
                Some(s) if Some(s.lport) == f.init.port => format!(
                    "from {} on the host, which the firewall sees as {} — the host's own NAT{}; the host's socket",
                    s.local,
                    f.init.addr,
                    if conns.is_some_and(|c| !c.is_empty()) { ", though its conntrack has no entry for it" } else { "" }
                ),
                _ => "not the same local port — NAT on the host that changed it, or another connection to the same place — the host's socket".into(),
            };
            let same = host.sockets.get(si).is_some_and(|s| Some(s.lport) == f.init.port);
            matched[fi] = Some((si, how, same));
        }
    }

    let mut floor: Option<i64> = None;
    for (fi, f) in flows.iter().enumerate() {
        if f.proto != proto::TCP || !matched[fi].as_ref().is_some_and(|m| m.2) {
            continue;
        }
        if let Some(age) = f.age() {
            match before(fw_now, age).zip(hn).and_then(|(made, hn)| made.checked_sub(hn)) {
                Some(lb) => floor = Some(floor.map_or(lb, |x: i64| x.max(lb))),

                None => {
                    unmeasured.get_or_insert_with(|| {
                        format!("an agreed flow's age ({age} s) does not compute against the two clocks, so the bound is not checked")
                    });
                }
            }
        }
    }
    let clock = Clock { fw_now: ev.now, host_now: host.now, skew, offset, floor, unmeasured };

    let mut hidden = Vec::new();
    for n in host.unread_namespaces() {
        hidden.push(format!("the host knows of network namespace {} ({}) and could not read it", n.id, n.found.join(", ")));
    }
    for u in host.unreached.iter().filter(|u| u.proto.as_deref().is_none_or(hemostat_sensor_linux::flowexport::is_stream)) {
        hidden.push(format!("{} hold(s) {} socket {} that is in no table the host read", u.holders.join(", "), u.proto.as_deref().unwrap_or("a"), u.inode));
    }

    let s = i64::try_from(skew).unwrap_or(i64::MAX);
    let mut joined = Vec::new();
    for (fi, f) in flows.iter().enumerate() {
        let mut basis: Vec<String> = f.states.iter().map(|st| state_line(st)).collect();
        if let Some((si, how, _)) = &matched[fi] {
            if let Some(sock) = host.sockets.get(*si) {
                basis.insert(0, format!("{how}: {}", sock_text(sock)));
            }
            joined.push(Joined { grade: Grade::Agreement, flow: f.key(), basis, class: "agreement" });
            continue;
        }
        let forwarded = conns.and_then(|cs| {
            cs.iter().find(|c| {
                c.proto == proto_name(f.proto)
                    && unmap(c.reply.0) == unmap(f.dst.addr)
                    && Some(c.reply.1) == f.dst.port
                    && unmap(c.reply.2) == unmap(f.init.addr)
                    && Some(c.reply.3) == f.init.port
            })
        });
        if let Some(c) = forwarded {
            let from = unmap(c.orig.0);
            let ns = host.namespaces.iter().find(|n| n.read && n.addrs.contains(&from));
            basis.push(match ns {
                Some(n) => format!(
                    "the host's conntrack shows it forwarded from {}, an address of namespace {}, which was read and holds no such socket",
                    ep(c.orig.0, c.orig.1),
                    n.id
                ),
                None => format!(
                    "the host's conntrack shows it forwarded from {}, an address of no namespace the host read: a namespace it could not reach, or a machine it routes for",
                    ep(c.orig.0, c.orig.1)
                ),
            });
        }
        let (grade, why, class) = if f.proto == proto::UDP {
            (Grade::Unknown, "UDP: no socket on the host for it now, and a UDP socket closes without a trace while its state lives on".to_string(), "udp")
        } else if twice.contains(&f.init.addr) {
            (Grade::Unknown, "its address is claimed by two machines".to_string(), "twice")
        } else if !f.established() {
            (Grade::Unknown, "no socket on the host for it, and pf does not hold it ESTABLISHED: opening or closing".to_string(), "closing")
        } else {
            match (f.age(), f.idle(ev)) {
                (None, _) => (Grade::Unknown, "pf printed no age for it".to_string(), "no-age"),
                (_, Err(e)) => (Grade::Unknown, format!("no socket on the host for it, but {e}"), "no-idle"),
                (Some(age), Ok(idle)) => match (clock.unmeasured.as_deref(), before(fw_now, age).zip(before(fw_now, idle)).zip(hn)) {
                    (Some(why), _) => (Grade::Unknown, format!("no socket on the host for it, but the clocks are NOT MEASURED: {why}"), "unmeasured"),
                    (None, None) => (
                        Grade::Unknown,
                        format!("no socket on the host for it, but its age ({age} s) and idle time ({idle} s) do not compute against the clocks"),
                        "unmeasured",
                    ),
                    (None, Some(((made, last), hn))) => {
                        let hb = i64::try_from(host.boot).unwrap_or(0);

                        if hb > 0 && hb.saturating_add(offset) > made.saturating_add(s) {
                            (Grade::Unknown, format!("the host booted at {} (on the box's clock), after the state was made at {made}: it may be the connection of a host that went away", hb.saturating_add(offset)), "booted")
                        } else if clock.violated() {
                            (Grade::Unknown, format!("the clock bound of ±{skew} s is contradicted by the agreed flows (see clocks), so no flow can be shown alive across the host's sweep"), "clock")
                        } else if made.saturating_add(s) < hn && last > hn.saturating_add(s) {
                            let mut b = format!(
                                "no socket on the host accounts for it, and it was live across the host's sweep: made at {made} and last carried a packet at {last} by the box's clock, the host's sweep at {hn} on it, ±{skew} s"
                            );
                            if hidden.is_empty() {
                                b.push_str(". The host's export claims full coverage: every table, every namespace it knows of, every socket in a table — the socket is hidden from all of them");
                            }
                            (Grade::Contradiction, b, "contradiction")
                        } else {
                            (Grade::Unknown, format!(
                                "no socket on the host for it, but it is not shown alive across the host's sweep: made at {made}, last packet at {last} (the box's clock), the sweep at {hn} on the same clock, ±{skew} s"
                            ), "not-alive")
                        }
                    }
                },
            }
        };
        basis.insert(0, why);
        if grade == Grade::Contradiction {
            basis.extend(hidden.iter().cloned());
        }
        joined.push(Joined { grade, flow: f.key(), basis, class });
    }
    joined.sort_by(|a, b| a.grade.cmp(&b.grade).then_with(|| a.flow.cmp(&b.flow)));

    let mut host_only = Vec::new();
    let dsts: BTreeSet<(IpAddr, Option<u16>)> = ev.states.iter().flatten().map(|s| (unmap(s.dst.addr), s.dst.port)).collect();
    let own_fw = verdict::own_addresses(ev);
    for (i, sk) in host.sockets.iter().enumerate() {
        let Some(r) = sk.remote.map(unmap) else { continue };
        if used[i] || sk.proto != "tcp" || sk.state != "ESTABLISHED" || local_scope(r) || host.addrs.contains(&r) || own_fw.contains(&r) {
            continue;
        }
        if sk.netns.is_none() && host.onlink.iter().any(|p| within(r, *p)) {
            continue;
        }
        if sk.netns.is_some() && host.namespaces.iter().any(|n| n.addrs.contains(&r)) {
            continue;
        }
        if !dsts.contains(&(r, Some(sk.rport))) {
            host_only.push(sock_text(sk));
        }
    }
    if !host_only.is_empty() {
        unknowns.push(format!(
            "{} connection(s) on the host off its link that the firewall holds no state for: closed between the captures, made after the firewall's, or another way out",
            host_only.len()
        ));
    }

    unknowns.extend(hidden.iter().map(|x| format!("host coverage: {x}")));
    unknowns.extend(crate::hostexport::notes(host).iter().map(|x| format!("host: {x}")));
    for t in &host.unread_tables {
        unknowns.push(format!("host coverage: socket table not read: {t}"));
    }
    if host.unmapped_processes > 0 {
        unknowns.push(format!("host coverage: {} process(es) whose descriptors could not be listed", host.unmapped_processes));
    }
    if let Err(e) = &host.conntrack {
        unknowns.push(format!("host NAT: conntrack not exported ({e}); a namespace's or container's flow is matched by destination only"));
    }
    unknowns.extend(host.gaps.iter().map(|g| format!("host: {g}")));
    unknowns.extend(ev.gaps.iter().map(|g| format!("firewall: {g}")));
    unknowns.extend(ev.suspect.iter().map(|g| format!("firewall telemetry is SUSPECT: {g}")));
    if let Err(e) = &ev.timeouts {
        unknowns.push(format!("firewall: pf's timeouts were not read ({e}): no state can be shown alive, so no host flow is a CONTRADICTION"));
    }
    if let Some(why) = &clock.unmeasured {
        unknowns.push(format!(
            "clocks NOT MEASURED: {why}. No state can be shown alive across the host's sweep, so none is a CONTRADICTION"
        ));
    }
    if let Some((now, hn)) = fw_now.zip(hn).filter(|(now, hn)| now.saturating_add(s) < *hn) {
        unknowns.push(format!(
            "the firewall's capture ({now}) is older than the host's sweep ({hn}) by more than ±{skew} s: no state in it can be shown alive after the sweep, so none can be a CONTRADICTION. Capture the firewall after the host"
        ));
    }
    unknowns.push(
        "the firewall's own NAT is undone by its states (the address before translation); a flow NATed by another \
         router between the host and the firewall is that router's, and is not joined"
            .into(),
    );

    let box_owned = verdict::box_owned(ev);
    Report { host_on_fw, flows: joined, box_owned, host_only, unknowns, clock }
}

fn state_line(s: &State) -> String {
    let nat = s.src_orig.map_or(String::new(), |o| format!(" ({o})"));
    let on = s.origif.as_deref().unwrap_or(&s.iface);
    let age = s.age.map_or(String::new(), |a| format!(", {a} s old"));
    let exp = s.expires.map_or(String::new(), |e| format!(", expires in {e} s"));
    format!("firewall state {}{nat} {} {} {} on {on}{age}{exp}", s.src, if s.dir == hemostat_sensor_freebsd::telemetry::filterlog::Dir::Out { "->" } else { "<-" }, s.dst, s.state)
}

#[derive(Debug, Clone)]
pub(crate) struct Stores {
    pub(crate) fw_dir: String,
    pub(crate) fw_seal: [u8; 32],
    pub(crate) fw_pinned: bool,
    pub(crate) fw_host_id: [u8; 32],
    pub(crate) host_dir: String,
    pub(crate) host_seal: [u8; 32],
    pub(crate) host_pinned: bool,
    pub(crate) host_host_id: [u8; 32],
    pub(crate) hostname: String,
    pub(crate) manifest: String,
}

impl Stores {
    fn pinned(&self) -> bool {
        self.fw_pinned && self.host_pinned
    }
}

pub(crate) fn exit_code(st: &Stores, ev: &Evidence, host: &HostFlows) -> u8 {
    let host_complete = crate::hostexport::incomplete(host).is_empty();
    if st.pinned() && ev.gaps.is_empty() && ev.suspect.is_empty() && ev.timeouts.is_ok() && host_complete {
        crate::EXIT_OK
    } else {
        crate::EXIT_PARTIAL
    }
}

const GROUP_OVER: usize = 3;

const GROUP_SHOWN: usize = 6;

fn class_text(c: &str) -> &'static str {
    match c {
        "udp" => "UDP — no socket on the host for it now, and a UDP socket closes without a trace while its state lives on",
        "closing" => "no socket on the host for them, and pf does not hold them ESTABLISHED: opening or closing",
        "not-alive" => "no socket on the host for them, and none is shown alive across the host's sweep: made after it, or idle since before it, within the clock bound",
        "twice" => "their address is claimed by two machines",
        "no-idle" => "no socket on the host for them, and their expiry does not say when they last carried a packet",
        "booted" => "the host booted after their states were made",
        "clock" => "the clock bound is contradicted by the agreed flows",
        "unmeasured" => "the clocks are NOT MEASURED: a time in one of the stores does not compute",
        "agreement" => "a socket on the host accounts for each",
        _ => "as their basis says",
    }
}

pub(crate) fn render(st: &Stores, r: &Report) -> String {
    use std::fmt::Write as _;
    let mut o = String::new();
    let _ = writeln!(o, "correlate — the firewall's view of {} against the host's own (collector)", h(&st.hostname));
    let pin = |p: bool| if p { "pinned" } else { "NOT PINNED: verified only under its own key" };
    let _ = writeln!(o, "  firewall   {} · seal {} ({}) · box {}", h(&st.fw_dir), hex32(&st.fw_seal), pin(st.fw_pinned), hex32(&st.fw_host_id).get(..16).unwrap_or(""));
    let _ = writeln!(o, "             judged again here against {}", h(&st.manifest));
    let _ = writeln!(o, "  host       {} · seal {} ({}) · host {}", h(&st.host_dir), hex32(&st.host_seal), pin(st.host_pinned), hex32(&st.host_host_id).get(..16).unwrap_or(""));
    let c = &r.clock;

    let d = i64::try_from(c.fw_now)
        .ok()
        .zip(i64::try_from(c.host_now).ok())
        .and_then(|(f, h)| f.checked_sub(h)?.checked_sub(c.offset))
        .map_or_else(
            || "the two captures are NOT MEASURED on one clock".to_string(),
            |d| format!("the firewall's capture is {d:+} s after the host's on one clock"),
        );
    let _ = writeln!(
        o,
        "  clocks     firewall {} · host {} · box − host taken as {:+} s (--offset) · {d}; bound ±{} s (--skew)",
        c.fw_now, c.host_now, c.offset, c.skew
    );
    if let Some(why) = &c.unmeasured {
        let _ = writeln!(o, "             NOT MEASURED: {} — no CONTRADICTION is called", h(why));
    }
    if let Some(f) = c.floor {
        let _ = writeln!(
            o,
            "             the agreed flows put (box clock − host clock) at {f:+} s or more{}",
            if c.violated() { " — OVER THE BOUND: no CONTRADICTION is called" } else { ", within the bound" }
        );
    }
    let _ = writeln!(
        o,
        "  answer     {} CONTRADICTION · {} agreement · {} unknown, of {} flow(s) from the host · the firewall's own: {} CONTRADICTION",
        r.contradictions(),
        r.count(Grade::Agreement),
        r.count(Grade::Unknown),
        r.flows.len(),
        r.box_owned.count(Standing::Contradiction)
    );
    let _ = writeln!(o, "\n  THE HOST ON THE FIREWALL");
    for w in &r.host_on_fw {
        let _ = writeln!(o, "    {}", h(w));
    }
    for g in [Grade::Contradiction, Grade::Unknown, Grade::Agreement] {
        let fs: Vec<&Joined> = r.flows.iter().filter(|f| f.grade == g).collect();
        if fs.is_empty() {
            continue;
        }
        let _ = writeln!(o, "\n  {} ({})", g.label().to_uppercase(), fs.len());

        let mut classes: Vec<&str> = fs.iter().map(|f| f.class).collect();
        classes.dedup();
        classes.sort_unstable();
        classes.dedup();
        for c in classes {
            let of: Vec<&&Joined> = fs.iter().filter(|f| f.class == c).collect();
            if of.len() > GROUP_OVER && g == Grade::Unknown {
                let _ = writeln!(o, "    {:<13} {} flow(s): {}", g.label(), of.len(), h(class_text(c)));
                for f in of.iter().take(GROUP_SHOWN) {
                    let _ = writeln!(o, "                  {}", h(&f.flow));
                }
                if of.len() > GROUP_SHOWN {
                    let _ = writeln!(o, "                  … and {} more (--json lists every one)", of.len() - GROUP_SHOWN);
                }
                continue;
            }
            for f in of {
                let _ = writeln!(o, "    {:<13} {}", g.label(), h(&f.flow));
                for b in &f.basis {
                    let _ = writeln!(o, "                  {}", h(b));
                }
            }
        }
    }
    crate::boxowned::render_box_owned(&mut o, &r.box_owned);
    if !r.host_only.is_empty() {
        let _ = writeln!(o, "\n  ON THE HOST, NOT ON THE FIREWALL ({})", r.host_only.len());
        for x in r.host_only.iter().take(20) {
            let _ = writeln!(o, "    {}", h(x));
        }
    }
    let _ = writeln!(o, "\n  What neither side could see:");
    for u in r.unknowns.iter().chain(r.box_owned.limits.iter()) {
        let _ = writeln!(o, "    - {}", h(u));
    }
    let _ = writeln!(
        o,
        "  Not seen by this check: a kernel on either side that lies consistently to its own agent; a flow \
         that crossed neither the firewall nor a table; which machine really answers for an address."
    );
    o
}

fn jstr(s: &str) -> String {
    format!("\"{}\"", jesc(s))
}

fn jlist(v: &[String]) -> String {
    format!("[{}]", v.iter().map(|s| jstr(s)).collect::<Vec<_>>().join(","))
}

pub(crate) fn render_json(st: &Stores, r: &Report, complete: bool) -> String {
    let flows: Vec<String> = r
        .flows
        .iter()
        .map(|f| format!("{{\"grade\":{},\"class\":{},\"flow\":{},\"basis\":{}}}", jstr(f.grade.label()), jstr(f.class), jstr(&f.flow), jlist(&f.basis)))
        .collect();
    format!(
        "{{\"firewall\":{{\"dir\":{},\"seal_pub\":{},\"pinned\":{},\"host_id\":{}}},\"host\":{{\"dir\":{},\"seal_pub\":{},\"pinned\":{},\"host_id\":{},\"hostname\":{}}},\
         \"clock\":{{\"firewall\":{},\"host\":{},\"offset\":{},\"skew\":{},\"floor\":{},\"violated\":{}}},\"contradictions\":{},\"flows\":[{}],\
         \"box_owned\":{},\"host_only\":{},\"host_on_firewall\":{},\"unknowns\":{},\"complete\":{complete}}}",
        jstr(&st.fw_dir),
        jstr(&hex32(&st.fw_seal)),
        st.fw_pinned,
        jstr(&hex32(&st.fw_host_id)),
        jstr(&st.host_dir),
        jstr(&hex32(&st.host_seal)),
        st.host_pinned,
        jstr(&hex32(&st.host_host_id)),
        jstr(&st.hostname),
        r.clock.fw_now,
        r.clock.host_now,
        r.clock.offset,
        r.clock.skew,
        r.clock.floor.map_or("null".to_string(), |f| f.to_string()),
        r.clock.violated(),
        r.contradictions(),
        flows.join(","),
        crate::boxowned::box_owned_json(&r.box_owned),
        jlist(&r.host_only),
        jlist(&r.host_on_fw),
        jlist(&r.unknowns),
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Ask {
    pub(crate) fw: String,
    pub(crate) fw_pin: Option<[u8; 32]>,
    pub(crate) host: String,
    pub(crate) host_pin: Option<[u8; 32]>,
    pub(crate) manifest: Option<String>,
    pub(crate) skew: u64,
    pub(crate) offset: i64,
}

pub(crate) fn parse_args(args: &[String]) -> Result<Ask, String> {
    let value = |flag: &str| -> Result<Option<String>, String> {
        let Some(i) = args.iter().position(|a| a == flag) else { return Ok(None) };
        match args.get(i + 1).filter(|v| !v.starts_with("--")) {
            Some(v) => Ok(Some(v.clone())),
            None => Err(format!("{flag} takes a value, and none was given")),
        }
    };
    let pin = |flag: &str| -> Result<Option<[u8; 32]>, String> {
        value(flag)?
            .map(|v| crate::identity::parse_hex32(&v).ok_or_else(|| format!("{flag} takes the store's seal key, 64 hex characters")))
            .transpose()
    };
    let fw = value("--fw")?.ok_or("correlate needs --fw DIR: the firewall's store, from `fw flows` or `fw verdict`")?;
    let host = value("--host")?.ok_or("correlate needs --host DIR: the host's store, from `overview --export`")?;
    let skew = match value("--skew")? {
        None => DEFAULT_SKEW,
        Some(v) => v.parse::<u64>().ok().filter(|s| *s <= 86_400).ok_or_else(|| format!("--skew takes 0 to 86400 seconds, not {v:?}"))?,
    };
    let offset = match value("--offset")? {
        None => 0,
        Some(v) => v.parse::<i64>().ok().filter(|o| o.unsigned_abs() <= 31_536_000).ok_or_else(|| format!("--offset takes the box's clock less the host's in seconds, not {v:?}"))?,
    };
    Ok(Ask { offset, fw, fw_pin: pin("--fw-pin")?, host, host_pin: pin("--host-pin")?, manifest: value("--manifest")?, skew })
}

#[cfg(feature = "mod-collector")]
pub(crate) fn run(args: &[String], json: bool) -> u8 {
    use hemostat_sensor_freebsd::telemetry;

    let ask = match parse_args(args) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("hemostat correlate: {e}");
            return crate::EXIT_USAGE;
        }
    };
    let manifest = match crate::vendor_manifest::load_with(ask.manifest.as_deref(), hemostat_sensor_linux::saferead::read_whole_file) {
        Ok(Some(m)) => m,
        Ok(None) => {
            eprintln!(
                "hemostat correlate: the firewall's store is judged again here, against the signed pfSense manifest. Pass \
                 --manifest PATH (PATH.sig beside it) or set $HEMOSTAT_MANIFEST, with the key in $HEMOSTAT_MANIFEST_PUBKEY"
            );
            return crate::EXIT_USAGE;
        }
        Err(e) => {
            eprintln!("hemostat correlate: manifest refused: {}", h(&e));
            return crate::EXIT_FAILED;
        }
    };
    let fw = match crate::sealed::open(&ask.fw, ask.fw_pin) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("hemostat correlate: the firewall's store at {} is refused: {}", h(&ask.fw), h(&e));
            return crate::EXIT_FAILED;
        }
    };
    let raw = match telemetry::Raw::from_records(fw.records.iter().map(Vec::as_slice)) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("hemostat correlate: {} is not a firewall telemetry store: {}", h(&ask.fw), h(&e));
            return crate::EXIT_FAILED;
        }
    };
    let ev = telemetry::judge(&raw, &manifest);
    drop(raw);
    let host_store = match crate::sealed::open(&ask.host, ask.host_pin) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("hemostat correlate: the host's store at {} is refused: {}", h(&ask.host), h(&e));
            return crate::EXIT_FAILED;
        }
    };
    let host = match HostFlows::from_records(host_store.records.iter().map(Vec::as_slice)) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("hemostat correlate: {} is not a host export: {}", h(&ask.host), h(&e));
            return crate::EXIT_FAILED;
        }
    };
    let st = Stores {
        fw_dir: ask.fw.clone(),
        fw_seal: fw.seal_pub,
        fw_pinned: ask.fw_pin.is_some(),
        fw_host_id: fw.host_id,
        host_dir: ask.host.clone(),
        host_seal: host_store.seal_pub,
        host_pinned: ask.host_pin.is_some(),
        host_host_id: host_store.host_id,
        hostname: host.hostname.clone(),
        manifest: format!("{} ({} paths)", manifest.release, manifest.paths()),
    };
    let r = correlate(&ev, &host, ask.skew, ask.offset, &BTreeSet::new());

    let code = if r.clock.unmeasured.is_some() { crate::EXIT_PARTIAL } else { exit_code(&st, &ev, &host) };
    if json {
        jprintln!("{}", render_json(&st, &r, code == crate::EXIT_OK));
    } else {
        print!("{}", render(&st, &r));
    }
    code
}
