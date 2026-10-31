use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

pub const SCOPE: &str = "hostflows/1";

pub const MAX_CONNTRACK: usize = 262_144;

const MAX_TABLE_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct HostSocket {

    pub proto: String,

    pub local: IpAddr,

    pub lport: u16,

    pub remote: Option<IpAddr>,

    pub rport: u16,

    pub state: String,

    pub netns: Option<String>,

    pub owner: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Iface {

    pub name: String,

    pub mac: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Netns {

    pub id: String,

    pub read: bool,

    pub found: Vec<String>,

    pub addrs: Vec<IpAddr>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Conn {

    pub proto: String,

    pub state: String,

    pub orig: (IpAddr, u16, IpAddr, u16),

    pub reply: (IpAddr, u16, IpAddr, u16),
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Unreached {

    pub proto: Option<String>,

    pub inode: u64,

    pub holders: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostFlows {

    pub now: u64,

    pub boot: u64,

    pub hostname: String,

    pub ifaces: Vec<Iface>,

    pub addrs: Vec<IpAddr>,

    pub onlink: Vec<(IpAddr, u8)>,

    pub forwarding: bool,

    pub sockets: Vec<HostSocket>,

    pub namespaces: Vec<Netns>,

    pub unreached: Vec<Unreached>,

    pub conntrack: Result<Vec<Conn>, String>,

    pub unread_tables: Vec<String>,

    pub unmapped_processes: usize,

    pub gaps: Vec<String>,
}

fn ip_text(a: &IpAddr) -> String {
    a.to_string()
}

pub fn unmap(a: IpAddr) -> IpAddr {
    match a {
        IpAddr::V6(v) => v.to_ipv4_mapped().map_or(a, IpAddr::V4),
        v4 => v4,
    }
}

fn parse_ip(s: &str) -> Option<IpAddr> {
    s.parse::<IpAddr>().ok().map(unmap)
}

impl Default for HostFlows {
    fn default() -> HostFlows {
        HostFlows {
            now: 0,
            boot: 0,
            hostname: String::new(),
            ifaces: Vec::new(),
            addrs: Vec::new(),
            onlink: Vec::new(),
            forwarding: false,
            sockets: Vec::new(),
            namespaces: Vec::new(),
            unreached: Vec::new(),
            conntrack: Err("not read".into()),
            unread_tables: Vec::new(),
            unmapped_processes: 0,
            gaps: Vec::new(),
        }
    }
}

impl HostFlows {

    pub fn records(&self) -> Vec<Vec<u8>> {
        let mut out: Vec<String> = vec![
            format!("V{SCOPE}"),
            format!("N{}", self.now),
            format!("B{}", self.boot),
            format!("H{}", self.hostname),
            format!("X{}", u8::from(self.forwarding)),
            format!("P{}", self.unmapped_processes),
        ];
        for i in &self.ifaces {
            out.push(format!("I{}\0{}", i.name, i.mac.as_deref().unwrap_or("")));
        }
        out.extend(self.addrs.iter().map(|a| format!("A{a}")));
        out.extend(self.onlink.iter().map(|(a, l)| format!("O{a}\0{l}")));
        for s in &self.sockets {
            out.push(format!(
                "S{}\0{}\0{}\0{}\0{}\0{}\0{}\0{}",
                s.proto,
                s.local,
                s.lport,
                s.remote.as_ref().map(ip_text).unwrap_or_default(),
                s.rport,
                s.state,
                s.netns.as_deref().unwrap_or(""),
                s.owner.as_deref().unwrap_or("")
            ));
        }
        for n in &self.namespaces {
            out.push(format!("M{}\0{}", n.id, u8::from(n.read)));
            out.extend(n.found.iter().map(|f| format!("m{}\0{f}", n.id)));
            out.extend(n.addrs.iter().map(|a| format!("a{}\0{a}", n.id)));
        }
        for u in &self.unreached {
            out.extend(u.holders.iter().map(|h| format!("U{}\0{h}", u.inode)));
            if let Some(p) = &u.proto {
                out.push(format!("Y{}\0{p}", u.inode));
            }
        }
        match &self.conntrack {
            Ok(c) => {
                out.push("t".into());
                for e in c {
                    let (a, b, c2, d) = e.orig;
                    let (w, x, y, z) = e.reply;
                    out.push(format!("T{}\0{}\0{a}\0{b}\0{c2}\0{d}\0{w}\0{x}\0{y}\0{z}", e.proto, e.state));
                }
            }
            Err(e) => out.push(format!("t{e}")),
        }
        out.extend(self.unread_tables.iter().map(|t| format!("R{t}")));
        out.extend(self.gaps.iter().map(|g| format!("G{g}")));
        out.into_iter().map(String::into_bytes).collect()
    }

    pub fn from_records<'a>(records: impl IntoIterator<Item = &'a [u8]>) -> Result<HostFlows, String> {
        let mut h = HostFlows::default();
        let mut scope = None;
        let mut now = None;
        let mut ns: BTreeMap<String, Netns> = BTreeMap::new();
        let mut held: BTreeMap<u64, Vec<String>> = BTreeMap::new();
        let mut protos: BTreeMap<u64, String> = BTreeMap::new();
        let mut ct: Option<Result<Vec<Conn>, String>> = None;
        for rec in records {
            let text = std::str::from_utf8(rec).map_err(|_| "a host-flows record is not UTF-8".to_string())?;
            let mut chars = text.chars();
            let kind = chars.next().ok_or("an empty record")?;
            let body = chars.as_str();
            let f: Vec<&str> = body.split('\0').collect();
            let bad = |what: &str| format!("a malformed {what} record");
            let get = |i: usize| f.get(i).copied().unwrap_or("");
            let num = |i: usize, what: &str| get(i).parse::<u64>().map_err(|_| bad(what));
            let port = |i: usize, what: &str| get(i).parse::<u16>().map_err(|_| bad(what));
            let ip = |i: usize, what: &str| parse_ip(get(i)).ok_or_else(|| bad(what));
            match kind {
                'V' => scope = Some(body.to_string()),
                'N' => now = Some(num(0, "time")?),
                'B' => h.boot = num(0, "boot")?,
                'H' => h.hostname = body.to_string(),
                'X' => h.forwarding = body == "1",
                'P' => h.unmapped_processes = usize::try_from(num(0, "count")?).unwrap_or(usize::MAX),
                'I' => h.ifaces.push(Iface { name: get(0).to_string(), mac: Some(get(1)).filter(|m| !m.is_empty()).map(str::to_string) }),
                'A' => h.addrs.push(ip(0, "address")?),
                'O' => h.onlink.push((ip(0, "prefix")?, get(1).parse().map_err(|_| bad("prefix"))?)),
                'S' => {
                    if f.len() != 8 {
                        return Err(bad("socket"));
                    }
                    h.sockets.push(HostSocket {
                        proto: get(0).to_string(),
                        local: ip(1, "socket")?,
                        lport: port(2, "socket")?,
                        remote: if get(3).is_empty() { None } else { Some(ip(3, "socket")?) },
                        rport: port(4, "socket")?,
                        state: get(5).to_string(),
                        netns: Some(get(6)).filter(|s| !s.is_empty()).map(str::to_string),
                        owner: Some(get(7)).filter(|s| !s.is_empty()).map(str::to_string),
                    });
                }
                'M' => {
                    let id = get(0).to_string();
                    ns.insert(id.clone(), Netns { id, read: get(1) == "1", found: Vec::new(), addrs: Vec::new() });
                }
                'm' => ns.get_mut(get(0)).ok_or_else(|| bad("namespace"))?.found.push(get(1).to_string()),
                'a' => {
                    let a = ip(1, "namespace address")?;
                    ns.get_mut(get(0)).ok_or_else(|| bad("namespace"))?.addrs.push(a);
                }
                'U' => held.entry(num(0, "socket")?).or_default().push(get(1).to_string()),
                'Y' => {
                    protos.insert(num(0, "socket")?, get(1).to_string());
                }
                't' => {
                    if ct.is_some() {
                        return Err(bad("conntrack"));
                    }
                    ct = Some(if body.is_empty() { Ok(Vec::new()) } else { Err(body.to_string()) });
                }
                'T' => {
                    let Some(Ok(v)) = ct.as_mut() else { return Err(bad("conntrack")) };
                    if f.len() != 10 {
                        return Err(bad("conntrack"));
                    }
                    v.push(Conn {
                        proto: get(0).to_string(),
                        state: get(1).to_string(),
                        orig: (ip(2, "conntrack")?, port(3, "conntrack")?, ip(4, "conntrack")?, port(5, "conntrack")?),
                        reply: (ip(6, "conntrack")?, port(7, "conntrack")?, ip(8, "conntrack")?, port(9, "conntrack")?),
                    });
                }
                'R' => h.unread_tables.push(body.to_string()),
                'G' => h.gaps.push(body.to_string()),
                _ => return Err("a record of a kind this build does not know".into()),
            }
        }
        match scope.as_deref() {
            Some(SCOPE) => {}
            Some(other) => return Err(format!("the store records {other:?}, not {SCOPE:?}")),
            None => return Err("the store carries no scope record".into()),
        }
        h.now = now.ok_or("the export does not say when it was made")?;
        h.namespaces = ns.into_values().collect();
        if protos.keys().any(|k| !held.contains_key(k)) {
            return Err("a socket's protocol is recorded for a socket nothing holds".into());
        }
        h.unreached = held.into_iter().map(|(inode, holders)| Unreached { proto: protos.remove(&inode), inode, holders }).collect();
        h.conntrack = ct.ok_or("the export does not say whether conntrack was read")?;
        Ok(h)
    }

    pub fn macs(&self) -> BTreeSet<&str> {
        self.ifaces.iter().filter_map(|i| i.mac.as_deref()).filter(|m| *m != "00:00:00:00:00:00").collect()
    }

    pub fn unread_namespaces(&self) -> impl Iterator<Item = &Netns> {
        self.namespaces.iter().filter(|n| !n.read)
    }
}

pub fn fib_trie_locals(text: &str) -> Vec<IpAddr> {
    let mut out = Vec::new();
    let mut last: Option<IpAddr> = None;
    for line in text.lines() {
        let t = line.trim();
        if let Some(a) = t.strip_prefix("|-- ") {
            last = parse_ip(a.trim());
        } else if t.starts_with("/32 host LOCAL") {
            if let Some(a) = last.take() {
                if !out.contains(&a) {
                    out.push(a);
                }
            }
        } else if !t.starts_with('/') {
            last = None;
        }
    }
    out
}

pub fn if_inet6(text: &str) -> Vec<(IpAddr, String)> {
    let mut out = Vec::new();
    for line in text.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        let (Some(hex), Some(name)) = (f.first(), f.get(5)) else { continue };
        if hex.len() != 32 {
            continue;
        }
        let Ok(v) = u128::from_str_radix(hex, 16) else { continue };
        out.push((IpAddr::V6(std::net::Ipv6Addr::from(v)), (*name).to_string()));
    }
    out
}

pub fn onlink_routes(text: &str) -> Vec<(IpAddr, u8)> {
    let mut out = Vec::new();
    for line in text.lines().skip(1) {
        let f: Vec<&str> = line.split_whitespace().collect();
        let (Some(dst), Some(gw), Some(mask)) = (f.get(1), f.get(2), f.get(7)) else { continue };
        let le = |s: &str| u32::from_str_radix(s, 16).ok().map(|v| std::net::Ipv4Addr::from(v.to_le_bytes()));
        let (Some(d), Some(g), Some(m)) = (le(dst), le(gw), le(mask)) else { continue };
        if !g.is_unspecified() || d.is_unspecified() {
            continue;
        }
        let len = u32::from(m).count_ones();
        let Ok(len) = u8::try_from(len) else { continue };
        let p = (IpAddr::V4(d), len);
        if !out.contains(&p) {
            out.push(p);
        }
    }
    out
}

pub fn conntrack(text: &str) -> (Vec<Conn>, usize) {
    let mut out = Vec::new();
    let mut unread = 0;
    for line in text.lines() {
        if out.len() >= MAX_CONNTRACK {
            unread += 1;
            continue;
        }
        let w: Vec<&str> = line.split_whitespace().collect();
        let Some(proto) = w.get(2).copied() else {
            unread += usize::from(!line.trim().is_empty());
            continue;
        };
        if !matches!(proto, "tcp" | "udp" | "udplite" | "sctp" | "dccp") {
            continue;
        }
        let state = if proto == "tcp" { w.get(5).copied().unwrap_or("").to_string() } else { String::new() };
        let mut tuples: Vec<(IpAddr, u16, IpAddr, u16)> = Vec::new();
        let mut cur: (Option<IpAddr>, Option<u16>, Option<IpAddr>, Option<u16>) = (None, None, None, None);
        for x in &w {
            if let Some(v) = x.strip_prefix("src=") {
                cur.0 = parse_ip(v);
            } else if let Some(v) = x.strip_prefix("dst=") {
                cur.2 = parse_ip(v);
            } else if let Some(v) = x.strip_prefix("sport=") {
                cur.1 = v.parse().ok();
            } else if let Some(v) = x.strip_prefix("dport=") {
                cur.3 = v.parse().ok();
                if let (Some(a), Some(b), Some(c), Some(d)) = cur {
                    tuples.push((a, b, c, d));
                }
                cur = (None, None, None, None);
            }
        }
        match tuples.as_slice() {
            [o, r] => out.push(Conn { proto: proto.to_string(), state, orig: *o, reply: *r }),
            _ => unread += 1,
        }
    }
    (out, unread)
}

pub fn nsfs_mounts(text: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for line in text.lines() {
        let Some((left, right)) = line.split_once(" - ") else { continue };
        if right.split_whitespace().next() != Some("nsfs") {
            continue;
        }
        let f: Vec<&str> = left.split_whitespace().collect();
        let (Some(root), Some(mp)) = (f.get(3), f.get(4)) else { continue };
        if root.starts_with("net:[") {
            out.push(((*root).to_string(), unescape_octal(mp)));
        }
    }
    out
}

fn unescape_octal(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while let Some(&c) = b.get(i) {
        let oct = b.get(i + 1..i + 4).filter(|d| c == b'\\' && d.iter().all(|x| (b'0'..=b'7').contains(x)));
        match oct.and_then(|d| u8::from_str_radix(std::str::from_utf8(d).ok()?, 8).ok()) {
            Some(v) => {
                out.push(v);
                i += 4;
            }
            None => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn inode_column(table: &str) -> Option<usize> {
    match table {
        "tcp" | "tcp6" | "udp" | "udp6" | "udplite" | "udplite6" | "raw" | "raw6" | "icmp" | "icmp6" => Some(9),
        "unix" => Some(6),
        "netlink" => Some(9),
        "packet" => Some(8),
        _ => None,
    }
}

pub const INODE_TABLES: [&str; 13] =
    ["tcp", "tcp6", "udp", "udp6", "udplite", "udplite6", "raw", "raw6", "icmp", "icmp6", "unix", "netlink", "packet"];

pub fn table_inodes(table: &str, text: &str) -> Vec<u64> {
    let Some(col) = inode_column(table) else { return Vec::new() };
    text.lines().skip(1).filter_map(|l| l.split_whitespace().nth(col)).filter_map(|v| v.parse().ok()).filter(|i| *i != 0).collect()
}

pub fn is_inet(proto: &str) -> bool {
    ["TCP", "UDP", "UDP-Lite", "UDPLITE", "RAW", "PING", "MPTCP", "SCTP", "DCCP"].iter().any(|p| proto.starts_with(p))
}

pub fn is_stream(proto: &str) -> bool {
    ["TCP", "MPTCP", "SCTP", "DCCP"].iter().any(|p| proto.starts_with(p))
}

#[cfg(target_os = "linux")]
fn sock_proto(fd_link: &std::path::Path) -> Option<String> {
    use std::os::unix::ffi::OsStrExt as _;
    let path = std::ffi::CString::new(fd_link.as_os_str().as_bytes()).ok()?;
    let mut buf = [0u8; 32];

    let n = unsafe { libc::getxattr(path.as_ptr(), c"system.sockprotoname".as_ptr(), buf.as_mut_ptr().cast(), buf.len()) };
    let n = usize::try_from(n).ok()?;
    let name = buf.get(..n)?;
    let name = name.split(|b| *b == 0).next()?;
    std::str::from_utf8(name).ok().filter(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_graphic())).map(str::to_string)
}

#[cfg(target_os = "linux")]
pub fn gather(r: &crate::overview::Report, now: u64) -> HostFlows {
    use std::fs;

    let mut h = HostFlows {
        now,
        boot: r.identity.boot_epoch,
        hostname: r.identity.hostname.clone(),
        unread_tables: r.unread_tables.clone(),
        unmapped_processes: r.unmapped_processes,
        ..HostFlows::default()
    };
    let read = |p: &str| crate::saferead::read_proc(std::path::Path::new(p), MAX_TABLE_BYTES);
    let text = |p: &str| read(p).map(|(b, _)| String::from_utf8_lossy(&b).into_owned());

    match fs::read_dir("/sys/class/net") {
        Ok(d) => {
            for e in d.flatten() {
                let name = e.file_name().to_string_lossy().into_owned();
                let mac = crate::saferead::read_kernel_text(e.path().join("address")).ok().map(|m| m.trim().to_ascii_lowercase()).filter(|m| m.len() == 17);
                h.ifaces.push(Iface { name, mac });
            }
            h.ifaces.sort();
        }
        Err(e) => h.gaps.push(format!("/sys/class/net could not be listed ({e}): no MAC is known")),
    }
    match text("/proc/net/fib_trie") {
        Ok(t) => h.addrs.extend(fib_trie_locals(&t)),
        Err(e) => h.gaps.push(format!("/proc/net/fib_trie ({e}): no IPv4 address is known")),
    }
    if let Ok(t) = text("/proc/net/if_inet6") {
        h.addrs.extend(if_inet6(&t).into_iter().map(|(a, _)| a));
    }
    h.addrs.sort();
    h.addrs.dedup();
    match text("/proc/net/route") {
        Ok(t) => h.onlink = onlink_routes(&t),
        Err(e) => h.gaps.push(format!("/proc/net/route ({e}): no on-link prefix is known")),
    }
    h.forwarding = ["/proc/sys/net/ipv4/ip_forward", "/proc/sys/net/ipv6/conf/all/forwarding"]
        .iter()
        .any(|p| text(p).is_ok_and(|v| v.trim() == "1"));

    for s in &r.sockets {
        let (Some(local), remote) = (parse_ip(&s.local), parse_ip(&s.remote)) else { continue };
        h.sockets.push(HostSocket {
            proto: s.proto.trim_end_matches('6').to_string(),
            local,
            lport: s.port,
            remote,
            rport: s.remote_port,
            state: s.state.to_string(),
            netns: s.netns.clone(),
            owner: match (&s.comm, s.pid) {
                (Some(c), Some(p)) => Some(format!("{c} (pid {p})")),
                _ => None,
            },
        });
    }
    h.sockets.sort();

    let others = crate::overview::other_netns();
    let ours = fs::read_link("/proc/self/ns/net").map(|p| p.display().to_string()).unwrap_or_default();
    let mut ns: BTreeMap<String, Netns> = BTreeMap::new();
    for (id, tasks) in &others {
        let n = ns.entry(id.clone()).or_insert_with(|| Netns { id: id.clone(), read: true, found: Vec::new(), addrs: Vec::new() });
        if let Some((pid, _)) = tasks.first() {
            n.found.push(format!("task of pid {pid} ({} task(s) in it)", tasks.len()));
        }
        for (pid, tid) in tasks.iter().take(4) {
            if let Ok(t) = text(&format!("/proc/{pid}/task/{tid}/net/fib_trie")) {
                n.addrs.extend(fib_trie_locals(&t));
                if let Ok(t6) = text(&format!("/proc/{pid}/task/{tid}/net/if_inet6")) {
                    n.addrs.extend(if_inet6(&t6).into_iter().map(|(a, _)| a));
                }
                break;
            }
        }
        n.addrs.sort();
        n.addrs.dedup();
    }
    let (fds, held_ns) = descriptor_walk();
    let mut mnt_seen = BTreeSet::new();
    for pid in std::iter::once("self".to_string()).chain(pids().into_iter().map(|p| p.to_string())) {
        let Ok(mnt) = fs::read_link(format!("/proc/{pid}/ns/mnt")) else { continue };
        if !mnt_seen.insert(mnt) {
            continue;
        }
        let Ok(t) = text(&format!("/proc/{pid}/mountinfo")) else { continue };
        for (id, mp) in nsfs_mounts(&t) {
            if id == ours {
                continue;
            }
            let n = ns.entry(id.clone()).or_insert_with(|| Netns { id: id.clone(), read: false, found: Vec::new(), addrs: Vec::new() });
            let how = format!("mount {mp}");
            if !n.found.contains(&how) {
                n.found.push(how);
            }
        }
    }
    for (id, holders) in &held_ns {
        if *id == ours {
            continue;
        }
        let n = ns.entry(id.clone()).or_insert_with(|| Netns { id: id.clone(), read: false, found: Vec::new(), addrs: Vec::new() });
        for who in holders.iter().take(4) {
            n.found.push(format!("descriptor held by {who}"));
        }
    }
    h.namespaces = ns.into_values().collect();

    let mut known: BTreeSet<u64> = BTreeSet::new();
    let tables_once = |known: &mut BTreeSet<u64>| {
        for t in INODE_TABLES {
            if let Ok(x) = text(&format!("/proc/net/{t}")) {
                known.extend(table_inodes(t, &x));
            }
            for (_, tasks) in &others {
                for (pid, tid) in tasks.iter().take(4) {
                    if let Ok(x) = text(&format!("/proc/{pid}/task/{tid}/net/{t}")) {
                        known.extend(table_inodes(t, &x));
                        break;
                    }
                }
            }
        }
    };
    tables_once(&mut known);
    let (fds2, _) = descriptor_walk();
    tables_once(&mut known);
    for (inode, (holders, at)) in fds {

        if known.contains(&inode) || !fds2.contains_key(&inode) {
            continue;
        }
        let proto = sock_proto(&at);
        if proto.as_deref().is_some_and(|p| !is_inet(p)) {
            continue;
        }
        h.unreached.push(Unreached { proto, inode, holders });
    }

    h.conntrack = match read("/proc/net/nf_conntrack") {
        Ok((b, truncated)) => {
            let (c, unread) = conntrack(&String::from_utf8_lossy(&b));
            if truncated {
                h.gaps.push("/proc/net/nf_conntrack was larger than the read cap; later entries were not read".into());
            }
            if unread > 0 {
                h.gaps.push(format!("{unread} conntrack line(s) not read"));
            }
            Ok(c)
        }

        Err(e) if e.kind() == std::io::ErrorKind::NotFound && !std::path::Path::new("/sys/module/nf_conntrack").exists() => Ok(Vec::new()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(
            "nf_conntrack is loaded, and this kernel has no /proc/net/nf_conntrack (built without NF_CONNTRACK_PROCFS): \
             the host's own NAT is not visible"
                .into(),
        ),
        Err(e) => Err(format!("/proc/net/nf_conntrack ({e})")),
    };
    h
}

#[cfg(target_os = "linux")]
fn pids() -> Vec<u32> {
    std::fs::read_dir("/proc")
        .map(|d| d.flatten().filter_map(|e| e.file_name().to_str().and_then(|n| n.parse().ok())).collect())
        .unwrap_or_default()
}

#[cfg(target_os = "linux")]
fn descriptor_walk() -> (BTreeMap<u64, (Vec<String>, std::path::PathBuf)>, BTreeMap<String, Vec<String>>) {
    let mut socks: BTreeMap<u64, (Vec<String>, std::path::PathBuf)> = BTreeMap::new();
    let mut nss: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for pid in pids() {
        let Ok(fds) = std::fs::read_dir(format!("/proc/{pid}/fd")) else { continue };
        let comm = crate::saferead::read_pid_text(format!("/proc/{pid}/comm")).map(|s| s.trim().to_string()).unwrap_or_default();
        let who = format!("{comm} (pid {pid})");
        for fd in fds.flatten() {
            let Ok(t) = std::fs::read_link(fd.path()) else { continue };
            let t = t.to_string_lossy();
            if let Some(n) = t.strip_prefix("socket:[").and_then(|r| r.strip_suffix(']')).and_then(|n| n.parse::<u64>().ok()) {
                let v = socks.entry(n).or_insert_with(|| (Vec::new(), fd.path()));
                if !v.0.contains(&who) {
                    v.0.push(who.clone());
                }
            } else if t.starts_with("net:[") {
                let v = nss.entry(t.into_owned()).or_default();
                if !v.contains(&who) {
                    v.push(who.clone());
                }
            }
        }
    }
    (socks, nss)
}
