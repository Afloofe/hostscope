use std::collections::BTreeMap;
use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};

const NETLINK_NETFILTER: i32 = 12;
const NLM_F_REQUEST: u16 = 0x1;
const NLM_F_DUMP: u16 = 0x300;
const NLM_F_DUMP_INTR: u16 = 0x10;
const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
const NFNL_SUBSYS_NFTABLES: u16 = 10;
const NFT_MSG_GETTABLE: u16 = 1;
const NFT_MSG_GETCHAIN: u16 = 4;
const NFT_MSG_GETRULE: u16 = 7;
const NFT_MSG_GETSET: u16 = 10;
const NFT_MSG_GETSETELEM: u16 = 13;
const NLA_TYPE_MASK: u16 = 0x3fff;

const NFTA_TABLE_NAME: u16 = 1;
const NFTA_TABLE_FLAGS: u16 = 2;
const NFT_TABLE_F_DORMANT: u32 = 0x1;
const NFTA_CHAIN_TABLE: u16 = 1;
const NFTA_CHAIN_NAME: u16 = 3;
const NFTA_CHAIN_HOOK: u16 = 4;
const NFTA_CHAIN_POLICY: u16 = 5;
const NFTA_CHAIN_TYPE: u16 = 7;
const NFTA_HOOK_HOOKNUM: u16 = 1;
const NFTA_HOOK_PRIORITY: u16 = 2;
const NFTA_HOOK_DEV: u16 = 3;
const NFTA_RULE_TABLE: u16 = 1;
const NFTA_RULE_CHAIN: u16 = 2;
const NFTA_RULE_EXPRESSIONS: u16 = 4;
const NFTA_EXPR_NAME: u16 = 1;
const NFTA_EXPR_DATA: u16 = 2;
const NFTA_SET_TABLE: u16 = 1;
const NFTA_SET_NAME: u16 = 2;
const NFTA_SET_ELEM_LIST_TABLE: u16 = 1;
const NFTA_SET_ELEM_LIST_SET: u16 = 2;
const NFTA_SET_ELEM_LIST_ELEMENTS: u16 = 3;

const ELEM_KEPT: [u16; 5] = [1, 2, 3, 9, 10];

const STATEFUL: [&str; 3] = ["counter", "quota", "last"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Chain {

    pub family: &'static str,

    pub table: String,

    pub name: String,

    pub kind: Option<String>,

    pub hook: Option<String>,

    pub policy: Option<&'static str>,

    pub rules: Vec<[u8; 32]>,

    pub table_dormant: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Ruleset {

    pub chains: Vec<Chain>,

    pub sets: BTreeMap<(&'static str, String, String), (usize, [u8; 32])>,

    pub gaps: Vec<String>,
}

impl Ruleset {

    pub fn rows(&self) -> BTreeMap<String, String> {
        let mut out = BTreeMap::new();
        for c in &self.chains {
            let mut v = String::new();
            if let Some(k) = &c.kind {
                v.push_str(&format!("type={k} "));
            }
            if let Some(h) = &c.hook {
                v.push_str(&format!("hook={h} "));
            }
            if let Some(p) = c.policy {
                v.push_str(&format!("policy={p} "));
            }
            v.push_str(&format!("rules={} digest={}", c.rules.len(), hex(&chain_digest(&c.rules))));

            if c.table_dormant {
                v.push_str(" table=dormant");
            }
            out.insert(format!("firewall/{}/{}/chain/{}", c.family, c.table, c.name), v);
        }
        for ((f, t, n), (count, d)) in &self.sets {
            out.insert(format!("firewall/{f}/{t}/set/{n}"), format!("elements={count} digest={}", hex(d)));
        }
        out
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn chain_digest(rules: &[[u8; 32]]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    for r in rules {
        h.update(r);
    }
    h.finalize().into()
}

fn family_name(f: u8) -> &'static str {
    match f {
        1 => "inet",
        2 => "ip",
        3 => "arp",
        5 => "netdev",
        7 => "bridge",
        10 => "ip6",
        _ => "unknown",
    }
}

fn hook_name(family: u8, n: u32) -> String {
    let base = ["prerouting", "input", "forward", "output", "postrouting", "ingress"];
    match (family, n) {
        (5, 0) => "ingress".into(),
        (5, 1) => "egress".into(),
        (_, n) => base.get(n as usize).map_or_else(|| format!("hook{n}"), |s| (*s).to_string()),
    }
}

fn attrs(b: &[u8]) -> Vec<(u16, &[u8])> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i + 4 <= b.len() {
        let len = u16::from_ne_bytes([b[i], b[i + 1]]) as usize;
        let ty = u16::from_ne_bytes([b[i + 2], b[i + 3]]) & NLA_TYPE_MASK;
        if len < 4 || i + len > b.len() {
            break;
        }
        out.push((ty, &b[i + 4..i + len]));
        i += (len + 3) & !3;
    }
    out
}

fn attr<'a>(list: &[(u16, &'a [u8])], ty: u16) -> Option<&'a [u8]> {
    list.iter().find(|(t, _)| *t == ty).map(|(_, v)| *v)
}

fn string(v: &[u8]) -> String {
    String::from_utf8_lossy(v.split(|b| *b == 0).next().unwrap_or_default()).into_owned()
}

fn be32(v: &[u8]) -> Option<u32> {
    Some(u32::from_be_bytes(v.get(..4)?.try_into().ok()?))
}

fn dormant_tables(msgs: &[(u8, Vec<u8>)]) -> std::collections::BTreeSet<(u8, String)> {
    msgs.iter()
        .filter_map(|(fam, m)| {
            let a = attrs(m);
            let flags = attr(&a, NFTA_TABLE_FLAGS).and_then(be32)?;
            (flags & NFT_TABLE_F_DORMANT != 0)
                .then(|| (*fam, attr(&a, NFTA_TABLE_NAME).map(string).unwrap_or_default()))
        })
        .collect()
}

fn is_anonymous(name: &str) -> bool {
    (name.starts_with("__set") || name.starts_with("__map")) && name.len() > 5
}

fn rule_digest(exprs: &[u8], anon: &BTreeMap<String, [u8; 32]>) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    for (_, elem) in attrs(exprs) {
        let e = attrs(elem);
        let name = attr(&e, NFTA_EXPR_NAME).map(string).unwrap_or_default();
        h.update(name.as_bytes());
        h.update([0]);
        if STATEFUL.contains(&name.as_str()) {
            continue;
        }
        if let Some(data) = attr(&e, NFTA_EXPR_DATA) {
            hash_normalised(&mut h, data, anon);
        }
        h.update([0xff]);
    }
    h.finalize().into()
}

fn hash_normalised(h: &mut sha2::Sha256, data: &[u8], anon: &BTreeMap<String, [u8; 32]>) {
    use sha2::Digest;
    for (ty, v) in attrs(data) {
        h.update(ty.to_ne_bytes());
        let s = string(v);
        if is_anonymous(&s) {
            h.update(b"anon:");
            h.update(anon.get(&s).copied().unwrap_or([0; 32]));
        } else {
            h.update((v.len() as u32).to_ne_bytes());
            h.update(v);
        }
    }
}

fn elements_digest(msgs: &[Vec<u8>]) -> (usize, [u8; 32]) {
    use sha2::{Digest, Sha256};
    let mut each: Vec<[u8; 32]> = Vec::new();
    for m in msgs {
        let top = attrs(m);
        let Some(list) = attr(&top, NFTA_SET_ELEM_LIST_ELEMENTS) else { continue };
        for (_, el) in attrs(list) {
            let mut h = Sha256::new();
            for (ty, v) in attrs(el) {
                if ELEM_KEPT.contains(&ty) {
                    h.update(ty.to_ne_bytes());
                    h.update((v.len() as u32).to_ne_bytes());
                    h.update(v);
                }
            }
            each.push(h.finalize().into());
        }
    }
    each.sort_unstable();
    let mut h = Sha256::new();
    for e in &each {
        h.update(e);
    }
    (each.len(), h.finalize().into())
}

fn dump(sock: &OwnedFd, msg: u16, family: u8, body: &[u8], seq: u32) -> std::io::Result<Vec<(u8, Vec<u8>)>> {
    for _ in 0..3 {
        match dump_once(sock, msg, family, body, seq)? {
            Some(v) => return Ok(v),
            None => continue,
        }
    }
    Err(std::io::Error::other("the ruleset kept changing during the dump"))
}

fn dump_once(sock: &OwnedFd, msg: u16, family: u8, body: &[u8], seq: u32) -> std::io::Result<Option<Vec<(u8, Vec<u8>)>>> {
    let len = 16 + 4 + body.len();
    let mut req = Vec::with_capacity(len);
    req.extend_from_slice(&(len as u32).to_ne_bytes());
    req.extend_from_slice(&((NFNL_SUBSYS_NFTABLES << 8) | msg).to_ne_bytes());
    req.extend_from_slice(&(NLM_F_REQUEST | NLM_F_DUMP).to_ne_bytes());
    req.extend_from_slice(&seq.to_ne_bytes());
    req.extend_from_slice(&0u32.to_ne_bytes());
    req.extend_from_slice(&[family, 0, 0, 0]);
    req.extend_from_slice(body);

    let sent = unsafe { libc::send(sock.as_raw_fd(), req.as_ptr().cast(), req.len(), 0) };
    if sent < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let mut out = Vec::new();
    let mut buf = vec![0u8; 256 * 1024];
    let mut interrupted = false;
    loop {

        let n = unsafe { libc::recv(sock.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len(), 0) };
        if n < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let mut data = buf.get(..n as usize).unwrap_or_default();
        while data.len() >= 16 {
            let mlen = u32::from_ne_bytes([data[0], data[1], data[2], data[3]]) as usize;
            let mtype = u16::from_ne_bytes([data[4], data[5]]);
            let flags = u16::from_ne_bytes([data[6], data[7]]);
            if mlen < 16 || mlen > data.len() {
                return Err(std::io::Error::other("a truncated netlink message"));
            }
            let payload = &data[16..mlen];
            if flags & NLM_F_DUMP_INTR != 0 {
                interrupted = true;
            }
            match mtype {
                NLMSG_DONE => return Ok(if interrupted { None } else { Some(out) }),
                NLMSG_ERROR => {
                    let code = payload.get(..4).map_or(0, |b| i32::from_ne_bytes([b[0], b[1], b[2], b[3]]));
                    if code == 0 {
                        return Ok(if interrupted { None } else { Some(out) });
                    }
                    return Err(std::io::Error::from_raw_os_error(-code));
                }
                _ => {
                    if payload.len() >= 4 {
                        out.push((payload[0], payload[4..].to_vec()));
                    }
                }
            }
            data = &data[((mlen + 3) & !3).min(data.len())..];
        }
    }
}

fn nla(ty: u16, v: &[u8]) -> Vec<u8> {
    let len = 4 + v.len();
    let mut out = Vec::with_capacity((len + 3) & !3);
    out.extend_from_slice(&(len as u16).to_ne_bytes());
    out.extend_from_slice(&ty.to_ne_bytes());
    out.extend_from_slice(v);
    out.resize((len + 3) & !3, 0);
    out
}

fn cstr(s: &str) -> Vec<u8> {
    let mut v = s.as_bytes().to_vec();
    v.push(0);
    v
}

pub fn read() -> std::io::Result<Ruleset> {

    let fd = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW | libc::SOCK_CLOEXEC, NETLINK_NETFILTER) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }

    let sock = unsafe { OwnedFd::from_raw_fd(fd) };

    let mut sa: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    sa.nl_family = libc::AF_NETLINK as u16;

    let rc = unsafe {
        libc::bind(
            sock.as_raw_fd(),
            core::ptr::addr_of!(sa).cast(),
            std::mem::size_of::<libc::sockaddr_nl>() as u32,
        )
    };
    if rc < 0 {
        return Err(std::io::Error::last_os_error());
    }

    let tv = libc::timeval { tv_sec: 5, tv_usec: 0 };

    unsafe {
        libc::setsockopt(
            sock.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            core::ptr::addr_of!(tv).cast(),
            std::mem::size_of::<libc::timeval>() as u32,
        );
    }

    let mut rs = Ruleset::default();

    let mut anon: BTreeMap<(u8, String, String), [u8; 32]> = BTreeMap::new();
    for (i, (fam, m)) in dump(&sock, NFT_MSG_GETSET, 0, &[], 1)?.into_iter().enumerate() {
        let a = attrs(&m);
        let table = attr(&a, NFTA_SET_TABLE).map(string).unwrap_or_default();
        let name = attr(&a, NFTA_SET_NAME).map(string).unwrap_or_default();
        let body = [nla(NFTA_SET_ELEM_LIST_TABLE, &cstr(&table)), nla(NFTA_SET_ELEM_LIST_SET, &cstr(&name))].concat();
        let elems = match dump(&sock, NFT_MSG_GETSETELEM, fam, &body, 100 + i as u32) {
            Ok(v) => v.into_iter().map(|(_, b)| b).collect::<Vec<_>>(),
            Err(e) => {
                rs.gaps.push(format!("set {table}/{name}: elements not read ({e})"));
                Vec::new()
            }
        };
        let (count, d) = elements_digest(&elems);
        if is_anonymous(&name) {
            anon.insert((fam, table, name), d);
        } else {
            rs.sets.insert((family_name(fam), table, name), (count, d));
        }
    }

    let dormant = match dump(&sock, NFT_MSG_GETTABLE, 0, &[], 4) {
        Ok(t) => dormant_tables(&t),
        Err(e) => {
            rs.gaps.push(format!(
                "table flags not read ({e}) — a table switched dormant would not show"
            ));
            std::collections::BTreeSet::new()
        }
    };

    let mut chains: BTreeMap<(u8, String, String), Chain> = BTreeMap::new();
    for (fam, m) in dump(&sock, NFT_MSG_GETCHAIN, 0, &[], 2)? {
        let a = attrs(&m);
        let table = attr(&a, NFTA_CHAIN_TABLE).map(string).unwrap_or_default();
        let name = attr(&a, NFTA_CHAIN_NAME).map(string).unwrap_or_default();
        let hook = attr(&a, NFTA_CHAIN_HOOK).map(|h| {
            let h = attrs(h);
            let num = attr(&h, NFTA_HOOK_HOOKNUM).and_then(be32).unwrap_or(u32::MAX);
            let prio = attr(&h, NFTA_HOOK_PRIORITY).and_then(be32).map_or(0, |p| p as i32);
            let dev = attr(&h, NFTA_HOOK_DEV).map(string);
            format!("{}:{prio}{}", hook_name(fam, num), dev.map_or(String::new(), |d| format!("@{d}")))
        });
        let policy = attr(&a, NFTA_CHAIN_POLICY).and_then(be32).map(|p| if p == 1 { "accept" } else { "drop" });
        let table_dormant = dormant.contains(&(fam, table.clone()));
        chains.insert(
            (fam, table.clone(), name.clone()),
            Chain {
                family: family_name(fam),
                table,
                name,
                kind: attr(&a, NFTA_CHAIN_TYPE).map(string),
                hook,
                policy,
                rules: Vec::new(),
                table_dormant,
            },
        );
    }
    for (fam, m) in dump(&sock, NFT_MSG_GETRULE, 0, &[], 3)? {
        let a = attrs(&m);
        let table = attr(&a, NFTA_RULE_TABLE).map(string).unwrap_or_default();
        let chain = attr(&a, NFTA_RULE_CHAIN).map(string).unwrap_or_default();
        let local: BTreeMap<String, [u8; 32]> = anon
            .iter()
            .filter(|((f, t, _), _)| *f == fam && *t == table)
            .map(|((_, _, n), d)| (n.clone(), *d))
            .collect();
        let d = rule_digest(attr(&a, NFTA_RULE_EXPRESSIONS).unwrap_or_default(), &local);
        if let Some(c) = chains.get_mut(&(fam, table, chain)) {
            c.rules.push(d);
        }
    }
    rs.chains = chains.into_values().collect();
    if legacy_tables_in_use() {
        rs.gaps.push(
            "legacy iptables (x_tables) tables are loaded, and their rules are not read — only \
             the nftables backend is"
                .into(),
        );
    }
    Ok(rs)
}

fn legacy_tables_in_use() -> bool {
    ["/proc/net/ip_tables_names", "/proc/net/ip6_tables_names"]
        .iter()
        .any(|p| crate::saferead::read_scan_target(std::path::Path::new(p)).is_some_and(|t| !t.trim().is_empty()))
}
