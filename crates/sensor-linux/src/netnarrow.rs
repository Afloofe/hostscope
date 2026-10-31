use std::collections::BTreeSet;
use std::net::IpAddr;

use hs_core::cidr::Cidr;

pub fn cgroup_of(text: &str) -> Result<String, String> {
    let mut v2: Option<&str> = None;
    let mut v1_seen = false;
    for line in text.lines() {
        let mut f = line.splitn(3, ':');
        let (Some(_id), Some(controllers), Some(path)) = (f.next(), f.next(), f.next()) else {
            continue;
        };
        if controllers.is_empty() {
            v2 = Some(path);
        } else {
            v1_seen = true;
        }
    }
    match v2 {
        Some(p) if !p.is_empty() => Ok(p.trim_start_matches('/').to_string()),
        _ if v1_seen => Err(
            "this host uses cgroup v1, where a socket carries no single cgroup path that \
             nftables can match. Per-process egress blocking is not available here — contain \
             the process itself, or isolate the host"
                .into(),
        ),
        _ => Err("the process has no cgroup v2 path, so nothing can name it in a rule".into()),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Occupancy {

    pub cgroup: String,

    pub target: u32,

    pub others: Vec<(u32, String)>,
}

impl Occupancy {

    pub fn is_precise(&self) -> bool {
        self.others.is_empty()
    }

    pub fn caveat(&self) -> String {
        if self.is_precise() {
            return format!(
                "The cgroup `{}` holds only pid {}, so this blocks that process and nothing \
                 else.",
                self.cgroup, self.target
            );
        }
        format!(
            "THIS IS NOT ONE PROCESS. nftables can only name a cgroup, and `{}` holds {} other \
             process(es) which will ALSO lose outbound network: {}. Blocking here is blocking \
             all of them — if that is not what you want, contain the process itself instead.",
            self.cgroup,
            self.others.len(),
            self.others
                .iter()
                .map(|(p, c)| format!("{p} ({c})"))
                .collect::<Vec<_>>()
                .join(", ")
        )
    }
}

pub fn occupancy(target: u32, cgroup: &str, procs: &[(u32, String, String)]) -> Occupancy {
    let beneath = |cg: &str| cg.strip_prefix(cgroup).is_some_and(|rest| rest.starts_with('/'));
    let mut others: Vec<(u32, String)> = procs
        .iter()
        .filter(|(pid, cg, _)| *pid != target && (cg == cgroup || beneath(cg)))
        .map(|(pid, _, comm)| (*pid, comm.clone()))
        .collect();
    others.sort_unstable();
    Occupancy { cgroup: cgroup.to_string(), target, others }
}

pub fn read_cgroups() -> Vec<(u32, String, String)> {
    let Ok(dir) = std::fs::read_dir("/proc") else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for e in dir.flatten() {
        let Some(pid) = e.file_name().to_str().and_then(|n| n.parse::<u32>().ok()) else {
            continue;
        };

        let Ok(text) = crate::saferead::read_pid_text(e.path().join("cgroup")) else {
            continue;
        };
        let Ok(cg) = cgroup_of(&text) else { continue };
        let comm = crate::saferead::read_pid_text(e.path().join("comm"))
            .map_or_else(|_| "?".into(), |c| c.trim().to_string());
        out.push((pid, cg, comm));
    }
    out
}

pub const LOG_SHIPPERS: &[&str] = &[
    "rsyslogd",
    "syslog-ng",
    "systemd-journald",
    "systemd-journal-upload",
    "wazuh-agentd",
    "ossec-agentd",
];

pub const NETBIRD: &str = "netbird";

const NETBIRD_AGENT: &str = "the NetBird agent";

pub fn netbird_runs() -> bool {
    read_cgroups().iter().any(|(_, _, comm)| comm == NETBIRD)
}

pub const DATADOG_DIR: &str = "datadog-agent";

const DATADOG_ROOT_COMMS: &[&str] = &["system-probe", "security-agent"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Covered {

    pub pid: u32,

    pub comm: String,

    pub exe: Option<String>,

    pub owners: Result<Vec<String>, String>,
}

fn log_shipper(exe: Option<&str>, comm: &str) -> Option<&'static str> {
    let Some(exe) = exe else {
        if DATADOG_ROOT_COMMS.contains(&comm) {
            return Some("the DataDog agent");
        }
        if comm == NETBIRD {
            return Some(NETBIRD_AGENT);
        }

        return LOG_SHIPPERS.iter().any(|s| s.get(..15).unwrap_or(s) == comm).then_some("a log shipper");
    };

    let exe = exe.strip_suffix(" (deleted)").unwrap_or(exe);
    if exe.split('/').any(|c| c == DATADOG_DIR) {
        return Some("the DataDog agent");
    }
    let name = exe.rsplit('/').next().unwrap_or(exe);
    if name == NETBIRD {
        return Some(NETBIRD_AGENT);
    }
    LOG_SHIPPERS.contains(&name).then_some("a log shipper")
}

pub fn never_narrowed(c: &Covered) -> Option<String> {
    let who = format!("pid {} ({})", c.pid, c.comm);
    match &c.owners {
        Ok(names) => {
            if let Some(n) = names.iter().find(|n| hs_core::accounts::is_hard_protected(n)) {
                return Some(format!(
                    "{who} belongs to `{n}`: whiteteam and the DataDog accounts (dd-agent, \
                     ddagentuser, datadog) are never narrowed"
                ));
            }
        }
        Err(why) => {
            return Some(format!(
                "the account {who} belongs to could not be established ({why}), so it cannot be \
                 shown not to be the white team's or the DataDog agent's — an account a directory \
                 serves looks exactly like this. Check `ps -o user,ruser -p {}` and contain it by \
                 hand if it is neither",
                c.pid
            ));
        }
    }
    let what = log_shipper(c.exe.as_deref(), &c.comm)?;
    let why = if what == NETBIRD_AGENT {
        "the packet says NetBird's traffic is never blocked"
    } else {
        "log shipping and monitoring are never a block target"
    };
    Some(match c.exe.as_deref() {
        Some(exe) => format!("{who} runs {exe}, {what}: {why}"),
        None => format!("{who} has no executable this run could read, and carries the name of {what}: {why}"),
    })
}

pub fn covering_refusal(o: &Occupancy, covered: &[Covered]) -> Option<String> {
    covered.iter().find_map(|c| {
        let why = never_narrowed(c)?;
        Some(if c.pid == o.target {
            why
        } else {
            format!(
                "the rule would name pid {}'s cgroup `{}`, which blocks every process in it and \
                 beneath it, and {why}",
                o.target, o.cgroup
            )
        })
    })
}

pub fn read_covered(o: &Occupancy, owners_of: impl Fn(u32) -> Result<Vec<String>, String>) -> Vec<Covered> {
    let pids = std::iter::once(o.target).chain(o.others.iter().map(|(p, _)| *p));
    let mut out = Vec::new();
    for pid in pids {
        let owners = owners_of(pid);
        let base = std::path::PathBuf::from(format!("/proc/{pid}"));
        if owners.is_err() && !base.exists() {
            continue;
        }
        let comm = crate::saferead::read_scan_target(&base.join("comm"))
            .map_or_else(|| "?".to_string(), |c| c.trim().to_string());
        let exe = std::fs::read_link(base.join("exe")).ok().map(|p| p.to_string_lossy().into_owned());
        out.push(Covered { pid, comm, exe, owners });
    }
    out
}

pub fn level_of(cgroup: &str) -> u32 {
    u32::try_from(cgroup.trim_matches('/').split('/').filter(|c| !c.is_empty()).count())
        .unwrap_or(1)
        .max(1)
}

const CGROUP_SAFE: &[char] = &['/', '.', '-', '_', '@', ':', '+', ',', '=', '\\'];

fn cgroup_is_quotable(cgroup: &str) -> bool {
    !cgroup.is_empty()
        && cgroup
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || CGROUP_SAFE.contains(&c))
}

pub fn render_proc_block(o: &Occupancy) -> Result<String, String> {
    if !cgroup_is_quotable(&o.cgroup) {
        return Err(format!(
            "the cgroup path for pid {} is not safe to name in a rule: {:?}. It goes inside \
             a quoted string in a ruleset this tool loads, and nftables has no way to escape \
             one — a quote ends the string wherever it appears, so a name carrying one (or a \
             space, or a control character) rewrites the rule rather than being matched by \
             it. Contain the process itself, or isolate the host",
            o.target,
            o.cgroup.chars().take(120).collect::<String>()
        ));
    }
    Ok(format!(
        "    socket cgroupv2 level {} \"{}\" drop  # pid {} and everything in its cgroup\n",
        level_of(&o.cgroup),
        o.cgroup,
        o.target
    ))
}

pub const WIDEST_V4: u8 = 24;

pub const WIDEST_V6: u8 = 56;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Width {

    #[default]
    Single,

    Subnet,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Kept {

    pub addr: IpAddr,

    pub what: String,
}

pub fn parse_dest(dest: &str, width: Width) -> Result<Cidr, String> {
    let d = dest.trim();
    if d.is_empty() {
        return Err("no destination was given".into());
    }
    let looks_numeric = d
        .chars()
        .all(|c| c.is_ascii_hexdigit() || c == '.' || c == ':' || c == '/');
    if !looks_numeric {
        return Err(format!(
            "`{d}` is not an address or a CIDR. A hostname is deliberately not accepted: it \
             would be resolved now, by the resolver on a host somebody else controls, and the \
             rule would end up naming whatever address they chose. Resolve it yourself, check \
             the answer, and pass the address"
        ));
    }
    let c = Cidr::parse(d).map_err(|e| format!("`{d}` is not one address or range: {e}"))?;
    if c.is_everything() {
        return Err(format!(
            "{c} is every address: that is egress isolation, not a narrowing. `hemostat network \
             --arm N --egress` isolates, and keeps DNS, DHCP, syslog, the Wazuh agent and the \
             DataDog agent while it does"
        ));
    }
    let (single, widest) = if c.is_v4() { (32, WIDEST_V4) } else { (128, WIDEST_V6) };
    match width {
        Width::Single if c.prefix() < single => Err(format!(
            "{c} is more than one address. --block-dest names one address: a range can hold a \
             scoring engine, a log host or a monitoring intake nobody listed, and the IRSeC packet \
             allows blocks of single IP addresses only. Name the address you mean, or — where the \
             rules of engagement allow ranges — pass --allow-subnet (up to /{WIDEST_V4} or \
             /{WIDEST_V6})"
        )),
        Width::Subnet if c.prefix() < widest => Err(format!(
            "{c} is wider than /{widest}, the widest --allow-subnet takes: name the narrower ranges \
             you mean"
        )),
        _ => Ok(c),
    }
}

pub fn kept_by(c: &Cidr, keep: &[Kept]) -> Option<String> {
    let hits: Vec<String> =
        keep.iter().filter(|k| c.contains(&k.addr)).map(|k| format!("{} ({})", k.addr, k.what)).collect();
    (!hits.is_empty()).then(|| {
        format!(
            "{c} covers {}: this host's log forwarding is never a block target. Block the \
             address you mean on its own",
            hits.join(", ")
        )
    })
}

pub fn render_dest_block(c: &Cidr, why: &str) -> String {
    let family = if c.is_v4() { "ip" } else { "ip6" };
    let single = if c.is_v4() { 32 } else { 128 };
    let to = if c.prefix() == single { c.addr().to_string() } else { c.to_string() };
    format!("    {family} daddr {to} drop  # {why}\n")
}

pub const RSYSLOG_CONF: &str = "/etc/rsyslog.conf";

pub const RSYSLOG_DIR: &str = "/etc/rsyslog.d";

fn syslog_host(s: &str) -> Option<IpAddr> {
    let s = s.trim();
    let unmapped = |a: IpAddr| match a {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(a, IpAddr::V4),
        v4 => v4,
    };
    if let Ok(a) = s.parse::<IpAddr>() {
        return Some(unmapped(a));
    }
    if let Some(rest) = s.strip_prefix('[') {
        let (a, port) = rest.split_once(']')?;
        let port_ok = port.is_empty() || port.strip_prefix(':').is_some_and(|p| p.parse::<u16>().is_ok());
        return if port_ok { a.parse().ok().map(unmapped) } else { None };
    }
    let (a, port) = s.rsplit_once(':')?;
    port.parse::<u16>().ok()?;
    a.parse().ok().map(unmapped)
}

pub fn syslog_targets(text: &str) -> Vec<IpAddr> {
    let mut out = Vec::new();
    for raw in text.lines() {
        let line = raw.trim();
        if line.starts_with('#') {
            continue;
        }
        for w in line.split_whitespace() {
            let Some(rest) = w.strip_prefix('@') else { continue };
            let rest = rest.strip_prefix('@').unwrap_or(rest);
            let rest = match rest.strip_prefix('(') {
                Some(r) => r.split_once(')').map_or("", |(_, host)| host),
                None => rest,
            };
            if let Some(a) = rest.split(';').next().and_then(syslog_host) {
                out.push(a);
            }
        }
        let lower = line.to_ascii_lowercase();
        let mut at = 0;
        while let Some(i) = lower.get(at..).and_then(|s| s.find("target")) {
            at += i + "target".len();
            let after = lower.get(at..).unwrap_or_default().trim_start();
            let Some(v) = after.strip_prefix('=').map(str::trim_start).and_then(|v| v.strip_prefix('"')) else {
                continue;
            };
            if let Some(a) = v.split_once('"').and_then(|(v, _)| syslog_host(v)) {
                out.push(a);
            }
        }
    }
    out.sort_unstable();
    out.dedup();
    out
}

pub fn read_syslog_targets() -> Result<Vec<Kept>, String> {
    use std::io::ErrorKind::NotFound;
    let mut files = vec![std::path::PathBuf::from(RSYSLOG_CONF)];
    match std::fs::read_dir(RSYSLOG_DIR) {
        Ok(rd) => {
            let mut more: Vec<std::path::PathBuf> =
                rd.flatten().map(|e| e.path()).filter(|p| p.extension().is_some_and(|x| x == "conf")).collect();
            more.sort();
            more.truncate(256);
            files.extend(more);
        }
        Err(e) if e.kind() == NotFound => {}
        Err(e) => return Err(format!("{RSYSLOG_DIR}: {e}")),
    }
    let mut out = Vec::new();
    for f in files {
        match crate::saferead::read_text(&f) {
            Ok(t) => out.extend(syslog_targets(&t).into_iter().map(|addr| Kept {
                addr,
                what: format!("a syslog server this host forwards to, in {}", f.display()),
            })),
            Err(e) if e.kind() == NotFound => {}
            Err(e) => return Err(format!("{}: {e}", f.display())),
        }
    }
    Ok(out)
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Narrowing {

    pub processes: Vec<Occupancy>,

    pub destinations: Vec<(String, String)>,

    pub width: Width,

    pub keep: Vec<Kept>,
}

impl Narrowing {

    pub fn is_empty(&self) -> bool {
        self.processes.is_empty() && self.destinations.is_empty()
    }

    pub fn caveats(&self) -> Vec<String> {
        let mut out: Vec<String> =
            self.processes.iter().filter(|o| !o.is_precise()).map(Occupancy::caveat).collect();

        if !self.is_empty() {
            out.push(
                "This does NOT cut connections that are already open. ESTABLISHED,RELATED is \
                 accepted ahead of every drop, so no live session is cut, including yours. \
                 Only NEW outbound connections are refused. A reverse shell or beacon that is \
                 connected now stays connected; to end it, stop the process."
                    .into(),
            );
        }
        if !self.processes.is_empty() {
            out.push(
                "A cgroup match follows the cgroup and not the program. A service restarted by \
                 its manager gets a FRESH cgroup and is not covered by a rule naming the old \
                 one — this holds a running process and does not survive it being restarted."
                    .into(),
            );
        }
        out
    }

    pub fn render_nft(&self) -> Result<String, String> {
        let mut s = String::from("table inet hemostat_narrow {\n");
        s.push_str("  chain output {\n");

        s.push_str("    type filter hook output priority -10; policy accept;\n\n");
        s.push_str("    # Never narrowed: loopback and the responder's own session.\n");
        s.push_str("    oif lo accept\n");
        s.push_str("    ct state established,related accept\n\n");
        for o in &self.processes {
            s.push_str(&render_proc_block(o)?);
        }

        for (d, why) in &self.destinations {
            let c = parse_dest(d, self.width)?;
            if let Some(refusal) = kept_by(&c, &self.keep) {
                return Err(refusal);
            }
            s.push_str(&render_dest_block(&c, why));
        }
        s.push_str("  }\n}\n");
        Ok(s)
    }
}

pub fn supports_cgroup_match(nft_version: &str, kernel: &str) -> Result<(), String> {
    let parse = |s: &str| -> (u32, u32, u32) {
        let mut it = s
            .split(|c: char| !c.is_ascii_digit())
            .filter(|p| !p.is_empty())
            .filter_map(|p| p.parse::<u32>().ok());
        (it.next().unwrap_or(0), it.next().unwrap_or(0), it.next().unwrap_or(0))
    };

    if parse(nft_version) < (0, 9, 8) {
        return Err(format!(
            "nftables {nft_version} has no `socket cgroupv2` match, which arrived in 0.9.8. \
             Per-process egress blocking is not available on this host"
        ));
    }
    let (kmaj, kmin, _) = parse(kernel);
    if (kmaj, kmin) < (5, 13) {
        return Err(format!(
            "this kernel is {kernel}, and the `socket cgroupv2` match needs 5.13. Per-process \
             egress blocking is not available on this host"
        ));
    }
    Ok(())
}

pub fn covered_pids(n: &Narrowing) -> BTreeSet<u32> {
    let mut out = BTreeSet::new();
    for o in &n.processes {
        out.insert(o.target);
        out.extend(o.others.iter().map(|(p, _)| *p));
    }
    out
}
