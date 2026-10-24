use std::collections::BTreeSet;

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
    let mut others: Vec<(u32, String)> = procs
        .iter()
        .filter(|(pid, cg, _)| *pid != target && cg == cgroup)
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
        let Ok(text) = std::fs::read_to_string(e.path().join("cgroup")) else {
            continue;
        };
        let Ok(cg) = cgroup_of(&text) else { continue };
        let comm = std::fs::read(e.path().join("comm"))
            .map_or_else(|_| "?".into(), |c| String::from_utf8_lossy(&c).trim().to_string());
        out.push((pid, cg, comm));
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

pub fn render_dest_block(dest: &str, why: &str) -> Result<String, String> {
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
    let family = if d.contains(':') { "ip6" } else { "ip" };
    Ok(format!("    {family} daddr {d} drop  # {why}\n"))
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Narrowing {

    pub processes: Vec<Occupancy>,

    pub destinations: Vec<(String, String)>,
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
            s.push_str(&render_dest_block(d, why)?);
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
