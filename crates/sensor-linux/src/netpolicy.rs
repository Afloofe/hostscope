use std::collections::BTreeSet;

pub const DECLARATION: &str = "/etc/hemostat/network-allow";

pub const SNAPSHOT: &str = "/var/lib/hemostat/net-snapshot.nft";

pub const CONFIRM: &str = "/var/lib/hemostat/net-confirmed";

pub const PROPOSED: &str = "/var/lib/hemostat/net-proposed.nft";

pub const ROLLBACK_UNIT: &str = "hemostat-net-rollback";

pub const ROLLBACK_SHELL: &str = "/bin/sh";

pub const ARM_ID: &str = "/var/lib/hemostat/net-arm-id";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Proto {

    Tcp,

    Udp,
}

impl Proto {

    pub fn token(self) -> &'static str {
        match self {
            Proto::Tcp => "tcp",
            Proto::Udp => "udp",
        }
    }

    pub fn parse(s: &str) -> Option<Proto> {
        match s.to_ascii_lowercase().as_str() {
            "tcp" => Some(Proto::Tcp),
            "udp" => Some(Proto::Udp),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Origin {

    Mandatory(String),

    Declared,

    Listening(String),
}

impl Origin {

    pub fn removable(&self) -> bool {
        !matches!(self, Origin::Mandatory(_))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Allow {

    pub proto: Proto,

    pub port: u16,

    pub from: Option<String>,

    pub origin: Origin,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {

    pub allows: Vec<Allow>,

    pub warnings: Vec<String>,
}

fn is_address_or_cidr(s: &str) -> bool {
    !s.is_empty()
        && s.chars().all(|c| c.is_ascii_hexdigit() || c == '.' || c == ':' || c == '/')
}

pub fn parse_declaration(text: &str) -> (Vec<Allow>, Vec<String>) {
    let mut out = Vec::new();
    let mut bad = Vec::new();
    for (n, raw) in text.lines().enumerate() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let mut parts = line.split_whitespace();
        let Some(spec) = parts.next() else { continue };

        if spec == "egress" {
            continue;
        }
        let Some((p, port)) = spec.split_once('/') else {
            bad.push(format!("{DECLARATION} line {}: expected proto/port, got `{line}`", n + 1));
            continue;
        };
        let (Some(proto), Ok(port)) = (Proto::parse(p), port.parse::<u16>()) else {
            bad.push(format!("{DECLARATION} line {}: `{spec}` is not a proto/port", n + 1));
            continue;
        };

        let from = match parts.next() {
            None => None,
            Some(cidr) if is_address_or_cidr(cidr) => Some(cidr.to_string()),
            Some(other) => {
                bad.push(format!(
                    "{DECLARATION} line {}: `{other}` is not an address or a CIDR. A hostname \
                     is deliberately not accepted — it would be resolved now, by the resolver \
                     on this host, and the rule would name whatever address that returned",
                    n + 1
                ));
                continue;
            }
        };
        out.push(Allow { proto, port, from, origin: Origin::Declared });
    }
    (out, bad)
}

pub fn session_port(ssh_connection: Option<&str>) -> Option<u16> {
    ssh_connection?.split_whitespace().nth(3)?.parse().ok()
}

pub fn plan(listening: &[(Proto, u16, String)], declared: &[Allow], session: Option<u16>) -> Plan {
    let mut allows: Vec<Allow> = Vec::new();
    let mut warnings: Vec<String> = Vec::new();

    if let Some(port) = session {
        allows.push(Allow {
            proto: Proto::Tcp,
            port,
            from: None,
            origin: Origin::Mandatory(format!(
                "you are connected to this host on tcp/{port}; dropping it ends this session \
                 and there is no way back in from here"
            )),
        });
    } else {
        warnings.push(
            "SSH_CONNECTION is not set, so this looks like a local session and no inbound port \
             is being held open on its account. If you are in fact remote — through a wrapper, \
             a container, or a session that dropped the variable — STOP and check, because \
             nothing here is protecting your way in."
                .to_string(),
        );
    }

    allows.extend(declared.iter().cloned());
    for (proto, port, what) in listening {

        if declared.iter().any(|d| d.proto == *proto && d.port == *port) {
            continue;
        }
        allows.push(Allow {
            proto: *proto,
            port: *port,
            from: None,
            origin: Origin::Listening(what.clone()),
        });
    }

    allows.sort();
    allows.dedup_by(|a, b| a.proto == b.proto && a.port == b.port && a.from == b.from);

    for d in declared.iter().filter(|d| d.from.is_some()) {
        if allows.iter().any(|a| !a.origin.removable() && a.proto == d.proto && a.port == d.port) {
            warnings.push(format!(
                "{}/{} is declared as reachable only from {}, but it is the port you are \
                 connected on, so it stays open from anywhere while this session needs it",
                d.proto.token(),
                d.port,
                d.from.as_deref().unwrap_or_default()
            ));
        }
    }

    if !allows.iter().any(|a| !a.origin.removable()) {
        warnings.push(
            "no port in this plan is protecting an operator session. Do not arm this over a \
             network connection you cannot afford to lose."
                .to_string(),
        );
    }

    Plan { allows, warnings }
}

pub fn describe(o: &Origin) -> String {
    match o {
        Origin::Mandatory(why) => format!("MANDATORY — {why}"),
        Origin::Declared => format!("declared in {DECLARATION}"),
        Origin::Listening(what) => format!("in use by {what}"),
    }
}

pub fn render_nft(plan: &Plan) -> String {
    let mut s = String::new();
    s.push_str("#!/usr/sbin/nft -f\n");
    s.push_str("# Generated by HEMOSTAT. Inbound default-deny with the exceptions below.\n");
    s.push_str("# Outbound and forwarding are left alone deliberately.\n\n");
    s.push_str("table inet hemostat\ndelete table inet hemostat\n\n");
    s.push_str("table inet hemostat {\n");
    s.push_str("  chain input {\n");
    s.push_str("    type filter hook input priority 0; policy drop;\n\n");
    s.push_str("    # Always first: without these the change ends the session that made it.\n");
    s.push_str("    iif lo accept\n");
    s.push_str("    ct state established,related accept\n");
    s.push_str("    ct state invalid drop\n");

    s.push_str("    meta l4proto icmp accept\n");
    s.push_str("    meta l4proto ipv6-icmp accept\n\n");
    for a in &plan.allows {

        if a.port == 0 {
            continue;
        }
        let from = match &a.from {
            Some(cidr) if cidr.contains(':') => format!("ip6 saddr {cidr} "),
            Some(cidr) => format!("ip saddr {cidr} "),
            None => String::new(),
        };
        s.push_str(&format!(
            "    {from}{} dport {} accept  # {}\n",
            a.proto.token(),
            a.port,
            describe(&a.origin)
        ));
    }
    s.push_str("  }\n}\n");
    s
}

pub fn is_loopback(local: &str) -> bool {
    let h = local.trim();
    let h = match h.strip_prefix('[') {
        Some(rest) => rest.split(']').next().unwrap_or(rest),
        None => h,
    };
    if let Ok(ip) = h.parse::<std::net::IpAddr>() {
        return ip.is_loopback();
    }

    if let Some((host, _)) = h.rsplit_once(':') {
        if let Ok(ip) = host.parse::<std::net::IpAddr>() {
            return ip.is_loopback();
        }
    }
    false
}

pub fn ephemeral_range() -> (u16, u16) {
    std::fs::read_to_string("/proc/sys/net/ipv4/ip_local_port_range")
        .ok()
        .and_then(|t| {
            let mut it = t.split_whitespace();
            Some((it.next()?.parse().ok()?, it.next()?.parse().ok()?))
        })
        .unwrap_or((32768, 60999))
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Surface {

    pub services: Vec<(Proto, u16, String)>,

    pub ephemeral: Vec<(Proto, u16, String)>,

    pub attributed: bool,

    pub unread: Vec<String>,
}

impl Surface {

    pub fn refusal(&self) -> Option<String> {
        (!self.unread.is_empty()).then(|| {
            format!(
                "{} could not be read, so the services listening in it are not in this plan \
                 and arming default-deny would close them. A refusal on a file every user can \
                 normally read is itself worth explaining — a hooked read of /proc/net is how an \
                 implant hides its listener",
                self.unread.join(", ")
            )
        })
    }
}

pub fn survey() -> Surface {
    let snap = crate::overview::report();
    let (lo, hi) = ephemeral_range();
    let mut seen: BTreeSet<(Proto, u16)> = BTreeSet::new();
    let mut out =
        Surface { attributed: snap.mapped_any, unread: snap.unread_here(), ..Surface::default() };

    for s in snap.listeners() {
        let proto = if s.proto.starts_with("tcp") { Proto::Tcp } else { Proto::Udp };
        if is_loopback(&s.local) {
            continue;
        }
        if !seen.insert((proto, s.port)) {
            continue;
        }
        let what = match s.pid {
            Some(pid) => format!("pid {pid}"),
            None => "an unidentified process".to_string(),
        };

        if proto == Proto::Udp && s.port >= lo && s.port <= hi {
            out.ephemeral.push((proto, s.port, what));
        } else {
            out.services.push((proto, s.port, what));
        }
    }
    out
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Armed {

    pub seconds: u64,

    pub how: String,

    pub snapshot: String,
}

pub(crate) fn tool(candidates: &[&str]) -> Option<std::path::PathBuf> {
    candidates.iter().map(std::path::PathBuf::from).find(|p| p.exists())
}

fn nft_path() -> Option<std::path::PathBuf> {
    tool(&["/usr/sbin/nft", "/sbin/nft", "/usr/bin/nft", "/bin/nft"])
}

fn nft(args: &[&str]) -> Result<String, String> {
    let exe = nft_path().ok_or_else(|| {
        "nft not found in /usr/sbin, /sbin or /usr/bin — nftables does not look installed. \
         It is deliberately not searched for on $PATH: on a host whose adversary is root, a \
         planted `nft` that exits 0 would have this report a firewall that was never applied"
            .to_string()
    })?;
    let out = std::process::Command::new(&exe)
        .args(args)
        .env_clear()
        .env("LC_ALL", "C")
        .output()
        .map_err(|e| format!("could not run {}: {e}", exe.display()))?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
    }
}

pub fn current_ruleset() -> Result<String, String> {
    nft(&["list", "ruleset"])
}

pub fn arm(plan: &Plan, seconds: u64) -> Result<Armed, String> {
    arm_with_egress(plan, None, seconds)
}

pub fn arm_with_egress(
    plan: &Plan,
    egress: Option<&EgressPlan>,
    seconds: u64,
) -> Result<Armed, String> {
    arm_ruleset(&render_nft_with_egress(plan, egress), seconds)
}

pub fn arm_ruleset(rendered: &str, seconds: u64) -> Result<Armed, String> {
    if seconds < 30 {
        return Err("a rollback window under 30s is not long enough to open a second \
                    connection and confirm; use at least 60"
            .into());
    }

    if window_is_open(std::path::Path::new(SNAPSHOT), std::path::Path::new(CONFIRM)) {
        return Err(format!(
            "a rollback from an earlier arm is still pending, and arming again would \
             overwrite {SNAPSHOT} with the policy that arm is already enforcing — the only \
             way back would become the deny itself. Close the open window first: \
             `hemostat network --confirm` to keep that policy, `--revert` to put the old \
             ruleset back now, or wait for the pending rollback to fire."
        ));
    }

    let dir = std::path::Path::new(SNAPSHOT).parent().ok_or("bad snapshot path")?;
    std::fs::create_dir_all(dir).map_err(|e| format!("could not create {}: {e}", dir.display()))?;

    let before = snapshot_text(&current_ruleset()?);
    std::fs::write(SNAPSHOT, &before)
        .map_err(|e| format!("could not save the current ruleset to {SNAPSHOT}: {e}"))?;

    let id = arm_id();
    std::fs::write(ARM_ID, format!("{id}\n"))
        .map_err(|e| format!("could not write {ARM_ID}, so nothing was applied: {e}"))?;

    let _ = std::fs::remove_file(CONFIRM);

    std::fs::write(PROPOSED, rendered)
        .map_err(|e| format!("could not write {PROPOSED}: {e}"))?;

    let how = schedule_rollback(seconds, &id)?;

    if let Err(e) = nft(&["-f", PROPOSED]) {

        let _ = nft(&["-f", SNAPSHOT]);
        let _ = std::fs::write(CONFIRM, "load failed; rolled back immediately\n");
        return Err(format!(
            "the ruleset would not load, so nothing was changed and the old one is back: {e}"
        ));
    }

    Ok(Armed { seconds, how, snapshot: SNAPSHOT.to_string() })
}

fn snapshot_text(current: &str) -> String {
    format!("flush ruleset\n{current}")
}

fn window_is_open(snapshot: &std::path::Path, confirm: &std::path::Path) -> bool {
    snapshot.exists() && !confirm.exists()
}

fn rollback_script(seconds: u64, nft: &std::path::Path, id: &str) -> String {
    let nft = nft.display();
    format!(
        "sleep {seconds}; \
         cur=; read -r cur 2>/dev/null < {ARM_ID}; \
         if [ ! -f {CONFIRM} ] && {{ [ -z \"$cur\" ] || [ \"$cur\" = {id} ]; }}; then \
           {nft} -f {SNAPSHOT} || {nft} delete table inet hemostat; \
           echo 'rolled back automatically: nobody confirmed within {seconds}s' > {CONFIRM}; \
         fi"
    )
}

pub(crate) fn is_rollback(argv: &[String]) -> bool {
    nft_path().is_some_and(|nft| is_rollback_with(argv, &nft))
}

fn is_rollback_with(argv: &[String], nft: &std::path::Path) -> bool {
    let [shell, c, script] = argv else { return false };
    let seconds = script
        .strip_prefix("sleep ")
        .and_then(|rest| rest.split_once(';'))
        .and_then(|(n, _)| n.parse::<u64>().ok());

    let id = script
        .split_once("[ \"$cur\" = ")
        .and_then(|(_, rest)| rest.split_once(" ]"))
        .map(|(id, _)| id)
        .filter(|id| !id.is_empty() && id.bytes().all(|b| b.is_ascii_hexdigit()));
    shell == ROLLBACK_SHELL
        && c == "-c"
        && seconds.zip(id).is_some_and(|(n, id)| *script == rollback_script(n, nft, id))
}

fn arm_id() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    format!("{nanos:x}{:x}", std::process::id())
}

fn schedule_rollback(seconds: u64, id: &str) -> Result<String, String> {

    let nft = nft_path()
        .ok_or_else(|| "nft not found, so no rollback could be scheduled".to_string())?;
    let script = rollback_script(seconds, &nft, id);

    let unit = format!("{ROLLBACK_UNIT}-{id}");
    let sd_ok = tool(&["/usr/bin/systemd-run", "/bin/systemd-run"]).is_some_and(|exe| {
        std::process::Command::new(exe)
            .args(["--unit", &unit, "--collect", "--quiet", ROLLBACK_SHELL, "-c", &script])
            .env_clear()
            .env("LC_ALL", "C")
            .status()
            .is_ok_and(|st| st.success())
    });
    if sd_ok {
        return Ok(format!(
            "systemd transient unit `{unit}.service` — inspect it with `systemctl status \
             {unit}`; `hemostat network --confirm` disarms it"
        ));
    }

    let setsid = tool(&["/usr/bin/setsid", "/bin/setsid"]).ok_or_else(|| {
        "neither systemd-run nor setsid is available to schedule the rollback, so NOTHING \
         was applied"
            .to_string()
    })?;
    let child = std::process::Command::new(setsid)
        .args([ROLLBACK_SHELL, "-c", &script])
        .env_clear()
        .env("LC_ALL", "C")
        .spawn()
        .map_err(|e| {
            format!(
                "could not schedule the rollback ({e}), so NOTHING was applied. Applying a \
                 default-deny policy with no way back is not something this will do"
            )
        })?;
    Ok(format!(
        "detached process pid {} (no systemd here) — it holds the only automatic way back, so \
         do not kill it until you have confirmed",
        child.id()
    ))
}

pub fn confirm() -> Result<String, String> {
    if !std::path::Path::new(SNAPSHOT).exists() {
        return Err("nothing is armed — there is no snapshot to roll back to".into());
    }

    if std::path::Path::new(CONFIRM).exists() {
        let prior = crate::saferead::read_text(std::path::Path::new(CONFIRM))
            .map(|t| t.trim().to_string())
            .unwrap_or_else(|e| format!("unreadable ({e})"));
        return Err(format!(
            "there is no pending rollback to confirm — the last armed window already ended: \
             {prior}. The ruleset in {SNAPSHOT} is the one from before that window."
        ));
    }
    std::fs::write(CONFIRM, "confirmed by the operator\n")
        .map_err(|e| format!("could not write {CONFIRM}: {e}"))?;
    Ok(format!(
        "confirmed. The scheduled rollback will not fire. The previous ruleset is still in \
         {SNAPSHOT} if you want it back: `nft -f {SNAPSHOT}`"
    ))
}

pub fn revert() -> Result<String, String> {
    if !std::path::Path::new(SNAPSHOT).exists() {
        return Err(format!("no saved ruleset at {SNAPSHOT}"));
    }
    nft(&["-f", SNAPSHOT])?;
    let _ = std::fs::write(CONFIRM, "reverted by the operator\n");
    Ok(format!("restored the ruleset saved in {SNAPSHOT}"))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EgressPlan {

    pub allows: Vec<EgressAllow>,

    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EgressAllow {

    pub proto: Proto,

    pub port: Option<u16>,

    pub to: Option<String>,

    pub origin: Origin,
}

pub fn parse_egress_declaration(text: &str) -> (Vec<EgressAllow>, Vec<String>) {
    let mut out = Vec::new();
    let mut bad = Vec::new();
    for (n, raw) in text.lines().enumerate() {
        let line = raw.split('#').next().unwrap_or("").trim();
        let mut parts = line.split_whitespace();
        if parts.next() != Some("egress") {
            continue;
        }
        let at = format!("{DECLARATION} line {}", n + 1);
        let (Some(spec), Some(to), None) = (parts.next(), parts.next(), parts.next()) else {
            bad.push(format!("{at}: expected `egress proto/port destination`, got `{line}`"));
            continue;
        };
        let parsed = spec.split_once('/').and_then(|(p, port)| {
            let proto = Proto::parse(p)?;
            match port {
                "*" => Some((proto, None)),
                _ => port.parse::<u16>().ok().map(|n| (proto, Some(n))),
            }
        });
        let Some((proto, port)) = parsed else {
            bad.push(format!("{at}: `{spec}` is not a proto/port (the port may be `*`)"));
            continue;
        };
        if !is_address_or_cidr(to) {
            bad.push(format!(
                "{at}: `{to}` is not an address or a CIDR. A hostname is deliberately not \
                 accepted — it would be resolved now, by the resolver on this host"
            ));
            continue;
        }
        if to.ends_with("/0") {
            bad.push(format!("{at}: `{to}` is everywhere, which is egress isolation turned off"));
            continue;
        }
        out.push(EgressAllow { proto, port, to: Some(to.to_string()), origin: Origin::Declared });
    }
    (out, bad)
}

pub fn egress_plan(
    resolvers: &[String],
    declared: &[EgressAllow],
    dhcp: bool,
    upstreams: &[String],
) -> EgressPlan {
    let mut allows = Vec::new();
    let mut warnings = Vec::new();

    let mut usable = 0usize;

    let mut stubs: Vec<String> = Vec::new();
    let allow_dns = |allows: &mut Vec<EgressAllow>, r: &str, why: String| {
        allows.push(EgressAllow {
            proto: Proto::Udp,
            port: Some(53),
            to: Some(r.to_string()),
            origin: Origin::Mandatory(why),
        });
        allows.push(EgressAllow {
            proto: Proto::Tcp,
            port: Some(53),
            to: Some(r.to_string()),
            origin: Origin::Mandatory(format!("DNS over TCP to {r}")),
        });
    };
    for raw in resolvers {
        let Ok(ip) = raw.parse::<std::net::IpAddr>() else {
            warnings.push(format!(
                "`nameserver {raw}` in /etc/resolv.conf is not a single address, so it is NOT \
                 allowed through. A resolver the plan cannot name exactly is not one it can let \
                 DNS reach without letting everything else through too"
            ));
            continue;
        };
        if ip.is_loopback() {
            stubs.push(ip.to_string());
            continue;
        }
        usable += 1;
        let r = ip.to_string();
        allow_dns(&mut allows, &r, format!("DNS to the configured resolver {r}"));
    }

    let resolved = |s: &String| s == "127.0.0.53" || s == "127.0.0.54";
    if stubs.iter().any(resolved) {
        for raw in upstreams {
            match raw.parse::<std::net::IpAddr>() {
                Ok(ip) if !ip.is_loopback() => {
                    usable += 1;
                    let r = ip.to_string();
                    allow_dns(&mut allows, &r, format!("DNS to {r}, the upstream systemd-resolved forwards to"));
                }
                Ok(_) => {}
                Err(_) => warnings.push(format!(
                    "`nameserver {raw}` in {RESOLVED_UPSTREAMS} is not a single address, so it \
                     is NOT allowed through"
                )),
            }
        }
    }
    let unserved: Vec<&String> =
        stubs.iter().filter(|s| !resolved(s) || usable == 0).collect();

    let dns_declared = declared
        .iter()
        .any(|d| d.proto == Proto::Udp && d.port.is_none_or(|p| p == 53));
    if !unserved.is_empty() && !dns_declared {
        warnings.push(format!(
            "this host resolves through a local resolver at {} and this plan does not know \
             where that resolver sends its own queries, so they are NOT allowed out and name \
             resolution will stop. Name the upstream in {DECLARATION} — `egress udp/53 <addr>` \
             and `egress tcp/53 <addr>` — before arming",
            unserved.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")
        ));
    }
    if usable == 0 && stubs.is_empty() {

        warnings.push(
            "no nameserver was found in /etc/resolv.conf, so this plan allows no DNS at all. \
             If anything on this host resolves names, it will stop"
                .into(),
        );
    }

    allows.push(EgressAllow {
        proto: Proto::Udp,
        port: Some(67),
        to: None,
        origin: Origin::Mandatory(
            if dhcp {
                "DHCP lease renewal — this host holds a lease".to_string()
            } else {
                "DHCP lease renewal — allowed unconditionally; denying it on a leased host \
                 costs the address, allowing it on a static one costs nothing"
                    .to_string()
            },
        ),
    });

    for d in declared {
        allows.push(d.clone());
    }

    warnings.push(
        "egress containment stops this host reaching anything not listed above. Outbound \
         updates, log shipping, backup agents, license checks and monitoring will all fail \
         while it is armed"
            .into(),
    );

    EgressPlan { allows, warnings }
}

pub fn resolvers() -> Vec<String> {

    let Ok(text) = crate::saferead::read_text(std::path::Path::new("/etc/resolv.conf")) else {
        return Vec::new();
    };
    parse_resolvers(&text)
}

pub const RESOLVED_UPSTREAMS: &str = "/run/systemd/resolve/resolv.conf";

pub fn resolved_upstreams() -> Vec<String> {
    crate::saferead::read_text(std::path::Path::new(RESOLVED_UPSTREAMS))
        .map(|t| parse_resolvers(&t))
        .unwrap_or_default()
}

pub fn parse_resolvers(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("").split(';').next().unwrap_or("").trim();
        if let Some(addr) = line.strip_prefix("nameserver") {
            let addr = addr.trim();
            if !addr.is_empty() && addr.len() < 64 {
                out.push(addr.to_string());
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

pub fn uses_dhcp() -> bool {
    for p in [
        "/var/lib/dhcp",
        "/var/lib/dhclient",
        "/var/lib/NetworkManager",
        "/run/systemd/netif/leases",
    ] {
        if let Ok(rd) = std::fs::read_dir(p) {
            if rd.flatten().any(|e| {
                e.file_name().to_string_lossy().contains("lease")
                    || p.contains("leases")
            }) {
                return true;
            }
        }
    }
    false
}

pub fn render_nft_with_egress(plan: &Plan, egress: Option<&EgressPlan>) -> String {
    let mut s = render_nft(plan);
    let Some(eg) = egress else {
        return s;
    };

    let tail = "  }\n}\n";
    if let Some(pos) = s.rfind(tail) {
        s.truncate(pos + tail.len());
    }
    s.push_str("\ntable inet hemostat {\n");
    s.push_str("  chain output {\n");
    s.push_str("    type filter hook output priority 0; policy drop;\n\n");
    s.push_str("    # Without these the rule ends the session that applied it.\n");
    s.push_str("    oif lo accept\n");
    s.push_str("    ct state established,related accept\n");
    s.push_str("    ct state invalid drop\n");
    s.push_str("    meta l4proto icmp accept\n");
    s.push_str("    meta l4proto ipv6-icmp accept\n\n");
    for a in &eg.allows {
        let to = match &a.to {
            Some(cidr) if cidr.contains(':') => format!("ip6 daddr {cidr} "),
            Some(cidr) => format!("ip daddr {cidr} "),
            None => String::new(),
        };
        let port = match a.port {
            Some(p) if p != 0 => format!("dport {p} "),
            _ => String::new(),
        };
        s.push_str(&format!(
            "    {to}{} {port}accept  # {}\n",
            a.proto.token(),
            describe(&a.origin)
        ));
    }
    s.push_str("  }\n}\n");
    s
}
