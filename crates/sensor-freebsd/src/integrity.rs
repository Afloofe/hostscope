pub mod parse;

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use hemostat_evcrypto::manifest::Manifest;
use hs_core::severity::Severity;

use crate::evidence::{Evidence, Obs, ToolObs};
use crate::posture::{Finding, Subject};
use crate::tools::{Invocation, Tool};
use parse::{LdClass, Proc, Sock};

pub const KIND: &str = "posture-integrity";

pub const SYSCTLS: [&str; 16] = [
    "kern.securelevel",
    "kern.elf64.allow_wx",
    "kern.elf32.allow_wx",
    "kern.elf64.aslr.enable",
    "kern.elf64.aslr.pie_enable",
    "kern.elf64.aslr.stack",
    "kern.elf32.aslr.enable",
    "kern.elf64.nxstack",
    "kern.elf32.nxstack",
    "security.bsd.map_at_zero",
    "security.bsd.unprivileged_proc_debug",
    "security.bsd.allow_destructive_dtrace",
    "kern.module_path",
    "kern.init_path",
    "kern.bootfile",
    "debug.kdb.current",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Probe {

    Kproc,

    Ps,

    Procstat,

    Sockstat,

    Netstat,

    States,

    Ifconfig,

    Environ,

    Kernel,
}

impl Probe {

    pub fn invocation(self) -> Invocation {
        match self {
            Probe::Kproc => Invocation::new(Tool::Sysctl, &["-b", "kern.proc.all"]),
            Probe::Ps => Invocation::new(Tool::Ps, &["-axww", "-o", "pid=", "-o", "ppid=", "-o", "state=", "-o", "comm="]),
            Probe::Procstat => Invocation::new(Tool::Procstat, &["--libxo", "json", "-a"]),
            Probe::Sockstat => Invocation::new(Tool::Sockstat, &["-46l"]),
            Probe::Netstat => Invocation::new(Tool::Netstat, &["-anW"]),
            Probe::States => Invocation::new(Tool::Pfctl, &["-ss", "-vv"]),
            Probe::Ifconfig => Invocation::new(Tool::Ifconfig, &["-a"]),
            Probe::Environ => Invocation::new(Tool::Procstat, &["--libxo", "json", "-ae"]),
            Probe::Kernel => {
                let mut a = vec!["-i", "-e"];
                a.extend(SYSCTLS);
                Invocation::new(Tool::Sysctl, &a)
            }
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Probe::Kproc => "sysctl kern.proc.all",
            Probe::Ps => "ps",
            Probe::Procstat => "procstat -a",
            Probe::Sockstat => "sockstat",
            Probe::Netstat => "netstat",
            Probe::States => "pfctl -ss",
            Probe::Ifconfig => "ifconfig",
            Probe::Environ => "procstat -ae",
            Probe::Kernel => "sysctl",
        }
    }
}

pub const STEPS: [Probe; 14] = [
    Probe::Kproc,
    Probe::Ps,
    Probe::Procstat,
    Probe::Kproc,
    Probe::Ps,
    Probe::Procstat,
    Probe::Sockstat,
    Probe::Netstat,
    Probe::States,
    Probe::Sockstat,
    Probe::Netstat,
    Probe::Ifconfig,
    Probe::Environ,
    Probe::Kernel,
];

const FIRST_NETSTAT: usize = 7;

pub const ENV_FILES: &[&str] = &[
    "/etc/login.conf",
    "/etc/login.conf.db",
    "/etc/profile",
    "/etc/csh.cshrc",
    "/etc/csh.login",
    "/root/.profile",
    "/root/.cshrc",
    "/root/.login",
    "/root/.shrc",
    "/root/.login_conf",
];

pub const MAX_FILE: u64 = 1024 * 1024;

pub const MAX_RC: usize = 512;

pub const SENSITIVE_KLDS: &[(&str, &str)] = &[
    ("ipdivert", "divert sockets: a process can take packets out of the stack, read or change them, and put them back"),
    ("dtrace", "DTrace: probes on any kernel function"),
    ("dtraceall", "DTrace with every provider: probes on any kernel function and system call"),
    ("fbt", "DTrace's function-boundary probes on every kernel function"),
    ("kinst", "DTrace's instruction-level probes inside kernel functions"),
    ("systrace", "DTrace's probes on every system call"),
    ("sdt", "DTrace's static kernel probes"),
    ("hwpmc", "hardware performance counters, readable by a process"),
    ("filemon", "a device that reports every file another process opens"),
    ("linux", "running Linux binaries"),
    ("linux64", "running Linux binaries"),
    ("linux_common", "running Linux binaries"),
    ("cuse", "character devices served by a userland process"),
];

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn step_key(step: usize, start: u64, end: u64, inv: &Invocation) -> String {
    format!("{step:02} {start}-{end} {}", crate::evidence::tool_key(inv))
}

fn digest_key(t: Tool) -> String {
    format!("tool:{}", t.path())
}

#[cfg(unix)]
pub fn collect(runner: &mut dyn crate::tools::Runner, root: &std::path::Path) -> Evidence {
    use crate::evidence::{Collector, Kind};
    let mut c = Collector::new(KIND, root);
    let t0 = std::time::Instant::now();
    let ms = |t: std::time::Instant| u64::try_from(t.duration_since(t0).as_millis()).unwrap_or(u64::MAX);
    for (step, p) in STEPS.iter().enumerate() {
        let inv = p.invocation();
        let start = ms(std::time::Instant::now());
        let r = runner.run(&inv);
        let end = ms(std::time::Instant::now());
        let t = match r {
            Ok(o) => ToolObs::Ran { status: o.status, stdout: o.stdout },
            Err(e) => ToolObs::Failed(e.to_string()),
        };
        c.ev.tools.insert(step_key(step, start, end, &inv), t);
        if let Some(d) = runner.tool_sha256(inv.tool()) {
            c.ev.obs.insert(digest_key(inv.tool()), Obs::Digest { sha256: d, len: 0 });
        }
    }

    for f in crate::persist::LOADER_FILES {
        c.file(f, MAX_FILE);
    }
    c.dir_files(crate::persist::LOADER_D, MAX_FILE);

    c.list("/etc");
    let rc: Vec<String> = c
        .ev
        .dir("/etc")
        .unwrap_or_default()
        .iter()
        .filter(|e| e.kind == Kind::File && (e.name == "rc" || e.name.starts_with("rc.")))
        .map(|e| crate::evidence::join("/etc", &e.name))
        .collect();
    for f in rc.iter().take(MAX_RC) {
        c.file(f, MAX_FILE);
    }
    for f in crate::persist::RC_CONF_FILES.iter().chain(ENV_FILES) {
        c.file(f, MAX_FILE);
    }
    for d in crate::persist::RC_D.iter().chain(crate::persist::RC_CONF_DIRS) {
        c.dir_files(d, MAX_FILE);
    }
    if rc.len() > MAX_RC {
        c.ev.obs.insert("/etc".into(), Obs::Refused(format!("{} rc files, over the {MAX_RC} read", rc.len())));
    }
    c.ev
}

#[derive(Debug, Clone)]
struct Step<'a> {
    probe: Probe,
    start: u64,
    end: u64,
    out: Result<&'a [u8], String>,
}

fn steps<'a>(ev: &'a Evidence, gaps: &mut Vec<String>) -> BTreeMap<usize, Step<'a>> {
    let mut out = BTreeMap::new();
    for (key, t) in &ev.tools {
        let parsed = (|| {
            let (n, rest) = key.split_once(' ')?;
            let (span, cmd) = rest.split_once(' ')?;
            let (a, b) = span.split_once('-')?;
            let step: usize = n.parse().ok()?;
            let probe = *STEPS.get(step)?;
            (crate::evidence::tool_key(&probe.invocation()) == cmd).then_some(())?;
            Some((step, probe, a.parse().ok()?, b.parse().ok()?))
        })();
        let Some((step, probe, start, end)) = parsed else {
            gaps.push(format!("integrity: a run of {key:?}, which this build does not make, was not used"));
            continue;
        };
        let out_ = match t {
            ToolObs::Ran { status: Some(0), stdout } => Ok(stdout.as_slice()),
            ToolObs::Ran { status: Some(c), .. } => Err(format!("{} exited {c}", probe.label())),
            ToolObs::Ran { status: None, .. } => Err(format!("{} was ended by a signal", probe.label())),
            ToolObs::Failed(why) => Err(format!("{}: {why}", probe.label())),
        };
        out.insert(step, Step { probe, start, end, out: out_ });
    }
    for (i, p) in STEPS.iter().enumerate() {
        if !out.contains_key(&i) {
            gaps.push(format!("integrity: step {i} ({}) was not run", p.label()));
        }
    }
    out
}

struct View<K> {
    probe: Probe,
    step: usize,
    seen: Option<BTreeMap<K, String>>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Miss<K> {
    key: K,
    name: String,
    missing: Probe,
    step: usize,
    seen_by: Probe,
    first: usize,
    last: usize,
}

fn bracket<K: Ord + Clone>(views: &[View<K>]) -> (Vec<Miss<K>>, BTreeSet<K>) {
    let mut all: BTreeSet<&K> = BTreeSet::new();
    for v in views {
        if let Some(s) = &v.seen {
            all.extend(s.keys());
        }
    }
    let mut misses: BTreeMap<(K, usize), Miss<K>> = BTreeMap::new();
    let mut once = BTreeSet::new();
    for k in all {
        let mut bracketed = false;
        for x in views.iter().map(|v| v.probe).collect::<BTreeSet<_>>() {
            let sightings: Vec<(usize, &String)> =
                views.iter().filter(|v| v.probe == x).filter_map(|v| Some((v.step, v.seen.as_ref()?.get(k)?))).collect();
            let (Some(&(first, name)), Some(&(last, name2))) = (sightings.first(), sightings.last()) else { continue };
            if first == last || name != name2 {
                continue;
            }
            bracketed = true;
            for y in views.iter().filter(|v| v.probe != x && v.step > first && v.step < last) {
                if let Some(s) = &y.seen {
                    if !s.contains_key(k) {
                        misses.entry((k.clone(), y.step)).or_insert_with(|| Miss {
                            key: k.clone(),
                            name: name.clone(),
                            missing: y.probe,
                            step: y.step,
                            seen_by: x,
                            first,
                            last,
                        });
                    }
                }
            }
        }
        if !bracketed {
            once.insert(k.clone());
        }
    }
    (misses.into_values().collect(), once)
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Judged {

    pub findings: Vec<Finding>,

    pub views: Vec<String>,

    pub gaps: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KldStanding {

    pub id: u32,

    pub name: String,

    pub path: Option<String>,

    pub vendor: bool,
}

pub fn judge(
    ev: &Evidence,
    agent_pid: u32,
    m: &Manifest,
    klds: Option<(&[KldStanding], &str)>,
) -> (Judged, BTreeMap<u32, String>) {
    let mut j = Judged::default();
    if ev.kind != KIND {
        j.gaps.push(format!("integrity: the evidence is of kind {:?}, not {KIND:?}; nothing in it was judged", ev.kind));
        return (j, BTreeMap::new());
    }
    let st = steps(ev, &mut j.gaps);
    processes(&st, agent_pid, &mut j);
    let socks = listeners(&st, &mut j);
    states(&st, socks.as_ref(), &mut j);
    let ctx = match klds {
        Some((k, text)) => klds_against_loader(ev, k, text, &mut j),
        None => {
            j.gaps.push("integrity: kldstat did not run, so no kernel file was held to the loader's files".into());
            BTreeMap::new()
        }
    };
    environment(ev, &st, m, &mut j);
    kernel(&st, &mut j);
    (j, ctx)
}

fn finding(severity: Severity, subject: Subject, what: String, why: String, pids: Vec<u32>) -> Finding {
    Finding { severity, subject, what, why, pids }
}

fn processes(st: &BTreeMap<usize, Step<'_>>, agent: u32, j: &mut Judged) {
    let mut views: Vec<View<u32>> = Vec::new();
    for (&step, s) in st.iter().filter(|(_, s)| matches!(s.probe, Probe::Kproc | Probe::Ps | Probe::Procstat)) {
        let parsed: Result<BTreeMap<u32, Proc>, String> = s.out.clone().and_then(|b| match s.probe {
            Probe::Kproc => parse::kinfo_procs(b),
            Probe::Ps => {
                let (p, unread) = parse::ps(&String::from_utf8_lossy(b));
                if unread > 0 {
                    j.gaps.push(format!("ps (step {step}): {unread} line(s) not understood"));
                }
                Ok(p)
            }
            _ => parse::procstat_basic(&String::from_utf8_lossy(b)),
        });
        let seen = match parsed {
            Ok(p) => Some(
                p.into_iter()

                    .filter(|(pid, q)| *pid != agent && q.ppid != agent)
                    .map(|(pid, q)| (pid, q.comm))
                    .collect(),
            ),
            Err(e) => {
                j.gaps.push(format!("{e}: the process views are compared without step {step}"));
                None
            }
        };
        views.push(View { probe: s.probe, step, seen });
    }
    let (misses, once) = bracket(&views);
    for x in &misses {
        j.findings.push(finding(
            Severity::Critical,
            Subject::ProcView,
            format!("{} (pid {})", x.name, x.key),
            format!(
                "{seen} listed it in its runs at steps {} and {}, so it existed throughout, and {missing} at step {} \
                 between them did not: one view of the process table left a live process out. Hooking one tool's \
                 way into the kernel's process list ({missing}) to hide a process looks like this",
                x.first,
                x.last,
                x.step,
                seen = x.seen_by.label(),
                missing = x.missing.label(),
            ),
            vec![x.key],
        ));
    }
    let counts: Vec<String> = views
        .iter()
        .map(|v| format!("{} {}", v.probe.label(), v.seen.as_ref().map_or("failed".to_string(), |s| s.len().to_string())))
        .collect();
    j.views.push(format!(
        "processes: {} — {} left out by a view while another bracketed it; {} seen in one run only (churn, not judged)",
        counts.join(", "),
        misses.len(),
        once.len()
    ));
}

struct Socks {
    netstat: BTreeMap<usize, Vec<Sock>>,
    listeners: Vec<Sock>,
}

fn listeners(st: &BTreeMap<usize, Step<'_>>, j: &mut Judged) -> Option<Socks> {
    let mut views: Vec<View<String>> = Vec::new();
    let mut socks = Socks { netstat: BTreeMap::new(), listeners: Vec::new() };
    for (&step, s) in st.iter().filter(|(_, s)| matches!(s.probe, Probe::Sockstat | Probe::Netstat)) {
        let parsed = s.out.clone().and_then(|b| {
            let t = String::from_utf8_lossy(b);
            if s.probe == Probe::Sockstat {
                parse::sockstat(&t)
            } else {
                parse::netstat(&t)
            }
        });
        let seen = match parsed {
            Ok((v, unread)) => {
                if unread > 0 {
                    j.gaps.push(format!("{} (step {step}): {unread} line(s) not understood", s.probe.label()));
                }
                let l: BTreeMap<String, String> = v.iter().filter(|x| x.is_listener()).map(|x| (x.key(), String::new())).collect();
                socks.listeners.extend(v.iter().filter(|x| x.is_listener()).cloned());
                if s.probe == Probe::Netstat {
                    socks.netstat.insert(step, v);
                }
                Some(l)
            }
            Err(e) => {
                j.gaps.push(format!("{e}: the listener views are compared without step {step}"));
                None
            }
        };
        views.push(View { probe: s.probe, step, seen });
    }
    let (misses, once) = bracket(&views);
    for x in &misses {
        j.findings.push(finding(
            Severity::Critical,
            Subject::SockView,
            x.key.clone(),
            format!(
                "{seen} showed this listener in its runs at steps {} and {}, and {missing} at step {} between them did \
                 not: one view of the socket table left a live listener out, which is how a hidden backdoor port looks",
                x.first,
                x.last,
                x.step,
                seen = x.seen_by.label(),
                missing = x.missing.label(),
            ),
            Vec::new(),
        ));
    }
    let counts: Vec<String> = views
        .iter()
        .map(|v| format!("{} {}", v.probe.label(), v.seen.as_ref().map_or("failed".to_string(), |s| s.len().to_string())))
        .collect();
    j.views.push(format!(
        "listeners: {} — {} left out by a view while another bracketed it; {} seen in one run only (not judged)",
        counts.join(", "),
        misses.len(),
        once.len()
    ));
    (!socks.netstat.is_empty()).then_some(socks)
}

fn same_addr(sock: &str, a: IpAddr) -> bool {
    let s = sock.split('%').next().unwrap_or(sock);
    s.parse::<IpAddr>().is_ok_and(|x| x == a || unmap(x) == unmap(a))
}

fn unmap(a: IpAddr) -> IpAddr {
    match a {
        IpAddr::V6(v) => v.to_ipv4_mapped().map_or(a, IpAddr::V4),
        v4 => v4,
    }
}

fn states(st: &BTreeMap<usize, Step<'_>>, socks: Option<&Socks>, j: &mut Judged) {
    use crate::telemetry::filterlog::proto;
    let state_step = STEPS.iter().position(|p| *p == Probe::States).unwrap_or(0);
    let Some(s) = st.get(&state_step) else { return };
    let text = match &s.out {
        Ok(b) => String::from_utf8_lossy(b).into_owned(),
        Err(e) => {
            j.gaps.push(format!("{e}: no pf state was held to the box's sockets"));
            return;
        }
    };
    let own: Vec<IpAddr> = match st.values().find(|s| s.probe == Probe::Ifconfig).map(|s| s.out.clone()) {
        Some(Ok(b)) => parse::ifconfig_addrs(&String::from_utf8_lossy(b)),
        Some(Err(e)) => {
            j.gaps.push(format!("{e}: the box's addresses are unknown, so no pf state was held to its sockets"));
            return;
        }
        None => return,
    };
    let Some(socks) = socks else {
        j.gaps.push("netstat did not run, so no pf state was held to the box's sockets".into());
        return;
    };
    let Some(first_net) = st.get(&FIRST_NETSTAT).filter(|s| s.probe == Probe::Netstat) else { return };
    let Some(net1) = socks.netstat.get(&FIRST_NETSTAT) else {
        j.gaps.push("the first netstat did not read, so no pf state can be shown to predate it".into());
        return;
    };
    let lag = s.end.saturating_sub(first_net.start);
    let table = crate::telemetry::states::parse(&text);
    if table.unread > 0 {
        j.gaps.push(format!("pfctl -ss: {} state(s) not understood", table.unread));
    }
    let mut creators: Vec<&str> = table.states.iter().filter_map(|s| s.creator.as_deref()).collect();
    creators.sort_unstable();
    creators.dedup();
    let pair = creators.len() > 1;
    let is_own = |a: IpAddr| own.contains(&a) || a.is_loopback();
    let (mut checked, mut held, mut young) = (0usize, 0usize, 0usize);
    for x in &table.states {
        if x.proto != Some(proto::TCP) || x.state != "ESTABLISHED:ESTABLISHED" || x.src_orig.is_some() || x.dst_orig.is_some() {
            continue;
        }
        let (local, peer) = if is_own(x.src.addr) {
            (x.src, x.dst)
        } else if is_own(x.dst.addr) {
            (x.dst, x.src)
        } else {
            continue;
        };
        if is_own(peer.addr) {
            continue;
        }
        let (Some(lp), Some(pp)) = (local.port, peer.port) else { continue };
        checked += 1;
        let tuple = |v: &[Sock]| {
            v.iter().any(|k| {
                k.proto.starts_with("tcp")
                    && k.lport == lp.to_string()
                    && k.fport == pp.to_string()
                    && same_addr(&k.laddr, local.addr)
                    && same_addr(&k.faddr, peer.addr)
            })
        };
        if tuple(net1) || socks.netstat.values().any(|v| tuple(v)) {
            held += 1;
            continue;
        }
        let listened = socks
            .listeners
            .iter()
            .any(|k| k.proto.starts_with("tcp") && k.lport == lp.to_string() && (k.laddr == "*" || same_addr(&k.laddr, local.addr)));
        let old = x.age.is_some_and(|a| a.saturating_mul(1000) > lag.saturating_add(1000));
        if listened || !old || pair {

            young += 1;
            continue;
        }
        j.findings.push(finding(
            Severity::Critical,
            Subject::SockView,
            format!("tcp {local} <-> {peer}"),
            format!(
                "pf holds this connection ESTABLISHED, {} s old, but netstat, run {lag} ms before pfctl -ss finished, \
                 lists no socket with these two ends and nothing listens on port {lp}: a connection the firewall itself \
                 is party to that its own socket table does not show",
                x.age.unwrap_or(0)
            ),
            Vec::new(),
        ));
    }
    if pair {
        j.views.push(format!("pf states: the table holds states from {} pf instances (a pfsync pair), so none is held against this box alone", creators.len()));
    }
    j.views.push(format!(
        "pf states: {} established TCP connection(s) with an end on this box; {held} held by a socket netstat lists, {young} too new, \
         queued or a peer's to judge",
        checked
    ));
}

fn klds_against_loader(ev: &Evidence, klds: &[KldStanding], kldstat: &str, j: &mut Judged) -> BTreeMap<u32, String> {
    let texts = crate::persist::loader_texts(ev);
    for f in crate::persist::LOADER_FILES {
        if let Some(why) = ev.unread(f).filter(|_| !matches!(ev.obs.get(*f), Some(Obs::Absent))) {
            j.gaps.push(format!("{f}: {why}; what the loader switches on is judged without it"));
        }
    }
    let modules: Vec<crate::persist::Module> = crate::persist::loader_modules(&texts).into_iter().filter(crate::persist::Module::is_kld).collect();
    let builtin: BTreeSet<String> = parse::kld_modules(kldstat).into_iter().collect();
    let stem = |n: &str| n.strip_suffix(".ko").unwrap_or(n).to_string();
    let switched_on = |k: &KldStanding| {
        modules.iter().find(|m| {
            stem(&m.name) == stem(&k.name)
                || m.named.as_deref().is_some_and(|n| k.path.as_deref() == Some(n) || n.rsplit('/').next().map(stem) == Some(stem(&k.name)))
        })
    };
    let mut ctx = BTreeMap::new();
    let (mut by_loader, mut after) = (Vec::new(), Vec::new());
    for k in klds.iter().filter(|k| k.name != "kernel") {
        let on = switched_on(k);
        if !k.vendor {
            ctx.insert(
                k.id,
                match on {
                    Some(m) => format!("{} switches it on ({}_load=\"YES\")", m.from, m.name),
                    None => "no loader file names it, so it was loaded after boot, by kldload or a script".to_string(),
                },
            );
            continue;
        }
        if on.is_some() {
            by_loader.push(k.name.clone());
            continue;
        }
        match SENSITIVE_KLDS.iter().find(|(n, _)| *n == stem(&k.name)) {
            Some((_, what)) => j.findings.push(finding(
                Severity::Warn,
                Subject::KldLoad,
                format!("{} (id {})", k.name, k.id),
                format!(
                    "the vendor's module, but no loader file names it, so it was loaded after boot; it gives {what}. \
                     pfSense loads it for no default feature: find who did"
                ),
                Vec::new(),
            )),
            None => after.push(format!("{} (id {})", k.name, k.id)),
        }
    }
    if !by_loader.is_empty() {
        j.findings.push(finding(
            Severity::Note,
            Subject::KldLoad,
            by_loader.join(", "),
            "the vendor's modules, switched on by a loader file: what the boot asked for".into(),
            Vec::new(),
        ));
    }
    if !after.is_empty() {
        j.findings.push(finding(
            Severity::Note,
            Subject::KldLoad,
            after.join(", "),
            "the vendor's modules, loaded after boot with no loader file naming them. pfSense's own code (thermal sensors, \
             limiters, IPv6 tunnels, crypto), devmatch(8) for the hardware it finds, and rc.d scripts load vendor modules \
             this way; nothing in these files is not the vendor's"
                .into(),
            Vec::new(),
        ));
    }
    let loaded = |m: &crate::persist::Module| {
        let n = stem(m.named.as_deref().and_then(|x| x.rsplit('/').next()).unwrap_or(&m.name));
        klds.iter().any(|k| stem(&k.name) == n || stem(&k.name) == stem(&m.name)) || builtin.contains(&m.name) || builtin.contains(&n)
    };
    for m in modules.iter().filter(|m| !loaded(m)) {
        j.findings.push(finding(
            Severity::Note,
            Subject::KldLoad,
            m.name.clone(),
            format!(
                "{} switches it on ({}_load=\"YES\"), and nothing of that name is loaded or built into the kernel: the \
                 loader skipped it, it was unloaded since boot, or it hides from kldstat. The first two are common (pfSense \
                 writes zfs_load on installs that never load ZFS)",
                m.from, m.name
            ),
            Vec::new(),
        ));
    }
    j.views.push(format!(
        "kernel modules: {} file(s) besides the kernel; {} switched on by a loader file, {} loaded after boot, {} not the vendor's; \
         {} loader module(s) switched on",
        klds.iter().filter(|k| k.name != "kernel").count(),
        by_loader.len(),
        after.len() + j.findings.iter().filter(|f| f.subject == Subject::KldLoad && f.severity == Severity::Warn).count(),
        ctx.len(),
        modules.len()
    ));
    ctx
}

fn is_tool_env(vars: &[String]) -> bool {
    let mut v: Vec<&str> = vars.iter().map(String::as_str).collect();
    v.sort_unstable();
    v == ["LC_ALL=C", "LD_LIBMAP_DISABLE=1", "LD_LIBRARY_PATH=/lib:/usr/lib", "PATH=/var/empty"]
}

fn ld_grade(class: LdClass) -> Severity {
    match class {
        LdClass::Inject => Severity::Critical,
        LdClass::Path => Severity::Warn,
        LdClass::Other => Severity::Note,
    }
}

fn ld_meaning(class: LdClass) -> &'static str {
    match class {
        LdClass::Inject => "it makes the runtime linker load code into, or redirect a library of, every dynamically linked program started with it",
        LdClass::Path => "it makes the runtime linker search other directories before the system's for every library",
        LdClass::Other => "it changes how the runtime linker behaves, without loading other code",
    }
}

fn environment(ev: &Evidence, st: &BTreeMap<usize, Step<'_>>, m: &Manifest, j: &mut Judged) {
    let mut files = 0usize;
    let mut mentions = 0usize;
    for (path, o) in &ev.obs {
        if path.starts_with("tool:") || path.starts_with("/boot/") {
            continue;
        }
        let Obs::Bytes(b) = o else {
            if let Obs::Refused(why) = o {
                j.gaps.push(format!("{path}: {why}; no LD_* name in it was looked for"));
            }
            continue;
        };
        files += 1;
        let lines = !path.ends_with(".db");
        let found = parse::ld_mentions(b, lines);
        if found.is_empty() {
            continue;
        }
        mentions += found.len();
        let digest: [u8; 32] = {
            use sha2::{Digest as _, Sha256};
            Sha256::digest(b).into()
        };
        let vendor = m.is_vendor(path, &digest) == Some(true);
        for x in found {
            let class = parse::ld_class(&x.name);
            let (sev, why) = if vendor {
                (Severity::Note, format!("the vendor's file, unchanged, names {}: {}", x.name, ld_meaning(class)))
            } else if x.comment {
                (Severity::Note, format!("named on a comment line, so it sets nothing; {}", ld_meaning(class)))
            } else {
                let whose = match m.is_vendor(path, &digest) {
                    Some(false) => "a vendor file, changed",
                    _ => "a file the vendor does not ship",
                };
                (ld_grade(class), format!("{whose}, and {} in it: {}", x.name, ld_meaning(class)))
            };
            let at = if x.line > 0 { format!("{path}:{}", x.line) } else { path.clone() };
            let what = if x.text.is_empty() { format!("{at}: {}", x.name) } else { format!("{at}: {}", x.text) };
            j.findings.push(finding(sev, Subject::LoaderEnv, what, why, Vec::new()));
        }
    }
    let env_step = STEPS.iter().position(|p| *p == Probe::Environ).unwrap_or(0);
    let mut procs = 0usize;
    match st.get(&env_step).map(|s| s.out.clone()) {
        None => {}
        Some(Err(e)) => j.gaps.push(format!("{e}: no running process's environment was read")),
        Some(Ok(b)) => match parse::environments(&String::from_utf8_lossy(b)) {
            Err(e) => j.gaps.push(format!("{e}: no running process's environment was read")),
            Ok(envs) => {
                for (pid, e) in envs {
                    procs += 1;
                    let lds: Vec<&String> = e.vars.iter().filter(|v| v.starts_with("LD_")).collect();
                    if lds.is_empty() {
                        continue;
                    }
                    if is_tool_env(&e.vars) {
                        j.findings.push(finding(
                            Severity::Note,
                            Subject::LoaderEnv,
                            format!("{} (pid {pid}): {}", e.command, e.vars.join(" ")),
                            "exactly the environment this agent gives the tools it verified (the system library \
                             directories, libmap off): this sweep's own procstat, shown rather than hidden"
                                .into(),
                            vec![pid],
                        ));
                        continue;
                    }
                    for v in lds {
                        let name = v.split('=').next().unwrap_or(v);
                        let class = parse::ld_class(name);
                        let empty = v.ends_with('=');
                        let sev = if empty { Severity::Note } else { ld_grade(class) };
                        j.findings.push(finding(
                            sev,
                            Subject::LoaderEnv,
                            format!("{} (pid {pid}): {}", e.command, v.chars().take(200).collect::<String>()),
                            if empty {
                                format!("set, but empty, in a running process's environment, so it does nothing; {}", ld_meaning(class))
                            } else {
                                format!(
                                    "in a running process's environment, and passed to everything it starts: {}",
                                    ld_meaning(class)
                                )
                            },
                            vec![pid],
                        ));
                    }
                }
            }
        },
    }
    j.views.push(format!(
        "loader environment: {files} rc, login and profile file(s) and {procs} process environment(s) read; {mentions} LD_* name(s) in the files"
    ));
}

fn kernel(st: &BTreeMap<usize, Step<'_>>, j: &mut Judged) {
    let step = STEPS.iter().position(|p| *p == Probe::Kernel).unwrap_or(0);
    let v = match st.get(&step).map(|s| s.out.clone()) {
        None => return,
        Some(Err(e)) => {
            j.gaps.push(format!("{e}: the kernel's settings were not read"));
            return;
        }
        Some(Ok(b)) => parse::sysctl_e(&String::from_utf8_lossy(b)),
    };
    let mut note = |sev: Severity, what: String, why: String| j.findings.push(finding(sev, Subject::Kernel, what, why, Vec::new()));
    let missing: Vec<&str> =
        SYSCTLS.iter().copied().filter(|k| *k != "security.bsd.allow_destructive_dtrace" && !v.contains_key(*k)).collect();
    let get = |k: &str| v.get(k).cloned();
    if let Some(s) = get("kern.securelevel") {
        let n: i64 = s.parse().unwrap_or(-1);
        if n <= 0 {
            note(
                Severity::Note,
                format!("kern.securelevel={s}"),
                "module loading is allowed: at this securelevel root can kldload any module, write /dev/mem and the raw \
                 disks, and clear immutable flags. pfSense ships -1; only 1 or more refuses kldload, and nothing short of \
                 a reboot lowers it again"
                    .into(),
            );
        } else {
            note(
                Severity::Note,
                format!("kern.securelevel={s}"),
                "module loading is refused: kldload and kldunload fail, memory and raw disks cannot be written, immutable \
                 flags cannot be cleared. Higher than pfSense's -1, so someone raised it on purpose"
                    .into(),
            );
        }
    }
    for bits in ["64", "32"] {
        if let Some(s) = get(&format!("kern.elf{bits}.allow_wx")) {
            let why = if s == "0" {
                format!("{bits}-bit processes cannot map memory writable and executable at once (W^X enforced)")
            } else {
                format!(
                    "{bits}-bit processes may map memory writable and executable at once: W^X is not enforced, so injected \
                     code needs no mprotect to run. FreeBSD's and pfSense's default"
                )
            };
            note(Severity::Note, format!("kern.elf{bits}.allow_wx={s}"), why);
        }
    }
    for (k, what) in [
        ("kern.elf64.aslr.enable", "address-space layout randomisation for 64-bit processes"),
        ("kern.elf64.aslr.pie_enable", "randomised load addresses for 64-bit position-independent executables"),
        ("kern.elf64.aslr.stack", "a randomised stack for 64-bit processes"),
        ("kern.elf64.nxstack", "a non-executable stack for 64-bit processes"),
        ("kern.elf32.nxstack", "a non-executable stack for 32-bit processes"),
    ] {
        if let Some(s) = get(k) {
            if s == "0" {
                note(
                    Severity::Warn,
                    format!("{k}=0"),
                    format!("{what} is off, and pfSense ships it on: memory-corruption exploits get easier. System Tunables can set this; find who did"),
                );
            } else {
                note(Severity::Note, format!("{k}={s}"), format!("{what} is on, as pfSense ships it"));
            }
        }
    }
    if let Some(s) = get("kern.elf32.aslr.enable") {
        note(
            Severity::Note,
            format!("kern.elf32.aslr.enable={s}"),
            if s == "0" {
                "32-bit processes run without address randomisation, as pfSense ships them; the box runs none of its own".into()
            } else {
                "32-bit processes run with address randomisation".into()
            },
        );
    }
    if let Some(s) = get("security.bsd.map_at_zero") {
        if s == "0" {
            note(Severity::Note, "security.bsd.map_at_zero=0".into(), "no process can map page zero, so a kernel NULL dereference is not an exploit; pfSense's default".into());
        } else {
            note(Severity::Warn, format!("security.bsd.map_at_zero={s}"), "processes may map page zero, which makes a kernel NULL dereference exploitable; pfSense ships 0".into());
        }
    }
    if let Some(s) = get("security.bsd.unprivileged_proc_debug") {
        note(
            Severity::Note,
            format!("security.bsd.unprivileged_proc_debug={s}"),
            if s == "0" {
                "only root can ptrace or read another process's memory".into()
            } else {
                "a user may ptrace and read the memory of its own processes; pfSense's default".into()
            },
        );
    }
    if let Some(s) = v.get("security.bsd.allow_destructive_dtrace") {
        note(
            Severity::Note,
            format!("security.bsd.allow_destructive_dtrace={s}"),
            format!(
                "DTrace is loaded (this setting exists only with it), and its destructive actions are {}",
                if s == "0" { "refused" } else { "allowed: a D script can change kernel memory and stop the system" }
            ),
        );
    }
    if let Some(s) = get("kern.module_path") {
        let odd: Vec<&str> = s.split(';').filter(|d| !d.is_empty() && !d.starts_with("/boot/")).collect();
        if odd.is_empty() {
            note(Severity::Note, format!("kern.module_path={s}"), "where kldload finds a module named without a path: all under /boot".into());
        } else {
            note(
                Severity::Warn,
                format!("kern.module_path={s}"),
                format!("kldload finds a module named without a path in {} too, outside /boot, where pfSense never puts one", odd.join(", ")),
            );
        }
    }
    for (k, stock, what) in [
        ("kern.init_path", "/sbin/init:/sbin/oinit:/sbin/init.bak:/rescue/init", "the programs the kernel tries as init at boot"),
        ("kern.bootfile", "/boot/kernel/kernel", "the kernel file this boot came from"),
    ] {
        if let Some(s) = get(k) {
            if s == stock {
                note(Severity::Note, format!("{k}={s}"), format!("{what}, as pfSense ships it"));
            } else {
                note(Severity::Warn, format!("{k}={s}"), format!("{what}, changed from pfSense's {stock}"));
            }
        }
    }
    if let Some(s) = get("debug.kdb.current") {
        note(
            Severity::Note,
            format!("debug.kdb.current={s}"),
            if s.is_empty() {
                "no kernel debugger backend is active".into()
            } else {
                format!("the in-kernel debugger {s} is compiled in: from the console it can read and change kernel memory. pfSense's kernel has it")
            },
        );
    }
    if !missing.is_empty() {
        j.gaps.push(format!("sysctl printed no {}: those settings were not judged", missing.join(", ")));
    }
    j.views.push(format!("kernel: {} setting(s) read", v.len()));
}

pub fn tool_digests(ev: &Evidence) -> Vec<(String, String)> {
    ev.obs
        .iter()
        .filter_map(|(k, o)| match (k.strip_prefix("tool:"), o) {
            (Some(p), Obs::Digest { sha256, .. }) => Some((p.to_string(), hex(sha256))),
            _ => None,
        })
        .collect()
}
