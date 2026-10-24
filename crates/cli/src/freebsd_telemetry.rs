use hemostat_sensor_freebsd::telemetry::Evidence;
use hemostat_sensor_freebsd::verdict::{self, DestVerdict, FlowRow, FlowVerdict, OutRow, Query, Verdict};

use crate::boxowned::{box_owned_json, render_box_owned};

use crate::freebsd::SealedAt;
use crate::render::{h, hex32, jesc};
use crate::{EXIT_OK, EXIT_PARTIAL};

#[cfg_attr(not(target_os = "freebsd"), allow(dead_code))]
pub(crate) const CURSOR_FILE: &str = "telemetry.cursor";

pub(crate) const DEFAULT_LIMIT: usize = 40;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Ask {

    Flows { dst: Option<std::net::IpAddr>, limit: usize },

    Verdict(Query),
}

fn value<'a>(args: &'a [String], flag: &str) -> Result<Option<&'a str>, String> {
    let Some(i) = args.iter().position(|a| a == flag) else { return Ok(None) };
    match args.get(i + 1).filter(|v| !v.starts_with("--")) {
        Some(v) => Ok(Some(v.as_str())),
        None => Err(format!("{flag} takes a value, and none was given")),
    }
}

pub(crate) fn parse_args(args: &[String]) -> Result<Ask, String> {
    const VALUED: [&str; 5] = ["--manifest", "--src", "--dst", "--limit", "--store"];

    let mut words = Vec::new();
    let mut skip = false;
    for a in args {
        if skip {
            skip = false;
            continue;
        }
        if VALUED.contains(&a.as_str()) {
            skip = true;
            continue;
        }
        if !a.starts_with("--") {
            words.push(a.as_str());
        }
    }
    let rest = match words.split_first() {
        Some((&"fw", rest)) => rest,
        _ => return Err("fw: not an fw command line".into()),
    };
    if args.iter().any(|a| a == "--store") {
        return Err("fw flows and fw verdict seal into /root/hemostat; --store is a `fw rules` flag".into());
    }
    let src = value(args, "--src")?;
    let dst = value(args, "--dst")?;
    let limit = value(args, "--limit")?;
    match rest {
        ["flows"] => {
            if src.is_some() {
                return Err("fw flows: --src is a verdict flag; use --dst to narrow the flows".into());
            }
            let dst = dst.map(|d| d.parse().map_err(|_| format!("--dst {d:?} is not an address"))).transpose()?;
            let limit = match limit {
                None => DEFAULT_LIMIT,
                Some(n) => n.parse::<usize>().ok().filter(|n| (1..=100_000).contains(n)).ok_or_else(|| format!("--limit takes 1 to 100000, not {n:?}"))?,
            };
            Ok(Ask::Flows { dst, limit })
        }
        ["verdict", target] => {
            if dst.is_some() || limit.is_some() {
                return Err("fw verdict: --dst and --limit are flows flags; the destination is the operand".into());
            }
            Ok(Ask::Verdict(Query::parse(target, src)?))
        }
        ["verdict"] => Err("fw verdict needs a destination: ADDR, ADDR:PORT, [V6]:PORT, each optionally /PROTO".into()),
        [] => Err("fw needs a subcommand: rules, flows or verdict".into()),
        [other, ..] => Err(format!("fw: {other:?} is not flows or verdict (or takes no further operands)")),
    }
}

#[derive(Debug, Clone)]
pub(crate) struct FwView {
    pub(crate) manifest: (String, usize),
    pub(crate) sealed: SealedAt,
    pub(crate) evidence: Evidence,
    pub(crate) reniced: Result<(), String>,

    pub(crate) cursor_write: Result<(), String>,
}

impl FwView {

    pub(crate) fn exit_code(&self) -> u8 {
        if self.evidence.gaps.is_empty() && self.evidence.suspect.is_empty() && self.cursor_write.is_ok() {
            EXIT_OK
        } else {
            EXIT_PARTIAL
        }
    }
}

fn standing(ev: &Evidence) -> String {
    if ev.suspect.is_empty() {
        let tools: Vec<&str> = ev.tools.iter().filter(|(s, d)| s.reports() && d.is_some()).map(|(s, _)| s.label()).collect();
        format!("VERIFIED — {} verified; filterlog and syslogd are the vendor's", tools.join(", "))
    } else {
        format!("SUSPECT — {}", ev.suspect.join("; "))
    }
}

fn header(o: &mut String, title: &str, v: &FwView) {
    use std::fmt::Write as _;
    let ev = &v.evidence;
    let _ = writeln!(o, "{title}");
    let _ = writeln!(o, "  manifest   {} ({} paths), signature checked against the pinned key", h(&v.manifest.0), v.manifest.1);
    let _ = writeln!(
        o,
        "  sealed     {} · {} records, {} KiB, sealed before any verdict and judged from the store",
        h(&v.sealed.dir),
        v.sealed.records,
        v.sealed.bytes / 1024
    );
    let _ = writeln!(o, "             seal key {} — keep it off-host", hex32(&v.sealed.seal_pub));
    let _ = writeln!(o, "  telemetry  {}", h(&standing(ev)));
    let new = ev.ring.iter().filter(|e| e.new).count();
    let rejected: usize = ev.rejects.values().sum();
    let why: Vec<String> = ev.rejects.iter().map(|(r, n)| format!("{n} {}", r.label())).collect();
    let _ = writeln!(
        o,
        "  log        {} lines read, {new} since the last sweep{} · ring {} of {}",
        ev.lines,
        if rejected > 0 { format!(", {rejected} not read ({})", why.join(", ")) } else { String::new() },
        ev.ring.len(),
        ev.ring.capacity()
    );
    let _ = writeln!(o, "             {}", h(&ev.continuity.describe(ev.cursor.as_ref())));
    if let Some(s) = &ev.states {
        let leaving = s.iter().filter(|x| x.dir == hemostat_sensor_freebsd::telemetry::filterlog::Dir::Out && x.origif.as_deref().is_some_and(|i| ev.is_wan(i))).count();
        let _ = writeln!(o, "  states     {} · {leaving} made leaving an outward interface ({})", s.len(), h(&ev.wan.join(", ")));
    }
    let _ = writeln!(o, "  who        {} neighbours, {} leases", ev.neighbours.len(), ev.leases.len());
    if let Err(e) = &v.reniced {
        let _ = writeln!(o, "  priority   NOT reniced: {}", h(e));
    }
    if let Err(e) = &v.cursor_write {
        let _ = writeln!(o, "  cursor     NOT written ({}): the next sweep cannot say whether the log continued", h(e));
    }
}

fn footer(o: &mut String, ev: &Evidence, limits: &[String]) {
    use std::fmt::Write as _;
    if !limits.is_empty() {
        let _ = writeln!(o, "\n  What the evidence could not see:");
        for l in limits {
            let _ = writeln!(o, "    - {}", h(l));
        }
    }
    for g in &ev.gaps {
        let _ = writeln!(o, "  NOT JUDGED: {}", h(g));
    }
    let _ = writeln!(
        o,
        "  Not seen by this check: a kernel that lies to pflog or pfctl; root rewriting the log and the \
         cursor together; and which LAN host really sent a flow — a lease and a neighbour entry are what \
         a host claimed (RFC-002 §4)."
    );
}

fn flow_line(f: &FlowVerdict) -> String {
    let mut s = format!("{:<8} {}", f.verdict.label(), f.key);
    if f.from_firewall {
        s.push_str("  (from the firewall itself)");
    }
    s
}

pub(crate) fn render_verdict(v: &FwView, d: &DestVerdict) -> String {
    use std::fmt::Write as _;
    let mut o = String::new();
    header(&mut o, &format!("fw verdict — did traffic to {} leave this firewall? (FreeBSD)", d.query), v);
    let suspect = if d.suspect.is_empty() { "" } else { "  [SUSPECT telemetry]" };
    let _ = writeln!(o, "\n  {:<8} {}{suspect}", d.verdict.label(), h(&d.query.to_string()));
    for f in &d.flows {
        let _ = writeln!(o, "\n  {}", h(&flow_line(f)));
        for b in &f.basis {
            let _ = writeln!(o, "           {}", h(b));
        }
        if let Some(w) = &f.who {
            let _ = writeln!(o, "           who: {}", h(w));
        }
    }
    if d.verdict == Verdict::Unknown {
        let _ = writeln!(o, "\n  UNKNOWN is not \"did not leave\": see what the evidence could not see.");
    }
    footer(&mut o, &v.evidence, &d.limits);
    o
}

fn row_line(r: &FlowRow) -> String {
    use hemostat_sensor_freebsd::telemetry::filterlog::proto;
    let dst = match (r.dst, r.dport) {
        (std::net::IpAddr::V6(a), Some(p)) => format!("[{a}]:{p}"),
        (a, Some(p)) => format!("{a}:{p}"),
        (a, None) => a.to_string(),
    };
    let span = if r.first == r.last { r.first.clone() } else { format!("{} .. {}", r.first, r.last) };
    format!(
        "{:>6} {:>5}  {:<5} {:<3} {:<8} {:<5} {} -> {}  tracker {}  {span}",
        r.count,
        r.new,
        r.action.label(),
        r.dir.label(),
        r.iface,
        proto::name(r.proto),
        r.src,
        dst,
        r.tracker
    )
}

fn out_line(r: &OutRow) -> String {
    let mut s = format!("{}  {}", r.key, r.state);
    if r.from_firewall {
        s.push_str("  (from the firewall itself)");
    }
    s
}

pub(crate) fn render_flows(v: &FwView, dst: Option<std::net::IpAddr>, limit: usize) -> String {
    use std::fmt::Write as _;
    let ev = &v.evidence;
    let mut o = String::new();
    header(&mut o, "fw flows — what this firewall logged passing and blocking, and what is leaving it now (FreeBSD)", v);
    let leaving = verdict::leaving(ev, dst);
    let _ = writeln!(o, "\n  LEAVING NOW — states made leaving an outward interface ({})", leaving.len());
    for r in &leaving {
        let _ = writeln!(o, "    {}", h(&out_line(r)));
        if let Some(w) = &r.who {
            let _ = writeln!(o, "        who: {}", h(w));
        }
    }
    let rows = verdict::flow_rows(ev, dst);
    let _ = writeln!(o, "\n  LOGGED — {} groups, busiest first{}", rows.len(), if rows.len() > limit { format!(", {limit} shown (--limit)") } else { String::new() });
    let _ = writeln!(o, "    {:>6} {:>5}  action dir iface proto src -> dst  rule  when", "lines", "new");
    for r in rows.iter().take(limit) {
        let _ = writeln!(o, "    {}", h(&row_line(r)));
        if let Some(n) = ev.rule(&r.tracker).filter(|n| !n.descr.is_empty()) {
            let _ = writeln!(o, "             {:?}", h(&n.descr));
        }
    }
    let conflicts = verdict::identity_conflicts(ev);
    if !conflicts.is_empty() {
        let _ = writeln!(o, "\n  LEASE AND NEIGHBOUR DISAGREE");
        for c in &conflicts {
            let _ = writeln!(o, "    {}", h(c));
        }
    }
    let own = verdict::box_owned(ev);
    render_box_owned(&mut o, &own);
    let mut limits = verdict::limits(ev);
    limits.extend(own.limits);
    footer(&mut o, ev, &limits);
    o
}

fn jstr(s: &str) -> String {
    format!("\"{}\"", jesc(s))
}

fn jlist(v: &[String]) -> String {
    format!("[{}]", v.iter().map(|s| jstr(s)).collect::<Vec<_>>().join(","))
}

fn evidence_json(v: &FwView) -> String {
    let ev = &v.evidence;
    let tools: Vec<String> = ev
        .tools
        .iter()
        .map(|(s, d)| format!("{{\"source\":{},\"sha256\":{}}}", jstr(s.label()), d.map_or("null".to_string(), |d| jstr(&hex32(&d)))))
        .collect();
    let rejects: Vec<String> = ev.rejects.iter().map(|(r, n)| format!("{}:{n}", jstr(r.label()))).collect();
    let span = ev.ring.span().map_or("null".to_string(), |(a, b)| format!("[{},{}]", jstr(a), jstr(b)));
    format!(
        "\"manifest\":{{\"release\":{},\"paths\":{}}},\"store\":{{\"dir\":{},\"seal_pub\":{},\"records\":{},\"bytes\":{}}},\
         \"suspect\":{},\"lines\":{},\"new_lines\":{},\"rejects\":{{{}}},\"ring\":{{\"held\":{},\"capacity\":{},\"evicted\":{},\"span\":{span}}},\
         \"continuity\":{},\"states\":{},\"tools\":[{}],\"gaps\":{},\"reniced\":{},\"cursor_written\":{}",
        jstr(&v.manifest.0),
        v.manifest.1,
        jstr(&v.sealed.dir),
        jstr(&hex32(&v.sealed.seal_pub)),
        v.sealed.records,
        v.sealed.bytes,
        jlist(&ev.suspect),
        ev.lines,
        ev.ring.iter().filter(|e| e.new).count(),
        rejects.join(","),
        ev.ring.len(),
        ev.ring.capacity(),
        ev.ring.evicted().0,
        jstr(&ev.continuity.describe(ev.cursor.as_ref())),
        ev.states.as_ref().map_or("null".to_string(), |s| s.len().to_string()),
        tools.join(","),
        jlist(&ev.gaps),
        v.reniced.is_ok(),
        v.cursor_write.is_ok()
    )
}

fn flow_json(f: &FlowVerdict) -> String {
    format!(
        "{{\"verdict\":{},\"flow\":{},\"basis\":{},\"from_firewall\":{},\"who\":{}}}",
        jstr(f.verdict.label()),
        jstr(&f.key.to_string()),
        jlist(&f.basis),
        f.from_firewall,
        f.who.as_deref().map_or("null".to_string(), jstr)
    )
}

pub(crate) fn render_verdict_json(v: &FwView, d: &DestVerdict) -> String {
    format!(
        "{{\"query\":{},\"verdict\":{},\"flows\":[{}],\"limits\":{},{},\"complete\":{}}}",
        jstr(&d.query.to_string()),
        jstr(d.verdict.label()),
        d.flows.iter().map(flow_json).collect::<Vec<_>>().join(","),
        jlist(&d.limits),
        evidence_json(v),
        v.exit_code() == EXIT_OK
    )
}

pub(crate) fn render_flows_json(v: &FwView, dst: Option<std::net::IpAddr>, limit: usize) -> String {
    use hemostat_sensor_freebsd::telemetry::filterlog::proto;
    let ev = &v.evidence;
    let leaving: Vec<String> = verdict::leaving(ev, dst)
        .iter()
        .map(|r| format!("{{\"flow\":{},\"state\":{},\"from_firewall\":{},\"who\":{}}}", jstr(&r.key.to_string()), jstr(&r.state), r.from_firewall, r.who.as_deref().map_or("null".to_string(), jstr)))
        .collect();
    let rows: Vec<String> = verdict::flow_rows(ev, dst)
        .iter()
        .take(limit)
        .map(|r| {
            format!(
                "{{\"action\":{},\"dir\":{},\"iface\":{},\"proto\":{},\"src\":{},\"dst\":{},\"dport\":{},\"tracker\":{},\"rule\":{},\
                 \"count\":{},\"new\":{},\"first\":{},\"last\":{}}}",
                jstr(r.action.label()),
                jstr(r.dir.label()),
                jstr(&r.iface),
                jstr(&proto::name(r.proto)),
                jstr(&r.src.to_string()),
                jstr(&r.dst.to_string()),
                r.dport.map_or("null".to_string(), |p| p.to_string()),
                jstr(&r.tracker),
                ev.rule(&r.tracker).map_or("null".to_string(), |n| jstr(&n.descr)),
                r.count,
                r.new,
                jstr(&r.first),
                jstr(&r.last)
            )
        })
        .collect();
    format!(
        "{{\"leaving\":[{}],\"logged\":[{}],\"identity_conflicts\":{},\"box_owned\":{},\"limits\":{},{},\"complete\":{}}}",
        leaving.join(","),
        rows.join(","),
        jlist(&verdict::identity_conflicts(ev)),
        box_owned_json(&verdict::box_owned(ev)),
        jlist(&verdict::limits(ev)),
        evidence_json(v),
        v.exit_code() == EXIT_OK
    )
}

#[cfg(target_os = "freebsd")]
pub(crate) fn run(args: &[String], json: bool) -> u8 {
    use hemostat_sensor_freebsd::{saferead, store, telemetry, tools};
    use crate::{EXIT_FAILED, EXIT_USAGE};

    let ask = match parse_args(args) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("hemostat {e}");
            return EXIT_USAGE;
        }
    };
    let path = value(args, "--manifest").ok().flatten();
    let manifest = match crate::vendor_manifest::load_with(path, saferead::read_whole_file) {
        Ok(Some(m)) => m,
        Ok(None) => {
            eprintln!(
                "hemostat fw: no manifest. Pass --manifest PATH (PATH.sig beside it) or set \
                 $HEMOSTAT_MANIFEST, with the key in $HEMOSTAT_MANIFEST_PUBKEY: without one no tool \
                 can be verified and no telemetry trusted"
            );
            return EXIT_PARTIAL;
        }
        Err(e) => {
            eprintln!("hemostat fw: manifest refused: {}", h(&e));
            return EXIT_FAILED;
        }
    };
    let mut sys = tools::System::new(Some(&manifest));
    let reniced = tools::renice_self(&mut sys, 10).map_err(|e| e.to_string());
    let (id, _) = match crate::identity::gather_identity_with(&mut sys) {
        Ok(x) => x,
        Err(e) => {
            eprintln!("hemostat fw: cannot read entropy for the identity: {e}");
            return EXIT_FAILED;
        }
    };
    let st = match store::Store::open(&mut sys, std::path::Path::new("/")) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("hemostat fw: nowhere to seal the evidence, so nothing is judged: {}", h(&e.to_string()));
            return EXIT_PARTIAL;
        }
    };
    let cursor_path = st.path().join(CURSOR_FILE);
    let cursor = match saferead::read_bytes(&cursor_path, 4096) {
        Ok(b) => Ok(Some(String::from_utf8_lossy(&b).into_owned())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.to_string()),
    };
    let secs = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs());
    let mut throttle = saferead::Throttle::new(saferead::HASH_BYTES_PER_SEC);
    let raw = telemetry::collect(&mut sys, std::path::Path::new("/"), &mut throttle, cursor, secs);
    let next = raw.next_cursor();
    let records = raw.records();
    drop(raw);
    let (tag, seed) = match (crate::identity::rand16(), crate::identity::rand32()) {
        (Ok(t), Ok(s)) => (t, s),
        (Err(e), _) | (_, Err(e)) => {
            eprintln!("hemostat fw: no entropy for the store: {e}");
            return EXIT_FAILED;
        }
    };
    let tag: String = tag.iter().take(4).map(|b| format!("{b:02x}")).collect();
    let dir = st.path().join(format!("fw-{secs}-{tag}")).display().to_string();
    let bytes: u64 = records.iter().map(|r| r.len() as u64).sum();
    if let Err(e) = st.admit(bytes + 64 * 1024) {
        eprintln!("hemostat fw: {}; nothing is judged", h(&e.to_string()));
        return EXIT_PARTIAL;
    }
    let ids = crate::freebsd_drift::Ids {
        engagement: id.engagement,
        host: id.host,
        agent: id.agent,
        instance: id.instance,
        run: id.run_id,
        boot: id.boot,
    };
    let sealed = match crate::freebsd_drift::seal(&dir, seed, &records, &ids) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("hemostat fw: could not seal the evidence, so nothing is judged: {}", h(&e));
            return EXIT_FAILED;
        }
    };
    let count = records.len();
    drop(records);
    let judged = crate::freebsd_drift::open(&dir, Some(sealed.seal_pub))
        .and_then(|o| telemetry::Raw::from_records(o.records.iter().map(Vec::as_slice)));
    let raw = match judged {
        Ok(r) => r,
        Err(e) => {
            eprintln!("hemostat fw: the store at {} did not read back ({}); nothing is judged", h(&dir), h(&e));
            return EXIT_FAILED;
        }
    };

    let cursor_write = match next {
        Some(c) => write_cursor(&cursor_path, &c.encode()),
        None => Err("filter.log was not read, so there is no place to continue from".into()),
    };
    let view = FwView {
        manifest: (manifest.release.clone(), manifest.paths()),
        sealed: SealedAt { dir, seal_pub: sealed.seal_pub, records: count, bytes },
        evidence: telemetry::judge(&raw, &manifest),
        reniced,
        cursor_write,
    };
    drop(raw);
    match ask {
        Ask::Flows { dst, limit } => {
            if json {
                jprintln!("{}", render_flows_json(&view, dst, limit));
            } else {
                print!("{}", render_flows(&view, dst, limit));
            }
        }
        Ask::Verdict(q) => {
            let d = verdict::verdict(&view.evidence, &q);
            if json {
                jprintln!("{}", render_verdict_json(&view, &d));
            } else {
                print!("{}", render_verdict(&view, &d));
            }
        }
    }
    view.exit_code()
}

#[cfg(target_os = "freebsd")]
fn write_cursor(path: &std::path::Path, text: &str) -> Result<(), String> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let tmp = path.with_extension("cursor.tmp");
    let _ = std::fs::remove_file(&tmp);
    let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&tmp).map_err(|e| e.to_string())?;
    f.write_all(text.as_bytes()).and_then(|()| f.sync_all()).map_err(|e| e.to_string())?;
    std::fs::rename(&tmp, path).map_err(|e| e.to_string())
}
