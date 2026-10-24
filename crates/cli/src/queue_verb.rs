use hemostat_fleet::ingest::Layout;
use hemostat_fleet::queue::{fold_with, suggestion, transition, Action, Actor, Alert, Queue, Resolution, Sev, Transition};
use hemostat_fleet::{hex, span, utc};

use crate::fleet::{collector_scope as collector_layout, flag_values as values, ledger_ids, login, operands_after_verb};
use crate::render::{h, hex32, jesc};
use crate::{EXIT_FAILED, EXIT_OK, EXIT_POLICY, EXIT_USAGE};

const VALUED: [&str; 8] = ["--root", "--engagement", "--as", "--reason", "--export", "--out", "--manifest", "--operator-key"];

fn usage() -> u8 {
    eprintln!(
        "usage: hemostat queue [--once]\n       \
         hemostat queue list | show <ID>\n       \
         hemostat queue ack <ID> | investigate <ID>\n       \
         hemostat queue resolve <ID> --as true-positive|false-positive|benign --reason <TEXT>\n       \
         hemostat queue note <ID> --reason <TEXT>\n       \
         hemostat queue --export report|jsonl [--out <FILE>]\n  \
         all take --root <DIR> --engagement <HEX>, and --manifest <PATH> for the signed manifest the firewall's \
         stores are judged against (default: the one under <engagement>/manifests/), and --operator-key \
         SHA256:… (repeatable, or $HEMOSTAT_OPERATOR_KEY) for the responder's own keys, which the firewall's \
         accounts store does not carry"
    );
    EXIT_USAGE
}

fn acting_login() -> Result<Actor, String> {
    let (ruid, euid, name) = login();
    let Some(uid) = ruid else {
        return Err("cannot read this process's uid from /proc/self/status, so no transition could name its actor".into());
    };
    if uid == 0 || euid == Some(0) {
        return Err(
            "refusing to change the queue as root (RFC-003 §4): every transition names the login that made \
             it, and root is an account people share, so the record would name no one. Log in to the \
             collector as yourself, a member of the collector's group"
                .into(),
        );
    }
    Ok(Actor { uid, name })
}

fn session_id() -> String {
    crate::identity::rand16().map_or_else(|_| "unknown".to_string(), |b| hex(&b))
}

type Judge = crate::rejudge::FirewallJudge;

fn load(layout: &Layout, judge: &Judge) -> Result<(Queue, Option<hemostat_evcrypto::secret::Secret32>), String> {
    let rk = hemostat_fleet::readkey::load(layout.base())?;
    let q = fold_with(layout, rk.as_ref(), judge)?;
    Ok((q, rk))
}

pub(crate) fn queue(args: &[String], json: bool) -> u8 {
    let ops = operands_after_verb(args, &VALUED);
    let (layout, engagement) = match collector_layout(args, "queue") {
        Ok(l) => l,
        Err(code) => return code,
    };
    let once = |f: &str| values(args, f).last().map(|s| (*s).to_string());
    let reason = once("--reason").unwrap_or_default();

    let keys = match crate::freebsd_sweeps::operator_keys(
        args,
        std::env::var(crate::freebsd_sweeps::OPERATOR_KEY_ENV).ok().as_deref(),
    ) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("hemostat queue: {}", h(&e));
            return EXIT_USAGE;
        }
    };
    let judge = Judge::new(layout.base(), once("--manifest").as_deref(), keys);
    let judge = &judge;

    if let Some(fmt) = once("--export") {
        if !ops.is_empty() {
            return usage();
        }
        return export(&layout, judge, &engagement, &fmt, once("--out").as_deref());
    }
    let action = match ops.as_slice() {
        [] => {

            let mut preset: Vec<(&'static str, String)> =
                vec![("--engagement", engagement.iter().map(|b| format!("{b:02x}")).collect())];
            for flag in ["--root", "--manifest"] {
                if let Some(v) = once(flag) {
                    preset.push((flag, v));
                }
            }
            return tui(&layout, judge, &engagement, args.iter().any(|a| a == "--once"), &preset);
        }
        ["list"] => return list(&layout, judge, &engagement, json),
        ["show", id] => return show(&layout, judge, id, json),
        ["ack", id] => Some((Action::Ack, *id)),
        ["investigate", id] => Some((Action::Investigate, *id)),
        ["note", id] => Some((Action::Note, *id)),
        ["resolve", id] => {
            let Some(r) = once("--as").as_deref().and_then(Resolution::parse) else {
                eprintln!("hemostat queue resolve: --as takes true-positive, false-positive or benign");
                return EXIT_USAGE;
            };
            Some((Action::Resolve(r), *id))
        }
        _ => None,
    };
    let Some((action, id)) = action else { return usage() };
    let actor = match acting_login() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("hemostat queue: {e}");
            return EXIT_POLICY;
        }
    };
    let session = session_id();
    match record(&layout, judge, &engagement, &actor, &session, "cli", action, id, &reason) {
        Ok(said) => {
            if json {
                jprintln!("{{\"ok\":true,\"said\":\"{}\"}}", jesc(&said));
            } else {
                println!("{}", h(&said));
            }
            EXIT_OK
        }
        Err(e) => {
            eprintln!("hemostat queue: {}", h(&e));
            EXIT_FAILED
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn record(
    layout: &Layout,
    judge: &Judge,
    engagement: &[u8; 16],
    actor: &Actor,
    session: &str,
    via: &str,
    action: Action,
    id: &str,
    reason: &str,
) -> Result<String, String> {
    let rk = hemostat_fleet::readkey::load(layout.base())?;
    let ids = ledger_ids(*engagement)?;
    let mut entropy = crate::identity::rand32;
    let name = action.name();
    let t = Transition { id, action, reason, actor, session, via };
    let r = transition(layout, rk.as_ref(), judge, &ids, &mut entropy, &t)?;
    Ok(format!(
        "{name} {}: {} -> {}, recorded in ledger run {} as {}. Nothing was sent to any host.",
        r.id,
        r.from.name(),
        r.to.name(),
        r.run,
        actor.label()
    ))
}

fn short(b: &[u8; 32]) -> String {
    hex(b).chars().take(12).collect()
}

fn detail(a: &Alert, q: &Queue, now: i64) -> Vec<String> {
    let mut v = Vec::new();
    v.push(format!("{} {} · {}", a.max_sev.token(), a.source, a.subject));
    v.push(format!("alert {} on host {}", a.id, hex(&a.host)));
    v.push(format!(
        "state {} · owner {} · {} sighting(s): first {}, last {} (collector clock), age {}",
        a.state.name(),
        a.owner.as_deref().unwrap_or("none"),
        a.sightings.len(),
        utc(a.first_ns),
        utc(a.last_ns),
        span(now - a.first_ns)
    ));
    if a.cur_sev == a.max_sev {
        v.push(format!("grade {} (the queue never lowers it)", a.max_sev.token()));
    } else {
        v.push(format!(
            "grade {}, the highest it was ever graded; its latest sighting graded {} (the queue never lowers it)",
            a.max_sev.token(),
            a.cur_sev.token()
        ));
    }
    if a.absent_from_latest {
        v.push(
            "ABSENT FROM LATEST: the host's latest store does not show it, and its sweep ran there with no gap. \
             It stays open until a person resolves it."
                .to_string(),
        );
    }
    v.push(String::new());
    v.push("EVIDENCE (latest sighting)".to_string());
    for e in &a.evidence {
        v.push(format!("  [{}] {}", e.severity, e.what));
        if !e.locus.is_empty() {
            v.push(format!("      at {}", e.locus));
        }
        if !e.why.is_empty() {
            v.push(format!("      {}", e.why));
        }
    }
    v.push(String::new());
    v.push("STORES".to_string());
    for s in &a.sightings {
        v.push(format!(
            "  {}  {}  records {}  {}  evidence {}  ledger run {}",
            utc(s.at_ns),
            s.store,
            if s.seqs.is_empty() { "-".to_string() } else { s.seqs.iter().map(u64::to_string).collect::<Vec<_>>().join(",") },
            s.severity.token(),
            hex(&s.digest).chars().take(16).collect::<String>(),
            s.ledger_run
        ));
    }
    v.push(String::new());
    v.push("HISTORY".to_string());
    if a.history.is_empty() {
        v.push("  none: no one has acted on it".to_string());
    }
    for e in &a.history {
        v.push(format!(
            "  {}  {}  {}  {} -> {}  \"{}\"  (ledger run {}){}",
            utc(e.at_ns),
            e.actor,
            e.action,
            e.from,
            e.to,
            e.reason,
            e.ledger_run,
            if e.owner_matches { "" } else { "  NOT WRITTEN BY THIS UID: the run directory has another owner" }
        ));
    }
    v.push(String::new());
    v.push("RE-JUDGEMENT".to_string());
    v.push(match (&a.judged_here, a.source.as_str()) {
        (_, "collector") => "  the collector's own alert".to_string(),
        _ if a.origin == hemostat_fleet::queue::Origin::Join => {
            "  a join's: derived across hosts from the stores below, by the collector, from nothing a host concluded \
             about another"
                .to_string()
        }
        (Some(basis), _) => format!(
            "  judged here, by the collector's own copy of the box's pure modules, from the raw input the store \
             sealed before the box judged anything — against {basis}. The box's verdict is not in its store; \
             compare the box's own output"
        ),
        (None, _) => "  not re-judgeable: a `collect` store seals findings, not the raw input they were judged from \
                      (RFC-002 §2), so this is the host's claim as it made it"
            .to_string(),
    });
    v.push("JOIN BASIS".to_string());
    let joined = q.joins_of(a);
    if a.basis.is_empty() && joined.is_empty() {
        v.push("  none: no cross-host join reads this alert".to_string());
    }
    for l in a.basis.iter().chain(joined.iter()) {
        v.push(format!("  {l}"));
    }
    if let Some(host) = q.hosts.iter().find(|h| h.host == a.host) {
        v.push(format!("HOST  pin {} · findings readable: {}", host.pin, host.readable));
    }
    v.push(String::new());
    let (verb, ticket) = suggestion(a);
    v.push("ON THE HOST".to_string());
    v.push(format!("  look: {verb}"));
    v.push(format!("  a change needs: {ticket}"));
    v.push(
        "  Nothing in the queue reaches the host: walk there, run the verb, and bring the ticket signed off-host."
            .to_string(),
    );
    v
}

fn host_lines(q: &Queue, now: i64) -> Vec<String> {
    let mut v = Vec::new();

    v.push("COVERAGE (J4)".to_string());
    if q.joins.coverage.is_empty() {
        v.push("  no host is enrolled or heard from".to_string());
    }
    for c in &q.joins.coverage {
        v.push(format!("  {:16} {}", c.status.to_uppercase(), c.label));
        for l in &c.lines {
            v.push(format!("                   {l}"));
        }
    }
    v.push(String::new());
    if q.hosts.is_empty() {
        v.push("no host has been heard from: nothing was ingested".to_string());
    }
    for h in &q.hosts {
        v.push(if h.label.is_empty() { format!("host {}", hex(&h.host)) } else { format!("host {} — {}", hex(&h.host), h.label) });
        v.push(format!(
            "  last store received {} · last store {} · pin {} · seal {}",
            if h.last_heard_ns == 0 { "never".to_string() } else { format!("{} ({} ago)", utc(h.last_heard_ns), span(now - h.last_heard_ns)) },
            h.last_store.map_or("-".to_string(), |g| short(&g)),
            h.pin,
            h.seal.map_or("-".to_string(), |k| short(&k))
        ));
        v.push(format!(
            "  variant {} {} · {} store(s) · findings readable: {}",
            if h.variant.is_empty() { "?" } else { &h.variant },
            h.version,
            h.stores,
            h.readable
        ));
        v.extend(beacon_lines(h.beacon.as_ref(), now));
        if h.gaps.is_empty() {
            v.push("  gaps in latest: none".to_string());
        } else {
            for g in &h.gaps {
                v.push(format!("  GAP {} ({}): {}", g.source, if g.partial { "ran in part" } else { "did not run" }, g.reason));
            }
        }
        for c in &h.carried {
            v.push(format!(
                "  carried, not judged here: {} ({} store(s){}) — {}",
                c.kind,
                c.stores,
                if c.raised { ", raised as not-rejudged" } else { "" },
                c.what
            ));
        }
        v.push(String::new());
    }
    v
}

fn beacon_lines(b: Option<&hemostat_fleet::queue::Beacon>, now: i64) -> Vec<String> {
    use hemostat_fleet::heartbeat::secs;
    let Some(b) = b else {
        return vec!["  heartbeat: none recorded — no `remote --beacon` from this host has reached the ledger".to_string()];
    };
    let state = match b.state.as_str() {
        "silent" => "SILENT: nothing since the last beat for longer than the dead-after; see its alert".to_string(),
        "lossy" => format!(
            "lossy: {} beacon(s) never arrived this run — that is the LINK; the agent was running to send the ones that did",
            b.missing
        ),
        "alive" => "alive".to_string(),
        other => other.to_string(),
    };
    let clock = match (b.offset_ns, b.spread_ns) {
        (Some(o), Some(s)) => format!(
            "clock offset {o} ± {} (collector − host, median of {} beat(s)) · {} step(s) seen",
            secs(s).trim_start_matches('+'),
            b.window,
            b.jumps,
            o = secs(o)
        ),
        _ => "clock offset: not measured".to_string(),
    };
    vec![
        format!(
            "  heartbeat ({}): {state} · last beat {} ({} ago), run {} seq {} · {} restart(s), {} replay(s) refused · as of {}",
            b.agent,
            utc(b.last_ns),
            span(now - b.last_ns),
            b.run,
            b.seq,
            b.restarts,
            b.stale,
            utc(b.as_of_ns)
        ),
        format!("  {clock}"),
    ]
}

fn cluster_lines(q: &Queue) -> Vec<String> {
    let j = &q.joins;
    let mut v = vec![
        "J2 SPREAD — one digest, key, crontab line or destination on two hosts or more, anchored by a finding graded \
         WARN or worse on one of them; a file the hosts merely share is no cluster. Each host's alert stays its own."
            .to_string(),
    ];
    if j.clusters.is_empty() {
        v.push("  none".to_string());
    }
    for c in &j.clusters {
        v.push(format!("  {} the {} {} — {} host(s)", c.severity.token(), c.entity.kind(), c.entity.value(), c.members.len()));
        for m in &c.members {
            let flagged: Vec<String> = m.flagged.iter().map(|(id, s)| format!("{id} {}", s.token())).collect();
            v.push(format!(
                "    {}: {}{}",
                m.label,
                if flagged.is_empty() { format!("nothing here flagged it — alert {}", m.spread.as_deref().unwrap_or("-")) } else { format!("flagged {}", flagged.join(", ")) },
                if m.present.is_empty() { String::new() } else { format!("; recorded at {}", m.present.join(", ")) }
            ));
        }
    }
    v.push(String::new());
    v.push("J3 LATERAL — a session to a host's remote-access port, and a new key, account or persistence there in the same window".to_string());
    if j.chains.is_empty() {
        v.push("  none".to_string());
    }
    for c in &j.chains {
        v.push(format!("  {} -> {} port {} ({}) · B's alert {} · chain alerts {}", short(&c.from), short(&c.to), c.port, c.service, c.alert, c.raised.join(", ")));
        v.push(format!("    {}", c.window));
    }
    v.push(String::new());
    v.push("J1 FLOW — each firewall capture against each host behind it, by address, MAC and lease".to_string());
    if j.flows.is_empty() {
        v.push("  no pair".to_string());
    }
    for p in &j.flows {
        v.push(format!(
            "  firewall {} × host {} (stores {} × {}): {} CONTRADICTION · {} agreement · {} UNKNOWN",
            short(&p.fw),
            short(&p.host),
            short(&p.fw_store),
            short(&p.host_store),
            p.counts.0,
            p.counts.1,
            p.counts.2
        ));
        v.push(format!("    clocks {}", p.clock));
        for u in p.unknowns.iter().take(6) {
            v.push(format!("    - {u}"));
        }
    }
    if !j.notes.is_empty() {
        v.push(String::new());
        v.extend(j.notes.iter().map(|n| format!("note: {n}")));
    }
    v
}

#[cfg(feature = "mod-tui")]
fn model(q: &Queue, engagement: &[u8; 16], actor: &str, now: i64) -> hemostat_tui::QueueModel {
    use hemostat_tui::{QueueModel, QueueRow, Sev as TSev};
    let tsev = |s: Sev| match s {
        Sev::Critical => TSev::Critical,
        Sev::Warn => TSev::Warn,
        Sev::Note | Sev::Info => TSev::Note,
    };
    let rows = q
        .alerts
        .iter()
        .map(|a| QueueRow {
            id: a.id.clone(),
            severity: tsev(a.max_sev),
            current: (a.cur_sev != a.max_sev).then(|| tsev(a.cur_sev)),
            host: short(&a.host),
            variant: q.hosts.iter().find(|h| h.host == a.host).map(|h| h.variant.clone()).unwrap_or_default(),
            source: a.source.clone(),
            subject: a.subject.clone(),
            sightings: a.sightings.len(),
            state: a.state.name(),
            owner: a.owner.clone().unwrap_or_default(),
            age: span(now - a.first_ns),
            absent: a.absent_from_latest,
            detail: detail(a, q, now),
        })
        .collect();
    QueueModel {
        title: format!("engagement {} · {} ledger run(s)", hex(engagement), q.ledger_runs),
        actor: actor.to_string(),
        rows,
        hosts: host_lines(q, now),
        cluster: cluster_lines(q),
        anomalies: q.anomalies.clone(),
        ..QueueModel::default()
    }
}

#[cfg(feature = "mod-tui")]
fn tui(layout: &Layout, judge: &Judge, engagement: &[u8; 16], once: bool, preset: &[(&'static str, String)]) -> u8 {
    use hemostat_tui::QCommand;
    let (q, _) = match load(layout, judge) {
        Ok(x) => x,
        Err(e) => {
            eprintln!("hemostat queue: {}", h(&e));
            return EXIT_FAILED;
        }
    };
    let now = hemostat_fleet::now_ns();
    if once {
        let (ruid, _, name) = login();
        let who = format!("uid={}({name})", ruid.map_or("?".to_string(), |u| u.to_string()));
        let m = model(&q, engagement, &who, now);
        let height = u16::try_from(m.rows.len() + m.anomalies.len().min(3) + 12).unwrap_or(u16::MAX).max(24);
        print!("{}", hemostat_tui::queue::to_text(&m, 200, height));
        return EXIT_OK;
    }
    let actor = match acting_login() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("hemostat queue: {e}");
            return EXIT_POLICY;
        }
    };
    let session = session_id();
    let initial = model(&q, engagement, &actor.label(), now);
    let res = hemostat_tui::run_queue(initial, |cmd| {
        let said = match cmd {
            QCommand::Refresh | QCommand::Quit => "re-read the ledger and the stores".to_string(),
            QCommand::Ack(id) => record(layout, judge, engagement, &actor, &session, "tui", Action::Ack, id, "")?,
            QCommand::Investigate(id) => record(layout, judge, engagement, &actor, &session, "tui", Action::Investigate, id, "")?,
            QCommand::Note(id, text) => record(layout, judge, engagement, &actor, &session, "tui", Action::Note, id, text)?,
            QCommand::Resolve(id, kind, text) => {
                let r = Resolution::parse(&kind.to_string()).ok_or_else(|| "no such resolution".to_string())?;
                record(layout, judge, engagement, &actor, &session, "tui", Action::Resolve(r), id, text)?
            }
        };
        let (q, _) = load(layout, judge)?;
        Ok((model(&q, engagement, &actor.label(), hemostat_fleet::now_ns()), said))
    }, crate::tui_verbs::verbs_with(hemostat_tui::verbs::Platform::Collector, preset));
    match res {
        Ok(()) => EXIT_OK,
        Err(e) => {
            eprintln!("hemostat queue: the terminal failed: {e}");
            EXIT_FAILED
        }
    }
}

#[cfg(not(feature = "mod-tui"))]
fn tui(_: &Layout, _: &Judge, _: &[u8; 16], _: bool, _: &[(&'static str, String)]) -> u8 {
    eprintln!("hemostat queue: this image has no terminal interface (mod-tui); `queue list` and `queue show` print the queue");
    crate::EXIT_NOT_BUILT
}

fn list(layout: &Layout, judge: &Judge, engagement: &[u8; 16], json: bool) -> u8 {
    let (q, _) = match load(layout, judge) {
        Ok(x) => x,
        Err(e) => {
            eprintln!("hemostat queue: {}", h(&e));
            return EXIT_FAILED;
        }
    };
    let now = hemostat_fleet::now_ns();
    if json {
        let lines = hemostat_fleet::export::to_jsonl(&q, &hex(engagement), now);
        let items: Vec<&str> = lines.lines().collect();
        jprintln!("[{}]", items.join(","));
        return EXIT_OK;
    }
    for a in &q.anomalies {
        println!("! {}", h(a));
    }
    println!(
        "{} alert(s): {} CRITICAL, {} WARN; {} host(s); {} ledger run(s); {} inventory row(s) not raised",
        q.alerts.len(),
        q.alerts.iter().filter(|a| a.max_sev == Sev::Critical).count(),
        q.alerts.iter().filter(|a| a.max_sev == Sev::Warn).count(),
        q.hosts.len(),
        q.ledger_runs,
        q.inventory_rows
    );
    for a in &q.alerts {
        println!(
            "  {}  {:8}  {}  {:12}  {:5}  {:24}  {:16}  {:>6}  {}",
            a.id,
            if a.cur_sev == a.max_sev { a.max_sev.token().to_string() } else { format!("{}*", a.max_sev.token()) },
            short(&a.host),
            h(&a.source),
            a.sightings.len(),
            if a.absent_from_latest { format!("{} · absent", a.state.name()) } else { a.state.name() },
            h(a.owner.as_deref().unwrap_or("-")),
            span(now - a.first_ns),
            h(&a.subject)
        );
    }

    println!("\nHOSTS");
    for l in host_lines(&q, now) {
        println!("  {}", h(&l));
    }
    println!("JOINS");
    for l in cluster_lines(&q) {
        println!("  {}", h(&l));
    }
    EXIT_OK
}

fn show(layout: &Layout, judge: &Judge, id: &str, json: bool) -> u8 {
    let (q, _) = match load(layout, judge) {
        Ok(x) => x,
        Err(e) => {
            eprintln!("hemostat queue: {}", h(&e));
            return EXIT_FAILED;
        }
    };
    let a = match q.find(id) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("hemostat queue show: {}", h(&e));
            return EXIT_FAILED;
        }
    };
    let now = hemostat_fleet::now_ns();
    if json {
        let all = hemostat_fleet::export::to_jsonl(&q, "", now);
        let line = all.lines().find(|l| l.contains(&format!("\"id\":\"{}\"", a.id))).unwrap_or("{}");
        jprintln!("{line}");
    } else {
        for l in detail(a, &q, now) {
            println!("{}", h(&l));
        }
    }
    EXIT_OK
}

fn export(layout: &Layout, judge: &Judge, engagement: &[u8; 16], fmt: &str, out: Option<&str>) -> u8 {
    let (q, _) = match load(layout, judge) {
        Ok(x) => x,
        Err(e) => {
            eprintln!("hemostat queue: {}", h(&e));
            return EXIT_FAILED;
        }
    };
    let now = hemostat_fleet::now_ns();
    let ledger_key = hemostat_fleet::ledger::ledger_public_key(&layout.ledger()).map_or("none".to_string(), |k| hex32(&k));
    let text = match fmt {
        "report" | "html" => hemostat_fleet::export::to_html(&q, &hex(engagement), now, &ledger_key),
        "jsonl" => hemostat_fleet::export::to_jsonl(&q, &hex(engagement), now),
        other => {
            eprintln!("hemostat queue --export: report or jsonl, not {}", h(other));
            return EXIT_USAGE;
        }
    };
    match out {
        None => {
            print!("{text}");
            EXIT_OK
        }
        Some(path) => {
            use std::io::Write as _;

            let written = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(path)
                .and_then(|mut f| f.write_all(text.as_bytes()).and_then(|()| f.sync_all()));
            match written {
                Ok(()) => {
                    println!(
                        "wrote the queue ({} alert(s), {} host(s)) as {fmt} to {}",
                        q.alerts.len(),
                        q.hosts.len(),
                        h(path)
                    );
                    EXIT_OK
                }
                Err(e) => {
                    eprintln!("hemostat queue --export: cannot write {}: {e}", h(path));
                    EXIT_FAILED
                }
            }
        }
    }
}
