#[cfg(any(
    feature = "mod-detect-sigma",
    all(target_os = "linux", any(
        feature = "mod-query",
        feature = "mod-correlation",
        feature = "mod-sensor-audit",
        feature = "mod-scan-yara",
    )),
))]
use crate::{render::h, EXIT_OK};
#[cfg(any(
    feature = "mod-detect-sigma",
    all(target_os = "linux", any(
        feature = "mod-query",
        feature = "mod-correlation",
        feature = "mod-scan-yara",
    )),
))]
use crate::render::json_str;

#[cfg(all(target_os = "linux", feature = "mod-sensor-audit"))]
use crate::render::triage_row;

#[cfg(all(target_os = "linux", feature = "mod-scan-yara"))]
use crate::render::jesc;
#[cfg(any(
    feature = "mod-detect-sigma",
    all(target_os = "linux", any(
        feature = "mod-query",
        feature = "mod-sensor-audit",
        feature = "mod-scan-yara",
    )),
))]
use crate::EXIT_PARTIAL;
#[cfg(any(
    feature = "mod-detect-sigma",
    all(target_os = "linux", any(feature = "mod-query", feature = "mod-scan-yara")),
))]
use crate::EXIT_USAGE;
#[cfg(all(target_os = "linux", feature = "mod-detect-sigma"))]
use crate::identity::gather_identity;

#[cfg(all(target_os = "linux", feature = "mod-query"))]
pub(crate) fn query_tables() -> Vec<Box<dyn hemostat_query::Table>> {
    #[cfg(feature = "mod-query-memory")]
    {
        hemostat_query::tables::all_with_memory()
    }
    #[cfg(not(feature = "mod-query-memory"))]
    {
        hemostat_query::tables::all()
    }
}

#[cfg(all(target_os = "linux", feature = "mod-query"))]
pub(crate) fn print_query(json: bool, sql: &str, list_tables: bool) -> u8 {
    use hemostat_query::{parse, run, Table};

    let owned = query_tables();
    let tables: Vec<&dyn Table> = owned.iter().map(AsRef::as_ref).collect();

    if list_tables || sql.trim().is_empty() {
        if !list_tables {
            eprintln!("hemostat query \"SELECT ... FROM ... [WHERE ...]\"   ·   --tables lists them\n");
        }
        for t in &tables {
            println!("{}", t.name());
            println!("  {}", h(t.describe()));
            println!("  columns: {}", t.columns().join(", "));
        }
        println!();
        println!(
            "  SELECT, FROM, WHERE (=, !=, <, <=, >, >=, LIKE, AND, OR, NOT, parentheses),\n  \
             ORDER BY and LIMIT. Anything else is refused by name rather than guessed at.\n  \
             This is a scan and not an index: it reads the host when you ask, which is what\n  \
             makes it a live query."
        );
        return if list_tables { EXIT_OK } else { EXIT_USAGE };
    }

    let q = match parse(sql) {
        Ok(q) => q,
        Err(e) => {
            eprintln!("hemostat query: {}", h(&e.message()));
            return EXIT_USAGE;
        }
    };
    let answer = match run(&q, &tables) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("hemostat query: {}", h(&e.message()));
            return EXIT_USAGE;
        }
    };

    if json {
        let rows: Vec<String> = answer
            .rows
            .iter()
            .map(|r| {
                let cells: Vec<String> = answer
                    .columns
                    .iter()
                    .zip(r.iter())
                    .map(|(c, v)| format!("{}:{}", json_str(c), json_str(&v.to_string())))
                    .collect();
                format!("{{{}}}", cells.join(","))
            })
            .collect();
        jprintln!(
            "{{\"complete\":{},\"scanned\":{},\"gaps\":[{}],\"rows\":[{}]}}",
            answer.complete(),
            answer.scanned,
            answer.gaps.iter().map(|g| json_str(g)).collect::<Vec<_>>().join(","),
            rows.join(",")
        );
        return if answer.complete() { EXIT_OK } else { EXIT_PARTIAL };
    }

    let rows: Vec<Vec<String>> =
        answer.rows.iter().map(|r| r.iter().map(|c| h(&c.to_string())).collect()).collect();

    let mut widths: Vec<usize> = answer.columns.iter().map(String::len).collect();
    for r in &rows {
        for (i, c) in r.iter().enumerate() {
            if let Some(w) = widths.get_mut(i) {
                *w = (*w).max(c.chars().count()).min(60);
            }
        }
    }
    let line: Vec<String> = answer
        .columns
        .iter()
        .enumerate()
        .map(|(i, c)| format!("{:<width$}", h(c), width = widths[i]))
        .collect();
    println!("{}", line.join("  "));
    println!("{}", widths.iter().map(|w| "-".repeat(*w)).collect::<Vec<_>>().join("  "));
    for r in &rows {
        let cells: Vec<String> = r
            .iter()
            .enumerate()
            .map(|(i, s)| {
                let s = if s.chars().count() > 60 {
                    format!("{}…", s.chars().take(59).collect::<String>())
                } else {
                    s.clone()
                };
                format!("{:<width$}", s, width = widths.get(i).copied().unwrap_or(0))
            })
            .collect();
        println!("{}", cells.join("  "));
    }
    println!();
    println!("  {}", h(&answer.coverage()));
    if answer.complete() {
        EXIT_OK
    } else {
        EXIT_PARTIAL
    }
}

#[cfg(all(target_os = "linux", feature = "mod-correlation"))]
pub(crate) fn print_correlate(json: bool) -> u8 {
    use hemostat_detect::correlate::{correlate, Entity, Item, Sev};

    let mut items: Vec<Item> = Vec::new();
    let mut n = 0_usize;
    let add = |source: &str,
                   severity: Sev,
                   subject: &str,
                   locus: &str,
                   what: &str,
                   known: Vec<Entity>,
                   items: &mut Vec<Item>,
                   n: &mut usize| {
        *n += 1;
        items.push(Item {
            id: format!("{source}:{n}"),
            source: source.to_string(),
            severity,
            subject: subject.to_string(),
            locus: locus.to_string(),
            what: what.to_string(),
            known,
        });
    };

    for f in &hemostat_sensor_linux::account_report().findings {
        add(
            "accounts",
            account_sev(f.severity),
            &f.subject,
            &f.subject,
            &f.what,
            vec![Entity::User(f.subject.clone())],
            &mut items,
            &mut n,
        );
    }

    for (source, fs) in [
        ("rootkit", hemostat_sensor_linux::rootkit_report().findings),
        ("suid", hemostat_sensor_linux::suid::report().findings),
        ("inventory", crate::vendor::inventory().0.findings),
        ("watchdog", hemostat_sensor_linux::watchdog::report().findings),
    ] {
        for f in &fs {
            add(source, rootkit_sev(f.severity), &f.subject, "", &f.what, Vec::new(), &mut items, &mut n);
        }
    }

    for (source, fs) in [
        ("persistence", hemostat_sensor_linux::persist_report().findings),
        ("systemd", hemostat_sensor_linux::enablement::report().findings),
        ("overview", hemostat_sensor_linux::overview_report().findings),
        ("injected", hemostat_sensor_linux::hooked_report().findings),
    ] {
        for f in &fs {
            add(source, triage_sev(f.severity), &f.subject, &f.locus, &f.what, Vec::new(), &mut items, &mut n);
        }
    }

    let c = correlate(&items);

    if json {
        let rows: Vec<String> = c
            .clusters
            .iter()
            .map(|cl| {
                format!(
                    "{{\"severity\":\"{}\",\"items\":[{}],\"shared\":[{}],\"sources\":[{}]}}",
                    cl.severity.token(),
                    cl.items.iter().map(|i| json_str(i)).collect::<Vec<_>>().join(","),
                    cl.shared
                        .iter()
                        .map(|e| json_str(&e.describe()))
                        .collect::<Vec<_>>()
                        .join(","),
                    cl.sources.iter().map(|s| json_str(s)).collect::<Vec<_>>().join(",")
                )
            })
            .collect();
        jprintln!(
            "{{\"findings\":{},\"clusters\":[{}],\"singletons\":{},\"hubs\":{}}}",
            items.len(),
            rows.join(","),
            c.singletons.len(),
            c.hubs.len()
        );
        return EXIT_OK;
    }

    println!("correlate — which findings are about the same things\n");
    println!("  {} finding(s) from the sweeps that ran", items.len());
    println!("  {}\n", h(&c.coverage()));

    let mut quiet = 0_usize;
    for cl in &c.clusters {
        if !cl.is_cross_sweep() && cl.severity < Sev::Warn {
            quiet += 1;
            continue;
        }
        println!("  [{}] {}", cl.severity.token(), h(&cl.headline()));
        for id in &cl.items {
            if let Some(it) = items.iter().find(|i| &i.id == id) {
                println!("      {} — {}", it.source, h(&it.what));
            }
        }
        println!();
    }
    if quiet > 0 {
        println!(
            "  ({quiet} cluster(s) not shown: one sweep describing the same thing more than \
             once, below warning level.)\n"
        );
    }
    if c.clusters.len() == quiet {
        println!("  No finding shares a thing with another. That is a result, not an absence:");
        println!("  on a host with one intrusion the findings usually do overlap.");
        println!();
    }

    println!(
        "  A cluster is a reading aid, not a verdict. Its severity is the highest of its\n  \
         members and never a sum — three warnings are not a critical, and an engine that\n  \
         promoted them would be inventing a judgement its inputs do not support."
    );
    EXIT_OK
}

#[cfg(all(target_os = "linux", feature = "mod-correlation"))]
fn account_sev(s: hemostat_sensor_linux::Severity) -> hemostat_detect::correlate::Sev {
    use hemostat_detect::correlate::Sev;
    use hemostat_sensor_linux::Severity as S;
    match s {
        S::Critical => Sev::Critical,
        S::Warn => Sev::Warn,
        S::Note => Sev::Note,
    }
}

#[cfg(all(target_os = "linux", feature = "mod-correlation"))]
fn rootkit_sev(s: hemostat_sensor_linux::rootkit::Severity) -> hemostat_detect::correlate::Sev {
    use hemostat_detect::correlate::Sev;
    use hemostat_sensor_linux::rootkit::Severity as S;
    match s {
        S::Critical => Sev::Critical,
        S::Warn => Sev::Warn,
        S::Note => Sev::Note,
    }
}

#[cfg(all(target_os = "linux", feature = "mod-correlation"))]
fn triage_sev(s: hemostat_sensor_linux::TriageSeverity) -> hemostat_detect::correlate::Sev {
    use hemostat_detect::correlate::Sev;
    use hemostat_sensor_linux::TriageSeverity as S;
    match s {
        S::Critical => Sev::Critical,
        S::Warn => Sev::Warn,
        S::Note => Sev::Note,
        S::Info => Sev::Info,
    }
}

#[cfg(feature = "mod-detect-sigma")]
pub(crate) fn collect_rule_documents(dir: &str) -> (Vec<(String, String)>, Vec<String>) {
    use hemostat_detect::yaml;

    let mut docs: Vec<(String, String)> = Vec::new();
    let mut unreadable: Vec<String> = Vec::new();
    let mut stack = vec![std::path::PathBuf::from(dir)];

    while let Some(p) = stack.pop() {
        let entries = match std::fs::read_dir(&p) {
            Ok(entries) => entries,
            Err(err) => {
                unreadable.push(format!("{} ({err})", p.display()));
                continue;
            }
        };
        for e in entries.flatten() {
            let path = e.path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            if !path.extension().is_some_and(|x| x == "yml" || x == "yaml") {
                continue;
            }
            match std::fs::read_to_string(&path) {
                Ok(t) => docs.extend(
                    yaml::documents(&t)
                        .into_iter()
                        .enumerate()
                        .map(|(i, d)| (format!("{}#{i}", path.display()), d)),
                ),
                Err(err) => unreadable.push(format!("{} ({err})", path.display())),
            }
        }
    }

    (docs, unreadable)
}

#[cfg(feature = "mod-detect-sigma")]
pub(crate) fn print_detect(json: bool, rules_dir: Option<&str>, watch: Option<u64>) -> u8 {
    use hemostat_detect::{run, RuleSet};

    let Some(dir) = rules_dir else {
        eprintln!(
            "hemostat detect --rules <dir>\n  \
             <dir> holds Sigma rules as .yml files. Nothing is bundled: a detection tool that \
             shipped its own rules would be making claims about your estate that its author \
             could not have checked."
        );
        return EXIT_USAGE;
    };

    let (docs, unreadable) = collect_rule_documents(dir);

    if docs.is_empty() {
        eprintln!(
            "hemostat detect: no .yml rules were found under {dir}. Nothing was evaluated, \
             which is NOT the same as nothing matching"
        );
        return EXIT_PARTIAL;
    }

    let set = RuleSet::from_documents(&docs);

    #[cfg(target_os = "windows")]
    if let Some(secs) = watch {
        return crate::win_detect::print_watch(json, &set, &unreadable, secs);
    }
    #[cfg(not(target_os = "windows"))]
    let _ = watch;

    let input = collect_events_for_detection();
    let events = &input.events;

    let complete = detect_complete(set.complete_over(events), &unreadable, events.len(), &input.gaps);
    let cut = hemostat_detect::truncated_events(events);

    let mut available: Vec<String> = Vec::new();
    for e in events {
        for (name, _) in e.fields.iter() {
            let n = name.as_str().to_string();
            if !available.contains(&n) {
                available.push(n);
            }
        }
    }
    available.sort();
    let available_refs: Vec<&str> = available.iter().map(String::as_str).collect();
    let inapplicable = inapplicable_rules(&set, &available_refs, events.len());

    if json {
        let rows: Vec<String> = run(&set, events)
            .iter()
            .map(|h| {
                format!(
                    "{{\"level\":\"{}\",\"title\":{},\"id\":{},\"seq\":{},\"truncated\":{},\"from\":{},\"event\":{}}}",
                    h.level.token(),
                    json_str(&h.title),
                    h.id.as_ref().map_or("null".into(), |i| json_str(i)),
                    h.seq,
                    h.truncated,
                    input.about(h.seq).map_or("null".into(), json_str),
                    input.event(h.seq).map_or("null".into(), event_json)
                )
            })
            .collect();
        let rejected: Vec<String> = set
            .rejected
            .iter()
            .map(|r| {
                format!(
                    "{{\"source\":{},\"title\":{},\"why\":{}}}",
                    json_str(&r.source),
                    r.title.as_ref().map_or("null".into(), |t| json_str(t)),
                    json_str(&r.error.message())
                )
            })
            .collect();

        let unmatchable: Vec<String> = inapplicable
            .iter()
            .map(|r| {
                format!(
                    "{{\"rule\":{},\"missing\":[{}]}}",
                    json_str(&r.title),
                    r.unavailable_fields(&available_refs)
                        .iter()
                        .map(|f| json_str(f))
                        .collect::<Vec<_>>()
                        .join(",")
                )
            })
            .collect();
        jprintln!(
            "{{\"evaluated\":{},\"not_evaluated\":{},\"events\":{},\"truncated_events\":{},\"complete\":{},\
              \"sources\":{},\"source_gaps\":[{}],\
              \"hits\":[{}],\"rejected\":[{}],\"unknown_fields\":[{}],\"inapplicable\":[{}]}}",
            set.rules.len(),
            set.rejected.len(),
            events.len(),
            cut,
            complete,
            input.sources_json,
            input.gaps.iter().map(|g| json_str(g)).collect::<Vec<_>>().join(","),
            rows.join(","),
            rejected.join(","),
            set.rules_naming_unknown_fields()
                .iter()
                .map(|(title, fields)| format!(
                    "{{\"rule\":{},\"fields\":[{}]}}",
                    json_str(title),
                    fields.iter().map(|f| json_str(f)).collect::<Vec<_>>().join(",")
                ))
                .collect::<Vec<_>>()
                .join(","),
            unmatchable.join(",")
        );
        return if complete { EXIT_OK } else { EXIT_PARTIAL };
    }

    println!("detect — Sigma rules over what this agent can see\n");
    println!("  {}", h(&set.coverage_over(events)));
    println!("  {} event(s) evaluated against them", events.len());
    for n in &input.notes {
        println!("  {}", h(n));
    }
    if events.is_empty() {
        println!("  {}", h(&input.no_events));
    }
    if !input.gaps.is_empty() {
        println!("\n  EVENT SOURCES THAT COULD NOT BE READ ({}):", input.gaps.len());
        for g in &input.gaps {
            println!("    {}", h(g));
        }
    }

    let unknown = set.rules_naming_unknown_fields();
    if !unknown.is_empty() {
        println!(
            "\n  {} of {} rule(s) name fields this agent does not emit. They were evaluated\n               and could not have matched on those fields — this agent emulates Sysmon's\n               vocabulary, and a feed written against a fuller one asks about records\n               nothing here produces:",
            unknown.len(),
            set.rules.len()
        );
        for (title, fields) in unknown.iter().take(8) {
            println!("      {} — {}", h(title), h(&fields.join(", ")));
        }
        if unknown.len() > 8 {
            println!("      ... and {} more", unknown.len() - 8);
        }
    }
    println!();

    let hits = run(&set, events);
    for hit in &hits {
        println!("  [{}] {}", hit.level.token(), h(&hit.title));
        if let Some(id) = &hit.id {
            println!("      sigma id {}, event seq {}", h(id), hit.seq);
        } else {
            println!("      event seq {}", hit.seq);
        }
        if let Some(about) = input.about(hit.seq) {
            println!("      from {}", h(about));
        }
        if let Some(e) = input.event(hit.seq) {
            println!("      {}", h(&event_line(e)));
        }
        if hit.truncated {
            println!(
                "      a field of this event was over {} bytes and was cut: its head and tail were \
                 evaluated, not its middle",
                hs_core::MAX_FIELD_BYTES
            );
        }
    }
    if hits.is_empty() && !events.is_empty() {
        println!("  no rule matched any event in this sample.");
    }

    if !inapplicable.is_empty() {
        println!();
        println!(
            "  RULES THAT RAN BUT COULD NOT MATCH HERE ({}):",
            inapplicable.len()
        );
        println!(
            "    every way each could match needs a field this platform's events lack; they \
             carry: {}",
            available.join(", ")
        );
        for r in inapplicable.iter().take(12) {
            println!(
                "    {} — needs {}",
                h(&r.title),
                h(&r.unavailable_fields(&available_refs).join(", "))
            );
        }
        if inapplicable.len() > 12 {
            println!("    … and {} more", inapplicable.len() - 12);
        }
    }

    if !set.rejected.is_empty() {
        println!();
        println!("  RULES THAT DID NOT RUN ({}):", set.rejected.len());
        for r in &set.rejected {
            println!(
                "    {} — {}",
                h(r.title.as_deref().unwrap_or(&r.source)),
                h(&r.error.message())
            );
        }
    }
    if !unreadable.is_empty() {
        println!();
        println!("  RULE FILES THAT COULD NOT BE READ ({}):", unreadable.len());
        for u in &unreadable {
            println!("    {}", h(u));
        }
    }

    println!();
    println!(
        "  A Sigma rule is a lead, not a verdict, and its author's level is carried through\n  \
         rather than re-graded. The count above is what matters: a rule that did not run is\n  \
         not a rule that found nothing."
    );
    if complete {
        EXIT_OK
    } else {
        EXIT_PARTIAL
    }
}

#[cfg(feature = "mod-detect-sigma")]
fn detect_complete(rules_complete: bool, unreadable: &[String], events: usize, gaps: &[String]) -> bool {
    rules_complete && unreadable.is_empty() && events > 0 && gaps.is_empty()
}

#[cfg(feature = "mod-detect-sigma")]
pub(crate) struct DetectInput {

    pub(crate) events: Vec<hs_core::Event>,

    pub(crate) about: Vec<String>,

    pub(crate) notes: Vec<String>,

    pub(crate) gaps: Vec<String>,

    pub(crate) sources_json: String,

    pub(crate) no_events: String,
}

#[cfg(feature = "mod-detect-sigma")]
impl DetectInput {

    pub(crate) fn about(&self, seq: u64) -> Option<&str> {
        self.about.get(usize::try_from(seq).ok()?).map(String::as_str)
    }

    pub(crate) fn event(&self, seq: u64) -> Option<&hs_core::Event> {
        self.events.get(usize::try_from(seq).ok()?).filter(|e| e.seq == seq)
    }
}

#[cfg(feature = "mod-detect-sigma")]
pub(crate) fn event_json(e: &hs_core::Event) -> String {
    use hs_core::FieldValue;
    let body: Vec<String> = e
        .fields
        .iter()
        .map(|(n, v)| {
            let v = match v {
                FieldValue::Str(s) => json_str(s),
                FieldValue::U64(n) => n.to_string(),
                FieldValue::I64(n) => n.to_string(),
                FieldValue::Bool(b) => b.to_string(),
            };
            format!("{}:{v}", json_str(n.as_str()))
        })
        .collect();
    format!("{{{}}}", body.join(","))
}

#[cfg(feature = "mod-detect-sigma")]
pub(crate) fn event_line(e: &hs_core::Event) -> String {
    use hs_core::event::fields;
    let get = |f| e.fields.get(f).map(ToString::to_string);
    let mut out = get(fields::IMAGE).unwrap_or_else(|| "(no image)".into());
    if let Some(p) = get(fields::PROCESS_ID) {
        out.push_str(&format!(" (pid {p})"));
    }
    match (get(fields::PARENT_IMAGE), get(fields::PARENT_PROCESS_ID)) {
        (Some(pi), Some(pp)) => out.push_str(&format!(" <- {pi} (pid {pp})")),
        (Some(pi), None) => out.push_str(&format!(" <- {pi}")),
        (None, Some(pp)) => out.push_str(&format!(" <- pid {pp}")),
        (None, None) => {}
    }
    if let Some(u) = get(fields::USER) {
        out.push_str(&format!(" as {u}"));
    }
    if let Some(c) = get(fields::COMMAND_LINE) {
        out.push_str(&format!(": {c}"));
    }
    out
}

#[cfg(feature = "mod-detect-sigma")]
fn inapplicable_rules<'a>(
    set: &'a hemostat_detect::RuleSet,
    available: &[&str],
    events: usize,
) -> Vec<&'a hemostat_detect::Rule> {
    if events == 0 {
        return Vec::new();
    }
    set.inapplicable(available)
}

#[cfg(all(feature = "mod-detect-sigma", target_os = "linux"))]
const NO_EVENTS: &str = "/proc yielded no processes, so no rule was evaluated against \
                         anything — a refusal to read, not an absent host. Exit 7.";
#[cfg(all(feature = "mod-detect-sigma", not(any(target_os = "linux", target_os = "windows"))))]
const NO_EVENTS: &str = "this platform has no event source for detect yet, so no rule was \
                         evaluated against anything. Exit 7.";

#[cfg(all(feature = "mod-detect-sigma", target_os = "linux"))]
pub(crate) fn collect_events_for_detection() -> DetectInput {
    use hemostat_sensor_linux::procfs;
    use hs_core::identity::{AgentId, EngagementId, HostId, InstanceId};
    use hs_core::time::{BootId, MonoTime, WallTime};

    let id = gather_identity().ok();
    let origin = hs_core::Origin {
        engagement: EngagementId::from_bytes(id.as_ref().map_or([0; 16], |i| i.engagement)),
        host: HostId::from_bytes(id.as_ref().map_or([0; 32], |i| i.host)),
        agent: AgentId::from_bytes(id.as_ref().map_or([0; 16], |i| i.agent)),
        instance: InstanceId::from_bytes(id.as_ref().map_or([0; 16], |i| i.instance)),
    };
    let wall = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_nanos()).unwrap_or(i64::MAX));
    let stamp = hs_core::Stamp {
        mono: MonoTime::from_nanos(0),
        wall: WallTime::from_nanos(wall),
        boot: BootId::from_bytes(id.as_ref().map_or([0; 16], |i| i.boot)),
    };

    let procs = procfs::walk();

    let cut = procfs::cmdline_gap(&procs);
    let events: Vec<hs_core::Event> = procs
        .into_iter()
        .enumerate()
        .map(|(i, p)| p.to_event(u64::try_from(i).unwrap_or(0), stamp, origin))
        .collect();
    let about = events
        .iter()
        .map(|e| match e.fields.get(hs_core::event::fields::PROCESS_ID) {
            Some(pid) => format!("procfs, /proc/{pid}"),
            None => "procfs".to_string(),
        })
        .collect();
    let n = events.len();
    let mut notes = vec!["the procfs floor: one sample of the processes running now".to_string()];
    notes.extend(cut);
    DetectInput {
        events,
        about,
        notes,
        gaps: Vec::new(),
        sources_json: format!("[{{\"source\":\"procfs\",\"state\":\"read\",\"records\":{n}}}]"),
        no_events: NO_EVENTS.into(),
    }
}

#[cfg(all(feature = "mod-detect-sigma", target_os = "windows"))]
pub(crate) fn collect_events_for_detection() -> DetectInput {
    crate::win_detect::collect()
}

#[cfg(all(feature = "mod-detect-sigma", not(any(target_os = "linux", target_os = "windows"))))]
pub(crate) fn collect_events_for_detection() -> DetectInput {
    DetectInput {
        events: Vec::new(),
        about: Vec::new(),
        notes: Vec::new(),
        gaps: Vec::new(),
        sources_json: "[]".into(),
        no_events: NO_EVENTS.into(),
    }
}

#[cfg(all(target_os = "linux", feature = "mod-sensor-audit"))]
pub(crate) fn print_audit(json: bool) -> u8 {
    use hemostat_sensor_linux::TriageSeverity;
    let r = hemostat_sensor_linux::audit_report();

    if json {
        let f = r
            .findings
            .iter()
            .map(|f| {
                triage_row(f)
            })
            .collect::<Vec<_>>()
            .join(",");
        jprintln!(
            "{{\"complete\":{},\"rules\":{},\"loaded\":{},\"findings\":[{f}]}}",
            r.complete(),
            r.rules.len(),
            r.loaded.map_or_else(|| "null".to_string(), |n| n.to_string())
        );
        return if r.complete() { EXIT_OK } else { EXIT_PARTIAL };
    }

    match (&r.status, &r.status_error) {
        (Some(s), _) => {
            println!(
                "audit posture: enabled={} ({}), collector pid {}, {} rule(s) loaded, {} on disk",
                s.enabled,
                if s.immutable() {
                    "locked until reboot"
                } else if s.enabled == 0 {
                    "OFF"
                } else {
                    "changeable"
                },
                if s.has_a_collector() { s.pid.to_string() } else { "NONE".into() },
                r.loaded.map_or_else(|| "UNKNOWN".to_string(), |n| n.to_string()),
                r.rules.len()
            );
            println!("  lost {} record(s), {} queued of {}", s.lost, s.backlog, s.backlog_limit);
        }
        (None, Some(why)) => println!("audit posture: UNKNOWN — {why}"),
        (None, None) => println!("audit posture: UNKNOWN"),
    }

    let crit = r.findings.iter().filter(|f| matches!(f.severity, TriageSeverity::Critical)).count();
    let warn = r.findings.iter().filter(|f| matches!(f.severity, TriageSeverity::Warn)).count();
    println!("  {} finding(s), {crit} critical, {warn} warn\n", r.findings.len());
    for f in &r.findings {
        println!("  [{}] {} — {}", f.severity.tag(), h(&f.subject), h(&f.locus));
        println!("      {}", h(&f.what));
        if !f.why.is_empty() {
            println!("      why: {}", h(&f.why));
        }
    }

    if r.complete() {
        println!(
            "\nThis asks whether the audit trail can be believed, not what is in it. The\n\
             lost counter is the number that matters: records the kernel dropped are holes\n\
             in the log, and they fall where the host was busiest."
        );
        EXIT_OK
    } else {
        println!(
            "\nThe kernel's own audit state could NOT be read, so nothing above establishes\n\
             the posture of this host. This is a partial result (exit 7), not a clean one."
        );
        EXIT_PARTIAL
    }
}

#[cfg(all(target_os = "linux", feature = "mod-scan-yara"))]
pub(crate) fn scan_targets() -> (Vec<std::path::PathBuf>, Vec<String>) {
    use std::collections::BTreeSet;

    let mut seen: BTreeSet<std::path::PathBuf> = BTreeSet::new();
    let mut notes: Vec<String> = Vec::new();

    let procs = hemostat_sensor_linux::procfs::walk();
    if procs.is_empty() {

        notes.push(
            "/proc yielded no processes, so no running executable was scanned — this is a \
             refusal to read, not an absence of targets"
                .into(),
        );
    }
    let mut deleted = 0usize;
    for p in &procs {
        let Some(exe) = &p.exe else { continue };

        if exe.ends_with(" (deleted)") {
            deleted += 1;
            continue;
        }
        seen.insert(std::path::PathBuf::from(exe));
    }
    if deleted > 0 {
        notes.push(format!(
            "{deleted} running process(es) execute a DELETED file. Their content was not \
             scanned — running from a file that no longer exists is itself the finding \
             `injected` raises"
        ));
    }

    match hemostat_sensor_linux::saferead::read_text(std::path::Path::new("/etc/ld.so.preload")) {
        Ok(text) => {
            for e in preload_entries(&text) {
                seen.insert(std::path::PathBuf::from(e));
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => notes.push(format!("/etc/ld.so.preload could not be read ({e})")),
    }

    (seen.into_iter().collect(), notes)
}

#[cfg(all(target_os = "linux", feature = "mod-scan-yara"))]
fn preload_entries(text: &str) -> Vec<&str> {
    text.lines()
        .flat_map(|l| l.split('#').next().unwrap_or("").split(|c: char| c == ':' || c.is_whitespace()))
        .filter(|e| !e.is_empty())
        .collect()
}

#[cfg(all(target_os = "linux", feature = "mod-scan-yara"))]
pub(crate) fn scan_expand(named: &[&str]) -> (Vec<std::path::PathBuf>, Vec<String>) {
    let mut out = Vec::new();
    let mut notes = Vec::new();
    for n in named {
        let p = std::path::PathBuf::from(n);
        match std::fs::symlink_metadata(&p) {
            Ok(md) if md.is_dir() => match std::fs::read_dir(&p) {
                Ok(rd) => out.extend(rd.flatten().map(|e| e.path())),
                Err(e) => notes.push(format!("{}: {e}", p.display())),
            },

            Ok(md) if md.file_type().is_symlink() => notes.push(format!(
                "{}: a symlink, not followed — name its target to scan it",
                p.display()
            )),
            Ok(_) => out.push(p),
            Err(e) => notes.push(format!("{}: {e}", p.display())),
        }
    }
    (out, notes)
}

#[cfg(all(target_os = "linux", feature = "mod-scan-yara"))]
pub(crate) fn print_scan(json: bool, named: &[&str], rules_override: Option<&str>) -> u8 {
    let (targets, mut notes) = if named.is_empty() {
        scan_targets()
    } else {
        scan_expand(named)
    };

    let dir = hemostat_scan::rules_dir(rules_override);
    if let (Some(want), None) = (rules_override, dir.as_ref()) {

        eprintln!("hemostat scan: {want} is not a directory, so those rules were not loaded");
        return EXIT_USAGE;
    }
    let o = hemostat_scan::scan_files(&targets, dir.as_deref());
    notes.extend(o.skipped.iter().map(|(p, why)| format!("{}: {why}", p.display())));

    if json {
        let hits = o
            .hits
            .iter()
            .map(|h| {
                format!(
                    "{{\"rule\":\"{}\",\"path\":\"{}\",\"note\":\"{}\",\"own_image\":{}}}",
                    jesc(&h.rule),
                    jesc(&h.path.to_string_lossy()),
                    jesc(&h.note),
                    h.own_image
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        let gaps = notes.iter().map(|n| format!("\"{}\"", jesc(n))).collect::<Vec<_>>().join(",");
        jprintln!(
            "{{\"rules\":{},\"targets\":{},\"scanned\":{},\"skipped\":{},\"hits\":[{hits}],\
             \"gaps\":[{gaps}],\"unavailable\":{},\"complete\":{}}}",
            o.rules,
            targets.len(),
            o.scanned,
            notes.len(),
            o.unavailable.as_ref().map_or("null".into(), |w| json_str(w)),
            scan_complete(&o, &notes)
        );
        return scan_exit(&o, &notes);
    }

    if let Some(why) = &o.unavailable {
        println!("content scan: DID NOT RUN — {}", h(why));
        println!();
        println!("  Nothing is claimed about the content of any file on this host.");
        return EXIT_PARTIAL;
    }

    println!(
        "content scan: {} rule(s) against {} target(s), {} scanned, {} hit(s)",
        o.rules,
        targets.len(),
        o.scanned,
        o.hits.len()
    );
    if named.is_empty() {
        println!(
            "  targets are every running process's executable plus /etc/ld.so.preload —\n  \
             where the cheap sensors point. Name paths to scan anything else."
        );
    }
    println!();

    if o.hits.is_empty() {
        println!("  no rule matched.");
        println!();
        println!(
            "  That is a statement about {} rule(s), not about this host. The built-in set is\n  \
             three shapes that are hard to reach by accident; point `--rules DIR` at a feed\n  \
             you trust for anything more.",
            o.rules
        );
    }
    for hit in &o.hits {
        if hit.own_image {

            println!("  [NOTE]  {} — {}", h(&hit.rule), h(&hit.path.to_string_lossy()));
            println!(
                "      HEMOSTAT's own running image (the inode /proc/self/exe names), which \
                 carries the text of its built-in rules"
            );
            continue;
        }
        println!("  [MATCH] {} — {}", h(&hit.rule), h(&hit.path.to_string_lossy()));
        if !hit.note.is_empty() {
            println!("      {}", h(&hit.note));
        }
    }

    if !notes.is_empty() {
        println!();
        println!("  {} target(s) were NOT scanned:", notes.len());
        for n in notes.iter().take(12) {
            println!("    {}", h(n));
        }
        if notes.len() > 12 {
            println!("    ... and {} more", notes.len() - 12);
        }
        println!("  Those are unexamined, not clean. Exit code 7 says the same thing.");
        return EXIT_PARTIAL;
    }
    EXIT_OK
}

#[cfg(all(target_os = "linux", feature = "mod-scan-yara"))]
fn scan_complete(o: &hemostat_scan::Outcome, notes: &[String]) -> bool {

    crate::coverage::scan(o, notes, notes.len()).gap().is_none()
}

#[cfg(all(target_os = "linux", feature = "mod-scan-yara"))]
fn scan_exit(o: &hemostat_scan::Outcome, notes: &[String]) -> u8 {
    if scan_complete(o, notes) {
        EXIT_OK
    } else {
        EXIT_PARTIAL
    }
}
