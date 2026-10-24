#[cfg(target_os = "linux")]
use crate::render::{accounts_row, h, jesc, json_array, json_str, rootkit_row, triage_row};
#[cfg(target_os = "linux")]
use crate::{EXIT_POLICY, EXIT_USAGE};

#[cfg(any(target_os = "linux", test))]
use crate::{EXIT_OK, EXIT_PARTIAL};
#[cfg(target_os = "linux")]
use crate::print_findings;
#[cfg(target_os = "linux")]
use crate::evidence::detection_json;
#[cfg(target_os = "linux")]
use crate::render::human_secs;
#[cfg(target_os = "linux")]
use crate::repeated_flag_values;

#[cfg(all(target_os = "linux", feature = "mod-tui"))]
use crate::views::posture_model;
#[cfg(all(target_os = "windows", feature = "mod-tui"))]
use crate::views::posture_model;

#[cfg(target_os = "linux")]
pub(crate) fn print_ad(json: bool) -> u8 {
    use hemostat_sensor_linux::adjoin;

    let r = adjoin::sweep();

    if json {
        let rows: Vec<String> = r
            .findings
            .iter()
            .map(|f| {
                triage_row(f)
            })
            .collect();
        jprintln!(
            "{{\"joined\":{},\"domain\":{},\"keytabs\":{},\"ccaches\":{},\"unreadable\":{},\
             \"findings\":[{}]}}",
            r.is_joined(),
            match &r.domain {
                Some(d) => json_str(d),
                None => "null".into(),
            },
            r.keytabs,
            r.ccaches,
            r.unreadable.len(),
            rows.join(",")
        );
        return if r.unreadable.is_empty() { EXIT_OK } else { EXIT_PARTIAL };
    }

    println!("ad — the domain credentials this host holds\n");
    if !r.is_joined() {

        println!("  this host is not joined to a domain: no keytab, and no enrolment record");
        println!("  in sssd.conf or smb.conf.");

        if let Some(d) = &r.domain {
            println!(
                "\n  /etc/krb5.conf names a default realm ({}), but every distribution ships\n  \
                 one — Arch's says ATHENA.MIT.EDU. A realm in that file is evidence a file\n  \
                 exists, not that this host joined anything, so its KDCs are not judged."
                , h(d)
            );
        }

        if r.unreadable.is_empty() {
            println!("\n  That is a statement about the host, not about what was checked.");
        } else {
            println!(
                "\n  But {} path(s) could NOT be read, including files that would say whether\n                   this host is enrolled:\n      {}\n  \n  So this is 'no join was found', not \
                 'this host is not joined'. Re-run elevated to settle it.",
                r.unreadable.len(),
                h(&r.unreadable.join("\n      "))
            );
        }
        return ad_exit(&r.unreadable);
    }

    match &r.domain {
        Some(d) => println!("  realm:   {}", h(d)),
        None => println!("  realm:   not configured, though a keytab is present"),
    }
    println!("  keytabs: {}", r.keytabs);
    println!("  tickets: {} credential cache(s) on disk", r.ccaches);

    println!(
        "  NOTE: the KEYRING and KCM ticket backends keep nothing in the filesystem, so a host\n  \
         using either has live tickets this sweep cannot count."
    );

    if !r.unreadable.is_empty() {
        println!(
            "\n  {} path(s) could NOT be read — their permissions are unchecked, not safe:\n      {}",
            r.unreadable.len(),
            h(&r.unreadable.join("\n      "))
        );
    }

    if r.findings.is_empty() {
        println!("\n  nothing about the credentials on this host matched a shape worth explaining.");
    }
    for f in &r.findings {
        println!("\n  [{:?}] {}", f.severity, h(&f.what));
        println!("      at {}", h(&f.locus));
        if !f.why.is_empty() {
            println!("      {}", h(&f.why));
        }
    }

    ad_exit(&r.unreadable)
}

#[cfg(any(target_os = "linux", test))]
fn ad_exit(unreadable: &[String]) -> u8 {
    if unreadable.is_empty() {
        EXIT_OK
    } else {
        EXIT_PARTIAL
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn print_firewall(json: bool) -> u8 {
    let r = hemostat_sensor_linux::firewall_report();

    let code = if r.unreadable.is_some() { EXIT_PARTIAL } else { EXIT_OK };
    let backend = match r.backend {
        Some(hemostat_sensor_linux::Backend::Nftables) => "nftables",
        Some(hemostat_sensor_linux::Backend::IptablesLegacy) => "iptables-legacy",
        None => "none found",
    };
    if json {
        jprintln!(
            "{{\"backend\":\"{backend}\",\"trust\":\"{}\",\"input_policy\":\"{}\",\
             \"rule_count\":{},\"accepting_ports\":[{}],\"unreadable\":{}}}",
            r.trust.tag(),
            r.input_policy.as_deref().unwrap_or("unknown"),
            r.rule_count,
            r.accepting_ports.iter().map(u16::to_string).collect::<Vec<_>>().join(","),
            r.unreadable.as_deref().map_or_else(|| "null".to_string(), |u| format!("\"{}\"", jesc(u))),
        );
        return code;
    }
    println!("firewall: {backend}  [trust: {}]", r.trust.tag());
    println!("  {}", r.trust.explain());
    if r.backend.is_some() {
        println!("\n  default input policy: {}", r.input_policy.as_deref().unwrap_or("unknown"));
        println!("  rules: {}", r.rule_count);
        println!(
            "  accepting ports: {}",
            if r.accepting_ports.is_empty() { "none explicit".to_string() }
            else { r.accepting_ports.iter().map(u16::to_string).collect::<Vec<_>>().join(", ") }
        );
    } else if let Some(reason) = &r.unreadable {

        println!("\n  ruleset NOT read: {}", h(reason));
    }
    code
}

#[cfg(target_os = "linux")]
pub(crate) fn print_suid(json: bool) -> u8 {
    let r = hemostat_sensor_linux::suid::report();
    print_findings(
        "SUID/SGID + capability + immutable scan",
        r.available,
        r.reason.as_deref(),
        &r.findings,
        json,
    )
}

#[cfg(target_os = "linux")]
pub(crate) fn print_inventory(json: bool) -> u8 {
    let r = hemostat_sensor_linux::inventory::report_with(crate::vendor::manifest_for("inventory").as_deref());
    print_findings(
        "inventory (package integrity + unpackaged + suspicious units)",
        r.available,
        r.reason.as_deref(),
        &r.findings,
        json,
    )
}

#[cfg(target_os = "linux")]
pub(crate) fn services_verb(args: &[String], json: bool) -> u8 {
    use hemostat_sensor_linux::services;

    let mut declared = services::declarations();

    let named = match repeated_flag_values(args, "--service") {
        Ok(v) => v,
        Err(flag) => {
            eprintln!("hemostat services: every {flag} needs a unit name, e.g. {flag} nginx");
            return EXIT_USAGE;
        }
    };
    for value in named {
        if let Some(d) = services::parse_line(&value) {
            if !declared.iter().any(|k| k.unit == d.unit) {
                declared.push(d);
            }
        }
    }

    if let Some(i) = args.iter().position(|a| a == "--start") {
        let Some(unit) = args.get(i + 1).map(String::as_str) else {
            eprintln!("hemostat services --start <unit> [--arm]: name the unit to enable and start");
            return EXIT_USAGE;
        };
        if !declared.iter().any(|d| d.unit.as_str() == unit) {
            eprintln!(
                "hemostat services: `{unit}` is not a declared service. Declare it in \
                 /etc/hemostat/critical (or pass --service {unit}) before starting it, so \
                 HEMOSTAT only acts on units you have named."
            );
            return EXIT_POLICY;
        }
        return crate::actions::start_service(unit, args);
    }

    if args.iter().any(|a| a == "--baseline") {
        eprintln!(
            "hemostat services: --baseline is retired. The baseline is now the declared \
             services' records in the sealed arrival snapshot — take it with `hemostat \
             snapshot` (declare the services first), and keep the seal key it prints off-host"
        );
        return EXIT_USAGE;
    }

    let store = args
        .iter()
        .position(|a| a == "--store")
        .and_then(|i| args.get(i + 1))
        .map_or(crate::snapshot::DEFAULT_STORE, String::as_str);
    let r = services::check(
        &declared,
        &crate::snapshot::service_baseline(store),
        crate::vendor::manifest_for("services").as_deref(),
    );

    if json {
        let roster: Vec<String> = r
            .services
            .iter()
            .map(|s| {
                format!(
                    "{{\"unit\":\"{}\",\"load\":\"{}\",\"active\":\"{}\",\"enabled\":\"{}\",\
                     \"fragment\":\"{}\",\"dropins\":{},\"exec\":\"{}\"}}",
                    jesc(&s.unit), jesc(&s.loaded), jesc(&s.active), jesc(&s.enabled),
                    jesc(&s.fragment.as_ref().map(|p| p.display().to_string()).unwrap_or_default()),
                    s.dropins.len(),
                    jesc(&s.exec.as_ref().map(|p| p.display().to_string()).unwrap_or_default()),
                )
            })
            .collect();
        let items: Vec<String> = r
            .findings
            .iter()
            .map(|f| detection_json("services", f.severity.tag(), &f.subject, &f.locus, &f.what, &f.why))
            .collect();
        jprintln!(
            "{{\"available\":{},\"declared\":{},\"packager\":\"{}\",\"baseline_compared\":{},\
             \"baseline_rows\":{},\"baseline_digest\":\"{}\",\
             \"reason\":\"{}\",\"services\":[{}],\"findings\":[{}]}}",
            r.available, r.declared, jesc(r.packager.as_deref().unwrap_or("")),
            r.baseline_compared, r.baseline_rows, jesc(&r.baseline_digest),
            jesc(r.reason.as_deref().unwrap_or("")),
            roster.join(","), items.join(",")
        );
        return services_exit(&r);
    }

    println!("critical services — declared by the operator, not inferred\n");
    if !r.available {
        println!("  NOT MEASURED: {}", h(r.reason.as_deref().unwrap_or("unknown")));
        return services_exit(&r);
    }
    if r.declared == 0 {
        println!("  {}", h(r.reason.as_deref().unwrap_or("")));

        if r.declaration_unreadable {
            for f in &r.findings {
                println!("  [{}] {}", f.severity.tag(), h(&f.locus));
                println!("        {}", h(&f.what));
                if !f.why.is_empty() {
                    println!("        why: {}", h(&f.why));
                }
            }
            return services_exit(&r);
        }
        println!(
            "\n  Example:\n    \
             # unit                paths that belong to it\n    \
             nginx                 /etc/nginx/nginx.conf /etc/nginx/conf.d\n    \
             mariadb.service       /etc/mysql\n    \
             named.service\n\n  \
             A line here also protects the service: no removal will touch it."
        );
        return EXIT_OK;
    }

    for s in &r.services {
        let state = if s.loaded == "not-found" || s.loaded.is_empty() {
            "NOT FOUND".to_string()
        } else if s.enabled == "masked" {
            "MASKED".to_string()
        } else if s.active == "active" {
            format!("up, {}", if s.enabled.is_empty() { "—" } else { &s.enabled })
        } else {
            format!("{}, {}", s.active, if s.enabled.is_empty() { "—" } else { &s.enabled })
        };
        let ok = s.active == "active" && s.enabled != "masked";
        println!("  [{}] {:<28} {}", if ok { "up " } else { "DOWN" }, h(&s.unit), h(&state));

        if !s.id.is_empty() && s.id != s.unit {
            println!("       is:    {} (an alias)", h(&s.id));
        }

        if let Some(f) = &s.fragment {
            println!("       unit:  {}", h(&f.display().to_string()));
        }
        for d in &s.dropins {
            println!("       +      {}", h(&d.display().to_string()));
        }
        if let Some(e) = &s.exec {
            println!("       runs:  {}", h(&e.display().to_string()));
        }
    }

    println!();
    match (&r.packager, r.baseline_compared) {
        (Some(p), true) => println!("  checked against the {p} packages and the arrival snapshot"),
        (Some(p), false) => println!(
            "  checked against the {p} packages · NO ARRIVAL SNAPSHOT — files no package owns \
             cannot be judged. Take one with `hemostat snapshot`"
        ),
        (None, true) => println!(
            "  checked against the arrival snapshot · no package manager found, so packaged \
             files could not be verified"
        ),
        (None, false) => println!(
            "  NEITHER CHECK AVAILABLE: no package manager found and no arrival snapshot — \
             only the service state above was measured"
        ),
    }

    if !r.baseline_digest.is_empty() {
        println!(
            "  arrival snapshot: {} service file(s) · seal key {} — compare against the one you kept off-host",
            r.baseline_rows,
            h(&r.baseline_digest)
        );
    }

    if r.findings.is_empty() {
        println!("\n  Nothing has touched them, by every check that could run.");
        return services_exit(&r);
    }
    println!();
    for f in &r.findings {
        println!("  [{}] {}", f.severity.tag(), h(&f.locus));
        println!("        {}", h(&f.what));
        if !f.why.is_empty() {
            println!("        why: {}", h(&f.why));
        }
    }
    services_exit(&r)
}

#[cfg(target_os = "linux")]
fn services_exit(r: &hemostat_sensor_linux::services::Report) -> u8 {
    if !r.available || r.declaration_unreadable {
        EXIT_PARTIAL
    } else {
        EXIT_OK
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn watch(json: bool) -> u8 {
    use hemostat_sensor_linux::ebpf_sensor as sensor;
    let mut s = match sensor::load() {
        Ok(s) => s,
        Err(e) => {
            eprintln!(
                "watch: NOT ARMED — the eBPF exec sensor could not load at {} (errno {})",
                e.stage.token(),
                e.errno
            );
            eprintln!("  {}", e.stage.meaning(e.errno));
            if let Some(log) = &e.verifier_log {
                eprintln!("  verifier: {log}");
            }

            return EXIT_PARTIAL;
        }
    };
    if !json {
        println!(
            "watch: live exec sensor armed — alerting on reverse-shell-shaped execs. Ctrl-C to stop."
        );
        println!();
    }
    loop {
        match s.poll_events(500) {
            Ok(events) => {
                for ev in &events {
                    let facts = sensor::gather_facts(ev);
                    if let Some(f) = sensor::classify(ev, &facts) {
                        if json {
                            jprintln!("{}", rootkit_row(&f));
                        } else {
                            println!("  [{}] {} — {}", f.severity.tag(), h(&f.subject), h(&f.what));
                        }
                    }
                }
            }
            Err(e) => {
                eprintln!("watch: ring-buffer poll failed: {e}");
                return EXIT_PARTIAL;
            }
        }
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn print_overview(json: bool) -> u8 {
    use hemostat_sensor_linux::overview;

    let r = overview::report();
    let i = &r.identity;
    let code = crate::coverage::overview(&r).exit_code();

    if json {

        let socks = r
            .listeners()
            .map(|s| {
                format!(
                    "{{\"proto\":\"{}\",\"local\":\"{}\",\"port\":{},\"uid\":{},\
                     \"pid\":{},\"comm\":\"{}\"}}",
                    s.proto,
                    jesc(&s.local),
                    s.port,
                    s.uid,
                    s.pid.map_or_else(|| "null".into(), |p| p.to_string()),
                    jesc(s.comm.as_deref().unwrap_or("")),
                )
            })
            .collect::<Vec<_>>()
            .join(",");

        let finds = r
            .findings
            .iter()
            .map(|f| {
                triage_row(f)
            })
            .collect::<Vec<_>>()
            .join(",");
        jprintln!(
            "{{\"hostname\":\"{}\",\"kernel\":\"{}\",\"distro\":\"{}\",\"uptime_secs\":{},\
             \"boot_epoch\":{},\"processes\":{},\"modules\":{},\"mem_total_kb\":{},\
             \"sockets\":{},\"mapped_any\":{},\"listeners\":[{socks}],\"findings\":[{finds}]}}",
            jesc(&i.hostname),
            jesc(&i.kernel),
            jesc(&i.distro),
            i.uptime_secs,
            i.boot_epoch,
            i.processes,
            i.modules,
            i.mem_total_kb,
            r.sockets.len(),
            r.mapped_any,
        );
        return code;
    }

    println!("--- host ---");

    println!("  hostname   {}", h(&i.hostname));
    println!("  kernel     {}", h(&i.kernel));
    println!("  distro     {}", h(&i.distro));
    println!("  uptime     {}", human_secs(i.uptime_secs));
    println!("  processes  {}", i.processes);
    println!("  modules    {}", i.modules);
    println!(
        "  memory     {} MiB total, {} MiB available",
        i.mem_total_kb / 1024,
        i.mem_available_kb / 1024
    );

    let listeners: Vec<_> = r.listeners().collect();
    println!("\n--- listening ({}) ---", listeners.len());
    if listeners.is_empty() {
        println!("  nothing is listening, or /proc/net could not be read");
    }
    for s in &listeners {

        let owner = match (&s.comm, s.pid) {
            (Some(c), Some(p)) => format!("{} (pid {p})", h(c)),
            _ => "?".to_string(),
        };
        println!(
            "  {:<5} {:<28} uid {:<6} {}{}",
            s.proto,
            format!("{}:{}", s.local, s.port),
            s.uid,
            owner,
            if s.world_reachable() { "  <- reachable off-host" } else { "" }
        );
    }

    println!("\n--- connections ---");
    println!("{}", connections_line(&r.sockets));
    if r.other_namespaces > 0 {
        println!(
            "  {} of them in {} other network namespace(s) — containers, `nsenter`. Those are\n  \
             not this host's own ports and are not in the table above; a finding about one\n  \
             names its namespace",
            r.sockets.iter().filter(|s| s.netns.is_some()).count(),
            r.other_namespaces
        );
    }

    if !r.findings.is_empty() {
        println!("\n--- findings ---");
        for f in &r.findings {
            println!("  [{}] {} — {}", f.severity.tag(), h(&f.subject), h(&f.locus));
            println!("      {}", h(&f.what));
            if !f.why.is_empty() {
                println!("      why: {}", h(&f.why));
            }
        }
    }

    println!(
        "\nSockets are read from /proc/net directly rather than through `ss` or `netstat`,\n\
         which are dynamically linked and so are subject to an LD_PRELOAD rootkit's\n\
         interception. This shares the kernel's surface instead: trust Syscall."
    );
    code
}

#[cfg(target_os = "linux")]
fn connections_line(sockets: &[hemostat_sensor_linux::overview::Socket]) -> String {
    let in_state = |state: &str| sockets.iter().filter(|s| s.state == state).count();
    format!(
        "  {} established, {} still connecting, {} sockets total",
        in_state("ESTABLISHED"),
        in_state("SYN_SENT"),
        sockets.len()
    )
}

#[cfg(target_os = "linux")]
pub(crate) fn print_injected(json: bool) -> u8 {
    use hemostat_sensor_linux::hooked;
    use hemostat_sensor_linux::triage::Severity;

    let r = hooked::report();

    let code = crate::coverage::injected(&r).exit_code();

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
            "{{\"examined\":{},\"unreadable\":{},\"maps_unreadable\":{},\"maps_capped\":{},\
             \"env_unreadable\":{},\"vanished\":{},\"marked\":{},\"anon_exec_total\":{},\
             \"critical\":{},\"findings\":[{f}]}}",
            r.examined,
            r.unreadable,
            r.maps_unreadable,
            r.maps_capped,
            r.env_unreadable,
            r.vanished,
            r.processes.len(),
            r.anon_exec_total,
            r.count_at_least(Severity::Critical),
        );
        return code;
    }

    println!(
        "injection surface: {} process(es) examined, {} unreadable, {} carrying a mark",
        r.examined,
        r.unreadable,
        r.processes.len()
    );
    if r.unreadable > 0 {
        println!(
            "  {} process(es) could not be read — those are unchecked, not clean. Re-run as root.",
            r.unreadable
        );
    }
    if r.vanished > 0 {
        println!("  {} more exited before they could be read in full.", r.vanished);
    }
    if r.maps_capped > 0 {
        println!(
            "  {} process(es) have a memory map over the read cap — examined only in part, not clean.",
            r.maps_capped
        );
    }
    println!();

    if r.examined == 0 {

        println!("  DID NOT RUN — /proc listed no processes. Nothing is claimed about any of them.");
    } else if r.findings.is_empty() {
        println!("  no process carries any of the marks this sweep looks for.");
    }
    for f in &r.findings {
        println!("  [{}] {} — {}", f.severity.tag(), h(&f.subject), h(&f.locus));
        println!("      {}", h(&f.what));
        if !f.why.is_empty() {
            println!("      why: {}", h(&f.why));
        }
    }

    println!(
        "\n  {} executable anonymous mapping(s) across all processes — counted, not listed:\n  \
         every JIT has them and listing them would bury the findings above.",
        r.anon_exec_total
    );
    println!(
        "\nThe methods checked are: ptrace attachment, LD_PRELOAD and LD_AUDIT, libraries\n\
         mapped from unexpected directories, memfd-backed execution, and running from a\n\
         deleted file. An implant hiding by a method not in that list is not found here.\n\
         All of it is read from /proc, so a kernel rootkit can lie about any of it."
    );
    code
}

#[cfg(target_os = "linux")]
pub(crate) fn print_persistence(json: bool, all: bool) -> u8 {
    use hemostat_sensor_linux::persist;
    use hemostat_sensor_linux::triage::Severity;

    let r = persist::report();

    let e = hemostat_sensor_linux::enablement::report();
    let systemd_at_least = |s: Severity| e.findings.iter().filter(|f| f.severity >= s).count();
    let critical = r.count_at_least(Severity::Critical) + systemd_at_least(Severity::Critical);
    let warn = r.count_at_least(Severity::Warn) + systemd_at_least(Severity::Warn);
    let code = persistence_exit(&r, &e);

    if json {
        let obs = r
            .observations
            .iter()
            .map(|o| {
                format!(
                    "{{\"id\":\"{}\",\"category\":\"{}\",\"coverage\":\"{}\",\"entries\":{}}}",
                    o.id,
                    o.category.token(),
                    o.coverage.token(),
                    o.entries
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        let f = r
            .findings
            .iter()
            .filter(|f| all || f.severity > Severity::Info)
            .map(|f| {
                triage_row(f)
            })
            .collect::<Vec<_>>()
            .join(",");

        let sd = e.findings.iter().map(triage_row).collect::<Vec<_>>().join(",");
        jprintln!(
            "{{\"established\":{},\"total\":{},\"critical\":{critical},\"warn\":{warn},\
             \"observations\":[{obs}],\"findings\":[{f}],\
             \"systemd\":{{\"applicable\":{},\"available\":{},\"reason\":{},\"examined\":{},\
             \"enabled\":{},\"findings\":[{sd}]}}}}",
            r.established,
            r.total,
            e.other_init.is_none(),
            e.available,
            e.reason.as_deref().map_or_else(|| "null".to_string(), json_str),
            e.examined,
            e.enabled.len(),
        );
        return code;
    }

    println!(
        "persistence: {} of {} mechanisms established, {} critical, {} to explain",
        r.established,
        r.total,
        critical,
        warn - critical,
    );
    if r.established < r.total {

        println!(
            "  {} mechanism(s) could NOT be read in full. Those surfaces are unchecked, not clean.",
            r.total - r.established
        );
    }
    println!();

    for (cat, obs) in persist::by_category(&r) {
        println!("--- {} ---", cat.token());
        for o in obs {
            let entries = if o.entries > 0 { format!("{} entry(s)", o.entries) } else { String::new() };
            println!("  {:<28} {:<13} {}", o.id, o.coverage.token(), entries);
        }
    }

    let shown: Vec<_> = r.findings.iter().filter(|f| all || f.severity > Severity::Info).collect();
    if !shown.is_empty() {
        println!("\n--- findings ---");
        for f in shown {
            println!("  [{}] {} — {}", f.severity.tag(), h(&f.subject), h(&f.locus));
            println!("      {}", h(&f.what));
            if !f.why.is_empty() {
                println!("      why: {}", h(&f.why));
            }
        }
    }

    let hidden = r.findings.len() - r.findings.iter().filter(|f| f.severity > Severity::Info).count();
    if !all && hidden > 0 {
        println!("\n  {hidden} inventory row(s) hidden; --all shows every entry found.");
    }

    if e.available {
        println!("\n--- what systemd says will start ---");
        println!(
            "  {} service unit(s) examined, {} enabled",
            e.examined,
            e.enabled.len()
        );

        if let Some(why) = &e.reason {
            println!("  NOT FULLY ASKED: {}", h(why));
        }
        if e.findings.is_empty() {
            if e.reason.is_none() {
                println!(
                    "  every loaded unit has a file, and every file is inside the tree swept above."
                );
            }
        } else {
            for f in &e.findings {
                println!("  [{}] {} — {}", f.severity.tag(), h(&f.subject), h(&f.locus));
                println!("      {}", h(&f.what));
                println!("      why: {}", h(&f.why));
            }
        }
    } else if let Some(why) = &e.reason {
        println!("\n--- what systemd says will start ---");
        let label = if e.other_init.is_some() { "not applicable" } else { "NOT ASKED" };
        println!("  {label}: {}", h(why));
    }

    println!(
        "\nEverything above is read through the ordinary filesystem calls, so it is trust\n\
         Syscall: a root attacker edits these files and a kernel rootkit can hide them\n\
         from the read entirely. A clean sweep is evidence, not proof.\n\
         What is not in the catalogue is not searched — `{}` rows, listed above.\n\
         The systemd section is a second, independent source and is trusted no further:\n\
         `systemctl` is a binary on a host whose adversary is root, and what it prints is a\n\
         rendered view in the same sense /proc/modules is. Its value is the disagreement.",
        r.total
    );
    code
}

#[cfg(target_os = "linux")]
fn persistence_exit(
    r: &hemostat_sensor_linux::PersistReport,
    e: &hemostat_sensor_linux::enablement::Report,
) -> u8 {
    crate::coverage::persistence(r).exit_code().max(crate::coverage::enablement(e).exit_code())
}

#[cfg(target_os = "linux")]
pub(crate) fn print_accounts(json: bool) -> u8 {
    let r = hemostat_sensor_linux::account_report();
    let code = crate::coverage::accounts(&r).exit_code();

    if json {
        let f = r
            .findings
            .iter()
            .map(|f| {
                accounts_row(f)
            })
            .collect::<Vec<_>>()
            .join(",");

        jprintln!(
            "{{\"accounts\":{},\"available\":{},\"unread\":{},\"findings\":[{f}]}}",
            r.accounts.len(),
            r.available,
            json_array(&r.unread)
        );
        return code;
    }

    println!("accounts: {} local, structural checks only", r.accounts.len());
    if r.findings.is_empty() {
        println!("\nno findings.");
    } else {
        println!();
        for f in &r.findings {
            println!("  [{}] {}", f.severity.tag(), h(&f.subject));
            println!("      {}", h(&f.what));
            println!("      why: {}", h(&f.why));
        }
    }
    println!(
        "\nThese are structural findings only — each is true about the account\n\
         regardless of what was expected. The agent keeps no baseline of\n\
         \"correct\" accounts, because it arrives on a host already assumed\n\
         compromised and there is no trustworthy earlier state to compare to."
    );
    code
}

#[cfg(all(feature = "mod-tui", not(target_os = "freebsd")))]
pub(crate) fn print_posture() {
    use hemostat_tui::to_text;
    print!("{}", to_text(&posture_model(), 102, 30));
}

#[cfg(target_os = "linux")]
pub(crate) fn print_sysctl() -> u8 {
    use hemostat_sensor_linux::sysctlpolicy as sp;
    let r = sp::report();
    if !r.available {
        println!("sysctl: DID NOT RUN — {}", h(r.reason.as_deref().unwrap_or("")));
        return EXIT_PARTIAL;
    }
    if r.findings.is_empty() {
        println!("sysctl: every checked tunable is at its hardened value.");
        println!("({} controls checked against the running kernel.)", sp::CONTROLS.len());
        return EXIT_OK;
    }
    for f in &r.findings {
        println!("[{:?}] {}", f.severity, h(&f.subject));
        println!("    {}", h(&f.what));
        println!("    {}", h(&f.why));
        println!();
    }
    let offerable = r
        .findings
        .iter()
        .filter(|f| {
            let key = f.subject.strip_prefix("sysctl · ").unwrap_or(&f.subject);
            sp::CONTROLS
                .iter()
                .find(|c| c.keys.first() == Some(&key))
                .is_some_and(|c| matches!(c.auto, sp::Auto::Offer))
        })
        .count();
    println!(
        "{} finding(s); {} can be fixed from the console, the rest are explained above and",
        r.findings.len(),
        offerable
    );
    println!("left to you deliberately.");
    EXIT_OK
}

#[cfg(all(target_os = "linux", feature = "mod-sensor-fanotify"))]
pub(crate) fn print_fswatch(args: &[String], json: bool) -> u8 {
    use hemostat_sensor_linux::fanotify;

    let seconds: u64 = args
        .iter()
        .position(|a| a == "--seconds")
        .and_then(|i| args.get(i + 1))
        .and_then(|v| v.parse().ok())
        .unwrap_or(60);

    let dirs = fanotify::default_loci();
    if dirs.is_empty() {
        eprintln!(
            "hemostat fswatch: none of the persistence directories this would watch exist on              this host. Nothing was watched, which is NOT the same as nothing happening"
        );
        return EXIT_PARTIAL;
    }

    let watch = match fanotify::arm(&dirs) {
        Ok(w) => w,
        Err(e) => {
            eprintln!("hemostat fswatch: {}", h(&e.message()));

            return EXIT_PARTIAL;
        }
    };

    if json {
        jprintln!("{{\"watching\":{},\"blind\":{},\"seconds\":{seconds}}}",
            watch.marked().len(), watch.skipped().len());
    } else {
        println!("{}", watch.coverage());
        println!();
        println!(
            "This reports what happens from NOW. It says nothing about what was already on the \
             host — run a sweep for that. It does not see deletions or renames."
        );
        println!();
    }

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(seconds);
    let show_all = args.iter().any(|a| a == "--all");

    let mut written: std::collections::BTreeSet<std::path::PathBuf> = std::collections::BTreeSet::new();
    let mut seen = 0_usize;
    let mut routine = 0_usize;
    let mut lost_said = 0_u32;
    while std::time::Instant::now() < deadline {
        let events = watch.drain(500);

        if watch.overflowed() > lost_said {
            lost_said = watch.overflowed();
            if !json {
                println!(
                    "  !! events LOST here: the kernel's event queue overflowed and dropped what \
                     did not fit. What follows is incomplete."
                );
            }
        }
        for ev in events {
            seen += 1;
            let kind = fanotify::classify(&ev, &written);
            if matches!(kind, fanotify::Kind::Wrote) {
                written.insert(ev.path.clone());
            }
            if !kind.worth_printing_by_default() {
                routine += 1;
                if !show_all {
                    continue;
                }
            }
            let who = crate::actions::comm_of(ev.pid);
            let tracked = hemostat_sensor_linux::snapshot::is_tracked(&ev.path);
            if json {

                jprintln!(
                    "{{\"path\":{},\"pid\":{},\"comm\":{},\"what\":{},\"event\":{},\"tracked\":{tracked}}}",
                    json_str(&ev.path.display().to_string()),
                    ev.pid,
                    json_str(&who),
                    json_str(&fanotify::describe(ev.mask)),
                    json_str(kind.phrase())
                );
            } else {

                println!(
                    "  {} — {} by pid {} ({})",
                    h(&ev.path.display().to_string()),
                    if matches!(kind, fanotify::Kind::RanAfterWrite) {
                        kind.phrase().to_string()
                    } else {
                        fanotify::describe(ev.mask)
                    },
                    ev.pid,
                    h(&who)
                );
                if tracked {
                    println!("      recorded by the arrival snapshot — `hemostat drift` names what changed");
                }
            }
        }
    }

    if !json {
        println!();

        if routine > 0 && !show_all {
            println!(
                "  ({routine} routine execution(s) of files that were NOT written during this \
                 watch are not listed — on a host with logins, /etc/update-motd.d alone \
                 accounts for most of them. `--all` shows every event.)"
            );
        }
        println!(
            "{seen} event(s) in {seconds}s. {}",
            if watch.skipped().is_empty() {
                "Every requested directory was watched.".to_string()
            } else {
                format!(
                    "{} director(ies) were NOT watched, so this is a PARTIAL result.",
                    watch.skipped().len()
                )
            }
        );
    }

    if watch.overflowed() > 0 {
        if json {
            jprintln!("{{\"lost\":true,\"queue_overflows\":{}}}", watch.overflowed());
        } else {
            println!(
                "Events were LOST: the kernel's event queue overflowed {} time(s) \
                 (fs.fanotify.max_queued_events), so this is a PARTIAL result.",
                watch.overflowed()
            );
        }
    }
    if watch.skipped().is_empty() && watch.overflowed() == 0 {
        EXIT_OK
    } else {
        EXIT_PARTIAL
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn print_watchdog(json: bool, watch_secs: Option<u64>) -> u8 {
    let single = hemostat_sensor_linux::watchdog::report();
    let available = single.available;
    let reason = single.reason.clone();
    let code = crate::coverage::from_flag(available, &reason).exit_code();
    let findings = match watch_secs {
        Some(n) => {
            if !json {
                println!("watching for {n}s to see what comes back...");
            }
            let mut f = single.findings;
            f.extend(hemostat_sensor_linux::watchdog::watch(n));
            f
        }
        None => single.findings,
    };

    if json {

        fn q(s: &str) -> String {
            let mut out = String::with_capacity(s.len() + 2);
            out.push('"');
            for c in s.chars() {
                match c {
                    '"' => out.push_str("\\\""),
                    '\\' => out.push_str("\\\\"),
                    '\n' => out.push_str("\\n"),
                    '\r' => out.push_str("\\r"),
                    '\t' => out.push_str("\\t"),
                    c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
                    c => out.push(c),
                }
            }
            out.push('"');
            out
        }

        let rows: Vec<String> = findings.iter().map(rootkit_row).collect();
        jprintln!(
            "{{\"available\":{available},\"reason\":{},\"findings\":[{}]}}",
            q(reason.as_deref().unwrap_or("")),
            rows.join(",")
        );
        return code;
    }

    if !available {
        println!("watchdog: DID NOT RUN — {}", h(reason.as_deref().unwrap_or("")));
        println!();
        println!("  Nothing is claimed about guard pairs or restart loops on this host.");
        println!("  This is not a clean result; it is no result. Re-run with privilege.");
        return code;
    }

    if findings.is_empty() {
        println!("watchdog: nothing found.");
        println!();
        println!("  No mutual guard pairs and no hand-rolled restart loops. That is the");
        println!("  expected result on a clean host: legitimate supervision goes through");
        println!("  systemd, which this deliberately does not flag.");
        println!();
        println!("  This is a one-shot look at /proc. To see what actually comes back,");
        println!("  run `hemostat watchdog --watch 30`.");
        return code;
    }

    for f in &findings {
        println!("[{:?}] {}", f.severity, h(&f.subject));
        println!("    {}", h(&f.what));
        println!("    {}", h(&f.why));
        println!();
    }
    println!(
        "{} finding(s). Remove a group from the console (`hemostat console`), which freezes",
        findings.len()
    );
    println!("every member before killing any of them.");
    code
}

#[cfg(target_os = "linux")]
pub(crate) fn print_ps(json: bool) {
    let procs = hemostat_sensor_linux::walk();
    let readable: Vec<_> = procs.iter().filter(|p| p.exe.is_some()).collect();

    if json {
        jprintln!(
            "{{\"visible\":{},\"image_readable\":{}}}",
            procs.len(),
            readable.len()
        );
        return;
    }

    println!(
        "procfs floor: {} processes visible, {} with a readable image",
        procs.len(),
        readable.len()
    );
    if readable.len() < procs.len() {
        println!(
            "  {} opaque: kernel threads have no image, and unprivileged the agent\n  \
             can only resolve /proc/<pid>/exe for its own user.",
            procs.len() - readable.len()
        );
    }
    println!("\n{:>8} {:>8} {:>6}  IMAGE", "PID", "PPID", "UID");
    for p in readable.iter().take(12) {
        let img = h(p.exe.as_deref().unwrap_or("(unreadable)"));
        println!("{:>8} {:>8} {:>6}  {img}", p.pid, p.ppid, p.uid);
    }
    if readable.len() > 12 {
        println!("  ... and {} more with readable images", readable.len() - 12);
    }

}
