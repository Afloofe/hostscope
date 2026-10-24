#[cfg(any(target_os = "linux", target_os = "windows"))]
use crate::render::{h, jesc, wrap_why};

#[cfg(target_os = "linux")]
fn store_arg(args: &[String]) -> String {
    args.iter()
        .position(|a| a == "--store")
        .and_then(|i| args.get(i + 1))
        .cloned()
        .unwrap_or_else(|| crate::snapshot::DEFAULT_STORE.to_string())
}

#[cfg(target_os = "linux")]
pub(crate) fn linux_report(args: &[String]) -> hemostat_sensor_linux::trust::Report {
    hemostat_sensor_linux::trust::report_with(&crate::snapshot::anchor_baseline(&store_arg(args)))
}

#[cfg(all(target_os = "linux", feature = "mod-enf-persistence"))]
pub(crate) fn removal_command(locus: &str, what: &str) -> Option<String> {
    let fp = fingerprint_in(what)?;
    let o = hemostat_enforce_linux::anchor::offer_for(std::path::Path::new(locus), &fp).ok()?;
    Some(format!("hemostat remediate --remove-anchor '{}'", o.token().replace('\'', "'\\''")))
}

#[cfg(all(target_os = "linux", feature = "mod-enf-persistence"))]
pub(crate) fn fingerprint_in(what: &str) -> Option<String> {
    let rest = what.split("sha256:").nth(1)?;
    let fp: String = rest.chars().take_while(char::is_ascii_hexdigit).collect();
    (fp.len() == 64).then_some(fp)
}

#[cfg(target_os = "linux")]
pub(crate) fn print_trust(args: &[String], json: bool) -> u8 {
    use hemostat_sensor_linux::triage::Severity;
    use hemostat_evcrypto::x509::Level;
    let all = args.iter().any(|a| a == "--all");
    let r = linux_report(args);
    let code = crate::coverage::trust(&r).exit_code();
    let crit = r.count_at_least(Severity::Critical);
    let warn = r.count_at_least(Severity::Warn) - crit;

    if json {
        let rows: Vec<String> = r
            .findings
            .iter()
            .filter(|f| all || f.severity > Severity::Info)
            .map(crate::render::triage_row)
            .collect();
        let anchors: Vec<String> = r
            .anchors
            .iter()
            .filter(|a| all || a.grade.level != Level::Info)
            .map(|a| {
                format!(
                    "{{\"sha256\":\"{}\",\"subject\":\"{}\",\"issuer\":\"{}\",\"not_before\":\"{}\",\"not_after\":\"{}\",\
                     \"level\":\"{}\",\"origin\":\"{:?}\",\"arrival\":\"{:?}\",\"signs_any\":{},\"inert\":{},\"locus\":\"{}\",\
                     \"package\":{},\"places\":[{}]}}",
                    a.cert.sha256_hex(),
                    jesc(&a.cert.subject),
                    jesc(&a.cert.issuer),
                    hemostat_evcrypto::x509::ymd(a.cert.not_before),
                    hemostat_evcrypto::x509::ymd(a.cert.not_after),
                    a.grade.level.tag(),
                    a.origin,
                    a.arrival,
                    a.grade.signs_any,
                    a.inert,
                    jesc(&a.locus.to_string_lossy()),
                    a.package().map_or_else(|| "null".to_string(), |p| format!("\"{}\"", jesc(p))),
                    a.seen
                        .iter()
                        .map(|s| format!("{{\"path\":\"{}\",\"place\":\"{}\",\"block\":{}}}", jesc(&s.path.to_string_lossy()), s.place.label(), s.block))
                        .collect::<Vec<_>>()
                        .join(",")
                )
            })
            .collect();
        jprintln!(
            "{{\"available\":{},\"reason\":{},\"packages\":{},\"baseline\":\"{}\",\"anchors_total\":{},\"critical\":{crit},\"warn\":{warn},\
             \"bundles\":[{}],\"unread\":[{}],\"findings\":[{}],\"anchors\":[{}],\"complete\":{}}}",
            r.available,
            r.reason.as_deref().map_or_else(|| "null".to_string(), |w| format!("\"{}\"", jesc(w))),
            r.packages.map_or_else(|| "null".to_string(), |p| format!("\"{p}\"")),
            jesc(&r.baseline),
            r.anchors.len(),
            r.bundles.iter().map(|(p, n)| format!("{{\"path\":\"{}\",\"certificates\":{n}}}", jesc(&p.to_string_lossy()))).collect::<Vec<_>>().join(","),
            r.unread.iter().map(|u| format!("\"{}\"", jesc(u))).collect::<Vec<_>>().join(","),
            rows.join(","),
            anchors.join(","),
            code == crate::EXIT_OK
        );
        return code;
    }

    println!("trust — the TLS trust store: every certificate this host will believe about any name");
    if !r.available {
        println!("  DID NOT RUN: {}", h(r.reason.as_deref().unwrap_or("no reason given")));
        return code;
    }
    println!(
        "  {} anchor(s) · {crit} critical · {warn} to explain · package record: {} · {}",
        r.anchors.len(),
        r.packages.unwrap_or("none (nothing is the vendor's by its word)"),
        h(&r.baseline)
    );
    for (p, n) in &r.bundles {
        println!("  read {} ({n} certificate(s))", h(&p.to_string_lossy()));
    }
    let shown: Vec<_> = r.findings.iter().filter(|f| all || f.severity > Severity::Info).collect();
    if shown.is_empty() {
        println!("\n  every anchor is one a package ships and still matches; nothing points TLS elsewhere.");
    } else {
        println!("\n--- findings ---");
        for f in shown {
            println!("  [{}] {} — {}", f.severity.tag(), h(&f.subject), h(&f.locus));
            println!("{}", wrap_why(&h(&f.what), "      "));
            if !f.why.is_empty() {
                println!("{}", wrap_why(&h(&f.why), "      why: "));
            }
            #[cfg(feature = "mod-enf-persistence")]
            if f.severity >= Severity::Warn {
                if let Some(cmd) = removal_command(&f.locus, &f.what) {
                    println!("      remove (a dry run until --arm): {}", h(&cmd));
                }
            }
        }
    }
    if all {
        println!("\n--- every anchor ---");
        for a in &r.anchors {
            println!(
                "  {:<8} {} · {} · {}",
                a.grade.level.tag(),
                h(&a.cert.subject),
                h(a.package().unwrap_or(if a.grade.level == Level::Info { "vendor" } else { "-" })),
                h(&a.locus.to_string_lossy())
            );
        }
    } else {
        let hidden = r.findings.iter().filter(|f| f.severity == Severity::Info).count();
        if hidden > 0 {
            println!("\n  {hidden} inventory row(s) hidden (the distribution's anchors, the system's own settings); --all lists every anchor.");
        }
    }
    for u in &r.unread {
        println!("  NOT READ: {}", h(u));
    }
    println!(
        "\n  NOT in this sweep: Java keystores, certificates an application bundles for itself (certifi,\n  \
         Node's built-in roots), browser profiles beyond Firefox's and ~/.pki/nssdb, and a TLS library\n  \
         recompiled with a different store. Everything here is read through ordinary file calls: a root\n  \
         adversary edits the store and the package record alike, so a clean answer is evidence, not proof."
    );
    code
}

#[cfg(target_os = "windows")]
pub(crate) fn win_covered(r: &hemostat_sensor_win::trust::Report) -> crate::coverage::Covered {
    use crate::coverage::Covered;
    if !r.available {
        Covered::NotAtAll(r.reason.clone().unwrap_or_else(|| "no reason given".into()))
    } else if r.unread.is_empty() {
        Covered::Fully
    } else {
        Covered::InPart(r.unread.join("; "))
    }
}

#[cfg(target_os = "windows")]
pub(crate) fn print_win_trust(args: &[String], json: bool) -> u8 {
    let all = args.iter().any(|a| a == "--all");
    let r = hemostat_sensor_win::trust::report();
    let code = win_covered(&r).exit_code();
    let shipped = r.anchors.iter().filter(|a| a.shipped.is_some()).count();
    if json {
        let anchors: Vec<String> = r
            .anchors
            .iter()
            .filter(|a| all || a.shipped.is_none())
            .map(|a| {
                format!(
                    "{{\"store\":\"{}\",\"thumbprint\":\"{}\",\"sha256\":\"{}\",\"subject\":\"{}\",\"level\":\"{}\",\"shipped\":{},\"signs_any\":{}}}",
                    jesc(&a.store),
                    jesc(&a.key),
                    a.cert.sha256_hex(),
                    jesc(&a.cert.subject),
                    a.level.tag(),
                    a.shipped.as_deref().map_or_else(|| "null".to_string(), |s| format!("\"{}\"", jesc(s))),
                    a.signs_any
                )
            })
            .collect();
        let rows: Vec<String> = r
            .findings
            .iter()
            .map(|f| {
                format!(
                    "{{\"severity\":\"{}\",\"subject\":\"{}\",\"what\":\"{}\",\"why\":\"{}\"}}",
                    f.severity.tag(),
                    jesc(&f.subject),
                    jesc(&f.what),
                    jesc(&f.why)
                )
            })
            .collect();
        jprintln!(
            "{{\"available\":{},\"stores\":{},\"users\":{},\"program_list\":{},\"shipped\":{shipped},\"unread\":[{}],\"findings\":[{}],\"anchors\":[{}],\"complete\":{}}}",
            r.available,
            r.stores,
            r.users,
            r.program,
            r.unread.iter().map(|u| format!("\"{}\"", jesc(u))).collect::<Vec<_>>().join(","),
            rows.join(","),
            anchors.join(","),
            r.complete()
        );
        return code;
    }
    println!("trust — the certificate stores: every root this machine and its users trust, and its trusted publishers");
    if !r.available {
        println!("  DID NOT RUN: {}", h(r.reason.as_deref().unwrap_or("no reason given")));
        return code;
    }
    println!(
        "  {} store(s) read across the machine and {} user hive(s); {} certificate(s), {shipped} of them Microsoft's \
         or its root program's{}",
        r.stores,
        r.users,
        r.anchors.len(),
        if r.program > 0 { format!(" (the host's root-program list names {})", r.program) } else { String::new() }
    );
    if r.findings.is_empty() {
        println!("\n  every certificate is one Microsoft or its root program ships.");
    } else {
        println!("\n--- findings ---");
        for f in &r.findings {
            println!("  [{}] {}", f.severity.tag(), h(&f.subject));
            println!("{}", wrap_why(&h(&f.what), "      "));
            println!("{}", wrap_why(&h(&f.why), "      why: "));
            if let Some(fix) = &f.fix {
                println!("{}", wrap_why(&h(fix), "      fix: "));
            }
        }
    }
    if all {
        println!("\n--- every certificate ---");
        for a in &r.anchors {
            println!("  {:<8} {} · {} · {}", a.level.tag(), h(&a.store), h(&a.cert.subject), h(a.shipped.as_deref().unwrap_or("-")));
        }
    }
    for u in &r.unread {
        println!("  NOT READ: {}", h(u));
    }
    println!(
        "\n  NOT in this sweep: an application's own store (Java, Firefox's cert9.db), certificates installed for\n  \
         a user whose hive is not loaded, and the Disallowed store. Registry reads only: SYSTEM can rewrite every\n  \
         one of these keys, so a clean answer is evidence, not proof."
    );
    code
}
