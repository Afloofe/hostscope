#[cfg(all(target_os = "linux", feature = "mod-collector"))]
use crate::render::{h, hex32, jesc};
#[cfg(all(target_os = "linux", feature = "mod-collector"))]
use crate::{EXIT_FAILED, EXIT_OK};
use crate::EXIT_USAGE;

#[cfg(any(all(any(target_os = "linux", target_os = "windows"), feature = "mod-remote"), all(target_os = "linux", feature = "mod-collector")))]
pub(crate) fn flag_values<'a>(args: &'a [String], flag: &str) -> Vec<&'a str> {
    values(args, flag)
}

#[cfg(any(all(any(target_os = "linux", target_os = "windows"), feature = "mod-remote"), all(target_os = "linux", feature = "mod-collector"), test))]
fn values<'a>(args: &'a [String], flag: &str) -> Vec<&'a str> {
    args.windows(2).filter(|w| w.first().map(String::as_str) == Some(flag)).filter_map(|w| w.get(1).map(String::as_str)).collect()
}

#[cfg(any(all(any(target_os = "linux", target_os = "windows"), feature = "mod-remote"), all(target_os = "linux", feature = "mod-collector"), test))]
pub(crate) fn operands_after_verb<'a>(args: &'a [String], valued: &[&str]) -> Vec<&'a str> {
    let mut out = Vec::new();
    let mut verb_seen = false;
    let mut value_next = false;
    for a in args {
        if std::mem::take(&mut value_next) {
            continue;
        }
        if a.starts_with("--") {
            value_next = valued.contains(&a.as_str());
        } else if verb_seen {
            out.push(a.as_str());
        } else {
            verb_seen = true;
        }
    }
    out
}

pub(crate) fn ship(args: &[String], json: bool) -> u8 {

    const PUSH_VALUED: [&str; 5] = ["--to", "--collector-key", "--receipt-key", "--link-key", "--checkpoints"];
    if !args.iter().any(|a| a == "--to" || a == "--identity") {
        eprintln!("usage: hemostat ship --to <HOST:PORT> <STORE>...   (push sealed stores to a collector)");
        return EXIT_USAGE;
    }
    #[cfg(all(any(target_os = "linux", target_os = "windows"), feature = "mod-remote"))]
    {
        if args.iter().any(|a| a == "--identity") {
            return crate::push::identity(args, json);
        }
        let stores = operands_after_verb(args, &PUSH_VALUED);
        crate::push::ship_to(args, &stores, json)
    }
    #[cfg(not(all(any(target_os = "linux", target_os = "windows"), feature = "mod-remote")))]
    {
        let _ = (&PUSH_VALUED, json);
        if cfg!(feature = "mod-remote") {
            eprintln!(
                "hemostat ship --to: the push runs on Linux and Windows; on the firewall, carry the \
                 sealed stores off with scp (RFC-003 §2.5)."
            );
            return EXIT_USAGE;
        }
        eprintln!(
            "{}\n  On an image without the push, carry sealed stores off with scp (RFC-003 §2.5).",
            hemostat_modules::module_refusal(hemostat_buildinfo::ModuleId::Remote, crate::MANIFEST.variant)
        );
        crate::EXIT_NOT_BUILT
    }
}

#[cfg(all(target_os = "linux", feature = "mod-collector"))]
pub(crate) fn login() -> (Option<u32>, Option<u32>, String) {
    let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    let ids: Vec<u32> = status
        .lines()
        .find_map(|l| l.strip_prefix("Uid:"))
        .map(|r| r.split_whitespace().filter_map(|x| x.parse().ok()).collect())
        .unwrap_or_default();
    let (ruid, euid) = (ids.first().copied(), ids.get(1).copied());
    let name = ruid
        .and_then(|uid| {
            hemostat_sensor_linux::saferead::read_scan_target(std::path::Path::new("/etc/passwd"))
                .unwrap_or_default()
                .lines()
                .find_map(|l| {
                    let mut f = l.split(':');
                    let n = f.next()?;
                    let _ = f.next();
                    (f.next()?.parse::<u32>().ok()? == uid).then(|| n.to_string())
                })
        })
        .unwrap_or_default();
    (ruid, euid, name)
}

#[cfg(all(target_os = "linux", feature = "mod-collector"))]
pub(crate) fn actor() -> String {
    let (ruid, _, name) = login();
    format!("uid={}({name})", ruid.map_or("?".to_string(), |u| u.to_string()))
}

#[cfg(all(target_os = "linux", feature = "mod-collector"))]
pub(crate) fn ledger_ids(engagement: [u8; 16]) -> Result<hemostat_fleet::ledger::LedgerIds, String> {
    use crate::identity::{gather_identity, rand16, rand32};
    let id = gather_identity().map_err(|e| format!("cannot establish the collector's identity: {e}"))?;
    let (agent, instance, r) = (|| -> std::io::Result<([u8; 16], [u8; 16], [u8; 32])> { Ok((rand16()?, rand16()?, rand32()?)) })()
        .map_err(|e| format!("cannot read entropy: {e}"))?;
    let [a, b, c, d, ..] = r;
    Ok(hemostat_fleet::ledger::LedgerIds {
        engagement,
        host: id.host,
        agent,
        instance,
        run_id: u32::from_le_bytes([a, b, c, d]),
        boot: id.boot,
    })
}

#[cfg(all(target_os = "linux", feature = "mod-collector"))]
pub(crate) fn collector_scope(args: &[String], verb: &str) -> Result<(hemostat_fleet::ingest::Layout, [u8; 16]), u8> {
    let root = values(args, "--root").last().copied().unwrap_or("hemostat-collector").to_string();
    let eng_text = values(args, "--engagement")
        .last()
        .map(|s| (*s).to_string())
        .or_else(|| std::env::var("HEMOSTAT_ENGAGEMENT_ID").ok());
    let Some(engagement) = eng_text.as_deref().and_then(crate::identity::parse_hex16) else {
        eprintln!(
            "hemostat {verb}: the collector serves one engagement — give it with --engagement <32 hex> or \
             $HEMOSTAT_ENGAGEMENT_ID, the value the agents collected under"
        );
        return Err(EXIT_USAGE);
    };
    Ok((hemostat_fleet::ingest::Layout::new(std::path::Path::new(&root), &engagement), engagement))
}

#[cfg(all(target_os = "linux", feature = "mod-collector"))]
pub(crate) fn enroll(args: &[String], json: bool) -> u8 {
    match collector_scope(args, "enroll") {
        Ok((layout, engagement)) => crate::wire::enroll_verb(&layout, engagement, args, json),
        Err(code) => code,
    }
}

#[cfg(all(target_os = "linux", feature = "mod-collector"))]
pub(crate) fn collector(args: &[String], json: bool) -> u8 {
    use crate::identity::{gather_identity, parse_hex32, rand16, rand32};
    use hemostat_fleet::ingest::{ingest_dir, IngestConfig, Verdict};
    use hemostat_fleet::ledger::{audit, ledger_public_key, run_record, Ledger, LedgerIds};

    const VALUED: [&str; 4] = ["--root", "--engagement", "--seal-key", "--seconds"];
    let ops = operands_after_verb(args, &VALUED);
    let usage = || {
        eprintln!(
            "usage: hemostat collector ingest <DIR> [--root <DIR>] [--engagement <HEX>] [--seal-key <HEX>]...\n       \
             hemostat collector ingest --spool [--follow] [--seconds <N>] [--root <DIR>] [--engagement <HEX>]\n       \
             hemostat collector listen <ADDR:PORT> [--seconds <N>] [--root <DIR>] [--engagement <HEX>]\n       \
             hemostat collector keys [--root <DIR>] [--engagement <HEX>]\n       \
             hemostat collector ledger [--root <DIR>] [--engagement <HEX>]\n       \
             hemostat collector read-key [--root <DIR>] [--engagement <HEX>]"
        );
        EXIT_USAGE
    };
    let (layout, engagement) = match collector_scope(args, "collector") {
        Ok(s) => s,
        Err(code) => return code,
    };
    let mut pins = Vec::new();
    for k in values(args, "--seal-key") {
        match parse_hex32(k) {
            Some(p) => pins.push(p),
            None => {
                eprintln!("hemostat collector: --seal-key takes a 64-hex seal public key, not {}", h(k));
                return EXIT_USAGE;
            }
        }
    }
    let seconds = match values(args, "--seconds").last().map(|v| v.parse::<u64>()) {
        None => None,
        Some(Ok(n)) if n > 0 => Some(n),
        Some(_) => {
            eprintln!("hemostat collector: --seconds takes a whole number of seconds above zero");
            return EXIT_USAGE;
        }
    };
    let spool = args.iter().any(|a| a == "--spool");
    let follow = args.iter().any(|a| a == "--follow");

    match ops.as_slice() {
        ["read-key"] => {

            let lock = match layout.lock() {
                Ok(l) => l,
                Err(e) => {
                    eprintln!("hemostat collector read-key: {}", h(&e));
                    return EXIT_FAILED;
                }
            };
            let mut entropy = rand32;
            let (pk, fresh) = match hemostat_fleet::readkey::make(layout.base(), &mut entropy) {
                Ok(k) => k,
                Err(e) => {
                    eprintln!("hemostat collector read-key: {}", h(&e));
                    return EXIT_FAILED;
                }
            };
            if fresh {
                let recorded = crate::wire::open_ledger(&layout, engagement, "collector read-key", "-").and_then(|mut l| {
                    let w = l.append(&format!("{{\"kind\":\"read-key\",\"public\":\"{}\"}}", hex32(&pk)));
                    let c = l.close();
                    w.and(c)
                });
                if let Err(e) = recorded {
                    eprintln!("hemostat collector read-key: the key was made and the ledger did not take its record: {}", h(&e));
                    return EXIT_FAILED;
                }
            }
            drop(lock);
            if json {
                jprintln!("{{\"read_key\":\"{}\",\"made\":{fresh}}}", hex32(&pk));
            } else {
                println!(
                    "engagement read key {} ({})\n  Give it to `collect` on each host as HEMOSTAT_READ_PUBKEY={}\n  \
                     Its private half stays here, beside the ledger, and is never replaced.",
                    hex32(&pk),
                    if fresh { "made now, and recorded in the ledger" } else { "already held" },
                    hex32(&pk)
                );
            }
            EXIT_OK
        }
        ["keys"] => crate::wire::keys_verb(&layout, json),
        ["listen", addr] => crate::wire::listen_verb(&layout, addr, seconds, json),
        ["ingest"] if spool => crate::wire::ingest_spool_verb(&layout, engagement, pins, follow, seconds, json),
        ["ledger"] => {
            let lp = layout.ledger();
            let pk = match ledger_public_key(&lp) {
                Ok(pk) => pk,
                Err(e) => {
                    eprintln!("hemostat collector ledger: {}", h(&e));
                    return EXIT_FAILED;
                }
            };
            match audit(&lp, &pk) {
                Ok(runs) => {
                    if json {
                        let rs: Vec<String> = runs
                            .iter()
                            .map(|r| {
                                let recs: Vec<String> = r
                                    .records
                                    .iter()
                                    .map(|x| format!("\"{}\"", jesc(&String::from_utf8_lossy(x))))
                                    .collect();
                                format!(
                                    "{{\"run\":{},\"genesis\":\"{}\",\"tip\":\"{}\",\"sealed\":{},\"records\":[{}]}}",
                                    r.summary.run,
                                    hex32(&r.summary.genesis),
                                    hex32(&r.summary.tip),
                                    r.summary.sealed,
                                    recs.join(",")
                                )
                            })
                            .collect();
                        jprintln!("{{\"ledger_key\":\"{}\",\"ok\":true,\"runs\":[{}]}}", hex32(&pk), rs.join(","));
                    } else {
                        println!("collector ledger: {} run(s), every one verified under ledger key {}", runs.len(), hex32(&pk));
                        for r in &runs {
                            println!(
                                "\n  run {} — {} record(s), {}; genesis {}",
                                r.summary.run,
                                r.summary.records,
                                if r.summary.sealed { "sealed" } else { "NOT SEALED (a crash; the next run's link says so)" },
                                hex32(&r.summary.genesis)
                            );
                            for x in r.records.iter().skip(2) {
                                println!("    {}", h(&String::from_utf8_lossy(x)));
                            }
                        }
                    }
                    EXIT_OK
                }
                Err(e) => {
                    eprintln!("hemostat collector ledger: the ledger does not audit: {}", h(&e));
                    EXIT_FAILED
                }
            }
        }
        ["ingest", source] => {
            let lock = match layout.lock() {
                Ok(l) => l,
                Err(e) => {
                    eprintln!("hemostat collector ingest: {}", h(&e));
                    return EXIT_FAILED;
                }
            };

            if let Some(why) = crate::resources::disk_refusal(layout.base()) {
                eprintln!("hemostat collector ingest: refusing — {}", h(&why));
                return EXIT_FAILED;
            }
            let id = match gather_identity() {
                Ok(i) => i,
                Err(e) => {
                    eprintln!("hemostat collector ingest: cannot establish the collector's identity: {e}");
                    return EXIT_FAILED;
                }
            };
            let fresh = (|| -> std::io::Result<([u8; 16], [u8; 16], [u8; 32])> { Ok((rand16()?, rand16()?, rand32()?)) })();
            let Ok((agent, instance, r)) = fresh else {
                eprintln!("hemostat collector ingest: cannot read entropy");
                return EXIT_FAILED;
            };
            let ids = LedgerIds {
                engagement,
                host: id.host,
                agent,
                instance,
                run_id: {
                    let [a, b, c, d, ..] = r;
                    u32::from_le_bytes([a, b, c, d])
                },
                boot: id.boot,
            };
            let mut entropy = rand32;
            let mut ledger = match Ledger::open(&layout.ledger(), &ids, &mut entropy) {
                Ok(l) => l,
                Err(e) => {
                    eprintln!("hemostat collector ingest: the ledger refused: {}", h(&e));
                    return EXIT_FAILED;
                }
            };

            let enrolled = match hemostat_fleet::enroll::enrolled(&layout) {
                Ok(e) => e,
                Err(e) => {
                    eprintln!("hemostat collector ingest: {}", h(&e));
                    return EXIT_FAILED;
                }
            };
            let cfg = IngestConfig { engagement, operator_pins: pins, enrolled: Some(enrolled) };
            let opened = ledger.append(&run_record("collector ingest", &actor(), &hemostat_fleet::shown(source)));
            let result = opened.and_then(|()| ingest_dir(&layout, std::path::Path::new(source), &cfg, &mut ledger));
            let report = match result {
                Ok(r) => r,
                Err(e) => {
                    let _ = ledger.append(&format!("{{\"kind\":\"run-failed\",\"why\":{}}}", hemostat_fleet::js(&e)));
                    let _ = ledger.close();
                    eprintln!("hemostat collector ingest: {}", h(&e));
                    return EXIT_FAILED;
                }
            };
            let count = |v: Verdict| report.outcomes.iter().filter(|o| o.verdict == v).count();
            let (acc, rej, held) = (count(Verdict::Accepted), count(Verdict::Rejected), count(Verdict::AlreadyHeld));
            let end = ledger.append(&format!(
                "{{\"kind\":\"run-end\",\"accepted\":{acc},\"rejected\":{rej},\"already_held\":{held},\"ignored\":{}}}",
                report.ignored.len()
            ));
            let run = ledger.run();
            let ledger_dir = ledger.dir().display().to_string();
            let ledger_key = ledger.seal_pub();
            let closed = end.and_then(|()| ledger.close());
            drop(lock);
            if json {
                let os: Vec<String> = report.outcomes.iter().map(|o| o.to_json()).collect();
                jprintln!(
                    "{{\"source\":\"{}\",\"collector\":\"{}\",\"ledger_run\":{run},\"ledger_key\":\"{}\",\"ledger_sealed\":{},\
                     \"outcomes\":[{}],\"ignored\":{}}}",
                    jesc(source),
                    jesc(&layout.base().display().to_string()),
                    hex32(&ledger_key),
                    closed.is_ok(),
                    os.join(","),
                    report.ignored.len()
                );
            } else {
                println!("collector ingest {} -> {}", h(source), h(&layout.base().display().to_string()));
                for o in &report.outcomes {
                    match o.verdict {
                        Verdict::Accepted => println!(
                            "  ACCEPTED  {}  {} store, {} record(s), pin {} -> {}",
                            h(&o.name),
                            o.shape.unwrap_or("?"),
                            o.records,
                            o.pin.unwrap_or("?"),
                            h(&o.kept)
                        ),
                        Verdict::AlreadyHeld => println!("  HELD      {}  {}", h(&o.name), h(&o.reason)),
                        Verdict::Rejected => {
                            println!("  REJECTED  {}  kept at {}", h(&o.name), h(&o.kept));
                            println!("            {}", h(&o.reason));
                        }
                    }
                }
                if !report.ignored.is_empty() {
                    println!("  ignored {} entr(ies) that are not parcel files (not read)", report.ignored.len());
                }
                println!(
                    "\n  {acc} accepted, {rej} rejected, {held} already held. Ledger run {run} at {} \
                     (ledger key {}).",
                    h(&ledger_dir),
                    hex32(&ledger_key)
                );
                println!("  Nothing was sent to any host, and nothing was written to {}.", h(source));
            }
            if let Err(e) = closed {
                eprintln!("hemostat collector ingest: {}", h(&e));
                return EXIT_FAILED;
            }
            if rej > 0 {
                EXIT_FAILED
            } else {
                EXIT_OK
            }
        }
        _ => usage(),
    }
}
