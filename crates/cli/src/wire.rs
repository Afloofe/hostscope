use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use hemostat_fleet::ingest::{IngestConfig, Layout};
use hemostat_fleet::keys::{self, LINK_KEY, RECEIPT_KEY};
use hemostat_fleet::ledger::{run_record, Ledger, LedgerIds};

use crate::render::{h, hex32, jesc};
use crate::{EXIT_FAILED, EXIT_OK, EXIT_USAGE};

pub(crate) fn open_ledger(layout: &Layout, engagement: [u8; 16], verb: &str, source: &str) -> Result<Ledger, String> {
    use crate::identity::{gather_identity, rand16, rand32};
    let id = gather_identity().map_err(|e| format!("cannot establish the collector's identity: {e}"))?;
    let (agent, instance, r) = (|| -> std::io::Result<([u8; 16], [u8; 16], [u8; 32])> { Ok((rand16()?, rand16()?, rand32()?)) })()
        .map_err(|e| format!("cannot read entropy: {e}"))?;
    let [a, b, c, d, ..] = r;
    let ids = LedgerIds { engagement, host: id.host, agent, instance, run_id: u32::from_le_bytes([a, b, c, d]), boot: id.boot };
    let mut entropy = rand32;
    let mut ledger = Ledger::open(&layout.ledger(), &ids, &mut entropy).map_err(|e| format!("the ledger refused: {e}"))?;
    ledger.append(&run_record(verb, &crate::fleet::actor(), &hemostat_fleet::shown(source)))?;
    Ok(ledger)
}

fn uid() -> Option<u32> {
    hemostat_sensor_linux::saferead::read_pid_text("/proc/self/status")
        .ok()?
        .lines()
        .find_map(|l| l.strip_prefix("Uid:"))
        .and_then(|r| r.split_whitespace().next())
        .and_then(|u| u.parse().ok())
}

pub(crate) fn keys_verb(layout: &Layout, json: bool) -> u8 {
    let dir = layout.keys();
    let mut entropy = crate::identity::rand32;
    let link = keys::load_or_make(&dir.join(LINK_KEY), &mut entropy);
    let receipt = keys::load_or_make(&dir.join(RECEIPT_KEY), &mut entropy);
    let ((link, link_new), (receipt, receipt_new)) = match (link, receipt) {
        (Ok(l), Ok(r)) => (l, r),
        (Err(e), _) | (_, Err(e)) => {
            eprintln!("hemostat collector keys: {}", h(&e));
            return EXIT_FAILED;
        }
    };
    let (lp, rp) = (keys::link_public(link), keys::receipt_public(receipt));
    if json {
        jprintln!(
            "{{\"keys\":\"{}\",\"link_public\":\"{}\",\"link_made\":{link_new},\"receipt_public\":\"{}\",\"receipt_made\":{receipt_new}}}",
            jesc(&dir.display().to_string()),
            hex32(&lp),
            hex32(&rp)
        );
    } else {
        println!("collector keys under {} (private halves 0600, never printed, never taken off this machine)\n", h(&dir.display().to_string()));
        println!("  link key     {}{}", hex32(&lp), if link_new { "   (made now)" } else { "" });
        println!("  receipt key  {}{}", hex32(&rp), if receipt_new { "   (made now)" } else { "" });
        println!(
            "\n  Every agent pins both: `ship --to HOST:PORT --collector-key <link> --receipt-key <receipt>`.\n  \
             The listener holds the link key; the ingest role holds the receipt key."
        );
    }
    EXIT_OK
}

pub(crate) fn listen_verb(layout: &Layout, addr: &str, seconds: Option<u64>, json: bool) -> u8 {
    if uid() == Some(0) {
        eprintln!(
            "hemostat collector listen: refusing to run as root. The listener is the one process that reads \
             bytes from the network, and it runs unprivileged (RFC-003 §3); run it as the collector account"
        );
        return EXIT_USAGE;
    }

    if let Err(e) = layout.lock().map(drop) {

        if !e.contains("another ingest") {
            eprintln!("hemostat collector listen: {}", h(&e));
            return EXIT_FAILED;
        }
    }
    let link = match keys::load(&layout.keys().join(LINK_KEY)) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("hemostat collector listen: {} — run `hemostat collector keys` first", h(&e));
            return EXIT_FAILED;
        }
    };
    let link_pub = keys::link_public(link);
    let l = match hemostat_fleet::listen::open_port(addr) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("hemostat collector listen: {}", h(&e));
            return EXIT_FAILED;
        }
    };
    let bound = l.local_addr().map_or_else(|_| addr.to_string(), |a| a.to_string());
    let dirs = hemostat_fleet::listen::Dirs {
        incoming: layout.incoming(),
        receipts: layout.receipts(),
        done: layout.done(),
        enroll: layout.enroll(),
        heartbeats: layout.heartbeats(),
    };
    let writable = vec![dirs.incoming.clone(), dirs.heartbeats.clone()];
    let readable = vec![dirs.receipts.clone(), dirs.done.clone(), dirs.enroll.clone(), PathBuf::from("/dev/urandom")];
    let confined = hemostat_sensor_linux::selfsandbox::confine(&writable, &readable);
    let sandbox_line = match &confined {
        Ok(c) => c.summary(),
        Err(e) => format!("NOT CONFINED: {}", e.message()),
    };
    if json {
        jprintln!(
            "{{\"listening\":\"{}\",\"link_public\":\"{}\",\"confined\":{},\"sandbox\":\"{}\"}}",
            jesc(&bound),
            hex32(&link_pub),
            confined.is_ok(),
            jesc(&sandbox_line)
        );
    } else {
        println!("collector listen on {} — link key {}", h(&bound), hex32(&link_pub));
        println!("  {}", h(&sandbox_line));
        println!(
            "  Opens frames only from enrolled agents; anything else is recorded as an unknown agent.\n  \
             Sends nothing but the receipt `collector ingest --spool` signs."
        );
    }
    let cfg = hemostat_fleet::listen::Config {
        dirs: dirs.clone(),
        receipt_wait: Duration::from_secs(90),
        max_conns: 16,
        until: seconds.map(|s| Instant::now() + Duration::from_secs(s)),
        entropy: Arc::new(crate::identity::rand32),
        disk: {
            let inc = dirs.incoming.clone();
            Arc::new(move || crate::resources::disk_refusal(&inc))
        },
        log: Arc::new(|line: &str| eprintln!("listen: {}", h(line))),
    };
    match hemostat_fleet::listen::serve(l, cfg, link) {
        Ok(s) => {
            if !json {
                println!("collector listen: {} connection(s), {} closed busy", s.connections, s.busy);
            }
            EXIT_OK
        }
        Err(e) => {
            eprintln!("hemostat collector listen: {}", h(&e));
            EXIT_FAILED
        }
    }
}

pub(crate) fn ingest_spool_verb(
    layout: &Layout,
    engagement: [u8; 16],
    pins: Vec<[u8; 32]>,
    follow: bool,
    seconds: Option<u64>,
    json: bool,
) -> u8 {
    use hemostat_fleet::spool::pending;
    let receipt = match keys::load(&layout.keys().join(RECEIPT_KEY)) {
        Ok(k) => hemostat_evcrypto::receipt::ReceiptKey::from_seed(k),
        Err(e) => {
            eprintln!("hemostat collector ingest: {} — run `hemostat collector keys` first", h(&e));
            return EXIT_FAILED;
        }
    };
    let until = seconds.map(|s| Instant::now() + Duration::from_secs(s));
    let mut code = EXIT_OK;
    let mut announced_flight = usize::MAX;

    let watch = layout.lock().and_then(|lock| {
        let w = hemostat_fleet::heartbeat::Watch::new(layout);
        drop(lock);
        w
    });
    let mut watch = match watch {
        Ok(w) => w,
        Err(e) => {
            eprintln!("hemostat collector ingest: the heartbeat watch could not read the ledger: {}", h(&e));
            return EXIT_FAILED;
        }
    };
    let mut next_beats = Instant::now();
    loop {
        if Instant::now() >= next_beats {
            next_beats = Instant::now() + Duration::from_secs(1);
            if let Err(e) = beats(layout, engagement, &mut watch, json) {
                eprintln!("hemostat collector ingest: heartbeats: {}", h(&e));
                if !follow {
                    return EXIT_FAILED;
                }
            }
        }
        let (ready, in_flight) = match pending(layout) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("hemostat collector ingest: {}", h(&e));
                return EXIT_FAILED;
            }
        };
        if in_flight != announced_flight && !json {
            if in_flight > 0 {
                println!(
                    "  {in_flight} connection(s) in flight or cut off mid-push (`.part`): never read, nothing of them ingested"
                );
            }
            announced_flight = in_flight;
        }
        if !ready.is_empty() {
            if let Err(e) = batch(layout, engagement, &pins, &receipt, json, &mut code) {
                eprintln!("hemostat collector ingest: {}", h(&e));
                if !follow {
                    return EXIT_FAILED;
                }
            }
        }
        if !follow || until.is_some_and(|u| Instant::now() >= u) {
            break;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    code
}

fn beats(layout: &Layout, engagement: [u8; 16], watch: &mut hemostat_fleet::heartbeat::Watch, json: bool) -> Result<(), String> {
    let enrolled = hemostat_fleet::enroll::enrolled(layout)?;
    watch.poll(layout, &enrolled, hemostat_fleet::now_ns())?;
    for n in watch.take_notes() {
        eprintln!("  heartbeats: {}", h(&n));
    }
    if watch.pending().is_empty() {
        return Ok(());
    }
    let lock = layout.lock()?;
    let mut ledger = open_ledger(layout, engagement, "collector ingest --spool", "heartbeats")?;
    let mut wrote = Ok(());
    for p in watch.pending() {
        wrote = ledger.append(&p.record);
        if wrote.is_err() {
            break;
        }
    }
    let wrote = wrote.and_then(|()| ledger.append(&format!("{{\"kind\":\"run-end\",\"heartbeat_records\":{}}}", watch.pending().len())));
    let run = ledger.run();
    let closed = ledger.close();
    drop(lock);
    wrote?;
    closed?;
    for p in watch.pending() {
        if json {
            jprintln!("{{\"what\":\"heartbeat\",\"line\":\"{}\",\"ledger_run\":{run}}}", jesc(&p.line));
        } else {
            println!("  {:<13} {}", "HEARTBEAT", h(&p.line));
        }
    }
    watch.commit();
    Ok(())
}

fn batch(
    layout: &Layout,
    engagement: [u8; 16],
    pins: &[[u8; 32]],
    receipt: &hemostat_evcrypto::receipt::ReceiptKey,
    json: bool,
    code: &mut u8,
) -> Result<(), String> {
    let lock = layout.lock()?;
    if let Some(why) = crate::resources::disk_refusal(layout.base()) {
        return Err(format!("refusing — {why}"));
    }
    let enrolled = hemostat_fleet::enroll::enrolled(layout)?;
    let cfg = IngestConfig { engagement, operator_pins: pins.to_vec(), enrolled: Some(enrolled) };
    let mut ledger = open_ledger(layout, engagement, "collector ingest --spool", &layout.incoming().display().to_string())?;
    let report = match hemostat_fleet::spool::ingest_spool(layout, &cfg, receipt, &mut ledger) {
        Ok(r) => r,
        Err(e) => {
            let _ = ledger.append(&format!("{{\"kind\":\"run-failed\",\"why\":{}}}", hemostat_fleet::js(&e)));
            let _ = ledger.close();
            return Err(e);
        }
    };
    let receipts = report.items.iter().filter(|i| i.receipted).count();
    ledger.append(&format!(
        "{{\"kind\":\"run-end\",\"connections\":{},\"receipts\":{receipts},\"in_flight\":{}}}",
        report.items.len(),
        report.in_flight
    ))?;
    let run = ledger.run();
    ledger.close()?;
    drop(lock);
    for i in &report.items {
        let bad = match &i.outcome {
            Some(o) => o.verdict == hemostat_fleet::ingest::Verdict::Rejected,
            None => i.kind != "announce",
        };
        if bad {
            *code = EXIT_FAILED;
        }
        if json {
            jprintln!(
                "{{\"conn\":\"{}\",\"what\":\"{}\",\"receipted\":{},\"line\":\"{}\",\"outcome\":{},\"ledger_run\":{run}}}",
                jesc(&i.conn),
                jesc(&i.kind),
                i.receipted,
                jesc(&i.line),
                i.outcome.as_ref().map_or("null".to_string(), |o| o.to_json())
            );
        } else {
            println!(
                "  {} {:<13} {}{}",
                h(&i.conn),
                i.kind.to_uppercase(),
                h(&i.line),
                if i.receipted { "  [receipt signed]" } else { "" }
            );
        }
    }
    Ok(())
}

pub(crate) fn enroll_verb(layout: &Layout, engagement: [u8; 16], args: &[String], json: bool) -> u8 {
    use crate::identity::parse_hex32;
    let one = |flag: &str| -> Result<Option<&str>, String> {
        let v = crate::fleet::flag_values(args, flag);
        match v.as_slice() {
            [] => Ok(None),
            [x] => Ok(Some(x)),
            _ => Err(format!("{flag} was given {} times; name one", v.len())),
        }
    };
    let parsed = (|| -> Result<hemostat_fleet::enroll::Enrolled, String> {
        let label = one("--label")?.ok_or("--label <NAME> is required: what the responder calls this host")?;
        let host = one("--host-id")?
            .ok_or("--host-id <64 hex> is required: the host id the agent's stores carry (`ship --identity` prints it)")?;
        let host = parse_hex32(host).ok_or("--host-id takes 64 hex")?;
        let digest = one("--digest")?.ok_or(
            "--digest <64 hex> is required: the SHA-256 of the binary you checked off-box before dropping it",
        )?;
        let digest = parse_hex32(digest).ok_or("--digest takes 64 hex")?;
        let link = match one("--link-key")? {
            None => None,
            Some(k) => Some(parse_hex32(k).ok_or("--link-key takes the agent's 64-hex link public key")?),
        };
        Ok(hemostat_fleet::enroll::Enrolled {
            label: label.to_string(),
            host,
            link,
            digest,
            enrolled_ns: hemostat_fleet::now_ns(),
            actor: crate::fleet::actor(),
        })
    })();
    let e = match parsed {
        Ok(e) => e,
        Err(why) => {
            eprintln!(
                "hemostat enroll: {}\n\nusage: hemostat enroll --label <NAME> --host-id <HEX> --digest <HEX> [--link-key <HEX>] \
                 [--root <DIR>] [--engagement <HEX>]",
                h(&why)
            );
            return EXIT_USAGE;
        }
    };
    let lock = match layout.lock() {
        Ok(l) => l,
        Err(err) => {
            eprintln!("hemostat enroll: {}", h(&err));
            return EXIT_FAILED;
        }
    };
    let result = open_ledger(layout, engagement, "enroll", &e.label).and_then(|mut ledger| {
        let r = hemostat_fleet::enroll::enroll(layout, &e, &mut ledger);
        let end = ledger.append(&format!("{{\"kind\":\"run-end\",\"enrolled\":{}}}", r.is_ok()));
        let closed = ledger.close();
        r.and(end).and(closed)
    });
    drop(lock);
    match result {
        Ok(()) => {
            if json {
                jprintln!("{{\"enrolled\":{}}}", e.to_json());
            } else {
                println!("enrolled {} — host {}", h(&e.label), hex32(&e.host));
                match e.link {
                    Some(k) => println!("  link key {}: its pushes now open at the listener", hex32(&k)),
                    None => println!("  no link key: this host arrives by media only"),
                }
                println!("  binary digest {}", hex32(&e.digest));
                println!("  by {}; recorded in the ledger", h(&e.actor));
            }
            EXIT_OK
        }
        Err(why) => {
            eprintln!("hemostat enroll: refused — {}", h(&why));
            EXIT_FAILED
        }
    }
}
