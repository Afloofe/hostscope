use hemostat_sensor_linux::flowexport::HostFlows;

use crate::render::{h, hex32, jesc};
use crate::{EXIT_FAILED, EXIT_OK, EXIT_PARTIAL, EXIT_USAGE};

pub(crate) fn export_dir(args: &[String]) -> Result<Option<&str>, String> {
    let Some(i) = args.iter().position(|a| a == "--export") else { return Ok(None) };
    match args.get(i + 1).filter(|v| !v.starts_with("--")) {
        Some(v) => Ok(Some(v.as_str())),
        None => Err("--export takes the directory to seal the export into".into()),
    }
}

pub(crate) fn incomplete(f: &HostFlows) -> Vec<String> {
    let mut out = Vec::new();
    for t in &f.unread_tables {
        out.push(format!("socket table not read: {t}"));
    }
    if f.unmapped_processes > 0 {
        out.push(format!("{} process(es) whose descriptors could not be listed", f.unmapped_processes));
    }
    for n in f.unread_namespaces() {
        out.push(format!("network namespace {} not read (no task in it; found by {})", n.id, n.found.join(", ")));
    }
    for u in f.unreached.iter().filter(|u| u.proto.as_deref().is_none_or(hemostat_sensor_linux::flowexport::is_stream)) {
        out.push(format!("{} socket {} held by {} is in no table read", u.proto.as_deref().unwrap_or("a"), u.inode, u.holders.join(", ")));
    }
    if let Err(e) = &f.conntrack {
        out.push(format!("conntrack not read: {e}"));
    }
    out.extend(f.gaps.iter().cloned());
    out
}

pub(crate) fn notes(f: &HostFlows) -> Vec<String> {
    f.unreached
        .iter()
        .filter(|u| u.proto.as_deref().is_some_and(|p| !hemostat_sensor_linux::flowexport::is_stream(p)))
        .map(|u| {
            format!(
                "{} socket {} held by {} is in no table read: never bound, or in a namespace not read",
                u.proto.as_deref().unwrap_or("?"),
                u.inode,
                u.holders.join(", ")
            )
        })
        .collect()
}

pub(crate) fn render(f: &HostFlows, dir: &str, seal_pub: &[u8; 32], records: usize) -> String {
    use std::fmt::Write as _;
    let mut o = String::new();
    let _ = writeln!(o, "overview --export — this host's sockets and addresses, for correlate on the collector");
    let _ = writeln!(o, "  sealed     {} · {records} records · seal key {} — keep it off-host", h(dir), hex32(seal_pub));
    let _ = writeln!(o, "  host       {} · clock {} · booted {}", h(&f.hostname), f.now, f.boot);
    let macs: Vec<&str> = f.macs().into_iter().collect();
    let _ = writeln!(o, "  wire       {} address(es), MAC(s) {}{}", f.addrs.len(), h(&macs.join(", ")), if f.forwarding { " · forwarding ON" } else { "" });
    let others = f.sockets.iter().filter(|s| s.netns.is_some()).count();
    let _ = writeln!(o, "  sockets    {} inet ({} in other namespaces)", f.sockets.len(), others);
    let read = f.namespaces.iter().filter(|n| n.read).count();
    let _ = writeln!(o, "  namespaces {} other, {read} read", f.namespaces.len());
    match &f.conntrack {
        Ok(c) => {
            let _ = writeln!(o, "  conntrack  {} entries", c.len());
        }
        Err(e) => {
            let _ = writeln!(o, "  conntrack  not read: {}", h(e));
        }
    }
    let gaps = incomplete(f);
    if gaps.is_empty() {
        let _ = writeln!(o, "  coverage   complete: every table, every process, every namespace known");
        for n in notes(f) {
            let _ = writeln!(o, "             note: {}", h(&n));
        }
    } else {
        let _ = writeln!(o, "  NOT COMPLETE:");
        for g in &gaps {
            let _ = writeln!(o, "    - {}", h(g));
        }
    }
    let _ = writeln!(o, "  Copy {} to the collector and run `hemostat correlate --host {} --host-pin {}` there.", h(dir), h(dir), hex32(seal_pub));
    o
}

pub(crate) fn render_json(f: &HostFlows, dir: &str, seal_pub: &[u8; 32], records: usize) -> String {
    let gaps: Vec<String> = incomplete(f).iter().map(|g| format!("\"{}\"", jesc(g))).collect();
    format!(
        "{{\"store\":{{\"dir\":\"{}\",\"seal_pub\":\"{}\",\"records\":{records}}},\"hostname\":\"{}\",\"now\":{},\"boot\":{},\
         \"addresses\":{},\"sockets\":{},\"namespaces\":{},\"unreached\":{},\"conntrack\":{},\"incomplete\":[{}],\"complete\":{}}}",
        jesc(dir),
        hex32(seal_pub),
        jesc(&f.hostname),
        f.now,
        f.boot,
        f.addrs.len(),
        f.sockets.len(),
        f.namespaces.len(),
        f.unreached.len(),
        f.conntrack.as_ref().map_or("null".to_string(), |c| c.len().to_string()),
        gaps.join(","),
        gaps.is_empty()
    )
}

#[cfg(target_os = "linux")]
pub(crate) fn run(args: &[String], json: bool) -> u8 {
    let dir = match export_dir(args) {
        Ok(Some(d)) => d.to_string(),
        Ok(None) => return EXIT_USAGE,
        Err(e) => {
            eprintln!("hemostat overview: {e}");
            return EXIT_USAGE;
        }
    };
    let r = hemostat_sensor_linux::overview::report();
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs());
    let flows = hemostat_sensor_linux::flowexport::gather(&r, now);
    drop(r);
    let records = flows.records();
    let id = match crate::identity::gather_identity() {
        Ok(i) => i,
        Err(e) => {
            eprintln!("hemostat overview: cannot read entropy for the identity: {e}");
            return EXIT_FAILED;
        }
    };
    let seed = match crate::identity::rand32() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("hemostat overview: no entropy for the seal key: {e}");
            return EXIT_FAILED;
        }
    };
    let ids = crate::sealed::Ids {
        engagement: id.engagement,
        host: id.host,
        agent: id.agent,
        instance: id.instance,
        run: id.run_id,
        boot: id.boot,
    };
    let sealed = match crate::sealed::seal(&dir, seed, &records, &ids) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("hemostat overview: could not seal the export at {}: {}", h(&dir), h(&e));
            return EXIT_FAILED;
        }
    };
    let count = records.len();
    drop(records);

    let back = crate::sealed::open(&dir, Some(sealed.seal_pub))
        .and_then(|o| HostFlows::from_records(o.records.iter().map(Vec::as_slice)));
    let flows = match back {
        Ok(f) => f,
        Err(e) => {
            eprintln!("hemostat overview: the export at {} did not read back ({}); it is not to be used", h(&dir), h(&e));
            return EXIT_FAILED;
        }
    };
    if json {
        jprintln!("{}", render_json(&flows, &dir, &sealed.seal_pub, count));
    } else {
        print!("{}", render(&flows, &dir, &sealed.seal_pub, count));
    }
    if incomplete(&flows).is_empty() {
        EXIT_OK
    } else {
        EXIT_PARTIAL
    }
}
