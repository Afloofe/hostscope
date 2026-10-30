use hemostat_sensor_freebsd::pfrules::{self, AnchorKind, Collected, Judged};

use crate::render::{h, hex32, jesc};
use crate::{EXIT_OK, EXIT_PARTIAL};

#[cfg_attr(not(target_os = "freebsd"), allow(dead_code))]
pub(crate) const DEFAULT_STORE: &str = "/root/hemostat/fw-rules";

pub(crate) fn sub_flags(sub: &str) -> Option<&'static [&'static str]> {
    Some(match sub {
        "rules" => &["--store", "--manifest"],
        "flows" => &["--manifest", "--dst", "--limit"],
        "verdict" => &["--manifest", "--src"],
        "block" => &["--alias", "--tracker", "--protect", "--manifest", "--meta", "--deadline", "--allow-subnet", "--arm", "--dry-run"],
        "confirm" => &["--manifest", "--meta", "--arm", "--dry-run"],
        "status" => &["--manifest", "--meta"],

        "watch" => &["--manifest", "--meta", "--manifest-pubkey"],
        "statekill" => &["--alias", "--protect", "--manifest", "--meta", "--allow-subnet", "--arm", "--dry-run"],
        _ => return None,
    })
}

pub(crate) fn check_sub_flags(sub: &str, args: &[String]) -> Result<(), String> {
    let Some(allowed) = sub_flags(sub) else { return Ok(()) };
    match args.iter().find(|a| a.starts_with("--") && a.as_str() != "--json" && !allowed.contains(&a.as_str())) {
        None => Ok(()),
        Some(a) => Err(format!(
            "hemostat fw {sub}: {} is not a `fw {sub}` flag, and nothing was run\n  fw {sub} takes: {} --json",
            h(a),
            allowed.join(" ")
        )),
    }
}

pub(crate) struct FwReport {
    pub(crate) store: String,
    pub(crate) seal_pub: [u8; 32],
    pub(crate) sources: usize,
    pub(crate) bytes: usize,
    pub(crate) tools: Vec<(String, String)>,
    pub(crate) judged: Judged,
}

impl FwReport {

    pub(crate) fn exit_code(&self) -> u8 {
        if self.judged.gaps.is_empty() {
            EXIT_OK
        } else {
            EXIT_PARTIAL
        }
    }
}

pub(crate) fn sealed_bytes(c: &Collected) -> usize {
    c.sources
        .iter()
        .map(|s| match &s.got {
            pfrules::Got::Ran(o) => o.stdout.len() + o.stderr.len(),
            pfrules::Got::Read(b) => b.len(),
            pfrules::Got::Absent => 0,
            pfrules::Got::Failed(w) => w.len(),
        })
        .sum()
}

fn kind_label(k: &AnchorKind) -> String {
    match k {
        AnchorKind::AlwaysEmpty => "empty by default".into(),
        AnchorKind::Feature(f, on) => format!("{}, {}", f.label(), if *on { "on" } else { "off" }),
        AnchorKind::Declared => "declared in rules.debug".into(),
        AnchorKind::Undeclared => "declared nowhere".into(),
    }
}

pub(crate) fn render_fw_rules(r: &FwReport) -> String {
    use std::fmt::Write as _;
    let s = &r.judged.summary;
    let mut o = String::new();
    let _ = writeln!(o, "fw rules — every rule pf is running, traced to config.xml or to pfSense's own ranges");
    let tools: Vec<String> = r.tools.iter().map(|(t, d)| format!("{} {}", h(t), d.get(..16).unwrap_or(d))).collect();
    let _ = writeln!(
        o,
        "  sealed before it was judged: {} (key {}) · {} sources, {} KiB{}",
        h(&r.store),
        hex32(&r.seal_pub),
        r.sources,
        r.bytes / 1024,
        if tools.is_empty() { String::new() } else { format!(" · verified {}", tools.join(", ")) }
    );
    let pf = match s.pf_enabled {
        Some(true) => "enabled",
        Some(false) => "DISABLED",
        None => "status unknown",
    };
    let _ = writeln!(
        o,
        "  pf {pf} · {} filter rules: {} from config.xml ({} trackers there), {} pfSense's own, {} neither · \
         NAT {} · ether {} · tables {}",
        s.filter_rules,
        s.from_config,
        s.config_trackers,
        s.generated,
        s.filter_rules.saturating_sub(s.from_config + s.generated),
        s.nat_rules,
        s.ether_rules,
        s.tables
    );
    let anchors: Vec<String> = s
        .anchors
        .iter()
        .map(|a| {
            let n = if a.rules == 0 { String::new() } else { format!(", {} rule(s)", a.rules) };
            format!("{} ({}{n})", h(&a.path), kind_label(&a.kind))
        })
        .collect();
    let _ = writeln!(o, "  anchors walked: {}", if anchors.is_empty() { "none".into() } else { anchors.join(", ") });
    for f in &r.judged.findings {
        let _ = writeln!(o, "  [{}] {}", f.severity.tag(), h(&f.subject));
        for line in f.what.lines() {
            let _ = writeln!(o, "        {}", h(line));
        }
        let _ = writeln!(o, "        why: {}", h(&f.why));
    }
    if r.judged.findings.is_empty() && r.judged.gaps.is_empty() {
        let _ = writeln!(o, "  every running rule is config.xml's or pfSense's own, and every anchor that should be empty is.");
    }
    for g in &r.judged.gaps {
        let _ = writeln!(o, "  NOT JUDGED: {}", h(g));
    }
    let _ = writeln!(
        o,
        "\n  The ranges are pfSense 2.7.2's filter.inc (sha256 {}…); `vendor` judges the box's copy. NAT \
         rules carry no id to trace and are sealed, not graded; a rule that reuses a config tracker is \
         traced to that rule, and `drift` is what compares the config itself.",
        pfrules::FILTER_INC_SHA256.get(..16).unwrap_or_default()
    );
    o
}

pub(crate) fn render_fw_rules_json(r: &FwReport) -> String {
    let s = &r.judged.summary;
    let rows: Vec<String> = r
        .judged
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
    let anchors: Vec<String> = s
        .anchors
        .iter()
        .map(|a| format!("{{\"path\":\"{}\",\"kind\":\"{}\",\"rules\":{}}}", jesc(&a.path), jesc(&kind_label(&a.kind)), a.rules))
        .collect();
    let tools: Vec<String> =
        r.tools.iter().map(|(t, d)| format!("{{\"tool\":\"{}\",\"sha256\":\"{}\"}}", jesc(t), jesc(d))).collect();
    format!(
        "{{\"store\":\"{}\",\"seal_pub\":\"{}\",\"sources\":{},\"bytes\":{},\"tools\":[{}],\"pf_enabled\":{},\
         \"filter_rules\":{},\"from_config\":{},\"generated\":{},\"config_trackers\":{},\"nat_rules\":{},\
         \"ether_rules\":{},\"tables\":{},\"anchors\":[{}],\"filter_inc_sha256\":\"{}\",\"gaps\":[{}],\
         \"findings\":[{}],\"complete\":{}}}",
        jesc(&r.store),
        hex32(&r.seal_pub),
        r.sources,
        r.bytes,
        tools.join(","),
        s.pf_enabled.map_or("null".to_string(), |b| b.to_string()),
        s.filter_rules,
        s.from_config,
        s.generated,
        s.config_trackers,
        s.nat_rules,
        s.ether_rules,
        s.tables,
        anchors.join(","),
        pfrules::FILTER_INC_SHA256,
        r.judged.gaps.iter().map(|g| format!("\"{}\"", jesc(g))).collect::<Vec<_>>().join(","),
        rows.join(","),
        r.exit_code() == EXIT_OK
    )
}

#[cfg(target_os = "freebsd")]
mod verb {
    use std::path::Path;

    use hemostat_sensor_freebsd::pfrules;
    use hemostat_sensor_freebsd::{saferead, tools};

    use super::*;
    use crate::freebsd_drift::{admit, open, prepare, seal};
    use crate::{EXIT_FAILED, EXIT_NOT_BUILT, EXIT_USAGE};

    fn read_file(path: &str) -> Result<Option<Vec<u8>>, String> {
        match saferead::read_bytes(Path::new(path), pfrules::MAX_FILE) {
            Ok(b) => Ok(Some(b)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.to_string()),
        }
    }

    pub(crate) fn fw(args: &[String], json: bool) -> u8 {
        let store_at = args.iter().position(|a| a == "--store");

        let valued = |i: usize| {
            i.checked_sub(1)
                .and_then(|p| args.get(p))
                .is_some_and(|f| {
                    matches!(
                        f.as_str(),
                        "--store" | "--manifest" | "--src" | "--dst" | "--limit" | "--alias" | "--tracker" | "--protect" | "--meta" | "--deadline" | "--manifest-pubkey"
                    )
                })
        };
        let sub = args
            .iter()
            .enumerate()
            .filter(|(i, a)| !a.starts_with("--") && !valued(*i))
            .map(|(_, a)| a.as_str())
            .nth(1);

        if let Err(msg) = sub.map_or(Ok(()), |s| check_sub_flags(s, args)) {
            eprintln!("{msg}");
            return EXIT_USAGE;
        }

        if matches!(sub, Some("flows" | "verdict")) {
            return crate::freebsd_telemetry::run(args, json);
        }

        match sub {
            Some("block") => return crate::freebsd_block::block(args, json),
            Some("confirm") => return crate::freebsd_contain::confirm(args, json),
            Some("watch") => return crate::freebsd_contain::watch(args),
            Some("status") => return crate::freebsd_contain::status(args, json),
            Some("statekill") => return crate::freebsd_contain::statekill(args, json),
            Some("rules") => {}
            _ => {
                eprintln!(
                    "hemostat fw: the fw verbs are `fw rules`, `fw flows`, `fw verdict`, `fw block`, \
                     `fw confirm`, `fw status` and `fw statekill`; `undo` lifts a block"
                );
                return EXIT_USAGE;
            }
        }
        if let Err(msg) = crate::remedy::require_built(hemostat_buildinfo::ActionClass::Collect) {
            eprintln!("hemostat fw rules: {msg}");
            return EXIT_NOT_BUILT;
        }
        let base = store_at.and_then(|i| args.get(i + 1)).cloned().unwrap_or_else(|| DEFAULT_STORE.to_string());
        let secs = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs());
        let tag: String = crate::identity::rand16()
            .map(|r| r.iter().take(4).map(|b| format!("{b:02x}")).collect())
            .unwrap_or_default();
        let dir = format!("{base}/{secs}-{tag}");
        let prep = match prepare("fw rules", &dir) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("hemostat fw rules: DID NOT RUN — {}", h(&e));
                return EXIT_FAILED;
            }
        };
        let open_file = |p: &std::path::Path| saferead::open_regular(p, saferead::NOT_REGULAR);

        let mpath = args.iter().position(|a| a == "--manifest").and_then(|i| args.get(i + 1)).map(String::as_str);
        let loaded = match crate::vendor_manifest::load_in_place(mpath, &open_file) {
            Ok(m) => m,
            Err(e) => {
                eprintln!("hemostat fw rules: DID NOT RUN — {}", h(&e));
                return EXIT_FAILED;
            }
        };
        let mut sys = tools::System::new(loaded.as_ref());
        let _ = tools::renice_self(&mut sys, 10);
        let mut collected = pfrules::collect(&mut sys, &mut read_file);
        match sys.verify(tools::Tool::Pfctl, &[]) {
            Ok(v) => collected.tools.push(("pfctl".into(), v.digest().map(|d| hex32(&d)).unwrap_or_default())),
            Err(e) => collected.gaps.push(format!("pfctl is not verified, so no listing is trustworthy: {e}")),
        }
        let records = pfrules::records(&collected);
        if let Err(e) = admit(&prep, records.iter().map(Vec::len).sum()) {
            eprintln!("hemostat fw rules: DID NOT RUN — {}", h(&e));
            return EXIT_FAILED;
        }

        if let Err(e) = hemostat_sensor_freebsd::store::create_private(std::path::Path::new(&base)) {
            eprintln!("hemostat fw rules: cannot make {base}: {e}");
            return EXIT_FAILED;
        }
        let seed = match crate::identity::rand32() {
            Ok(s) => s,
            Err(e) => {
                eprintln!("hemostat fw rules: no entropy for the seal key: {e}");
                return EXIT_FAILED;
            }
        };

        let sealed = match seal(&dir, seed, &records, &prep.ids) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("hemostat fw rules: {}", h(&e));
                return EXIT_FAILED;
            }
        };
        let (sources, bytes) = (collected.sources.len(), sealed_bytes(&collected));
        drop(collected);
        drop(records);
        let back = match open(&dir, Some(sealed.seal_pub)).and_then(|o| pfrules::from_records(o.records.iter().map(Vec::as_slice))) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("hemostat fw rules: the store this run just sealed does not read back: {}", h(&e));
                return EXIT_FAILED;
            }
        };
        let mut judged = pfrules::judge(&back);

        let (entries, mut jgaps) = crate::freebsd_contain::journals_on_box();
        let (lost, lgaps) = crate::freebsd_contain::lost_findings(&entries, &back);
        judged.findings.extend(lost);
        judged.findings.sort_by_key(|f| std::cmp::Reverse(f.severity));
        jgaps.extend(lgaps);
        judged.gaps.extend(jgaps);
        let report = FwReport { store: dir, seal_pub: sealed.seal_pub, sources, bytes, tools: back.tools.clone(), judged };
        if json {
            jprintln!("{}", render_fw_rules_json(&report));
        } else {
            print!("{}", render_fw_rules(&report));
        }
        report.exit_code()
    }
}

#[cfg(target_os = "freebsd")]
pub(crate) use verb::fw;
