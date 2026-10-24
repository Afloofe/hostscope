#![cfg_attr(all(target_os = "linux", not(test)), allow(dead_code, unused_imports))]

use hemostat_sensor_freebsd::evidence::{Evidence, Judged};

use crate::render::{h, hex32, jesc};
use crate::{EXIT_OK, EXIT_PARTIAL};

#[cfg_attr(not(target_os = "freebsd"), allow(dead_code))]
pub(crate) const STORE_BASE: &str = "/root/hemostat";

#[cfg_attr(not(any(target_os = "freebsd", feature = "mod-collector")), allow(dead_code))]
pub(crate) const OPERATOR_KEY_ENV: &str = "HEMOSTAT_OPERATOR_KEY";

pub(crate) const ACCOUNTS: &str = "accounts";

pub(crate) const PERSISTENCE: &str = "persistence";

pub(crate) const TRUST: &str = "trust";

pub(crate) struct SweepReport {
    pub(crate) verb: &'static str,
    pub(crate) store: String,
    pub(crate) seal: [u8; 32],
    pub(crate) records: usize,

    pub(crate) manifest: Option<(String, usize)>,
    pub(crate) judged: Judged,
}

impl SweepReport {

    pub(crate) fn exit_code(&self) -> u8 {
        if self.judged.gaps.is_empty() {
            EXIT_OK
        } else {
            EXIT_PARTIAL
        }
    }
}

fn title(verb: &str) -> &'static str {
    match verb {
        "accounts" => "who can get onto this firewall, and as what — master.passwd, group, key files, sudo and doas, against config.xml",
        "trust" => "every CA this firewall believes about any name — the OS store certctl builds, ca_root_nss, and config.xml's certificate manager",
        _ => "what starts by itself on this firewall — cron, rc.d, periodic, the loader, devd, boot commands and packages",
    }
}

pub(crate) fn render_sweep(r: &SweepReport) -> String {
    use hs_core::severity::Severity;
    use std::fmt::Write as _;
    let mut o = String::new();
    let _ = writeln!(o, "{} — {}", r.verb, title(r.verb));
    let _ = writeln!(
        o,
        "  what was read was sealed before it was judged: {} ({} records, key {})",
        h(&r.store),
        r.records,
        hex32(&r.seal)
    );
    match &r.manifest {
        Some((rel, n)) => {
            let _ = writeln!(o, "  held to the signed manifest {} ({n} paths)", h(rel));
        }
        None => {
            let _ = writeln!(o, "  no signed manifest: nothing was held to what the vendor ships");
        }
    }
    let j = &r.judged;
    let _ = writeln!(
        o,
        "  {} critical · {} warn · {} note",
        j.count(Severity::Critical),
        j.count(Severity::Warn),
        j.count(Severity::Note)
    );
    for f in &j.findings {
        let _ = writeln!(o, "  [{}] {}", f.severity.tag(), h(&f.subject));
        for (i, line) in f.what.lines().enumerate() {
            let _ = writeln!(o, "        {}{}", if i == 0 { "" } else { "  " }, h(line));
        }
        let _ = writeln!(o, "        why: {}", h(&f.why));
    }
    if j.findings.is_empty() && j.gaps.is_empty() {
        let _ = writeln!(o, "  nothing to report.");
    }
    for g in &j.gaps {
        let _ = writeln!(o, "  NOT JUDGED: {}", h(g));
    }
    let _ = writeln!(
        o,
        "\n  Advice only: nothing here changes an account, a file or a package. Removing an account or \
         a permission is your call, made by hand in the console."
    );
    o
}

pub(crate) fn render_sweep_json(r: &SweepReport) -> String {
    use hs_core::severity::Severity;
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
    let man = match &r.manifest {
        Some((rel, n)) => format!("{{\"release\":\"{}\",\"paths\":{n}}}", jesc(rel)),
        None => "null".into(),
    };
    format!(
        "{{\"sweep\":\"{}\",\"store\":\"{}\",\"seal\":\"{}\",\"records\":{},\"manifest\":{man},\
         \"counts\":{{\"critical\":{},\"warn\":{},\"note\":{}}},\"gaps\":[{}],\"findings\":[{}],\"complete\":{}}}",
        r.verb,
        jesc(&r.store),
        hex32(&r.seal),
        r.records,
        r.judged.count(Severity::Critical),
        r.judged.count(Severity::Warn),
        r.judged.count(Severity::Note),
        r.judged.gaps.iter().map(|g| format!("\"{}\"", jesc(g))).collect::<Vec<_>>().join(","),
        rows.join(","),
        r.exit_code() == EXIT_OK
    )
}

pub(crate) fn operator_keys(args: &[String], env: Option<&str>) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if a == "--operator-key" {
            out.push(it.next().cloned().ok_or("--operator-key needs a fingerprint (SHA256:…)")?);
        }
    }
    if out.is_empty() {
        out.extend(env.unwrap_or_default().split([',', ' ']).filter(|s| !s.is_empty()).map(str::to_string));
    }
    for k in &out {
        let b = k.strip_prefix("SHA256:").unwrap_or("");
        if b.len() != 43 || !b.chars().all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/') {
            return Err(format!(
                "{k:?} is not an OpenSSH SHA256 fingerprint; `ssh-keygen -lf KEY.pub` prints the one to enroll"
            ));
        }
    }
    Ok(out)
}

pub(crate) fn seal_and_reread(
    dir: &str,
    seed: [u8; 32],
    ev: &Evidence,
    ids: &crate::freebsd_drift::Ids,
) -> Result<(Evidence, [u8; 32], usize), String> {
    let records = ev.records();
    let n = records.len();
    let sealed = crate::freebsd_drift::seal(dir, seed, &records, ids)?;
    drop(records);
    let back = crate::freebsd_drift::open(dir, Some(sealed.seal_pub))
        .map_err(|e| format!("the store this run just sealed does not read back: {e}"))?;
    let ev = Evidence::from_records(back.records.iter().map(Vec::as_slice))
        .map_err(|e| format!("the store this run just sealed does not decode: {e}"))?;
    Ok((ev, sealed.seal_pub, n))
}

#[cfg(target_os = "freebsd")]
mod verbs {
    use std::path::Path;

    use hemostat_sensor_freebsd::evidence::Collector;
    use hemostat_sensor_freebsd::{accounts, persist, saferead, tools};

    use super::*;
    use crate::{EXIT_FAILED, EXIT_USAGE};

    fn arg<'a>(args: &'a [String], flag: &str) -> Option<&'a str> {
        args.iter().position(|a| a == flag).and_then(|i| args.get(i + 1)).map(String::as_str)
    }

    fn run(
        verb: &'static str,
        args: &[String],
        json: bool,
        gather: impl FnOnce(&mut Collector, &mut tools::System<'_>),
        judge: impl FnOnce(&Evidence, Option<&hemostat_evcrypto::manifest::Manifest>) -> Judged,
    ) -> u8 {
        let open_file = |p: &std::path::Path| saferead::open_regular(p, saferead::NOT_REGULAR);
        let loaded = match crate::vendor_manifest::load_in_place(arg(args, "--manifest"), &open_file) {
            Ok(m) => m,
            Err(e) => {
                eprintln!("hemostat {verb}: DID NOT RUN — {}", h(&e));
                return EXIT_FAILED;
            }
        };
        let mut sys = tools::System::new(loaded.as_ref());

        if let Err(e) = tools::renice_self(&mut sys, 10) {
            eprintln!("hemostat {verb}: could not lower this agent's priority ({}); running at the default", h(&e.to_string()));
        }
        let secs = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs());
        let tag: String = crate::identity::rand16()
            .map(|r| r.iter().take(4).map(|b| format!("{b:02x}")).collect())
            .unwrap_or_default();
        let base = format!("{}/{verb}", arg(args, "--store").unwrap_or(STORE_BASE).trim_end_matches('/'));
        let dir = format!("{base}/{secs}-{tag}");
        let prep = match crate::freebsd_drift::prepare_in(verb, &dir, &mut sys) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("hemostat {verb}: DID NOT RUN — {}", h(&e));
                return EXIT_FAILED;
            }
        };
        let mut c = Collector::new(verb, Path::new("/"));
        gather(&mut c, &mut sys);
        if let Err(e) = crate::freebsd_drift::admit(&prep, c.ev.size()) {
            eprintln!("hemostat {verb}: DID NOT RUN — {}", h(&e));
            return EXIT_FAILED;
        }

        if let Err(e) = hemostat_sensor_freebsd::store::create_private(Path::new(&base)) {
            eprintln!("hemostat {verb}: cannot make {base}: {e}");
            return EXIT_FAILED;
        }
        let seed = match crate::identity::rand32() {
            Ok(s) => s,
            Err(e) => {
                eprintln!("hemostat {verb}: no entropy for the seal key: {e}");
                return EXIT_FAILED;
            }
        };
        let (ev, seal, records) = match seal_and_reread(&dir, seed, &c.ev, &prep.ids) {
            Ok(x) => x,
            Err(e) => {
                eprintln!("hemostat {verb}: {}", h(&e));
                return EXIT_FAILED;
            }
        };
        drop(c);
        let man = loaded.as_ref().map(|m| m.manifest());
        let report = SweepReport {
            verb,
            store: dir,
            seal,
            records,
            manifest: man.map(|m| (m.release.clone(), m.paths())),
            judged: judge(&ev, man),
        };
        if json {
            jprintln!("{}", render_sweep_json(&report));
        } else {
            print!("{}", render_sweep(&report));
        }
        report.exit_code()
    }

    pub(crate) fn accounts(args: &[String], json: bool) -> u8 {
        let keys = match operator_keys(args, std::env::var(OPERATOR_KEY_ENV).ok().as_deref()) {
            Ok(k) => k,
            Err(e) => {
                eprintln!("hemostat accounts: {}", h(&e));
                return EXIT_USAGE;
            }
        };
        let opts = accounts::Opts { operator_keys: keys };
        run(ACCOUNTS, args, json, |c, _| accounts::gather(c), |ev, _| accounts::judge(ev, &opts))
    }

    pub(crate) fn persistence(args: &[String], json: bool) -> u8 {
        run(PERSISTENCE, args, json, |c, sys| persist::gather(c, sys), persist::judge)
    }

    pub(crate) fn trust(args: &[String], json: bool) -> u8 {
        run(TRUST, args, json, |c, _| hemostat_sensor_freebsd::trust::gather(c), hemostat_sensor_freebsd::trust::judge)
    }
}

#[cfg(target_os = "freebsd")]
pub(crate) use verbs::{accounts, persistence, trust};
