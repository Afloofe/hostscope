use hemostat_enforce_pf::journal::{self, Entry, State};
use hemostat_sensor_freebsd::pfrules;
use hs_core::severity::Severity;

use crate::render::h;

#[cfg_attr(not(target_os = "freebsd"), allow(dead_code))]
pub(crate) const EVIDENCE_STORE: &str = "/root/hemostat/containment-evidence";

pub(crate) const EVIDENCE_KIND: &str = "pfsense-containment-evidence";

#[cfg_attr(not(target_os = "freebsd"), allow(dead_code))]
pub(crate) const BACKUP_DIR: &str = "/cf/conf/backup";

#[derive(Debug, Clone)]
pub(crate) struct Backup {
    pub(crate) name: String,
    pub(crate) digest: Result<([u8; 32], u64), String>,
}

pub(crate) fn evidence_records(
    id: &str,
    step: &str,
    config: &Result<Vec<u8>, String>,
    backups: &Result<Vec<Backup>, String>,
) -> Vec<Vec<u8>> {
    let mut r = vec![
        [b"k".as_slice(), EVIDENCE_KIND.as_bytes()].concat(),
        [b"j".as_slice(), id.as_bytes()].concat(),
        [b"w".as_slice(), step.as_bytes()].concat(),
    ];
    match config {
        Ok(raw) => r.extend(hemostat_sensor_freebsd::drift::raw_records(raw)),
        Err(why) => r.push(format!("gconfig.xml could not be read: {why}").into_bytes()),
    }
    match backups {
        Ok(list) => {
            for b in list {
                match &b.digest {
                    Ok((d, n)) => r.push(format!("b{}\t{n}\t{}", crate::render::hex32(d), b.name).into_bytes()),
                    Err(why) => r.push(format!("g{BACKUP_DIR}/{}: {why}", b.name).into_bytes()),
                }
            }
        }
        Err(why) => r.push(format!("g{BACKUP_DIR} could not be listed: {why}").into_bytes()),
    }
    r
}

#[derive(Debug)]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) struct Evidence {

    pub(crate) config: Vec<u8>,

    pub(crate) backups: Vec<String>,

    pub(crate) gaps: Vec<String>,
}

pub(crate) fn decode_evidence(records: &[Vec<u8>]) -> Result<Evidence, String> {
    if records.iter().find_map(|r| r.strip_prefix(b"k")) != Some(EVIDENCE_KIND.as_bytes()) {
        return Err("not a containment evidence store".into());
    }
    let raw = hemostat_sensor_freebsd::drift::raw_from_records(records.iter().map(Vec::as_slice))?;
    let rows = records.iter().filter_map(|r| r.strip_prefix(b"b")).map(|b| String::from_utf8_lossy(b).into_owned()).collect();
    let gaps = records.iter().filter_map(|r| r.strip_prefix(b"g")).map(|b| String::from_utf8_lossy(b).into_owned()).collect();
    Ok(Evidence { config: raw, backups: rows, gaps })
}

pub(crate) const STATEKILL_KIND: &str = "pfsense-statekill-evidence";

pub(crate) fn statekill_records(id: &str, cidr: &str, listing: &str, matched: &[String]) -> Vec<Vec<u8>> {
    let mut r = vec![
        [b"k".as_slice(), STATEKILL_KIND.as_bytes()].concat(),
        [b"j".as_slice(), id.as_bytes()].concat(),
        [b"c".as_slice(), cidr.as_bytes()].concat(),
    ];
    r.extend(hemostat_sensor_freebsd::drift::raw_records(listing.as_bytes()));
    r.extend(matched.iter().map(|m| [b"m".as_slice(), m.as_bytes()].concat()));
    r
}

pub(crate) fn decode_statekill(records: &[Vec<u8>]) -> Result<Vec<String>, String> {
    if records.iter().find_map(|r| r.strip_prefix(b"k")) != Some(STATEKILL_KIND.as_bytes()) {
        return Err("not a state-kill evidence store".into());
    }
    hemostat_sensor_freebsd::drift::raw_from_records(records.iter().map(Vec::as_slice))?;
    Ok(records.iter().filter_map(|r| r.strip_prefix(b"m")).map(|b| String::from_utf8_lossy(b).into_owned()).collect())
}

pub(crate) fn spend_at(log: &str, nonce: &[u8; 16]) -> Result<(), String> {
    use std::io::Write as _;
    let hex: String = nonce.iter().map(|b| format!("{b:02x}")).collect();
    let spent = format!("{log}.spent");
    hemostat_sensor_freebsd::store::create_private(std::path::Path::new(&spent)).map_err(|e| format!("the ticket could not be recorded as spent ({spent}: {e}), so it was not used"))?;
    let marker = std::path::Path::new(&spent).join(&hex);
    match std::fs::OpenOptions::new().create_new(true).write(true).open(&marker) {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            return Err("the ticket was spent by another run between verification and use; nothing was done".into())
        }
        Err(e) => return Err(format!("the ticket could not be recorded as spent ({}: {e}), so it was not used", marker.display())),
    }
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(log) {
        let _ = writeln!(f, "{hex}");
    }
    Ok(())
}

pub(crate) fn lost_findings(entries: &[Entry], c: &pfrules::Collected) -> (Vec<pfrules::Finding>, Vec<String>) {
    if !entries.iter().any(|e| e.state() == State::Confirmed) {
        return (Vec::new(), Vec::new());
    }
    let config = match c.get(pfrules::CONFIG_PATH) {
        Some(pfrules::Got::Read(b)) => hemostat_sensor_freebsd::configxml::parse(b).map_err(|e| e.to_string()),
        _ => Err("config.xml was not collected".to_string()),
    };
    let config = match config {
        Ok(cfg) => cfg,
        Err(why) => return (Vec::new(), vec![format!("the confirmed HEMOSTAT blocks were not re-checked: {why}")]),
    };
    let table = |a: hemostat_enforce_pf::Alias| match c.get(&pfrules::pfctl_key(&["-t", a.name(), "-T", "show"])) {
        Some(pfrules::Got::Ran(o)) if o.success() => Some(o.text()),
        _ => None,
    };
    let findings = journal::recheck(entries, &config, &table)
        .into_iter()
        .map(|l| pfrules::Finding {
            severity: Severity::Warn,
            subject: format!("containment {} ({} in {})", l.id, l.cidr, l.alias.name()),
            what: format!("block lost to another writer: {}", l.what),
            why: format!(
                "HEMOSTAT confirmed this block into config.xml, and it is no longer there. The GUI, a package, \
                 check_reload_status or an XMLRPC sync wrote config.xml after it, last writer wins. Re-apply \
                 it by hand (`hemostat fw block {} --alias {} …`), and find who wrote",
                l.cidr,
                l.alias.name()
            ),
        })
        .collect();
    (findings, Vec::new())
}

#[cfg_attr(not(target_os = "freebsd"), allow(dead_code))]
pub(crate) fn confirm_armed(args: &[String]) -> bool {
    args.iter().any(|a| a == "--arm") && !args.iter().any(|a| a == "--dry-run")
}

pub(crate) fn clock(secs: u64) -> String {
    format!("{:02}:{:02}:{:02} UTC", (secs / 3600) % 24, (secs / 60) % 60, secs % 60)
}

pub(crate) fn render_status(rows: &[(Entry, Option<bool>)], gaps: &[String], now: u64) -> String {
    use std::fmt::Write as _;
    let mut o = String::new();
    let _ = writeln!(o, "fw status — HEMOSTAT's containment journal ({})", journal::DIR);
    if rows.is_empty() && gaps.is_empty() {
        let _ = writeln!(o, "  no journal: HEMOSTAT has not acted on this firewall");
    }
    for (e, live) in rows {
        let i = &e.intent;
        let when = match e.state() {
            State::Live | State::Intent if i.deadline > now => format!(" · lifted at {} (in {} s) unless confirmed", clock(i.deadline), i.deadline - now),
            State::Live | State::Intent => format!(" · deadline {} passed", clock(i.deadline)),
            State::Confirmed => format!(" · config revision {}", e.confirmed.as_deref().unwrap_or("?")),
            State::Lifted => format!(" · by {}", e.lifted.as_deref().unwrap_or("?")),
            _ => String::new(),
        };

        let table = match (i.class, live) {
            (journal::Class::StateKill, _) | (_, None) => "",
            (_, Some(true)) => " · in pf's table",
            (_, Some(false)) => " · not in pf's table",
        };
        let _ = writeln!(o, "  {}  {:<18} {} {:<12} {}{when}{table}", i.id, i.class.token(), i.alias.name(), e.state().token(), i.cidr);
        for (step, why) in &e.failed {
            let _ = writeln!(o, "        failed at {}: {}", h(step), h(why));
        }
        for n in &e.notes {
            let _ = writeln!(o, "        note: {}", h(n));
        }
    }
    for g in gaps {
        let _ = writeln!(o, "  NOT READ: {}", h(g));
    }
    o
}

#[cfg_attr(not(target_os = "freebsd"), allow(dead_code))]
pub(crate) struct Armed<'a> {
    pub(crate) asked: &'a crate::freebsd_block::Asked,
    pub(crate) host: [u8; 32],

    pub(crate) nonce: Option<[u8; 16]>,

    pub(crate) manifest: String,

    pub(crate) meta: Option<String>,
}

pub(crate) fn follow_flags(manifest: &str, meta: Option<&str>) -> String {
    let mut s = String::new();
    if !manifest.is_empty() {
        s.push_str(" --manifest ");
        s.push_str(&sh_quote(manifest));
    }
    if let Some(m) = meta.filter(|m| !m.is_empty()) {
        s.push_str(" --meta ");
        s.push_str(&sh_quote(m));
    }
    s
}

fn sh_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

#[cfg(target_os = "freebsd")]
mod verb {
    use std::path::Path;

    use hemostat_broker::perimeter::{Decision, Evidence};
    use hemostat_enforce_pf::apply::{self, Applied, Confirmed, Lifted, Unconfirmed, WatchStep};
    use hemostat_enforce_pf::journal::{Class, Intent, Journals, UndoKind};
    use hemostat_enforce_pf::DryRun;
    use hemostat_sensor_freebsd::configxml::{self, Config};
    use hemostat_sensor_freebsd::{saferead, tools};

    use super::*;
    use crate::freebsd_block::{exit_code, golden_refusal, load_policy, load_ticket_as, now_secs, render_stages, spent, width_asked};
    use crate::render::{hex32, jesc};
    use crate::{EXIT_AUTHZ, EXIT_DRYRUN, EXIT_FAILED, EXIT_NOT_BUILT, EXIT_OK, EXIT_PARTIAL, EXIT_POLICY, EXIT_USAGE};

    fn booting() -> bool {
        std::fs::symlink_metadata(apply::BOOTING).is_ok()
    }

    fn now() -> u64 {
        now_secs().ok().and_then(|n| u64::try_from(n).ok()).unwrap_or(0)
    }

    pub(super) fn read_config() -> Result<Config, String> {
        let b = saferead::read_bytes(Path::new(configxml::CONFIG_PATH), configxml::MAX_BYTES).map_err(|e| format!("{}: {e}", configxml::CONFIG_PATH))?;
        configxml::parse(&b).map_err(|e| format!("{}: {e}", configxml::CONFIG_PATH))
    }

    fn backups() -> Result<Vec<Backup>, String> {
        let rd = std::fs::read_dir(BACKUP_DIR).map_err(|e| e.to_string())?;
        let mut out = Vec::new();
        for ent in rd.take(4096) {
            let ent = ent.map_err(|e| e.to_string())?;
            let name = ent.file_name().to_string_lossy().into_owned();
            let p = ent.path();
            let digest = std::fs::symlink_metadata(&p)
                .map_err(|e| e.to_string())
                .and_then(|m| if m.is_file() { Ok(m.len()) } else { Err("not a regular file".to_string()) })
                .and_then(|n| saferead::sha256_of(&p).map(|d| (d, n)).map_err(|e| e.to_string()));
            out.push(Backup { name, digest });
        }
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }

    pub(super) fn seal_evidence(sys: &mut tools::System<'_>, id: &str, step: &str) -> Result<(String, [u8; 32]), String> {
        use crate::freebsd_drift::{admit_reserved, open, prepare_in, seal};
        let dir = format!("{EVIDENCE_STORE}/{}-{id}-{step}", now());
        let prep = prepare_in("fw", &dir, sys)?;
        let config = saferead::read_bytes(Path::new(configxml::CONFIG_PATH), configxml::MAX_BYTES).map_err(|e| e.to_string());
        let recs = evidence_records(id, step, &config, &backups());
        admit_reserved(&prep, recs.iter().map(Vec::len).sum())?;
        hemostat_sensor_freebsd::store::create_private(Path::new(EVIDENCE_STORE)).map_err(|e| format!("{EVIDENCE_STORE}: {e}"))?;
        let seed = crate::identity::rand32().map_err(|e| format!("no entropy for the seal key: {e}"))?;
        let sealed = seal(&dir, seed, &recs, &prep.ids)?;
        let back = open(&dir, Some(sealed.seal_pub))?;
        decode_evidence(&back.records).map_err(|e| format!("the evidence store does not read back: {e}"))?;
        Ok((dir, sealed.seal_pub))
    }

    struct Loaded {
        manifest: Option<hemostat_evcrypto::manifest::Verified>,
        meta: Option<hemostat_evcrypto::manifest::meta::VerifiedMeta>,
        mpath: String,
        given_meta: Option<String>,
    }

    fn load(args: &[String]) -> Result<Loaded, String> {
        let val = |n: &str| args.iter().position(|a| a == n).and_then(|i| args.get(i + 1)).cloned();
        let path = val("--manifest");
        let open = |p: &Path| saferead::open_regular(p, saferead::NOT_REGULAR);
        let manifest = crate::vendor_manifest::load_in_place(path.as_deref(), &open)?;
        let mpath = path.or_else(|| std::env::var(crate::vendor_manifest::MANIFEST_ENV).ok()).unwrap_or_default();
        let given_meta = val("--meta");
        let meta = manifest.as_ref().and_then(|m| {
            crate::vendor_manifest::load_meta_in_place(&crate::vendor_manifest::meta_path_for(&mpath, given_meta.as_deref()), m, &open).ok()
        });
        Ok(Loaded { manifest, meta, mpath, given_meta })
    }

    fn id_arg(args: &[String]) -> Option<String> {
        let valued = ["--manifest", "--meta", "--manifest-pubkey", "--protect", "--deadline", "--alias", "--tracker", "--store"];
        args.iter()
            .enumerate()
            .filter(|(i, a)| !a.starts_with("--") && !i.checked_sub(1).and_then(|p| args.get(p)).is_some_and(|f| valued.contains(&f.as_str())))
            .map(|(_, a)| a.clone())
            .nth(2)
    }

    fn start_watcher(sys: &mut tools::System<'_>, id: &str, ctx: &Armed<'_>) -> Result<u32, String> {
        let exe = std::env::current_exe().map_err(|e| format!("the agent cannot name its own image: {e}"))?;
        let exe = exe.to_str().ok_or("the agent's path is not UTF-8")?.to_string();
        let key = crate::vendor_manifest::pinned_manifest_key()?;
        let pidfile = format!("{}/{id}.pid", journal::DIR);
        let _ = std::fs::remove_file(&pidfile);
        let key = hex32(&key);
        let mut a: Vec<&str> = vec!["-f", "-p", &pidfile, &exe, "fw", "watch", id, "--manifest", &ctx.manifest];
        if let Some(m) = &ctx.meta {
            a.extend(["--meta", m.as_str()]);
        }
        a.extend(["--manifest-pubkey", key.as_str()]);
        let out = tools::Runner::run(sys, &tools::Invocation::new(tools::Tool::Daemon, &a)).map_err(|e| format!("daemon: {e}"))?;
        if !out.success() {
            return Err(format!("daemon exited {:?}: {}", out.status, String::from_utf8_lossy(&out.stderr).trim()));
        }
        for _ in 0..30 {
            if let Some(pid) = saferead::read_text(Path::new(&pidfile)).ok().and_then(|s| s.trim().parse::<u32>().ok()) {
                return Ok(pid);
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        Err(format!("daemon ran, and {pidfile} never named the watcher"))
    }

    fn print_doc(json: bool, text: &str, doc: &str) {
        if json {
            jprintln!("{doc}");
        } else {
            print!("{text}");
        }
    }

    pub(crate) fn arm(sys: &mut tools::System<'_>, ctx: &Armed<'_>, d: &DryRun, auth: &hemostat_enforce_pf::Authority, json: bool) -> u8 {
        use std::fmt::Write as _;
        let a = ctx.asked;

        let follow = follow_flags(&ctx.manifest, ctx.meta.as_deref());
        let f = h(&follow);
        let mut o = render_stages(d, &ctx.host, "fw block", "ARMED");
        let doc = |outcome: &str, id: &str, detail: &str| {
            format!(
                "{{\"cidr\":\"{}\",\"alias\":\"{}\",\"host_id\":\"{}\",\"id\":\"{id}\",\"outcome\":\"{outcome}\",\"detail\":\"{}\",\"journal\":\"{}\"}}",
                d.cidr,
                d.alias.name(),
                hex32(&ctx.host),
                jesc(detail),
                jesc(&if id.is_empty() { String::new() } else { format!("{}/{id}.tsv", journal::DIR) })
            )
        };
        if !d.passed() {
            let _ = writeln!(o, "  Nothing applied.");
            print_doc(json, &o, &doc("refused", "", "a stage refused; see the text rendering"));
            return exit_code(d);
        }
        let Some(nonce) = ctx.nonce else {
            let _ = writeln!(o, "  REFUSED: the ticket verified but its nonce was not read back. Nothing applied.");
            print_doc(json, &o, &doc("refused", "", "no nonce"));
            return EXIT_AUTHZ;
        };
        let id = journal::id_of(&nonce);
        let j = Journals::at(journal::DIR);
        if j.path(&id).exists() {
            let _ = writeln!(o, "  REFUSED: a journal for {id} exists already; one ticket is one action. Nothing applied.");
            print_doc(json, &o, &doc("refused", &id, "journal exists"));
            return EXIT_AUTHZ;
        }
        if let Err(why) = apply::refuse_while_booting(booting()) {
            let _ = writeln!(o, "  REFUSED: {}. Nothing applied; the ticket is kept.", h(&why));
            print_doc(json, &o, &doc("refused", &id, &why));
            return crate::EXIT_POLICY;
        }

        if let Err(why) = apply::refuse_duplicate(&j, a.enrolled.alias, &a.cidr, &follow) {
            let _ = writeln!(o, "  REFUSED: {}. Nothing applied; the ticket is kept.", h(&why));
            print_doc(json, &o, &doc("refused", &id, &why));
            return crate::EXIT_POLICY;
        }

        let (store, key) = match seal_evidence(sys, &id, "block") {
            Ok(x) => x,
            Err(why) => {
                let _ = writeln!(o, "  REFUSED  evidence     {} Nothing applied.", h(&why));
                print_doc(json, &o, &doc("refused", &id, &why));
                return EXIT_FAILED;
            }
        };
        let _ = writeln!(o, "    sealed   evidence      config.xml and /cf/conf/backup digests: {} (key {})", h(&store), hex32(&key));
        let allowed = match d.armed(auth, Evidence::Sealed) {
            Decision::Allow(x) => x,
            Decision::Refused { stage, reason } => {
                let _ = writeln!(o, "    REFUSED  {:<13} {} Nothing applied.", stage.token(), h(&reason));
                print_doc(json, &o, &doc("refused", &id, &reason));
                return crate::EXIT_POLICY;
            }
            Decision::DryRun { .. } => return EXIT_FAILED,
        };

        let log = std::env::var("HEMOSTAT_NONCE_LOG").unwrap_or_else(|_| "/root/hemostat/used-tickets".to_string());
        if let Err(why) = spend_at(&log, &nonce) {
            let _ = writeln!(o, "    REFUSED  ticket-v2     {} Nothing applied.", h(&why));
            print_doc(json, &o, &doc("refused", &id, &why));
            return EXIT_AUTHZ;
        }
        let _ = writeln!(o, "    spent    ticket-v2     nonce {id}…");

        let t = now();
        let intent = Intent {
            id: id.clone(),
            at: t,
            class: Class::Block,
            alias: a.enrolled.alias,
            cidr: a.cidr,
            existed: false,
            tracker: a.enrolled.tracker,
            deadline: t + a.deadline,
            undo: UndoKind::Lift,
            host: hex32(&ctx.host),
            protect: a.enrolled.protect.clone(),
        };
        let config = match read_config() {
            Ok(c) => c,
            Err(why) => {
                let _ = writeln!(o, "  FAILED: config.xml did not read immediately before the add: {}. Nothing applied.", h(&why));
                print_doc(json, &o, &doc("failed", &id, &why));
                return EXIT_FAILED;
            }
        };
        match apply::apply(sys, &j, allowed, intent, &config, &follow) {
            Ok(Applied::Live) => {}
            Ok(Applied::Existed(why)) => {
                let _ = writeln!(o, "\n  ALREADY BLOCKED: {}. Journal {}.", h(&why), j.path(&id).display());
                print_doc(json, &o, &doc("existed", &id, &why));
                return EXIT_OK;
            }
            Err(why) => {
                let _ = writeln!(o, "\n  FAILED: {}. The journal says how far it got: `hemostat undo {id}{f}` lifts whatever of it is live.", h(&why));
                print_doc(json, &o, &doc("failed", &id, &why));
                return EXIT_FAILED;
            }
        }
        let _ = writeln!(o, "\n  LIVE     {} in pf's table {} (-T show and -T test agree) · journal {}", a.cidr, a.enrolled.alias.name(), j.path(&id).display());

        match start_watcher(sys, &id, ctx) {
            Ok(pid) => {
                let _ = j.append(&id, "watch", &[("pid", pid.to_string())]);
                let _ = writeln!(
                    o,
                    "  WATCHER  pid {pid} lifts it at {} (in {} s) unless it is confirmed:\n\n      hemostat fw confirm {id} --arm{f}\n\n  \
                     Not in config.xml yet, so a filter reload or a reboot drops it too. `hemostat undo {id}{f}` lifts it now.",
                    clock(t + a.deadline),
                    a.deadline
                );
                print_doc(json, &o, &doc("live", &id, &format!("watcher pid {pid}, deadline {}", t + a.deadline)));
                EXIT_OK
            }
            Err(why) => {
                let _ = j.append(&id, "watch", &[("failed", why.clone())]);
                let _ = writeln!(o, "  WATCHER  could not be started ({}). A block with no deadline is not commit-confirm, so it is lifted now.", h(&why));
                let _ = j.hold(&id).map(|_held| {
                    let mut no_seal = || Err("the watcher's lift writes no config".to_string());
                    match apply::lift(sys, &j, &id, "watch-failed", false, &read_config, &mut no_seal, &follow) {
                        Ok(l) => {
                            let _ = writeln!(o, "  LIFTED   {l:?}");
                        }
                        Err(e) => {
                            let _ = writeln!(o, "  LIFT FAILED: {} — run `hemostat undo {id}{f}`", h(&e));
                        }
                    }
                });
                print_doc(json, &o, &doc("failed", &id, &why));
                EXIT_FAILED
            }
        }
    }

    pub(crate) fn watch(args: &[String]) -> u8 {
        let Some(id) = id_arg(args).filter(|i| journal::valid_id(i)) else {
            eprintln!("hemostat fw watch: needs the block's id");
            return EXIT_USAGE;
        };

        if let Some(k) = args.iter().position(|a| a == "--manifest-pubkey").and_then(|i| args.get(i + 1)) {
            std::env::set_var("HEMOSTAT_MANIFEST_PUBKEY", k);
        }
        let l = match load(args) {
            Ok(l) => l,
            Err(e) => {
                eprintln!("hemostat fw watch: {}", h(&e));
                return EXIT_FAILED;
            }
        };
        let mut sys = tools::System::new(l.manifest.as_ref()).with_meta(l.meta.as_ref());
        let _ = tools::renice_self(&mut sys, 10);
        let j = Journals::at(journal::DIR);

        let f = follow_flags(&l.mpath, l.given_meta.as_deref());

        let mut failed = 0u32;
        loop {
            let why = match j.read(&id).map(|e| apply::watch_step(&e, now())) {
                Ok(WatchStep::Wait(s)) => {
                    failed = 0;
                    std::thread::sleep(std::time::Duration::from_secs(s.max(1)));
                    continue;
                }
                Ok(WatchStep::Stop(_)) => return EXIT_OK,
                Ok(WatchStep::Due) => match lift_due(&mut sys, &j, &id, &f) {
                    Ok(code) => return code,
                    Err(why) => why,
                },
                Err(why) => why,
            };
            failed = failed.saturating_add(1);
            match apply::lift_retry_after(failed) {
                Some(s) => std::thread::sleep(std::time::Duration::from_secs(s)),
                None => {
                    let what = format!(
                        "watcher: gave up after {failed} failed tries at the deadline, the last: {why}. The block may \
                         still be live: `hemostat undo {id}{f}` lifts it"
                    );
                    let _ = j.append(&id, "note", &[("what", what)]);
                    eprintln!("hemostat fw watch: {}", h(&why));
                    return EXIT_FAILED;
                }
            }
        }
    }

    fn lift_due(sys: &mut tools::System<'_>, j: &Journals, id: &str, follow: &str) -> Result<u8, String> {
        let _held = j.hold(id)?;
        match apply::watch_step(&j.read(id)?, now()) {
            WatchStep::Due => {}
            WatchStep::Stop(_) => return Ok(EXIT_OK),
            WatchStep::Wait(_) => return Err("the deadline is not due yet by this box's clock".into()),
        }
        let mut no_seal = || Err("the watcher's lift writes no config".to_string());
        match apply::lift(sys, j, id, "watch", false, &read_config, &mut no_seal, follow)? {
            Lifted::Left(why) => {
                let _ = j.append(id, "note", &[("what", format!("watcher at the deadline: {why}"))]);
                Ok(EXIT_PARTIAL)
            }
            _ => Ok(EXIT_OK),
        }
    }

    pub(crate) fn confirm(args: &[String], json: bool) -> u8 {
        if let Some(n) = hemostat_modules::noop::PerimeterBlock::compiled_out() {
            match n.apply(crate::MANIFEST.variant) {
                Err(e) => eprintln!("hemostat fw confirm: {e}. Making a block persistent is a forward action; `undo` lifts one in every variant"),
                Ok(never) => match never {},
            }
            return EXIT_NOT_BUILT;
        }
        let Some(id) = id_arg(args).filter(|i| journal::valid_id(i)) else {
            eprintln!("hemostat fw confirm: needs the id `fw block` printed (eight hex digits)");
            return EXIT_USAGE;
        };
        let armed = confirm_armed(args);
        if let Err(why) = apply::refuse_while_booting(booting()) {
            eprintln!("hemostat fw confirm: REFUSED — {}. The block stays live until its deadline", h(&why));
            return crate::EXIT_POLICY;
        }
        let l = match load(args) {
            Ok(l) => l,
            Err(e) => {
                eprintln!("hemostat fw confirm: DID NOT RUN — {}", h(&e));
                return EXIT_FAILED;
            }
        };

        if l.manifest.is_none() {
            eprintln!(
                "hemostat fw confirm: DID NOT RUN — no signed manifest is loaded. Give it the one `fw block` was given \
                 (--manifest PATH, or HEMOSTAT_MANIFEST): without it this run cannot read the host id the block's \
                 journal names, and nothing it runs can be checked. Nothing was written; an unconfirmed block still \
                 lifts at its deadline"
            );
            return EXIT_FAILED;
        }

        let follow = follow_flags(&l.mpath, l.given_meta.as_deref());
        let mut sys = tools::System::new(l.manifest.as_ref()).with_meta(l.meta.as_ref());
        let _ = tools::renice_self(&mut sys, 10);
        let (idn, _) = match crate::identity::gather_identity_with(&mut sys) {
            Ok(x) => x,
            Err(e) => {
                eprintln!("hemostat fw confirm: cannot read entropy for the identity: {e}");
                return EXIT_FAILED;
            }
        };
        let j = Journals::at(journal::DIR);
        let held = match j.hold(&id) {
            Ok(x) => x,
            Err(e) => {
                eprintln!("hemostat fw confirm: {}", h(&e));
                return EXIT_FAILED;
            }
        };
        let e = match j.read(&id) {
            Ok(e) => e,
            Err(why) => {
                eprintln!("hemostat fw confirm: {}", h(&why));
                return EXIT_FAILED;
            }
        };
        if e.intent.host != hex32(&idn.host) {
            eprintln!("hemostat fw confirm: the journal was written for host {}, and this is {}", h(&e.intent.host), hex32(&idn.host));
            return EXIT_FAILED;
        }

        let width = hemostat_enforce_pf::protect::Width::of(&e.intent.cidr);
        if let Some(why) = golden_refusal(width, crate::golden::active()) {
            let left = apply::held(&read_config(), &e, &follow).unwrap_or_else(|| format!("The block lifts at its deadline ({})", clock(e.intent.deadline)));
            eprintln!("hemostat fw confirm: REFUSED — {why}. Nothing written. {}", h(&left));
            return EXIT_POLICY;
        }
        let own = read_config().as_ref().map(crate::golden::own_addrs_of).unwrap_or_default();
        if let Some(why) = crate::golden::block_scope_here(&e.intent.cidr, &own) {
            let left = apply::held(&read_config(), &e, &follow).unwrap_or_else(|| format!("The block lifts at its deadline ({})", clock(e.intent.deadline)));
            eprintln!("hemostat fw confirm: REFUSED — {}. Nothing written. {}", h(&why), h(&left));
            return EXIT_POLICY;
        }
        let enrolled = hemostat_enforce_pf::Enrolled {
            alias: e.intent.alias,
            tracker: e.intent.tracker,
            protect: e.intent.protect.clone(),
            width,
        };
        let engagement = std::env::var("HEMOSTAT_ENGAGEMENT_ID").ok().and_then(|x| crate::identity::parse_hex16(&x));
        let operand = hemostat_enforce_pf::operand(hemostat_buildinfo::ActionClass::PerimeterBlock, &idn.host, e.intent.alias, &e.intent.cidr);
        let t = now();
        let ti = i64::try_from(t).unwrap_or(i64::MAX);
        let policy = load_policy(engagement, &idn.host, ti);
        let (ticket, _) = load_ticket_as(hemostat_buildinfo::ActionClass::PerimeterBlock, engagement, &idn.host, &operand, ti, |n| {
            journal::id_of(n) == id && spent(n)
        });
        let auth = hemostat_enforce_pf::Authority {
            profile: crate::authz::current_profile(),
            built: true,
            policy,
            ticket,
        };
        let config = read_config();
        let inc = hemostat_enforce_pf::preflight::hash_incs(Path::new("/"));
        let resolv = saferead::read_text(Path::new("/etc/resolv.conf")).map_err(|e| e.to_string());
        let ssh = std::env::var("SSH_CONNECTION").ok();
        let d = hemostat_enforce_pf::confirm_stages(
            &mut sys,
            idn.host,
            e.intent.cidr,
            &enrolled,
            &config,
            &inc,
            l.manifest.as_ref().map(hemostat_evcrypto::manifest::Verified::manifest),
            &resolv,
            ssh.as_deref(),
            &auth,
        );
        let mut o = render_stages(&d, &idn.host, "fw confirm", &if armed { id.clone() } else { format!("{id}, DRY RUN") });
        let doc = |outcome: &str, detail: &str| {
            format!(
                "{{\"id\":\"{id}\",\"cidr\":\"{}\",\"alias\":\"{}\",\"outcome\":\"{outcome}\",\"detail\":\"{}\"}}",
                e.intent.cidr,
                e.intent.alias.name(),
                jesc(detail)
            )
        };

        let lifts = format!("The block lifts at its deadline ({}) unless it is confirmed.", clock(e.intent.deadline));
        use std::fmt::Write as _;

        if !d.passed() || (armed && !matches!(d.armed(&auth, Evidence::Sealed), Decision::Allow(_))) {
            let left = apply::held(&read_config(), &e, &follow).unwrap_or_else(|| lifts.clone());
            let _ = writeln!(o, "  Nothing written. {}", h(&left));
            print_doc(json, &o, &doc("refused", "a stage refused"));
            return exit_code(&d);
        }
        if !armed {

            let (outcome, detail, code) = match apply::would_confirm(&mut sys, &j, &id, t, &read_config, &follow) {
                Ok(None) => {
                    let _ = writeln!(
                        o,
                        "\n  would write  {} into {} in config.xml under \"HEMOSTAT {id}\" through pfSense's own PHP (one \
                         revision, \"HEMOSTAT block {} {id}\"), reload the filter, re-add and re-test it, and prove it from \
                         disk — after sealing config.xml and the backup digests",
                        e.intent.cidr,
                        e.intent.alias.name(),
                        e.intent.cidr
                    );
                    let f = h(&follow);
                    let _ = writeln!(
                        o,
                        "\n  DRY RUN: nothing was sealed or written. {lifts} To confirm it:\n\n      hemostat fw confirm {id} --arm{f}"
                    );
                    ("dry-run", String::new(), EXIT_DRYRUN)
                }
                Ok(Some(rev)) => {
                    let _ = writeln!(o, "\n  ALREADY CONFIRMED at revision {rev}; there is nothing to write.");
                    ("already", rev, EXIT_OK)
                }
                Err(u) => {
                    let _ = writeln!(o, "\n  REFUSED  journal       {}. Nothing written.", h(u.why()));
                    let outcome = if matches!(u, Unconfirmed::Held(_)) { "held" } else { "refused" };
                    (outcome, u.why().to_string(), EXIT_POLICY)
                }
            };
            print_doc(json, &o, &doc(outcome, &detail));
            return code;
        }
        let verified: Vec<String> = inc.as_ref().map(|v| v.iter().filter(|f| f.sha256.is_ok()).map(|f| f.path.clone()).collect()).unwrap_or_default();
        let mut seal_sys = tools::System::new(l.manifest.as_ref()).with_meta(l.meta.as_ref());
        let mut sealed_at = None;
        let mut seal = || {
            let s = seal_evidence(&mut seal_sys, &id, "confirm")?;
            sealed_at = Some(s);
            Ok(())
        };
        let got = apply::confirm(&mut sys, &j, &id, t, &read_config, &mut seal, &verified, &follow);
        drop(held);
        if let Some((store, key)) = &sealed_at {
            let _ = writeln!(o, "    sealed   evidence      {} (key {})", h(store), hex32(key));
        }
        match got {
            Ok(Confirmed::Done { rev, unverified }) => {
                let _ = writeln!(
                    o,
                    "\n  CONFIRMED {} in {} · config.xml revision {rev} (\"HEMOSTAT block {} {id}\"), proven from disk · \
                     re-added and re-tested after the reload",
                    e.intent.cidr,
                    e.intent.alias.name(),
                    e.intent.cidr
                );
                for f in &unverified {
                    let _ = writeln!(o, "  WARN: alias.php included {}, which preflight did not verify", h(f));
                }
                print_doc(json, &o, &doc("confirmed", &rev));
                if unverified.is_empty() {
                    EXIT_OK
                } else {
                    EXIT_PARTIAL
                }
            }
            Ok(Confirmed::Already(rev)) => {
                let _ = writeln!(o, "\n  ALREADY CONFIRMED at revision {rev}; nothing written.");
                print_doc(json, &o, &doc("already", &rev));
                EXIT_OK
            }
            Err(Unconfirmed::Live(why)) => {
                let _ = writeln!(o, "\n  NOT CONFIRMED: {}. config.xml does not list it: {lifts}", h(&why));
                print_doc(json, &o, &doc("refused", &why));
                EXIT_FAILED
            }

            Err(Unconfirmed::Held(why)) => {
                let _ = writeln!(o, "\n  NOT CONFIRMED, AND THE WATCHER WILL NOT LIFT IT AT ITS DEADLINE: {}", h(&why));
                print_doc(json, &o, &doc("held", &why));
                EXIT_FAILED
            }
        }
    }

    pub(crate) fn undo(args: &[String], json: bool) -> u8 {
        use std::fmt::Write as _;
        let one = args.iter().enumerate().filter(|(i, a)| !a.starts_with("--") && !i.checked_sub(1).and_then(|p| args.get(p)).is_some_and(|f| matches!(f.as_str(), "--manifest" | "--meta"))).map(|(_, a)| a.clone()).nth(1);
        if let Some(i) = &one {
            if !journal::valid_id(i) {
                eprintln!("hemostat undo: {} is not a containment id (eight hex digits)", h(i));
                return EXIT_USAGE;
            }
        }
        let l = match load(args) {
            Ok(l) => l,
            Err(e) => {
                eprintln!("hemostat undo: DID NOT RUN — {}", h(&e));
                return EXIT_FAILED;
            }
        };
        let follow = follow_flags(&l.mpath, l.given_meta.as_deref());
        let mut sys = tools::System::new(l.manifest.as_ref()).with_meta(l.meta.as_ref());
        let _ = tools::renice_self(&mut sys, 10);
        let j = Journals::at(journal::DIR);
        let ids = match &one {
            Some(i) => vec![i.clone()],
            None => match j.ids() {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("hemostat undo: {}", h(&e));
                    return EXIT_FAILED;
                }
            },
        };
        let mut o = String::new();
        let _ = writeln!(o, "undo — replaying HEMOSTAT's containment journal ({}); only HEMOSTAT's own entries are lifted", journal::DIR);
        let _ = writeln!(o, "  (no ticket: undo only lifts, and what it lifts is judged from the journal and the box)");
        if l.manifest.is_none() {
            let _ = writeln!(
                o,
                "  no signed manifest is loaded, so no lift can run: pfctl and config.xml are reached only through tools \
                 it verifies. Give undo the one `fw block` was given (--manifest PATH, or HEMOSTAT_MANIFEST)"
            );
        }
        let mut rows = Vec::new();
        let mut code = EXIT_OK;
        for id in &ids {
            let row = (|| -> Result<String, String> {
                let _held = j.hold(id)?;
                let e = j.read(id)?;
                if e.intent.undo == UndoKind::Nothing {
                    return Ok(format!("{}: nothing to undo — killed states cannot be restored", e.intent.class.token()));
                }
                let mut seal_sys = tools::System::new(l.manifest.as_ref()).with_meta(l.meta.as_ref());

                let mut seal = || {
                    apply::refuse_while_booting(booting())?;
                    seal_evidence(&mut seal_sys, id, "lift").map(|_| ())
                };
                Ok(match apply::lift(&mut sys, &j, id, "undo", true, &read_config, &mut seal, &follow)? {
                    Lifted::Done { config: true, table: true } => format!("LIFTED {} from {} — config.xml and pf's table; -T test fails", e.intent.cidr, e.intent.alias.name()),
                    Lifted::Done { config: false, table: true } => format!("LIFTED {} from pf's table {}; -T test fails", e.intent.cidr, e.intent.alias.name()),

                    Lifted::Done { config, table: false } => {
                        format!("LIFTED {} — {}", e.intent.cidr, apply::unloaded(e.intent.alias, &e.intent.cidr, config))
                    }
                    Lifted::Covered => {
                        code = EXIT_PARTIAL;
                        format!("LIFTED {} from {}, but -T test still matches: another entry covers it", e.intent.cidr, e.intent.alias.name())
                    }
                    Lifted::Left(why) => format!("left: {why}"),
                    Lifted::Nothing(why) => format!("nothing to do: {why}"),
                })
            })();
            let (state, text) = match row {
                Ok(t) => ("ok", t),
                Err(why) => {
                    code = EXIT_FAILED;
                    ("failed", why)
                }
            };
            let _ = writeln!(o, "  {id}  {}", h(&text));
            rows.push(format!("{{\"id\":\"{id}\",\"result\":\"{state}\",\"detail\":\"{}\"}}", jesc(&text)));
        }
        if ids.is_empty() {
            let _ = writeln!(o, "  no journal: nothing HEMOSTAT did here to undo");
        }
        print_doc(json, &o, &format!("{{\"undone\":[{}]}}", rows.join(",")));
        code
    }

    pub(crate) fn statekill(args: &[String], json: bool) -> u8 {
        use std::fmt::Write as _;
        use hemostat_buildinfo::ActionClass;
        if let Some(n) = hemostat_modules::noop::PerimeterStateKill::compiled_out() {
            match n.apply(crate::MANIFEST.variant) {
                Err(e) => eprintln!("hemostat fw statekill: {e}"),
                Ok(never) => match never {},
            }
            return EXIT_NOT_BUILT;
        }
        let val = |n: &str| args.iter().position(|a| a == n).and_then(|i| args.get(i + 1)).cloned();

        let dry = !args.iter().any(|a| a == "--arm") || args.iter().any(|a| a == "--dry-run");
        let Some(raw) = id_arg(args) else {
            eprintln!("hemostat fw statekill: needs one CIDR");
            return EXIT_USAGE;
        };
        let cidr = match hs_core::cidr::Cidr::parse(&raw) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("hemostat fw statekill: refused: {e}");
                return EXIT_USAGE;
            }
        };
        let Some(alias) = val("--alias").as_deref().and_then(hemostat_enforce_pf::Alias::from_name) else {
            eprintln!("hemostat fw statekill: --alias HEMOSTAT_OUT (every state to the CIDR) or HEMOSTAT_IN (every state from it)");
            return EXIT_USAGE;
        };
        let mut protect = Vec::new();
        for (i, a) in args.iter().enumerate() {
            if a == "--protect" {
                match args.get(i + 1).map(|v| hs_core::cidr::Cidr::parse(v)) {
                    Some(Ok(c)) => protect.push(c),
                    _ => {
                        eprintln!("hemostat fw statekill: --protect needs a CIDR");
                        return EXIT_USAGE;
                    }
                }
            }
        }

        let width = width_asked(args);
        if let Some(why) = golden_refusal(width, crate::golden::active()) {
            eprintln!("hemostat fw statekill: REFUSED — {why}. Nothing was read or killed");
            return EXIT_POLICY;
        }

        let own = read_config().as_ref().map(crate::golden::own_addrs_of).unwrap_or_default();
        if let Some(why) = crate::golden::block_scope_here(&cidr, &own) {
            eprintln!("hemostat fw statekill: REFUSED — {}. Nothing was read or killed", h(&why));
            return EXIT_POLICY;
        }
        let l = match load(args) {
            Ok(l) => l,
            Err(e) => {
                eprintln!("hemostat fw statekill: DID NOT RUN — {}", h(&e));
                return EXIT_FAILED;
            }
        };
        let mut sys = tools::System::new(l.manifest.as_ref()).with_meta(l.meta.as_ref());
        let _ = tools::renice_self(&mut sys, 10);
        let (idn, _) = match crate::identity::gather_identity_with(&mut sys) {
            Ok(x) => x,
            Err(e) => {
                eprintln!("hemostat fw statekill: cannot read entropy for the identity: {e}");
                return EXIT_FAILED;
            }
        };
        let engagement = std::env::var("HEMOSTAT_ENGAGEMENT_ID").ok().and_then(|x| crate::identity::parse_hex16(&x));
        let operand = hemostat_enforce_pf::operand(ActionClass::PerimeterStateKill, &idn.host, alias, &cidr);
        let t = now();
        let ti = i64::try_from(t).unwrap_or(i64::MAX);
        let policy = load_policy(engagement, &idn.host, ti);
        let (ticket, nonce) = load_ticket_as(ActionClass::PerimeterStateKill, engagement, &idn.host, &operand, ti, |n| !spent(n));
        let auth = hemostat_enforce_pf::Authority { profile: crate::authz::current_profile(), built: true, policy, ticket };
        let enrolled = hemostat_enforce_pf::Enrolled { alias, tracker: 0, protect, width };
        let config = read_config();
        let resolv = saferead::read_text(Path::new("/etc/resolv.conf")).map_err(|e| e.to_string());
        let ssh = std::env::var("SSH_CONNECTION").ok();
        let d = hemostat_enforce_pf::stages(
            &mut sys,
            ActionClass::PerimeterStateKill,
            idn.host,
            cidr,
            &enrolled,
            &config,
            &Ok(Vec::new()),
            l.manifest.as_ref().map(hemostat_evcrypto::manifest::Verified::manifest),
            &resolv,
            ssh.as_deref(),
            &auth,
        );
        let mut o = render_stages(&d, &idn.host, "fw statekill", if dry { "DRY RUN" } else { "ARMED" });
        let doc = |outcome: &str, id: &str, detail: &str| {
            format!(
                "{{\"cidr\":\"{cidr}\",\"alias\":\"{}\",\"id\":\"{id}\",\"outcome\":\"{outcome}\",\"detail\":\"{}\"}}",
                alias.name(),
                jesc(detail)
            )
        };
        if dry || !d.passed() {
            print_doc(json, &o, &doc(if d.passed() { "dry-run" } else { "refused" }, "", ""));
            return exit_code(&d);
        }
        let Some(nonce) = nonce else {
            let _ = writeln!(o, "  REFUSED: the ticket's nonce was not read back. Nothing killed.");
            print_doc(json, &o, &doc("refused", "", "no nonce"));
            return EXIT_AUTHZ;
        };
        let id = journal::id_of(&nonce);
        let j = Journals::at(journal::DIR);
        if j.path(&id).exists() {
            let _ = writeln!(o, "  REFUSED: a journal for {id} exists already; one ticket is one action. Nothing killed.");
            print_doc(json, &o, &doc("refused", &id, "journal exists"));
            return EXIT_AUTHZ;
        }

        let mut ro = hemostat_enforce_pf::cmd::ReadOnly::new(&mut sys);
        let listing = match hemostat_enforce_pf::statekill::listing(&mut ro) {
            Ok(t) => t,
            Err(why) => {
                let _ = writeln!(o, "  REFUSED  evidence      pf's states could not be read ({}). Nothing killed.", h(&why));
                print_doc(json, &o, &doc("refused", &id, &why));
                return EXIT_FAILED;
            }
        };
        let matched = hemostat_enforce_pf::statekill::matching(&listing, alias, &cidr);
        if matched.is_empty() {
            let _ = writeln!(o, "\n  NOTHING TO KILL: no state {} {cidr}. Nothing sealed or killed; the ticket is kept.", if alias == hemostat_enforce_pf::Alias::Out { "to" } else { "from" });
            print_doc(json, &o, &doc("nothing", &id, "no matching state"));
            return EXIT_OK;
        }
        let sealed = (|| -> Result<(String, [u8; 32]), String> {
            use crate::freebsd_drift::{admit, open, prepare_in, seal};
            let dir = format!("{EVIDENCE_STORE}/{t}-{id}-statekill");
            let prep = prepare_in("fw statekill", &dir, &mut sys)?;
            let recs = statekill_records(&id, &cidr.to_string(), &listing, &matched);

            admit(&prep, recs.iter().map(Vec::len).sum())?;
            hemostat_sensor_freebsd::store::create_private(Path::new(EVIDENCE_STORE)).map_err(|e| format!("{EVIDENCE_STORE}: {e}"))?;
            let seed = crate::identity::rand32().map_err(|e| format!("no entropy for the seal key: {e}"))?;
            let s = seal(&dir, seed, &recs, &prep.ids)?;
            let back = open(&dir, Some(s.seal_pub))?;
            let n = decode_statekill(&back.records)?.len();
            if n != matched.len() {
                return Err(format!("the store read back {n} states, not {}", matched.len()));
            }
            Ok((dir, s.seal_pub))
        })();
        let (store, key) = match sealed {
            Ok(x) => x,
            Err(why) => {
                let _ = writeln!(o, "  REFUSED  evidence      {} Nothing killed.", h(&why));
                print_doc(json, &o, &doc("refused", &id, &why));
                return EXIT_FAILED;
            }
        };
        let _ = writeln!(o, "    sealed   evidence      {} matching state(s) and the whole listing: {} (key {})", matched.len(), h(&store), hex32(&key));
        for m in &matched {
            let _ = writeln!(o, "               {}", h(m.lines().next().unwrap_or_default()));
        }
        let allowed = match d.armed(&auth, Evidence::Sealed) {
            Decision::Allow(x) => x,
            Decision::Refused { stage, reason } => {
                let _ = writeln!(o, "    REFUSED  {:<13} {} Nothing killed.", stage.token(), h(&reason));
                print_doc(json, &o, &doc("refused", &id, &reason));
                return crate::EXIT_POLICY;
            }
            Decision::DryRun { .. } => return EXIT_FAILED,
        };
        let log = std::env::var("HEMOSTAT_NONCE_LOG").unwrap_or_else(|_| "/root/hemostat/used-tickets".to_string());
        if let Err(why) = spend_at(&log, &nonce) {
            let _ = writeln!(o, "    REFUSED  ticket-v2     {} Nothing killed.", h(&why));
            print_doc(json, &o, &doc("refused", &id, &why));
            return EXIT_AUTHZ;
        }
        let intent = Intent {
            id: id.clone(),
            at: t,
            class: Class::StateKill,
            alias,
            cidr,
            existed: false,
            tracker: 0,
            deadline: t,
            undo: UndoKind::Nothing,
            host: hex32(&idn.host),
            protect: enrolled.protect.clone(),
        };
        match hemostat_enforce_pf::statekill::kill(&mut sys, &j, allowed, intent, matched.len(), &store) {
            Ok(k) => {
                let _ = writeln!(
                    o,
                    "\n  KILLED   {} matching state(s) sealed; pf killed {}; {} matching remain · journal {} (undo: nothing — a killed state cannot be restored)",
                    k.matched,
                    k.killed.map_or("an unreported number".to_string(), |n| n.to_string()),
                    k.remaining,
                    j.path(&id).display()
                );
                print_doc(json, &o, &doc("killed", &id, &format!("matched {} killed {:?} remaining {}", k.matched, k.killed, k.remaining)));
                if k.remaining == 0 {
                    EXIT_OK
                } else {
                    EXIT_PARTIAL
                }
            }
            Err(why) => {
                let _ = writeln!(o, "\n  FAILED: {}", h(&why));
                print_doc(json, &o, &doc("failed", &id, &why));
                EXIT_FAILED
            }
        }
    }

    pub(crate) fn status(args: &[String], json: bool) -> u8 {
        let l = match load(args) {
            Ok(l) => l,
            Err(e) => {
                eprintln!("hemostat fw status: DID NOT RUN — {}", h(&e));
                return EXIT_FAILED;
            }
        };
        let mut sys = tools::System::new(l.manifest.as_ref()).with_meta(l.meta.as_ref());
        let mut ro = hemostat_enforce_pf::cmd::ReadOnly::new(&mut sys);
        let j = Journals::at(journal::DIR);
        let mut rows = Vec::new();
        let mut gaps = Vec::new();
        let mut shows: std::collections::BTreeMap<&str, Option<Vec<hs_core::cidr::Cidr>>> = Default::default();
        for id in j.ids().unwrap_or_default() {
            match j.read(&id) {
                Ok(e) => {
                    let a = e.intent.alias;
                    let t = shows
                        .entry(a.name())
                        .or_insert_with(|| {
                            tools::Runner::run(&mut ro, &tools::Invocation::new(tools::Tool::Pfctl, &["-t", a.name(), "-T", "show"]))
                                .ok()
                                .filter(tools::Output::success)
                                .map(|o| journal::table_entries(&o.text()))
                        })
                        .as_ref()
                        .map(|v| v.contains(&e.intent.cidr));
                    rows.push((e, t));
                }
                Err(why) => gaps.push(why),
            }
        }
        let doc: Vec<String> = rows
            .iter()
            .map(|(e, t)| {
                format!(
                    "{{\"id\":\"{}\",\"class\":\"{}\",\"alias\":\"{}\",\"cidr\":\"{}\",\"state\":\"{}\",\"deadline\":{},\"in_table\":{}}}",
                    e.intent.id,
                    e.intent.class.token(),
                    e.intent.alias.name(),
                    e.intent.cidr,
                    e.state().token(),
                    e.intent.deadline,
                    t.map_or("null".to_string(), |b| b.to_string())
                )
            })
            .collect();
        print_doc(json, &render_status(&rows, &gaps, now()), &format!("{{\"entries\":[{}]}}", doc.join(",")));
        let _ = l.mpath;
        let _ = l.given_meta;
        if gaps.is_empty() {
            EXIT_OK
        } else {
            EXIT_PARTIAL
        }
    }
}

#[cfg(target_os = "freebsd")]
pub(crate) use verb::{arm, confirm, status, statekill, undo, watch};

#[cfg(target_os = "freebsd")]
pub(crate) fn journals_on_box() -> (Vec<Entry>, Vec<String>) {
    let j = journal::Journals::at(journal::DIR);
    let mut out = Vec::new();
    let mut gaps = Vec::new();
    match j.ids() {
        Ok(ids) => {
            for id in ids {
                match j.read(&id) {
                    Ok(e) => out.push(e),
                    Err(why) => gaps.push(format!("containment journal {id} did not read: {why}")),
                }
            }
        }
        Err(why) => gaps.push(format!("the containment journal could not be listed: {why}")),
    }
    (out, gaps)
}
