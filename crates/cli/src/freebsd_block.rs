use hemostat_broker::perimeter::{Decision, Policy, Signed, Stage};
use hemostat_enforce_pf::{Alias, DryRun};
use hs_core::cidr::Cidr;

use crate::render::{h, hex32, jesc};
use crate::{EXIT_AUTHZ, EXIT_DRYRUN, EXIT_NOT_BUILT, EXIT_POLICY};

#[cfg_attr(not(target_os = "freebsd"), allow(dead_code))]
const MAX_AUTHORITY_BYTES: u64 = 1024 * 1024;

#[cfg_attr(not(target_os = "freebsd"), allow(dead_code))]
const EPOCH_FLOOR: &str = "/root/hemostat/policy-epoch";

#[cfg_attr(not(target_os = "freebsd"), allow(dead_code))]
const NONCE_LOG: &str = "/root/hemostat/used-tickets";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Asked {
    pub(crate) cidr: Cidr,
    pub(crate) enrolled: hemostat_enforce_pf::Enrolled,

    pub(crate) dry: bool,

    pub(crate) deadline: u64,
}

pub(crate) const DEFAULT_DEADLINE: u64 = 120;

pub(crate) const MIN_DEADLINE: u64 = 30;

pub(crate) const MAX_DEADLINE: u64 = 3600;

pub(crate) fn parse_args(args: &[String]) -> Result<Asked, String> {
    let val = |name: &str| args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).map(String::as_str);

    let dry = !args.iter().any(|a| a == "--arm") || args.iter().any(|a| a == "--dry-run");
    let deadline = match val("--deadline") {
        None => DEFAULT_DEADLINE,
        Some(v) => match v.parse::<u64>() {
            Ok(n) if (MIN_DEADLINE..=MAX_DEADLINE).contains(&n) => n,
            _ => return Err(format!("--deadline is seconds, {MIN_DEADLINE} to {MAX_DEADLINE}")),
        },
    };
    let valued = ["--alias", "--tracker", "--protect", "--manifest", "--meta", "--deadline"];
    let positional: Vec<&str> = args
        .iter()
        .enumerate()
        .filter(|(i, a)| !a.starts_with("--") && !i.checked_sub(1).and_then(|p| args.get(p)).is_some_and(|f| valued.contains(&f.as_str())))
        .map(|(_, a)| a.as_str())
        .collect();

    let raw = match positional.as_slice() {
        [_, _, c] => *c,
        [_, _] => return Err("fw block needs one CIDR".into()),
        _ => return Err("fw block takes one CIDR; one ticket binds one range".into()),
    };
    let cidr = Cidr::parse(raw).map_err(|e| format!("refused: {e}"))?;
    let alias_name = val("--alias").ok_or("--alias HEMOSTAT_OUT or --alias HEMOSTAT_IN is required")?;
    let alias = Alias::from_name(alias_name).ok_or_else(|| {
        format!("{} is not an enrolled alias: HEMOSTAT acts only on HEMOSTAT_OUT and HEMOSTAT_IN", h(alias_name))
    })?;
    let tracker = val("--tracker")
        .ok_or("--tracker N is required: the tracker of the rule that blocks the alias, as the GUI shows it")?
        .parse::<u32>()
        .map_err(|_| "--tracker is the rule's numeric tracker".to_string())?;
    let mut protect = Vec::new();
    for (i, a) in args.iter().enumerate() {
        if a == "--protect" {
            let v = args.get(i + 1).ok_or("--protect needs a CIDR")?;
            protect.push(Cidr::parse(v).map_err(|e| format!("--protect {}: {e}", h(v)))?);
        }
    }
    Ok(Asked { cidr, enrolled: hemostat_enforce_pf::Enrolled { alias, tracker, protect }, dry, deadline })
}

pub(crate) fn exit_code(d: &DryRun) -> u8 {
    match &d.decision {
        Some(Decision::DryRun { .. }) => EXIT_DRYRUN,
        Some(Decision::Refused { stage: Stage::Ticket, .. }) => EXIT_AUTHZ,
        Some(Decision::Refused { stage: Stage::BuildStatus, .. }) => EXIT_NOT_BUILT,
        Some(Decision::Refused { stage: Stage::Mode, .. }) => EXIT_DRYRUN,
        Some(Decision::Refused { .. } | Decision::Allow(_)) | None => EXIT_POLICY,
    }
}

pub(crate) fn render(d: &DryRun, host: &[u8; 32]) -> String {
    render_stages(d, host, "fw block", "DRY RUN")
}

pub(crate) fn render_stages(d: &DryRun, host: &[u8; 32], verb: &str, label: &str) -> String {
    use std::fmt::Write as _;
    let mut o = String::new();
    let _ = writeln!(o, "{verb} {} in {} — {label}", d.cidr, d.alias.name());
    let _ = writeln!(o, "  host id   {}", hex32(host));
    let _ = writeln!(o, "  operand   {} (ticket v2: class, host, alias, {}, CIDR)", hex32(&d.operand), d.alias.dir().token());
    let _ = writeln!(o, "\n  preflight (read-only)");
    for c in &d.preflight.checks {
        match &c.result {
            Ok(s) => {
                let _ = writeln!(o, "    ok       {:<13} {}", c.what, h(s));
            }
            Err(s) => {
                let _ = writeln!(o, "    REFUSED  {:<13} {}", c.what, h(s));
            }
        }
    }
    match &d.decision {
        None => {
            let _ = writeln!(o, "\n  REFUSED at preflight; the broker was not asked. Nothing applied.");
        }
        Some(dec) => {
            let _ = writeln!(o, "\n  broker (RFC-002 §2 order)");
            match dec {
                Decision::DryRun { passed } => {
                    for (s, why) in passed {
                        let _ = writeln!(o, "    ok       {:<13} {}", s.token(), h(why));
                    }
                    if label == "DRY RUN" {
                        let _ = writeln!(o, "\n  every stage passed: dry run, nothing applied. No ticket was spent and no file was written.");
                    }
                }
                Decision::Refused { stage, reason } => {

                    for s in Stage::ORDER.iter().take_while(|s| *s != stage) {
                        let _ = writeln!(o, "    ok       {}", s.token());
                    }
                    let _ = writeln!(o, "    REFUSED  {:<13} {}", stage.token(), h(reason));
                    let _ = writeln!(o, "\n  REFUSED at {}. Nothing applied.", stage.token());
                }
                Decision::Allow(_) => {
                    let _ = writeln!(o, "\n  allowed, and this image has no apply: nothing applied.");
                }
            }
        }
    }
    o
}

pub(crate) fn render_json(d: &DryRun, host: &[u8; 32]) -> String {
    let checks: Vec<String> = d
        .preflight
        .checks
        .iter()
        .map(|c| match &c.result {
            Ok(s) => format!("{{\"check\":\"{}\",\"ok\":true,\"detail\":\"{}\"}}", c.what, jesc(s)),
            Err(s) => format!("{{\"check\":\"{}\",\"ok\":false,\"detail\":\"{}\"}}", c.what, jesc(s)),
        })
        .collect();
    let (outcome, stage, reason, passed) = match &d.decision {
        None => ("refused", "\"preflight\"".to_string(), d.preflight.refusal().and_then(|c| c.result.clone().err()).unwrap_or_default(), Vec::new()),
        Some(Decision::Refused { stage, reason }) => ("refused", format!("\"{}\"", stage.token()), reason.clone(), Vec::new()),
        Some(Decision::DryRun { passed }) => ("dry-run", "null".into(), String::new(), passed.clone()),
        Some(Decision::Allow(_)) => ("allowed", "null".into(), String::new(), Vec::new()),
    };
    let stages: Vec<String> =
        passed.iter().map(|(s, w)| format!("{{\"stage\":\"{}\",\"detail\":\"{}\"}}", s.token(), jesc(w))).collect();
    format!(
        "{{\"cidr\":\"{}\",\"alias\":\"{}\",\"dir\":\"{}\",\"host_id\":\"{}\",\"operand\":\"{}\",\
         \"preflight\":[{}],\"stages\":[{}],\"outcome\":\"{outcome}\",\"refused_at\":{stage},\
         \"reason\":\"{}\",\"applied\":false}}",
        d.cidr,
        d.alias.name(),
        d.alias.dir().token(),
        hex32(host),
        hex32(&d.operand),
        checks.join(","),
        stages.join(","),
        jesc(&reason)
    )
}

pub(crate) fn split_policy(blob: &[u8]) -> Result<(&[u8], &[u8]), String> {
    let len = blob
        .get(..4)
        .and_then(|b| <[u8; 4]>::try_from(b).ok())
        .map(|b| u32::from_be_bytes(b) as usize)
        .ok_or("the policy file is too short to hold its own length")?;
    let body = blob.get(4..4usize.saturating_add(len)).ok_or_else(|| format!("the policy file claims {len} bytes it does not have"))?;
    Ok((body, blob.get(4 + len..).unwrap_or_default()))
}

pub(crate) fn signed(p: hemostat_evcrypto::policy::Policy) -> Policy {
    Policy::Verified(Signed {
        allowed: p.allowed_actions,
        scope: p.scope,
        profile: match p.profile {
            hemostat_evcrypto::policy::PolicyProfile::It => hs_core::mode::Profile::It,
            hemostat_evcrypto::policy::PolicyProfile::Ot => hs_core::mode::Profile::Ot,
        },
        bulk_threshold: usize::from(p.bulk_threshold),
    })
}

pub(crate) fn split_ticket(blob: &[u8]) -> Result<(&[u8], &[u8]), String> {
    let v = *blob.first().ok_or("the ticket file is empty")?;
    let n = hemostat_evcrypto::ticket::claims_len(v).ok_or_else(|| format!("the ticket is format version {v}, which this build does not know"))?;
    blob.split_at_checked(n).ok_or_else(|| "the ticket file is too short to hold its claims".to_string())
}

#[cfg(target_os = "freebsd")]
pub(crate) fn now_secs() -> Result<i64, String> {
    let d = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| "this box's clock reads as before 1970, so no expiry can be checked".to_string())?;
    Ok(i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

#[cfg(target_os = "freebsd")]
fn read_file(path: &str) -> Result<Vec<u8>, String> {
    hemostat_sensor_freebsd::saferead::read_bytes(std::path::Path::new(path), MAX_AUTHORITY_BYTES)
        .map_err(|e| format!("cannot read {}: {e}", h(path)))
}

#[cfg(target_os = "freebsd")]
pub(crate) fn load_policy(engagement: Option<[u8; 16]>, host: &[u8; 32], now: i64) -> Policy {
    let Some(path) = std::env::var("HEMOSTAT_POLICY").ok().filter(|p| !p.trim().is_empty()) else {
        return Policy::None;
    };
    let go = || -> Result<Policy, String> {
        let engagement = engagement.ok_or("$HEMOSTAT_ENGAGEMENT_ID is not set, so no policy can be bound to this engagement")?;
        let pinned = std::env::var("HEMOSTAT_ENGAGEMENT_PUBKEY")
            .ok()
            .as_deref()
            .and_then(crate::identity::parse_hex32)
            .ok_or("$HEMOSTAT_ENGAGEMENT_PUBKEY is not a 64-hex engagement root key")?;
        let blob = read_file(&path)?;
        let (body, cose) = split_policy(&blob)?;
        let floor_path = std::env::var("HEMOSTAT_EPOCH_FLOOR").unwrap_or_else(|_| EPOCH_FLOOR.to_string());
        let floor = match hemostat_sensor_freebsd::saferead::read_text(std::path::Path::new(&floor_path)) {
            Ok(s) => s.trim().parse::<u32>().map_err(|_| format!("the epoch floor at {} is not a number", h(&floor_path)))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => 0,
            Err(e) => return Err(format!("the epoch floor at {} could not be read ({e})", h(&floor_path))),
        };
        hemostat_evcrypto::policy::verify(&pinned, body, cose, &engagement, host, now, floor)
            .map(signed)
            .map_err(|r| r.message())
    };
    go().unwrap_or_else(Policy::Refused)
}

#[cfg(target_os = "freebsd")]
pub(crate) fn spent(nonce: &[u8; 16]) -> bool {
    let log = std::env::var("HEMOSTAT_NONCE_LOG").unwrap_or_else(|_| NONCE_LOG.to_string());
    let hex: String = nonce.iter().map(|b| format!("{b:02x}")).collect();
    std::path::Path::new(&format!("{log}.spent")).join(&hex).exists()
        || hemostat_sensor_freebsd::saferead::read_text(std::path::Path::new(&log))
            .is_ok_and(|s| s.lines().any(|l| l.trim() == hex))
}

#[cfg(target_os = "freebsd")]
pub(crate) fn load_ticket_as(
    class: hemostat_buildinfo::ActionClass,
    engagement: Option<[u8; 16]>,
    host: &[u8; 32],
    operand: &[u8; 32],
    now: i64,
    fresh: impl FnMut(&[u8; 16]) -> bool,
) -> (hemostat_broker::perimeter::Ticket, Option<[u8; 16]>) {
    use hemostat_broker::perimeter::Ticket;
    use hemostat_evcrypto::ticket::{verify_v2, Asked, Op};
    let Some(path) = std::env::var("HEMOSTAT_TICKET").ok().filter(|p| !p.trim().is_empty()) else {
        return (Ticket::None, None);
    };
    let go = || -> Result<[u8; 16], String> {
        let engagement = engagement.ok_or("$HEMOSTAT_ENGAGEMENT_ID is not set, so no ticket can be bound to this engagement")?;
        let pinned = std::env::var("HEMOSTAT_RESPONDER_PUBKEY")
            .ok()
            .as_deref()
            .and_then(crate::identity::parse_hex32)
            .ok_or("$HEMOSTAT_RESPONDER_PUBKEY is not a 64-hex responder key")?;
        let blob = read_file(&path)?;
        let (claims, cose) = split_ticket(&blob)?;
        let asked = Asked { op: Op::Action, class: hemostat_broker::class_code(class), engagement, host: *host };
        verify_v2(&pinned, claims, cose, &asked, operand, now, fresh).map(|c| c.claims.nonce).map_err(|r| r.message())
    };
    match go() {
        Ok(n) => (Ticket::Verified, Some(n)),
        Err(why) => (Ticket::Refused(why), None),
    }
}

#[cfg(target_os = "freebsd")]
pub(crate) fn block(args: &[String], json: bool) -> u8 {
    use hemostat_sensor_freebsd::{configxml, saferead, tools};

    let asked = match parse_args(args) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("hemostat fw block: {e}");
            return crate::EXIT_USAGE;
        }
    };
    let path = args.iter().position(|a| a == "--manifest").and_then(|i| args.get(i + 1));
    let open = |p: &std::path::Path| saferead::open_regular(p, saferead::NOT_REGULAR);
    let loaded = match crate::vendor_manifest::load_in_place(path.map(String::as_str), &open) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("hemostat fw block: DID NOT RUN — {}", h(&e));
            return crate::EXIT_FAILED;
        }
    };
    let manifest = loaded.as_ref();
    let mpath = path.cloned().or_else(|| std::env::var(crate::vendor_manifest::MANIFEST_ENV).ok()).unwrap_or_default();
    let given = args.iter().position(|a| a == "--meta").and_then(|i| args.get(i + 1)).map(String::as_str);
    let meta = manifest.and_then(|m| {
        crate::vendor_manifest::load_meta_in_place(&crate::vendor_manifest::meta_path_for(&mpath, given), m, &open).ok()
    });
    let mut sys = tools::System::new(manifest).with_meta(meta.as_ref());
    let _ = tools::renice_self(&mut sys, 10);
    let (id, _) = match crate::identity::gather_identity_with(&mut sys) {
        Ok(x) => x,
        Err(e) => {
            eprintln!("hemostat fw block: cannot read entropy for the identity: {e}");
            return crate::EXIT_FAILED;
        }
    };
    let engagement = std::env::var("HEMOSTAT_ENGAGEMENT_ID").ok().and_then(|e| crate::identity::parse_hex16(&e));
    let config = saferead::read_bytes(std::path::Path::new(configxml::CONFIG_PATH), configxml::MAX_BYTES)
        .map_err(|e| e.to_string())
        .and_then(|b| configxml::parse(&b).map_err(|e| e.to_string()));
    let inc = hemostat_enforce_pf::preflight::hash_incs(std::path::Path::new("/"));
    let resolv = saferead::read_text(std::path::Path::new("/etc/resolv.conf")).map_err(|e| e.to_string());
    let ssh = std::env::var("SSH_CONNECTION").ok();
    let operand = hemostat_enforce_pf::operand(
        hemostat_buildinfo::ActionClass::PerimeterBlock,
        &id.host,
        asked.enrolled.alias,
        &asked.cidr,
    );
    let (policy, (ticket, nonce)) = match now_secs() {
        Ok(now) => (
            load_policy(engagement, &id.host, now),
            load_ticket_as(hemostat_buildinfo::ActionClass::PerimeterBlock, engagement, &id.host, &operand, now, |n| !spent(n)),
        ),
        Err(why) => (Policy::Refused(why.clone()), (hemostat_broker::perimeter::Ticket::Refused(why), None)),
    };
    let auth = hemostat_enforce_pf::Authority {
        profile: crate::authz::current_profile(),
        built: hemostat_modules::noop::PerimeterBlock::compiled_out().is_none(),
        policy,
        ticket,
    };
    let d = hemostat_enforce_pf::dry_run(
        &mut sys,
        id.host,
        asked.cidr,
        &asked.enrolled,
        &config,
        &inc,
        manifest.map(hemostat_evcrypto::manifest::Verified::manifest),
        &resolv,
        ssh.as_deref(),
        &auth,
    );
    if !asked.dry {
        let ctx = crate::freebsd_contain::Armed {
            asked: &asked,
            host: id.host,
            nonce,
            manifest: mpath,
            meta: given.map(str::to_string),
        };
        return crate::freebsd_contain::arm(&mut sys, &ctx, &d, &auth, json);
    }
    if json {
        jprintln!("{}", render_json(&d, &id.host));
    } else {
        print!("{}", render(&d, &id.host));
    }
    exit_code(&d)
}
