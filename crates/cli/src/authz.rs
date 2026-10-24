#[cfg(target_os = "linux")]
use crate::{EXIT_FAILED, EXIT_OK, EXIT_USAGE};
#[cfg(target_os = "linux")]
use crate::identity::{gather_identity, parse_hex16, parse_hex32, rand16};
#[cfg(target_os = "linux")]
use crate::render::{hex16, hex32};
#[cfg(target_os = "linux")]
use crate::EXIT_AUTHZ;
#[cfg(target_os = "linux")]
use crate::{EXIT_DRYRUN, EXIT_NOT_BUILT, EXIT_POLICY};

#[cfg(all(target_os = "linux", feature = "mod-enf-persistence"))]
pub(crate) fn class_of_action(a: &hemostat_enforce_linux::RemovalAction) -> hemostat_buildinfo::ActionClass {
    use hemostat_buildinfo::ActionClass as A;
    use hemostat_enforce_linux::RemovalAction as R;
    match a {
        R::KillProcess { .. } => A::Kill,
        R::SuspendProcess { .. } => A::Suspend,

        R::UnloadModule { .. }
        | R::MaskService { .. }
        | R::StopAndRemoveUnit { .. }
        | R::DisablePersistence { .. }
        | R::RemoveLdPreload { .. }
        | R::StripLine { .. }
        | R::RemoveAnchor { .. } => A::PersistenceNeutralize,
        R::QuarantineFile { .. } => A::Quarantine,

        R::StartService { .. } => A::ServiceStart,
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn exit_for_refusal(stage: hemostat_broker::Stage) -> u8 {
    use hemostat_broker::Stage;
    match stage {
        Stage::BuildStatus => EXIT_NOT_BUILT,
        Stage::Authorization => EXIT_AUTHZ,
        Stage::Mode => EXIT_DRYRUN,

        Stage::Profile | Stage::Suppression | Stage::Policy | Stage::Bulk | Stage::Evidence => {
            EXIT_POLICY
        }
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn broker_class(
    class: hemostat_buildinfo::ActionClass,
    reboot_gated: bool,
    armed: bool,
    authority: hemostat_broker::Authority,
    sanction: &hemostat_broker::Sanction,
    targets: usize,
) -> Result<Vec<hemostat_broker::Unchecked>, (hemostat_broker::Stage, String)> {
    use hemostat_broker::{decide_full, Decision, Origin, Request};
    use hs_core::mode::Mode;

    let built =
        !matches!(hemostat_modules::executor_for(class), hemostat_modules::Executor::NotInVariant);
    let req =
        Request { class, summary: format!("{class}"), origin: Origin::Operator, targets, reboot_gated };
    let mode = if armed { Mode::Armed } else { Mode::DryRun };
    match decide_full(&req, mode, current_profile(), built, authority, sanction) {
        Decision::Refused { stage, reason, instead } => {
            let alt = instead.map_or_else(String::new, |a| format!(" Consider `{a}`."));

            let variant = if stage == hemostat_broker::Stage::BuildStatus {
                format!(" (this is the {} variant)", crate::MANIFEST.variant)
            } else {
                String::new()
            };
            Err((stage, format!("refused at the {} stage: {reason}{variant}.{alt}", stage.token())))
        }
        Decision::Planned { unchecked } | Decision::Proceed { unchecked } => Ok(unchecked),
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn armed_gate(
    verb: &str,
    class: hemostat_buildinfo::ActionClass,
    armed: bool,
    targets: usize,
) -> Result<Option<PendingTicket>, u8> {
    gate(verb, class, false, armed, targets)
}

#[cfg(target_os = "linux")]
pub(crate) fn armed_gate_at_boot(
    verb: &str,
    class: hemostat_buildinfo::ActionClass,
    armed: bool,
    targets: usize,
) -> Result<Option<PendingTicket>, u8> {
    gate(verb, class, true, armed, targets)
}

#[cfg(target_os = "linux")]
fn gate(
    verb: &str,
    class: hemostat_buildinfo::ActionClass,
    reboot_gated: bool,
    armed: bool,
    targets: usize,
) -> Result<Option<PendingTicket>, u8> {
    let ticket_class = hemostat_buildinfo::ActionClass::ALL
        .iter()
        .position(|a| *a == class)
        .and_then(|i| u8::try_from(i).ok())
        .unwrap_or(hemostat_evcrypto::ticket::NO_CLASS);
    let (authority, ticket) =
        presented_authority(hemostat_evcrypto::ticket::Op::Action, ticket_class).map_err(|why| {
            eprintln!("hemostat {verb}: {why}");
            EXIT_AUTHZ
        })?;
    let sanction = loaded_sanction().map_err(|why| {
        eprintln!("hemostat {verb}: {why}");
        EXIT_POLICY
    })?;
    match broker_class(class, reboot_gated, armed, authority, &sanction, targets) {
        Err((stage, why)) => {
            eprintln!("hemostat {verb}: {why}");
            Err(exit_for_refusal(stage))
        }
        Ok(gaps) => {
            for g in gaps {
                eprintln!("  broker stage NOT performed: {} — {}", g.stage.token(), g.why);
            }
            Ok(ticket)
        }
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn spend_armed(verb: &str, armed: bool, ticket: Option<PendingTicket>) -> Result<(), u8> {
    match ticket {
        Some(t) if armed => t.spend().map_err(|why| {
            eprintln!("hemostat {verb}: {why}");
            why.exit_code()
        }),
        _ => Ok(()),
    }
}

#[cfg(all(target_os = "linux", feature = "mod-enf-persistence"))]

pub(crate) fn broker_admits(
    action: &hemostat_enforce_linux::RemovalAction,
    armed: bool,
    authority: hemostat_broker::Authority,
    sanction: &hemostat_broker::Sanction,
    targets: usize,
) -> Result<Vec<hemostat_broker::Unchecked>, (hemostat_broker::Stage, String)> {

    broker_class(class_of_action(action), false, armed, authority, sanction, targets)
}

#[cfg(target_os = "linux")]
pub(crate) const POLICY_ENV: &str = "HEMOSTAT_POLICY";

#[cfg(target_os = "linux")]
pub(crate) const EPOCH_FLOOR: &str = "/var/lib/hemostat/policy-epoch";

#[cfg(target_os = "linux")]
pub(crate) fn epoch_secs(t: std::time::SystemTime) -> Result<i64, String> {
    let d = t.duration_since(std::time::UNIX_EPOCH).map_err(|_| {
        "this host's clock reads as before 1970, so no expiry on a ticket or a policy can be \
         checked against it. Refusing rather than treating every one of them as unexpired — \
         set the clock, then retry"
            .to_string()
    })?;

    Ok(i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

#[cfg(target_os = "linux")]
fn now_secs() -> Result<i64, String> {
    epoch_secs(std::time::SystemTime::now())
}

#[cfg(target_os = "linux")]
const MAX_AUTHORITY_BYTES: u64 = 1024 * 1024;

#[cfg(target_os = "linux")]
pub(crate) fn epoch_floor(path: &str) -> Result<u32, String> {
    match hemostat_sensor_linux::saferead::read_text(std::path::Path::new(path)) {
        Ok(s) => s.trim().parse().map_err(|_| {
            format!(
                "the epoch floor at {path} is not a number ({:?}). Refusing rather than \
                 treating it as zero, which would admit any previously superseded policy",
                s.trim().chars().take(40).collect::<String>()
            )
        }),

        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(0),
        Err(e) => Err(format!(
            "the epoch floor at {path} could not be read ({e}). Treating that as no floor \
             would accept a superseded policy, so the policy is refused instead — run with \
             access to the file, or point $HEMOSTAT_EPOCH_FLOOR somewhere readable"
        )),
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn loaded_sanction() -> Result<hemostat_broker::Sanction, String> {
    use hemostat_broker::Sanction;
    use hemostat_evcrypto::policy::verify;

    let Ok(path) = std::env::var(POLICY_ENV) else {
        return Ok(Sanction::None);
    };
    if path.trim().is_empty() {
        return Ok(Sanction::None);
    }

    let pinned = std::env::var("HEMOSTAT_ENGAGEMENT_PUBKEY")
        .ok()
        .as_deref()
        .and_then(parse_hex32)
        .ok_or_else(|| {
            format!(
                "a policy was supplied at {path}, but $HEMOSTAT_ENGAGEMENT_PUBKEY is not set to \
                 a 64-hex engagement root key. A policy verified against no pinned key is not a \
                 verified policy"
            )
        })?;

    let blob = hemostat_sensor_linux::saferead::read_bytes(std::path::Path::new(&path), MAX_AUTHORITY_BYTES)
        .map_err(|e| format!("cannot read the policy at {path}: {e}"))?;

    let len = blob
        .get(..4)
        .and_then(|b| <[u8; 4]>::try_from(b).ok())
        .map(|b| u32::from_be_bytes(b) as usize)
        .ok_or_else(|| format!("the policy at {path} is too short to hold its own length"))?;
    let body = blob
        .get(4..4 + len)
        .ok_or_else(|| format!("the policy at {path} claims {len} bytes it does not have"))?;
    let cose = blob.get(4 + len..).unwrap_or_default();

    let id = gather_identity().map_err(|e| format!("cannot establish identity: {e}"))?;
    let now = now_secs()?;
    let floor_path =
        std::env::var("HEMOSTAT_EPOCH_FLOOR").unwrap_or_else(|_| EPOCH_FLOOR.to_string());
    let floor = epoch_floor(&floor_path)?;

    match verify(&pinned, body, cose, &id.engagement, &id.host, now, floor) {
        Ok(p) => {

            if p.epoch > floor {
                if let Some(d) = std::path::Path::new(&floor_path).parent() {
                    if !d.as_os_str().is_empty() {
                        let _ = std::fs::create_dir_all(d);
                    }
                }
                if std::fs::write(&floor_path, format!("{}\n", p.epoch)).is_err() {
                    return Err(format!(
                        "the policy at epoch {} verified, but the epoch floor could not be \
                         written to {floor_path}. Accepting it without recording it would \
                         leave the older, wider policy replayable",
                        p.epoch
                    ));
                }
            }

            let gap = policy_build_gap(&p.allowed_actions);
            if !gap.is_empty() {
                eprintln!(
                    "hemostat: the engagement policy permits {} class(es) this build does not \
                     contain (policy_build_gap): {}. Those actions will be refused as NOT-BUILT \
                     here; a different variant carries them",
                    gap.len(),
                    gap.iter().map(ToString::to_string).collect::<Vec<_>>().join(", ")
                );
            }
            Ok(Sanction::Verified {
                allowed: p.allowed_actions,
                bulk_threshold: usize::from(p.bulk_threshold),
                profile: match p.profile {
                    hemostat_evcrypto::policy::PolicyProfile::It => hs_core::mode::Profile::It,
                    hemostat_evcrypto::policy::PolicyProfile::Ot => hs_core::mode::Profile::Ot,
                },
            })
        }
        Err(r) => Err(format!("the supplied engagement policy was refused: {}", r.message())),
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn policy_build_gap(allowed: &[u8]) -> Vec<hemostat_buildinfo::ActionClass> {
    hemostat_buildinfo::ActionClass::ALL
        .iter()
        .copied()
        .filter(|c| allowed.contains(&hemostat_broker::class_code(*c)))
        .filter(|c| {
            matches!(hemostat_modules::executor_for(*c), hemostat_modules::Executor::NotInVariant)
        })
        .collect()
}

#[cfg(target_os = "linux")]
pub(crate) const TICKET_ENV: &str = "HEMOSTAT_TICKET";

#[cfg(target_os = "linux")]
pub(crate) const NONCE_LOG: &str = "/var/lib/hemostat/used-tickets";

#[cfg(target_os = "linux")]
fn nonce_log() -> String {
    std::env::var("HEMOSTAT_NONCE_LOG").unwrap_or_else(|_| NONCE_LOG.to_string())
}

#[cfg(target_os = "linux")]
pub(crate) fn nonce_already_spent(nonce: &[u8; 16]) -> bool {
    let log = nonce_log();
    let hex: String = nonce.iter().map(|b| format!("{b:02x}")).collect();
    if std::path::Path::new(&format!("{log}.spent")).join(&hex).exists() {
        return true;
    }
    hemostat_sensor_linux::saferead::read_scan_target(std::path::Path::new(&log))
        .is_some_and(|seen| seen.lines().any(|l| l.trim() == hex))
}

#[cfg(target_os = "linux")]
pub(crate) fn spend_nonce(nonce: &[u8; 16]) -> Result<(), SpendError> {
    spend_nonce_at(&nonce_log(), nonce)
}

#[cfg(target_os = "linux")]
fn spend_nonce_at(log: &str, nonce: &[u8; 16]) -> Result<(), SpendError> {
    let hex: String = nonce.iter().map(|b| format!("{b:02x}")).collect();
    let unrecordable = |path: &std::path::Path, err| SpendError::Unrecordable { path: path.display().to_string(), err };
    if let Some(d) = std::path::Path::new(log).parent() {
        if !d.as_os_str().is_empty() {
            std::fs::create_dir_all(d).map_err(|e| unrecordable(d, e))?;
        }
    }

    let spent = format!("{log}.spent");
    std::fs::create_dir_all(&spent).map_err(|e| unrecordable(std::path::Path::new(&spent), e))?;
    let marker = std::path::Path::new(&spent).join(&hex);
    match std::fs::OpenOptions::new().create_new(true).write(true).open(&marker) {
        Ok(_) => {}

        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => return Err(SpendError::AlreadySpent),

        Err(e) => return Err(unrecordable(&marker, e)),
    }

    use std::io::Write as _;
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(log) {
        let _ = writeln!(f, "{hex}");
    }
    Ok(())
}

#[cfg(target_os = "linux")]
#[derive(Debug)]
pub(crate) enum SpendError {

    AlreadySpent,

    Unrecordable { path: String, err: std::io::Error },
}

#[cfg(target_os = "linux")]
impl SpendError {

    pub(crate) fn exit_code(&self) -> u8 {
        match self {
            SpendError::AlreadySpent => EXIT_AUTHZ,
            SpendError::Unrecordable { .. } => EXIT_FAILED,
        }
    }
}

#[cfg(target_os = "linux")]
impl std::fmt::Display for SpendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SpendError::AlreadySpent => f.write_str(
                "the presented ticket was spent by another run between verification and use; \
                 nothing was done",
            ),
            SpendError::Unrecordable { path, err } => write!(
                f,
                "the presented ticket verified, but spending it could not be recorded at {path} \
                 ({err}), and a single-use ticket that cannot be recorded as used is not \
                 single-use, so nothing was done. The ticket was NOT consumed: point \
                 $HEMOSTAT_NONCE_LOG at a file on writable storage and present it again"
            ),
        }
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn presented_authority(
    op: hemostat_evcrypto::ticket::Op,
    class: u8,
) -> Result<(hemostat_broker::Authority, Option<PendingTicket>), String> {
    use hemostat_broker::Authority;
    use hemostat_evcrypto::ticket::{verify, Asked, CLAIMS_LEN};

    let Ok(path) = std::env::var(TICKET_ENV) else {
        return Ok((Authority::None, None));
    };
    if path.trim().is_empty() {
        return Ok((Authority::None, None));
    }

    let pinned = std::env::var("HEMOSTAT_RESPONDER_PUBKEY")
        .ok()
        .as_deref()
        .and_then(parse_hex32)
        .ok_or_else(|| {
            format!(
                "a ticket was presented at {path}, but $HEMOSTAT_RESPONDER_PUBKEY is not set to \
                 a 64-hex responder key. A ticket verified against no pinned key is not a \
                 verified ticket"
            )
        })?;

    if std::env::var("HEMOSTAT_ENGAGEMENT_ID").is_err() {
        return Err(format!(
            "a ticket was presented at {path}, but $HEMOSTAT_ENGAGEMENT_ID is not set. This \
             agent generates a fresh engagement id on every run when none is pinned, so no \
             ticket can be bound to it. Set the engagement id the ticket was minted against"
        ));
    }

    let blob = hemostat_sensor_linux::saferead::read_bytes(std::path::Path::new(&path), MAX_AUTHORITY_BYTES)
        .map_err(|e| format!("cannot read the ticket at {path}: {e}"))?;
    let (claims, cose) = blob
        .split_at_checked(CLAIMS_LEN)
        .ok_or_else(|| format!("the ticket at {path} is too short to hold its claims"))?;

    let id = gather_identity().map_err(|e| format!("cannot establish identity: {e}"))?;
    let asked = Asked {
        op,
        class,
        engagement: id.engagement,
        host: id.host,
    };
    let now = now_secs()?;

    let mut presented = None;
    match verify(&pinned, claims, cose, &asked, now, |n| {
        presented = Some(*n);
        !nonce_already_spent(n)
    }) {
        Ok(_) => Ok((Authority::Verified, presented.map(|nonce| PendingTicket { nonce }))),
        Err(r) => Err(format!("the presented ticket was refused: {}", r.message())),
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn reversal_authority(
    op: hemostat_evcrypto::ticket::Op,
    armed: bool,
) -> Result<Option<&'static str>, (u8, String)> {
    let (authority, ticket) =
        presented_authority(op, hemostat_evcrypto::ticket::NO_CLASS).map_err(|why| (EXIT_AUTHZ, why))?;
    if authority == hemostat_broker::Authority::None {
        return Ok(Some(
            "no responder ticket was presented, so this was not authorised against a pinned \
             responder key — the authorization stage was not performed",
        ));
    }
    if armed {
        if let Some(t) = ticket {
            t.spend().map_err(|e| (e.exit_code(), e.to_string()))?;
        }
    }
    Ok(None)
}

#[cfg(target_os = "linux")]
#[must_use = "a verified ticket must be spent before the action it authorises"]
pub(crate) struct PendingTicket {
    nonce: [u8; 16],
}

#[cfg(target_os = "linux")]
impl PendingTicket {

    pub(crate) fn spend(self) -> Result<(), SpendError> {
        spend_nonce(&self.nonce)
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn mint_ticket(args: &[String]) -> u8 {
    use hemostat_evcrypto::ticket::{Claims, Op, ResponderKey, NO_CLASS, VERSION};

    let arg = |name: &str| {
        args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).map(String::as_str)
    };

    let Some(seed) = std::env::var("HEMOSTAT_RESPONDER_KEY").ok().as_deref().and_then(parse_hex32)
    else {
        eprintln!(
            "hemostat ticket: set $HEMOSTAT_RESPONDER_KEY to the responder signing seed \
             (64 hex chars). It never goes to the host — only the ticket does."
        );
        return EXIT_USAGE;
    };
    let key = ResponderKey::from_seed(seed);

    let op = match arg("--op").unwrap_or("action") {
        "action" => Op::Action,
        "lift" => Op::Lift,
        "uninstall" => Op::Uninstall,
        "undo" => Op::Undo,
        "export" => Op::Export,
        other => {
            eprintln!("hemostat ticket: unknown --op {other:?}");
            return EXIT_USAGE;
        }
    };
    let class = arg("--class")
        .and_then(|c| {
            hemostat_buildinfo::ActionClass::ALL
                .iter()
                .position(|a| a.name().eq_ignore_ascii_case(c))
                .and_then(|i| u8::try_from(i).ok())
        })
        .unwrap_or(NO_CLASS);
    if op == Op::Action && class == NO_CLASS {
        eprintln!("hemostat ticket: --op action needs a --class naming one action class");
        return EXIT_USAGE;
    }

    let perimeter = op == Op::Action && hemostat_evcrypto::ticket::requires_v2(class);
    let operand_args = match (perimeter, arg("--alias"), arg("--cidr")) {
        (true, Some(a), Some(c)) => {
            let Some(dir) = alias_dir(a) else {
                eprintln!("hemostat ticket: --alias must be HEMOSTAT_OUT or HEMOSTAT_IN, the two aliases HEMOSTAT may act on");
                return EXIT_USAGE;
            };
            match hs_core::cidr::Cidr::parse(c) {
                Ok(cidr) => Some((a, dir, cidr)),
                Err(e) => {
                    eprintln!("hemostat ticket: --cidr refused: {e}");
                    return EXIT_USAGE;
                }
            }
        }
        (true, _, _) => {
            eprintln!(
                "hemostat ticket: a perimeter class takes a v2 ticket: --alias HEMOSTAT_OUT|HEMOSTAT_IN \
                 and --cidr NET/LEN name exactly what it may block"
            );
            return EXIT_USAGE;
        }
        (false, None, None) => None,
        (false, _, _) => {
            eprintln!("hemostat ticket: --alias and --cidr are for the perimeter classes only");
            return EXIT_USAGE;
        }
    };

    let Some(engagement) = arg("--engagement").and_then(parse_hex16) else {
        eprintln!("hemostat ticket: --engagement needs 32 hex chars (the store's engagement id)");
        return EXIT_USAGE;
    };
    let Some(host) = arg("--host").and_then(parse_hex32) else {
        eprintln!(
            "hemostat ticket: --host needs 64 hex chars (the target's host id, which \
             `hemostat verify` prints). The agent id is generated fresh every run, so a ticket \
             bound to it could never verify; the host id is the stable one."
        );
        return EXIT_USAGE;
    };
    let ttl: i64 = arg("--ttl").and_then(|t| t.parse().ok()).unwrap_or(300);

    let nonce = match rand16() {
        Ok(n) => n,
        Err(e) => {
            eprintln!("hemostat ticket: cannot read entropy for the nonce: {e}");
            return EXIT_FAILED;
        }
    };

    let now = match now_secs() {
        Ok(n) => n,
        Err(why) => {
            eprintln!("hemostat ticket: {why}");
            return EXIT_FAILED;
        }
    };

    let claims = Claims {
        version: VERSION,
        op,
        class,
        engagement,
        host,
        nonce,
        not_after: now.saturating_add(ttl),
    };

    let (blob, bound) = if let Some((alias, dir, cidr)) = &operand_args {
        use hemostat_evcrypto::ticket::{operand, ClaimsV2, VERSION_V2};
        let rendered = cidr.to_string();
        let v2 = ClaimsV2 {
            claims: Claims { version: VERSION_V2, ..claims },
            operand: operand(class, &host, alias, *dir, &rendered),
        };
        let mut b = v2.encode().to_vec();
        b.extend_from_slice(&key.mint_v2(&v2));
        (b, Some((alias.to_string(), rendered, v2.operand)))
    } else {
        let mut b = claims.encode().to_vec();
        b.extend_from_slice(&key.mint(&claims));
        (b, None)
    };
    let out = arg("--out").unwrap_or("hemostat-ticket.bin");
    if let Err(e) = std::fs::write(out, &blob) {
        eprintln!("hemostat ticket: cannot write {out}: {e}");
        return EXIT_FAILED;
    }
    println!("ticket written to {out}");
    println!("  op         {}", op.token());
    println!("  valid for  {ttl}s (until epoch {})", claims.not_after);
    println!("  responder  {}", hex32(&key.public_bytes()));
    if let Some((alias, cidr, op)) = &bound {
        let what = if class == hemostat_broker::class_code(hemostat_buildinfo::ActionClass::PerimeterStateKill) {
            let dir = if alias_dir(alias) == Some(hemostat_evcrypto::ticket::Dir::In) { "from" } else { "to" };
            format!("kill every state {dir} {cidr} ({alias})")
        } else {
            format!("block {cidr} in {alias}")
        };
        println!("  version    2: {what} on host {}", hex32(&host));
        println!("  operand    {}", hex32(op));
    }
    println!();

    println!("On the host, pin the key and the engagement, and present the ticket:");
    println!("  HEMOSTAT_RESPONDER_PUBKEY={} \\", hex32(&key.public_bytes()));
    println!("  HEMOSTAT_ENGAGEMENT_ID={} \\", hex16(&engagement));
    match &bound {
        Some((alias, cidr, _)) if class == hemostat_broker::class_code(hemostat_buildinfo::ActionClass::PerimeterStateKill) => {
            println!("  HEMOSTAT_TICKET=/path/to/{out} hemostat fw statekill {cidr} --alias {alias} --dry-run")
        }
        Some((alias, cidr, _)) => println!("  HEMOSTAT_TICKET=/path/to/{out} hemostat fw block {cidr} --alias {alias} --tracker N --dry-run"),
        None => println!("  HEMOSTAT_TICKET=/path/to/{out} hemostat console"),
    }
    if op == Op::Export {
        println!();
        println!("NOTE: no verb in this build checks an export ticket yet; `export` runs without one.");
    }
    EXIT_OK
}

#[cfg(target_os = "linux")]
pub(crate) fn alias_dir(name: &str) -> Option<hemostat_evcrypto::ticket::Dir> {
    use hemostat_evcrypto::ticket::Dir;
    match name {
        "HEMOSTAT_OUT" => Some(Dir::Out),
        "HEMOSTAT_IN" => Some(Dir::In),
        _ => None,
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn mint_policy(args: &[String]) -> u8 {
    use hemostat_evcrypto::policy::{Policy, PolicyProfile, RootKey, VERSION};

    let arg = |name: &str| {
        args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).map(String::as_str)
    };
    let Some(seed) = std::env::var("HEMOSTAT_ENGAGEMENT_KEY").ok().as_deref().and_then(parse_hex32) else {
        eprintln!(
            "hemostat policy: set $HEMOSTAT_ENGAGEMENT_KEY to the engagement root's signing seed \
             (64 hex chars). It never goes to the host — only the policy does."
        );
        return EXIT_USAGE;
    };
    let key = RootKey::from_seed(seed);
    let Some(engagement) = arg("--engagement").and_then(parse_hex16) else {
        eprintln!("hemostat policy: --engagement needs 32 hex chars");
        return EXIT_USAGE;
    };
    let Some(epoch) = arg("--epoch").and_then(|e| e.parse::<u32>().ok()) else {
        eprintln!("hemostat policy: --epoch needs a number: the anti-rollback counter, higher than any policy before it");
        return EXIT_USAGE;
    };
    let mut allowed = Vec::new();
    for name in arg("--allow").unwrap_or("").split(',').filter(|s| !s.is_empty()) {
        match hemostat_buildinfo::ActionClass::ALL.iter().find(|a| a.name().eq_ignore_ascii_case(name)) {
            Some(c) => allowed.push(hemostat_broker::class_code(*c)),
            None => {
                eprintln!("hemostat policy: unknown class {}", crate::render::h(name));
                return EXIT_USAGE;
            }
        }
    }
    if allowed.is_empty() {
        eprintln!("hemostat policy: --allow needs at least one action class");
        return EXIT_USAGE;
    }
    let mut scope = Vec::new();
    for h in arg("--scope").unwrap_or("").split(',').filter(|s| !s.is_empty()) {
        match parse_hex32(h) {
            Some(x) => scope.push(x),
            None => {
                eprintln!("hemostat policy: --scope takes 64-hex host ids, comma-separated");
                return EXIT_USAGE;
            }
        }
    }
    let profile = match arg("--profile").unwrap_or("it") {
        "it" => PolicyProfile::It,
        "ot" => PolicyProfile::Ot,
        other => {
            eprintln!("hemostat policy: --profile is it or ot, not {}", crate::render::h(other));
            return EXIT_USAGE;
        }
    };
    let Some(bulk) = arg("--bulk").map_or(Some(10), |b| b.parse::<u16>().ok()) else {
        eprintln!("hemostat policy: --bulk needs a number");
        return EXIT_USAGE;
    };
    let ttl: i64 = arg("--ttl").and_then(|t| t.parse().ok()).unwrap_or(3600);
    let now = match now_secs() {
        Ok(n) => n,
        Err(why) => {
            eprintln!("hemostat policy: {why}");
            return EXIT_FAILED;
        }
    };
    let mut policy = Policy {
        version: VERSION,
        epoch,
        profile,
        engagement,
        not_after: now.saturating_add(ttl),
        bulk_threshold: bulk,
        allowed_actions: allowed,
        scope,
    };

    policy.allowed_actions.sort_unstable();
    policy.allowed_actions.dedup();
    policy.scope.sort_unstable();
    policy.scope.dedup();
    let body = policy.encode();
    let cose = key.sign(&policy);
    let Ok(len) = u32::try_from(body.len()) else {
        eprintln!("hemostat policy: the policy is too large to frame");
        return EXIT_FAILED;
    };
    let mut blob = len.to_be_bytes().to_vec();
    blob.extend_from_slice(&body);
    blob.extend_from_slice(&cose);
    let out = arg("--out").unwrap_or("hemostat-policy.bin");
    if let Err(e) = std::fs::write(out, &blob) {
        eprintln!("hemostat policy: cannot write {out}: {e}");
        return EXIT_FAILED;
    }
    println!("policy written to {out}");
    println!("  epoch      {epoch}");
    println!("  valid for  {ttl}s (until epoch {})", policy.not_after);
    println!("  allows     {} class(es); scope {}", policy.allowed_actions.len(),
        if policy.scope.is_empty() { "every host".to_string() } else { format!("{} host id(s)", policy.scope.len()) });
    println!();
    println!("On the host, pin the root key and the engagement, and point at the policy:");
    println!("  HEMOSTAT_ENGAGEMENT_PUBKEY={} \\", hex32(&key.public_bytes()));
    println!("  HEMOSTAT_ENGAGEMENT_ID={} \\", hex16(&engagement));
    println!("  HEMOSTAT_POLICY=/path/to/{out}");
    EXIT_OK
}

#[cfg(any(target_os = "linux", target_os = "freebsd", all(target_os = "windows", feature = "mod-tui")))]
pub(crate) fn current_profile() -> hs_core::mode::Profile {
    use hs_core::mode::Profile;
    let raw = std::env::var("HEMOSTAT_PROFILE").unwrap_or_default();
    match profile_from_env(&raw) {
        Some(p) => p,
        None => {
            eprintln!(
                "hemostat: $HEMOSTAT_PROFILE is `{}`, which is not `it` or `ot` — running as \
                 IT. If this is a plant host, stop and set HEMOSTAT_PROFILE=ot.",
                crate::render::h(&raw)
            );
            Profile::It
        }
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn resource_profile(verb: &str) -> hs_core::mode::Profile {
    let policy = loaded_sanction();
    if let Err(why) = &policy {
        eprintln!(
            "hemostat {verb}: NOTE: {}; the memory priority follows OT rather than guess",
            crate::render::h(why)
        );
    }
    profile_under(current_profile(), &policy)
}

#[cfg(target_os = "linux")]
pub(crate) fn profile_under(
    env: hs_core::mode::Profile,
    policy: &Result<hemostat_broker::Sanction, String>,
) -> hs_core::mode::Profile {
    use hemostat_broker::Sanction;
    match policy {
        Ok(Sanction::Verified { profile, .. }) => env.tighten(*profile),
        Ok(Sanction::None) => env,
        Err(_) => hs_core::mode::Profile::Ot,
    }
}

#[cfg(any(target_os = "linux", target_os = "freebsd", all(target_os = "windows", feature = "mod-tui")))]
pub(crate) fn profile_from_env(raw: &str) -> Option<hs_core::mode::Profile> {
    use hs_core::mode::Profile;
    let v = raw.trim();
    if v.is_empty() {
        return Some(Profile::It);
    }
    if v.eq_ignore_ascii_case("ot") {
        return Some(Profile::Ot);
    }
    if v.eq_ignore_ascii_case("it") {
        return Some(Profile::It);
    }
    None
}
