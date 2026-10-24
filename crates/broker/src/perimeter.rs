use hemostat_buildinfo::ActionClass;
use hs_core::mode::{Mode, Profile};

use crate::{class_code, refused_under_ot, Origin};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {

    Mode,

    BuildStatus,

    Profile,

    Scope,

    Origin,

    Protect,

    Bulk,

    Ticket,

    Evidence,
}

impl Stage {

    pub const ORDER: [Stage; 9] = [
        Stage::Mode,
        Stage::BuildStatus,
        Stage::Profile,
        Stage::Scope,
        Stage::Origin,
        Stage::Protect,
        Stage::Bulk,
        Stage::Ticket,
        Stage::Evidence,
    ];

    pub const fn token(self) -> &'static str {
        match self {
            Stage::Mode => "mode",
            Stage::BuildStatus => "build-status",
            Stage::Profile => "profile",
            Stage::Scope => "policy-scope",
            Stage::Origin => "origin",
            Stage::Protect => "protect-set",
            Stage::Bulk => "bulk",
            Stage::Ticket => "ticket-v2",
            Stage::Evidence => "evidence",
        }
    }
}

pub const MAX_ENTRIES: usize = 8;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {

    pub class: ActionClass,

    pub origin: Origin,

    pub host: [u8; 32],

    pub operand: [u8; 32],

    pub summary: String,

    pub entries: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signed {

    pub allowed: Vec<u8>,

    pub scope: Vec<[u8; 32]>,

    pub profile: Profile,

    pub bulk_threshold: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Policy {

    None,

    Refused(String),

    Verified(Signed),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Protect {

    Clear,

    Refused(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ticket {

    None,

    Refused(String),

    Verified,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Evidence {

    Sealed,

    NotYet,
}

#[derive(Debug, Clone, Copy)]
pub struct Inputs<'a> {

    pub mode: Mode,

    pub profile: Profile,

    pub built: bool,

    pub policy: &'a Policy,

    pub protect: &'a Protect,

    pub ticket: &'a Ticket,

    pub evidence: Evidence,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Allowed {
    class: ActionClass,
    host: [u8; 32],
    operand: [u8; 32],
}

impl Allowed {

    pub fn class(&self) -> ActionClass {
        self.class
    }

    pub fn host(&self) -> [u8; 32] {
        self.host
    }

    pub fn operand(&self) -> [u8; 32] {
        self.operand
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Decision {

    Refused {

        stage: Stage,

        reason: String,
    },

    DryRun {

        passed: Vec<(Stage, String)>,
    },

    Allow(Allowed),
}

fn refuse(stage: Stage, reason: impl Into<String>) -> Decision {
    Decision::Refused { stage, reason: reason.into() }
}

pub const fn is_perimeter(class: ActionClass) -> bool {
    matches!(class, ActionClass::PerimeterBlock | ActionClass::PerimeterStateKill)
}

pub fn decide(req: &Request, i: &Inputs<'_>) -> Decision {
    let mut passed: Vec<(Stage, String)> = Vec::new();
    if !is_perimeter(req.class) {
        return refuse(
            Stage::BuildStatus,
            format!("`{}` is not a perimeter class; host classes go through the host pipeline", req.class),
        );
    }

    match i.mode {
        Mode::Observe => {
            return refuse(
                Stage::Mode,
                format!("the agent is in observe mode; `{}` was not attempted", req.class),
            )
        }
        Mode::DryRun => passed.push((Stage::Mode, "dry run: every stage runs, nothing is applied".into())),
        Mode::Armed => passed.push((Stage::Mode, "armed".into())),
    }

    if !i.built {
        return refuse(
            Stage::BuildStatus,
            format!(
                "{} is NOT-BUILT in this variant: its module was left out of the build, so no \
                 mode or authorisation can reach it",
                req.class
            ),
        );
    }
    passed.push((Stage::BuildStatus, format!("{} is in this image", req.class)));

    let profile = match i.policy {
        Policy::Verified(s) => i.profile.tighten(s.profile),
        Policy::None | Policy::Refused(_) => i.profile,
    };
    if profile == Profile::Ot && refused_under_ot(req.class) {
        return refuse(
            Stage::Profile,
            format!(
                "`{}` is refused under the ot profile: it cuts every matching connection through \
                 the firewall, a plant's included, and cannot be undone",
                req.class
            ),
        );
    }
    passed.push((Stage::Profile, format!("{} profile", if profile == Profile::Ot { "ot" } else { "it" })));

    let threshold = match i.policy {
        Policy::None => {
            return refuse(
                Stage::Scope,
                "no signed engagement policy was supplied. A perimeter action needs one that \
                 permits the class and names this firewall's host id in its scope",
            )
        }
        Policy::Refused(why) => return refuse(Stage::Scope, format!("the engagement policy was refused: {why}")),
        Policy::Verified(s) => {
            if !s.allowed.contains(&class_code(req.class)) {
                return refuse(
                    Stage::Scope,
                    format!("the signed engagement policy does not permit `{}`", req.class),
                );
            }
            if s.scope.is_empty() {
                return refuse(
                    Stage::Scope,
                    "the signed policy's scope is empty, which means every host. That is enough \
                     for a host verb and not for the edge: the scope must list this firewall's \
                     host id",
                );
            }
            if !s.scope.contains(&req.host) {
                return refuse(
                    Stage::Scope,
                    "this firewall's host id is not in the signed policy's scope",
                );
            }
            s.bulk_threshold.min(MAX_ENTRIES)
        }
    };
    passed.push((Stage::Scope, "signed policy permits the class and lists this host id".into()));

    if let Origin::Rule { id } = &req.origin {
        return refuse(
            Stage::Origin,
            format!("rule `{id}` originated this. No rule fires a perimeter action; a human does"),
        );
    }
    passed.push((Stage::Origin, "operator".into()));

    if let Protect::Refused(why) = i.protect {
        return refuse(Stage::Protect, why.clone());
    }
    passed.push((Stage::Protect, "covers no management peer, interface, VIP, gateway, DNS server or enrolled range".into()));

    if req.entries > threshold {
        return refuse(
            Stage::Bulk,
            format!(
                "the alias would hold {} HEMOSTAT entries, over the {threshold} one operator may \
                 add. More is dual control, which is not built, so it is refused",
                req.entries
            ),
        );
    }
    passed.push((Stage::Bulk, format!("{} of {threshold} entries", req.entries)));

    match i.ticket {
        Ticket::None => {
            return refuse(
                Stage::Ticket,
                "no responder ticket was presented. A perimeter action needs a v2 ticket bound \
                 to this alias, direction and CIDR",
            )
        }
        Ticket::Refused(why) => return refuse(Stage::Ticket, format!("the presented ticket was refused: {why}")),
        Ticket::Verified => passed.push((Stage::Ticket, "v2, bound to this operand; not spent".into())),
    }

    match (i.mode, i.evidence) {
        (Mode::Armed, Evidence::NotYet) => {
            return refuse(
                Stage::Evidence,
                "config.xml and the /cf/conf/backup digests were not sealed, and an armed write \
                 comes after them (RFC-002 §3)",
            )
        }
        (_, Evidence::Sealed) => passed.push((Stage::Evidence, "sealed".into())),
        (_, Evidence::NotYet) => passed.push((
            Stage::Evidence,
            "would seal config.xml and the /cf/conf/backup digests before any write".into(),
        )),
    }

    match i.mode {
        Mode::Armed => Decision::Allow(Allowed { class: req.class, host: req.host, operand: req.operand }),
        _ => Decision::DryRun { passed },
    }
}
