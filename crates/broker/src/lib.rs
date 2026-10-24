#![forbid(unsafe_code)]

use hemostat_buildinfo::ActionClass;
use hs_core::mode::{Mode, Profile};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Origin {

    Operator,

    Rule {

        id: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {

    pub class: ActionClass,

    pub summary: String,

    pub origin: Origin,

    pub targets: usize,

    pub reboot_gated: bool,
}

pub mod allowlist;
pub mod perimeter;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {

    Mode,

    BuildStatus,

    Profile,

    Suppression,

    Policy,

    Authorization,

    Bulk,

    Evidence,
}

impl Stage {

    pub const fn token(self) -> &'static str {
        match self {
            Stage::Mode => "mode",
            Stage::BuildStatus => "build-status",
            Stage::Profile => "profile",
            Stage::Suppression => "suppression",
            Stage::Policy => "policy",
            Stage::Authorization => "authorization",
            Stage::Bulk => "bulk",
            Stage::Evidence => "evidence",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unchecked {

    pub stage: Stage,

    pub why: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {

    Refused {

        stage: Stage,

        reason: String,

        instead: Option<ActionClass>,
    },

    Planned {

        unchecked: Vec<Unchecked>,
    },

    Proceed {

        unchecked: Vec<Unchecked>,
    },
}

impl Decision {

    pub const fn proceeds(&self) -> bool {
        matches!(self, Decision::Proceed { .. })
    }

    pub fn unchecked(&self) -> &[Unchecked] {
        match self {
            Decision::Refused { .. } => &[],
            Decision::Planned { unchecked } | Decision::Proceed { unchecked } => unchecked,
        }
    }
}

pub const fn is_reverse(class: ActionClass) -> bool {
    matches!(class, ActionClass::Lift | ActionClass::Uninstall)
}

pub const fn refused_under_ot(class: ActionClass) -> bool {
    matches!(
        class,
        ActionClass::Kill
            | ActionClass::SessionKill
            | ActionClass::CredRotate
            | ActionClass::ExecBlock
            | ActionClass::IsolateInbound
            | ActionClass::Isolate
            | ActionClass::SidecarInstall
            | ActionClass::PerimeterStateKill
    )
}

pub const fn needs_ot_second_party(class: ActionClass) -> bool {
    matches!(
        class,
        ActionClass::Kill
            | ActionClass::Suspend
            | ActionClass::SessionKill
            | ActionClass::Isolate
            | ActionClass::PersistenceNeutralize
            | ActionClass::Quarantine
            | ActionClass::CredRotate
            | ActionClass::GroupDrop
            | ActionClass::AccountDisable
    )
}

pub const fn alternative_under(class: ActionClass, profile: Profile) -> Option<ActionClass> {
    match profile {
        Profile::Ot => None,
        Profile::It => alternative_to(class),
    }
}

pub const fn alternative_to(class: ActionClass) -> Option<ActionClass> {
    match class {

        ActionClass::Kill | ActionClass::SessionKill => Some(ActionClass::Suspend),
        _ => None,
    }
}

pub fn class_code(class: ActionClass) -> u8 {
    ActionClass::ALL
        .iter()
        .position(|a| *a == class)
        .and_then(|i| u8::try_from(i).ok())
        .unwrap_or(u8::MAX)
}

pub const BULK_THRESHOLD: usize = 10;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Authority {

    None,

    Verified,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Sanction {

    None,

    Verified {

        allowed: Vec<u8>,

        bulk_threshold: usize,

        profile: Profile,
    },
}

pub fn decide(req: &Request, mode: Mode, profile: Profile, built: bool) -> Decision {
    decide_with(req, mode, profile, built, Authority::None)
}

pub fn decide_full(
    req: &Request,
    mode: Mode,
    profile: Profile,
    built: bool,
    authority: Authority,
    sanction: &Sanction,
) -> Decision {
    decide_inner(req, mode, profile, built, authority, sanction, &allowlist::Allowlist::default())
}

pub fn decide_suppressed(
    req: &Request,
    mode: Mode,
    profile: Profile,
    built: bool,
    authority: Authority,
    sanction: &Sanction,
    allow: &allowlist::Allowlist,
) -> Decision {
    decide_inner(req, mode, profile, built, authority, sanction, allow)
}

pub fn decide_with(
    req: &Request,
    mode: Mode,
    profile: Profile,
    built: bool,
    authority: Authority,
) -> Decision {
    decide_inner(
        req,
        mode,
        profile,
        built,
        authority,
        &Sanction::None,
        &allowlist::Allowlist::default(),
    )
}

fn decide_inner(
    req: &Request,
    mode: Mode,
    profile: Profile,
    built: bool,
    authority: Authority,
    sanction: &Sanction,
    allow: &allowlist::Allowlist,
) -> Decision {

    let profile = match sanction {
        Sanction::Verified { profile: signed, .. } => profile.tighten(*signed),
        Sanction::None => profile,
    };

    if !built {
        return Decision::Refused {
            stage: Stage::BuildStatus,
            reason: format!(
                "{} is NOT-BUILT in this variant: its module was left out of the build, so \
                 no mode or authorisation can reach it",
                req.class
            ),
            instead: None,
        };
    }

    if !is_reverse(req.class) {
        match mode {
            Mode::Observe => {
                return Decision::Refused {
                    stage: Stage::Mode,
                    reason: format!(
                        "the agent is in observe mode, where every state-changing class is \
                         rejected. `{}` was not attempted",
                        req.class
                    ),
                    instead: None,
                }
            }
            Mode::DryRun | Mode::Armed => {}
        }
    }

    if profile == Profile::Ot && refused_under_ot(req.class) {
        return Decision::Refused {
            stage: Stage::Profile,
            reason: format!(
                "`{}` is refused outright under the ot profile: on a plant host a wedged or \
                 killed process has consequences this agent cannot see",
                req.class
            ),
            instead: alternative_under(req.class, profile),
        };
    }
    if profile == Profile::Ot && needs_ot_second_party(req.class) {
        return Decision::Refused {
            stage: Stage::Profile,
            reason: format!(
                "`{}` on an ot host needs dual control or an ot_override (design §16.2.4), and \
                 neither exists in this build — so it is refused rather than performed on one \
                 operator's say-so. Preserve the evidence and escalate instead (§16.2.5)",
                req.class
            ),
            instead: None,
        };
    }

    if profile == Profile::Ot && req.reboot_gated {
        return Decision::Refused {
            stage: Stage::Profile,
            reason: format!(
                "this `{}` takes effect only at the next boot, and reboot-gated hardening is \
                 refused under the ot profile (design §16.2.4): a plant host is not restarted \
                 on this tool's say-so, and what the change breaks would be found at a restart \
                 nobody here will see",
                req.class
            ),
            instead: None,
        };
    }

    let mut unchecked = Vec::new();
    match &req.origin {
        Origin::Operator => {}
        Origin::Rule { id } => {

            let covered = allow
                .judge(req.class, &req.summary, true)
                .map(|e| format!(" An allowlist entry also covers this target — {e}."))
                .unwrap_or_default();
            return Decision::Refused {
                stage: Stage::Suppression,
                reason: format!(
                    "rule `{id}` originated this action, and no rule may act on a host: every \
                     removal, network change and config change needs a human to arm it \
                     (`--arm`, or the console).{covered}"
                ),
                instead: None,
            };
        }
    }

    let threshold = match sanction {
        Sanction::Verified { allowed, bulk_threshold, .. } => {
            let code = class_code(req.class);
            if !allowed.contains(&code) {
                return Decision::Refused {
                    stage: Stage::Policy,
                    reason: format!(
                        "the signed engagement policy does not permit `{}`. This is not a \
                         failure and not an authorisation problem: the engagement never \
                         sanctioned this class",
                        req.class
                    ),
                    instead: alternative_under(req.class, profile),
                };
            }
            *bulk_threshold
        }
        Sanction::None => {
            unchecked.push(Unchecked {
                stage: Stage::Policy,
                why: "no signed engagement policy was loaded, so the class was not checked \
                      against allowed_actions, this host was not checked against scope, and no \
                      expiry or epoch floor was enforced",
            });
            BULK_THRESHOLD
        }
    };

    if req.targets > threshold {
        return Decision::Refused {
            stage: Stage::Bulk,
            reason: format!(
                "{} targets is over the bulk threshold of {threshold}, which promotes \
                 this to a dual-control action. Dual control is not implemented in this \
                 build, so it cannot be authorised — narrow the target set and act deliberately",
                req.targets
            ),
            instead: None,
        };
    }

    match authority {

        Authority::Verified => {}
        Authority::None => unchecked.push(Unchecked {
            stage: Stage::Authorization,
            why: "no responder ticket was presented, so nothing was verified against a pinned \
                  responder key. This action is authorised by whoever can run this binary",
        }),
    }

    if needs_evidence_first(req.class) {
        unchecked.push(Unchecked {
            stage: Stage::Evidence,
            why: "this class destroys evidence and §11.5 requires a durable capture of it \
                  first; no capture is built, so nothing of what it destroys was kept",
        });
    }

    if mode.enforces() {
        Decision::Proceed { unchecked }
    } else {
        Decision::Planned { unchecked }
    }
}

pub const fn needs_evidence_first(class: ActionClass) -> bool {
    matches!(
        class,
        ActionClass::Kill
            | ActionClass::SessionKill
            | ActionClass::TicketPurge
            | ActionClass::CredRotate
            | ActionClass::PerimeterStateKill
    )
}
