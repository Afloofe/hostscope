#![forbid(unsafe_code)]

pub mod apply;
pub mod cmd;
pub mod journal;
pub mod preflight;
pub mod protect;
pub mod statekill;

use hemostat_broker::perimeter::{self, Decision, Evidence, Request};
use hemostat_buildinfo::ActionClass;
use hemostat_evcrypto::ticket::Dir;
use hemostat_sensor_freebsd::configxml::Config;
use hs_core::cidr::Cidr;
use hs_core::mode::{Mode, Profile};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Alias {

    Out,

    In,
}

impl Alias {

    pub const fn name(self) -> &'static str {
        match self {
            Alias::Out => "HEMOSTAT_OUT",
            Alias::In => "HEMOSTAT_IN",
        }
    }

    pub const fn dir(self) -> Dir {
        match self {
            Alias::Out => Dir::Out,
            Alias::In => Dir::In,
        }
    }

    pub const fn side(self) -> &'static str {
        match self {
            Alias::Out => "destination",
            Alias::In => "source",
        }
    }

    pub fn from_name(s: &str) -> Option<Alias> {
        match s {
            "HEMOSTAT_OUT" => Some(Alias::Out),
            "HEMOSTAT_IN" => Some(Alias::In),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Enrolled {

    pub alias: Alias,

    pub tracker: u32,

    pub protect: Vec<Cidr>,
}

pub fn operand(class: ActionClass, host: &[u8; 32], alias: Alias, cidr: &Cidr) -> [u8; 32] {
    hemostat_evcrypto::ticket::operand(
        hemostat_broker::class_code(class),
        host,
        alias.name(),
        alias.dir(),
        &cidr.to_string(),
    )
}

#[derive(Debug, Clone)]
pub struct Authority {

    pub profile: Profile,

    pub built: bool,

    pub policy: perimeter::Policy,

    pub ticket: perimeter::Ticket,
}

#[derive(Debug)]
pub struct DryRun {

    pub cidr: Cidr,

    pub alias: Alias,

    pub operand: [u8; 32],

    pub preflight: preflight::Preflight,

    pub protected: Option<protect::Protected>,

    pub decision: Option<Decision>,

    pub request: Option<Request>,

    pub protect: Option<perimeter::Protect>,
}

impl DryRun {

    pub fn passed(&self) -> bool {
        matches!(self.decision, Some(Decision::DryRun { .. }))
    }

    pub fn armed(&self, auth: &Authority, evidence: Evidence) -> Decision {
        let (Some(req), Some(protect), true) = (&self.request, &self.protect, self.passed()) else {
            return Decision::Refused {
                stage: perimeter::Stage::Mode,
                reason: "the stages did not all pass, so nothing is armed".into(),
            };
        };
        perimeter::decide(
            req,
            &perimeter::Inputs {
                mode: Mode::Armed,
                profile: auth.profile,
                built: auth.built,
                policy: &auth.policy,
                protect,
                ticket: &auth.ticket,
                evidence,
            },
        )
    }
}

#[allow(clippy::too_many_arguments)]
pub fn dry_run(
    r: &mut dyn hemostat_sensor_freebsd::tools::Runner,
    host: [u8; 32],
    cidr: Cidr,
    enrolled: &Enrolled,
    config: &Result<Config, String>,
    inc: &Result<Vec<preflight::IncFile>, String>,
    manifest: Option<&hemostat_evcrypto::manifest::Manifest>,
    resolv: &Result<String, String>,
    ssh_connection: Option<&str>,
    auth: &Authority,
) -> DryRun {
    stages(r, ActionClass::PerimeterBlock, host, cidr, enrolled, config, inc, manifest, resolv, ssh_connection, auth)
}

#[allow(clippy::too_many_arguments)]
pub fn confirm_stages(
    r: &mut dyn hemostat_sensor_freebsd::tools::Runner,
    host: [u8; 32],
    cidr: Cidr,
    enrolled: &Enrolled,
    config: &Result<Config, String>,
    inc: &Result<Vec<preflight::IncFile>, String>,
    manifest: Option<&hemostat_evcrypto::manifest::Manifest>,
    resolv: &Result<String, String>,
    ssh_connection: Option<&str>,
    auth: &Authority,
) -> DryRun {
    counted(r, ActionClass::PerimeterBlock, host, cidr, enrolled, config, inc, manifest, resolv, ssh_connection, auth, true)
}

#[allow(clippy::too_many_arguments)]
pub fn stages(
    r: &mut dyn hemostat_sensor_freebsd::tools::Runner,
    class: ActionClass,
    host: [u8; 32],
    cidr: Cidr,
    enrolled: &Enrolled,
    config: &Result<Config, String>,
    inc: &Result<Vec<preflight::IncFile>, String>,
    manifest: Option<&hemostat_evcrypto::manifest::Manifest>,
    resolv: &Result<String, String>,
    ssh_connection: Option<&str>,
    auth: &Authority,
) -> DryRun {
    counted(r, class, host, cidr, enrolled, config, inc, manifest, resolv, ssh_connection, auth, false)
}

#[allow(clippy::too_many_arguments)]
fn counted(
    r: &mut dyn hemostat_sensor_freebsd::tools::Runner,
    class: ActionClass,
    host: [u8; 32],
    cidr: Cidr,
    enrolled: &Enrolled,
    config: &Result<Config, String>,
    inc: &Result<Vec<preflight::IncFile>, String>,
    manifest: Option<&hemostat_evcrypto::manifest::Manifest>,
    resolv: &Result<String, String>,
    ssh_connection: Option<&str>,
    auth: &Authority,
    present: bool,
) -> DryRun {
    let mut ro = cmd::ReadOnly::new(r);
    let op = operand(class, &host, enrolled.alias, &cidr);
    let pf = preflight::gather(&mut ro);
    let kill = class == ActionClass::PerimeterStateKill;
    let pre = if kill { preflight::judge_kill(&pf, config) } else { preflight::judge(&pf, config, inc, manifest, enrolled) };
    if !pre.passed() {
        return DryRun {
            cidr,
            alias: enrolled.alias,
            operand: op,
            preflight: pre,
            protected: None,
            decision: None,
            request: None,
            protect: None,
        };
    }
    let ps = protect::gather(&mut ro);
    let protected = protect::collect(&ps, config.as_ref().ok(), resolv, ssh_connection, enrolled);
    let verdict = protect::judge(&cidr, &protected);
    let req = Request {
        class,
        origin: hemostat_broker::Origin::Operator,
        host,
        operand: op,
        summary: if kill {
            format!("kill every state {} {cidr}", if enrolled.alias == Alias::Out { "to" } else { "from" })
        } else {
            format!("block {cidr} in {}", enrolled.alias.name())
        },

        entries: match (kill, present) {
            (true, _) => 0,
            (false, true) => pre.entries.unwrap_or(0),
            (false, false) => pre.entries.unwrap_or(0).saturating_add(1),
        },
    };
    let decision = perimeter::decide(
        &req,
        &perimeter::Inputs {
            mode: Mode::DryRun,
            profile: auth.profile,
            built: auth.built,
            policy: &auth.policy,
            protect: &verdict,
            ticket: &auth.ticket,
            evidence: Evidence::NotYet,
        },
    );
    DryRun {
        cidr,
        alias: enrolled.alias,
        operand: op,
        preflight: pre,
        protected: Some(protected),
        decision: Some(decision),
        request: Some(req),
        protect: Some(verdict),
    }
}
