use crate::facts::{Facts, Flag, Integrity};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {

    Note,

    Warn,

    Critical,
}

impl Severity {

    pub fn tag(self) -> &'static str {
        match self {
            Severity::Note => "note",
            Severity::Warn => "WARN",
            Severity::Critical => "CRITICAL",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {

    pub severity: Severity,

    pub subject: String,

    pub what: String,

    pub why: String,

    pub fix: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdversaryCeiling {

    UserMode,

    KernelReachable,

    Unknown,
}

impl AdversaryCeiling {

    pub fn token(self) -> &'static str {
        match self {
            AdversaryCeiling::UserMode => "user-mode",
            AdversaryCeiling::KernelReachable => "kernel-reachable",
            AdversaryCeiling::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentCeiling {

    System,

    Elevated,

    Limited,

    Unknown,
}

impl AgentCeiling {

    pub fn token(self) -> &'static str {
        match self {
            AgentCeiling::System => "system",
            AgentCeiling::Elevated => "elevated",
            AgentCeiling::Limited => "limited",
            AgentCeiling::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Standing {

    Level,

    Outranked,

    Underprivileged,

    Unknown,
}

impl Standing {

    pub fn token(self) -> &'static str {
        match self {
            Standing::Level => "level",
            Standing::Outranked => "outranked",
            Standing::Underprivileged => "underprivileged",
            Standing::Unknown => "unknown",
        }
    }

    pub fn meaning(self) -> &'static str {
        match self {
            Standing::Level => {

                "the agent and the attacker hold the same rights: both in user mode, no \
                 kernel code on either side. This is what §6 is written for. It means \
                 detect, survive and preserve — never prevent — because anything the \
                 agent can do to the attacker, the attacker can do back"
            }
            Standing::Outranked => {
                "the attacker has a route into the kernel and this agent, by design, has \
                 none. Every prevention claim in §6 was written about a weaker adversary \
                 than the one on this host. Treat on-box self-protection as defeasible and \
                 get the evidence off the host"
            }
            Standing::Underprivileged => {
                "the agent is not running as SYSTEM, so most of what §6 describes is out \
                 of reach and nothing below is a statement about the host. Re-run elevated"
            }
            Standing::Unknown => {
                "not enough was readable to place the agent against the adversary. Treat \
                 every capability below as unestablished rather than absent"
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Posture {

    pub agent: AgentCeiling,

    pub adversary: AdversaryCeiling,

    pub standing: Standing,

    pub findings: Vec<Finding>,

    pub facts: Facts,
}

impl Posture {

    pub fn count_at_least(&self, sev: Severity) -> usize {
        self.findings.iter().filter(|f| f.severity >= sev).count()
    }
}

pub mod subject {

    pub const WDIGEST: &str = "WDigest";

    pub const LSA_PROTECTION: &str = "LSA protection";

    pub const DRIVER_BLOCKLIST: &str = "vulnerable-driver blocklist";
}

fn adversary_ceiling(f: &Facts) -> AdversaryCeiling {

    let hvci = match (f.hvci, f.vbs) {
        (Flag::On, Flag::Off) => Flag::Off,
        (h, _) => h,
    };
    let barriers = [f.secure_boot, hvci, f.driver_blocklist];
    if barriers.contains(&Flag::Off) {
        return AdversaryCeiling::KernelReachable;
    }
    if barriers.iter().all(|b| *b == Flag::On) {
        return AdversaryCeiling::UserMode;
    }
    AdversaryCeiling::Unknown
}

fn agent_ceiling(f: &Facts) -> AgentCeiling {
    match (f.integrity, f.elevated) {
        (Integrity::System, _) => AgentCeiling::System,
        (Integrity::High, _) => AgentCeiling::Elevated,
        (Integrity::Unknown, Flag::Unreadable) => AgentCeiling::Unknown,
        _ => AgentCeiling::Limited,
    }
}

fn standing(agent: AgentCeiling, adversary: AdversaryCeiling) -> Standing {
    match agent {
        AgentCeiling::Limited => return Standing::Underprivileged,
        AgentCeiling::Unknown => return Standing::Unknown,
        AgentCeiling::System | AgentCeiling::Elevated => {}
    }
    match adversary {
        AdversaryCeiling::KernelReachable => Standing::Outranked,
        AdversaryCeiling::UserMode => Standing::Level,
        AdversaryCeiling::Unknown => Standing::Unknown,
    }
}

pub fn assess(facts: Facts) -> Posture {
    let mut findings = Vec::new();
    let agent = agent_ceiling(&facts);
    let adversary = adversary_ceiling(&facts);
    let standing = standing(agent, adversary);

    for (flag, subject, what_off, why_off, fix) in [
        (
            facts.secure_boot,
            "Secure Boot",
            "is disabled",
            "unsigned and revoked boot components load, which is the broadest route to \
             kernel code and the one that survives a reboot",
            "enable Secure Boot in firmware; it cannot be turned on from Windows",
        ),
        (
            facts.hvci,
            "HVCI / Memory Integrity",
            "is off",
            "the hypervisor is not validating kernel code, so a driver that passes the \
             loader's signature check is not checked again — this is the barrier that \
             makes most bring-your-own-driver attacks fail on a modern host",
            "Windows Security > Device security > Core isolation > Memory integrity, or \
             the DeviceGuard policy; needs a reboot",
        ),
        (
            facts.driver_blocklist,
            subject::DRIVER_BLOCKLIST,
            "is off",
            "Microsoft's list of known-exploitable signed drivers is not being enforced, \
             so the standard bring-your-own-vulnerable-driver path is open to any \
             attacker already holding SYSTEM",
            "Windows Security > Device security > Core isolation > Microsoft vulnerable \
             driver blocklist",
        ),
    ] {
        match flag {
            Flag::Off => findings.push(Finding {
                severity: Severity::Critical,
                subject: subject.to_string(),
                what: format!("{subject} {what_off}"),
                why: format!(
                    "{why_off}. §6's self-protection claims are all conditioned on the \
                     attacker NOT holding kernel code, and this is one of the three things \
                     that keeps that true"
                ),
                fix: Some(fix.to_string()),
            }),
            Flag::Unreadable => findings.push(Finding {
                severity: Severity::Warn,
                subject: subject.to_string(),
                what: format!("{subject} could not be read"),
                why: "an unreadable barrier is not a barrier that is up: this host cannot \
                      be reported as confining the attacker to user mode until it is read"
                    .to_string(),
                fix: Some("re-run as SYSTEM; if it still cannot be read, treat the \
                           adversary ceiling as kernel-reachable".to_string()),
            }),
            Flag::On => {}
        }
    }

    if let Some(basis) = &facts.driver_blocklist_basis {
        if let Some(f) = findings.iter_mut().find(|f| f.subject == subject::DRIVER_BLOCKLIST) {
            f.severity = f.severity.min(Severity::Warn);
            f.what = format!("{} (inferred from the build, not read)", f.what);
            f.why = format!("{}. {basis}", f.why);
        }
    }

    for (flag, subject) in [
        (facts.wdigest_plaintext, subject::WDIGEST),
        (facts.lsa_ppl, subject::LSA_PROTECTION),
    ] {
        if flag == Flag::Unreadable {
            findings.push(Finding {
                severity: Severity::Warn,
                subject: subject.to_string(),
                what: format!("{subject} could not be read"),
                why: "an unreadable credential setting is not a safe one: whether LSASS is \
                      caching or exposing credentials on this host is unknown until it is read"
                    .to_string(),
                fix: Some("re-run as SYSTEM; if it still cannot be read, something is \
                           denying the read, and that is worth finding out"
                    .to_string()),
            });
        }
    }
    if facts.wdigest_plaintext == Flag::On {
        findings.push(Finding {
            severity: Severity::Critical,
            subject: subject::WDIGEST.to_string(),
            what: "UseLogonCredential is set, so plaintext credentials are cached in LSASS"
                .to_string(),
            why: "any attacker at SYSTEM reads passwords rather than hashes out of memory, \
                  which turns one compromised host into every account used on it"
                .to_string(),
            fix: Some(
                "set HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest\
                 \\UseLogonCredential to 0, then rotate anything that logged on since"
                    .to_string(),
            ),
        });
    }
    if facts.lsa_ppl == Flag::Off {
        findings.push(Finding {
            severity: Severity::Warn,
            subject: subject::LSA_PROTECTION.to_string(),
            what: "LSASS is not running as a protected process (RunAsPPL is off)".to_string(),
            why: "the kernel is not refusing handle access to LSASS, so credential dumping \
                  needs nothing beyond the SYSTEM rights the attacker already has"
                .to_string(),
            fix: Some(
                "set HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\RunAsPPL to 1; it takes \
                 effect at the next boot and can break security products that inject into \
                 LSASS, so preview the impact first"
                    .to_string(),
            ),
        });
    }

    match facts.defender_rtp {
        Flag::On if !facts.defender_rtp_observed => {}
        Flag::On => findings.push(Finding {
            severity: Severity::Warn,
            subject: "Defender real-time protection".to_string(),
            what: "real-time protection is ON, which is not the expected state for this \
                   engagement"
                .to_string(),
            why: "§1.4a records that this environment runs with Defender disabled. Something \
                  turned it on. The agent never does, so this is a change made by the host, \
                  an administrator, or the attacker — and it is reported as a transition to \
                  investigate, not corrected"
                .to_string(),
            fix: None,
        }),
        Flag::Off | Flag::Unreadable => {}
    }

    if agent == AgentCeiling::Limited || agent == AgentCeiling::Unknown {
        findings.push(Finding {
            severity: Severity::Critical,
            subject: "agent privilege".to_string(),
            what: format!("running at integrity {}", facts.integrity.token()),
            why: "most of §6 needs SYSTEM, and a failed read above may be a permissions \
                  error rather than a disabled feature — so nothing here is yet a statement \
                  about the host"
                .to_string(),
            fix: Some("re-run as SYSTEM".to_string()),
        });
    } else if agent == AgentCeiling::Elevated {

        findings.push(Finding {
            severity: Severity::Note,
            subject: "agent privilege".to_string(),
            what: "running as an elevated administrator, not as SYSTEM".to_string(),
            why: "§6 is written about a SYSTEM agent. At High integrity most of the sweep \
                  works, but a read that came back unreadable may be a permissions error \
                  rather than a disabled feature, and self-protection is weaker than the \
                  design assumes"
                .to_string(),
            fix: Some("re-run as SYSTEM for the full picture".to_string()),
        });
    } else if facts.se_debug == Flag::Off {
        findings.push(Finding {
            severity: Severity::Warn,
            subject: "SeDebugPrivilege".to_string(),
            what: "the token does not carry SeDebugPrivilege".to_string(),
            why: "without it the agent cannot open other processes for inspection, so \
                  process-level query and containment are unavailable even at SYSTEM"
                .to_string(),
            fix: None,
        });
    }

    findings.push(Finding {
        severity: match standing {
            Standing::Outranked | Standing::Underprivileged => Severity::Critical,
            Standing::Unknown => Severity::Warn,
            Standing::Level => Severity::Note,
        },
        subject: "standing".to_string(),
        what: format!(
            "agent {} against an adversary whose ceiling is {}",
            agent.token(),
            adversary.token()
        ),
        why: standing.meaning().to_string(),
        fix: None,
    });

    findings.sort_by_key(|f| core::cmp::Reverse(f.severity));
    Posture { agent, adversary, standing, findings, facts }
}
