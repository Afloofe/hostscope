#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Adversary {

    Unprivileged,

    RootUserspace,

    RootKernel,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Trust {

    OffLevel,

    Contradiction,

    Kernel,

    Syscall,
}

impl Trust {

    pub fn defeated_by(self) -> Option<Adversary> {
        match self {
            Trust::OffLevel | Trust::Contradiction => None,
            Trust::Kernel => Some(Adversary::RootKernel),
            Trust::Syscall => Some(Adversary::RootUserspace),
        }
    }

    pub fn holds_against(self, adversary: Adversary) -> bool {
        match self.defeated_by() {
            None => true,
            Some(weakest) => adversary < weakest,
        }
    }

    pub fn tag(self) -> &'static str {
        match self {
            Trust::OffLevel => "off-level",
            Trust::Contradiction => "contradiction",
            Trust::Kernel => "kernel",
            Trust::Syscall => "syscall",
        }
    }

    pub fn explain(self) -> &'static str {
        match self {
            Trust::OffLevel => {
                "certain: observed off-host or anchored below the adversary; nothing on the \
                 host can fake it"
            }
            Trust::Contradiction => {
                "certain evidence of tampering: two on-host sources disagree, and a lie is the \
                 only thing that makes them disagree"
            }
            Trust::Kernel => {
                "trustworthy against a root attacker without kernel code; a malicious kernel \
                 module could contest it"
            }
            Trust::Syscall => {
                "a userspace read: trustworthy only against an unprivileged attacker; root or a \
                 kernel rootkit can fake it"
            }
        }
    }
}

pub fn weakest(sources: impl IntoIterator<Item = Trust>) -> Option<Trust> {
    sources.into_iter().max()
}
