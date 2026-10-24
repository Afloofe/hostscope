#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Mode {

    Observe,

    DryRun,

    Armed,
}

impl Mode {

    pub const fn enforces(self) -> bool {
        matches!(self, Mode::Armed)
    }

    pub const fn label(self) -> &'static str {
        match self {
            Mode::Observe => "observe",
            Mode::DryRun => "dry-run",
            Mode::Armed => "armed",
        }
    }
}

impl core::fmt::Display for Mode {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.label())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Profile {

    It,

    Ot,
}

impl Profile {

    pub const fn tighten(self, requested: Profile) -> Profile {
        match (self, requested) {
            (Profile::Ot, _) | (_, Profile::Ot) => Profile::Ot,
            _ => Profile::It,
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            Profile::It => "it",
            Profile::Ot => "ot",
        }
    }
}

impl core::fmt::Display for Profile {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.label())
    }
}
