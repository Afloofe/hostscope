#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Lane {

    P0,

    P1,

    P2,
}

impl Lane {

    pub const fn is_sheddable(self) -> bool {
        !matches!(self, Lane::P0)
    }

    pub const fn label(self) -> &'static str {
        match self {
            Lane::P0 => "P0",
            Lane::P1 => "P1",
            Lane::P2 => "P2",
        }
    }
}

impl core::fmt::Display for Lane {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.label())
    }
}
