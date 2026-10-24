use core::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MonoTime(u64);

impl MonoTime {

    pub const fn from_nanos(ns: u64) -> Self {
        Self(ns)
    }

    pub const fn as_nanos(self) -> u64 {
        self.0
    }

    pub const fn saturating_since(self, earlier: MonoTime) -> u64 {
        self.0.saturating_sub(earlier.0)
    }

    pub const fn elapsed_since(self, start: MonoTime, dur_ns: u64) -> bool {
        self.saturating_since(start) >= dur_ns
    }
}

impl fmt::Display for MonoTime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}ns", self.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct WallTime(i64);

impl WallTime {

    pub const fn from_nanos(ns: i64) -> Self {
        Self(ns)
    }

    pub const fn as_nanos(self) -> i64 {
        self.0
    }

    pub const UNKNOWN: WallTime = WallTime(0);
}

impl fmt::Display for WallTime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}ns-since-epoch", self.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BootId([u8; 16]);

impl BootId {

    pub const fn from_bytes(b: [u8; 16]) -> Self {
        Self(b)
    }

    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl fmt::Display for BootId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in &self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stamp {

    pub mono: MonoTime,

    pub wall: WallTime,

    pub boot: BootId,
}

impl Stamp {

    pub fn comparable_with(&self, other: &Stamp) -> bool {
        self.boot == other.boot
    }

    pub fn since(&self, earlier: &Stamp) -> Option<u64> {
        self.comparable_with(earlier)
            .then(|| self.mono.saturating_since(earlier.mono))
    }
}
