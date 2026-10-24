use core::fmt;

pub type Result<T> = core::result::Result<T, CoreError>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CoreError {

    NotBuilt {

        what: &'static str,

        variant: &'static str,
    },

    Unsupported {

        what: &'static str,

        reason: &'static str,
    },

    Invalid {

        what: &'static str,

        detail: String,
    },

    CrossBoot,
}

impl fmt::Display for CoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CoreError::NotBuilt { what, variant } => {
                write!(f, "{what}: NOT-BUILT in variant {variant}")
            }
            CoreError::Unsupported { what, reason } => {
                write!(f, "{what}: unsupported on this host ({reason})")
            }
            CoreError::Invalid { what, detail } => {
                write!(f, "invalid {what}: {detail}")
            }
            CoreError::CrossBoot => f.write_str(
                "refused to compare timestamps from different boots: the interval would be meaningless",
            ),
        }
    }
}

impl std::error::Error for CoreError {}
