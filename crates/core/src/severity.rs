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
