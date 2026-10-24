use core::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {

    Info,

    Note,

    Warn,

    Critical,
}

impl Severity {

    pub fn tag(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Note => "note",
            Severity::Warn => "WARN",
            Severity::Critical => "CRITICAL",
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.tag())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Coverage {

    Clean,

    Populated,

    Partial,

    Unreadable,

    NotPresent,
}

impl Coverage {

    pub fn token(self) -> &'static str {
        match self {
            Coverage::Clean => "clean",
            Coverage::Populated => "populated",
            Coverage::Partial => "partial",
            Coverage::Unreadable => "unreadable",
            Coverage::NotPresent => "not-present",
        }
    }

    pub fn established(self) -> bool {
        !matches!(self, Coverage::Unreadable | Coverage::Partial)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {

    pub severity: Severity,

    pub subject: String,

    pub locus: String,

    pub what: String,

    pub why: String,
}

impl Finding {

    pub fn info(subject: impl Into<String>, locus: impl Into<String>, what: impl Into<String>) -> Finding {
        Finding {
            severity: Severity::Info,
            subject: subject.into(),
            locus: locus.into(),
            what: what.into(),
            why: String::new(),
        }
    }

    pub fn flag(
        severity: Severity,
        subject: impl Into<String>,
        locus: impl Into<String>,
        what: impl Into<String>,
        why: impl Into<String>,
    ) -> Finding {
        Finding {
            severity,
            subject: subject.into(),
            locus: locus.into(),
            what: what.into(),
            why: why.into(),
        }
    }
}

pub fn rank(findings: &mut [Finding]) {
    findings.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| a.subject.cmp(&b.subject))
            .then_with(|| a.locus.cmp(&b.locus))
    });
}
