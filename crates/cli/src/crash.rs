use std::fmt::Write as _;
use std::path::{Path, PathBuf};

pub(crate) const DEFAULT_CRASH_DIR: &str = "/var/lib/hemostat/crash";

pub(crate) const CRASH_DIR_ENV: &str = "HEMOSTAT_CRASH_DIR";

pub(crate) fn candidate_dirs() -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Ok(d) = std::env::var(CRASH_DIR_ENV) {
        if !d.is_empty() {
            out.push(PathBuf::from(d));
        }
    }
    out.push(PathBuf::from(DEFAULT_CRASH_DIR));
    out.push(std::env::temp_dir().join("hemostat-crash"));
    out
}

pub(crate) struct Report<'a> {

    pub(crate) verb: &'a str,

    pub(crate) variant: &'a str,

    pub(crate) rev: &'a str,

    pub(crate) dirty: bool,

    pub(crate) pid: u32,

    pub(crate) when: u64,

    pub(crate) location: Option<String>,

    pub(crate) message: &'a str,
}

impl Report<'_> {

    pub(crate) fn render(&self) -> String {
        let mut s = String::with_capacity(768);
        let _ = writeln!(s, "hemostat crash record");
        let _ = writeln!(s, "when-epoch-secs: {}", self.when);
        let _ = writeln!(s, "pid:             {}", self.pid);
        let _ = writeln!(s, "verb:            {}", self.verb);
        let _ = writeln!(
            s,
            "image:           variant {} rev {}{}",
            self.variant,
            self.rev,
            if self.dirty { " (built from a MODIFIED tree)" } else { "" }
        );
        let _ = writeln!(
            s,
            "where:           {}",
            self.location.as_deref().unwrap_or("unknown — the runtime gave no location")
        );
        let _ = writeln!(s, "what:            {}", one_line(self.message));
        let _ = writeln!(s);
        let _ = writeln!(
            s,
            "This process aborted. It was built with `panic = abort`, so nothing unwound\n\
             and no destructor ran: an evidence store open at this moment has an unsealed\n\
             segment and may have a torn final record, which `hemostat verify` reports as a\n\
             torn tail rather than as tampering.\n\
             \n\
             Whatever sweep was in progress DID NOT COMPLETE. Its absence from the store is\n\
             not a clean result for that surface.\n\
             \n\
             If this repeats on the same input, treat the crash as attacker-reachable: the\n\
             location above names the code that read something on this host, and a panic\n\
             that can be induced on demand is a way to remove the agent silently."
        );
        s
    }

    pub(crate) fn file_name(&self) -> String {
        format!("crash-{}-{}.txt", self.when, self.pid)
    }
}

fn one_line(s: &str) -> String {
    s.chars().map(|c| if c == '\n' || c == '\r' { ' ' } else { c }).collect()
}

pub(crate) fn write_report(dirs: &[PathBuf], name: &str, text: &str) -> Option<PathBuf> {
    for dir in dirs {
        if std::fs::create_dir_all(dir).is_err() {
            continue;
        }
        let path = Path::new(dir).join(name);
        if std::fs::write(&path, text).is_ok() {
            return Some(path);
        }
    }
    None
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

pub(crate) fn install(verb: String, variant: &'static str, rev: &'static str, dirty: bool) {
    let prior = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let message = payload_str(info);
        let location = info.location().map(|l| format!("{}:{}:{}", l.file(), l.line(), l.column()));
        let report = Report {
            verb: &verb,
            variant,
            rev,
            dirty,
            pid: std::process::id(),
            when: now_secs(),
            location,
            message: &message,
        };
        let text = report.render();

        eprintln!("\n{text}");
        match write_report(&candidate_dirs(), &report.file_name(), &text) {
            Some(p) => eprintln!("crash record written to {}", crate::render::h(&p.display().to_string())),
            None => eprintln!(
                "crash record could NOT be written to disk (tried {}, {} and a temporary \
                 directory) — copy the text above before this terminal is gone",
                CRASH_DIR_ENV, DEFAULT_CRASH_DIR
            ),
        }

        prior(info);
    }));
}

fn payload_str(info: &std::panic::PanicHookInfo<'_>) -> String {
    if let Some(s) = info.payload().downcast_ref::<&str>() {
        return (*s).to_string();
    }
    if let Some(s) = info.payload().downcast_ref::<String>() {
        return s.clone();
    }
    "a panic payload this build cannot render as text".to_string()
}
