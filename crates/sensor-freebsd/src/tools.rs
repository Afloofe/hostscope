pub mod elf;
pub mod loader;
#[cfg(unix)]
pub mod system;
pub mod verify;

use std::time::Duration;

pub use verify::{Unverified, Verification, Verifier};

#[cfg(unix)]
pub use system::System;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Tool {

    Pfctl,

    Procstat,

    Sockstat,

    Kldstat,

    Sysctl,

    PkgStatic,

    Arp,

    Ndp,

    Netstat,

    Php,

    Renice,

    Daemon,

    Mount,

    Fstat,

    Ifconfig,

    Ps,
}

impl Tool {

    pub const ALL: [Tool; 16] = [
        Tool::Pfctl,
        Tool::Procstat,
        Tool::Sockstat,
        Tool::Kldstat,
        Tool::Sysctl,
        Tool::PkgStatic,
        Tool::Arp,
        Tool::Ndp,
        Tool::Netstat,
        Tool::Php,
        Tool::Renice,
        Tool::Daemon,
        Tool::Mount,
        Tool::Fstat,
        Tool::Ifconfig,
        Tool::Ps,
    ];

    pub fn path(self) -> &'static str {
        match self {
            Tool::Pfctl => "/sbin/pfctl",
            Tool::Procstat => "/usr/bin/procstat",
            Tool::Sockstat => "/usr/bin/sockstat",
            Tool::Kldstat => "/sbin/kldstat",
            Tool::Sysctl => "/sbin/sysctl",
            Tool::PkgStatic => "/usr/local/sbin/pkg-static",
            Tool::Arp => "/usr/sbin/arp",
            Tool::Ndp => "/usr/sbin/ndp",
            Tool::Netstat => "/usr/bin/netstat",
            Tool::Php => "/usr/local/bin/php",
            Tool::Renice => "/usr/bin/renice",
            Tool::Daemon => "/usr/sbin/daemon",
            Tool::Mount => "/sbin/mount",
            Tool::Fstat => "/usr/bin/fstat",
            Tool::Ifconfig => "/sbin/ifconfig",
            Tool::Ps => "/bin/ps",
        }
    }

    pub fn name(self) -> &'static str {
        self.path().rsplit('/').next().unwrap_or("")
    }

    pub fn library_path(self) -> &'static [&'static str] {
        match self {
            Tool::Php => &["/lib", "/usr/lib", "/usr/local/lib"],
            _ => &["/lib", "/usr/lib"],
        }
    }
}

impl core::fmt::Display for Tool {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.name())
    }
}

pub const PHP_EXT_DIR: &str = "/usr/local/lib/php/20220829";

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PhpExt(String);

impl PhpExt {

    pub fn new(name: &str) -> Option<PhpExt> {
        let ok = !name.is_empty()
            && name.len() <= 32
            && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_');
        ok.then(|| PhpExt(name.to_string()))
    }

    pub fn path(&self) -> String {
        format!("{PHP_EXT_DIR}/{}.so", self.0)
    }

    pub fn name(&self) -> &str {
        &self.0
    }
}

pub const DEFAULT_MAX_OUTPUT: u64 = 16 * 1024 * 1024;

pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invocation {
    tool: Tool,
    args: Vec<String>,
    exts: Vec<PhpExt>,
    stdin: Option<Vec<u8>>,
    max_output: u64,
    timeout: Duration,
}

impl Invocation {

    pub fn new(tool: Tool, args: &[&str]) -> Invocation {
        Invocation {
            tool,
            args: args.iter().map(|a| (*a).to_string()).collect(),
            exts: Vec::new(),
            stdin: None,
            max_output: DEFAULT_MAX_OUTPUT,
            timeout: DEFAULT_TIMEOUT,
        }
    }

    pub fn php(exts: Vec<PhpExt>, args: &[&str]) -> Invocation {
        Invocation { exts, ..Invocation::new(Tool::Php, args) }
    }

    pub fn stdin(mut self, bytes: Vec<u8>) -> Invocation {
        self.stdin = Some(bytes);
        self
    }

    pub fn max_output(mut self, n: u64) -> Invocation {
        self.max_output = n;
        self
    }

    pub fn timeout(mut self, d: Duration) -> Invocation {
        self.timeout = d;
        self
    }

    pub fn tool(&self) -> Tool {
        self.tool
    }

    pub fn args(&self) -> &[String] {
        &self.args
    }

    pub fn exts(&self) -> &[PhpExt] {
        &self.exts
    }

    pub fn stdin_bytes(&self) -> Option<&[u8]> {
        self.stdin.as_deref()
    }

    pub fn output_cap(&self) -> u64 {
        self.max_output
    }

    pub fn time_limit(&self) -> Duration {
        self.timeout
    }

    pub fn argv(&self) -> Vec<String> {
        let mut v = Vec::new();
        if self.tool == Tool::Php {
            v.push("-n".to_string());
            for e in &self.exts {
                v.push("-d".to_string());
                v.push(format!("extension={}", e.path()));
            }
        }
        v.extend(self.args.iter().cloned());
        v
    }

    pub fn refusal(&self) -> Option<String> {
        if self.tool != Tool::Php {
            return (!self.exts.is_empty()).then(|| format!("{} takes no PHP extensions", self.tool));
        }
        for a in self.args.iter().take_while(|a| a.as_str() != "--") {
            let undoes_n = ["-c", "-z", "-d", "--php-ini", "--zend-extension", "--define"]
                .iter()
                .any(|p| a == p || (p.len() == 2 && a.starts_with(p)) || a.starts_with(&format!("{p}=")));
            if undoes_n {
                return Some(format!(
                    "php argument {a:?} would load configuration or code that was not verified; \
                     extensions go through Invocation::php"
                ));
            }
        }
        None
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Output {

    pub status: Option<i32>,

    pub stdout: Vec<u8>,

    pub stderr: Vec<u8>,
}

impl Output {

    pub fn ok(stdout: &str) -> Output {
        Output { status: Some(0), stdout: stdout.as_bytes().to_vec(), stderr: Vec::new() }
    }

    pub fn failed(code: i32, stderr: &str) -> Output {
        Output { status: Some(code), stdout: Vec::new(), stderr: stderr.as_bytes().to_vec() }
    }

    pub fn success(&self) -> bool {
        self.status == Some(0)
    }

    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.stdout).into_owned()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunError {

    Unverified(Unverified),

    Refused(String),

    Spawn(String),

    Timeout(Duration),

    TooLarge(u64),

    NotScripted(String),
}

impl RunError {

    pub fn is_unverified(&self) -> bool {
        matches!(self, RunError::Unverified(_))
    }
}

impl core::fmt::Display for RunError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            RunError::Unverified(u) => write!(f, "tool unverified: {u}"),
            RunError::Refused(why) => write!(f, "refused: {why}"),
            RunError::Spawn(why) => write!(f, "could not run: {why}"),
            RunError::Timeout(d) => write!(f, "killed after {} s", d.as_secs()),
            RunError::TooLarge(n) => write!(f, "printed more than {n} bytes; not read in part"),
            RunError::NotScripted(what) => write!(f, "not in the script: {what}"),
        }
    }
}

pub trait Runner {

    fn run(&mut self, inv: &Invocation) -> Result<Output, RunError>;

    fn tool_sha256(&self, tool: Tool) -> Option<[u8; 32]> {
        let _ = tool;
        None
    }
}

#[derive(Debug, Default)]
pub struct Scripted {
    script: Vec<(Tool, Vec<String>, Result<Output, RunError>)>,
    calls: Vec<Invocation>,
    digests: std::collections::BTreeMap<Tool, [u8; 32]>,
}

impl Scripted {

    pub fn new() -> Scripted {
        Scripted::default()
    }

    pub fn on(mut self, tool: Tool, args: &[&str], out: Output) -> Scripted {
        self.script.push((tool, args.iter().map(|a| (*a).to_string()).collect(), Ok(out)));
        self
    }

    pub fn on_err(mut self, tool: Tool, args: &[&str], err: RunError) -> Scripted {
        self.script.push((tool, args.iter().map(|a| (*a).to_string()).collect(), Err(err)));
        self
    }

    pub fn with_digest(mut self, tool: Tool, digest: [u8; 32]) -> Scripted {
        self.digests.insert(tool, digest);
        self
    }

    pub fn calls(&self) -> &[Invocation] {
        &self.calls
    }

    pub fn unused(&self) -> usize {
        self.script.len()
    }
}

impl Runner for Scripted {
    fn run(&mut self, inv: &Invocation) -> Result<Output, RunError> {
        self.calls.push(inv.clone());
        if let Some(why) = inv.refusal() {
            return Err(RunError::Refused(why));
        }
        let at = self.script.iter().position(|(t, a, _)| *t == inv.tool && a.as_slice() == inv.args.as_slice());
        match at {
            Some(i) => self.script.remove(i).2,
            None => Err(RunError::NotScripted(format!("{} {}", inv.tool, inv.args.join(" ")))),
        }
    }

    fn tool_sha256(&self, tool: Tool) -> Option<[u8; 32]> {
        self.digests.get(&tool).copied()
    }
}

pub fn renice_self(r: &mut dyn Runner, nice: i32) -> Result<(), RunError> {
    let pid = std::process::id().to_string();
    let nice = nice.to_string();
    let out = r.run(&Invocation::new(Tool::Renice, &[&nice, "-p", &pid]))?;
    if out.success() {
        Ok(())
    } else {
        Err(RunError::Spawn(format!(
            "renice exited {:?}: {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        )))
    }
}
