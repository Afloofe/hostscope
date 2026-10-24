use hemostat_broker::perimeter::Allowed;
use hemostat_buildinfo::ActionClass;
use hemostat_sensor_freebsd::tools::{Invocation, Output, PhpExt, RunError, Runner, Tool};
use hs_core::cidr::Cidr;

use crate::Alias;

pub fn is_read(inv: &Invocation) -> bool {
    let a: Vec<&str> = inv.args().iter().map(String::as_str).collect();
    match inv.tool() {
        Tool::Pfctl => pfctl_reads(&a),
        Tool::Sysctl => !a.is_empty() && a.iter().all(|x| !x.contains('=') && (*x == "-n" || !x.starts_with('-'))),
        Tool::Sockstat => a.iter().all(|x| x.starts_with('-') && x.bytes().skip(1).all(|b| b"46cl".contains(&b))),
        Tool::Netstat => a.iter().all(|x| matches!(*x, "-i" | "-n" | "-r" | "-rn" | "-in" | "-W" | "--libxo" | "json")),
        Tool::Procstat | Tool::Fstat | Tool::Kldstat | Tool::Ps => true,
        Tool::Arp | Tool::Ndp => a == ["-an"],
        Tool::Mount => a.is_empty() || a == ["-p"],
        Tool::Ifconfig => a.is_empty() || a == ["-a"],
        Tool::Renice => matches!(a.as_slice(), [_, "-p", pid] if *pid == std::process::id().to_string()),
        Tool::Php | Tool::Daemon | Tool::PkgStatic => false,
    }
}

fn pfctl_reads(a: &[&str]) -> bool {
    let mut i = 0;
    let mut listed = false;
    while let Some(x) = a.get(i) {
        match *x {
            "-v" | "-vv" => {}
            "-a" | "-t" => {

                match a.get(i + 1) {
                    Some(v) if !v.starts_with('-') => i += 1,
                    _ => return false,
                }
            }
            "-T" => {
                return match a.get(i + 1) {
                    Some(&"show") => i + 2 == a.len() && a.contains(&"-t"),
                    Some(&"test") => i + 2 < a.len() && a.contains(&"-t") && a.get(i + 2..).is_some_and(|r| r.iter().all(|v| !v.starts_with('-'))),
                    _ => false,
                };
            }
            s if s.starts_with("-s") && s.len() > 2 => listed = true,
            s if s.starts_with("-vvs") || s.starts_with("-vs") => listed = true,
            _ => return false,
        }
        i += 1;
    }
    listed
}

pub struct ReadOnly<'a> {
    inner: &'a mut dyn Runner,
}

impl<'a> ReadOnly<'a> {

    pub fn new(inner: &'a mut dyn Runner) -> ReadOnly<'a> {
        ReadOnly { inner }
    }
}

impl Runner for ReadOnly<'_> {
    fn run(&mut self, inv: &Invocation) -> Result<Output, RunError> {
        if !is_read(inv) {
            return Err(RunError::Refused(format!(
                "{} {} is not a read, and this path only reads",
                inv.tool(),
                inv.args().join(" ")
            )));
        }
        self.inner.run(inv)
    }

    fn tool_sha256(&self, tool: Tool) -> Option<[u8; 32]> {
        self.inner.tool_sha256(tool)
    }
}

pub const PHP_EXTS: [&str; 5] = ["ctype", "gettext", "mbstring", "xml", "pfSense"];

pub const ALIAS_PHP: &str = include_str!("alias.php");

pub const PHP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(300);

#[derive(Debug)]
pub struct Replayed {
    alias: Alias,
    cidr: Cidr,
    id: String,
    config: bool,
}

impl Replayed {

    pub(crate) fn judged(alias: Alias, cidr: Cidr, id: String, config: bool) -> Replayed {
        Replayed { alias, cidr, id, config }
    }

    pub fn config(&self) -> bool {
        self.config
    }

    pub fn alias(&self) -> Alias {
        self.alias
    }

    pub fn cidr(&self) -> &Cidr {
        &self.cidr
    }

    pub fn id(&self) -> &str {
        &self.id
    }
}

#[derive(Debug)]
pub struct Confirmable {
    alias: Alias,
    cidr: Cidr,
    id: String,
}

impl Confirmable {
    pub(crate) fn judged(alias: Alias, cidr: Cidr, id: String) -> Confirmable {
        Confirmable { alias, cidr, id }
    }

    pub fn alias(&self) -> Alias {
        self.alias
    }

    pub fn cidr(&self) -> &Cidr {
        &self.cidr
    }

    pub fn id(&self) -> &str {
        &self.id
    }
}

#[derive(Debug)]
pub struct WriteCommand {
    inv: Invocation,
    what: String,
}

fn php(op: &str, alias: Alias, cidr: &Cidr, id: &str) -> Invocation {
    let exts = PHP_EXTS.iter().filter_map(|e| PhpExt::new(e)).collect();
    let c = cidr.to_string();
    Invocation::php(exts, &["-q", "--", op, alias.name(), &c, id])
        .stdin(ALIAS_PHP.as_bytes().to_vec())
        .timeout(PHP_TIMEOUT)
}

pub fn test_address(cidr: &Cidr) -> String {
    cidr.addr().to_string()
}

impl WriteCommand {

    pub fn block(allowed: Allowed, alias: Alias, cidr: &Cidr) -> Result<WriteCommand, String> {
        if allowed.class() != ActionClass::PerimeterBlock {
            return Err(format!("an allowance for {} cannot add a table entry", allowed.class()));
        }
        let want = crate::operand(ActionClass::PerimeterBlock, &allowed.host(), alias, cidr);
        if want != allowed.operand() {
            return Err("the allowance was for a different alias, direction or CIDR".into());
        }
        let c = cidr.to_string();
        Ok(WriteCommand {
            inv: Invocation::new(Tool::Pfctl, &["-t", alias.name(), "-T", "add", &c]),
            what: format!("add {c} to {}", alias.name()),
        })
    }

    pub fn statekill(allowed: Allowed, alias: Alias, cidr: &Cidr) -> Result<WriteCommand, String> {
        if allowed.class() != ActionClass::PerimeterStateKill {
            return Err(format!("an allowance for {} cannot kill states", allowed.class()));
        }
        let want = crate::operand(ActionClass::PerimeterStateKill, &allowed.host(), alias, cidr);
        if want != allowed.operand() {
            return Err("the allowance was for a different alias, direction or CIDR".into());
        }
        let c = cidr.to_string();
        let any = if cidr.is_v4() { "0.0.0.0/0" } else { "::/0" };
        let (inv, what) = match alias {
            Alias::Out => (Invocation::new(Tool::Pfctl, &["-k", any, "-k", &c]), format!("kill every state to {c}")),
            Alias::In => (Invocation::new(Tool::Pfctl, &["-k", &c]), format!("kill every state from {c}")),
        };
        Ok(WriteCommand { inv, what })
    }

    pub fn lift(entry: &Replayed) -> WriteCommand {
        let c = entry.cidr.to_string();
        WriteCommand {
            inv: Invocation::new(Tool::Pfctl, &["-t", entry.alias.name(), "-T", "delete", &c]),
            what: format!("delete {c} from {}", entry.alias.name()),
        }
    }

    pub fn unconfig(entry: &Replayed) -> Option<WriteCommand> {
        entry.config.then(|| WriteCommand {
            inv: php("remove", entry.alias, &entry.cidr, &entry.id),
            what: format!("remove {} from {} in config.xml (HEMOSTAT {}) and reload the filter", entry.cidr, entry.alias.name(), entry.id),
        })
    }

    pub fn confirm(entry: &Confirmable) -> WriteCommand {
        WriteCommand {
            inv: php("add", entry.alias, &entry.cidr, &entry.id),
            what: format!("add {} to {} in config.xml (HEMOSTAT {}) and reload the filter", entry.cidr, entry.alias.name(), entry.id),
        }
    }

    pub fn readd(entry: &Confirmable) -> WriteCommand {
        let c = entry.cidr.to_string();
        WriteCommand {
            inv: Invocation::new(Tool::Pfctl, &["-t", entry.alias.name(), "-T", "add", &c]),
            what: format!("re-add {c} to {}", entry.alias.name()),
        }
    }

    pub fn describe(&self) -> &str {
        &self.what
    }

    pub fn invocation(&self) -> &Invocation {
        &self.inv
    }

    pub fn run(self, r: &mut dyn Runner) -> Result<Output, RunError> {
        r.run(&self.inv)
    }
}
