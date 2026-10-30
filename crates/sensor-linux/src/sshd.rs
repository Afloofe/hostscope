use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::rootkit::{Finding, Severity};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ground {

    Resolved,

    Unavailable(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Effective {

    pub values: BTreeMap<String, Vec<String>>,

    pub ground: Ground,
}

impl Effective {

    pub fn one(&self, key: &str) -> Option<&str> {
        match self.values.get(key).map(Vec::as_slice) {
            Some([only]) => Some(only.as_str()),
            _ => None,
        }
    }
}

pub fn parse_effective(text: &str) -> BTreeMap<String, Vec<String>> {
    let mut out: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (key, value) = match line.split_once(char::is_whitespace) {
            Some((k, v)) => (k, v.trim()),
            None => (line, ""),
        };
        out.entry(key.to_ascii_lowercase()).or_default().push(value.to_string());
    }
    out
}

fn sshd_bin() -> Option<PathBuf> {
    ["/usr/sbin/sshd", "/usr/bin/sshd", "/sbin/sshd"]
        .iter()
        .map(PathBuf::from)
        .find(|p| p.is_file())
}

pub fn effective_with(extra: &[&str]) -> Effective {
    run_t(extra, None)
}

pub fn check_config(bin: &Path, config: std::fs::File) -> Result<(), String> {
    let again = config.try_clone().ok();
    let cmd = || {
        let mut c = std::process::Command::new(bin);
        c.args(["-t", "-f", "/proc/self/fd/0"]).env_clear().env("LC_ALL", "C");
        c
    };
    let mut out = output_within(&mut cmd(), std::process::Stdio::from(config), SSHD_T_LIMIT);
    if let Some(dir) = out.as_ref().ok().and_then(Option::as_ref).and_then(missing_privsep_dir) {
        if let Some(f) = again {
            let mut retry = cmd();
            if std::io::Seek::rewind(&mut &f).is_ok() && with_privsep_dir(&mut retry, &dir) {
                out = output_within(&mut retry, std::process::Stdio::from(f), SSHD_T_LIMIT);
            }
        }
    }
    match out {
        Ok(Some(o)) if o.status.success() => Ok(()),
        Ok(Some(o)) => {
            let why = String::from_utf8_lossy(&o.stderr).trim().to_string();
            Err(if why.is_empty() { format!("{} -t exited {}", bin.display(), o.status) } else { why })
        }
        Ok(None) => Err(format!(
            "{} -t had not answered after {} seconds and was stopped",
            bin.display(),
            SSHD_T_LIMIT.as_secs()
        )),
        Err(e) => Err(format!("could not run {}: {e}", bin.display())),
    }
}

const SSHD_T_LIMIT: std::time::Duration = std::time::Duration::from_secs(10);

const SSHD_T_MAX_OUTPUT: u64 = 1 << 20;

fn run_t(extra: &[&str], stdin: Option<std::fs::File>) -> Effective {
    let Some(bin) = sshd_bin() else {
        return Effective {
            values: BTreeMap::new(),
            ground: Ground::Unavailable("no sshd binary found on this host".into()),
        };
    };
    let mut cmd = std::process::Command::new(&bin);
    cmd.arg("-T").args(extra);

    let had_stdin = stdin.is_some();
    let again = stdin.as_ref().and_then(|f| f.try_clone().ok());
    let stdin = stdin.map_or_else(std::process::Stdio::null, std::process::Stdio::from);
    let mut out = output_within(&mut cmd, stdin, SSHD_T_LIMIT);

    if let Some(dir) = out.as_ref().ok().and_then(Option::as_ref).and_then(missing_privsep_dir) {

        let retry_stdin = match again {
            Some(f) => std::io::Seek::rewind(&mut &f).ok().map(|()| std::process::Stdio::from(f)),
            None if !had_stdin => Some(std::process::Stdio::null()),
            None => None,
        };
        let mut retry = std::process::Command::new(&bin);
        retry.arg("-T").args(extra);
        if let Some(s) = retry_stdin.filter(|_| with_privsep_dir(&mut retry, &dir)) {
            out = output_within(&mut retry, s, SSHD_T_LIMIT);
        }
    }
    let out = match out {
        Ok(Some(o)) => Ok(o),
        Ok(None) => {
            return Effective {
                values: BTreeMap::new(),
                ground: Ground::Unavailable(format!(
                    "{} -T had not answered after {} seconds and was stopped",
                    bin.display(),
                    SSHD_T_LIMIT.as_secs()
                )),
            }
        }
        Err(e) => Err(e),
    };
    match out {
        Ok(o) if o.status.success() => Effective {
            values: parse_effective(&String::from_utf8_lossy(&o.stdout)),
            ground: Ground::Resolved,
        },
        Ok(o) => {
            let why = String::from_utf8_lossy(&o.stderr).trim().to_string();
            Effective {
                values: BTreeMap::new(),
                ground: Ground::Unavailable(if why.is_empty() {
                    format!("{} -T exited {}", bin.display(), o.status)
                } else {

                    format!(
                        "{why} — `sshd -T` must read the host keys, so it needs root, and it \
                         fails outright where sshd has never been set up"
                    )
                }),
            }
        }
        Err(e) => Effective {
            values: BTreeMap::new(),
            ground: Ground::Unavailable(format!("could not run {}: {e}", bin.display())),
        },
    }
}

fn missing_privsep_dir(o: &std::process::Output) -> Option<PathBuf> {
    if o.status.success() {
        return None;
    }
    let err = String::from_utf8_lossy(&o.stderr);
    let dir = err.lines().find_map(|l| l.trim().strip_prefix("Missing privilege separation directory: "))?;
    let dir = PathBuf::from(dir.trim());
    let parent = dir.parent()?;
    (dir.is_absolute() && parent != Path::new("/") && dir.file_name().is_some()).then_some(dir)
}

fn with_privsep_dir(cmd: &mut std::process::Command, dir: &Path) -> bool {
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::process::CommandExt;
    let (Some(parent), Ok(d)) = (dir.parent(), std::ffi::CString::new(dir.as_os_str().as_bytes())) else {
        return false;
    };
    let Ok(p) = std::ffi::CString::new(parent.as_os_str().as_bytes()) else { return false };
    let root = c"/";
    let tmpfs = c"tmpfs";
    let opts = c"mode=0755,size=64k";

    unsafe {
        cmd.pre_exec(move || {
            let fail = || Err(std::io::Error::last_os_error());
            if libc::unshare(libc::CLONE_NEWNS) != 0 {
                return fail();
            }
            if libc::mount(std::ptr::null(), root.as_ptr(), std::ptr::null(), libc::MS_REC | libc::MS_PRIVATE, std::ptr::null()) != 0 {
                return fail();
            }
            if libc::mount(
                tmpfs.as_ptr(),
                p.as_ptr(),
                tmpfs.as_ptr(),
                libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
                opts.as_ptr().cast(),
            ) != 0
            {
                return fail();
            }
            if libc::mkdir(d.as_ptr(), 0o755) != 0 {
                return fail();
            }
            Ok(())
        });
    }
    true
}

pub fn effective() -> Effective {
    effective_with(&[])
}

pub fn output_within(
    cmd: &mut std::process::Command,
    stdin: std::process::Stdio,
    limit: std::time::Duration,
) -> std::io::Result<Option<std::process::Output>> {
    use std::process::Stdio;
    use std::time::{Duration, Instant};

    fn drain<R: std::io::Read + Send + 'static>(pipe: Option<R>) -> std::sync::mpsc::Receiver<Vec<u8>> {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut buf = Vec::new();
            if let Some(p) = pipe {
                let _ = std::io::Read::read_to_end(&mut p.take(SSHD_T_MAX_OUTPUT), &mut buf);
            }
            let _ = tx.send(buf);
        });
        rx
    }

    let mut child = cmd.stdin(stdin).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn()?;
    let stdout = drain(child.stdout.take());
    let stderr = drain(child.stderr.take());
    let deadline = Instant::now() + limit;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(10)),
            outcome => {
                let _ = child.kill();
                let _ = child.wait();
                return outcome.map(|_| None);
            }
        }
    };

    let grace = Duration::from_secs(1);
    Ok(Some(std::process::Output {
        status,
        stdout: stdout.recv_timeout(grace).unwrap_or_default(),
        stderr: stderr.recv_timeout(grace).unwrap_or_default(),
    }))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Want {

    Is(&'static str),

    AtMost(u64),

    AtLeast(u64),
}

#[derive(Debug, Clone, Copy)]
pub struct Control {

    pub key: &'static str,

    pub spelling: &'static str,

    pub want: Want,

    pub severity: Severity,

    pub why: &'static str,

    pub breaks: &'static str,
}

pub const CONTROLS: &[Control] = &[
    Control {
        key: "permitrootlogin",
        spelling: "PermitRootLogin",
        want: Want::Is("no"),
        severity: Severity::Critical,
        why: "root may log in over the network directly, so a password guess or a stolen key \
              is immediately the whole host, and the audit trail never names a person",
        breaks: "any automation that logs in as root — backups, config management, and a \
                 responder's own habit. Check for a non-root account with sudo FIRST",
    },
    Control {
        key: "permitemptypasswords",
        spelling: "PermitEmptyPasswords",
        want: Want::Is("no"),
        severity: Severity::Critical,
        why: "an account with an empty password field can be logged into by anyone who types \
              its name. This is the OpenSSH default, so a `yes` was put there by somebody",
        breaks: "logins by accounts that genuinely have no password — some appliance and \
                 kiosk images. PAM usually refuses these anyway, so it is often already inert",
    },
    Control {
        key: "passwordauthentication",
        spelling: "PasswordAuthentication",
        want: Want::Is("no"),
        severity: Severity::Warn,
        why: "passwords over SSH are guessable at leisure by anyone who can reach the port, \
              and every credential-stuffing run on the internet tries them",
        breaks: "EVERY password login, including yours. Only safe once key authentication is \
                 confirmed working for every account that needs in — verify before, not after",
    },
    Control {
        key: "permituserenvironment",
        spelling: "PermitUserEnvironment",
        want: Want::Is("no"),
        severity: Severity::Warn,
        why: "lets a user set environment variables through ~/.ssh/environment, which is a \
              documented route to LD_PRELOAD and therefore to code execution at login",
        breaks: "anything that relies on ~/.ssh/environment, which is rare and usually a \
                 workaround for something better done in the shell profile",
    },
    Control {
        key: "hostbasedauthentication",
        spelling: "HostbasedAuthentication",
        want: Want::Is("no"),
        severity: Severity::Warn,
        why: "trusts the client host's say-so about who the user is; one compromised machine \
              in the trust set becomes all of them",
        breaks: "host-based trust, if it is actually in use. Rare outside HPC clusters",
    },
    Control {
        key: "ignorerhosts",
        spelling: "IgnoreRhosts",
        want: Want::Is("yes"),
        severity: Severity::Warn,
        why: "~/.rhosts and ~/.shosts let a user grant access from named hosts without any \
              credential, and a writable home directory is enough to add one",
        breaks: "rhosts-style trust. Effectively nothing on a modern host",
    },
    Control {
        key: "strictmodes",
        spelling: "StrictModes",
        want: Want::Is("yes"),
        severity: Severity::Warn,
        why: "without it sshd will honour a world-writable ~/.ssh/authorized_keys, so any \
              user who can write another's home directory can log in as them",
        breaks: "logins for accounts whose home or .ssh permissions are already too loose — \
                 which is the condition being fixed. Check permissions first or you lock them out",
    },
    Control {
        key: "x11forwarding",
        spelling: "X11Forwarding",
        want: Want::Is("no"),
        severity: Severity::Warn,
        why: "an X11 channel back to the client is a well-worn path for keystroke capture, \
              and almost nothing on a server needs it",
        breaks: "remote GUI applications and `ssh -X`. Real on a workstation, rare on a server",
    },
    Control {
        key: "gatewayports",
        spelling: "GatewayPorts",
        want: Want::Is("no"),
        severity: Severity::Warn,
        why: "lets a forwarded port bind to every interface rather than loopback, turning any \
              user's SSH session into a way to publish a service to the whole network",
        breaks: "deliberate remote-accessible tunnels. Uncommon and usually a workaround",
    },
    Control {
        key: "permittunnel",
        spelling: "PermitTunnel",
        want: Want::Is("no"),
        severity: Severity::Note,
        why: "tun-device forwarding builds a VPN through the SSH session, which moves far more \
              than a shell and is rarely what a server should offer",
        breaks: "SSH-based VPNs, if any exist here",
    },
    Control {
        key: "maxauthtries",
        spelling: "MaxAuthTries",
        want: Want::AtMost(4),
        severity: Severity::Warn,
        why: "a high limit lets one connection try many credentials, which is what makes \
              online guessing practical",
        breaks: "a client that offers several keys before the right one — ssh-agent with a \
                 large keyring hits this and fails in a way that looks like a rejected key",
    },
    Control {
        key: "logingracetime",
        spelling: "LoginGraceTime",
        want: Want::AtMost(60),
        severity: Severity::Warn,
        why: "unauthenticated connections hold a slot for this long; a generous value is what \
              makes pre-auth connection exhaustion easy",
        breaks: "logins over very slow links, and interactive workflows where somebody takes \
                 a while to find a hardware token. 0 means no limit at all",
    },
    Control {
        key: "clientaliveinterval",
        spelling: "ClientAliveInterval",
        want: Want::AtMost(300),
        severity: Severity::Note,
        why: "with no keepalive, a session whose client has vanished stays open and \
              authenticated indefinitely",
        breaks: "long-running commands over flaky links may be disconnected sooner. Set with \
                 ClientAliveCountMax; 0 disables it entirely",
    },
    Control {
        key: "loglevel",
        spelling: "LogLevel",
        want: Want::Is("verbose"),
        severity: Severity::Note,
        why: "VERBOSE records the key fingerprint used for each login, which is the difference \
              between knowing an account was used and knowing which key used it",
        breaks: "more log volume. Nothing functional",
    },
    Control {
        key: "usepam",
        spelling: "UsePAM",
        want: Want::Is("yes"),
        severity: Severity::Warn,
        why: "PAM is where account expiry, lockout and session limits are enforced; without \
              it those controls are simply not applied to SSH logins",
        breaks: "turning it ON is usually safe; note that some hardened setups deliberately \
                 run without PAM and rely on keys alone",
    },
];

pub fn judge(c: &Control, value: &str) -> Option<String> {
    let v = value.trim();
    match c.want {
        Want::Is(want) => {
            if v.eq_ignore_ascii_case(want) {
                None
            } else {
                Some(v.to_string())
            }
        }
        Want::AtMost(max) => match v.parse::<u64>() {

            Ok(0) => Some(format!("{v} (no limit)")),
            Ok(n) if n <= max => None,
            Ok(n) => Some(n.to_string()),
            Err(_) => Some(format!("{v} (not a number)")),
        },
        Want::AtLeast(min) => match v.parse::<u64>() {
            Ok(0) => Some(format!("{v} (disabled)")),
            Ok(n) if n >= min => None,
            Ok(n) => Some(n.to_string()),
            Err(_) => Some(format!("{v} (not a number)")),
        },
    }
}

const KEY_ONLY_ROOT: &[&str] = &["prohibit-password", "without-password", "forced-commands-only"];

pub fn severity_for(c: &Control, value: &str) -> Severity {
    if c.key == "permitrootlogin" && KEY_ONLY_ROOT.iter().any(|k| value.trim().eq_ignore_ascii_case(k)) {
        Severity::Warn
    } else {
        c.severity
    }
}

pub fn wanted_value(c: &Control) -> String {
    match c.want {
        Want::Is(v) => v.to_string(),
        Want::AtMost(n) => n.to_string(),
        Want::AtLeast(n) => n.to_string(),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {

    pub findings: Vec<Finding>,

    pub available: bool,

    pub reason: Option<String>,
}

pub fn report() -> Report {
    let eff = effective();
    let mut r = from_effective(&eff);
    if r.available {
        let mut overrides = match_overrides(Path::new(MAIN_CONFIG));
        let launch = launch_overrides();
        let Running { daemons, unread } = running_daemons();
        let (running, elsewhere) = split_daemons(daemons);

        let running: Vec<Override> =
            running.into_iter().filter(|o| !launch.iter().any(|l| l.key == o.key && l.value == o.value)).collect();
        overrides.extend(launch);
        overrides.extend(running);
        r.findings.extend(override_findings(&eff, &overrides));
        for d in &elsewhere {
            r.findings.extend(elsewhere_findings(d));
        }
        r.findings.extend(unread);
    }
    r
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Override {

    pub key: String,

    pub value: String,

    pub scope: String,
}

pub fn match_overrides(root: &Path) -> Vec<Override> {
    let mut out = Vec::new();
    let mut seen = Vec::new();
    walk_matches(root, None, &mut out, &mut seen, 0);
    out
}

fn walk_matches(
    path: &Path,
    inherited: Option<&str>,
    out: &mut Vec<Override>,
    seen: &mut Vec<PathBuf>,
    depth: u32,
) {

    if depth > 16 || seen.iter().any(|p| p == path) {
        return;
    }
    seen.push(path.to_path_buf());
    let Some(text) = crate::saferead::read_scan_target(path) else { return };
    let mut scope: Option<String> = inherited.map(str::to_string);
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (key, rest) = line
            .split_once(|c: char| c.is_whitespace() || c == '=')
            .unwrap_or((line, ""));
        let key = key.to_ascii_lowercase();
        let rest = rest.trim_start_matches(|c: char| c.is_whitespace() || c == '=').trim();
        if key == "match" {
            scope = (!rest.eq_ignore_ascii_case("all")).then(|| rest.to_string());
        } else if key == "include" {
            for pattern in rest.split_whitespace() {

                let pattern = if pattern.starts_with('/') {
                    pattern.to_string()
                } else {
                    format!("/etc/ssh/{pattern}")
                };
                for f in expand_glob(&pattern) {
                    walk_matches(&f, scope.as_deref(), out, seen, depth + 1);
                }
            }
        } else if let Some(criteria) = &scope {
            if CONTROLS.iter().any(|c| c.key == key) {
                let value = rest.split_whitespace().next().unwrap_or("").trim_matches('"');
                out.push(Override {
                    key,
                    value: value.to_string(),
                    scope: format!("connections matching `Match {criteria}`"),
                });
            }
        }
    }
}

const LAUNCH_ENV: &[(&str, &str)] = &[("/etc/default/ssh", "SSHD_OPTS"), ("/etc/sysconfig/sshd", "OPTIONS")];

pub fn launch_overrides() -> Vec<Override> {
    LAUNCH_ENV
        .iter()
        .filter_map(|(file, _)| {
            let text = crate::saferead::read_scan_target(Path::new(file))?;
            Some(parse_launch_options(&text, file))
        })
        .flatten()
        .collect()
}

fn parse_launch_options(text: &str, file: &str) -> Vec<Override> {
    let Some(var) = LAUNCH_ENV.iter().find(|(f, _)| *f == file).map(|(_, v)| *v) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for line in text.lines() {
        let Some(value) = line.trim().strip_prefix(var).and_then(|r| r.strip_prefix('=')) else {
            continue;
        };
        let value = value.trim().trim_matches(|c| c == '"' || c == '\'');
        let mut words = value.split_whitespace();
        while let Some(w) = words.next() {
            let opt = match w.strip_prefix("-o") {
                Some("") => words.next(),
                Some(inline) => Some(inline),
                None => None,
            };
            let Some((k, v)) = opt.and_then(|o| o.split_once('=')) else { continue };
            let key = k.trim().to_ascii_lowercase();
            if CONTROLS.iter().any(|c| c.key == key) {
                out.push(Override {
                    key,
                    value: v.trim().to_string(),
                    scope: format!("the daemon's command line (`-o {}={}` in {file})", k.trim(), v.trim()),
                });
            }
        }
    }
    out
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Daemon {
    pid: u32,

    config: Option<String>,

    options: Vec<(String, String)>,

    reexec: bool,
}

fn daemon_args(raw: &[u8]) -> Option<Vec<String>> {
    let parts: Vec<String> =
        raw.split(|b| *b == 0).filter(|p| !p.is_empty()).map(|p| String::from_utf8_lossy(p).into_owned()).collect();
    match parts.as_slice() {
        [title] => {
            let (argv, _) = title.split_once(": ")?.1.split_once(" [listener]")?;
            Some(argv.split_whitespace().skip(1).map(str::to_string).collect())
        }
        [_, args @ ..] => Some(args.to_vec()),
        [] => None,
    }
}

fn daemon(pid: u32, args: &[String]) -> Daemon {
    const WITH_ARG: &str = "CEbcfghkopu";
    let mut d = Daemon { pid, config: None, options: Vec::new(), reexec: false };
    let mut words = args.iter();
    while let Some(w) = words.next() {
        if w == "--" {
            break;
        }
        let Some(letters) = w.strip_prefix('-') else { continue };
        let with_arg = letters.char_indices().find(|(_, c)| WITH_ARG.contains(*c));
        d.reexec |= with_arg.map_or(letters, |(at, _)| letters.get(..at).unwrap_or("")).contains('R');
        let Some((at, letter)) = with_arg else { continue };
        let inline = letters.get(at + letter.len_utf8()..).unwrap_or("");
        let Some(arg) = (if inline.is_empty() { words.next().map(String::as_str) } else { Some(inline) }) else {
            break;
        };
        match letter {
            'f' => d.config = Some(arg.to_string()),
            'o' => {

                let (k, v) = match arg.split_once(|c: char| c == '=' || c.is_whitespace()) {
                    Some((k, v)) => (k.to_string(), v.trim().trim_start_matches('=').trim().to_string()),
                    None => {
                        let mut v = words.next().map_or("", String::as_str).trim_start_matches('=');
                        if v.is_empty() {
                            v = words.next().map_or("", String::as_str);
                        }
                        (arg.to_string(), v.to_string())
                    }
                };
                d.options.push((k.trim().to_ascii_lowercase(), v.trim_matches('"').to_string()));
            }
            _ => {}
        }
    }
    d
}

#[derive(Debug, Default)]
struct Running {

    daemons: Vec<Daemon>,

    unread: Vec<Finding>,
}

fn running_daemons() -> Running {
    let mut out = Running::default();
    let ns = |base: &Path, which: &str| std::fs::read_link(base.join("ns").join(which)).ok();
    let us = Path::new("/proc/self");
    let (Some(our_mnt), Some(our_net)) = (ns(us, "mnt"), ns(us, "net")) else { return out };
    let Ok(rd) = std::fs::read_dir("/proc") else { return out };
    for e in rd.flatten() {
        let Some(pid) = e.file_name().to_str().and_then(|n| n.parse::<u32>().ok()) else { continue };
        let base = PathBuf::from(format!("/proc/{pid}"));
        let Ok(exe) = std::fs::read_link(base.join("exe")) else { continue };
        let exe = exe.to_string_lossy();
        if Path::new(exe.strip_suffix(" (deleted)").unwrap_or(&exe)).file_name() != Some("sshd".as_ref())
            || !std::fs::read(base.join("status")).is_ok_and(|s| runs_as_root(&s))
            || ns(&base, "net").as_ref() != Some(&our_net)
        {
            continue;
        }
        let raw = match crate::saferead::read_proc(&base.join("cmdline"), crate::saferead::MAX_PROC_BYTES) {
            Ok((raw, _)) => raw,

            Err(_) if !base.exists() => continue,
            Err(e) => {
                out.unread.push(unread(
                    pid,
                    format!("an sshd running as root whose command line could not be read ({e}), so its `-o` and `-f` are unknown"),
                ));
                continue;
            }
        };
        let Some(args) = daemon_args(&raw) else { continue };
        let mut d = daemon(pid, &args);
        if d.reexec {
            continue;
        }

        if let (Some(c), Ok(cwd)) = (d.config.as_mut(), std::fs::read_link(base.join("cwd"))) {
            if !c.starts_with('/') {
                *c = cwd.join(&*c).to_string_lossy().into_owned();
            }
        }
        let file = d.config.clone().unwrap_or_else(|| MAIN_CONFIG.to_string());
        if !file.starts_with('/') {
            out.unread.push(unread(
                pid,
                format!("an sshd running as root on `-f {file}`, relative to a working directory that could not be read"),
            ));
            continue;
        }
        if ns(&base, "mnt").as_ref() != Some(&our_mnt) && !same_file_there(&base, &file) {
            out.unread.push(unread(
                pid,
                format!(
                    "an sshd running as root on this host's network, in a mount namespace of its own where \
                     {file} is not this host's file — `unshare -m`, or a host-network container, starts one \
                     on any configuration"
                ),
            ));
            continue;
        }
        out.daemons.push(d);
    }
    out
}

fn runs_as_root(status: &[u8]) -> bool {
    String::from_utf8_lossy(status).lines().find_map(|l| l.strip_prefix("Uid:")).is_some_and(|ids| {
        let mut ids = ids.split_whitespace();
        ids.next() == Some("0") && ids.next() == Some("0")
    })
}

fn same_file_there(base: &Path, file: &str) -> bool {
    use std::os::unix::fs::MetadataExt as _;
    match (std::fs::metadata(base.join("root").join(file.trim_start_matches('/'))), std::fs::metadata(file)) {
        (Ok(there), Ok(here)) => (there.dev(), there.ino()) == (here.dev(), here.ino()),
        _ => false,
    }
}

fn unread(pid: u32, what: String) -> Finding {
    Finding {
        severity: Severity::Warn,
        subject: format!("sshd · pid {pid}"),
        what,
        why: "every control here was judged on this host's config, and this daemon's — \
              PermitRootLogin among them — is unchecked"
            .into(),
    }
}

fn split_daemons(daemons: Vec<Daemon>) -> (Vec<Override>, Vec<Daemon>) {
    let mut main: Vec<Override> = Vec::new();
    let mut elsewhere = Vec::new();
    for d in daemons {
        if d.config.as_deref().is_some_and(|c| Path::new(c) != Path::new(MAIN_CONFIG)) {
            elsewhere.push(d);
            continue;
        }
        for (k, v) in &d.options {
            let Some(c) = CONTROLS.iter().find(|c| c.key == k) else { continue };
            if !main.iter().any(|o| &o.key == k && &o.value == v) {
                main.push(Override {
                    key: k.clone(),
                    value: v.clone(),
                    scope: format!("the running daemon's command line (`-o {}={v}`, pid {})", c.spelling, d.pid),
                });
            }
        }
    }
    (main, elsewhere)
}

fn elsewhere_findings(d: &Daemon) -> Vec<Finding> {
    let Some(file) = d.config.as_deref() else { return Vec::new() };
    let on = format!("the sshd running as pid {}, which reads {file} rather than {MAIN_CONFIG}", d.pid);
    let unchecked = |what: String| {
        vec![Finding {
            severity: Severity::Warn,
            subject: format!("sshd · pid {}", d.pid),
            what: format!("reads {file} rather than {MAIN_CONFIG}, and {what}"),
            why: "every control here was judged on the main config, so this daemon's settings — \
                  PermitRootLogin among them — are unchecked. A file it was started on that \
                  no longer parses, is gone, or is not a file at all is worth a look of its own"
                .into(),
        }]
    };
    let config = match crate::saferead::open_regular(Path::new(file), crate::saferead::NOT_REGULAR) {
        Ok((f, _)) => f,
        Err(e) if e.kind() == std::io::ErrorKind::InvalidInput => {
            return unchecked("it is not a regular file, so it was not opened".into());
        }
        Err(e) => return unchecked(format!("it could not be opened here ({e})")),
    };
    let eff = run_t(&["-f", "/proc/self/fd/0"], Some(config));
    let r = from_effective(&eff);
    if !r.available {
        return unchecked(format!("`sshd -T -f {file}` failed"));
    }
    let listed = |key: &str| eff.values.get(key).map(|v| v.join(", ")).filter(|v| !v.is_empty());
    let mut what = vec![format!("reads {file} rather than {MAIN_CONFIG}")];
    what.extend(listed("port").map(|p| format!("listens on port {p}")));
    what.extend(listed("authorizedkeysfile").map(|k| format!("takes keys from {k}")));
    let mut out = vec![Finding {
        severity: Severity::Note,
        subject: format!("sshd · pid {}", d.pid),
        what: what.join(", "),
        why: "its controls were judged on that file, and any that fail are listed beside this. A \
              daemon on a config of its own picks its own port, host keys and AuthorizedKeysFile: \
              an SFTP-only or jump instance is run that way, and so is a backdoor listener. \
              Confirm whose it is"
            .into(),
    }];
    out.extend(r.findings.into_iter().map(|mut f| {
        f.what = format!("{} on {on}", f.what);
        f
    }));
    let mut overrides = match_overrides(Path::new(file));
    for o in &mut overrides {
        o.scope = format!("{} on {on}", o.scope);
    }
    overrides.extend(d.options.iter().filter(|(k, _)| CONTROLS.iter().any(|c| c.key == k)).map(|(k, v)| Override {
        key: k.clone(),
        value: v.clone(),
        scope: format!("the command line of {on}"),
    }));
    out.extend(override_findings(&eff, &overrides));
    out
}

pub fn override_findings(eff: &Effective, overrides: &[Override]) -> Vec<Finding> {
    let mut out = Vec::new();
    for o in overrides {
        let Some(c) = CONTROLS.iter().find(|c| c.key == o.key) else { continue };
        if eff.one(c.key).is_some_and(|v| judge(c, v).is_some()) {
            continue;
        }
        let Some(actual) = judge(c, &o.value) else { continue };
        out.push(Finding {
            severity: severity_for(c, &o.value),
            subject: format!("sshd · {}", c.spelling),
            what: format!(
                "{} is {} for {} (should be {})",
                c.spelling,
                actual,
                o.scope,
                wanted_value(c)
            ),
            why: format!(
                "{}. `sshd -T` reports the global value, and this is not it: a Match block \
                 overrides it for the connections it names, and a `-o` overrides it for all \
                 of them. A drop-in cannot change either; edit it where it is",
                c.why
            ),
        });
    }
    out
}

pub fn from_effective(eff: &Effective) -> Report {
    if let Ground::Unavailable(why) = &eff.ground {
        return Report { findings: Vec::new(), available: false, reason: Some(why.clone()) };
    }

    let mut findings = Vec::new();
    for c in CONTROLS {

        let Some(value) = eff.one(c.key) else { continue };
        if let Some(actual) = judge(c, value) {
            findings.push(Finding {
                severity: severity_for(c, value),
                subject: format!("sshd · {}", c.spelling),
                what: format!("{} is {} (should be {})", c.spelling, actual, wanted_value(c)),
                why: format!("{}. Applying this costs: {}", c.why, c.breaks),
            });
        }
    }
    Report { findings, available: true, reason: None }
}

pub fn parse_order(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    walk_config(root, &mut out, 0);
    out
}

fn walk_config(path: &Path, out: &mut Vec<PathBuf>, depth: u32) {
    if depth > 16 || out.iter().any(|p| p == path) {
        return;
    }
    let Some(text) = crate::saferead::read_scan_target(path) else { return };
    out.push(path.to_path_buf());

    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('#') {
            continue;
        }
        let lower = line.to_ascii_lowercase();
        if lower.starts_with("match ") {

            break;
        }
        if let Some(rest) = lower.strip_prefix("include ") {
            let pattern = line[line.len() - rest.len()..].trim();
            for f in expand_glob(pattern) {
                walk_config(&f, out, depth + 1);
            }
        }
    }
}

pub fn expand_glob(pattern: &str) -> Vec<PathBuf> {
    let p = Path::new(pattern);
    if !pattern.contains('*') {
        return if p.is_file() { vec![p.to_path_buf()] } else { Vec::new() };
    }
    let (Some(dir), Some(name)) = (p.parent(), p.file_name().and_then(|n| n.to_str())) else {
        return Vec::new();
    };
    let Some((prefix, suffix)) = name.split_once('*') else { return Vec::new() };
    let Ok(entries) = std::fs::read_dir(dir) else { return Vec::new() };
    let mut files: Vec<PathBuf> = entries
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|f| f.is_file())
        .filter(|f| {
            f.file_name().and_then(|n| n.to_str()).is_some_and(|n| {
                n.starts_with(prefix) && n.ends_with(suffix) && n.len() >= prefix.len() + suffix.len()
            })
        })
        .collect();
    files.sort();
    files
}

pub const MAIN_CONFIG: &str = "/etc/ssh/sshd_config";

pub const DROP_IN: &str = "00-hemostat-hardening.conf";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Staged {

    pub file: PathBuf,

    pub line: String,

    pub created: bool,

    pub confirmed: String,

    pub previous: Option<String>,

    pub body: String,
}

fn dropin_dir(root: &Path) -> Option<PathBuf> {
    let text = crate::saferead::read_scan_target(root)?;
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('#') {
            continue;
        }
        let lower = line.to_ascii_lowercase();

        if lower.starts_with("match ") {
            return None;
        }
        if let Some(rest) = lower.strip_prefix("include ") {
            let pattern = line[line.len() - rest.len()..].trim();
            let dir = Path::new(pattern).parent()?;
            if dir.is_dir() {
                return Some(dir.to_path_buf());
            }
        }
    }
    None
}

pub fn stage(spelling: &str, value: &str) -> Result<Staged, String> {

    let mut overrides = launch_overrides();
    overrides.extend(split_daemons(running_daemons().daemons).0);
    if let Some(o) = overrides.into_iter().find(|o| blocks(o, spelling, value)) {
        return Err(format!(
            "{spelling} is set to {} on {}, which wins over every config file — a drop-in \
             cannot change it. Remove it there by hand",
            o.value, o.scope
        ));
    }
    stage_in(Path::new(MAIN_CONFIG), &[], spelling, value)
}

fn blocks(o: &Override, spelling: &str, value: &str) -> bool {
    if !o.key.eq_ignore_ascii_case(spelling) || o.value.eq_ignore_ascii_case(value) {
        return false;
    }
    match CONTROLS.iter().find(|c| c.key == o.key) {
        Some(c) => judge(c, &o.value).is_some(),
        None => true,
    }
}

pub fn stage_in(
    root: &Path,
    extra: &[&str],
    spelling: &str,
    value: &str,
) -> Result<Staged, String> {

    let ok = |s: &str| !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric() || " .,:@/_-".contains(c));
    if !ok(spelling) || !ok(value) {
        return Err(format!("refusing to write `{spelling} {value}`: unexpected characters"));
    }

    let before = effective_with(extra);
    if let Ground::Unavailable(why) = &before.ground {
        return Err(format!(
            "will not write a config that cannot be checked afterwards: {why}"
        ));
    }

    let Some(dir) = dropin_dir(root) else {
        return Err(format!(
            "{} has no `Include` line above its first `Match` block, so a drop-in would never \
             be read. Set `{spelling} {value}` in it by hand — editing the main config is a \
             bigger decision than a keypress",
            root.display()
        ));
    };

    if let Some(m) = match_overrides(root).into_iter().find(|o| blocks(o, spelling, value)) {
        return Err(format!(
            "{spelling} is set to {} for {}, and a Match block overrides every global setting \
             for the connections it names — a drop-in cannot change it, and `sshd -T` without \
             a connection would confirm a value those logins never get. Change it in that block \
             by hand",
            m.value, m.scope
        ));
    }

    let file = dir.join(DROP_IN);
    let previous = read_dropin(&file)?;
    let created = previous.is_none();

    let mut lines: Vec<String> = previous
        .as_deref()
        .unwrap_or("")
        .lines()
        .filter(|l| {
            !l.trim()
                .to_ascii_lowercase()
                .starts_with(&format!("{} ", spelling.to_ascii_lowercase()))
        })
        .map(str::to_string)
        .collect();
    if lines.is_empty() {
        lines.push("# Written by HEMOSTAT. Each line was verified with `sshd -T` after".into());
        lines.push("# being written. Delete this file to undo all of it.".into());
    }
    lines.push(format!("{spelling} {value}"));
    let body = format!("{}
", lines.join("
"));

    write_dropin(&file, &body, created)
        .map_err(|e| format!("could not write {}: {e}", file.display()))?;

    let after = effective_with(extra);

    let rollback = || -> String {
        let r = match &previous {
            Some(old) => write_dropin(&file, old, false),
            None => match std::fs::symlink_metadata(&file) {
                Ok(m) if m.file_type().is_file() => std::fs::remove_file(&file),
                Ok(_) => Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "it is no longer the regular file this wrote",
                )),
                Err(e) => Err(e),
            },
        };
        match r {
            Ok(()) => " It has been rolled back and nothing was changed.".to_string(),
            Err(e) => format!(
                " THE ROLLBACK ALSO FAILED ({e}): {} is still on the host and still in \
                 sshd's parse order. Remove or restore it by hand before relying on this \
                 daemon's configuration.",
                file.display()
            ),
        }
    };

    match &after.ground {
        Ground::Unavailable(why) => {
            let note = rollback();
            Err(format!("the write made sshd's config unreadable ({why}).{note}"))
        }
        Ground::Resolved => {
            let key = spelling.to_ascii_lowercase();
            match after.one(&key) {
                Some(now) if now.eq_ignore_ascii_case(value) => Ok(Staged {
                    file,
                    line: format!("{spelling} {value}"),
                    created,
                    confirmed: now.to_string(),
                    previous: previous.clone(),
                    body: body.clone(),
                }),
                Some(now) => {
                    let note = rollback();
                    Err(format!(
                        "the drop-in was written but `sshd -T` still reports {spelling} = {now}. Something earlier in the parse order sets it and wins, because OpenSSH takes the FIRST value it obtains, not the last.{note} Find the earlier setting in: {}",
                        parse_order(root)
                            .iter()
                            .map(|p| p.display().to_string())
                            .collect::<Vec<_>>()
                            .join(", ")
                    ))
                }
                None => {
                    let note = rollback();
                    Err(format!(
                        "`sshd -T` does not report {spelling} at all after the write — this build of OpenSSH may not support it.{note}"
                    ))
                }
            }
        }
    }
}

fn read_dropin(file: &Path) -> Result<Option<String>, String> {
    use std::io::Read as _;
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};

    let refuse = |why: String| {
        format!(
            "refusing to stage into {}: {why}. A link or special file at the name this tool \
             writes is how a config write lands in another file; look at what it is, and \
             remove it, before staging",
            file.display()
        )
    };
    let f = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW)
        .open(file)
    {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(refuse(format!("it could not be opened without following a link ({e})"))),
    };
    let md = f.metadata().map_err(|e| refuse(e.to_string()))?;
    if !md.is_file() || md.len() > crate::saferead::MAX_SCAN_BYTES {
        return Err(refuse("it is not a regular file of a size this wrote".into()));
    }
    if md.nlink() > 1 {
        return Err(refuse(format!(
            "it is one of {} hard links to the same file, and a write here rewrites all of them",
            md.nlink()
        )));
    }
    let mut buf = Vec::new();
    (&f).read_to_end(&mut buf).map_err(|e| refuse(e.to_string()))?;
    Ok(Some(String::from_utf8_lossy(&buf).into_owned()))
}

fn write_dropin(file: &Path, body: &str, create: bool) -> std::io::Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};

    let mut o = std::fs::OpenOptions::new();
    o.write(true).custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW);
    if create {
        o.create_new(true).mode(0o644);
    }
    let mut f = o.open(file)?;
    let md = f.metadata()?;
    if !md.is_file() {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "not a regular file"));
    }
    if md.nlink() > 1 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "it has another hard link, which a write here would rewrite too",
        ));
    }
    f.set_len(0)?;
    f.write_all(body.as_bytes())
}
