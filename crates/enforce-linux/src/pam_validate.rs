use std::io::{Read as _, Write as _};
use std::os::unix::fs::MetadataExt as _;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const USERADD: &[&str] = &["/usr/sbin/useradd", "/sbin/useradd"];
const CHPASSWD: &[&str] = &["/usr/sbin/chpasswd", "/sbin/chpasswd"];
const USERDEL: &[&str] = &["/usr/sbin/userdel", "/sbin/userdel"];
const SU: &[&str] = &["/usr/bin/su", "/bin/su"];

const CHILD_PATH: &str = "/usr/sbin:/usr/bin:/sbin:/bin";

struct Tools {
    useradd: PathBuf,
    chpasswd: PathBuf,
    userdel: PathBuf,
    su: PathBuf,
}

impl Tools {
    fn find() -> Result<Tools, String> {
        Ok(Tools {
            useradd: system_tool(USERADD, false)?,
            chpasswd: system_tool(CHPASSWD, false)?,
            userdel: system_tool(USERDEL, false)?,
            su: system_tool(SU, true)?,
        })
    }
}

fn system_tool(candidates: &[&str], setuid: bool) -> Result<PathBuf, String> {
    let path = candidates
        .iter()
        .map(Path::new)
        .find(|p| p.symlink_metadata().is_ok())
        .ok_or_else(|| format!("none of {} is there", candidates.join(", ")))?;
    let f = crate::paths::open_unredirected(path)
        .map_err(|e| format!("{} could not be opened without being redirected: {e}", path.display()))?;
    let md = f.metadata().map_err(|e| format!("{}: {e}", path.display()))?;
    match tool_refusal(md.is_file(), md.uid(), md.mode(), setuid) {
        Some(why) => Err(format!("{} {why}, so it is not run", path.display())),
        None => Ok(path.to_path_buf()),
    }
}

fn tool_refusal(is_file: bool, uid: u32, mode: u32, setuid: bool) -> Option<String> {
    if !is_file {
        return Some("is not a regular file".into());
    }
    if uid != 0 {
        return Some(format!("is owned by uid {uid}, not root"));
    }
    if mode & 0o022 != 0 {
        return Some(format!("can be written by its group or others (mode {:o})", mode & 0o7777));
    }
    if setuid && mode & 0o4000 == 0 {
        return Some(format!(
            "is not setuid (mode {:o}), so run from an unprivileged account it cannot check a \
             password",
            mode & 0o7777
        ));
    }
    None
}

fn clean(cmd: &mut Command) -> &mut Command {
    cmd.env_clear().env("PATH", CHILD_PATH).env("LC_ALL", "C").env("LANG", "C")
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Probe {

    Works,

    Rejects,

    AcceptsAnyPassword,

    Unavailable(String),
}

impl Probe {

    pub fn describe(&self) -> String {
        match self {
            Probe::Works => {
                "a test login with the right password succeeded and a wrong password was refused"
                    .into()
            }
            Probe::Rejects => "a test login with the right password was REJECTED".into(),
            Probe::AcceptsAnyPassword => {
                "a test login WITHOUT the right password was ACCEPTED — this PAM stack lets \
                 anyone in"
                    .into()
            }
            Probe::Unavailable(why) => format!("the live test could not run: {why}"),
        }
    }

    pub fn can_gate(&self) -> bool {
        matches!(self, Probe::Works | Probe::AcceptsAnyPassword)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AfterSwap {

    Ungated,

    Keep,

    KeepStillOpen,

    RollBack,
}

pub fn after_swap(before: &Probe, after: &Probe) -> AfterSwap {
    if !before.can_gate() {
        return AfterSwap::Ungated;
    }
    match (before, after) {
        (_, Probe::Works) => AfterSwap::Keep,
        (Probe::AcceptsAnyPassword, Probe::AcceptsAnyPassword) => AfterSwap::KeepStillOpen,
        _ => AfterSwap::RollBack,
    }
}

pub fn probe() -> Probe {
    let tools = match Tools::find() {
        Ok(t) => t,
        Err(why) => return Probe::Unavailable(why),
    };
    let caller = match unprivileged_caller() {
        Ok(c) => c,
        Err(why) => return Probe::Unavailable(why),
    };
    let password = random_password();
    let wrong = wrong_password(&password);
    let user = match make_canary(&tools, &password) {
        Ok(u) => u,
        Err(why) => return Probe::Unavailable(why),
    };
    let right = su_attempt(&tools.su, caller, &user, &password);

    let control = matches!(&right, Ok(a) if a.took_the_password())
        .then(|| su_attempt(&tools.su, caller, &user, &wrong));
    remove_canary(&tools, &user);
    verdict(&right, control.as_ref())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Attempt {

    prompted: bool,

    fed: bool,

    succeeded: bool,
}

impl Attempt {

    fn took_the_password(self) -> bool {
        self.prompted && self.fed && self.succeeded
    }

    fn refused_the_password(self) -> bool {
        self.prompted && self.fed && !self.succeeded
    }
}

fn verdict(right: &Result<Attempt, String>, wrong: Option<&Result<Attempt, String>>) -> Probe {
    let right = match right {
        Ok(a) => *a,
        Err(why) => return Probe::Unavailable(why.clone()),
    };
    if right.succeeded && !right.took_the_password() {
        return Probe::AcceptsAnyPassword;
    }
    if right.refused_the_password() {
        return Probe::Rejects;
    }
    if !right.took_the_password() {
        return Probe::Unavailable(if right.prompted {
            "the password could not be written to su".into()
        } else {
            "su ended without asking for a password, so no password was tested".into()
        });
    }
    match wrong {
        None => Probe::Unavailable("the wrong-password check did not run".into()),
        Some(Err(why)) => Probe::Unavailable(format!("the wrong-password check could not run: {why}")),
        Some(Ok(w)) if w.succeeded => Probe::AcceptsAnyPassword,
        Some(Ok(w)) if w.refused_the_password() => Probe::Works,
        Some(Ok(_)) => Probe::Unavailable(
            "the wrong-password check ended before a password was given, so a wrong one was \
             never refused"
                .into(),
        ),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Caller {
    uid: u32,
    gid: u32,
}

const NOBODY: Caller = Caller { uid: 65534, gid: 65534 };

fn unprivileged_caller() -> Result<Caller, String> {
    caller_from_passwd(
        hemostat_sensor_linux::saferead::read_scan_target(Path::new("/etc/passwd")).as_deref(),
    )
}

fn caller_from_passwd(passwd: Option<&str>) -> Result<Caller, String> {
    let line = passwd.and_then(|t| t.lines().find(|l| l.split(':').next() == Some("nobody")));
    let c = line
        .and_then(|l| {
            let mut f = l.split(':').skip(2);
            Some(Caller { uid: f.next()?.parse().ok()?, gid: f.next()?.parse().ok()? })
        })
        .unwrap_or(NOBODY);
    if c.uid == 0 || c.gid == 0 {
        return Err(format!(
            "`nobody` is uid {} gid {} here, which is root's, so su run as it would not be \
             an unprivileged login",
            c.uid, c.gid
        ));
    }
    Ok(c)
}

fn random_password() -> String {
    let mut buf = [0u8; 18];
    if std::fs::File::open("/dev/urandom").and_then(|mut f| f.read_exact(&mut buf)).is_err() {
        let t = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_nanos());
        return format!("{}{t:x}", std::process::id());
    }
    buf.iter().map(|b| format!("{b:02x}")).collect()
}

fn wrong_password(right: &str) -> String {
    differ_from_the_start(random_password(), right)
}

fn differ_from_the_start(candidate: String, right: &str) -> String {
    let first = candidate.chars().next();
    if first.is_some() && first != right.chars().next() {
        return candidate;
    }
    let lead = if right.starts_with('x') { 'y' } else { 'x' };
    format!("{lead}{}", candidate.chars().skip(1).collect::<String>())
}

static PROBES: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

fn canary_name(pid: u32, n: u32) -> String {
    format!("hemostat-pamck-{pid}-{}", n % 1000)
}

const ACCOUNT_LIMIT: Duration = Duration::from_secs(30);

fn run_within(cmd: &mut Command, stdin: Stdio, what: &str) -> Result<std::process::Output, String> {
    run_bounded(cmd, stdin, what, ACCOUNT_LIMIT)
}

fn run_bounded(cmd: &mut Command, stdin: Stdio, what: &str, limit: Duration) -> Result<std::process::Output, String> {
    match hemostat_sensor_linux::sshd::output_within(cmd, stdin, limit) {
        Ok(Some(out)) => Ok(out),
        Ok(None) => Err(format!("{what} had not finished after {limit:?}, and was stopped")),
        Err(e) => Err(format!("{what}: {e}")),
    }
}

fn make_canary(tools: &Tools, password: &str) -> Result<String, String> {
    let n = PROBES.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let user = canary_name(std::process::id(), n);
    let _ = run_within(clean(&mut Command::new(&tools.userdel)).args(["-f", &user]), Stdio::null(), "userdel");
    let add = match run_within(
        clean(&mut Command::new(&tools.useradd)).args(["-M", "-s", "/bin/sh", &user]),
        Stdio::null(),
        "useradd",
    ) {
        Ok(out) => out,
        Err(why) => {

            remove_canary(tools, &user);
            return Err(why);
        }
    };
    if !add.status.success() {
        return Err(format!("useradd failed: {}", String::from_utf8_lossy(&add.stderr).trim()));
    }

    if let Err(why) = set_password(tools, &user, password) {
        remove_canary(tools, &user);
        return Err(why);
    }
    Ok(user)
}

fn set_password(tools: &Tools, user: &str, password: &str) -> Result<(), String> {
    let (line, mut feed) = std::io::pipe().map_err(|e| format!("chpasswd pipe: {e}"))?;
    feed.write_all(format!("{user}:{password}\n").as_bytes()).map_err(|e| format!("chpasswd write: {e}"))?;
    drop(feed);
    let out = run_within(clean(&mut Command::new(&tools.chpasswd)), Stdio::from(line), "chpasswd")?;
    if !out.status.success() {
        return Err(format!("chpasswd failed: {}", String::from_utf8_lossy(&out.stderr).trim()));
    }
    Ok(())
}

pub fn set_and_prove(user: &str, password: &str) -> Result<Probe, String> {
    if user.contains([':', '\n']) || password.contains([':', '\n']) {
        return Err("a name or password with ':' or a line break, which chpasswd cannot carry".into());
    }
    let tools = Tools::find()?;
    let caller = unprivileged_caller()?;
    set_password(&tools, user, password)?;
    let right = su_attempt(&tools.su, caller, user, password);
    let control = matches!(&right, Ok(a) if a.took_the_password())
        .then(|| su_attempt(&tools.su, caller, user, &wrong_password(password)));
    clear_failures(user);
    Ok(verdict(&right, control.as_ref()))
}

pub fn restore_hash(user: &str, hash: &str) -> Result<(), String> {
    if user.contains([':', '\n']) || hash.contains([':', '\n']) || hash.is_empty() {
        return Err("a name or hash that chpasswd cannot carry, or an empty hash".into());
    }
    let tools = Tools::find()?;
    let (line, mut feed) = std::io::pipe().map_err(|e| format!("chpasswd pipe: {e}"))?;
    feed.write_all(format!("{user}:{hash}\n").as_bytes()).map_err(|e| format!("chpasswd write: {e}"))?;
    drop(feed);
    let out = run_within(clean(&mut Command::new(&tools.chpasswd)).arg("-e"), Stdio::from(line), "chpasswd -e")?;
    if !out.status.success() {
        return Err(format!("chpasswd -e failed: {}", String::from_utf8_lossy(&out.stderr).trim()));
    }
    Ok(())
}

fn clear_failures(user: &str) {
    if let Ok(faillock) = system_tool(FAILLOCK, false) {
        let _ = run_within(
            clean(&mut Command::new(faillock)).args(["--user", user, "--reset"]),
            Stdio::null(),
            "faillock",
        );
    }
}

const FAILLOCK: &[&str] = &["/usr/sbin/faillock", "/sbin/faillock"];

fn remove_canary(tools: &Tools, user: &str) {
    let _ = run_within(clean(&mut Command::new(&tools.userdel)).args(["-f", user]), Stdio::null(), "userdel");
}

fn su_attempt(su: &Path, caller: Caller, user: &str, password: &str) -> Result<Attempt, String> {

    const SEEN_CAP: usize = 64 * 1024;

    const ATTEMPT_LIMIT: Duration = Duration::from_secs(15);

    const ECHO_WAIT: Duration = Duration::from_secs(1);

    let mut master: RawFd = -1;
    let mut slave: RawFd = -1;

    if unsafe { libc::openpty(&mut master, &mut slave, std::ptr::null_mut(), std::ptr::null(), std::ptr::null()) } != 0 {
        return Err(format!("openpty: {}", std::io::Error::last_os_error()));
    }

    unsafe {
        let fl = libc::fcntl(master, libc::F_GETFD);
        if fl != -1 {
            libc::fcntl(master, libc::F_SETFD, fl | libc::FD_CLOEXEC);
        }
    }

    let slave_fd = slave;
    let mut cmd = Command::new(su);
    clean(&mut cmd).arg(user).arg("-c").arg("/bin/true");

    cmd.uid(caller.uid).gid(caller.gid);

    unsafe {
        cmd.pre_exec(move || {

            if libc::setsid() == -1 {
                return Err(std::io::Error::last_os_error());
            }

            libc::ioctl(slave_fd, libc::TIOCSCTTY, 0);
            for fd in 0..3 {
                if libc::dup2(slave_fd, fd) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            if slave_fd > 2 {
                libc::close(slave_fd);
            }
            Ok(())
        });
    }
    let spawned = cmd.spawn();

    unsafe {
        libc::close(slave);
    }
    let mut child = match spawned {
        Ok(c) => c,
        Err(e) => {

            unsafe { libc::close(master) };
            return Err(format!("spawn su: {e}"));
        }
    };

    let mut m = unsafe { std::fs::File::from_raw_fd(master) };
    set_nonblocking(m.as_raw_fd());

    let deadline = Instant::now() + ATTEMPT_LIMIT;
    let mut seen: Vec<u8> = Vec::new();

    let mut prompt_at: Option<Instant> = None;
    let mut answered = false;
    let mut fed = false;
    let mut buf = [0u8; 4096];
    let status = loop {
        if let Ok(n) = m.read(&mut buf) {
            if let Some(got) = buf.get(..n).filter(|_| seen.len() < SEEN_CAP) {
                seen.extend_from_slice(got);
            }
            if prompt_at.is_none() && contains_ci(&seen, b"assword") {
                prompt_at = Some(Instant::now());
            }
        }

        if let Some(at) = prompt_at.filter(|_| !answered) {
            if echo_is_off(m.as_raw_fd()) || at.elapsed() >= ECHO_WAIT {
                answered = true;
                fed = m
                    .write_all(password.as_bytes())
                    .and_then(|()| m.write_all(b"\n"))
                    .and_then(|()| m.flush())
                    .is_ok();
            }
        }
        match child.try_wait() {
            Ok(Some(st)) => break Some(st),
            Ok(None) => {}
            Err(_) => break None,
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            break None;
        }
        std::thread::sleep(Duration::from_millis(40));
    };
    match status {
        Some(st) => Ok(Attempt { prompted: prompt_at.is_some(), fed, succeeded: st.success() }),
        None => Err(format!(
            "su did not finish within {} s (timed out, or its prompt never came)",
            ATTEMPT_LIMIT.as_secs()
        )),
    }
}

fn echo_is_off(fd: RawFd) -> bool {
    let mut t = std::mem::MaybeUninit::<libc::termios>::uninit();

    if unsafe { libc::tcgetattr(fd, t.as_mut_ptr()) } != 0 {
        return false;
    }

    let t = unsafe { t.assume_init() };
    t.c_lflag & libc::ECHO == 0
}

fn set_nonblocking(fd: RawFd) {

    unsafe {
        let fl = libc::fcntl(fd, libc::F_GETFL);
        if fl != -1 {
            libc::fcntl(fd, libc::F_SETFL, fl | libc::O_NONBLOCK);
        }
    }
}

fn contains_ci(hay: &[u8], needle: &[u8]) -> bool {
    needle.len() <= hay.len() && hay.windows(needle.len()).any(|w| w.eq_ignore_ascii_case(needle))
}
