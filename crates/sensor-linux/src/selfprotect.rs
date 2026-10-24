use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};

use crate::btf;
use crate::bpfabi::{ProgLoadAttr, LinkCreateAttr};

const BPF_PROG_LOAD: i32 = 5;
const BPF_LINK_CREATE: i32 = 28;
const BPF_PROG_TYPE_LSM: u32 = 29;
const BPF_LSM_MAC: u32 = 27;

const HOOK: &str = "bpf_lsm_task_kill";

pub(crate) const PROG_NAME: &str = "hemostat_deny";

const TASK_STRUCT: &str = "task_struct";
const TGID: &str = "tgid";

const HELPER_GET_CURRENT_PID_TGID: i32 = 14;

const DENIED_SIGNALS: u32 = (1 << libc::SIGINT)
    | (1 << libc::SIGQUIT)
    | (1 << libc::SIGKILL)
    | (1 << libc::SIGTERM)
    | (1 << libc::SIGSTOP);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArmStage {

    BtfRead,

    HookLookup,

    FieldLookup,

    Load,

    Link,

    ShutdownPath,
}

impl ArmStage {

    pub fn token(self) -> &'static str {
        match self {
            ArmStage::BtfRead => "btf-read",
            ArmStage::HookLookup => "hook-lookup",
            ArmStage::FieldLookup => "field-lookup",
            ArmStage::Load => "load",
            ArmStage::Link => "link",
            ArmStage::ShutdownPath => "shutdown-path",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArmError {

    pub stage: ArmStage,

    pub errno: i32,

    pub verifier_log: Option<String>,
}

#[derive(Debug)]
pub struct Armed {
    #[allow(dead_code)]
    prog: OwnedFd,
    #[allow(dead_code)]
    link: OwnedFd,

    pub target: u32,

    pub tgid_offset: u32,
}

fn program(target: u32, tgid_offset: u32) -> [u8; 16 * 8] {

    const fn insn(op: u8, dst: u8, src: u8, off: i16, imm: i32) -> [u8; 8] {
        let regs = dst | (src << 4);
        let off = off.to_le_bytes();
        let imm = imm.to_le_bytes();
        [op, regs, off[0], off[1], imm[0], imm[1], imm[2], imm[3]]
    }

    const ALU64: u8 = 0x07;
    const JMP: u8 = 0x05;
    const LDX: u8 = 0x01;
    const MEM: u8 = 0x60;
    const DW: u8 = 0x18;
    const W: u8 = 0x00;
    const X: u8 = 0x08;
    const MOV: u8 = 0xb0;
    const LSH: u8 = 0x60;
    const RSH: u8 = 0x70;
    const AND: u8 = 0x50;
    const JEQ: u8 = 0x10;
    const JNE: u8 = 0x50;
    const CALL: u8 = 0x80;
    const EXIT: u8 = 0x90;

    let off = i16::try_from(tgid_offset).unwrap_or(i16::MAX);
    let target = i32::try_from(target).unwrap_or(i32::MAX);

    let insns: [[u8; 8]; 16] = [
        insn(ALU64 | MOV | X, 6, 1, 0, 0),
        insn(ALU64 | MOV, 9, 0, 0, 0),
        insn(LDX | MEM | DW, 1, 6, 0, 0),
        insn(LDX | MEM | W, 7, 1, off, 0),
        insn(JMP | JNE, 7, 0, 9, target),
        insn(LDX | MEM | DW, 8, 6, 16, 0),
        insn(ALU64 | MOV, 1, 0, 0, 1),
        insn(ALU64 | LSH | X, 1, 8, 0, 0),
        insn(ALU64 | AND, 1, 0, 0, DENIED_SIGNALS as i32),
        insn(JMP | JEQ, 1, 0, 4, 0),
        insn(JMP | CALL, 0, 0, 0, HELPER_GET_CURRENT_PID_TGID),
        insn(ALU64 | RSH, 0, 0, 0, 32),
        insn(JMP | JEQ, 0, 0, 1, 1),
        insn(ALU64 | MOV, 9, 0, 0, -1),
        insn(ALU64 | MOV | X, 0, 9, 0, 0),
        insn(JMP | EXIT, 0, 0, 0, 0),
    ];

    let mut out = [0u8; 16 * 8];
    for (slot, byte) in out.iter_mut().zip(insns.iter().flatten()) {
        *slot = *byte;
    }
    out
}

unsafe fn bpf(cmd: i32, attr: *const core::ffi::c_void, size: u32) -> i64 {

    unsafe { libc::syscall(libc::SYS_bpf, cmd, attr, size) }
}

fn last_errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

pub fn shutdown_reaches_the_exempt_sender(
    pid1_comm: &str,
    container: Option<&str>,
) -> Result<(), String> {
    if let Some(kind) = container {
        let kind = kind.trim();
        return Err(format!(
            "this host is a {} container: the init that stops this process is the \
             container's PID 1, not tgid 1 of the initial namespace, so the one sender the \
             deny exempts is not the one that will try to shut us down",
            if kind.is_empty() { "detected" } else { kind }
        ));
    }

    if pid1_comm.trim() != "systemd" {
        return Err(format!(
            "PID 1 on this host is `{}`, not systemd. The deny exempts only tgid 1 of the \
             initial PID namespace, and on sysvinit, OpenRC, runit and s6 the shutdown \
             broadcast comes from `killall5` or a supervisor run as a child of an rc \
             script — outside the exemption. An armed agent would refuse those signals and \
             stay alive into the unmount phase (§7.6.2, §16)",
            pid1_comm.trim()
        ));
    }
    Ok(())
}

fn shutdown_path_evidence() -> (String, Option<String>) {
    let comm = std::fs::read_to_string("/proc/1/comm")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "unreadable".to_string());

    let container = crate::saferead::read_scan_target(std::path::Path::new(
        "/run/systemd/container",
    ))
    .map(|s| s.trim().to_string());
    (comm, container)
}

pub fn arm_resident(target: u32) -> Result<Armed, ArmError> {
    let (comm, container) = shutdown_path_evidence();
    if let Err(why) = shutdown_reaches_the_exempt_sender(&comm, container.as_deref()) {
        return Err(ArmError {
            stage: ArmStage::ShutdownPath,
            errno: libc::EPERM,
            verifier_log: Some(why),
        });
    }
    arm(target)
}

pub fn arm(target: u32) -> Result<Armed, ArmError> {
    if target <= 1 {
        return Err(ArmError { stage: ArmStage::Load, errno: libc::EINVAL, verifier_log: None });
    }

    let blob = btf::vmlinux()
        .map_err(|errno| ArmError { stage: ArmStage::BtfRead, errno, verifier_log: None })?;
    let btf_id = btf::func_id(&blob, HOOK).map_err(|why| ArmError {
        stage: ArmStage::HookLookup,
        errno: not_found_errno(&why),
        verifier_log: None,
    })?;
    let tgid_offset =
        btf::member_offset(&blob, TASK_STRUCT, TGID).map_err(|why| ArmError {
            stage: ArmStage::FieldLookup,
            errno: not_found_errno(&why),
            verifier_log: None,
        })?;

    let insns = program(target, tgid_offset);
    let license = c"GPL";
    let mut name = [0u8; 16];
    for (slot, byte) in name.iter_mut().zip(PROG_NAME.as_bytes()) {
        *slot = *byte;
    }

    let attr = ProgLoadAttr {
        prog_type: BPF_PROG_TYPE_LSM,
        insn_cnt: (insns.len() / 8) as u32,
        insns: insns.as_ptr() as u64,
        license: license.as_ptr() as u64,
        prog_name: name,
        expected_attach_type: BPF_LSM_MAC,
        attach_btf_id: btf_id,
        ..Default::default()
    };

    let prog = unsafe {
        bpf(
            BPF_PROG_LOAD,
            std::ptr::addr_of!(attr).cast(),
            core::mem::size_of::<ProgLoadAttr>() as u32,
        )
    };
    if prog < 0 {
        let errno = last_errno();

        return Err(ArmError { stage: ArmStage::Load, errno, verifier_log: verifier_log(&attr) });
    }

    let prog = unsafe { OwnedFd::from_raw_fd(prog as i32) };

    let link_attr = LinkCreateAttr {
        prog_fd: prog.as_raw_fd() as u32,
        target_fd: 0,
        attach_type: BPF_LSM_MAC,
        flags: 0,
    };

    let link = unsafe {
        bpf(
            BPF_LINK_CREATE,
            std::ptr::addr_of!(link_attr).cast(),
            core::mem::size_of::<LinkCreateAttr>() as u32,
        )
    };
    if link < 0 {
        return Err(ArmError { stage: ArmStage::Link, errno: last_errno(), verifier_log: None });
    }

    let link = unsafe { OwnedFd::from_raw_fd(link as i32) };

    Ok(Armed { prog, link, target, tgid_offset })
}

fn verifier_log(attr: &ProgLoadAttr) -> Option<String> {
    const LOG_BYTES: usize = 16 * 1024;
    let mut buf = vec![0u8; LOG_BYTES];

    let mut with_log = ProgLoadAttr {
        prog_type: attr.prog_type,
        insn_cnt: attr.insn_cnt,
        insns: attr.insns,
        license: attr.license,
        log_level: 1,
        log_size: LOG_BYTES as u32,
        log_buf: buf.as_mut_ptr() as u64,
        prog_name: attr.prog_name,
        expected_attach_type: attr.expected_attach_type,
        attach_btf_id: attr.attach_btf_id,
        ..Default::default()
    };
    with_log.prog_flags = attr.prog_flags;

    let fd = unsafe {
        bpf(
            BPF_PROG_LOAD,
            std::ptr::addr_of!(with_log).cast(),
            core::mem::size_of::<ProgLoadAttr>() as u32,
        )
    };
    if fd >= 0 {

        drop(unsafe { OwnedFd::from_raw_fd(fd as i32) });
        return None;
    }

    let end = buf.iter().position(|b| *b == 0).unwrap_or(buf.len());
    let text = buf
        .get(..end)
        .map(|b| String::from_utf8_lossy(b).trim().to_string())
        .unwrap_or_default();
    if text.is_empty() {
        return None;
    }
    let tail: Vec<&str> = text.lines().rev().take(6).collect();
    Some(tail.into_iter().rev().collect::<Vec<_>>().join(" | "))
}

fn not_found_errno(why: &btf::NotFound) -> i32 {
    match why {
        btf::NotFound::WalkedEverything { .. } => libc::ENOENT,
        btf::NotFound::NotBtf => libc::EINVAL,
        btf::NotFound::StoppedEarly { .. } => libc::EPROTO,

        btf::NotFound::NotByteAligned { .. } => libc::ERANGE,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {

    Denies,

    AttachedButInert,

    NotArmed,

    Inconclusive,
}

impl Verdict {

    pub fn token(self) -> &'static str {
        match self {
            Verdict::Denies => "denies",
            Verdict::AttachedButInert => "attached-but-inert",
            Verdict::NotArmed => "not-armed",
            Verdict::Inconclusive => "inconclusive",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Trial {

    pub tgid_offset: Option<u32>,

    pub armed: Result<(), ArmError>,

    pub kill_errno: i32,

    pub survived: bool,

    pub kill_after_detach: bool,

    pub died_of: i32,

    pub kernel_origin_passes: Option<bool>,

    pub verdict: Verdict,
}

fn spawn_victim(alarm_secs: u32) -> Option<u32> {

    let pid = unsafe { libc::fork() };
    match pid {
        -1 => None,
        0 => {

            unsafe {
                libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL);
                libc::alarm(alarm_secs);
                loop {
                    libc::pause();
                }
            }
        }
        n => u32::try_from(n).ok(),
    }
}

fn kill(pid: u32, sig: i32) -> i32 {

    let r = unsafe { libc::kill(pid as libc::pid_t, sig) };
    if r == 0 {
        0
    } else {
        last_errno()
    }
}

fn reaped(pid: u32, block: bool) -> Option<i32> {
    let mut status: libc::c_int = 0;
    let flags = if block { 0 } else { libc::WNOHANG };

    let r = unsafe { libc::waitpid(pid as libc::pid_t, &mut status, flags) };
    if r > 0 {
        Some(status)
    } else {
        None
    }
}

fn term_signal(status: i32) -> i32 {
    if libc::WIFSIGNALED(status) {
        libc::WTERMSIG(status)
    } else {
        0
    }
}

fn settle() {
    std::thread::sleep(std::time::Duration::from_millis(50));
}

pub fn trial() -> Trial {
    let mut t = Trial {
        tgid_offset: None,
        armed: Ok(()),
        kill_errno: 0,
        survived: false,
        kill_after_detach: false,
        died_of: 0,
        kernel_origin_passes: None,
        verdict: Verdict::Inconclusive,
    };

    let Some(victim) = spawn_victim(30) else {
        return t;
    };

    let armed = match arm(victim) {
        Ok(a) => {
            t.tgid_offset = Some(a.tgid_offset);
            a
        }
        Err(e) => {

            let _ = kill(victim, libc::SIGKILL);
            let _ = reaped(victim, true);
            t.armed = Err(e);
            t.verdict = Verdict::NotArmed;
            return t;
        }
    };

    t.kill_errno = kill(victim, libc::SIGKILL);
    settle();

    let reaped_now = reaped(victim, false);
    t.survived = reaped_now.is_none();

    let hook_fired = t.kill_errno == libc::EPERM && t.survived;
    if hook_fired {
        t.kernel_origin_passes = Some(kernel_origin_control());
    }

    drop(armed);
    t.kill_after_detach = kill(victim, libc::SIGKILL) == 0;
    settle();
    t.died_of = reaped_now.or_else(|| reaped(victim, true)).map_or(0, term_signal);

    t.verdict = match (hook_fired, t.kill_after_detach, t.died_of) {

        (true, true, s) if s == libc::SIGKILL => Verdict::Denies,

        (false, _, _) if t.kill_errno == 0 => Verdict::AttachedButInert,
        _ => Verdict::Inconclusive,
    };
    t
}

fn kernel_origin_control() -> bool {
    let Some(victim) = spawn_victim(1) else {
        return false;
    };
    let Ok(armed) = arm(victim) else {
        let _ = kill(victim, libc::SIGKILL);
        let _ = reaped(victim, true);
        return false;
    };

    std::thread::sleep(std::time::Duration::from_millis(2500));
    let died_of_alarm = reaped(victim, false).map(term_signal) == Some(libc::SIGALRM);

    drop(armed);
    if !died_of_alarm {
        let _ = kill(victim, libc::SIGKILL);
        let _ = reaped(victim, true);
    }
    died_of_alarm
}
