use std::collections::BTreeSet;
use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};
use std::path::Path;

use crate::bpfabi::{IterCreateAttr, LinkCreateAttr, ProgLoadAttr};
use crate::triage::{self, Coverage, Finding, Severity};
use crate::{btf, rootkit};

const BPF_PROG_LOAD: i32 = 5;
const BPF_LINK_CREATE: i32 = 28;
const BPF_ITER_CREATE: i32 = 33;

const BPF_PROG_TYPE_TRACING: u32 = 26;
const BPF_TRACE_ITER: u32 = 28;

const HELPER_SEQ_WRITE: i32 = 127;

const ITER_ATTACH: &str = "bpf_iter_task";

const TASK_STRUCT: &str = "task_struct";
const PID: &str = "pid";
const TGID: &str = "tgid";

const PROG_NAME: &str = "hm_task_iter";

const RECORD: usize = 8;

const SUBJECT: &str = "kernel-ground-truth";

fn program(pid_off: u32, tgid_off: u32) -> [u8; 15 * RECORD] {

    const fn insn(op: u8, dst: u8, src: u8, off: i16, imm: i32) -> [u8; 8] {
        let regs = dst | (src << 4);
        let off = off.to_le_bytes();
        let imm = imm.to_le_bytes();
        [op, regs, off[0], off[1], imm[0], imm[1], imm[2], imm[3]]
    }

    const ALU64: u8 = 0x07;
    const JMP: u8 = 0x05;
    const LDX: u8 = 0x01;
    const STX: u8 = 0x03;
    const MEM: u8 = 0x60;
    const DW: u8 = 0x18;
    const W: u8 = 0x00;
    const X: u8 = 0x08;
    const MOV: u8 = 0xb0;
    const ADD: u8 = 0x00;
    const JEQ: u8 = 0x10;
    const CALL: u8 = 0x80;
    const EXIT: u8 = 0x90;

    let pid = i16::try_from(pid_off).unwrap_or(i16::MAX);
    let tgid = i16::try_from(tgid_off).unwrap_or(i16::MAX);

    let insns: [[u8; 8]; 15] = [
        insn(ALU64 | MOV | X, 6, 1, 0, 0),
        insn(LDX | MEM | DW, 2, 6, 8, 0),
        insn(JMP | JEQ, 2, 0, 10, 0),
        insn(LDX | MEM | W, 7, 2, pid, 0),
        insn(LDX | MEM | W, 8, 2, tgid, 0),
        insn(STX | MEM | W, 10, 7, -8, 0),
        insn(STX | MEM | W, 10, 8, -4, 0),
        insn(LDX | MEM | DW, 3, 6, 0, 0),
        insn(LDX | MEM | DW, 1, 3, 0, 0),
        insn(ALU64 | MOV | X, 2, 10, 0, 0),
        insn(ALU64 | ADD, 2, 0, 0, -8),
        insn(ALU64 | MOV, 3, 0, 0, RECORD as i32),
        insn(JMP | CALL, 0, 0, 0, HELPER_SEQ_WRITE),
        insn(ALU64 | MOV, 0, 0, 0, 0),
        insn(JMP | EXIT, 0, 0, 0, 0),
    ];

    let mut out = [0u8; 15 * RECORD];
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

struct Enumeration {

    tasks: Vec<(u32, u32)>,
    attach_btf_id: u32,
    pid_off: u32,
    tgid_off: u32,

    ragged: usize,
}

struct EnumFail {
    stage: &'static str,
    errno: i32,
    verifier_log: Option<String>,
    attach_btf_id: u32,
    pid_off: u32,
    tgid_off: u32,
}

impl EnumFail {

    fn reason(&self) -> String {
        match self.stage {
            "btf-read" => format!(
                "kernel BTF unreadable (errno {}): needs root and CONFIG_DEBUG_INFO_BTF",
                self.errno
            ),
            "iter-lookup" => {
                "this kernel's BTF has no bpf_iter_task: too old for a task iterator (< 5.8)".into()
            }
            "field-lookup" => {
                format!("task_struct.pid/tgid offset unresolved from BTF (errno {})", self.errno)
            }
            "load" => {
                let tail = self
                    .verifier_log
                    .as_deref()
                    .map(|l| format!("; verifier: {l}"))
                    .unwrap_or_default();
                format!(
                    "bpf(PROG_LOAD) refused (errno {}): needs root/CAP_BPF, not an unprivileged-bpf-disabled context{tail}",
                    self.errno
                )
            }
            "link" => format!("bpf(LINK_CREATE) refused (errno {}): BPF restricted here", self.errno),
            "iter-create" => format!("bpf(ITER_CREATE) refused (errno {})", self.errno),
            "read" => format!("iterator read failed (errno {})", self.errno),
            other => format!("{other} failed (errno {})", self.errno),
        }
    }
}

fn enumerate() -> Result<Enumeration, EnumFail> {
    let fail = |stage, errno, log, id, pid, tgid| EnumFail {
        stage,
        errno,
        verifier_log: log,
        attach_btf_id: id,
        pid_off: pid,
        tgid_off: tgid,
    };

    let blob = btf::vmlinux().map_err(|e| fail("btf-read", e, None, 0, 0, 0))?;
    let attach_btf_id =
        btf::func_id(&blob, ITER_ATTACH).map_err(|w| fail("iter-lookup", enoent_like(&w), None, 0, 0, 0))?;
    let pid_off = btf::member_offset(&blob, TASK_STRUCT, PID)
        .map_err(|w| fail("field-lookup", enoent_like(&w), None, attach_btf_id, 0, 0))?;
    let tgid_off = btf::member_offset(&blob, TASK_STRUCT, TGID)
        .map_err(|w| fail("field-lookup", enoent_like(&w), None, attach_btf_id, pid_off, 0))?;

    let insns = program(pid_off, tgid_off);
    let license = c"GPL";
    let mut name = [0u8; 16];
    for (slot, byte) in name.iter_mut().zip(PROG_NAME.as_bytes()) {
        *slot = *byte;
    }
    let attr = ProgLoadAttr {
        prog_type: BPF_PROG_TYPE_TRACING,
        insn_cnt: (insns.len() / RECORD) as u32,
        insns: insns.as_ptr() as u64,
        license: license.as_ptr() as u64,
        prog_name: name,
        expected_attach_type: BPF_TRACE_ITER,
        attach_btf_id,
        ..Default::default()
    };

    let prog = unsafe {
        bpf(BPF_PROG_LOAD, std::ptr::addr_of!(attr).cast(), core::mem::size_of::<ProgLoadAttr>() as u32)
    };
    if prog < 0 {
        let errno = last_errno();
        return Err(fail("load", errno, verifier_log(&attr), attach_btf_id, pid_off, tgid_off));
    }

    let prog = unsafe { OwnedFd::from_raw_fd(prog as i32) };

    let link_attr = LinkCreateAttr {
        prog_fd: prog.as_raw_fd() as u32,
        target_fd: 0,
        attach_type: BPF_TRACE_ITER,
        flags: 0,
    };

    let link = unsafe {
        bpf(BPF_LINK_CREATE, std::ptr::addr_of!(link_attr).cast(), core::mem::size_of::<LinkCreateAttr>() as u32)
    };
    if link < 0 {
        return Err(fail("link", last_errno(), None, attach_btf_id, pid_off, tgid_off));
    }

    let link = unsafe { OwnedFd::from_raw_fd(link as i32) };

    let iter_attr = IterCreateAttr { link_fd: link.as_raw_fd() as u32, flags: 0 };

    let iter = unsafe {
        bpf(BPF_ITER_CREATE, std::ptr::addr_of!(iter_attr).cast(), core::mem::size_of::<IterCreateAttr>() as u32)
    };
    if iter < 0 {
        return Err(fail("iter-create", last_errno(), None, attach_btf_id, pid_off, tgid_off));
    }

    let iter = unsafe { OwnedFd::from_raw_fd(iter as i32) };

    let mut data = Vec::new();
    let mut buf = [0u8; 16 * 1024];
    loop {

        let n = unsafe { libc::read(iter.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) };
        if n < 0 {
            return Err(fail("read", last_errno(), None, attach_btf_id, pid_off, tgid_off));
        }
        if n == 0 {
            break;
        }
        if let Some(chunk) = buf.get(..n as usize) {
            data.extend_from_slice(chunk);
        }

        if data.len() > 8 * 1024 * 1024 {
            break;
        }
    }

    let mut tasks = Vec::new();
    let mut rest = data.as_slice();
    while let Some((rec, tail)) = rest.split_first_chunk::<RECORD>() {
        let (pidb, tgidb) = rec.split_at(4);
        if let (Ok(p), Ok(t)) = (<[u8; 4]>::try_from(pidb), <[u8; 4]>::try_from(tgidb)) {
            tasks.push((u32::from_ne_bytes(p), u32::from_ne_bytes(t)));
        }
        rest = tail;
    }

    Ok(Enumeration { tasks, attach_btf_id, pid_off, tgid_off, ragged: rest.len() })
}

fn walk_tgids() -> Option<BTreeSet<u32>> {
    enumerate().ok().map(|e| e.tasks.iter().map(|(_, t)| *t).collect())
}

#[derive(Debug, Clone)]
pub struct Report {

    pub findings: Vec<Finding>,

    pub coverage: Coverage,

    pub reason: Option<String>,

    pub tasks_walked: usize,

    pub processes_walked: usize,

    pub procfs_processes: usize,

    pub hidden: Vec<u32>,
}

pub fn report() -> Report {
    let empty = |coverage, reason| Report {
        findings: Vec::new(),
        coverage,
        reason,
        tasks_walked: 0,
        processes_walked: 0,
        procfs_processes: 0,
        hidden: Vec::new(),
    };

    let proc_before = rootkit::pids_via_readdir();
    let walk = match enumerate() {
        Ok(e) => e,
        Err(f) => return empty(Coverage::Unreadable, Some(f.reason())),
    };
    let proc_after = rootkit::pids_via_readdir();

    let (listed, proc_ok) = match (proc_before, proc_after) {
        (Some(mut a), Some(b)) => {
            a.extend(b);
            (a, true)
        }
        (Some(s), None) | (None, Some(s)) => (s, false),
        (None, None) => (BTreeSet::new(), false),
    };

    let iter_tgids: BTreeSet<u32> = walk.tasks.iter().map(|(_, t)| *t).collect();
    let tasks_walked = walk.tasks.len();
    let processes_walked = iter_tgids.len();

    let candidates: Vec<u32> =
        iter_tgids.difference(&listed).copied().filter(|&t| t != 0).collect();

    let mut findings = Vec::new();
    let mut hidden = Vec::new();
    if !candidates.is_empty() {
        let confirm = walk_tgids().unwrap_or_default();
        for tgid in candidates {
            if !confirm.contains(&tgid) {
                continue;
            }
            hidden.push(tgid);

            let stat_visible = Path::new(&format!("/proc/{tgid}")).exists();
            let (what, why) = if stat_visible {
                (
                    "process in the kernel's task iterator but not in a /proc directory read",
                    "the kernel schedules this task yet a directory read of /proc omits it, while \
                     stat of /proc/<pid> still answers — the signature of a getdents-hooking \
                     rootkit. Seen from the kernel's own task iteration, below the /proc layer the \
                     hook manipulates",
                )
            } else {
                (
                    "process in the kernel's task iterator but invisible to /proc entirely",
                    "the kernel schedules this task yet neither a /proc directory read nor a stat \
                     of /proc/<pid> sees it — hiding that reaches below the directory read (DKOM, \
                     or stat hooked as well). Ground truth here is the kernel's own task \
                     iteration, which this is the only sweep to establish",
                )
            };
            findings.push(Finding::flag(Severity::Critical, SUBJECT, format!("pid {tgid}"), what, why));
        }
    }
    triage::rank(&mut findings);

    let coverage = if !proc_ok {
        Coverage::Partial
    } else if hidden.is_empty() {
        Coverage::Clean
    } else {
        Coverage::Populated
    };
    let reason = (!proc_ok)
        .then(|| "a /proc directory read failed on one or both bracket samples".to_string());

    Report {
        findings,
        coverage,
        reason,
        tasks_walked,
        processes_walked,
        procfs_processes: listed.len(),
        hidden,
    }
}

#[derive(Debug, Clone)]
pub struct ProbeReport {

    pub loaded: bool,

    pub stage: &'static str,

    pub errno: i32,

    pub verifier_log: Option<String>,

    pub attach_btf_id: u32,

    pub pid_off: u32,

    pub tgid_off: u32,

    pub tasks_read: usize,

    pub sample: Vec<(u32, u32)>,

    pub ragged_bytes: usize,
}

impl std::fmt::Display for ProbeReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "kground probe: loaded={} stage={}", self.loaded, self.stage)?;
        if self.errno != 0 {
            writeln!(f, "  errno={}", self.errno)?;
        }
        if let Some(log) = &self.verifier_log {
            writeln!(f, "  verifier: {log}")?;
        }
        writeln!(
            f,
            "  attach_btf_id={} pid_off={} tgid_off={}",
            self.attach_btf_id, self.pid_off, self.tgid_off
        )?;
        writeln!(f, "  tasks_read={} ragged_bytes={}", self.tasks_read, self.ragged_bytes)?;
        if !self.sample.is_empty() {
            writeln!(f, "  sample (pid,tgid): {:?}", self.sample)?;
        }
        Ok(())
    }
}

pub fn probe() -> ProbeReport {
    match enumerate() {
        Ok(e) => {
            let sample = e.tasks.iter().take(12).copied().collect();
            ProbeReport {
                loaded: true,
                stage: "done",
                errno: 0,
                verifier_log: None,
                attach_btf_id: e.attach_btf_id,
                pid_off: e.pid_off,
                tgid_off: e.tgid_off,
                tasks_read: e.tasks.len(),
                sample,
                ragged_bytes: e.ragged,
            }
        }
        Err(f) => ProbeReport {
            loaded: false,
            stage: f.stage,
            errno: f.errno,
            verifier_log: f.verifier_log,
            attach_btf_id: f.attach_btf_id,
            pid_off: f.pid_off,
            tgid_off: f.tgid_off,
            tasks_read: 0,
            sample: Vec::new(),
            ragged_bytes: 0,
        },
    }
}

fn verifier_log(attr: &ProgLoadAttr) -> Option<String> {
    const LOG_BYTES: usize = 16 * 1024;
    let mut log = vec![0u8; LOG_BYTES];
    let mut with_log = ProgLoadAttr {
        prog_type: attr.prog_type,
        insn_cnt: attr.insn_cnt,
        insns: attr.insns,
        license: attr.license,
        log_level: 1,
        log_size: LOG_BYTES as u32,
        log_buf: log.as_mut_ptr() as u64,
        prog_name: attr.prog_name,
        expected_attach_type: attr.expected_attach_type,
        attach_btf_id: attr.attach_btf_id,
        ..Default::default()
    };
    with_log.prog_flags = attr.prog_flags;

    let fd = unsafe {
        bpf(BPF_PROG_LOAD, std::ptr::addr_of!(with_log).cast(), core::mem::size_of::<ProgLoadAttr>() as u32)
    };
    if fd >= 0 {

        drop(unsafe { OwnedFd::from_raw_fd(fd as i32) });
        return None;
    }
    let end = log.iter().position(|b| *b == 0).unwrap_or(log.len());
    let text = log.get(..end).map(|b| String::from_utf8_lossy(b).trim().to_string()).unwrap_or_default();
    if text.is_empty() {
        return None;
    }
    let tail: Vec<&str> = text.lines().rev().take(6).collect();
    Some(tail.into_iter().rev().collect::<Vec<_>>().join(" | "))
}

fn enoent_like(why: &btf::NotFound) -> i32 {
    match why {
        btf::NotFound::WalkedEverything { .. } => libc::ENOENT,
        btf::NotFound::NotBtf => libc::EINVAL,
        btf::NotFound::StoppedEarly { .. } => libc::EPROTO,
        btf::NotFound::NotByteAligned { .. } => libc::ERANGE,
    }
}
