use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};
use std::sync::atomic::{AtomicU64, Ordering};

use crate::btf;
use crate::rootkit::{Finding, Severity};
use crate::bpfabi::ProgLoadAttr;

const BPF_MAP_CREATE: i32 = 0;
const BPF_PROG_LOAD: i32 = 5;
const BPF_RAW_TRACEPOINT_OPEN: i32 = 17;

const BPF_MAP_TYPE_RINGBUF: u32 = 27;

const BPF_PROG_TYPE_RAW_TRACEPOINT: u32 = 17;

const BPF_PSEUDO_MAP_FD: u8 = 1;

const HELPER_GET_CURRENT_PID_TGID: i32 = 14;
const HELPER_GET_CURRENT_UID_GID: i32 = 15;
const HELPER_GET_CURRENT_COMM: i32 = 16;
const HELPER_GET_CURRENT_TASK: i32 = 35;
const HELPER_PROBE_READ_KERNEL: i32 = 113;
const HELPER_RINGBUF_OUTPUT: i32 = 130;

const TRACEPOINT: &[u8] = b"sched_process_exec\0";

const TASK_STRUCT: &str = "task_struct";
const REAL_PARENT: &str = "real_parent";
const TGID: &str = "tgid";

const EVENT_SIZE: usize = 28;
const EV_PID: usize = 0;
const EV_PPID: usize = 4;
const EV_UID: usize = 8;
const EV_COMM: usize = 12;
const COMM_LEN: usize = 16;

const RING_BYTES: u32 = 256 * 1024;

const BPF_RINGBUF_BUSY_BIT: u32 = 1 << 31;
const BPF_RINGBUF_DISCARD_BIT: u32 = 1 << 30;
const BPF_RINGBUF_HDR_SZ: usize = 8;
const RINGBUF_LEN_MASK: u32 = 0x3fff_ffff;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event {

    pub pid: u32,

    pub ppid: u32,

    pub uid: u32,

    pub comm: String,
}

fn le_u32(b: &[u8], off: usize) -> Option<u32> {
    b.get(off..off + 4).and_then(|s| s.try_into().ok()).map(u32::from_le_bytes)
}

fn record_data_len(len_field: u32) -> usize {
    (len_field & RINGBUF_LEN_MASK) as usize
}

fn is_busy(len_field: u32) -> bool {
    len_field & BPF_RINGBUF_BUSY_BIT != 0
}

fn is_discard(len_field: u32) -> bool {
    len_field & BPF_RINGBUF_DISCARD_BIT != 0
}

fn roundup_len(len_field: u32) -> u64 {
    let raw = record_data_len(len_field) as u64 + BPF_RINGBUF_HDR_SZ as u64;
    raw.div_ceil(8) * 8
}

fn decode_event(sample: &[u8]) -> Option<Event> {
    let pid = le_u32(sample, EV_PID)?;
    let ppid = le_u32(sample, EV_PPID)?;
    let uid = le_u32(sample, EV_UID)?;
    let comm = comm_from_bytes(sample.get(EV_COMM..EV_COMM + COMM_LEN)?);
    Some(Event { pid, ppid, uid, comm })
}

fn comm_from_bytes(b: &[u8]) -> String {
    let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    b.get(..end).map(|s| String::from_utf8_lossy(s).into_owned()).unwrap_or_default()
}

#[allow(dead_code)]
fn parse_records(data: &[u8], mask: u64, cons: u64, prod: u64) -> (Vec<Event>, u64) {
    let mut events = Vec::new();
    let mut pos = cons;
    while pos < prod {
        let idx = (pos & mask) as usize;
        let Some(len_field) = le_u32(data, idx) else {
            break;
        };
        if is_busy(len_field) {
            break;
        }
        let advance = roundup_len(len_field);
        if !is_discard(len_field) {
            let start = idx + BPF_RINGBUF_HDR_SZ;
            if let Some(sample) = data.get(start..start + record_data_len(len_field)) {
                if let Some(ev) = decode_event(sample) {
                    events.push(ev);
                }
            }
        }
        pos = pos.wrapping_add(advance);
    }
    (events, pos)
}

fn program(map_fd: i32, ppid_offsets: Option<(u32, u32)>) -> Vec<u8> {

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
    const ST: u8 = 0x02;
    const LD: u8 = 0x00;
    const MEM: u8 = 0x60;
    const IMM: u8 = 0x00;
    const W: u8 = 0x00;
    const DW: u8 = 0x18;
    const X: u8 = 0x08;
    const MOV: u8 = 0xb0;
    const ADD: u8 = 0x00;
    const RSH: u8 = 0x70;
    const CALL: u8 = 0x80;
    const EXIT: u8 = 0x90;

    let st_dw = ST | MEM | DW;
    let stx_w = STX | MEM | W;
    let ldx_dw = LDX | MEM | DW;
    let ld_imm64 = LD | IMM | DW;
    let mov_k = ALU64 | MOV;
    let mov_x = ALU64 | MOV | X;
    let add_k = ALU64 | ADD;
    let rsh_k = ALU64 | RSH;
    let call = JMP | CALL;
    let exit = JMP | EXIT;

    const R0: u8 = 0;
    const R1: u8 = 1;
    const R2: u8 = 2;
    const R3: u8 = 3;
    const R4: u8 = 4;
    const R10: u8 = 10;

    const SCRATCH: i16 = -40;
    const EV_BASE: i16 = -32;
    const OFF_PPID: i16 = -28;
    const OFF_UID: i16 = -24;
    const OFF_COMM: i16 = -20;

    let mut p: Vec<[u8; 8]> = Vec::new();

    for off in [SCRATCH, -32, -24, -16, -8] {
        p.push(insn(st_dw, R10, 0, off, 0));
    }

    p.push(insn(call, 0, 0, 0, HELPER_GET_CURRENT_PID_TGID));
    p.push(insn(rsh_k, R0, 0, 0, 32));
    p.push(insn(stx_w, R10, R0, EV_BASE, 0));

    p.push(insn(call, 0, 0, 0, HELPER_GET_CURRENT_UID_GID));
    p.push(insn(stx_w, R10, R0, OFF_UID, 0));

    if let Some((real_parent_off, tgid_off)) = ppid_offsets {

        p.push(insn(call, 0, 0, 0, HELPER_GET_CURRENT_TASK));

        p.push(insn(mov_x, R3, R0, 0, 0));
        p.push(insn(add_k, R3, 0, 0, real_parent_off as i32));

        p.push(insn(mov_x, R1, R10, 0, 0));
        p.push(insn(add_k, R1, 0, 0, i32::from(SCRATCH)));
        p.push(insn(mov_k, R2, 0, 0, 8));
        p.push(insn(call, 0, 0, 0, HELPER_PROBE_READ_KERNEL));

        p.push(insn(ldx_dw, R3, R10, SCRATCH, 0));
        p.push(insn(add_k, R3, 0, 0, tgid_off as i32));

        p.push(insn(mov_x, R1, R10, 0, 0));
        p.push(insn(add_k, R1, 0, 0, i32::from(OFF_PPID)));
        p.push(insn(mov_k, R2, 0, 0, 4));
        p.push(insn(call, 0, 0, 0, HELPER_PROBE_READ_KERNEL));
    }

    p.push(insn(mov_x, R1, R10, 0, 0));
    p.push(insn(add_k, R1, 0, 0, i32::from(OFF_COMM)));
    p.push(insn(mov_k, R2, 0, 0, COMM_LEN as i32));
    p.push(insn(call, 0, 0, 0, HELPER_GET_CURRENT_COMM));

    p.push(insn(ld_imm64, R1, BPF_PSEUDO_MAP_FD, 0, map_fd));
    p.push([0u8; 8]);
    p.push(insn(mov_x, R2, R10, 0, 0));
    p.push(insn(add_k, R2, 0, 0, i32::from(EV_BASE)));
    p.push(insn(mov_k, R3, 0, 0, EVENT_SIZE as i32));
    p.push(insn(mov_k, R4, 0, 0, 0));
    p.push(insn(call, 0, 0, 0, HELPER_RINGBUF_OUTPUT));

    p.push(insn(mov_k, R0, 0, 0, 0));
    p.push(insn(exit, 0, 0, 0, 0));

    let mut out = Vec::with_capacity(p.len() * 8);
    for i in &p {
        out.extend_from_slice(i);
    }
    out
}

fn ppid_offsets() -> Option<(u32, u32)> {
    let blob = btf::vmlinux().ok()?;
    let real_parent = btf::member_offset(&blob, TASK_STRUCT, REAL_PARENT).ok()?;
    let tgid = btf::member_offset(&blob, TASK_STRUCT, TGID).ok()?;
    Some((real_parent, tgid))
}

#[repr(C)]
#[derive(Default)]
struct MapCreateAttr {
    map_type: u32,
    key_size: u32,
    value_size: u32,
    max_entries: u32,
    map_flags: u32,
    inner_map_fd: u32,
    numa_node: u32,
    map_name: [u8; 16],
    map_ifindex: u32,
    btf_fd: u32,
    btf_key_type_id: u32,
    btf_value_type_id: u32,
    btf_vmlinux_value_type_id: u32,
    map_extra: u64,
}

#[repr(C)]
#[derive(Default)]
struct RawTracepointOpenAttr {
    name: u64,
    prog_fd: u32,
    _pad: u32,
}

const _: () = {
    assert!(core::mem::size_of::<MapCreateAttr>() == 72);
    assert!(core::mem::offset_of!(MapCreateAttr, map_name) == 28);
    assert!(core::mem::offset_of!(MapCreateAttr, map_extra) == 64);

    assert!(core::mem::size_of::<RawTracepointOpenAttr>() == 16);
    assert!(core::mem::offset_of!(RawTracepointOpenAttr, prog_fd) == 8);
};

unsafe fn bpf(cmd: i32, attr: *const core::ffi::c_void, size: u32) -> i64 {

    unsafe { libc::syscall(libc::SYS_bpf, cmd, attr, size) }
}

fn last_errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn obj_name(src: &[u8]) -> [u8; 16] {
    let mut name = [0u8; 16];
    for (slot, byte) in name.iter_mut().zip(src) {
        *slot = *byte;
    }
    name
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoadStage {

    MapCreate,

    ProgLoad,

    Attach,

    MmapConsumer,

    MmapProducer,
}

impl LoadStage {

    pub fn token(self) -> &'static str {
        match self {
            LoadStage::MapCreate => "map-create",
            LoadStage::ProgLoad => "prog-load",
            LoadStage::Attach => "attach",
            LoadStage::MmapConsumer => "mmap-consumer",
            LoadStage::MmapProducer => "mmap-producer",
        }
    }

    pub fn meaning(self, errno: i32) -> &'static str {
        match (self, errno) {
            (LoadStage::MapCreate, e) | (LoadStage::ProgLoad, e) | (LoadStage::Attach, e)
                if e == libc::EPERM =>
            {
                "refused for lack of privilege — re-run as root with CAP_BPF and CAP_SYS_ADMIN"
            }
            (LoadStage::MapCreate, e) if e == libc::EINVAL => {
                "this kernel has no BPF ring-buffer support (needs 5.8+)"
            }
            (LoadStage::MapCreate, _) => "the ring-buffer map could not be created",
            (LoadStage::ProgLoad, e) if e == libc::EACCES => {
                "the verifier rejected the sensor program — see the verifier log"
            }
            (LoadStage::ProgLoad, _) => "the kernel would not load the raw-tracepoint program",
            (LoadStage::Attach, e) if e == libc::ENOENT => {
                "the sched_process_exec tracepoint is not present on this kernel"
            }
            (LoadStage::Attach, _) => {
                "the kernel would not attach the program to sched_process_exec"
            }
            (LoadStage::MmapConsumer, _) | (LoadStage::MmapProducer, _) => {
                "the ring buffer could not be mapped into this process"
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadError {

    pub stage: LoadStage,

    pub errno: i32,

    pub verifier_log: Option<String>,
}

pub struct Sensor {
    map: OwnedFd,
    #[allow(dead_code)]
    prog: OwnedFd,
    #[allow(dead_code)]
    link: OwnedFd,

    consumer: *mut u8,

    producer: *mut u8,

    data: *mut u8,
    page: usize,
    producer_len: usize,
    mask: u64,
    cons_pos: u64,
    have_ppid: bool,
}

impl Sensor {

    pub fn have_ppid(&self) -> bool {
        self.have_ppid
    }

    pub fn poll_events(&mut self, timeout_ms: i32) -> std::io::Result<Vec<Event>> {
        let mut pfd = libc::pollfd {
            fd: self.map.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };

        let r = unsafe { libc::poll(&mut pfd, 1, timeout_ms) };
        if r < 0 {
            let e = std::io::Error::last_os_error();
            if e.raw_os_error() == Some(libc::EINTR) {
                return Ok(Vec::new());
            }
            return Err(e);
        }
        Ok(self.drain())
    }

    fn drain(&mut self) -> Vec<Event> {

        let prod = unsafe { (*(self.producer as *const AtomicU64)).load(Ordering::Acquire) };
        let mut pos = self.cons_pos;
        let mut events = Vec::new();
        while pos < prod {
            let idx = (pos & self.mask) as usize;

            let len_field = unsafe { read_u32(self.data.add(idx)) };
            if is_busy(len_field) {
                break;
            }
            let advance = roundup_len(len_field);
            if !is_discard(len_field) {
                let mut sample = [0u8; EVENT_SIZE];
                let n = record_data_len(len_field).min(EVENT_SIZE);
                for (k, slot) in sample.iter_mut().take(n).enumerate() {

                    *slot = unsafe { *self.data.add(idx + BPF_RINGBUF_HDR_SZ + k) };
                }
                if let Some(ev) = decode_event(&sample) {
                    events.push(ev);
                }
            }
            pos = pos.wrapping_add(advance);
        }

        unsafe { (*(self.consumer as *const AtomicU64)).store(pos, Ordering::Release) };
        self.cons_pos = pos;
        events
    }
}

impl Drop for Sensor {
    fn drop(&mut self) {

        unsafe {
            libc::munmap(self.consumer.cast(), self.page);
            libc::munmap(self.producer.cast(), self.producer_len);
        }
    }
}

fn page_size() -> usize {

    let n = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if n > 0 {
        n as usize
    } else {
        4096
    }
}

unsafe fn read_u32(p: *const u8) -> u32 {
    let mut b = [0u8; 4];
    for (i, slot) in b.iter_mut().enumerate() {

        *slot = unsafe { *p.add(i) };
    }
    u32::from_le_bytes(b)
}

pub fn load() -> Result<Sensor, LoadError> {

    let map_attr = MapCreateAttr {
        map_type: BPF_MAP_TYPE_RINGBUF,
        max_entries: RING_BYTES,
        map_name: obj_name(b"hemostat_exec"),
        ..Default::default()
    };

    let map = unsafe {
        bpf(
            BPF_MAP_CREATE,
            std::ptr::addr_of!(map_attr).cast(),
            core::mem::size_of::<MapCreateAttr>() as u32,
        )
    };
    if map < 0 {
        return Err(LoadError { stage: LoadStage::MapCreate, errno: last_errno(), verifier_log: None });
    }

    let map = unsafe { OwnedFd::from_raw_fd(map as i32) };

    let have_ppid_offsets = ppid_offsets();
    let insns = program(map.as_raw_fd(), have_ppid_offsets);
    let license = c"GPL";
    let attr = ProgLoadAttr {
        prog_type: BPF_PROG_TYPE_RAW_TRACEPOINT,
        insn_cnt: (insns.len() / 8) as u32,
        insns: insns.as_ptr() as u64,
        license: license.as_ptr() as u64,
        prog_name: obj_name(b"hemostat_exec"),
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
        return Err(LoadError { stage: LoadStage::ProgLoad, errno, verifier_log: verifier_log(&attr) });
    }

    let prog = unsafe { OwnedFd::from_raw_fd(prog as i32) };

    let rt_attr = RawTracepointOpenAttr {
        name: TRACEPOINT.as_ptr() as u64,
        prog_fd: prog.as_raw_fd() as u32,
        _pad: 0,
    };

    let link = unsafe {
        bpf(
            BPF_RAW_TRACEPOINT_OPEN,
            std::ptr::addr_of!(rt_attr).cast(),
            core::mem::size_of::<RawTracepointOpenAttr>() as u32,
        )
    };
    if link < 0 {
        return Err(LoadError { stage: LoadStage::Attach, errno: last_errno(), verifier_log: None });
    }

    let link = unsafe { OwnedFd::from_raw_fd(link as i32) };

    let page = page_size();

    let consumer = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            page,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            map.as_raw_fd(),
            0,
        )
    };
    if consumer == libc::MAP_FAILED {
        return Err(LoadError { stage: LoadStage::MmapConsumer, errno: last_errno(), verifier_log: None });
    }

    let producer_len = page + 2 * RING_BYTES as usize;

    let producer = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            producer_len,
            libc::PROT_READ,
            libc::MAP_SHARED,
            map.as_raw_fd(),
            page as libc::off_t,
        )
    };
    if producer == libc::MAP_FAILED {
        let errno = last_errno();

        unsafe { libc::munmap(consumer, page) };
        return Err(LoadError { stage: LoadStage::MmapProducer, errno, verifier_log: None });
    }

    let data = unsafe { (producer as *mut u8).add(page) };

    Ok(Sensor {
        map,
        prog,
        link,
        consumer: consumer as *mut u8,
        producer: producer as *mut u8,
        data,
        page,
        producer_len,
        mask: (RING_BYTES as u64) - 1,
        cons_pos: 0,
        have_ppid: have_ppid_offsets.is_some(),
    })
}

fn verifier_log(attr: &ProgLoadAttr) -> Option<String> {
    const LOG_BYTES: usize = 16 * 1024;
    let mut buf = vec![0u8; LOG_BYTES];

    let with_log = ProgLoadAttr {
        prog_type: attr.prog_type,
        insn_cnt: attr.insn_cnt,
        insns: attr.insns,
        license: attr.license,
        log_level: 1,
        log_size: LOG_BYTES as u32,
        log_buf: buf.as_mut_ptr() as u64,
        prog_name: attr.prog_name,
        ..Default::default()
    };

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

const SHELL_INTERP: &[&str] = &[
    "sh", "bash", "dash", "zsh", "ksh", "ash", "busybox", "python", "python2", "python3", "perl",
    "ruby", "php", "lua", "node", "tclsh",
];

const NET_TOOLS: &[&str] = &["nc", "ncat", "netcat", "socat"];

const SUSPICIOUS_DIRS: &[&str] = &["/tmp/", "/var/tmp/", "/dev/shm/", "/run/shm/"];

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExecFacts {

    pub exe_path: Option<String>,

    pub deleted: bool,

    pub tty_nr: Option<i32>,
}

fn split_deleted(link: &str) -> (&str, bool) {
    match link.strip_suffix(" (deleted)") {
        Some(p) => (p, true),
        None => (link, false),
    }
}

fn is_suspicious_dir(path: &str) -> bool {
    SUSPICIOUS_DIRS.iter().any(|d| path.starts_with(d))
}

fn basename_is_hidden(path: &str) -> bool {
    path.rsplit('/').next().unwrap_or(path).starts_with('.')
}

fn parse_tty_nr(stat: &str) -> Option<i32> {
    let after = stat.get(stat.rfind(')')? + 1..)?;

    after.split_whitespace().nth(4)?.parse().ok()
}

fn bump(cur: Option<Severity>, s: Severity) -> Option<Severity> {
    Some(cur.map_or(s, |c| c.max(s)))
}

pub fn classify(ev: &Event, facts: &ExecFacts) -> Option<Finding> {
    let comm = ev.comm.as_str();
    let is_shell = SHELL_INTERP.contains(&comm);
    let is_nettool = NET_TOOLS.contains(&comm);
    let no_tty = facts.tty_nr == Some(0);
    let exe = facts.exe_path.as_deref();
    let susp_loc = exe.is_some_and(is_suspicious_dir);
    let hidden = exe.is_some_and(basename_is_hidden);
    let deleted = facts.deleted;

    let mut sev: Option<Severity> = None;
    let mut reasons: Vec<String> = Vec::new();

    if deleted {
        reasons.push("runs an image unlinked from disk (a deleted file or memfd) — fileless execution".into());
        sev = bump(sev, if is_shell || is_nettool || no_tty { Severity::Warn } else { Severity::Note });
    }
    if susp_loc {
        let dir = exe.unwrap_or("");
        reasons.push(format!("executes from a world-writable / volatile path ({dir})"));
        sev = bump(sev, if is_shell || is_nettool { Severity::Warn } else { Severity::Note });
    }
    if is_nettool {
        if no_tty {
            reasons.push("a network relay tool (nc/ncat/socat) with no controlling terminal — the classic reverse-shell shape".into());
            sev = bump(sev, Severity::Warn);
        } else {
            reasons.push("a network relay tool (nc/ncat/socat) was executed".into());
            sev = bump(sev, Severity::Note);
        }
    }
    if is_shell && no_tty && (susp_loc || deleted || hidden) {
        reasons.push("a shell/interpreter with no controlling terminal, from an unusual image".into());
        sev = bump(sev, Severity::Warn);
    }
    if hidden {
        reasons.push("the executable's name is dot-hidden".into());
        sev = bump(sev, Severity::Note);
    }

    let severity = sev?;
    Some(Finding {
        severity,
        subject: format!("exec {comm} (pid {}, uid {})", ev.pid, ev.uid),
        what: reasons.join("; "),
        why: "a behavioural lead from a live exec, not a rootkit verdict: confirm by inspecting the \
              process and any socket it holds (ls -l /proc/<pid>/fd, ss -tanp). A shell or \
              interpreter with no controlling terminal is also normal for daemons, cron and \
              container entrypoints, so this fires only when the image is also unusual or the \
              program is a network relay tool. It cannot see a reverse shell that reuses an \
              already-running interpreter without exec, nor one renamed to a benign path."
            .into(),
    })
}

pub fn gather_facts(ev: &Event) -> ExecFacts {
    let mut f = ExecFacts::default();
    if let Ok(link) = std::fs::read_link(format!("/proc/{}/exe", ev.pid)) {
        let s = link.to_string_lossy().into_owned();
        let (path, deleted) = split_deleted(&s);
        f.exe_path = Some(path.to_string());
        f.deleted = deleted;
    }
    if let Ok(stat) = crate::saferead::read_pid_text(format!("/proc/{}/stat", ev.pid)) {
        f.tty_nr = parse_tty_nr(&stat);
    }
    f
}
