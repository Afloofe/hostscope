use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};

use crate::btf;
use crate::bpfabi::{ProgLoadAttr, LinkCreateAttr};

const BPF_PROG_LOAD: i32 = 5;
const BPF_LINK_CREATE: i32 = 28;

const BPF_PROG_TYPE_LSM: u32 = 29;

const BPF_LSM_MAC: u32 = 27;

const TRIAL_HOOK: &str = "bpf_lsm_task_kill";

const NOOP_PROGRAM: [u8; 16] = [
    0xb7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {

    BtfRead,

    BtfLookup,

    Load,

    Link,
}

impl Stage {

    pub fn meaning(self, errno: i32) -> &'static str {
        match (self, errno) {
            (Stage::BtfRead, _) => {
                "/sys/kernel/btf/vmlinux could not be read — no CONFIG_DEBUG_INFO_BTF, or \
                 insufficient privilege"
            }
            (Stage::BtfLookup, libc::EPROTO) => {
                "this reader could not finish walking the kernel's BTF, so the hook may be \
                 present and unseen — a defect here, not a limitation of the host"
            }
            (Stage::BtfLookup, _) => "the kernel's BTF does not name this hook",
            (Stage::Load, libc::EPERM) | (Stage::Link, libc::EPERM) => {
                "refused for lack of privilege — re-run with CAP_BPF and CAP_SYS_ADMIN"
            }
            (Stage::Load, libc::EACCES) => "the verifier rejected the program",
            (Stage::Load, _) => "the kernel would not load an LSM program",
            (Stage::Link, libc::EINVAL) => {
                "the kernel has the hook but refused to attach — lockdown, or a partial backport"
            }
            (Stage::Link, _) => "the kernel would not create the link",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrialAttach {

    Attached,

    Refused {

        stage: Stage,

        errno: i32,
    },
}

impl TrialAttach {

    pub fn ok(&self) -> bool {
        matches!(self, TrialAttach::Attached)
    }

    pub fn detail(&self) -> String {
        match self {
            TrialAttach::Attached => {
                format!("loaded and linked a no-op {TRIAL_HOOK} program")
            }
            TrialAttach::Refused { stage, errno } => format!(
                "refused at {} with errno {errno} ({}): {}",
                match stage {
                    Stage::BtfRead => "BTF read",
                    Stage::BtfLookup => "BTF lookup",
                    Stage::Load => "program load",
                    Stage::Link => "link create",
                },
                errno_name(*errno),
                stage.meaning(*errno)
            ),
        }
    }
}

fn errno_name(e: i32) -> &'static str {
    match e {
        libc::EPERM => "EPERM",
        libc::EACCES => "EACCES",
        libc::EINVAL => "EINVAL",
        libc::ENOENT => "ENOENT",
        libc::ENOSYS => "ENOSYS",
        libc::EPROTO => "EPROTO",
        libc::E2BIG => "E2BIG",
        0 => "none",
        _ => "see errno.h",
    }
}

unsafe fn bpf(cmd: i32, attr: *const core::ffi::c_void, size: u32) -> i64 {

    unsafe { libc::syscall(libc::SYS_bpf, cmd, attr, size) }
}

pub fn trial_attach() -> TrialAttach {
    let blob = match btf::vmlinux() {
        Ok(b) => b,
        Err(errno) => return TrialAttach::Refused { stage: Stage::BtfRead, errno },
    };
    let btf_id = match btf::func_id(&blob, TRIAL_HOOK) {
        Ok(id) => id,
        Err(why) => {
            return TrialAttach::Refused {
                stage: Stage::BtfLookup,
                errno: match why {

                    btf::NotFound::WalkedEverything { .. } => libc::ENOENT,
                    btf::NotFound::NotBtf => libc::EINVAL,

                    btf::NotFound::StoppedEarly { .. } => libc::EPROTO,

                    btf::NotFound::NotByteAligned { .. } => libc::ERANGE,
                },
            }
        }
    };

    let license = c"GPL";
    let mut name = [0u8; 16];
    for (slot, byte) in name.iter_mut().zip(b"hemostat_trial") {
        *slot = *byte;
    }

    let attr = ProgLoadAttr {
        prog_type: BPF_PROG_TYPE_LSM,
        insn_cnt: (NOOP_PROGRAM.len() / 8) as u32,
        insns: NOOP_PROGRAM.as_ptr() as u64,
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
        return TrialAttach::Refused { stage: Stage::Load, errno: last_errno() };
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
        return TrialAttach::Refused { stage: Stage::Link, errno: last_errno() };
    }

    drop(unsafe { OwnedFd::from_raw_fd(link as i32) });
    TrialAttach::Attached
}

fn last_errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

const FAN_CLOEXEC: u32 = 0x0000_0001;
const FAN_NONBLOCK: u32 = 0x0000_0002;
const FAN_CLASS_CONTENT: u32 = 0x0000_0004;

const FAN_OPEN_EXEC_PERM: u64 = 0x0004_0000;

const FAN_MARK_ADD: u32 = 0x0000_0001;
const FAN_MARK_REMOVE: u32 = 0x0000_0002;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FanStage {

    Init,

    Mark,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FanotifyTrial {

    Available,

    Refused {

        stage: FanStage,

        errno: i32,
    },
}

impl FanotifyTrial {

    pub fn ok(&self) -> bool {
        matches!(self, FanotifyTrial::Available)
    }

    pub fn detail(&self) -> String {
        match self {
            FanotifyTrial::Available => {
                "opened a permission-class group and accepted a FAN_OPEN_EXEC_PERM mark".to_string()
            }
            FanotifyTrial::Refused { stage, errno } => format!(
                "refused at {} with errno {errno} ({}): {}",
                match stage {
                    FanStage::Init => "fanotify_init",
                    FanStage::Mark => "fanotify_mark",
                },
                errno_name(*errno),
                match (stage, *errno) {
                    (_, libc::EPERM) => {
                        "the permission class needs CAP_SYS_ADMIN — re-run elevated"
                    }
                    (FanStage::Init, libc::EINVAL) => {
                        "this kernel does not offer the permission class"
                    }
                    (FanStage::Mark, libc::EINVAL) => {
                        "this kernel does not accept FAN_OPEN_EXEC_PERM (needs 5.0)"
                    }
                    (FanStage::Mark, libc::ENOSYS) => "fanotify is not built into this kernel",
                    _ => "fanotify permission mode is unavailable",
                }
            ),
        }
    }
}

pub fn trial_fanotify() -> FanotifyTrial {

    let group = unsafe {
        libc::syscall(
            libc::SYS_fanotify_init,
            FAN_CLOEXEC | FAN_NONBLOCK | FAN_CLASS_CONTENT,
            libc::O_RDONLY as u32,
        )
    };
    if group < 0 {
        return FanotifyTrial::Refused { stage: FanStage::Init, errno: last_errno() };
    }

    let group = unsafe { OwnedFd::from_raw_fd(group as i32) };

    let target = c"/proc/self/exe";

    let marked = unsafe {
        libc::syscall(
            libc::SYS_fanotify_mark,
            group.as_raw_fd(),
            FAN_MARK_ADD,
            FAN_OPEN_EXEC_PERM,
            libc::AT_FDCWD,
            target.as_ptr(),
        )
    };
    if marked < 0 {
        return FanotifyTrial::Refused { stage: FanStage::Mark, errno: last_errno() };
    }

    let _ = unsafe {
        libc::syscall(
            libc::SYS_fanotify_mark,
            group.as_raw_fd(),
            FAN_MARK_REMOVE,
            FAN_OPEN_EXEC_PERM,
            libc::AT_FDCWD,
            target.as_ptr(),
        )
    };
    drop(group);
    FanotifyTrial::Available
}
