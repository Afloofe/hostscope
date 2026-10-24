use crate::posture::{Finding, Severity};
use hs_core::toolchain::{Identified, Toolchain};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Module {

    pub process: String,

    pub pid: u32,

    pub name: String,

    pub path: String,
}

const SYSTEM_LOAD_DIRS: &[&str] = &[
    "c:/windows/system32",
    "c:/windows/syswow64",
    "c:/windows/winsxs",
    "c:/windows/assembly",
    "c:/windows/microsoft.net",
    "c:/program files",
    "c:/program files (x86)",
    "c:/windows/servicing",
    "c:/windows/systemapps",
    "c:/program files/windowsapps",

    "c:/windows/shellcomponents",
    "c:/windows/shellexperiences",
];

const WRITABLE_DIRS: &[&str] =
    &["c:/users/public", "c:/windows/temp", "c:/temp", "c:/programdata", "c:/perflogs"];

const SYSTEM_PROCESSES: &[&str] = &[
    "explorer.exe",
    "lsass.exe",
    "winlogon.exe",
    "services.exe",
    "csrss.exe",
    "smss.exe",
    "svchost.exe",
    "spoolsv.exe",
    "dwm.exe",
    "taskhostw.exe",
    "runtimebroker.exe",
    "sihost.exe",
];

fn normalise(p: &str) -> String {
    p.trim().trim_matches('"').replace('\\', "/").to_ascii_lowercase()
}

fn is_explorers_own_image(m: &Module) -> bool {
    let leaf = |s: &str| s.rsplit(['/', '\\']).next().unwrap_or(s).to_ascii_lowercase();
    leaf(&m.process) == "explorer.exe"
        && m.name.eq_ignore_ascii_case("explorer.exe")
        && normalise(&m.path) == "c:/windows/explorer.exe"
}

pub fn is_system_process(name: &str) -> bool {
    let n = name.rsplit(['/', '\\']).next().unwrap_or(name).to_ascii_lowercase();
    SYSTEM_PROCESSES.iter().any(|p| *p == n)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {

    System,

    UserWritable,

    Elsewhere,

    Unknown,
}

pub fn origin(path: &str) -> Origin {
    if path.trim().is_empty() {
        return Origin::Unknown;
    }
    let p = normalise(path);
    if WRITABLE_DIRS.iter().any(|d| under(&p, d)) {
        return Origin::UserWritable;
    }
    if SYSTEM_LOAD_DIRS.iter().any(|d| under(&p, d)) {
        return Origin::System;
    }
    Origin::Elsewhere
}

fn under(path: &str, dir: &str) -> bool {
    path.strip_prefix(dir).is_some_and(|rest| rest.starts_with('/'))
}

pub fn judge(m: &Module, ident: Option<&Identified>) -> Option<Finding> {
    let sysproc = is_system_process(&m.process);
    let org = origin(&m.path);

    if sysproc && org == Origin::UserWritable {
        return Some(Finding {
            severity: Severity::Critical,
            subject: format!("module:{}:{}", m.process, m.name),
            what: format!(
                "{} (pid {}) has {} mapped from {}, which any user can write to",
                m.process, m.pid, m.name, m.path
            ),
            why: "a system process loading code from a world-writable directory is either a \
                  hijack that already succeeded or an injection that already happened. This is \
                  read from the process itself, so no registry key had to be honest for it to \
                  be true"
                .into(),
            fix: Some(format!(
                "capture {} before touching it, then find what made {} load it — a shell \
                 extension, a search-order hijack or a direct injection",
                m.path, m.process
            )),
        });
    }

    if let Some(id) = ident {
        if sysproc && matches!(id.toolchain, Toolchain::Go | Toolchain::Nim) {
            return Some(Finding {
                severity: Severity::Critical,
                subject: format!("module:{}:{}", m.process, m.name),
                what: format!(
                    "{} (pid {}) has {} mapped, and that module was built with {} — {}",
                    m.process,
                    m.pid,
                    m.name,
                    id.toolchain.token(),
                    id.evidence
                ),
                why: "Windows components are not written in Go or Nim. A module in one of those \
                      toolchains inside a system process was brought here, whatever directory it \
                      is sitting in"
                    .into(),
                fix: Some(format!("capture {} and identify what loaded it", m.path)),
            });
        }
    }

    if sysproc && org == Origin::Elsewhere && !is_explorers_own_image(m) {
        return Some(Finding {
            severity: Severity::Warn,
            subject: format!("module:{}:{}", m.process, m.name),
            what: format!("{} (pid {}) has {} mapped from {}", m.process, m.pid, m.name, m.path),
            why: "third-party code inside a Windows process is usually a registered shell or COM \
                  extension, which is also how an attacker gets persistent execution in a trusted \
                  process without creating one"
                .into(),
            fix: Some(format!("check what registered {} and whether it is signed", m.name)),
        });
    }

    if sysproc && org == Origin::Unknown {
        return Some(Finding {
            severity: Severity::Warn,
            subject: format!("module:{}:{}", m.process, m.name),
            what: format!("{} (pid {}) has {} mapped with no readable path", m.process, m.pid, m.name),
            why: "a module whose path cannot be read is a module this sweep did not check. That \
                  is not the same as one it checked and cleared"
                .into(),
            fix: None,
        });
    }

    None
}

#[cfg(target_os = "windows")]
pub fn modules_of(pid: u32, process: &str) -> Result<Vec<Module>, u32> {
    use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, MODULEENTRY32W,
        TH32CS_SNAPMODULE, TH32CS_SNAPMODULE32,
    };

    let snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid) };
    if snap == INVALID_HANDLE_VALUE {

        return Err(unsafe { GetLastError() });
    }

    let mut out = Vec::new();

    let mut e: MODULEENTRY32W = unsafe { core::mem::zeroed() };
    e.dwSize = core::mem::size_of::<MODULEENTRY32W>() as u32;

    let mut ok = unsafe { Module32FirstW(snap, core::ptr::addr_of_mut!(e)) };
    while ok != 0 {
        let name = from_wide(&e.szModule);
        let path = from_wide(&e.szExePath);
        out.push(Module { process: process.to_string(), pid, name, path });

        ok = unsafe { Module32NextW(snap, core::ptr::addr_of_mut!(e)) };
    }

    unsafe { CloseHandle(snap) };
    Ok(out)
}

#[cfg(target_os = "windows")]
pub fn processes() -> Vec<(u32, String)> {
    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };

    let snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if snap == INVALID_HANDLE_VALUE {
        return Vec::new();
    }
    let mut out = Vec::new();

    let mut e: PROCESSENTRY32W = unsafe { core::mem::zeroed() };
    e.dwSize = core::mem::size_of::<PROCESSENTRY32W>() as u32;

    let mut ok = unsafe { Process32FirstW(snap, core::ptr::addr_of_mut!(e)) };
    while ok != 0 {
        out.push((e.th32ProcessID, from_wide(&e.szExeFile)));

        ok = unsafe { Process32NextW(snap, core::ptr::addr_of_mut!(e)) };
    }

    unsafe { CloseHandle(snap) };
    out
}

#[cfg(not(target_os = "windows"))]
pub fn processes() -> Vec<(u32, String)> {
    Vec::new()
}

pub fn open_failure(process: &str, code: u32) -> (bool, String) {
    open_failure_measured(process, code, Protection::Unknown)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protection {

    Protected(u32),

    None,

    Unknown,
}

pub const PROTECTION_LEVEL_NONE: u32 = 0xFFFF_FFFE;

impl Protection {

    pub const fn from_level(level: u32) -> Self {
        if level == PROTECTION_LEVEL_NONE {
            Protection::None
        } else {
            Protection::Protected(level)
        }
    }

    pub fn signer(self) -> &'static str {
        match self {
            Protection::Protected(0) => "PsProtectedSignerWinTcb-Light",
            Protection::Protected(1) => "PsProtectedSignerWindows",
            Protection::Protected(2) => "PsProtectedSignerWindows-Light",
            Protection::Protected(3) => "PsProtectedSignerAntimalware-Light",
            Protection::Protected(4) => "PsProtectedSignerLsa-Light",
            Protection::Protected(5) => "PsProtectedSignerWinTcb",
            Protection::Protected(6) => "PsProtectedSignerCodeGen-Light",
            Protection::Protected(7) => "PsProtectedSignerAuthenticode",
            Protection::Protected(8) => "PsProtectedSignerApp-Light",
            Protection::Protected(_) => "a protection level this build does not name",
            Protection::None => "not protected",
            Protection::Unknown => "unknown",
        }
    }
}

pub fn open_failure_measured(process: &str, code: u32, protection: Protection) -> (bool, String) {
    if code == 5 {
        match protection {
            Protection::Protected(_) => {
                return (
                    true,
                    format!(
                        "{process} is a protected process ({}); the kernel refuses its module \
                         list to every caller, SeDebugPrivilege included. Expected, and not a \
                         gap this agent can close without a driver",
                        protection.signer()
                    ),
                );
            }
            Protection::None if is_protected_by_design(process) => {
                return (
                    false,
                    format!(
                        "{process} refused access, and the kernel says it is NOT a protected \
                         process — which the real {process} always is. Something carrying \
                         that name is refusing a token that holds SeDebugPrivilege; worth \
                         looking at rather than accepting"
                    ),
                );
            }
            _ => {}
        }
    }
    let protected = is_protected_by_design(process);
    let hardened = refuses_on_a_stock_host(process);
    let text = match code {

        5 if protected => format!(
            "{process} is a protected process; the kernel refuses its module list to every \
             caller, SeDebugPrivilege included. Expected, and not a gap this agent can close \
             without a driver"
        ),
        5 if hardened => format!(
            "{process} refused its module list, which it does on a stock host too — measured \
             against PowerShell on a clean Server 2022, which also gets only the main module. \
             Its modules are unexamined either way, but this is not a sign of anything"
        ),
        5 => format!(
            "{process} refused access even though it is not protected by design and this token \
             holds SeDebugPrivilege — worth looking at rather than accepting"
        ),

        299 => format!(
            "{process}'s module list changed while it was being read; a retry usually succeeds"
        ),

        87 => format!("{process} exited between being listed and being opened"),
        other => format!("{process} could not be opened: error {other}"),
    };
    (protected || hardened, text)
}

pub fn refuses_on_a_stock_host(process: &str) -> bool {
    let n = process.rsplit(['/', '\\']).next().unwrap_or(process).to_ascii_lowercase();
    matches!(n.as_str(), "lsass.exe" | "services.exe" | "wininit.exe" | "secure system")
}

pub fn is_protected_by_design(process: &str) -> bool {
    let n = process.rsplit(['/', '\\']).next().unwrap_or(process).to_ascii_lowercase();
    matches!(n.as_str(), "smss.exe" | "csrss.exe" | "registry" | "memory compression" | "system")
}

#[cfg(target_os = "windows")]
fn from_wide(w: &[u16]) -> String {
    let end = w.iter().position(|c| *c == 0).unwrap_or(w.len());
    String::from_utf16_lossy(w.get(..end).unwrap_or_default())
}

#[cfg(target_os = "windows")]
pub fn protection_of(pid: u32) -> Protection {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Threading::{
        GetProcessInformation, OpenProcess, ProcessProtectionLevelInfo,
        PROCESS_PROTECTION_LEVEL_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION,
    };

    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if handle.is_null() {
        return Protection::Unknown;
    }
    let mut info = PROCESS_PROTECTION_LEVEL_INFORMATION { ProtectionLevel: 0 };

    let ok = unsafe {
        GetProcessInformation(
            handle,
            ProcessProtectionLevelInfo,
            core::ptr::addr_of_mut!(info).cast(),
            core::mem::size_of::<PROCESS_PROTECTION_LEVEL_INFORMATION>() as u32,
        )
    };

    unsafe { CloseHandle(handle) };
    if ok == 0 {
        Protection::Unknown
    } else {
        Protection::from_level(info.ProtectionLevel)
    }
}

#[cfg(not(target_os = "windows"))]
pub fn protection_of(_pid: u32) -> Protection {
    Protection::Unknown
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FileKey {
    volume: u64,
    index: u64,
    size: u64,
    modified: u64,
}

#[cfg(target_os = "windows")]
fn file_key(f: &std::fs::File) -> Option<FileKey> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
    };

    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { core::mem::zeroed() };

    let ok = unsafe { GetFileInformationByHandle(f.as_raw_handle(), core::ptr::addr_of_mut!(info)) };
    (ok != 0).then(|| FileKey {
        volume: u64::from(info.dwVolumeSerialNumber),
        index: (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow),
        size: (u64::from(info.nFileSizeHigh) << 32) | u64::from(info.nFileSizeLow),
        modified: (u64::from(info.ftLastWriteTime.dwHighDateTime) << 32)
            | u64::from(info.ftLastWriteTime.dwLowDateTime),
    })
}

#[cfg(unix)]
fn file_key(f: &std::fs::File) -> Option<FileKey> {
    use std::os::unix::fs::MetadataExt;
    let md = f.metadata().ok()?;
    Some(FileKey {
        volume: md.dev(),
        index: md.ino(),
        size: md.size(),
        modified: (md.mtime() as u64).wrapping_mul(1_000_000_000).wrapping_add(md.mtime_nsec() as u64),
    })
}

#[cfg(not(any(unix, target_os = "windows")))]
fn file_key(_f: &std::fs::File) -> Option<FileKey> {
    None
}

pub const MAX_MODULE_BYTES: u64 = 256 * 1024 * 1024;

#[derive(Debug, Default)]
pub struct IdentCache {
    answers: std::collections::HashMap<FileKey, Option<Identified>>,

    pub reads: usize,

    pub hits: usize,
}

impl IdentCache {

    pub fn identify(&mut self, path: &str) -> Option<Identified> {
        use std::io::Read as _;
        let f = std::fs::File::open(path).ok()?;
        let key = file_key(&f);
        if let Some(k) = key {
            if let Some(answer) = self.answers.get(&k) {
                self.hits += 1;
                return answer.clone();
            }
        }
        self.reads += 1;
        let mut bytes = Vec::new();
        let answer = f
            .take(MAX_MODULE_BYTES)
            .read_to_end(&mut bytes)
            .ok()
            .map(|_| hs_core::toolchain::identify(&bytes));
        if let Some(k) = key {
            self.answers.insert(k, answer.clone());
        }
        answer
    }
}

#[cfg(not(target_os = "windows"))]
pub fn modules_of(_pid: u32, _process: &str) -> Result<Vec<Module>, u32> {
    Err(0)
}

#[cfg(target_os = "windows")]
pub fn enable_debug_privilege() -> bool {
    enable_privilege("SeDebugPrivilege")
}

#[cfg(target_os = "windows")]
pub fn enable_privilege(privilege: &str) -> bool {
    let Some(token) = Token::open(privilege) else { return false };
    let (enabled, _previous) = token.enable();
    enabled
}

#[cfg(target_os = "windows")]
pub fn with_privilege<T>(privilege: &str, f: impl FnOnce(bool) -> T) -> T {
    use windows_sys::Win32::Security::AdjustTokenPrivileges;

    let Some(token) = Token::open(privilege) else { return f(false) };
    let (enabled, previous) = token.enable();
    let out = f(enabled);
    if let Some(previous) = previous {

        unsafe {
            AdjustTokenPrivileges(
                token.handle,
                0,
                core::ptr::addr_of!(previous),
                0,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
            );
        }
    }
    out
}

#[cfg(target_os = "windows")]
struct Token {
    handle: windows_sys::Win32::Foundation::HANDLE,
    luid: windows_sys::Win32::Foundation::LUID,
}

#[cfg(target_os = "windows")]
impl Token {
    fn open(privilege: &str) -> Option<Self> {
        use windows_sys::Win32::Foundation::LUID;
        use windows_sys::Win32::Security::{LookupPrivilegeValueW, TOKEN_ADJUST_PRIVILEGES, TOKEN_QUERY};
        use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

        let name: Vec<u16> = privilege.encode_utf16().chain(core::iter::once(0)).collect();
        let mut luid = LUID { LowPart: 0, HighPart: 0 };

        if unsafe {
            LookupPrivilegeValueW(core::ptr::null(), name.as_ptr(), core::ptr::addr_of_mut!(luid))
        } == 0
        {
            return None;
        }
        let mut handle = core::ptr::null_mut();

        if unsafe {
            OpenProcessToken(
                GetCurrentProcess(),
                TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                core::ptr::addr_of_mut!(handle),
            )
        } == 0
        {
            return None;
        }
        Some(Self { handle, luid })
    }

    fn enable(&self) -> (bool, Option<windows_sys::Win32::Security::TOKEN_PRIVILEGES>) {
        use windows_sys::Win32::Foundation::{GetLastError, ERROR_NOT_ALL_ASSIGNED};
        use windows_sys::Win32::Security::{
            AdjustTokenPrivileges, LUID_AND_ATTRIBUTES, SE_PRIVILEGE_ENABLED, TOKEN_PRIVILEGES,
        };

        let tp = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [LUID_AND_ATTRIBUTES { Luid: self.luid, Attributes: SE_PRIVILEGE_ENABLED }],
        };
        let mut previous = TOKEN_PRIVILEGES {
            PrivilegeCount: 0,
            Privileges: [LUID_AND_ATTRIBUTES {
                Luid: windows_sys::Win32::Foundation::LUID { LowPart: 0, HighPart: 0 },
                Attributes: 0,
            }],
        };
        let mut len: u32 = 0;

        let ok = unsafe {
            AdjustTokenPrivileges(
                self.handle,
                0,
                core::ptr::addr_of!(tp),
                u32::try_from(core::mem::size_of::<TOKEN_PRIVILEGES>()).unwrap_or(0),
                core::ptr::addr_of_mut!(previous),
                core::ptr::addr_of_mut!(len),
            )
        };

        let enabled = ok != 0 && unsafe { GetLastError() } != ERROR_NOT_ALL_ASSIGNED;
        (enabled, (ok != 0).then_some(previous))
    }
}

#[cfg(target_os = "windows")]
impl Drop for Token {
    fn drop(&mut self) {

        unsafe { windows_sys::Win32::Foundation::CloseHandle(self.handle) };
    }
}

#[cfg(not(target_os = "windows"))]
pub fn enable_debug_privilege() -> bool {
    false
}
