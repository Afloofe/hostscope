use crate::posture::{Finding, Severity};

pub const NOT_READ: &str =
    "UDP sockets are not read, so a UDP-only listener — DNS, a beacon's callback port — \
     is not in this table and nothing here says it is absent";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Socket {

    pub proto: &'static str,

    pub local: String,

    pub port: u16,

    pub remote: String,

    pub remote_port: u16,

    pub state: &'static str,

    pub pid: u32,

    pub image: Option<String>,
}

impl Socket {

    pub fn listening(&self) -> bool {
        self.state == "LISTEN"
    }

    pub fn world_reachable(&self) -> bool {
        self.listening() && !is_loopback(&self.local)
    }
}

pub fn is_loopback(addr: &str) -> bool {
    addr.starts_with("127.") || addr == "::1"
}

pub fn ipv6_text(b: &[u8; 16]) -> String {
    let g: [u16; 8] = core::array::from_fn(|i| {
        u16::from_be_bytes([b[i * 2], b[i * 2 + 1]])
    });

    if g[0..5].iter().all(|x| *x == 0) && g[5] == 0xffff {
        return format!("{}.{}.{}.{}", b[12], b[13], b[14], b[15]);
    }

    if g.iter().all(|x| *x == 0) {
        return "::".to_string();
    }

    let (mut best_start, mut best_len) = (usize::MAX, 0usize);
    let (mut run_start, mut run_len) = (0usize, 0usize);
    for (i, v) in g.iter().enumerate() {
        if *v == 0 {
            if run_len == 0 {
                run_start = i;
            }
            run_len += 1;
            if run_len > best_len {
                best_start = run_start;
                best_len = run_len;
            }
        } else {
            run_len = 0;
        }
    }
    if best_len < 2 {
        best_start = usize::MAX;
    }

    let mut out = String::with_capacity(39);
    let mut i = 0;
    while i < 8 {
        if i == best_start {
            out.push_str("::");
            i += best_len;
            continue;
        }
        if !out.is_empty() && !out.ends_with(':') {
            out.push(':');
        }
        let _ = core::fmt::Write::write_fmt(&mut out, format_args!("{:x}", g[i]));
        i += 1;
    }
    out
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Report {

    pub sockets: Vec<Socket>,

    pub findings: Vec<Finding>,

    pub available: bool,

    pub reason: Option<String>,

    pub named: usize,

    pub gaps: Vec<String>,
}

impl Report {

    pub fn complete(&self) -> bool {
        self.available && self.gaps.is_empty()
    }

    pub fn note_gaps(&mut self, v6_failed: Option<u32>, process_list_complete: bool) {
        if let Some(rc) = v6_failed {
            self.gaps.push(format!(
                "the IPv6 TCP table could not be read (GetExtendedTcpTable returned {rc}), so a \
                 v6-only listener is not in this table"
            ));
        }
        if !process_list_complete {
            self.gaps.push(
                "the process list could not be read, so no socket could be attributed to a \
                 program"
                    .into(),
            );
        }
    }
}

const WRITABLE: &[&str] = &[
    r"c:\windows\temp",
    r"c:\temp",
    r"c:\users\public",
    r"\appdata\local\temp",
    r"\appdata\roaming",
    r"\downloads\",
];

const ORDINARY: &[&str] = &[
    "svchost.exe",
    "services.exe",
    "lsass.exe",
    "system",
    "wininit.exe",
    "spoolsv.exe",
    "msmpeng.exe",
    "sshd.exe",
    "dns.exe",
    "inetinfo.exe",
    "w3wp.exe",
    "sqlservr.exe",
];

pub fn is_ordinary_listener(image: &str) -> bool {
    let leaf = image.rsplit(['\\', '/']).next().unwrap_or(image).to_lowercase();
    ORDINARY.iter().any(|o| leaf == *o)
}

pub fn under_writable(image: &str) -> Option<&'static str> {
    let p = image.to_lowercase();
    WRITABLE.iter().copied().find(|w| p.contains(w))
}

pub fn is_bare_name(image: &str) -> bool {
    !image.contains(['\\', '/'])
}

const SYSTEM_PID: u32 = 4;

pub fn judge(sockets: &[Socket], scan_complete: bool, can_open_any: bool) -> Vec<Finding> {
    let mut out = Vec::new();

    for s in sockets.iter().filter(|s| s.world_reachable()) {
        let locus = format!("{}/{} on {}", s.proto, s.port, s.local);
        match &s.image {
            Some(image) if under_writable(image).is_some() => {
                let dir = under_writable(image).unwrap_or("a user-writable directory");
                out.push(Finding {
                    severity: Severity::Critical,
                    subject: locus,
                    what: format!("`{image}` (pid {}) answers from off this host", s.pid),
                    why: format!(
                        "the program holding this port runs out of {dir}, which any \
                         non-administrator can write. Whatever is reachable on this port can \
                         be replaced by whoever can write that directory, and a service does \
                         not get installed there by accident"
                    ),
                    fix: None,
                });
            }

            Some(image) if is_bare_name(image) && s.pid != SYSTEM_PID => out.push(Finding {
                severity: if can_open_any { Severity::Warn } else { Severity::Note },
                subject: locus,
                what: format!(
                    "`{image}` (pid {}) answers from off this host, and where it runs from could \
                     not be read",
                    s.pid
                ),
                why: if can_open_any {
                    "this run holds SeDebugPrivilege, and the path query is one even a protected \
                     process answers — so this process refused it. A name with no directory \
                     cannot be checked against the writable-path rule, and a program copied to \
                     C:\\Users\\Public under a system process's name reads exactly like the \
                     real one"
                        .into()
                } else {
                    "without SeDebugPrivilege a process another account owns can refuse the \
                     path query, so this name was never checked against where the program runs \
                     from. Re-run elevated"
                        .into()
                },
                fix: None,
            }),
            Some(image) if !is_ordinary_listener(image) => {
                out.push(Finding {
                    severity: Severity::Warn,
                    subject: locus,
                    what: format!("`{image}` (pid {}) answers from off this host", s.pid),
                    why: "this is not one of the images that ordinarily answer a port on \
                          Windows. That is not a verdict — every real server runs something \
                          that is not svchost — but it is the list to read first against what \
                          this host is supposed to be running"
                        .into(),
                    fix: None,
                });
            }

            Some(_) => {}
            None => out.push(Finding {
                severity: if scan_complete { Severity::Warn } else { Severity::Note },
                subject: locus,
                what: format!("listening, and pid {} could not be named", s.pid),
                why: if scan_complete {
                    "the process table was read and this socket's owner is not in it: a port \
                     answering with nothing behind it that this host will admit to. That is \
                     what a hidden process looks like from user mode — and a process that \
                     exited between the two reads leaves the same gap, so re-run and see \
                     whether it persists"
                        .into()
                } else {
                    "the owning process could not be named because the process list was not \
                     fully readable on this run. That says nothing about the port; re-run \
                     elevated"
                        .into()
                },
                fix: None,
            }),
        }
    }

    out.sort_by_key(|f| std::cmp::Reverse(f.severity));
    out
}

pub fn assemble(mut sockets: Vec<Socket>, scan_complete: bool, can_open_any: bool) -> Report {

    sockets.sort_by(|a, b| {
        b.listening()
            .cmp(&a.listening())
            .then_with(|| a.port.cmp(&b.port))
            .then_with(|| a.proto.cmp(b.proto))
    });
    let named = sockets.iter().filter(|s| s.image.is_some()).count();
    let findings = judge(&sockets, scan_complete, can_open_any);
    Report { sockets, findings, available: true, reason: None, named, gaps: Vec::new() }
}

pub fn unavailable(why: impl Into<String>) -> Report {
    Report {
        sockets: Vec::new(),
        findings: Vec::new(),
        available: false,
        reason: Some(why.into()),
        named: 0,
        gaps: Vec::new(),
    }
}

#[cfg(not(target_os = "windows"))]
pub fn report() -> Report {
    unavailable("this binary was not built for Windows")
}

#[cfg(target_os = "windows")]
pub fn report() -> Report {
    read::report()
}

#[cfg(target_os = "windows")]
mod read {
    use super::{assemble, unavailable, Report, Socket};
    use std::collections::BTreeMap;
    use windows_sys::Win32::Foundation::{CloseHandle, ERROR_INSUFFICIENT_BUFFER, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetExtendedTcpTable, MIB_TCP6ROW_OWNER_PID, MIB_TCPROW_OWNER_PID,
        TCP_TABLE_OWNER_PID_ALL,
    };
    use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6};
    use windows_sys::Win32::System::Threading::{
        OpenProcess, QueryFullProcessImageNameW, PROCESS_QUERY_LIMITED_INFORMATION,
    };
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };

    fn state_name(v: u32) -> &'static str {
        match v {
            1 => "CLOSED",
            2 => "LISTEN",
            3 => "SYN_SENT",
            4 => "SYN_RCVD",
            5 => "ESTABLISHED",
            6 => "FIN_WAIT1",
            7 => "FIN_WAIT2",
            8 => "CLOSE_WAIT",
            9 => "CLOSING",
            10 => "LAST_ACK",
            11 => "TIME_WAIT",
            12 => "DELETE_TCB",
            _ => "UNKNOWN",
        }
    }

    fn port(raw: u32) -> u16 {
        u16::from_be((raw & 0xFFFF) as u16)
    }

    fn ipv4(raw: u32) -> String {
        let b = raw.to_ne_bytes();
        format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3])
    }

    fn process_names() -> (BTreeMap<u32, String>, bool) {
        let mut out = BTreeMap::new();

        let snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
        if snap == INVALID_HANDLE_VALUE {
            return (out, false);
        }

        let mut e: PROCESSENTRY32W = unsafe { core::mem::zeroed() };
        e.dwSize = core::mem::size_of::<PROCESSENTRY32W>() as u32;

        let mut ok = unsafe { Process32FirstW(snap, core::ptr::addr_of_mut!(e)) };
        while ok != 0 {
            let name = {
                let raw = &e.szExeFile;
                let end = raw.iter().position(|c| *c == 0).unwrap_or(raw.len());
                String::from_utf16_lossy(raw.get(..end).unwrap_or_default())
            };
            out.insert(e.th32ProcessID, name);

            ok = unsafe { Process32NextW(snap, core::ptr::addr_of_mut!(e)) };
        }

        unsafe { CloseHandle(snap) };
        let complete = !out.is_empty();
        (out, complete)
    }

    fn full_path(pid: u32) -> Option<String> {
        if pid == 0 {
            return None;
        }

        let h = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
        if h.is_null() {
            return None;
        }
        let mut buf = [0u16; 32_768];
        let mut len = buf.len() as u32;

        let ok = unsafe {
            QueryFullProcessImageNameW(h, 0, buf.as_mut_ptr(), core::ptr::addr_of_mut!(len))
        };

        unsafe { CloseHandle(h) };
        if ok == 0 {
            return None;
        }
        Some(String::from_utf16_lossy(buf.get(..len as usize).unwrap_or_default()))
    }

    fn tcp_table(family: u32, proto: &'static str, out: &mut Vec<Socket>) -> Result<(), u32> {
        let mut size: u32 = 0;

        let rc = unsafe {
            GetExtendedTcpTable(
                core::ptr::null_mut(),
                core::ptr::addr_of_mut!(size),
                0,
                family,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            )
        };
        if rc != ERROR_INSUFFICIENT_BUFFER && rc != 0 {
            return Err(rc);
        }
        if size == 0 {
            return Ok(());
        }
        let mut buf = vec![0u8; size as usize];

        let rc = unsafe {
            GetExtendedTcpTable(
                buf.as_mut_ptr().cast(),
                core::ptr::addr_of_mut!(size),
                0,
                family,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            )
        };
        if rc != 0 {
            return Err(rc);
        }

        let Some(head) = buf.get(..4) else { return Ok(()) };
        let count = u32::from_ne_bytes([head[0], head[1], head[2], head[3]]) as usize;

        if family == AF_INET6 as u32 {
            let stride = core::mem::size_of::<MIB_TCP6ROW_OWNER_PID>();
            for i in 0..count {
                let start = 4 + i * stride;
                let Some(slice) = buf.get(start..start + stride) else { break };

                let row: MIB_TCP6ROW_OWNER_PID =
                    unsafe { core::ptr::read_unaligned(slice.as_ptr().cast()) };
                let listening = state_name(row.dwState) == "LISTEN";
                out.push(Socket {
                    proto,
                    local: super::ipv6_text(&row.ucLocalAddr),
                    port: port(row.dwLocalPort),
                    remote: if listening {
                        String::new()
                    } else {
                        super::ipv6_text(&row.ucRemoteAddr)
                    },
                    remote_port: if listening { 0 } else { port(row.dwRemotePort) },
                    state: state_name(row.dwState),
                    pid: row.dwOwningPid,
                    image: None,
                });
            }
            return Ok(());
        }

        let stride = core::mem::size_of::<MIB_TCPROW_OWNER_PID>();
        for i in 0..count {
            let start = 4 + i * stride;
            let Some(slice) = buf.get(start..start + stride) else { break };

            let row: MIB_TCPROW_OWNER_PID =
                unsafe { core::ptr::read_unaligned(slice.as_ptr().cast()) };
            let listening = state_name(row.dwState) == "LISTEN";
            out.push(Socket {
                proto,
                local: ipv4(row.dwLocalAddr),
                port: port(row.dwLocalPort),
                remote: if listening { String::new() } else { ipv4(row.dwRemoteAddr) },
                remote_port: if listening { 0 } else { port(row.dwRemotePort) },
                state: state_name(row.dwState),
                pid: row.dwOwningPid,
                image: None,
            });
        }
        Ok(())
    }

    pub(super) fn report() -> Report {

        let can_open_any = crate::modules::enable_debug_privilege();
        let mut sockets = Vec::new();
        if let Err(rc) = tcp_table(AF_INET as u32, "tcp", &mut sockets) {
            return unavailable(format!(
                "the IPv4 TCP table could not be read (GetExtendedTcpTable returned {rc}), so \
                 nothing is claimed about what this host is listening to"
            ));
        }

        let mut v6_failed = None;
        if let Err(rc) = tcp_table(AF_INET6 as u32, "tcp6", &mut sockets) {
            v6_failed = Some(rc);
        }

        let (names, complete) = process_names();

        for s in &mut sockets {
            s.image = full_path(s.pid).or_else(|| names.get(&s.pid).cloned());
        }
        let mut r = assemble(sockets, complete, can_open_any);
        r.note_gaps(v6_failed, complete);
        r
    }
}
