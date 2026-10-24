#[cfg(not(target_os = "windows"))]
pub fn facts() -> crate::facts::Facts {
    use crate::facts::Facts;

    let mut f = Facts::default();
    f.notes.push(
        "not a Windows host: nothing was read, and every reading below is `unreadable` \
         rather than absent"
            .to_string(),
    );
    f
}

#[cfg(target_os = "windows")]
pub use windows_impl::facts;

#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
fn parse_privilege_luids(buf: &[u8]) -> Vec<(u32, i32)> {
    const ARRAY_OFF: usize = 4;
    const ENTRY: usize = 12;
    let le_u32 = |b: &[u8]| u32::from_ne_bytes(b.try_into().unwrap_or([0; 4]));
    let Some(count_bytes) = buf.get(0..4) else {
        return Vec::new();
    };
    let declared = le_u32(count_bytes) as usize;
    let available = buf.len().saturating_sub(ARRAY_OFF) / ENTRY;
    let count = declared.min(available);
    (0..count)
        .filter_map(|i| {
            let at = ARRAY_OFF + i * ENTRY;
            let low = le_u32(buf.get(at..at + 4)?);
            let high = le_u32(buf.get(at + 4..at + 8)?) as i32;
            Some((low, high))
        })
        .collect()
}

#[cfg(target_os = "windows")]
mod windows_impl {
    use crate::facts::{Facts, Flag, Integrity, Reading};

    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, LUID};
    use windows_sys::Win32::Security::{
        GetTokenInformation, LookupPrivilegeValueW, TokenElevation, TokenIntegrityLevel,
        TokenPrivileges, TOKEN_ELEVATION, TOKEN_MANDATORY_LABEL, TOKEN_QUERY,
    };
    use windows_sys::Win32::System::Registry::{
        RegGetValueW, HKEY_LOCAL_MACHINE, RRF_RT_REG_DWORD,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(core::iter::once(0)).collect()
    }

    fn hklm_dword(subkey: &str, value: &str) -> Reading {
        let subkey = wide(subkey);
        let value = wide(value);
        let mut data: u32 = 0;
        let mut size: u32 = core::mem::size_of::<u32>() as u32;

        let rc = unsafe {
            RegGetValueW(
                HKEY_LOCAL_MACHINE,
                subkey.as_ptr(),
                value.as_ptr(),
                RRF_RT_REG_DWORD,
                core::ptr::null_mut(),
                core::ptr::addr_of_mut!(data).cast(),
                core::ptr::addr_of_mut!(size),
            )
        };

        const ERROR_FILE_NOT_FOUND: u32 = 2;
        const ERROR_PATH_NOT_FOUND: u32 = 3;
        match rc {
            0 => Reading::Value(data),
            ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND => Reading::Absent,
            _ => Reading::Unreadable,
        }
    }

    struct Token(HANDLE);

    impl Drop for Token {
        fn drop(&mut self) {

            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }

    impl Token {

        fn open() -> Option<Token> {
            let mut handle: HANDLE = core::ptr::null_mut();

            let ok = unsafe {
                OpenProcessToken(
                    GetCurrentProcess(),
                    TOKEN_QUERY,
                    core::ptr::addr_of_mut!(handle),
                )
            };
            (ok != 0).then_some(Token(handle))
        }

        fn information(&self, class: i32) -> Option<Vec<u8>> {
            let mut needed: u32 = 0;

            unsafe {
                GetTokenInformation(self.0, class, core::ptr::null_mut(), 0, &mut needed);
            }
            if needed == 0 {
                return None;
            }
            let mut buf = vec![0u8; needed as usize];

            let ok = unsafe {
                GetTokenInformation(
                    self.0,
                    class,
                    buf.as_mut_ptr().cast(),
                    needed,
                    core::ptr::addr_of_mut!(needed),
                )
            };
            (ok != 0).then_some(buf)
        }
    }

    fn integrity(token: &Token) -> Integrity {
        const UNTRUSTED: u32 = 0x0000;
        const LOW: u32 = 0x1000;
        const MEDIUM: u32 = 0x2000;
        const HIGH: u32 = 0x3000;
        const SYSTEM: u32 = 0x4000;

        let Some(buf) = token.information(TokenIntegrityLevel) else {
            return Integrity::Unknown;
        };
        if buf.len() < core::mem::size_of::<TOKEN_MANDATORY_LABEL>() {
            return Integrity::Unknown;
        }

        let label = unsafe { buf.as_ptr().cast::<TOKEN_MANDATORY_LABEL>().read_unaligned() };
        let sid = label.Label.Sid;
        if sid.is_null() {
            return Integrity::Unknown;
        }

        let last = unsafe {
            let count = *sid.cast::<u8>().add(1);
            if count == 0 {
                return Integrity::Unknown;
            }
            let sub = sid.cast::<u8>().add(8).cast::<u32>();
            *sub.add(count as usize - 1)
        };

        match last {
            SYSTEM => Integrity::System,
            HIGH => Integrity::High,
            MEDIUM => Integrity::Medium,
            LOW | UNTRUSTED => Integrity::Low,

            n if n > SYSTEM => Integrity::System,
            n if n > HIGH => Integrity::High,
            n if n > MEDIUM => Integrity::Medium,
            _ => Integrity::Low,
        }
    }

    fn elevated(token: &Token) -> Flag {
        let Some(buf) = token.information(TokenElevation) else {
            return Flag::Unreadable;
        };
        if buf.len() < core::mem::size_of::<TOKEN_ELEVATION>() {
            return Flag::Unreadable;
        }

        let e = unsafe { &*buf.as_ptr().cast::<TOKEN_ELEVATION>() };
        if e.TokenIsElevated != 0 { Flag::On } else { Flag::Off }
    }

    fn has_privilege(privileges: &[LUID], name: &str) -> Flag {
        let name = wide(name);
        let mut luid = LUID { LowPart: 0, HighPart: 0 };

        let ok = unsafe {
            LookupPrivilegeValueW(
                core::ptr::null(),
                name.as_ptr(),
                core::ptr::addr_of_mut!(luid),
            )
        };
        if ok == 0 {
            return Flag::Unreadable;
        }
        if privileges.iter().any(|p| p.LowPart == luid.LowPart && p.HighPart == luid.HighPart) {
            Flag::On
        } else {
            Flag::Off
        }
    }

    fn privileges(token: &Token) -> Option<Vec<LUID>> {
        let buf = token.information(TokenPrivileges)?;

        if buf.len() < core::mem::size_of::<u32>() {
            return None;
        }

        let out = super::parse_privilege_luids(&buf)
            .into_iter()
            .map(|(low, high)| LUID { LowPart: low, HighPart: high })
            .collect();
        Some(out)
    }

    fn build_number() -> Option<u32> {
        const NT_BUILD_NUMBER: usize = 0x7FFE_0260;

        let raw = unsafe { core::ptr::read_volatile(NT_BUILD_NUMBER as *const u32) };

        let build = raw & 0x0FFF_FFFF;
        (build > 0).then_some(build)
    }

    pub fn facts() -> Facts {
        let mut f = Facts::default();

        match Token::open() {
            None => f
                .notes
                .push("could not open this process's token; privilege is unknown".to_string()),
            Some(token) => {
                f.integrity = integrity(&token);
                f.elevated = elevated(&token);
                match privileges(&token) {
                    None => f.notes.push(
                        "could not read the token's privilege list; every privilege below \
                         is unreadable rather than absent"
                            .to_string(),
                    ),
                    Some(p) => {
                        f.se_debug = has_privilege(&p, "SeDebugPrivilege");
                        f.se_load_driver = has_privilege(&p, "SeLoadDriverPrivilege");
                        f.se_backup = has_privilege(&p, "SeBackupPrivilege");
                        f.se_security = has_privilege(&p, "SeSecurityPrivilege");
                    }
                }
            }
        }

        f.secure_boot = Flag::from_dword(
            hklm_dword(
                r"SYSTEM\CurrentControlSet\Control\SecureBoot\State",
                "UEFISecureBootEnabled",
            ),
            Flag::Off,

            Flag::Off,
        );
        f.hvci = Flag::from_dword(
            hklm_dword(
                r"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity",
                "Enabled",
            ),
            Flag::Off,
            Flag::Off,
        );
        f.vbs = Flag::from_dword(
            hklm_dword(
                r"SYSTEM\CurrentControlSet\Control\DeviceGuard",
                "EnableVirtualizationBasedSecurity",
            ),
            Flag::Off,
            Flag::Off,
        );
        let blocklist =
            hklm_dword(r"SYSTEM\CurrentControlSet\Control\CI\Config", "VulnerableDriverBlocklistEnable");

        if matches!(blocklist, crate::facts::Reading::Absent) {
            let (flag, basis) = crate::facts::infer_blocklist(build_number(), f.hvci);
            f.driver_blocklist = flag;
            f.driver_blocklist_basis = basis;
        } else {
            f.driver_blocklist = Flag::from_dword(blocklist, Flag::Off, Flag::Unreadable);
        }

        f.lsa_ppl = Flag::from_dword(
            hklm_dword(r"SYSTEM\CurrentControlSet\Control\Lsa", "RunAsPPL"),
            Flag::Off,
            Flag::Off,
        );
        f.wdigest_plaintext = Flag::from_dword(
            hklm_dword(
                r"SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest",
                "UseLogonCredential",
            ),
            Flag::Off,

            Flag::Off,
        );

        let rtp_reading = hklm_dword(
            r"SOFTWARE\Microsoft\Windows Defender\Real-Time Protection",
            "DisableRealtimeMonitoring",
        );

        f.defender_rtp_observed = matches!(rtp_reading, crate::facts::Reading::Value(_));
        f.defender_rtp = Flag::from_dword(
            rtp_reading,
            Flag::On,

            Flag::On,
        );

        f.defender_tamper = Flag::from_enum(
            hklm_dword(r"SOFTWARE\Microsoft\Windows Defender\Features", "TamperProtection"),
            &[5],
            &[0, 4],

            Flag::Off,
        );

        f
    }
}
