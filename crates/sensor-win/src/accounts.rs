use crate::posture::{Finding, Severity};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Account {

    pub name: String,

    pub flags: u32,

    pub administrator: bool,
}

pub const UF_ACCOUNTDISABLE: u32 = 0x0002;

pub const UF_PASSWD_NOTREQD: u32 = 0x0020;

pub const UF_DONT_EXPIRE_PASSWD: u32 = 0x1_0000;

pub const UF_LOCKOUT: u32 = 0x0010;

impl Account {

    pub const fn enabled(&self) -> bool {
        self.flags & UF_ACCOUNTDISABLE == 0
    }

    pub const fn password_not_required(&self) -> bool {
        self.flags & UF_PASSWD_NOTREQD != 0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminMember {

    pub name: String,

    pub is_group: bool,

    pub sid: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Report {

    pub accounts: Vec<Account>,

    pub admins: Vec<AdminMember>,

    pub findings: Vec<Finding>,

    pub available: bool,

    pub reason: Option<String>,

    pub admin_group: String,

    pub domain_sid: Option<String>,
}

const BUILTIN: &[&str] = &[
    "administrator",
    "guest",
    "defaultaccount",
    "wdagutilityaccount",
    "krbtgt",
];

pub fn is_builtin(name: &str) -> bool {
    BUILTIN.iter().any(|b| name.eq_ignore_ascii_case(b))
}

pub fn local_rid(sid: &str, domain_sid: Option<&str>) -> Option<u32> {
    let rid = match domain_sid {
        Some(d) => sid.strip_prefix(d)?.strip_prefix('-')?,
        None => sid.strip_prefix("S-1-5-21-")?.rsplit('-').next()?,
    };
    rid.parse().ok()
}

pub fn is_local_member(m: &AdminMember, domain_sid: Option<&str>) -> bool {
    m.sid.as_deref().is_none_or(|sid| local_rid(sid, domain_sid).is_some())
}

fn never_an_administrator(rid: u32) -> Option<&'static str> {
    match rid {
        501 => Some("Guest"),
        502 => Some("krbtgt"),
        503 => Some("DefaultAccount"),
        504 => Some("WDAGUtilityAccount"),
        _ => None,
    }
}

pub fn judge(
    accounts: &[Account],
    admins: &[AdminMember],
    domain_sid: Option<&str>,
) -> Vec<Finding> {
    let mut out = Vec::new();

    for a in accounts.iter().filter(|a| a.enabled() && a.password_not_required()) {
        out.push(Finding {
            severity: Severity::Critical,
            subject: format!("account {}", a.name),
            what: "can be logged into with no password at all".into(),
            why: format!(
                "`{}` has PASSWD_NOTREQD set and is not disabled, so it accepts an empty \
                 password. If it is also an administrator, that is a local administrator \
                 anybody who can reach a logon prompt can become{}",
                a.name,
                if a.administrator { " — and it is" } else { "" }
            ),
            fix: Some(format!(
                "set a password on `{}` or disable it. This is a manual decision: removing \
                 an account or changing its rights during an incident can take a service \
                 with it",
                a.name
            )),
        });
    }

    for a in accounts.iter().filter(|a| a.enabled() && a.name.eq_ignore_ascii_case("guest")) {
        out.push(Finding {
            severity: Severity::Critical,
            subject: format!("account {}", a.name),
            what: "the Guest account is enabled".into(),
            why: "Guest ships disabled on every version of Windows, so an enabled one was \
                  enabled deliberately. It is an unauthenticated foothold and is a standard \
                  scoring check on any hardening benchmark"
                .into(),
            fix: Some("disable Guest".into()),
        });
    }

    for m in admins {
        let rid = m.sid.as_deref().and_then(|sid| local_rid(sid, domain_sid));

        if rid == Some(500) {
            continue;
        }

        if let Some(builtin) = rid.and_then(never_an_administrator) {
            out.push(Finding {
                severity: Severity::Critical,
                subject: format!("administrator {}", m.name),
                what: format!(
                    "`{}` — the built-in {builtin} account — is a local administrator",
                    m.name
                ),
                why: format!(
                    "Windows creates {builtin} itself and never puts it in Administrators, so \
                     somebody did. A built-in account reads as part of the furniture on an \
                     account list, which is the reason to choose one{}",
                    if is_disabled(accounts, m, domain_sid) {
                        " — it is disabled now, and enabling it is one command"
                    } else {
                        ""
                    }
                ),
                fix: Some(format!(
                    "remove `{}` from the Administrators group. This is a manual decision: \
                     changing an account's rights during an incident can take a service with it",
                    m.name
                )),
            });
            continue;
        }
        let enabled = local_account(accounts, m, domain_sid).map(Account::enabled);
        out.push(Finding {
            severity: if enabled == Some(false) { Severity::Note } else { Severity::Warn },
            subject: format!("administrator {}", m.name),
            what: if m.is_group {
                format!("`{}` is a GROUP in the local Administrators group", m.name)
            } else {
                format!("`{}` is a local administrator", m.name)
            },
            why: if m.is_group {
                format!(
                    "a nested group means the real administrator list is everyone in `{}`, \
                     which this host cannot enumerate on its own if the group is a domain \
                     one. Read it wherever it is defined",
                    m.name
                )
            } else {
                format!(
                    "`{}` is not one of the accounts Windows creates{}, so somebody granted \
                     this. That may be entirely correct — confirm it against who is supposed \
                     to administer this host{}",
                    m.name,
                    if is_builtin(leaf(&m.name)) && is_local_member(m, domain_sid) {
                        " — it has the name of one, and not that account's SID"
                    } else {
                        ""
                    },
                    match enabled {
                        Some(false) => ", noting the account is currently disabled",
                        Some(true) => "",

                        None => ". It is not a local account, so it is a domain principal or \
                                 was not readable here",
                    }
                )
            },
            fix: None,
        });
    }

    out.sort_by_key(|f| std::cmp::Reverse(f.severity));
    out
}

pub fn local_account<'a>(
    accounts: &'a [Account],
    m: &AdminMember,
    domain_sid: Option<&str>,
) -> Option<&'a Account> {
    if !is_local_member(m, domain_sid) {
        return None;
    }
    accounts.iter().find(|a| a.name.eq_ignore_ascii_case(leaf(&m.name)))
}

fn is_disabled(accounts: &[Account], m: &AdminMember, domain_sid: Option<&str>) -> bool {
    local_account(accounts, m, domain_sid).is_some_and(|a| !a.enabled())
}

pub fn leaf(name: &str) -> &str {
    name.rsplit('\\').next().unwrap_or(name)
}

pub fn assemble(
    accounts: Vec<Account>,
    admins: Vec<AdminMember>,
    admin_group: String,
    domain_sid: Option<String>,
) -> Report {
    let findings = judge(&accounts, &admins, domain_sid.as_deref());
    Report { accounts, admins, findings, available: true, reason: None, admin_group, domain_sid }
}

pub fn unavailable(why: impl Into<String>) -> Report {
    Report {
        accounts: Vec::new(),
        admins: Vec::new(),
        findings: Vec::new(),
        available: false,
        reason: Some(why.into()),
        admin_group: String::new(),
        domain_sid: None,
    }
}

pub const PRIVILEGED_GROUPS: &[(u32, &str)] = &[
    (544, "Administrators"),
    (555, "Remote Desktop Users"),
    (580, "Remote Management Users"),
    (551, "Backup Operators"),
    (549, "Server Operators"),
    (548, "Account Operators"),
    (550, "Print Operators"),
    (578, "Hyper-V Administrators"),
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupRead {

    pub sid: String,

    pub name: String,

    pub members: Result<Vec<AdminMember>, String>,
}

#[cfg(target_os = "windows")]
pub fn privileged_groups() -> Vec<GroupRead> {
    read::privileged_groups()
}

#[cfg(not(target_os = "windows"))]
pub fn privileged_groups() -> Vec<GroupRead> {
    PRIVILEGED_GROUPS
        .iter()
        .map(|(rid, name)| GroupRead {
            sid: format!("S-1-5-32-{rid}"),
            name: (*name).to_string(),
            members: Err("this binary was not built for Windows".into()),
        })
        .collect()
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
    use super::{assemble, unavailable, Account, AdminMember, Report};
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::NetworkManagement::NetManagement::{
        NetApiBufferFree, NetLocalGroupGetMembers, NetUserEnum, NetUserModalsGet,
        FILTER_NORMAL_ACCOUNT, LOCALGROUP_MEMBERS_INFO_2, MAX_PREFERRED_LENGTH, USER_INFO_1,
        USER_MODALS_INFO_2,
    };
    use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
    use windows_sys::Win32::Security::{
        CreateWellKnownSid, LookupAccountSidW, WinBuiltinAdministratorsSid, PSID, SidTypeGroup,
        SidTypeWellKnownGroup, SidTypeAlias,
    };

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(core::iter::once(0)).collect()
    }

    unsafe fn pwstr(p: *const u16) -> String {
        if p.is_null() {
            return String::new();
        }
        let mut len = 0usize;

        while unsafe { *p.add(len) } != 0 {
            len += 1;

            if len > 32_768 {
                break;
            }
        }

        String::from_utf16_lossy(unsafe { core::slice::from_raw_parts(p, len) })
    }

    unsafe fn sid_text(sid: PSID) -> Option<String> {
        if sid.is_null() {
            return None;
        }
        let mut text: *mut u16 = core::ptr::null_mut();

        if unsafe { ConvertSidToStringSidW(sid, core::ptr::addr_of_mut!(text)) } == 0 {
            return None;
        }

        let out = unsafe { pwstr(text) };

        unsafe { LocalFree(text.cast()) };
        Some(out)
    }

    fn account_domain_sid() -> Option<String> {
        let mut buf: *mut u8 = core::ptr::null_mut();

        let rc = unsafe { NetUserModalsGet(core::ptr::null(), 2, core::ptr::addr_of_mut!(buf)) };
        if rc != 0 || buf.is_null() {
            return None;
        }

        let sid = unsafe { sid_text((*buf.cast::<USER_MODALS_INFO_2>()).usrmod2_domain_id) };

        unsafe { NetApiBufferFree(buf.cast()) };
        sid
    }

    fn admin_group_name() -> Option<String> {

        let mut sid = [0u8; 256];
        let mut sid_len = sid.len() as u32;

        let ok = unsafe {
            CreateWellKnownSid(
                WinBuiltinAdministratorsSid,
                core::ptr::null_mut(),
                sid.as_mut_ptr().cast(),
                core::ptr::addr_of_mut!(sid_len),
            )
        };
        if ok == 0 {
            return None;
        }

        let mut name = [0u16; 256];
        let mut name_len = name.len() as u32;
        let mut domain = [0u16; 256];
        let mut domain_len = domain.len() as u32;
        let mut kind = SidTypeGroup;

        let ok = unsafe {
            LookupAccountSidW(
                core::ptr::null(),
                sid.as_mut_ptr().cast(),
                name.as_mut_ptr(),
                core::ptr::addr_of_mut!(name_len),
                domain.as_mut_ptr(),
                core::ptr::addr_of_mut!(domain_len),
                core::ptr::addr_of_mut!(kind),
            )
        };
        if ok == 0 {
            return None;
        }
        Some(String::from_utf16_lossy(name.get(..name_len as usize).unwrap_or_default()))
    }

    fn users() -> Result<Vec<(String, u32)>, u32> {
        let mut out = Vec::new();
        let mut resume: u32 = 0;
        loop {
            let mut buf: *mut u8 = core::ptr::null_mut();
            let mut read: u32 = 0;
            let mut total: u32 = 0;

            let rc = unsafe {
                NetUserEnum(
                    core::ptr::null(),
                    1,
                    FILTER_NORMAL_ACCOUNT,
                    core::ptr::addr_of_mut!(buf),
                    MAX_PREFERRED_LENGTH,
                    core::ptr::addr_of_mut!(read),
                    core::ptr::addr_of_mut!(total),
                    core::ptr::addr_of_mut!(resume),
                )
            };

            const ERROR_MORE_DATA: u32 = 234;
            if rc != 0 && rc != ERROR_MORE_DATA {
                return Err(rc);
            }
            if !buf.is_null() {

                let items = unsafe {
                    core::slice::from_raw_parts(buf.cast::<USER_INFO_1>(), read as usize)
                };
                for u in items {

                    out.push((unsafe { pwstr(u.usri1_name) }, u.usri1_flags));
                }

                unsafe { NetApiBufferFree(buf.cast()) };
            }
            if rc != ERROR_MORE_DATA {
                return Ok(out);
            }
        }
    }

    fn group_members(group: &str) -> Result<Vec<AdminMember>, u32> {
        let g = wide(group);
        let mut out = Vec::new();
        let mut resume: usize = 0;
        loop {
            let mut buf: *mut u8 = core::ptr::null_mut();
            let mut read: u32 = 0;
            let mut total: u32 = 0;

            let rc = unsafe {
                NetLocalGroupGetMembers(
                    core::ptr::null(),
                    g.as_ptr(),
                    2,
                    core::ptr::addr_of_mut!(buf),
                    MAX_PREFERRED_LENGTH,
                    core::ptr::addr_of_mut!(read),
                    core::ptr::addr_of_mut!(total),
                    core::ptr::addr_of_mut!(resume),
                )
            };
            const ERROR_MORE_DATA: u32 = 234;
            if rc != 0 && rc != ERROR_MORE_DATA {
                return Err(rc);
            }
            if !buf.is_null() {

                let items = unsafe {
                    core::slice::from_raw_parts(
                        buf.cast::<LOCALGROUP_MEMBERS_INFO_2>(),
                        read as usize,
                    )
                };
                for m in items {

                    let name = unsafe { pwstr(m.lgrmi2_domainandname) };
                    out.push(AdminMember {
                        name,

                        is_group: m.lgrmi2_sidusage == SidTypeGroup
                            || m.lgrmi2_sidusage == SidTypeWellKnownGroup
                            || m.lgrmi2_sidusage == SidTypeAlias,

                        sid: unsafe { sid_text(m.lgrmi2_sid) },
                    });
                }

                unsafe { NetApiBufferFree(buf.cast()) };
            }
            if rc != ERROR_MORE_DATA {
                return Ok(out);
            }
        }
    }

    fn group_name_of(sid: &str) -> Result<Option<String>, u32> {
        use windows_sys::Win32::Security::Authorization::ConvertStringSidToSidW;
        const ERROR_NONE_MAPPED: u32 = 1332;
        let w = wide(sid);
        let mut psid: PSID = core::ptr::null_mut();

        if unsafe { ConvertStringSidToSidW(w.as_ptr(), core::ptr::addr_of_mut!(psid)) } == 0 {

            return Err(unsafe { windows_sys::Win32::Foundation::GetLastError() });
        }
        let mut name = [0u16; 256];
        let mut name_len = name.len() as u32;
        let mut domain = [0u16; 256];
        let mut domain_len = domain.len() as u32;
        let mut kind = SidTypeGroup;

        let ok = unsafe {
            LookupAccountSidW(
                core::ptr::null(),
                psid,
                name.as_mut_ptr(),
                core::ptr::addr_of_mut!(name_len),
                domain.as_mut_ptr(),
                core::ptr::addr_of_mut!(domain_len),
                core::ptr::addr_of_mut!(kind),
            )
        };

        let err = unsafe { windows_sys::Win32::Foundation::GetLastError() };

        unsafe { LocalFree(psid) };
        if ok == 0 {
            return if err == ERROR_NONE_MAPPED { Ok(None) } else { Err(err) };
        }
        Ok(Some(String::from_utf16_lossy(name.get(..name_len as usize).unwrap_or_default())))
    }

    pub(super) fn privileged_groups() -> Vec<super::GroupRead> {

        const NERR_GROUP_NOT_FOUND: u32 = 2220;
        const ERROR_NO_SUCH_ALIAS: u32 = 1376;
        super::PRIVILEGED_GROUPS
            .iter()
            .map(|(rid, english)| {
                let sid = format!("S-1-5-32-{rid}");
                let (name, members) = match group_name_of(&sid) {
                    Ok(None) => ((*english).to_string(), Ok(Vec::new())),
                    Err(rc) => ((*english).to_string(), Err(format!("{sid} could not be resolved (error {rc})"))),
                    Ok(Some(name)) => {
                        let m = match group_members(&name) {
                            Ok(v) => Ok(v),
                            Err(rc) if rc == NERR_GROUP_NOT_FOUND || rc == ERROR_NO_SUCH_ALIAS => Ok(Vec::new()),
                            Err(rc) => Err(format!(
                                "`{name}` could not be read (NetLocalGroupGetMembers returned {rc})"
                            )),
                        };
                        (name, m)
                    }
                };
                super::GroupRead { sid, name, members }
            })
            .collect()
    }

    pub(super) fn report() -> Report {
        let Some(group) = admin_group_name() else {
            return unavailable(
                "the built-in Administrators group could not be resolved from its SID, so \
                 this run cannot say who administers this host",
            );
        };
        let accounts = match users() {
            Ok(v) => v,
            Err(rc) => {
                return unavailable(format!(
                    "the local account list could not be read (NetUserEnum returned {rc})"
                ))
            }
        };

        let admins = match group_members(&group) {
            Ok(v) => v,
            Err(rc) => {
                return unavailable(format!(
                    "the `{group}` group could not be read (NetLocalGroupGetMembers returned \
                     {rc}), so who administers this host is unknown"
                ))
            }
        };

        let domain_sid = account_domain_sid();
        let accounts = accounts
            .into_iter()
            .map(|(name, flags)| {
                let administrator = admins.iter().any(|m| {
                    super::is_local_member(m, domain_sid.as_deref())
                        && super::leaf(&m.name).eq_ignore_ascii_case(&name)
                });
                Account { name, flags, administrator }
            })
            .collect();
        assemble(accounts, admins, group, domain_sid)
    }
}
