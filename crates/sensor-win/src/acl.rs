#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ace {

    pub sid: String,

    pub mask: u32,

    pub allow: bool,
}

const UNPRIVILEGED_SIDS: &[&str] = &[
    "S-1-1-0",
    "S-1-5-11",
    "S-1-5-32-545",
    "S-1-5-4",
    "S-1-5-32-546",
    "S-1-5-32-547",
];

pub const FILE_ADD_FILE: u32 = 0x0002;

pub const FILE_ADD_SUBDIRECTORY: u32 = 0x0004;

pub const GENERIC_WRITE: u32 = 0x4000_0000;

pub const FILE_ALL_ACCESS: u32 = 0x001F_01FF;

pub const FILE_GENERIC_WRITE: u32 = 0x0012_0116;

pub const fn mask_allows_write(mask: u32) -> bool {
    mask & (FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY | GENERIC_WRITE) != 0
        || mask & FILE_ALL_ACCESS == FILE_ALL_ACCESS
        || mask & FILE_GENERIC_WRITE == FILE_GENERIC_WRITE
}

pub fn is_unprivileged_sid(sid: &str) -> bool {
    UNPRIVILEGED_SIDS.iter().any(|s| s.eq_ignore_ascii_case(sid))
}

pub fn grants_unprivileged_write(aces: &[Ace]) -> bool {

    aces.iter().any(|allow_ace| {
        if !allow_ace.allow || !is_unprivileged_sid(&allow_ace.sid) {
            return false;
        }
        if !mask_allows_write(allow_ace.mask) {
            return false;
        }

        !aces.iter().any(|deny| {
            !deny.allow && deny.sid == allow_ace.sid && mask_allows_write(deny.mask)
        })
    })
}

const ADMIN_SIDS: &[&str] = &["S-1-5-18", "S-1-5-32-544"];

pub fn is_admin_sid(sid: &str) -> bool {
    ADMIN_SIDS.iter().any(|s| s.eq_ignore_ascii_case(sid))
}

pub fn grantee_beyond_admins(aces: &[Ace]) -> Option<&str> {
    aces.iter()
        .find(|a| a.allow && a.mask != 0 && !ADMIN_SIDS.iter().any(|s| s.eq_ignore_ascii_case(&a.sid)))
        .map(|a| a.sid.as_str())
}

const ERROR_FILE_NOT_FOUND: u32 = 2;

const ERROR_PATH_NOT_FOUND: u32 = 3;

#[cfg(target_os = "windows")]
const _: () = assert!(
    ERROR_FILE_NOT_FOUND == windows_sys::Win32::Foundation::ERROR_FILE_NOT_FOUND
        && ERROR_PATH_NOT_FOUND == windows_sys::Win32::Foundation::ERROR_PATH_NOT_FOUND
);

pub const fn path_absent(rc: u32) -> bool {
    rc == ERROR_FILE_NOT_FOUND || rc == ERROR_PATH_NOT_FOUND
}

#[cfg(target_os = "windows")]
pub fn dacl_of(path: &str) -> Option<Vec<Ace>> {
    dacl_of_read(path).ok()
}

#[cfg(target_os = "windows")]
pub fn dacl_of_read(path: &str) -> Result<Vec<Ace>, u32> {
    use windows_sys::Win32::Foundation::{LocalFree, ERROR_SUCCESS};
    use windows_sys::Win32::Security::Authorization::{
        ConvertSidToStringSidW, GetNamedSecurityInfoW, SE_FILE_OBJECT,
    };
    use windows_sys::Win32::Security::{
        GetAce, ACCESS_ALLOWED_ACE, ACL, DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
    };

    let wide: Vec<u16> = path.encode_utf16().chain(core::iter::once(0)).collect();
    let mut dacl: *mut ACL = core::ptr::null_mut();
    let mut sd: PSECURITY_DESCRIPTOR = core::ptr::null_mut();

    let rc = unsafe {
        GetNamedSecurityInfoW(
            wide.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            core::ptr::addr_of_mut!(dacl),
            core::ptr::null_mut(),
            core::ptr::addr_of_mut!(sd),
        )
    };
    if rc != ERROR_SUCCESS {
        return Err(rc);
    }

    if dacl.is_null() {

        unsafe { LocalFree(sd.cast()) };
        return Ok(vec![Ace { sid: "S-1-1-0".into(), mask: FILE_ALL_ACCESS, allow: true }]);
    }

    let mut out = Vec::new();

    let count = unsafe { (*dacl).AceCount } as u32;
    for i in 0..count {
        let mut ace: *mut core::ffi::c_void = core::ptr::null_mut();

        if unsafe { GetAce(dacl, i, core::ptr::addr_of_mut!(ace)) } == 0 || ace.is_null() {
            continue;
        }

        let hdr = unsafe { &*(ace as *const ACCESS_ALLOWED_ACE) };
        let allow = match hdr.Header.AceType {
            0 => true,
            1 => false,

            _ => continue,
        };
        let mask = hdr.Mask;

        let sid_ptr = core::ptr::addr_of!(hdr.SidStart) as *mut core::ffi::c_void;
        let mut sid_str: *mut u16 = core::ptr::null_mut();

        if unsafe { ConvertSidToStringSidW(sid_ptr, core::ptr::addr_of_mut!(sid_str)) } == 0 {
            continue;
        }

        let s = unsafe {
            let mut len = 0usize;
            while *sid_str.add(len) != 0 {
                len += 1;
            }
            String::from_utf16_lossy(core::slice::from_raw_parts(sid_str, len))
        };

        unsafe { LocalFree(sid_str.cast()) };
        out.push(Ace { sid: s, mask, allow });
    }

    unsafe { LocalFree(sd.cast()) };
    Ok(out)
}

#[cfg(target_os = "windows")]
pub fn owner_of_read(path: &str) -> Result<String, u32> {
    use windows_sys::Win32::Foundation::{GetLastError, LocalFree, ERROR_SUCCESS};
    use windows_sys::Win32::Security::Authorization::{
        ConvertSidToStringSidW, GetNamedSecurityInfoW, SE_FILE_OBJECT,
    };
    use windows_sys::Win32::Security::{OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID};

    let wide: Vec<u16> = path.encode_utf16().chain(core::iter::once(0)).collect();
    let mut owner: PSID = core::ptr::null_mut();
    let mut sd: PSECURITY_DESCRIPTOR = core::ptr::null_mut();

    let rc = unsafe {
        GetNamedSecurityInfoW(
            wide.as_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            core::ptr::addr_of_mut!(owner),
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            core::ptr::addr_of_mut!(sd),
        )
    };
    if rc != ERROR_SUCCESS {
        return Err(rc);
    }

    if owner.is_null() {

        unsafe { LocalFree(sd.cast()) };
        return Err(u32::MAX);
    }
    let mut text: *mut u16 = core::ptr::null_mut();

    let ok = unsafe { ConvertSidToStringSidW(owner, core::ptr::addr_of_mut!(text)) };

    let err = unsafe { GetLastError() };
    if ok == 0 || text.is_null() {

        unsafe { LocalFree(sd.cast()) };
        return Err(err);
    }

    let sid = unsafe {
        let mut len = 0usize;
        while *text.add(len) != 0 {
            len += 1;
        }
        String::from_utf16_lossy(core::slice::from_raw_parts(text, len))
    };

    unsafe {
        LocalFree(text.cast());
        LocalFree(sd.cast());
    }
    Ok(sid)
}

pub const PRIVATE_SDDL: &str = "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";

#[cfg(target_os = "windows")]
pub fn create_private_dir(path: &str) -> Result<(), String> {
    use windows_sys::Win32::Foundation::{GetLastError, LocalFree};
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows_sys::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
    use windows_sys::Win32::Storage::FileSystem::CreateDirectoryW;

    let sddl: Vec<u16> = PRIVATE_SDDL.encode_utf16().chain(core::iter::once(0)).collect();
    let mut sd: PSECURITY_DESCRIPTOR = core::ptr::null_mut();

    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            core::ptr::addr_of_mut!(sd),
            core::ptr::null_mut(),
        )
    } == 0
    {

        return Err(format!("the private descriptor could not be built (error {})", unsafe { GetLastError() }));
    }
    let sa = SECURITY_ATTRIBUTES {
        nLength: core::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: sd,
        bInheritHandle: 0,
    };
    let wide: Vec<u16> = path.encode_utf16().chain(core::iter::once(0)).collect();

    let ok = unsafe { CreateDirectoryW(wide.as_ptr(), core::ptr::addr_of!(sa)) };

    let err = unsafe { GetLastError() };

    unsafe { LocalFree(sd) };
    if ok == 0 {
        return Err(format!("{path} could not be created (error {err})"));
    }
    Ok(())
}

#[cfg(not(target_os = "windows"))]
pub fn create_private_dir(path: &str) -> Result<(), String> {
    Err(format!("{path}: this binary was not built for Windows"))
}

#[cfg(not(target_os = "windows"))]
pub fn dacl_of(_path: &str) -> Option<Vec<Ace>> {
    None
}

#[cfg(not(target_os = "windows"))]
pub fn dacl_of_read(_path: &str) -> Result<Vec<Ace>, u32> {
    Err(u32::MAX)
}

#[cfg(not(target_os = "windows"))]
pub fn owner_of_read(_path: &str) -> Result<String, u32> {
    Err(u32::MAX)
}
