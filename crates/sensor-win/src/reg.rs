pub const ABSENT: u32 = 2;

#[cfg(target_os = "windows")]
const _: () = assert!(ABSENT == windows_sys::Win32::Foundation::ERROR_FILE_NOT_FOUND);

#[cfg(target_os = "windows")]
pub fn hklm_values(subkey: &str) -> Vec<(String, String)> {
    hklm_values_read(subkey).unwrap_or_default()
}

#[cfg(target_os = "windows")]
pub fn hklm_values_read(subkey: &str) -> Result<Vec<(String, String)>, u32> {
    use windows_sys::Win32::Foundation::{ERROR_MORE_DATA, ERROR_NO_MORE_ITEMS, ERROR_SUCCESS};
    use windows_sys::Win32::System::Registry::{
        RegCloseKey, RegEnumValueW, RegOpenKeyExW, HKEY, HKEY_LOCAL_MACHINE, KEY_READ,
        REG_EXPAND_SZ, REG_MULTI_SZ, REG_SZ,
    };

    const MAX_VALUE_BYTES: u32 = 16 * 1024 * 1024;

    let path: Vec<u16> = subkey.encode_utf16().chain(core::iter::once(0)).collect();
    let mut h: HKEY = core::ptr::null_mut();

    let rc = unsafe {
        RegOpenKeyExW(HKEY_LOCAL_MACHINE, path.as_ptr(), 0, KEY_READ, core::ptr::addr_of_mut!(h))
    };
    if rc != ERROR_SUCCESS {
        return Err(rc);
    }

    let mut out = Vec::new();
    for i in 0..4096u32 {

        let mut name = vec![0u16; 16_384];
        let mut data = vec![0u8; 8192];
        let mut name_len = name.len() as u32;
        let mut data_len = data.len() as u32;
        let mut kind: u32 = 0;

        let mut rc = ERROR_MORE_DATA;
        for _ in 0..2 {
            name_len = name.len() as u32;
            data_len = data.len() as u32;

            rc = unsafe {
                RegEnumValueW(
                    h,
                    i,
                    name.as_mut_ptr(),
                    core::ptr::addr_of_mut!(name_len),
                    core::ptr::null_mut(),
                    core::ptr::addr_of_mut!(kind),
                    data.as_mut_ptr().cast(),
                    core::ptr::addr_of_mut!(data_len),
                )
            };
            if rc != ERROR_MORE_DATA || data_len > MAX_VALUE_BYTES {
                break;
            }
            data.resize(data_len as usize, 0);
        }
        if rc == ERROR_NO_MORE_ITEMS {
            break;
        }
        if rc != ERROR_SUCCESS {

            continue;
        }
        if kind != REG_SZ && kind != REG_EXPAND_SZ && kind != REG_MULTI_SZ {
            continue;
        }
        let n = from_wide(name.get(..name_len as usize).unwrap_or_default());
        let chars = (data_len as usize) / 2;
        let d = from_wide(data_as_u16(&data).get(..chars).unwrap_or_default());
        out.push((n, d));
    }

    unsafe { RegCloseKey(h) };
    Ok(out)
}

#[cfg(target_os = "windows")]
pub fn hklm_dword(subkey: &str, value: &str) -> Option<u32> {
    use windows_sys::Win32::System::Registry::REG_DWORD;
    hklm_fixed::<4>(subkey, value, REG_DWORD).map(u32::from_le_bytes)
}

#[cfg(target_os = "windows")]
pub fn hklm_qword(subkey: &str, value: &str) -> Option<u64> {
    use windows_sys::Win32::System::Registry::REG_QWORD;
    hklm_fixed::<8>(subkey, value, REG_QWORD).map(u64::from_le_bytes)
}

#[cfg(target_os = "windows")]
fn hklm_fixed<const N: usize>(subkey: &str, value: &str, want: u32) -> Option<[u8; N]> {
    use windows_sys::Win32::Foundation::ERROR_SUCCESS;
    use windows_sys::Win32::System::Registry::{
        RegCloseKey, RegOpenKeyExW, RegQueryValueExW, HKEY, HKEY_LOCAL_MACHINE, KEY_READ,
    };

    let path: Vec<u16> = subkey.encode_utf16().chain(core::iter::once(0)).collect();
    let name: Vec<u16> = value.encode_utf16().chain(core::iter::once(0)).collect();
    let mut h: HKEY = core::ptr::null_mut();

    let rc = unsafe {
        RegOpenKeyExW(HKEY_LOCAL_MACHINE, path.as_ptr(), 0, KEY_READ, core::ptr::addr_of_mut!(h))
    };
    if rc != ERROR_SUCCESS {
        return None;
    }
    let mut kind: u32 = 0;
    let mut buf = [0u8; N];
    let mut len = N as u32;

    let rc = unsafe {
        RegQueryValueExW(
            h,
            name.as_ptr(),
            core::ptr::null(),
            core::ptr::addr_of_mut!(kind),
            buf.as_mut_ptr(),
            core::ptr::addr_of_mut!(len),
        )
    };

    unsafe { RegCloseKey(h) };
    if rc != ERROR_SUCCESS || kind != want || len as usize != N {
        return None;
    }
    Some(buf)
}

#[cfg(target_os = "windows")]
fn data_as_u16(data: &[u8]) -> Vec<u16> {
    let (pairs, _odd) = data.as_chunks::<2>();
    pairs.iter().copied().map(u16::from_le_bytes).collect()
}

#[cfg(target_os = "windows")]
fn from_wide(w: &[u16]) -> String {
    let end = w.iter().position(|c| *c == 0).unwrap_or(w.len());
    String::from_utf16_lossy(w.get(..end).unwrap_or_default())
}

#[cfg(not(target_os = "windows"))]
pub fn hklm_values_read(_subkey: &str) -> Result<Vec<(String, String)>, u32> {
    Ok(Vec::new())
}

#[cfg(not(target_os = "windows"))]
pub fn hklm_values(_subkey: &str) -> Vec<(String, String)> {
    Vec::new()
}

#[cfg(not(target_os = "windows"))]
pub fn hklm_dword(_subkey: &str, _value: &str) -> Option<u32> {
    None
}

#[cfg(not(target_os = "windows"))]
pub fn hklm_qword(_subkey: &str, _value: &str) -> Option<u64> {
    None
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Hive {

    Machine,

    User,

    Users,
}

#[cfg(target_os = "windows")]
pub fn default_value(hive: Hive, subkey: &str) -> Option<String> {
    use windows_sys::Win32::Foundation::ERROR_SUCCESS;
    use windows_sys::Win32::System::Registry::{
        RegCloseKey, RegOpenKeyExW, RegQueryValueExW, HKEY, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE,
        HKEY_USERS, KEY_READ, REG_EXPAND_SZ, REG_SZ,
    };

    let root = match hive {
        Hive::Machine => HKEY_LOCAL_MACHINE,
        Hive::User => HKEY_CURRENT_USER,
        Hive::Users => HKEY_USERS,
    };
    let path: Vec<u16> = subkey.encode_utf16().chain(core::iter::once(0)).collect();
    let mut h: HKEY = core::ptr::null_mut();

    if unsafe { RegOpenKeyExW(root, path.as_ptr(), 0, KEY_READ, core::ptr::addr_of_mut!(h)) }
        != ERROR_SUCCESS
    {
        return None;
    }

    let mut kind: u32 = 0;
    let mut len: u32 = 0;

    let rc = unsafe {
        RegQueryValueExW(
            h,
            core::ptr::null(),
            core::ptr::null(),
            core::ptr::addr_of_mut!(kind),
            core::ptr::null_mut(),
            core::ptr::addr_of_mut!(len),
        )
    };

    if rc != ERROR_SUCCESS || len == 0 || len > 65_536 {

        unsafe { RegCloseKey(h) };
        return None;
    }

    let mut buf = vec![0u8; len as usize];
    let mut out_len = len;

    let rc = unsafe {
        RegQueryValueExW(
            h,
            core::ptr::null(),
            core::ptr::null(),
            core::ptr::addr_of_mut!(kind),
            buf.as_mut_ptr(),
            core::ptr::addr_of_mut!(out_len),
        )
    };

    unsafe { RegCloseKey(h) };
    if rc != ERROR_SUCCESS || (kind != REG_SZ && kind != REG_EXPAND_SZ) {
        return None;
    }
    let (pairs, _odd) = buf.as_chunks::<2>();
    let wide: Vec<u16> = pairs.iter().copied().map(u16::from_le_bytes).collect();
    let s = from_wide(&wide);
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

#[cfg(target_os = "windows")]
pub fn subkeys(hive: Hive, subkey: &str) -> Vec<String> {
    subkeys_read(hive, subkey).unwrap_or_default()
}

#[cfg(target_os = "windows")]
pub fn subkeys_read(hive: Hive, subkey: &str) -> Result<Vec<String>, u32> {
    use windows_sys::Win32::Foundation::{ERROR_NO_MORE_ITEMS, ERROR_SUCCESS};
    use windows_sys::Win32::System::Registry::{
        RegCloseKey, RegEnumKeyExW, RegOpenKeyExW, HKEY, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE,
        HKEY_USERS, KEY_READ,
    };

    let root = match hive {
        Hive::Machine => HKEY_LOCAL_MACHINE,
        Hive::User => HKEY_CURRENT_USER,
        Hive::Users => HKEY_USERS,
    };
    let path: Vec<u16> = subkey.encode_utf16().chain(core::iter::once(0)).collect();
    let mut h: HKEY = core::ptr::null_mut();

    let rc = unsafe { RegOpenKeyExW(root, path.as_ptr(), 0, KEY_READ, core::ptr::addr_of_mut!(h)) };
    if rc != ERROR_SUCCESS {
        return Err(rc);
    }
    let mut out = Vec::new();
    for i in 0..16_384u32 {

        let mut name = vec![0u16; 256];
        let mut len = name.len() as u32;

        let rc = unsafe {
            RegEnumKeyExW(
                h,
                i,
                name.as_mut_ptr(),
                core::ptr::addr_of_mut!(len),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
            )
        };
        if rc == ERROR_NO_MORE_ITEMS {
            break;
        }
        if rc != ERROR_SUCCESS {
            continue;
        }
        out.push(from_wide(name.get(..len as usize).unwrap_or_default()));
    }

    unsafe { RegCloseKey(h) };
    Ok(out)
}

#[cfg(target_os = "windows")]
pub fn binary(hive: Hive, subkey: &str, value: &str, cap: usize) -> Result<Option<Vec<u8>>, u32> {
    use windows_sys::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_MORE_DATA, ERROR_SUCCESS};
    use windows_sys::Win32::System::Registry::{
        RegCloseKey, RegOpenKeyExW, RegQueryValueExW, HKEY, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, HKEY_USERS, KEY_READ,
    };
    let root = match hive {
        Hive::Machine => HKEY_LOCAL_MACHINE,
        Hive::User => HKEY_CURRENT_USER,
        Hive::Users => HKEY_USERS,
    };
    let path: Vec<u16> = subkey.encode_utf16().chain(core::iter::once(0)).collect();
    let name: Vec<u16> = value.encode_utf16().chain(core::iter::once(0)).collect();
    let mut h: HKEY = core::ptr::null_mut();

    let rc = unsafe { RegOpenKeyExW(root, path.as_ptr(), 0, KEY_READ, core::ptr::addr_of_mut!(h)) };
    if rc == ERROR_FILE_NOT_FOUND {
        return Ok(None);
    }
    if rc != ERROR_SUCCESS {
        return Err(rc);
    }
    let mut kind: u32 = 0;
    let mut len: u32 = 0;

    let rc = unsafe {
        RegQueryValueExW(h, name.as_ptr(), core::ptr::null(), core::ptr::addr_of_mut!(kind), core::ptr::null_mut(), core::ptr::addr_of_mut!(len))
    };
    if rc != ERROR_SUCCESS || len as usize > cap {

        unsafe { RegCloseKey(h) };
        return match rc {
            ERROR_FILE_NOT_FOUND => Ok(None),
            ERROR_SUCCESS => Err(ERROR_MORE_DATA),
            other => Err(other),
        };
    }
    let mut buf = vec![0u8; len as usize];
    let mut out_len = len;

    let rc = unsafe {
        RegQueryValueExW(h, name.as_ptr(), core::ptr::null(), core::ptr::addr_of_mut!(kind), buf.as_mut_ptr(), core::ptr::addr_of_mut!(out_len))
    };

    unsafe { RegCloseKey(h) };
    if rc != ERROR_SUCCESS {
        return Err(rc);
    }
    buf.truncate(out_len as usize);
    Ok(Some(buf))
}

#[cfg(not(target_os = "windows"))]
pub fn binary(_hive: Hive, _subkey: &str, _value: &str, _cap: usize) -> Result<Option<Vec<u8>>, u32> {
    Ok(None)
}

#[cfg(not(target_os = "windows"))]
pub fn default_value(_hive: Hive, _subkey: &str) -> Option<String> {
    None
}

#[cfg(not(target_os = "windows"))]
pub fn subkeys(_hive: Hive, _subkey: &str) -> Vec<String> {
    Vec::new()
}

#[cfg(not(target_os = "windows"))]
pub fn subkeys_read(_hive: Hive, _subkey: &str) -> Result<Vec<String>, u32> {
    Ok(Vec::new())
}
