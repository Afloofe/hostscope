#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Trust {

    Valid,

    Unsigned,

    Broken(String),

    Untrusted(String),

    Unknown(String),
}

impl Trust {

    pub const fn is_valid(&self) -> bool {
        matches!(self, Trust::Valid)
    }

    pub const fn is_definitely_unsigned(&self) -> bool {
        matches!(self, Trust::Unsigned)
    }

    pub fn token(&self) -> &'static str {
        match self {
            Trust::Valid => "signed",
            Trust::Unsigned => "unsigned",
            Trust::Broken(_) => "signature-broken",
            Trust::Untrusted(_) => "signature-untrusted",
            Trust::Unknown(_) => "unchecked",
        }
    }
}

pub fn judge_status(status: i32) -> Trust {
    judge_status_with_last_error(status, None)
}

pub fn judge_status_with_last_error(status: i32, last_error: Option<u32>) -> Trust {

    const TRUST_E_NOSIGNATURE: i32 = 0x800B0100_u32 as i32;
    const TRUST_E_BAD_DIGEST: i32 = 0x80096010_u32 as i32;
    const TRUST_E_EXPLICIT_DISTRUST: i32 = 0x800B0111_u32 as i32;
    const TRUST_E_SUBJECT_NOT_TRUSTED: i32 = 0x800B0004_u32 as i32;
    const CERT_E_UNTRUSTEDROOT: i32 = 0x800B0109_u32 as i32;
    const CERT_E_CHAINING: i32 = 0x800B010A_u32 as i32;
    const CERT_E_EXPIRED: i32 = 0x800B0101_u32 as i32;
    const CRYPT_E_FILE_ERROR: i32 = 0x80092003_u32 as i32;

    match status {
        0 => Trust::Valid,
        TRUST_E_NOSIGNATURE => match last_error {

            Some(e) if e == TRUST_E_NOSIGNATURE as u32 => Trust::Unsigned,

            Some(e) => Trust::Broken(format!(
                "a signature is present and could not be parsed (WinVerifyTrust returned \
                 TRUST_E_NOSIGNATURE, GetLastError 0x{e:08x}) — this is not an unsigned file, \
                 it is a malformed one"
            )),
            None => Trust::Unsigned,
        },
        TRUST_E_BAD_DIGEST => Trust::Broken(
            "the file's contents do not match the hash it was signed over — it was modified \
             after signing"
                .into(),
        ),
        TRUST_E_EXPLICIT_DISTRUST => {
            Trust::Broken("the signer is explicitly distrusted on this host".into())
        }

        CERT_E_UNTRUSTEDROOT => Trust::Untrusted(
            "the signature chains to a root this host does not trust, which includes \
             self-signed certificates"
                .into(),
        ),
        CERT_E_CHAINING => Trust::Untrusted("the certificate chain could not be built".into()),
        TRUST_E_SUBJECT_NOT_TRUSTED => Trust::Untrusted("the signature was not trusted".into()),

        CERT_E_EXPIRED => Trust::Valid,
        CRYPT_E_FILE_ERROR => {
            Trust::Unknown("the file could not be read for verification".into())
        }
        other => Trust::Unknown(format!("WinVerifyTrust returned {other:#x}")),
    }
}

#[cfg(target_os = "windows")]
pub fn verify_verbose(path: &str) -> (Trust, i32, Option<i32>) {
    let (trust, embedded, catalog, _) = verify_full(path);
    (trust, embedded, catalog)
}

#[cfg(target_os = "windows")]
pub fn verify(path: &str) -> Trust {
    verify_verbose(path).0
}

#[cfg(target_os = "windows")]
pub fn verify_signer(path: &str) -> (Trust, Option<String>) {
    let (trust, _, _, signer) = verify_full(path);
    (trust, signer)
}

#[cfg(not(target_os = "windows"))]
pub fn verify_signer(path: &str) -> (Trust, Option<String>) {
    (verify(path), None)
}

#[cfg(target_os = "windows")]
fn verify_full(path: &str) -> (Trust, i32, Option<i32>, Option<String>) {
    let path = match crate::localpath::vet(path) {
        Ok(Some((p, md))) if md.is_file() => p,
        Ok(Some(_)) => return (Trust::Unknown("it is not a file".into()), 0, None, None),
        Ok(None) => return (Trust::Unknown("there is no file at that path".into()), 0, None, None),
        Err(why) => return (Trust::Unknown(format!("not opened for verification: {why}")), 0, None, None),
    };
    let (embedded_status, embedded, signer) = verify_embedded(&path);
    if !matches!(embedded, Trust::Unsigned) {
        return (embedded, embedded_status, None, signer);
    }
    let (catalog_status, verdict, signer) = verify_catalog_verbose(&path);
    (verdict, embedded_status, Some(catalog_status), signer)
}

#[cfg(target_os = "windows")]
fn signer_of(state: windows_sys::Win32::Foundation::HANDLE) -> Option<String> {
    use windows_sys::Win32::Security::Cryptography::{CertGetNameStringW, CERT_NAME_SIMPLE_DISPLAY_TYPE};
    use windows_sys::Win32::Security::WinTrust::{WTHelperGetProvSignerFromChain, WTHelperProvDataFromStateData};

    if state.is_null() {
        return None;
    }

    let prov = unsafe { WTHelperProvDataFromStateData(state) };
    if prov.is_null() {
        return None;
    }

    let sgnr = unsafe { WTHelperGetProvSignerFromChain(prov, 0, 0, 0) };
    if sgnr.is_null() {
        return None;
    }

    let (count, chain) = unsafe { ((*sgnr).csCertChain, (*sgnr).pasCertChain) };
    if count == 0 || chain.is_null() {
        return None;
    }

    let cert = unsafe { (*chain).pCert };
    if cert.is_null() {
        return None;
    }
    let mut buf = [0u16; 512];

    let n = unsafe {
        CertGetNameStringW(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, core::ptr::null(), buf.as_mut_ptr(), buf.len() as u32)
    };

    let len = (n as usize).saturating_sub(1).min(buf.len());
    let name = String::from_utf16_lossy(buf.get(..len).unwrap_or_default()).trim().to_string();
    (!name.is_empty()).then_some(name)
}

#[cfg(target_os = "windows")]
fn verify_embedded(path: &str) -> (i32, Trust, Option<String>) {
    use windows_sys::Win32::Security::WinTrust::{
        WinVerifyTrust, WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_FILE_INFO,
        WTD_CHOICE_FILE, WTD_REVOKE_NONE, WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY,
        WTD_UI_NONE,
    };

    let wide: Vec<u16> = path.encode_utf16().chain(core::iter::once(0)).collect();

    let mut file_info = WINTRUST_FILE_INFO {
        cbStruct: core::mem::size_of::<WINTRUST_FILE_INFO>() as u32,
        pcwszFilePath: wide.as_ptr(),
        hFile: core::ptr::null_mut(),
        pgKnownSubject: core::ptr::null_mut(),
    };

    let mut data: WINTRUST_DATA = unsafe { core::mem::zeroed() };
    data.cbStruct = core::mem::size_of::<WINTRUST_DATA>() as u32;
    data.dwUIChoice = WTD_UI_NONE;

    data.fdwRevocationChecks = WTD_REVOKE_NONE;
    data.dwUnionChoice = WTD_CHOICE_FILE;
    data.Anonymous.pFile = core::ptr::addr_of_mut!(file_info);
    data.dwStateAction = WTD_STATEACTION_VERIFY;

    let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    let status = unsafe {
        WinVerifyTrust(
            core::ptr::null_mut(),
            core::ptr::addr_of_mut!(action),
            core::ptr::addr_of_mut!(data).cast(),
        )
    };

    let last_error = unsafe { windows_sys::Win32::Foundation::GetLastError() };
    let verdict = judge_status_with_last_error(status, Some(last_error));
    let signer = if verdict.is_valid() { signer_of(data.hWVTStateData) } else { None };

    data.dwStateAction = WTD_STATEACTION_CLOSE;

    unsafe {
        WinVerifyTrust(
            core::ptr::null_mut(),
            core::ptr::addr_of_mut!(action),
            core::ptr::addr_of_mut!(data).cast(),
        )
    };

    (status, verdict, signer)
}

#[cfg(target_os = "windows")]
fn verify_catalog_verbose(path: &str) -> (i32, Trust, Option<String>) {
    use windows_sys::Win32::Foundation::{CloseHandle, GENERIC_READ, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Security::Cryptography::CTL_CONTEXT;

    use windows_sys::Win32::Security::Cryptography::Catalog::{
        CryptCATAdminAcquireContext2, CryptCATAdminCalcHashFromFileHandle2,
        CryptCATAdminEnumCatalogFromHash, CryptCATAdminReleaseCatalogContext,
        CryptCATAdminReleaseContext, CryptCATCatalogInfoFromContext, CATALOG_INFO,
    };
    use windows_sys::Win32::Security::WinTrust::{
        WinVerifyTrust, WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_CATALOG_INFO, WINTRUST_DATA,
        WTD_CHOICE_CATALOG, WTD_REVOKE_NONE, WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY,
        WTD_UI_NONE,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, GetFileType, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_TYPE_DISK,
        OPEN_EXISTING, SECURITY_IDENTIFICATION, SECURITY_SQOS_PRESENT,
    };

    let wide: Vec<u16> = path.encode_utf16().chain(core::iter::once(0)).collect();

    let file = unsafe {
        CreateFileW(
            wide.as_ptr(),
            GENERIC_READ,
            FILE_SHARE_READ,
            core::ptr::null(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
            core::ptr::null_mut(),
        )
    };
    if file == INVALID_HANDLE_VALUE {
        return (0, Trust::Unknown("the file could not be opened for catalog verification".into()), None);
    }

    if unsafe { GetFileType(file) } != FILE_TYPE_DISK {

        unsafe { CloseHandle(file) };
        return (0, Trust::Unknown("it opened as something other than a file on disk".into()), None);
    }

    let mut admin: isize = 0;

    let sha256: Vec<u16> = "SHA256".encode_utf16().chain(core::iter::once(0)).collect();

    if unsafe {
        CryptCATAdminAcquireContext2(
            core::ptr::addr_of_mut!(admin),
            core::ptr::null(),
            sha256.as_ptr(),
            core::ptr::null(),
            0,
        )
    } == 0
    {

        unsafe { CloseHandle(file) };
        return (0, Trust::Unknown("the catalog subsystem could not be opened".into()), None);
    }

    let mut hash_len: u32 = 0;

    unsafe {
        CryptCATAdminCalcHashFromFileHandle2(
            admin,
            file,
            core::ptr::addr_of_mut!(hash_len),
            core::ptr::null_mut(),
            0,
        );
    }
    if hash_len == 0 || hash_len > 64 {

        unsafe {
            CryptCATAdminReleaseContext(admin, 0);
            CloseHandle(file);
        }
        return (0, Trust::Unknown("the file hash could not be sized".into()), None);
    }
    let mut hash = vec![0u8; hash_len as usize];

    if unsafe {
        CryptCATAdminCalcHashFromFileHandle2(
            admin,
            file,
            core::ptr::addr_of_mut!(hash_len),
            hash.as_mut_ptr(),
            0,
        )
    } == 0
    {

        unsafe {
            CryptCATAdminReleaseContext(admin, 0);
            CloseHandle(file);
        }
        return (0, Trust::Unknown("the file hash could not be computed".into()), None);
    }

    let cat = unsafe {
        CryptCATAdminEnumCatalogFromHash(
            admin,
            hash.as_ptr(),
            hash_len,
            0,
            core::ptr::null_mut(),
        )
    };
    if cat == 0 {

        unsafe {
            CryptCATAdminReleaseContext(admin, 0);
            CloseHandle(file);
        }
        return (0, Trust::Unsigned, None);
    }

    let mut info: CATALOG_INFO = unsafe { core::mem::zeroed() };
    info.cbStruct = core::mem::size_of::<CATALOG_INFO>() as u32;

    let got_info = unsafe { CryptCATCatalogInfoFromContext(cat, core::ptr::addr_of_mut!(info), 0) };

    let mut cat_status = 0i32;
    let mut signer = None;
    let verdict = if got_info == 0 {
        Trust::Unknown("the catalog claiming this file could not be described".into())
    } else {

        let tag: String = hash.iter().map(|b| format!("{b:02X}")).collect();
        let tag_w: Vec<u16> = tag.encode_utf16().chain(core::iter::once(0)).collect();

        let mut ci: WINTRUST_CATALOG_INFO = unsafe { core::mem::zeroed() };
        ci.cbStruct = core::mem::size_of::<WINTRUST_CATALOG_INFO>() as u32;
        ci.pcwszCatalogFilePath = info.wszCatalogFile.as_ptr();
        ci.pcwszMemberTag = tag_w.as_ptr();
        ci.pcwszMemberFilePath = wide.as_ptr();
        ci.hMemberFile = file;
        ci.pbCalculatedFileHash = hash.as_mut_ptr();
        ci.cbCalculatedFileHash = hash_len;
        ci.pcCatalogContext = core::ptr::null_mut::<CTL_CONTEXT>();
        ci.hCatAdmin = admin;

        let mut data: WINTRUST_DATA = unsafe { core::mem::zeroed() };
        data.cbStruct = core::mem::size_of::<WINTRUST_DATA>() as u32;
        data.dwUIChoice = WTD_UI_NONE;
        data.fdwRevocationChecks = WTD_REVOKE_NONE;
        data.dwUnionChoice = WTD_CHOICE_CATALOG;
        data.Anonymous.pCatalog = core::ptr::addr_of_mut!(ci);
        data.dwStateAction = WTD_STATEACTION_VERIFY;

        let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;

        let status = unsafe {
            WinVerifyTrust(
                core::ptr::null_mut(),
                core::ptr::addr_of_mut!(action),
                core::ptr::addr_of_mut!(data).cast(),
            )
        };
        if judge_status(status).is_valid() {
            signer = signer_of(data.hWVTStateData);
        }

        data.dwStateAction = WTD_STATEACTION_CLOSE;

        unsafe {
            WinVerifyTrust(
                core::ptr::null_mut(),
                core::ptr::addr_of_mut!(action),
                core::ptr::addr_of_mut!(data).cast(),
            )
        };
        cat_status = status;
        judge_status(status)
    };

    unsafe {
        CryptCATAdminReleaseCatalogContext(admin, cat, 0);
        CryptCATAdminReleaseContext(admin, 0);
        CloseHandle(file);
    }
    (cat_status, verdict, signer)
}

#[cfg(not(target_os = "windows"))]
pub fn verify(_path: &str) -> Trust {
    Trust::Unknown("Authenticode is a Windows mechanism".into())
}
