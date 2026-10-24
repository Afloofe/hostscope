use crate::posture::{Finding, Severity};

pub const SERVICE_NAMES: &[&str] = &["Sysmon64", "Sysmon"];

pub const DEFAULT_DRIVER: &str = "SysmonDrv";

pub const DEFAULT_DRIVER_IMAGE: &str = "SysmonDrv.sys";

pub const ALTITUDE: &str = "385201";

pub fn is_sysmon_driver(image_path: Option<&str>, altitudes: &[String]) -> bool {
    image_path.is_some_and(|p| p.to_ascii_lowercase().contains("sysmondrv"))
        || altitudes.iter().any(|a| a.trim() == ALTITUDE)
}

pub const CONFIG_CHANGED_EVENT_ID: u32 = 16;

pub const SERVICE_STATE_EVENT_ID: u32 = 4;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct State {

    pub service: Option<String>,

    pub service_start: Option<u32>,

    pub driver_service: Option<String>,

    pub driver_loaded: Option<bool>,

    pub attached_volumes: Option<usize>,

    pub rules_bytes: Option<usize>,

    pub hashing: Option<String>,

    pub archive_directory: Option<String>,

    pub params_unreadable: bool,

    pub service_unreadable: bool,

    pub service_state: Option<u32>,

    pub traces: Vec<String>,
}

impl State {

    pub const fn installed(&self) -> bool {
        self.service.is_some()
    }

    pub fn renamed_driver(&self) -> bool {
        self.driver_service.as_ref().is_some_and(|d| d != DEFAULT_DRIVER)
    }
}

pub const MIN_REAL_RULESET: usize = 2048;

pub fn judge(s: &State) -> Vec<Finding> {
    let mut f = Vec::new();

    if !s.installed() && s.service_unreadable {
        f.push(Finding {
            severity: Severity::Warn,
            subject: "sysmon".into(),
            what: "whether Sysmon is installed was NOT established".into(),
            why: "the service keys could not be read — see the gaps. This is not the same as \
                  Sysmon being absent, and it is the more interesting of the two: a key this \
                  process may not open is a key somebody may have ACL'd, and an agent that \
                  reports the host as having no EDR is doing the hiding for them. Re-run \
                  elevated before concluding anything about this host's telemetry"
                .into(),
            fix: Some("re-run as SYSTEM or an administrator".into()),
        });
    } else if !s.installed() && !s.traces.is_empty() {

        f.push(Finding {
            severity: Severity::Critical,
            subject: "sysmon".into(),
            what: format!(
                "Sysmon is NOT installed now, but it was: {}",
                s.traces.join("; ")
            ),
            why: "a host that never had Sysmon carries none of these. An uninstall — \
                  `sysmon -u`, or deleting the service key by hand — leaves them behind, and so \
                  does an administrator retiring it on purpose, which this cannot tell apart \
                  from an intruder removing the telemetry before acting. Either way the Sysmon \
                  record ends at the removal, and everything after it has to be reconstructed \
                  from the Security channel. Date it from the end of the Sysmon channel (event 4 \
                  is its own service state change) and from System events 7036/7040/7045 for \
                  the service"
                .into(),
            fix: Some(
                "establish who removed it and when before relying on anything after that point; \
                 if it was not a planned change, reinstall from known-good media and treat the \
                 gap as part of the incident"
                    .into(),
            ),
        });
        return f;
    } else if !s.installed() {
        f.push(Finding {
            severity: Severity::Note,
            subject: "sysmon".into(),
            what: "Sysmon is not installed on this host".into(),
            why: "an inventory fact rather than a fault — most hosts never had it. It matters \
                  for what follows: without Sysmon there is no record of process command lines \
                  beyond what 4688 carries, no network-connection-to-process attribution, no \
                  image-load events and no record of a process opening another's memory. \
                  Reconstruct from the Security channel and artefacts instead, and do not read \
                  the empty Sysmon channel as a quiet host"
                .into(),
            fix: None,
        });
        return f;
    }

    if s.driver_loaded == Some(true) && s.attached_volumes == Some(0) {
        f.push(Finding {
            severity: Severity::Critical,
            subject: "sysmon".into(),
            what: format!(
                "the {} driver is loaded but attached to NO volumes",
                s.driver_service.as_deref().unwrap_or(DEFAULT_DRIVER)
            ),
            why: "`fltmc detach` removes a minifilter from a volume without unloading the \
                  image, so the driver is still in the loaded-driver list, the service still \
                  reports RUNNING, and every registry key is where it was — while the filter \
                  sees nothing at all. A minifilter attached to nothing records nothing. This \
                  is the quieter half of the pair `fltmc unload` makes loud"
                .into(),
            fix: Some(format!(
                "fltmc attach {} <volume> for each volume that matters, then confirm events are \
                 arriving before relying on the channel",
                s.driver_service.as_deref().unwrap_or(DEFAULT_DRIVER)
            )),
        });
    }

    match s.driver_loaded {
        Some(false) => f.push(Finding {
            severity: Severity::Critical,
            subject: "sysmon".into(),
            what: format!(
                "the {} service is installed but its driver ({}) is NOT loaded",
                s.service.as_deref().unwrap_or("Sysmon"),
                s.driver_service.as_deref().unwrap_or(DEFAULT_DRIVER)
            ),
            why: "Sysmon is a service and a minifilter driver, and the driver is the half that \
                  sees anything. `fltmc unload SysmonDrv` detaches it in one command, leaves \
                  the service running and every registry key in place, and leaves `sc query` \
                  reporting RUNNING — so everything an administrator would check says Sysmon is \
                  working while it records nothing. Treat the Sysmon channel as having a hole \
                  from whenever this happened, and look for Sysmon event 4 (service state \
                  changed) to date it"
                .into(),
            fix: Some(format!(
                "fltmc load {}, then confirm events are arriving before relying on the channel",
                s.driver_service.as_deref().unwrap_or(DEFAULT_DRIVER)
            )),
        }),
        None => f.push(Finding {
            severity: Severity::Warn,
            subject: "sysmon".into(),
            what: "Sysmon is installed, but whether its driver is loaded could not be determined"
                .into(),
            why: "the loaded-driver list could not be enumerated, which usually means this is \
                  not running elevated. A service that is present is not evidence that the \
                  driver behind it is attached, and that is the state worth checking — so this \
                  is UNKNOWN rather than healthy"
                .into(),
            fix: Some("re-run elevated".into()),
        }),
        Some(true) => {}
    }

    match s.service_state {
        Some(SERVICE_RUNNING) | None => {}
        Some(state) => f.push(Finding {
            severity: Severity::Critical,
            subject: "sysmon".into(),
            what: format!(
                "the {} service is installed but NOT running (it is {})",
                s.service.as_deref().unwrap_or("Sysmon"),
                service_state_name(state)
            ),
            why: "the driver sees events and the service is what writes them to the channel, so \
                  a stopped service records nothing while the driver list, its volume \
                  attachments and every registry key look healthy. Treat the Sysmon channel as \
                  having a hole from when it stopped: System event 7036 dates it, and Sysmon \
                  event 4 is its own record of the state change"
                .into(),
            fix: Some(format!(
                "sc start {}, then confirm events are arriving before relying on the channel",
                s.service.as_deref().unwrap_or("Sysmon64")
            )),
        }),
    }

    if s.service_start == Some(4) {
        f.push(Finding {
            severity: Severity::Critical,
            subject: "sysmon".into(),
            what: "the Sysmon service is set to Disabled".into(),
            why: "it will not start at the next boot. If the driver is loaded now, this host is \
                  recording until it restarts and then silently stops — which is a gap that \
                  begins at a reboot nobody will connect to it"
                .into(),
            fix: Some(format!(
                "sc config {} start= auto",
                s.service.as_deref().unwrap_or("Sysmon64")
            )),
        });
    }

    match s.rules_bytes {

        None if s.params_unreadable => f.push(Finding {
            severity: Severity::Warn,
            subject: "sysmon".into(),
            what: "whether Sysmon has a compiled rule set was not established".into(),
            why: "the Parameters key of Sysmon's driver service would not open, or no driver \
                  service was found to read it under — see the gaps — and that is where the \
                  compiled rule blob lives. This is not a report that Sysmon is unconfigured — it \
                  is a report that nobody could look. Re-run elevated, or check the key's ACL: a \
                  Parameters key the local administrator cannot read is itself worth explaining"
                .into(),
            fix: None,
        }),
        None => f.push(Finding {
            severity: Severity::Warn,
            subject: "sysmon".into(),
            what: "Sysmon is installed with no compiled rule set".into(),
            why: "with no configuration Sysmon runs its default, which records process creation \
                  and little else — no network connections, no image loads, no process access. \
                  That is not nothing, and it is not what anybody who deployed Sysmon \
                  deliberately was expecting to have"
                .into(),
            fix: None,
        }),
        Some(n) if n < MIN_REAL_RULESET => f.push(Finding {
            severity: Severity::Warn,
            subject: "sysmon".into(),
            what: format!("the compiled Sysmon rule set is {n} bytes"),
            why: "published Sysmon configurations compile to tens of kilobytes. A blob this \
                  small is either a stub nobody finished or a configuration that was replaced \
                  with one that excludes almost everything — the size cannot tell those apart. \
                  Sysmon event 16 records a configuration change and is the way to date one"
                .into(),
            fix: None,
        }),
        Some(_) => {}
    }

    if s.renamed_driver() {
        f.push(Finding {
            severity: Severity::Note,
            subject: "sysmon".into(),
            what: format!(
                "the driver is installed as `{}` rather than `{DEFAULT_DRIVER}`",
                s.driver_service.as_deref().unwrap_or("")
            ),
            why: "not a fault: `sysmon -d <name>` is a deliberate measure against malware that \
                  looks for the default name. Recorded because it changes what to look for — a \
                  check for `SysmonDrv` on this host would report it missing"
                .into(),
            fix: None,
        });
    }

    f
}

pub const SERVICE_RUNNING: u32 = 4;

pub fn service_state_name(state: u32) -> String {
    match state {
        1 => "STOPPED".into(),
        2 => "START_PENDING".into(),
        3 => "STOP_PENDING".into(),
        4 => "RUNNING".into(),
        5 => "CONTINUE_PENDING".into(),
        6 => "PAUSE_PENDING".into(),
        7 => "PAUSED".into(),
        other => format!("in state {other}"),
    }
}

#[derive(Debug, Clone, Default)]
pub struct Sweep {

    pub state: State,

    pub gaps: Vec<String>,

    pub findings: Vec<Finding>,
}

impl Sweep {

    pub const fn complete(&self) -> bool {
        self.gaps.is_empty() && (!self.state.installed() || self.state.driver_loaded.is_some())
    }

    pub fn coverage(&self) -> String {
        if !self.state.installed() {
            if self.state.service_unreadable {
                return format!(
                    "whether Sysmon is installed was NOT established: {}",
                    self.gaps.join("; ")
                );
            }
            if !self.state.traces.is_empty() {
                return "Sysmon is NOT installed now, but traces show it was".into();
            }
            if !self.gaps.is_empty() {
                return format!(
                    "Sysmon is not installed; whether it ever was could not be fully checked: {}",
                    self.gaps.join("; ")
                );
            }
            return "Sysmon is not installed, and nothing an uninstall leaves behind is here — \
                    so there is nothing to be blind about"
                .into();
        }
        let mut s = match self.state.driver_loaded {
            Some(true) => "Sysmon is installed and its driver is loaded".to_string(),
            Some(false) => "Sysmon is installed and its driver is NOT loaded".to_string(),
            None => "Sysmon is installed; whether its driver is loaded is UNKNOWN".to_string(),
        };
        if !self.gaps.is_empty() {
            s.push_str(&format!(" — not everything could be read: {}", self.gaps.join("; ")));
        }
        s
    }
}

#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
const SERVICES: &str = r"SYSTEM\CurrentControlSet\Services";

#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
fn parameters_key(driver: &str) -> String {
    format!(r"{SERVICES}\{driver}\Parameters")
}

#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
const REG_BINARY: u32 = 3;

#[cfg(target_os = "windows")]
const _: () = assert!(REG_BINARY == windows_sys::Win32::System::Registry::REG_BINARY);

#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
const fn rule_blob_len(rc: u32, kind: u32, len: u32) -> Result<Option<usize>, u32> {
    match rc {
        0 if kind == REG_BINARY => Ok(Some(len as usize)),
        0 => Ok(None),
        crate::reg::ABSENT => Ok(None),
        _ => Err(rc),
    }
}

#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
const FILTER_NOT_FOUND: i32 = 0x801F_0013_u32 as i32;

#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
const NO_MORE_INSTANCES: i32 = 0x8007_0103_u32 as i32;

#[cfg(target_os = "windows")]
const _: () = assert!(
    NO_MORE_INSTANCES
        == (0x8007_0000 | windows_sys::Win32::Foundation::ERROR_NO_MORE_ITEMS) as i32
);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
enum FirstInstance {

    Found,

    NoneAttached,

    Unknown,
}

#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
const fn first_instance(hr: i32) -> FirstInstance {
    match hr {
        0 => FirstInstance::Found,
        FILTER_NOT_FOUND | NO_MORE_INSTANCES => FirstInstance::NoneAttached,
        _ => FirstInstance::Unknown,
    }
}

#[cfg(target_os = "windows")]
fn rules_len(params: &str) -> Result<Option<usize>, u32> {
    use windows_sys::Win32::Foundation::ERROR_SUCCESS;
    use windows_sys::Win32::System::Registry::{
        RegCloseKey, RegOpenKeyExW, RegQueryValueExW, HKEY, HKEY_LOCAL_MACHINE, KEY_QUERY_VALUE,
    };

    let path: Vec<u16> = params.encode_utf16().chain(core::iter::once(0)).collect();
    let name: Vec<u16> = "Rules".encode_utf16().chain(core::iter::once(0)).collect();
    let mut h: HKEY = core::ptr::null_mut();

    let rc = unsafe {
        RegOpenKeyExW(HKEY_LOCAL_MACHINE, path.as_ptr(), 0, KEY_QUERY_VALUE, core::ptr::addr_of_mut!(h))
    };
    if rc != ERROR_SUCCESS {
        return rule_blob_len(rc, 0, 0);
    }
    let mut kind: u32 = 0;
    let mut len: u32 = 0;

    let rc = unsafe {
        RegQueryValueExW(
            h,
            name.as_ptr(),
            core::ptr::null(),
            core::ptr::addr_of_mut!(kind),
            core::ptr::null_mut(),
            core::ptr::addr_of_mut!(len),
        )
    };

    unsafe { RegCloseKey(h) };
    rule_blob_len(rc, kind, len)
}

#[cfg(target_os = "windows")]
fn attached_volume_count(filter: &str) -> Option<usize> {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::Storage::InstallableFileSystems::{
        FilterInstanceFindClose, FilterInstanceFindFirst, FilterInstanceFindNext,
        InstanceBasicInformation,
    };

    let name: Vec<u16> = filter.encode_utf16().chain(core::iter::once(0)).collect();
    let mut buf = vec![0_u8; 1024];
    let mut returned: u32 = 0;
    let mut find = std::ptr::null_mut();

    let hr = unsafe {
        FilterInstanceFindFirst(
            name.as_ptr(),
            InstanceBasicInformation,
            buf.as_mut_ptr().cast(),
            u32::try_from(buf.len()).unwrap_or(0),
            std::ptr::addr_of_mut!(returned),
            std::ptr::addr_of_mut!(find),
        )
    };
    match first_instance(hr) {
        FirstInstance::Found => {}

        FirstInstance::NoneAttached => return Some(0),
        FirstInstance::Unknown => return None,
    }

    let mut n = 1usize;
    loop {

        let hr = unsafe {
            FilterInstanceFindNext(
                find,
                InstanceBasicInformation,
                buf.as_mut_ptr().cast(),
                u32::try_from(buf.len()).unwrap_or(0),
                std::ptr::addr_of_mut!(returned),
            )
        };
        if hr != 0 {

            break;
        }
        n += 1;
        if n > 4096 {
            break;
        }
    }

    unsafe {
        FilterInstanceFindClose(find);
        let _ = CloseHandle;
    }
    Some(n)
}

#[cfg(target_os = "windows")]
fn driver_is_loaded(image: &str) -> Option<bool> {
    use windows_sys::Win32::System::ProcessStatus::{
        EnumDeviceDrivers, GetDeviceDriverBaseNameW,
    };

    let mut bases = vec![std::ptr::null_mut::<std::ffi::c_void>(); 1024];
    let mut needed: u32 = 0;

    let ok = unsafe {
        EnumDeviceDrivers(
            bases.as_mut_ptr(),
            u32::try_from(bases.len() * std::mem::size_of::<*mut std::ffi::c_void>()).unwrap_or(0),
            std::ptr::addr_of_mut!(needed),
        )
    };
    if ok == 0 {
        return None;
    }
    let count = (needed as usize / std::mem::size_of::<*mut std::ffi::c_void>()).min(bases.len());

    let want = image.to_ascii_lowercase();
    let mut name = [0_u16; 260];
    for base in bases.iter().take(count) {

        let n = unsafe {
            GetDeviceDriverBaseNameW(*base, name.as_mut_ptr(), u32::try_from(name.len()).unwrap_or(0))
        };
        if n == 0 {
            continue;
        }
        let got = String::from_utf16_lossy(&name[..n as usize]).to_ascii_lowercase();
        if got == want {
            return Some(true);
        }
    }
    Some(false)
}

#[cfg(target_os = "windows")]
fn find_driver_service(gaps: &mut Vec<String>) -> Option<String> {
    use windows_sys::Win32::Foundation::ERROR_FILE_NOT_FOUND;

    let default_key = format!(r"{SERVICES}\{DEFAULT_DRIVER}");
    let default_has_values = match crate::reg::hklm_values_read(&default_key) {
        Ok(v) => !v.is_empty(),
        Err(rc) if rc == ERROR_FILE_NOT_FOUND => false,
        Err(rc) => {
            gaps.push(format!(
                "{default_key} could not be read (error {rc}); the driver service was looked \
                 for by image name instead"
            ));
            false
        }
    };
    if default_has_values {
        return Some(DEFAULT_DRIVER.to_string());
    }
    crate::reg::subkeys(crate::reg::Hive::Machine, SERVICES).into_iter().find(|k| {
        let key = format!(r"{SERVICES}\{k}");
        let image = crate::reg::hklm_values(&key)
            .into_iter()
            .find(|(n, _)| n.eq_ignore_ascii_case("ImagePath"))
            .map(|(_, v)| v);
        if is_sysmon_driver(image.as_deref(), &[]) {
            return true;
        }

        let instances = format!(r"{key}\Instances");
        let altitudes: Vec<String> = crate::reg::subkeys(crate::reg::Hive::Machine, &instances)
            .iter()
            .flat_map(|i| crate::reg::hklm_values(&format!(r"{instances}\{i}")))
            .filter(|(n, _)| n.eq_ignore_ascii_case("Altitude"))
            .map(|(_, v)| v)
            .collect();
        is_sysmon_driver(None, &altitudes)
    })
}

#[cfg(target_os = "windows")]
pub(crate) fn service_state(name: &str) -> Option<u32> {
    use windows_sys::Win32::System::Services::{
        CloseServiceHandle, OpenSCManagerW, OpenServiceW, QueryServiceStatus, SC_MANAGER_CONNECT,
        SERVICE_QUERY_STATUS, SERVICE_STATUS,
    };
    let wide: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();

    let scm = unsafe { OpenSCManagerW(core::ptr::null(), core::ptr::null(), SC_MANAGER_CONNECT) };
    if scm.is_null() {
        return None;
    }

    let svc = unsafe { OpenServiceW(scm, wide.as_ptr(), SERVICE_QUERY_STATUS) };
    if svc.is_null() {

        unsafe { CloseServiceHandle(scm) };
        return None;
    }

    let mut status: SERVICE_STATUS = unsafe { core::mem::zeroed() };

    let ok = unsafe { QueryServiceStatus(svc, core::ptr::addr_of_mut!(status)) };

    unsafe {
        CloseServiceHandle(svc);
        CloseServiceHandle(scm);
    }
    (ok != 0).then_some(status.dwCurrentState)
}

pub const CHANNEL_FILE: &str = r"System32\winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx";

pub const INSTALLED_IMAGES: &[&str] = &["Sysmon64.exe", "Sysmon.exe"];

#[cfg(target_os = "windows")]
fn traces_of_an_uninstall(w: &mut Sweep) -> Vec<String> {
    let mut traces = Vec::new();

    let driver = find_driver_service(&mut w.gaps);
    if let Some(d) = &driver {
        traces.push(format!(r"its driver service HKLM\{SERVICES}\{d} is still registered"));
    }
    let image = driver.as_ref().map_or_else(|| DEFAULT_DRIVER_IMAGE.to_string(), |d| format!("{d}.sys"));
    match driver_is_loaded(&image) {
        Some(true) => {
            w.state.driver_loaded = Some(true);
            traces.push(format!("{image} is loaded in the kernel right now"));
        }
        Some(false) => w.state.driver_loaded = Some(false),
        None => w.gaps.push(
            "the loaded-driver list could not be enumerated, so a Sysmon driver left running \
             after its service was removed would not have been seen"
                .into(),
        ),
    }

    let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
    let mut look = |rel: &str, what: &str| {
        let path = format!(r"{root}\{rel}");
        match std::fs::metadata(&path) {
            Ok(md) => traces.push(format!("{what} {path} is still there ({} bytes)", md.len())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => w.gaps.push(format!("{path} could not be examined: {e}")),
        }
    };
    look(CHANNEL_FILE, "its event log");
    for exe in INSTALLED_IMAGES {
        look(exe, "its binary");
    }
    traces
}

#[cfg(target_os = "windows")]
pub fn sweep() -> Sweep {
    use windows_sys::Win32::Foundation::ERROR_FILE_NOT_FOUND;

    let mut w = Sweep::default();

    for name in SERVICE_NAMES {
        let key = format!(r"{SERVICES}\{name}");
        let values = match crate::reg::hklm_values_read(&key) {
            Ok(v) => v,
            Err(rc) if rc == ERROR_FILE_NOT_FOUND => continue,
            Err(rc) => {
                w.state.service_unreadable = true;
                w.gaps.push(format!(
                    "{key} could not be read (error {rc}), so whether Sysmon is installed \
                     under that name was not established"
                ));
                continue;
            }
        };
        if values.is_empty() {
            continue;
        }
        w.state.service = Some((*name).to_string());
        w.state.service_start = crate::reg::hklm_dword(&key, "Start");
        break;
    }

    if !w.state.installed() {

        if !w.state.service_unreadable {
            w.state.traces = traces_of_an_uninstall(&mut w);
        }
        w.findings = judge(&w.state);
        return w;
    }

    let service = w.state.service.clone().unwrap_or_default();
    w.state.service_state = service_state(&service);
    if w.state.service_state.is_none() {
        w.gaps.push(format!(
            "the service manager could not be asked whether {service} is running"
        ));
    }

    let driver = find_driver_service(&mut w.gaps);
    w.state.driver_service = driver.clone();

    match &driver {
        Some(d) => {
            let params = parameters_key(d);
            match rules_len(&params) {
                Ok(n) => w.state.rules_bytes = n,
                Err(rc) => {
                    w.state.params_unreadable = true;
                    w.gaps.push(format!(
                        "{params} could not be read (error {rc}), so the compiled rule set was \
                         not established"
                    ));
                }
            }
            let values = crate::reg::hklm_values_read(&params).unwrap_or_default();
            let value_of = |name: &str| {
                values.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.clone())
            };
            w.state.hashing = value_of("HashingAlgorithm");
            w.state.archive_directory = value_of("ArchiveDirectory");
        }

        None => {
            w.state.params_unreadable = true;
            w.gaps.push(
                "no Sysmon driver service was identified — deleted, or renamed past the image \
                 and altitude checks — so its compiled rule set was not looked for"
                    .into(),
            );
        }
    }

    let image = driver
        .as_ref()
        .map_or_else(|| DEFAULT_DRIVER_IMAGE.to_string(), |d| format!("{d}.sys"));
    w.state.driver_loaded = match driver_is_loaded(&image) {
        Some(true) => Some(true),
        Some(false) => driver_is_loaded(DEFAULT_DRIVER_IMAGE),
        None => {
            w.gaps.push("the loaded-driver list could not be enumerated".into());
            None
        }
    };

    let filter = driver.clone().unwrap_or_else(|| DEFAULT_DRIVER.to_string());
    w.state.attached_volumes = match attached_volume_count(&filter) {
        Some(n) => Some(n),
        None => {
            w.gaps.push(format!(
                "the filter manager could not be asked how many volumes `{filter}` is attached \
                 to, so a detached minifilter would be indistinguishable from a working one"
            ));
            None
        }
    };

    w.findings = judge(&w.state);
    w
}

#[cfg(not(target_os = "windows"))]
pub fn sweep() -> Sweep {
    Sweep {
        gaps: vec!["this build does not run on Windows, so nothing was read".into()],
        ..Default::default()
    }
}
