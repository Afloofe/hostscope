#[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "windows"))]

#[cfg_attr(target_os = "freebsd", allow(dead_code))]
pub(crate) struct Identity {
    pub(crate) engagement: [u8; 16],
    pub(crate) host: [u8; 32],
    pub(crate) agent: [u8; 16],
    pub(crate) instance: [u8; 16],
    pub(crate) run_id: u32,
    pub(crate) boot: [u8; 16],

    pub(crate) host_id_source: &'static str,
}

#[cfg(target_os = "linux")]
pub(crate) fn gather_identity() -> std::io::Result<Identity> {
    use sha2::{Digest, Sha256};

    let (machine, host_id_source) = [
        ("/etc/machine-id", hemostat_sensor_linux::saferead::read_scan_target(std::path::Path::new("/etc/machine-id"))),
        (
            "/var/lib/dbus/machine-id",
            hemostat_sensor_linux::saferead::read_scan_target(std::path::Path::new("/var/lib/dbus/machine-id")),
        ),
        (
            "/sys/class/dmi/id/product_uuid",
            std::fs::read_to_string("/sys/class/dmi/id/product_uuid").ok(),
        ),
        (
            "/proc/sys/kernel/hostname",
            std::fs::read_to_string("/proc/sys/kernel/hostname").ok(),
        ),
    ]
    .into_iter()
    .find_map(|(name, v)| {
        let v = v?;
        (!v.trim().is_empty()).then(|| (v.trim().to_string(), name))
    })
    .unwrap_or_else(|| (String::new(), "none"));

    let host: [u8; 32] = if host_id_source == "none" {
        let mut b = [0u8; 32];
        fill_random(&mut b)?;
        Sha256::digest(b).into()
    } else {
        Sha256::digest(machine.as_bytes()).into()
    };

    let boot = match read_boot_id() {
        Some(b) => b,
        None => rand16()?,
    };

    let engagement = match std::env::var("HEMOSTAT_ENGAGEMENT_ID")
        .ok()
        .and_then(|h| parse_hex16(&h))
    {
        Some(e) => e,
        None => rand16()?,
    };

    let agent = rand16()?;
    let instance = rand16()?;
    let mut r4 = [0u8; 4];
    fill_random(&mut r4)?;
    let run_id = u32::from_le_bytes(r4);

    Ok(Identity {
        engagement,
        host,
        agent,
        instance,
        run_id,
        boot,
        host_id_source,
    })
}

#[cfg(target_os = "freebsd")]
pub(crate) fn gather_identity_with(
    runner: &mut dyn hemostat_sensor_freebsd::tools::Runner,
) -> std::io::Result<(Identity, hemostat_sensor_freebsd::identity::HostIdentity)> {
    use hemostat_sensor_freebsd::identity;
    use sha2::{Digest, Sha256};

    let found = identity::read(runner, std::path::Path::new("/"));
    let host: [u8; 32] = match found.host_id {
        Some(h) => h,
        None => {
            let mut b = [0u8; 32];
            fill_random(&mut b)?;
            Sha256::digest(b).into()
        }
    };
    let engagement = match std::env::var("HEMOSTAT_ENGAGEMENT_ID").ok().and_then(|h| parse_hex16(&h)) {
        Some(e) => e,
        None => rand16()?,
    };
    let mut r4 = [0u8; 4];
    fill_random(&mut r4)?;
    let id = Identity {
        engagement,
        host,
        agent: rand16()?,
        instance: rand16()?,
        run_id: u32::from_le_bytes(r4),
        boot: rand16()?,
        host_id_source: found.source.label(),
    };
    Ok((id, found))
}

#[cfg(target_os = "windows")]
pub(crate) fn gather_identity() -> std::io::Result<Identity> {
    use sha2::{Digest, Sha256};
    let guid = hemostat_sensor_win::reg::hklm_values_read(r"SOFTWARE\Microsoft\Cryptography")
        .ok()
        .and_then(|v| v.into_iter().find(|(n, _)| n.eq_ignore_ascii_case("MachineGuid")).map(|(_, g)| g))
        .map(|g| g.trim().to_ascii_lowercase())
        .filter(|g| !g.is_empty());
    let (host, host_id_source): ([u8; 32], &'static str) = match &guid {
        Some(g) => (Sha256::digest(g.as_bytes()).into(), "MachineGuid"),
        None => (Sha256::digest(rand32()?).into(), "none"),
    };
    let engagement = match std::env::var("HEMOSTAT_ENGAGEMENT_ID").ok().and_then(|h| parse_hex16(&h)) {
        Some(e) => e,
        None => rand16()?,
    };
    let mut r4 = [0u8; 4];
    fill_random(&mut r4)?;
    Ok(Identity {
        engagement,
        host,
        agent: rand16()?,
        instance: rand16()?,
        run_id: u32::from_le_bytes(r4),
        boot: rand16()?,
        host_id_source,
    })
}

#[cfg(target_os = "windows")]
pub(crate) fn fill_random(buf: &mut [u8]) -> std::io::Result<()> {
    hemostat_sensor_win::rng::fill(buf).map_err(std::io::Error::other)
}

#[cfg(target_os = "linux")]
pub(crate) fn read_boot_id() -> Option<[u8; 16]> {
    let s = std::fs::read_to_string("/proc/sys/kernel/random/boot_id").ok()?;
    parse_hex16(&s)
}

#[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "windows"))]
pub(crate) fn parse_hex16(s: &str) -> Option<[u8; 16]> {
    let hex: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if hex.len() < 32 {
        return None;
    }
    let mut out = [0u8; 16];
    for (i, b) in out.iter_mut().enumerate() {
        let byte = hex.get(i * 2..i * 2 + 2)?;
        *b = u8::from_str_radix(byte, 16).ok()?;
    }
    Some(out)
}

pub(crate) fn parse_hex32(s: &str) -> Option<[u8; 32]> {
    let hex: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if hex.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(hex.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

pub(crate) fn pinned_key(var: &str) -> Result<Option<[u8; 32]>, String> {
    match std::env::var(var) {
        Ok(v) => parse_pin(var, Some(&v)),
        Err(std::env::VarError::NotPresent) => Ok(None),

        Err(std::env::VarError::NotUnicode(_)) => parse_pin(var, Some("\u{FFFD}")),
    }
}

pub(crate) fn parse_pin(var: &str, raw: Option<&str>) -> Result<Option<[u8; 32]>, String> {
    let Some(v) = raw.filter(|v| !v.trim().is_empty()) else {
        return Ok(None);
    };
    match parse_hex32(v) {
        Some(k) => Ok(Some(k)),
        None => Err(format!(
            "${var} is set but is not 64 hex characters (got {} usable hex digit(s)). A pin that \
             does not parse checks nothing, so it is refused rather than dropped: fix the value \
             — the bare 64 hex, with no label or 0x — or unset it",
            v.chars().filter(char::is_ascii_hexdigit).count()
        )),
    }
}

pub(crate) fn recovery_key() -> Option<[u8; 32]> {
    if let Ok(path) = std::env::var("HEMOSTAT_RECOVERY_KEY_FILE") {
        if !path.trim().is_empty() {
            return std::fs::read_to_string(&path)
                .map_err(|e| {
                    eprintln!("hemostat read: cannot read $HEMOSTAT_RECOVERY_KEY_FILE ({path}): {e}");
                })
                .ok()
                .as_deref()
                .map(str::trim)
                .and_then(parse_hex32);
        }
    }
    std::env::var("HEMOSTAT_RECOVERY_KEY").ok().as_deref().map(str::trim).and_then(parse_hex32)
}

#[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "windows"))]
pub(crate) fn rand16() -> std::io::Result<[u8; 16]> {
    let mut b = [0u8; 16];
    fill_random(&mut b)?;
    Ok(b)
}

#[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "windows"))]
pub(crate) fn rand32() -> std::io::Result<[u8; 32]> {
    let mut b = [0u8; 32];
    fill_random(&mut b)?;
    Ok(b)
}

#[cfg(target_os = "linux")]
pub(crate) fn fill_random(buf: &mut [u8]) -> std::io::Result<()> {
    hemostat_sensor_linux::rng::fill(buf)
}

#[cfg(target_os = "freebsd")]
pub(crate) fn fill_random(buf: &mut [u8]) -> std::io::Result<()> {
    getrandom::getrandom(buf).map_err(|e| std::io::Error::other(format!("getrandom(2): {e}")))
}
