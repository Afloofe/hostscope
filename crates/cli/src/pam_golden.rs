#![allow(dead_code)]

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DistroKey {

    pub id: String,

    pub version_id: String,
}

pub(crate) fn parse_os_release(text: &str) -> Option<DistroKey> {
    let mut id = None;
    let mut version_id = None;
    for line in text.lines() {
        let Some((k, v)) = line.trim().split_once('=') else { continue };
        let v = v.trim().trim_matches('"').to_string();
        match k.trim() {
            "ID" => id = Some(v),
            "VERSION_ID" => version_id = Some(v),
            _ => {}
        }
    }
    Some(DistroKey { id: id?, version_id: version_id? })
}

const OS_RELEASE: &str = "/etc/os-release";

pub(crate) fn detect() -> Result<DistroKey, String> {
    detect_from(std::path::Path::new(OS_RELEASE))
}

fn detect_from(path: &std::path::Path) -> Result<DistroKey, String> {
    let text = hemostat_sensor_linux::saferead::read_text(path)
        .map_err(|e| format!("distro unknown: {} could not be read ({e})", path.display()))?;
    parse_os_release(&text)
        .ok_or_else(|| format!("distro unknown: {} does not name both ID and VERSION_ID", path.display()))
}

pub(crate) fn host_arch() -> &'static str {
    std::env::consts::ARCH
}

pub(crate) struct KnownModule {

    pub path: &'static str,

    pub pkg: &'static str,

    pub pkg_version: &'static str,

    pub distro_id: &'static str,

    pub version_id: &'static str,

    pub arch: &'static str,

    pub sha256: &'static str,

    pub bytes: &'static [u8],
}

pub(crate) const KNOWN: &[KnownModule] = &[

    KnownModule {
        path: "/usr/lib/x86_64-linux-gnu/security/pam_unix.so",
        pkg: "libpam-modules",
        pkg_version: "1.5.3-5ubuntu5.7",
        distro_id: "ubuntu",
        version_id: "24.04",
        arch: "x86_64",
        sha256: "48c7a809be645451122cbf1957532dc4d3907c52eb59f01269c5380ee8cc8806",
        bytes: include_bytes!("pam_known/ubuntu-24.04/x86_64/pam_unix.so"),
    },

];

pub(crate) fn known_good_for<'a>(key: &DistroKey, arch: &str, path: &str) -> Option<&'a KnownModule> {
    KNOWN
        .iter()
        .find(|m| m.distro_id == key.id && m.version_id == key.version_id && m.arch == arch && m.path == path)
}
