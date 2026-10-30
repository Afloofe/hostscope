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

impl KnownModule {

    fn is_for(&self, key: &DistroKey, arch: &str) -> bool {
        self.distro_id == key.id && self.version_id == key.version_id && self.arch == arch
    }
}

macro_rules! known {
    (
        distro_id: $distro_id:literal,
        version_id: $version_id:literal,
        arch: $arch:literal,
        dir: $dir:literal,
        file: $file:literal,
        pkg: $pkg:literal,
        pkg_version: $pkg_version:literal,
        sha256: $sha256:literal $(,)?
    ) => {
        KnownModule {
            path: concat!($dir, "/", $file),
            pkg: $pkg,
            pkg_version: $pkg_version,
            distro_id: $distro_id,
            version_id: $version_id,
            arch: $arch,
            sha256: $sha256,
            bytes: include_bytes!(concat!(
                "pam_known/", $distro_id, "-", $version_id, "/", $arch, "/", $pkg_version, "/", $file
            )),
        }
    };
}

pub(crate) const KNOWN: &[KnownModule] = &[

    known! {
        distro_id: "debian",
        version_id: "12",
        arch: "x86_64",
        dir: "/usr/lib/x86_64-linux-gnu/security",
        file: "pam_unix.so",
        pkg: "libpam-modules",
        pkg_version: "1.5.2-6",
        sha256: "86bd97b9a61a38bf9fa026bf8e008c81b2daf4cc0aea74ce909f22a644f07375",
    },
    known! {
        distro_id: "debian",
        version_id: "12",
        arch: "x86_64",
        dir: "/usr/lib/x86_64-linux-gnu/security",
        file: "pam_unix.so",
        pkg: "libpam-modules",
        pkg_version: "1.5.2-6+deb12u1",
        sha256: "0b6f6a5e217dc7e22782b9efdb9d89b9f6b2393f357f54465a938b99c5577cc6",
    },
    known! {
        distro_id: "debian",
        version_id: "12",
        arch: "x86_64",
        dir: "/usr/lib/x86_64-linux-gnu/security",
        file: "pam_unix.so",
        pkg: "libpam-modules",
        pkg_version: "1.5.2-6+deb12u2",
        sha256: "f4ef9b05d76c72ff807e82929e745ae34e769f0caab1e357163ebc63eb1621b1",
    },

    known! {
        distro_id: "ubuntu",
        version_id: "22.04",
        arch: "x86_64",
        dir: "/usr/lib/x86_64-linux-gnu/security",
        file: "pam_unix.so",
        pkg: "libpam-modules",
        pkg_version: "1.4.0-11ubuntu2",
        sha256: "cc1cfdf7a48504f9204fa024eddbf0cb4263756cdc0a8fe364696a6cb5989369",
    },
    known! {
        distro_id: "ubuntu",
        version_id: "22.04",
        arch: "x86_64",
        dir: "/usr/lib/x86_64-linux-gnu/security",
        file: "pam_unix.so",
        pkg: "libpam-modules",
        pkg_version: "1.4.0-11ubuntu2.1",
        sha256: "535e65ba78d444f3e7a2b67f22ce42ff4169ecaa1df88a95453e4cb07931e28a",
    },
    known! {
        distro_id: "ubuntu",
        version_id: "22.04",
        arch: "x86_64",
        dir: "/usr/lib/x86_64-linux-gnu/security",
        file: "pam_unix.so",
        pkg: "libpam-modules",
        pkg_version: "1.4.0-11ubuntu2.3",
        sha256: "71410f9bdb48ff7571d478ca6c623ec2b611a29b97c38d712d9f5c2777ffd8a0",
    },
    known! {
        distro_id: "ubuntu",
        version_id: "22.04",
        arch: "x86_64",
        dir: "/usr/lib/x86_64-linux-gnu/security",
        file: "pam_unix.so",
        pkg: "libpam-modules",
        pkg_version: "1.4.0-11ubuntu2.4",
        sha256: "ccb2e029e4ba9cad72c8f746c4c28062c2e1521cfb91c6b7c431446fb5c8eef7",
    },
    known! {
        distro_id: "ubuntu",
        version_id: "22.04",
        arch: "x86_64",
        dir: "/usr/lib/x86_64-linux-gnu/security",
        file: "pam_unix.so",
        pkg: "libpam-modules",
        pkg_version: "1.4.0-11ubuntu2.5",
        sha256: "019b063ad60a21e4ae52930c85a7eb1aca4ad5121b2af0cc931d7cd4c49e7d1b",
    },
    known! {
        distro_id: "ubuntu",
        version_id: "22.04",
        arch: "x86_64",
        dir: "/usr/lib/x86_64-linux-gnu/security",
        file: "pam_unix.so",
        pkg: "libpam-modules",
        pkg_version: "1.4.0-11ubuntu2.6",
        sha256: "81b3595c4973a59ecab70487743a07bb78536f90d774769a3dcce0603663cbfc",
    },
    known! {
        distro_id: "ubuntu",
        version_id: "22.04",
        arch: "x86_64",
        dir: "/usr/lib/x86_64-linux-gnu/security",
        file: "pam_unix.so",
        pkg: "libpam-modules",
        pkg_version: "1.4.0-11ubuntu2.7",
        sha256: "562448fdd7db60153c01681e824775fadeab3af46bff4c0dd08f4a717d00b07a",
    },
    known! {
        distro_id: "ubuntu",
        version_id: "22.04",
        arch: "x86_64",
        dir: "/usr/lib/x86_64-linux-gnu/security",
        file: "pam_unix.so",
        pkg: "libpam-modules",
        pkg_version: "1.4.0-11ubuntu2.8",
        sha256: "8703ea12795558a76774a97551975403375bf4b10f90d85bd4f405197954c815",
    },

    known! {
        distro_id: "ubuntu",
        version_id: "24.04",
        arch: "x86_64",
        dir: "/usr/lib/x86_64-linux-gnu/security",
        file: "pam_unix.so",
        pkg: "libpam-modules",
        pkg_version: "1.5.3-5ubuntu5",
        sha256: "ef00d5e0eb9f0bd7b576d88b1226bbabf28f85d82eda7e95f9df336db8ba1565",
    },
    known! {
        distro_id: "ubuntu",
        version_id: "24.04",
        arch: "x86_64",
        dir: "/usr/lib/x86_64-linux-gnu/security",
        file: "pam_unix.so",
        pkg: "libpam-modules",
        pkg_version: "1.5.3-5ubuntu5.1",
        sha256: "73d81874a897d9db3d86af8c300d7a8ff8be0496aca08dd0bd787ceb82d6d685",
    },
    known! {
        distro_id: "ubuntu",
        version_id: "24.04",
        arch: "x86_64",
        dir: "/usr/lib/x86_64-linux-gnu/security",
        file: "pam_unix.so",
        pkg: "libpam-modules",
        pkg_version: "1.5.3-5ubuntu5.2",
        sha256: "d2a1ac4ace365d29cb52686b306cdcaa84515da833fedca3a72dbf2ddd948a87",
    },
    known! {
        distro_id: "ubuntu",
        version_id: "24.04",
        arch: "x86_64",
        dir: "/usr/lib/x86_64-linux-gnu/security",
        file: "pam_unix.so",
        pkg: "libpam-modules",
        pkg_version: "1.5.3-5ubuntu5.4",
        sha256: "9857eb006e8d0431994de4539dae48cedb99c3e8fa72fd3cc78314d31c6942f6",
    },
    known! {
        distro_id: "ubuntu",
        version_id: "24.04",
        arch: "x86_64",
        dir: "/usr/lib/x86_64-linux-gnu/security",
        file: "pam_unix.so",
        pkg: "libpam-modules",
        pkg_version: "1.5.3-5ubuntu5.5",
        sha256: "f2e5b0631cf15ffc95b483b826ff548aff5db9b4bbb9e1deb0e82633aa8fb377",
    },
    known! {
        distro_id: "ubuntu",
        version_id: "24.04",
        arch: "x86_64",
        dir: "/usr/lib/x86_64-linux-gnu/security",
        file: "pam_unix.so",
        pkg: "libpam-modules",
        pkg_version: "1.5.3-5ubuntu5.6",
        sha256: "ab5a696836077700ba0449afaf00ebf43299a43c4112c272302382aed350b8e7",
    },
    known! {
        distro_id: "ubuntu",
        version_id: "24.04",
        arch: "x86_64",
        dir: "/usr/lib/x86_64-linux-gnu/security",
        file: "pam_unix.so",
        pkg: "libpam-modules",
        pkg_version: "1.5.3-5ubuntu5.7",
        sha256: "48c7a809be645451122cbf1957532dc4d3907c52eb59f01269c5380ee8cc8806",
    },

    known! {
        distro_id: "rocky",
        version_id: "9.0",
        arch: "x86_64",
        dir: "/usr/lib64/security",
        file: "pam_unix.so",
        pkg: "pam",
        pkg_version: "1.5.1-9.el9_0.1",
        sha256: "1755386dac4e759c921552169078ad55d1a37bce4bd25c437c4ab207117f59ec",
    },
    known! {
        distro_id: "rocky",
        version_id: "9.1",
        arch: "x86_64",
        dir: "/usr/lib64/security",
        file: "pam_unix.so",
        pkg: "pam",
        pkg_version: "1.5.1-12.el9",
        sha256: "c368bbc39413dbd87a3561b8e1e7231e7da42c3294776f2b118f66e00366587d",
    },
    known! {
        distro_id: "rocky",
        version_id: "9.2",
        arch: "x86_64",
        dir: "/usr/lib64/security",
        file: "pam_unix.so",
        pkg: "pam",
        pkg_version: "1.5.1-14.el9",
        sha256: "ed872f759061900f157b79b959278fc51cf9ef53cd26e9eef75d6d5759c926fe",
    },
    known! {
        distro_id: "rocky",
        version_id: "9.3",
        arch: "x86_64",
        dir: "/usr/lib64/security",
        file: "pam_unix.so",
        pkg: "pam",
        pkg_version: "1.5.1-15.el9",
        sha256: "e7bac2b215e427c6ed93d8abc0c6518ad4d324f064c0d3af2e72389e74fe91f1",
    },
    known! {
        distro_id: "rocky",
        version_id: "9.4",
        arch: "x86_64",
        dir: "/usr/lib64/security",
        file: "pam_unix.so",
        pkg: "pam",
        pkg_version: "1.5.1-19.el9",
        sha256: "5ec6ee098d3321c4af35bd9e1244d288353f47298d34eba932d1ca9ea842795b",
    },
    known! {
        distro_id: "rocky",
        version_id: "9.5",
        arch: "x86_64",
        dir: "/usr/lib64/security",
        file: "pam_unix.so",
        pkg: "pam",
        pkg_version: "1.5.1-20.el9",
        sha256: "10925d151cf81291705796ac8888bfea24852071b1850f4b31877aecdb459a76",
    },
    known! {
        distro_id: "rocky",
        version_id: "9.5",
        arch: "x86_64",
        dir: "/usr/lib64/security",
        file: "pam_unix.so",
        pkg: "pam",
        pkg_version: "1.5.1-22.el9_5",
        sha256: "c80e995d6ac3c7b43ed89af5a996c7af5f34cd464adafec95fc0d913bb57fd13",
    },
    known! {
        distro_id: "rocky",
        version_id: "9.6",
        arch: "x86_64",
        dir: "/usr/lib64/security",
        file: "pam_unix.so",
        pkg: "pam",
        pkg_version: "1.5.1-23.el9",
        sha256: "e46a8a49a7eef6e7b794eb2324c59549d8280f9c0f7b8358ec0fee372e18a082",
    },
    known! {
        distro_id: "rocky",
        version_id: "9.6",
        arch: "x86_64",
        dir: "/usr/lib64/security",
        file: "pam_unix.so",
        pkg: "pam",
        pkg_version: "1.5.1-25.el9_6",
        sha256: "3ca462ae7e0346e2ed4ec2ddcc349266995f54bda5a7c032d264a799a3b1f0d0",
    },
    known! {
        distro_id: "rocky",
        version_id: "9.6",
        arch: "x86_64",
        dir: "/usr/lib64/security",
        file: "pam_unix.so",
        pkg: "pam",
        pkg_version: "1.5.1-26.el9_6",
        sha256: "7be7efb6af3f7b2504d805c6952a268916c89051ec7aca20d931d91833fa57cc",
    },
    known! {
        distro_id: "rocky",
        version_id: "9.7",
        arch: "x86_64",
        dir: "/usr/lib64/security",
        file: "pam_unix.so",
        pkg: "pam",
        pkg_version: "1.5.1-26.el9_6",
        sha256: "7be7efb6af3f7b2504d805c6952a268916c89051ec7aca20d931d91833fa57cc",
    },
    known! {
        distro_id: "rocky",
        version_id: "9.8",
        arch: "x86_64",
        dir: "/usr/lib64/security",
        file: "pam_unix.so",
        pkg: "pam",
        pkg_version: "1.5.1-28.el9",
        sha256: "9dcf1f971a109cc548b1aa58e1aa2085e428af2677331d26019cb7b272ff753d",
    },
    known! {
        distro_id: "rocky",
        version_id: "9.8",
        arch: "x86_64",
        dir: "/usr/lib64/security",
        file: "pam_unix.so",
        pkg: "pam",
        pkg_version: "1.5.1-28.el9_8.1",
        sha256: "5d964522399e6181c14dd765883e7a98410babd4147d272933a76c714738d201",
    },
];

pub(crate) enum Pick {

    Build(&'static KnownModule),

    NoBuild {

        pkg: &'static str,

        installed: Option<String>,

        baked: Vec<&'static str>,
    },

    Ambiguous(String),
}

pub(crate) fn pick(
    table: &'static [KnownModule],
    key: &DistroKey,
    arch: &str,
    path: &str,
    installed_version: impl FnOnce(&str) -> Option<String>,
) -> Option<Pick> {
    let builds: Vec<&'static KnownModule> =
        table.iter().filter(|m| m.is_for(key, arch) && m.path == path).collect();
    let pkg = builds.first()?.pkg;
    if let Some(other) = builds.iter().find(|m| m.pkg != pkg) {
        return Some(Pick::Ambiguous(format!(
            "the baked table names two packages for {path}, {pkg} and {}, so which version gates it is not known",
            other.pkg
        )));
    }
    let installed = installed_version(pkg);
    let mut matching = builds.iter().filter(|m| installed.as_deref() == Some(m.pkg_version));
    Some(match (matching.next(), matching.next()) {
        (Some(&m), None) => Pick::Build(m),
        (Some(&m), Some(_)) => Pick::Ambiguous(format!(
            "the baked table holds more than one build of {pkg} {} for {path}, so which bytes are stock is not known",
            m.pkg_version
        )),
        (None, _) => Pick::NoBuild { pkg, installed, baked: builds.iter().map(|m| m.pkg_version).collect() },
    })
}

pub(crate) fn paths_for(table: &'static [KnownModule], key: &DistroKey, arch: &str) -> Vec<&'static str> {
    let mut paths: Vec<&'static str> = Vec::new();
    for m in table.iter().filter(|m| m.is_for(key, arch)) {
        if !paths.contains(&m.path) {
            paths.push(m.path);
        }
    }
    paths
}

const fn same(a: &str, b: &str) -> bool {
    let (mut a, mut b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    while let ([x, more_a @ ..], [y, more_b @ ..]) = (a, b) {
        if *x != *y {
            return false;
        }
        a = more_a;
        b = more_b;
    }
    true
}

const fn told_apart(m: &KnownModule, mut rest: &[KnownModule]) -> bool {
    while let [n, more @ ..] = rest {
        let one_slot = same(m.distro_id, n.distro_id)
            && same(m.version_id, n.version_id)
            && same(m.arch, n.arch)
            && same(m.path, n.path);
        if one_slot && !(same(m.pkg, n.pkg) && !same(m.pkg_version, n.pkg_version)) {
            return false;
        }
        rest = more;
    }
    true
}

const fn unambiguous(mut table: &[KnownModule]) -> bool {
    while let [m, rest @ ..] = table {
        if m.pkg_version.is_empty() || !told_apart(m, rest) {
            return false;
        }
        table = rest;
    }
    true
}

const _: () = assert!(
    unambiguous(KNOWN),
    "pam_golden::KNOWN: two builds of one path on one release share a pkg_version or name different packages, or one names no version"
);
