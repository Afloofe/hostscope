#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Toolchain {

    Go,

    Nim,

    Rust,

    PyInstaller,

    DotNet,

    Unknown,
}

impl Toolchain {

    pub const fn token(self) -> &'static str {
        match self {
            Toolchain::Go => "go",
            Toolchain::Nim => "nim",
            Toolchain::Rust => "rust",
            Toolchain::PyInstaller => "pyinstaller",
            Toolchain::DotNet => "dotnet",
            Toolchain::Unknown => "unknown",
        }
    }

    pub const fn ships_as_one_file(self) -> bool {
        matches!(self, Toolchain::Go | Toolchain::Nim | Toolchain::Rust | Toolchain::PyInstaller)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {

    Pe,

    Elf,

    Other,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identified {

    pub format: Format,

    pub toolchain: Toolchain,

    pub evidence: &'static str,

    pub complete: bool,
}

const GO_BUILDINF: &[u8] = b"\xff Go buildinf:";

const MARKERS: &[(&[u8], Toolchain, &str)] = &[

    (b"PyInstaller", Toolchain::PyInstaller, "the string `PyInstaller`"),
    (b"_MEIPASS", Toolchain::PyInstaller, "PyInstaller's `_MEIPASS` extraction marker"),

    (GO_BUILDINF, Toolchain::Go, "Go's `\\xff Go buildinf:` build-info magic"),
    (b".gopclntab", Toolchain::Go, "the `.gopclntab` section name"),
    (b"go.buildid", Toolchain::Go, "the `go.buildid` symbol"),
    (b"runtime.gopanic", Toolchain::Go, "the `runtime.gopanic` symbol"),
    (b"Go build ID:", Toolchain::Go, "the `Go build ID:` string"),

    (b"NimMainModule", Toolchain::Nim, "Nim's `NimMainModule` entry point"),
    (b"NimMainInner", Toolchain::Nim, "Nim's `NimMainInner` entry point"),
    (b"nimFrame", Toolchain::Nim, "Nim's `nimFrame` stack-trace helper"),
    (b"nim_program_result", Toolchain::Nim, "Nim's `nim_program_result` symbol"),
    (b"@mstdlib_system.nim", Toolchain::Nim, "Nim's bundled `stdlib_system.nim` path"),

    (b"core::panicking", Toolchain::Rust, "Rust's `core::panicking` path"),
    (b"/rustc/", Toolchain::Rust, "a `/rustc/<hash>` source path"),
    (b"RUST_BACKTRACE", Toolchain::Rust, "the `RUST_BACKTRACE` environment name"),
];

pub const MAX_FULL_READ: u64 = 64 * 1024 * 1024;

pub const WINDOW: usize = 4 * 1024 * 1024;

pub fn identify(bytes: &[u8]) -> Identified {
    let format = if bytes.starts_with(b"MZ") {
        Format::Pe
    } else if bytes.starts_with(b"\x7fELF") {
        Format::Elf
    } else {
        Format::Other
    };
    identify_parts(&[bytes], format, true)
}

pub fn identify_windowed(head: &[u8], tail: &[u8]) -> Identified {
    let format = if head.starts_with(b"MZ") {
        Format::Pe
    } else if head.starts_with(b"\x7fELF") {
        Format::Elf
    } else {
        Format::Other
    };
    identify_parts(&[head, tail], format, false)
}

fn identify_parts(parts: &[&[u8]], format: Format, complete: bool) -> Identified {

    if format == Format::Pe && parts.iter().any(|p| contains(p, b"mscoree.dll")) {
        return Identified {
            format,
            toolchain: Toolchain::DotNet,
            evidence: "an `mscoree.dll` import, which only a managed PE carries",
            complete,
        };
    }

    for (needle, tc, evidence) in MARKERS {
        if parts.iter().any(|p| contains(p, needle)) {
            return Identified { format, toolchain: *tc, evidence, complete };
        }
    }

    Identified {
        format,
        toolchain: Toolchain::Unknown,
        evidence: if complete {
            "no toolchain marker anywhere in the file"
        } else {
            "no toolchain marker in the part of the file that was read"
        },
        complete,
    }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > haystack.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}

const EXPECTED_DIRS: &[&str] = &[
    "c:/program files",
    "c:/program files (x86)",
    "/usr/bin",
    "/usr/sbin",
    "/usr/local/bin",
    "/usr/lib",
    "/opt",
    "/snap",
    "/nix/store",
];

const SUSPECT_DIRS: &[&str] = &[
    "c:/users/public",
    "c:/windows/temp",
    "c:/temp",
    "c:/programdata",
    "c:/perflogs",
    "/tmp",
    "/var/tmp",
    "/dev/shm",
    "/home",
];

const SYSTEM_DIRS: &[&str] = &["c:/windows/system32", "c:/windows/syswow64", "/sbin", "/bin"];

fn under(path: &str, dir: &str) -> bool {
    path.strip_prefix(dir).is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
}

fn normalise(path: &str) -> String {
    path.trim().trim_matches('"').replace('\\', "/").to_ascii_lowercase()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Weight {

    Ordinary,

    Notable,

    Alarming,
}

pub fn weigh(id: &Identified, path: &str) -> Weight {

    if id.format == Format::Other || id.toolchain == Toolchain::Unknown {
        return Weight::Ordinary;
    }
    let p = normalise(path);

    let in_any = |dirs: &[&str]| dirs.iter().any(|d| under(&p, d));

    if in_any(SYSTEM_DIRS) && id.toolchain.ships_as_one_file() {
        return Weight::Alarming;
    }

    if in_any(SUSPECT_DIRS) && id.toolchain.ships_as_one_file() {
        return Weight::Alarming;
    }

    if in_any(EXPECTED_DIRS) {
        return Weight::Ordinary;
    }

    if id.toolchain.ships_as_one_file() {
        Weight::Notable
    } else {
        Weight::Ordinary
    }
}
