use std::collections::BTreeSet;
use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;

use crate::rootkit::{Finding, Severity};

const SYSTEM_BIN_DIRS: &[&str] = &["/usr/bin", "/usr/sbin", "/bin", "/sbin"];

const SYSTEM_LIB_DIRS: &[&str] = &["/usr/lib", "/usr/lib64", "/lib", "/lib64"];

const UNIT_DIRS: &[&str] = &[
    "/etc/systemd/system",
    "/run/systemd/system",
    "/usr/lib/systemd/system",
    "/lib/systemd/system",
];

const WRITABLE_PREFIXES: &[&str] = &[
    "/tmp/", "/var/tmp/", "/dev/shm/", "/home/", "/run/user/",
];

const WRITABLE_EXACT: &[&str] = &["/tmp", "/var/tmp", "/dev/shm"];

const HASH_CAP: usize = 4000;

const MAX_HASH_BYTES: u64 = 256 * 1024 * 1024;

#[derive(Debug, Clone, Default)]
pub struct Report {

    pub findings: Vec<Finding>,

    pub available: bool,

    pub reason: Option<String>,

    pub package_system: Option<String>,

    pub files_hashed: usize,

    pub hash_cap: usize,

    pub mismatches: usize,

    pub unpackaged: usize,

    pub units_scanned: usize,

    pub vendor_release: Option<String>,

    pub vendor_checked: usize,
}

const MD5_S: [u32; 64] = [
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
];

const MD5_K: [u32; 64] = [
    0xd76a_a478, 0xe8c7_b756, 0x2420_70db, 0xc1bd_ceee,
    0xf57c_0faf, 0x4787_c62a, 0xa830_4613, 0xfd46_9501,
    0x6980_98d8, 0x8b44_f7af, 0xffff_5bb1, 0x895c_d7be,
    0x6b90_1122, 0xfd98_7193, 0xa679_438e, 0x49b4_0821,
    0xf61e_2562, 0xc040_b340, 0x265e_5a51, 0xe9b6_c7aa,
    0xd62f_105d, 0x0244_1453, 0xd8a1_e681, 0xe7d3_fbc8,
    0x21e1_cde6, 0xc337_07d6, 0xf4d5_0d87, 0x455a_14ed,
    0xa9e3_e905, 0xfcef_a3f8, 0x676f_02d9, 0x8d2a_4c8a,
    0xfffa_3942, 0x8771_f681, 0x6d9d_6122, 0xfde5_380c,
    0xa4be_ea44, 0x4bde_cfa9, 0xf6bb_4b60, 0xbebf_bc70,
    0x289b_7ec6, 0xeaa1_27fa, 0xd4ef_3085, 0x0488_1d05,
    0xd9d4_d039, 0xe6db_99e5, 0x1fa2_7cf8, 0xc4ac_5665,
    0xf429_2244, 0x432a_ff97, 0xab94_23a7, 0xfc93_a039,
    0x655b_59c3, 0x8f0c_cc92, 0xffef_f47d, 0x8584_5dd1,
    0x6fa8_7e4f, 0xfe2c_e6e0, 0xa301_4314, 0x4e08_11a1,
    0xf753_7e82, 0xbd3a_f235, 0x2ad7_d2bb, 0xeb86_d391,
];

#[allow(clippy::indexing_slicing, clippy::many_single_char_names)]
pub(crate) fn md5_hex(data: &[u8]) -> String {
    let (mut a0, mut b0, mut c0, mut d0) =
        (0x6745_2301u32, 0xefcd_ab89u32, 0x98ba_dcfeu32, 0x1032_5476u32);

    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut msg = Vec::with_capacity(data.len() + 72);
    msg.extend_from_slice(data);
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_le_bytes());

    let (blocks, _remainder) = msg.as_chunks::<64>();
    for chunk in blocks {
        let mut m = [0u32; 16];
        for (i, word) in m.iter_mut().enumerate() {
            let b = i * 4;
            *word = u32::from_le_bytes([chunk[b], chunk[b + 1], chunk[b + 2], chunk[b + 3]]);
        }
        let (mut a, mut b, mut c, mut d) = (a0, b0, c0, d0);
        for i in 0..64 {
            let (f, g) = match i {
                0..=15 => ((b & c) | (!b & d), i),
                16..=31 => ((d & b) | (!d & c), (5 * i + 1) % 16),
                32..=47 => (b ^ c ^ d, (3 * i + 5) % 16),
                _ => (c ^ (b | !d), (7 * i) % 16),
            };
            let f = f
                .wrapping_add(a)
                .wrapping_add(MD5_K[i])
                .wrapping_add(m[g]);
            a = d;
            d = c;
            c = b;
            b = b.wrapping_add(f.rotate_left(MD5_S[i]));
        }
        a0 = a0.wrapping_add(a);
        b0 = b0.wrapping_add(b);
        c0 = c0.wrapping_add(c);
        d0 = d0.wrapping_add(d);
    }

    let mut out = String::with_capacity(32);
    for v in [a0, b0, c0, d0] {
        for byte in v.to_le_bytes() {
            out.push_str(&byte_hex(byte));
        }
    }
    out
}

fn byte_hex(b: u8) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let hi = HEX[(b >> 4) as usize] as char;
    let lo = HEX[(b & 0x0f) as usize] as char;
    let mut s = String::with_capacity(2);
    s.push(hi);
    s.push(lo);
    s
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Md5Entry {

    md5: String,

    path: String,
}

fn parse_md5sums(text: &str) -> Vec<Md5Entry> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim_end();
        if line.is_empty() {
            continue;
        }
        let Some((md5, rest)) = line.split_once(char::is_whitespace) else {
            continue;
        };
        let rel = rest.trim_start();

        if md5.len() != 32 || !md5.bytes().all(|b| b.is_ascii_hexdigit()) || rel.is_empty() {
            continue;
        }
        out.push(Md5Entry {
            md5: md5.to_ascii_lowercase(),
            path: format!("/{}", rel.trim_start_matches('/')),
        });
    }
    out
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RpmVerify {

    path: String,

    config: bool,
}

fn parse_rpm_va(text: &str) -> Vec<RpmVerify> {
    let mut out = Vec::new();
    for line in text.lines() {

        let Some(slash) = line.find(" /") else {
            continue;
        };
        let path = line[slash + 1..].trim().to_string();
        let prefix = &line[..slash];
        let mut toks = prefix.split_whitespace();
        let Some(flags) = toks.next() else {
            continue;
        };

        if !flags.contains('5') {
            continue;
        }

        let config = toks.any(|t| t == "c");
        out.push(RpmVerify { path, config });
    }
    out
}

fn hash_priority(path: &str) -> u8 {
    if SYSTEM_BIN_DIRS.iter().any(|d| is_child(path, d)) {
        return 0;
    }
    let Some(rel) = SYSTEM_LIB_DIRS.iter().find_map(|d| path.strip_prefix(d)?.strip_prefix('/')) else {
        return 4;
    };
    let (dir, name) = rel.rsplit_once('/').unwrap_or(("", rel));
    if matches!(dir.split('/').next(), Some("modules" | "firmware")) {
        return 3;
    }
    let multiarch = |d: &str| d.contains("-linux-gnu");
    let where_the_loader_looks = match dir.split_once('/') {
        None => dir.is_empty() || dir == "security" || multiarch(dir),
        Some((arch, "security")) => multiarch(arch),
        Some(_) => false,
    };
    if where_the_loader_looks && (name.ends_with(".so") || name.contains(".so.")) {
        1
    } else {
        2
    }
}

fn is_child(path: &str, dir: &str) -> bool {
    path.starts_with(dir) && path.as_bytes().get(dir.len()) == Some(&b'/')
}

fn is_verifiable_system_path(path: &str) -> bool {
    SYSTEM_BIN_DIRS
        .iter()
        .chain(SYSTEM_LIB_DIRS.iter())
        .any(|d| is_child(path, d))
}

fn reverse_shell_shape(cmd: &str) -> Option<&'static str> {
    let c = cmd.to_ascii_lowercase();
    let toks: Vec<&str> = c.split_whitespace().collect();

    let is_nc = |t: &str| {
        let base = t.rsplit('/').next().unwrap_or(t);
        matches!(base, "nc" | "ncat" | "netcat" | "nc.traditional" | "nc.openbsd")
    };
    let has_nc = toks.iter().any(|t| is_nc(t));

    if c.contains("/dev/tcp/") || c.contains("/dev/udp/") {

        let shell_dash_i = toks.windows(2).any(|w| {
            let base = w[0].rsplit('/').next().unwrap_or(w[0]);
            matches!(base, "bash" | "sh" | "zsh" | "dash" | "ksh" | "ash" | "busybox")
                && w[1] == "-i"
        });
        let stdio_wired = c.contains(">&")
            || c.contains("0>&1")
            || c.contains("0<&1")
            || c.contains("2>&")
            || c.contains("exec ")
            || shell_dash_i;
        if stdio_wired {
            return Some("shell /dev/tcp reverse shell");
        }
    }

    if has_nc
        && toks.iter().any(|t| {
            *t == "-e" || *t == "-c" || t.starts_with("-e/") || t.starts_with("-c/")
        })
    {
        return Some("netcat -e command execution");
    }

    if c.contains("mkfifo") && has_nc {
        return Some("mkfifo + netcat backpipe");
    }

    if c.contains("socat")
        && c.contains("exec:")
        && (c.contains("tcp:") || c.contains("tcp-connect") || c.contains("openssl:"))
    {
        return Some("socat exec-to-tcp bridge");
    }

    if (c.contains("python") || c.contains("python3"))
        && c.contains("-c")
        && c.contains("socket")
        && (c.contains("connect"))
        && (c.contains("subprocess")
            || c.contains("pty")
            || c.contains("os.dup2")
            || c.contains("/bin/sh")
            || c.contains("/bin/bash"))
    {
        return Some("python socket reverse shell");
    }

    if (c.contains("perl") || c.contains("ruby"))
        && (c.contains("-e") || c.contains("-rsocket"))
        && c.contains("socket")
        && (c.contains("exec") || c.contains("/bin/sh") || c.contains("/bin/bash"))
    {
        return Some("perl/ruby socket reverse shell");
    }

    if c.contains("php")
        && c.contains("fsockopen")
        && (c.contains("exec") || c.contains("proc_open") || c.contains("shell_exec"))
    {
        return Some("php fsockopen reverse shell");
    }
    None
}

fn is_writable_path(path: &str) -> bool {
    WRITABLE_EXACT.contains(&path)
        || WRITABLE_PREFIXES.iter().any(|p| path.starts_with(p))
}

fn exec_start_binary(value: &str) -> Option<String> {
    let stripped = value.trim_start_matches(['-', '@', '+', '!', ':']).trim();
    let first = stripped.split_whitespace().next()?.trim_matches(['"', '\'']);
    (!first.is_empty()).then(|| first.to_string())
}

fn unit_exec_lines(body: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for line in crate::services::logical_lines(body) {
        let line = line.trim();
        if line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        if matches!(
            key,
            "ExecStart"
                | "ExecStartPre"
                | "ExecStartPost"
                | "ExecReload"
                | "ExecStop"
                | "ExecStopPost"
                | "ExecCondition"
        ) {
            let value = value.trim();
            if !value.is_empty() {
                out.push((key.to_string(), value.to_string()));
            }
        }
    }
    out
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum CmdOutcome {

    Ok(String),

    Failed(String),

    NotInstalled,
}

fn run_cmd(program: &str, args: &[&str]) -> CmdOutcome {
    let result = Command::new(program)
        .args(args)
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .env("LC_ALL", "C")
        .output();
    match result {
        Ok(out) if out.status.success() => {
            CmdOutcome::Ok(String::from_utf8_lossy(&out.stdout).into_owned())
        }
        Ok(out) => {

            let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
            if !stdout.trim().is_empty() {
                CmdOutcome::Ok(stdout)
            } else {
                let code = out
                    .status
                    .code()
                    .map_or_else(|| "killed by signal".to_string(), |c| format!("exit {c}"));
                let err = String::from_utf8_lossy(&out.stderr);
                let tail = err.trim().lines().next().unwrap_or("");
                CmdOutcome::Failed(if tail.is_empty() {
                    code
                } else {
                    format!("{code}: {tail}")
                })
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => CmdOutcome::NotInstalled,
        Err(e) => CmdOutcome::Failed(e.to_string()),
    }
}

pub fn report() -> Report {
    report_with(None)
}

pub fn report_with(manifest: Option<&crate::vendor::Manifest>) -> Report {
    let mut findings = Vec::new();
    let mut rep = Report { hash_cap: HASH_CAP, ..Report::default() };
    let mut cov = Coverage::default();

    let mut judged = BTreeSet::new();
    if let Some(m) = manifest {
        let v = crate::vendor::sweep(m);
        rep.vendor_checked = v.checked;
        rep.mismatches += v.findings.iter().filter(|f| f.severity == Severity::Critical).count();
        rep.vendor_release = Some(m.release.clone());
        findings.extend(v.findings);
        judged = v.judged;
    }
    run_package_integrity(&mut findings, &mut rep, &judged);
    if let Some(m) = manifest {
        findings.push(Finding {
            severity: Severity::Note,
            subject: "package integrity (reference)".into(),
            what: format!(
                "{} file(s) judged against the signed {} vendor manifest; the package-database \
                 check above covered the rest, including any covered file on a package version \
                 the manifest was not built from",
                judged.len(), m.release
            ),
            why: "the manifest was built off this host and is signed, so root here cannot make a \
                  trojan match it; the host's own package database can be rewritten by the same \
                  root, so its findings are the weaker of the two"
                .into(),
        });
    }

    run_unpackaged_scan(&mut findings, &mut rep, &mut cov);

    run_service_scan(&mut findings, &mut rep, &mut cov);
    run_writable_path_scan(&mut findings, &mut cov);
    run_process_scan(&mut findings, &mut cov);

    findings.extend(refusal_findings(&cov.refused));

    let (available, reason) = availability(&cov);
    rep.available = available;
    rep.reason = reason;
    rep.findings = findings;
    rep.findings.sort_by_key(|f| std::cmp::Reverse(f.severity));
    rep
}

#[derive(Debug, Default)]
struct Coverage {

    read: usize,

    refused: Vec<(String, String)>,
}

impl Coverage {

    fn open(&mut self, dir: &str) -> Option<fs::ReadDir> {
        match fs::read_dir(dir) {
            Ok(rd) => {
                self.read += 1;
                Some(rd)
            }

            Err(e) if e.kind() == io::ErrorKind::NotFound => None,
            Err(e) => {
                self.refused.push((dir.to_string(), e.to_string()));
                None
            }
        }
    }
}

fn refusal_findings(refused: &[(String, String)]) -> Vec<Finding> {
    refused
        .iter()
        .map(|(dir, why)| Finding {
            severity: Severity::Note,
            subject: format!("inventory root {dir} skipped"),
            what: format!("{dir} could not be listed: {why}"),
            why: "this is 'could not look', not 'nothing there' — no finding in this report \
                  says anything about what that directory holds"
                .into(),
        })
        .collect()
}

fn availability(cov: &Coverage) -> (bool, Option<String>) {
    if cov.read > 0 {
        return (true, None);
    }
    (
        false,
        Some(if cov.refused.is_empty() {
            "none of the inventory scan roots exist on this host".into()
        } else {
            format!(
                "none of the inventory scan roots could be listed ({} refused) — re-run as root",
                cov.refused.len()
            )
        }),
    )
}

fn run_package_integrity(findings: &mut Vec<Finding>, rep: &mut Report, judged: &BTreeSet<String>) {
    let dpkg_info = Path::new("/var/lib/dpkg/info");
    let rpm_db = Path::new("/var/lib/rpm");

    if dpkg_info.is_dir() {
        rep.package_system = Some("dpkg".into());
        verify_dpkg(findings, rep, judged);
    } else if rpm_db.is_dir() || Path::new("/usr/bin/rpm").exists() {
        rep.package_system = Some("rpm".into());
        verify_rpm(findings, rep);
    } else {
        findings.push(Finding {
            severity: Severity::Note,
            subject: "package integrity".into(),
            what: "no dpkg or rpm database found, so on-disk binaries were not verified against a \
                   packaging baseline"
                .into(),
            why: "package verification is the strongest part of this inventory (it catches a \
                  trojaned system binary); this host uses neither dpkg nor rpm, so it did not run \
                  — parts B and C still ran".into(),
        });
    }
}

fn left_to_dpkg(path: &str, judged: &BTreeSet<String>) -> bool {
    is_verifiable_system_path(path) && !judged.contains(path)
}

fn verify_dpkg(findings: &mut Vec<Finding>, rep: &mut Report, judged: &BTreeSet<String>) {
    let Ok(dir) = fs::read_dir("/var/lib/dpkg/info") else {
        findings.push(did_not_run_pkg("/var/lib/dpkg/info could not be read"));
        return;
    };

    let mut entries: Vec<Md5Entry> = Vec::new();
    for ent in dir.flatten() {
        let name = ent.file_name();
        let name = name.to_string_lossy();
        if !name.ends_with(".md5sums") {
            continue;
        }
        if let Some(text) = crate::saferead::read_scan_target(&ent.path()) {
            for e in parse_md5sums(&text) {

                if left_to_dpkg(&e.path, judged) {
                    entries.push(e);
                }
            }
        }
    }

    order_for_hashing(&mut entries);
    let beyond_cap = entries.len().saturating_sub(HASH_CAP);
    entries.truncate(HASH_CAP);

    let mut hashed = 0usize;
    let mut mismatches = 0usize;

    let mut now_links: Vec<&str> = Vec::new();
    let mut missing: Vec<&str> = Vec::new();
    let mut unhashable = 0usize;
    for e in &entries {
        let actual = match hash_file(Path::new(&e.path)) {
            Hashed::Md5(m) => m,
            Hashed::Symlink => {
                now_links.push(&e.path);
                continue;
            }
            Hashed::Missing => {
                missing.push(&e.path);
                continue;
            }
            Hashed::Unhashable => {
                unhashable += 1;
                continue;
            }
        };
        hashed += 1;
        if actual != e.md5 {
            mismatches += 1;
            findings.push(Finding {
                severity: Severity::Critical,
                subject: format!("modified system binary {}", e.path),
                what: format!(
                    "on-disk MD5 {actual} does not match the digest dpkg recorded at install \
                     ({})",
                    e.md5
                ),
                why: "dpkg records the shipped digest of every packaged file; a mismatch on a \
                      binary or library under a system path means the file was replaced or patched \
                      after install — a trojaned `ls`/`ps`/`sshd` is a classic rootkit persistence \
                      move. This rests on the dpkg database, which a root attacker could also \
                      rewrite; corroborate against a known-good copy, but treat the host as \
                      compromised until you have".into(),
            });
        }
    }

    rep.files_hashed = hashed;
    rep.mismatches += mismatches;

    if !now_links.is_empty() || !missing.is_empty() {
        let sample: Vec<&str> = now_links.iter().chain(missing.iter()).take(6).copied().collect();
        findings.push(Finding {
            severity: Severity::Warn,
            subject: "package integrity (dpkg)".into(),
            what: format!(
                "{} packaged file(s) dpkg recorded as regular files are now symlinks, and {} are \
                 missing — e.g. {}",
                now_links.len(),
                missing.len(),
                sample.join(", ")
            ),
            why: "dpkg records a digest only for regular files, so an entry that is now a link \
                  was replaced, and a missing one was removed. A diversion or an alternatives \
                  switch explains some; replacing a binary with a link to a trojan explains the \
                  rest. None of these were hashed, and none of them count toward \"all match\""
                .into(),
        });
    }

    findings.extend(dpkg_summary(hashed, mismatches, now_links.len(), missing.len(), unhashable, beyond_cap));
}

fn order_for_hashing(entries: &mut [Md5Entry]) {
    entries.sort_by(|a, b| hash_priority(&a.path).cmp(&hash_priority(&b.path)).then_with(|| a.path.cmp(&b.path)));
}

fn dpkg_summary(
    hashed: usize,
    mismatches: usize,
    links: usize,
    missing: usize,
    unhashable: usize,
    beyond_cap: usize,
) -> Option<Finding> {
    let unverified = links + missing + unhashable;
    if mismatches != 0 && unverified == 0 && beyond_cap == 0 {
        return None;
    }
    Some(Finding {
        severity: Severity::Note,
        subject: "package integrity (dpkg)".into(),
        what: format!(
            "re-hashed {hashed} packaged system binaries/libraries; {}{}{}",
            if mismatches == 0 {
                "all of those match the digests dpkg recorded".to_string()
            } else {
                format!("{mismatches} do NOT match the digests dpkg recorded (above)")
            },
            if unverified > 0 {
                format!(
                    "; {unverified} could NOT be hashed ({links} now links, {missing} missing, {unhashable} \
                     unreadable or over the size cap) and are unverified, not matching"
                )
            } else {
                String::new()
            },
            if beyond_cap > 0 {
                format!(
                    " (capped at {HASH_CAP}: {beyond_cap} more were not hashed — kernel modules and \
                     firmware are the first left out, binaries and shared libraries the last)"
                )
            } else {
                String::new()
            }
        ),
        why: "verifies files against the local dpkg baseline only — it catches a binary an \
              attacker replaced without curating the package metadata, not one where they also \
              rewrote the recorded md5. A signed off-host manifest is the stronger check".into(),
    })
}

fn verify_rpm(findings: &mut Vec<Finding>, rep: &mut Report) {
    let out = match run_cmd("/usr/bin/rpm", &["-Va"]) {
        CmdOutcome::Ok(s) => s,
        CmdOutcome::NotInstalled => match run_cmd("rpm", &["-Va"]) {
            CmdOutcome::Ok(s) => s,
            CmdOutcome::NotInstalled => {
                findings.push(did_not_run_pkg(
                    "an rpm database is present but the rpm binary was not found on PATH",
                ));
                return;
            }
            CmdOutcome::Failed(reason) => {
                findings.push(did_not_run_pkg(&format!("`rpm -Va` ran and failed: {reason}")));
                return;
            }
        },
        CmdOutcome::Failed(reason) => {
            findings.push(did_not_run_pkg(&format!("`rpm -Va` ran and failed: {reason}")));
            return;
        }
    };

    let changed = parse_rpm_va(&out);
    let mut mismatches = 0usize;
    for v in &changed {
        let in_system = is_verifiable_system_path(&v.path);
        if v.config {

            continue;
        }
        if in_system {
            mismatches += 1;
            findings.push(Finding {
                severity: Severity::Critical,
                subject: format!("modified system binary {}", v.path),
                what: "`rpm -Va` reports the MD5 digest of this packaged file has changed (a `5` \
                       in the verify flags)"
                    .into(),
                why: "rpm verifies each packaged file against the digest in its database; a digest \
                      change on a non-config file under a system path means the binary or library \
                      was modified after install — the trojaned-system-binary case. Corroborate \
                      against a fresh package, but treat as compromise until you do".into(),
            });
        } else {
            findings.push(Finding {
                severity: Severity::Warn,
                subject: format!("modified packaged file {}", v.path),
                what: "`rpm -Va` reports this packaged file's MD5 digest changed".into(),
                why: "a packaged file was modified after install; outside the core system bin/lib \
                      dirs this is a lead rather than a near-certain trojan — identify what changed \
                      it".into(),
            });
        }
    }

    rep.mismatches = mismatches;

    if changed.is_empty() {
        findings.push(Finding {
            severity: Severity::Note,
            subject: "package integrity (rpm)".into(),
            what: "`rpm -Va` reports no packaged file with a changed MD5 digest".into(),
            why: "verifies against the local rpm database; catches a file replaced without also \
                  updating rpm's record, not one where the attacker curated both".into(),
        });
    }
}

fn did_not_run_pkg(reason: &str) -> Finding {
    Finding {
        severity: Severity::Note,
        subject: "package integrity".into(),
        what: format!("DID NOT RUN: {reason}"),
        why: "package verification catches a trojaned system binary and is the strongest part of \
              this inventory; when it cannot run, that is reported rather than shown as a clean \
              result".into(),
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Hashed {

    Md5(String),

    Symlink,

    Missing,

    Unhashable,
}

fn hash_file(path: &Path) -> Hashed {

    let meta = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Hashed::Missing,
        Err(_) => return Hashed::Unhashable,
    };
    if meta.file_type().is_symlink() {
        return Hashed::Symlink;
    }
    if !meta.file_type().is_file() {
        return Hashed::Unhashable;
    }

    match crate::saferead::read_whole_file(path, MAX_HASH_BYTES) {
        Some(data) => Hashed::Md5(md5_hex(&data)),
        None => Hashed::Unhashable,
    }
}

fn run_unpackaged_scan(findings: &mut Vec<Finding>, rep: &mut Report, cov: &mut Coverage) {
    let dpkg_info = Path::new("/var/lib/dpkg/info");
    if !dpkg_info.is_dir() {

        if rep.package_system.as_deref() == Some("rpm") {
            findings.push(Finding {
                severity: Severity::Note,
                subject: "unpackaged binaries".into(),
                what: "DID NOT RUN on this rpm host: per-file ownership (`rpm -qf`) is not scanned \
                       to avoid thousands of subprocesses"
                    .into(),
                why: "the dpkg path reads a file-owned index in bulk; the equivalent bulk read \
                      differs on rpm, so this part is dpkg-only for now — parts A and C still \
                      cover this host".into(),
            });
        }
        return;
    }

    let owned = dpkg_owned_paths();
    if owned.is_empty() {
        findings.push(Finding {
            severity: Severity::Note,
            subject: "unpackaged binaries".into(),
            what: "DID NOT RUN: no dpkg .list files could be read, so package ownership is unknown"
                .into(),
            why: "without the set of package-owned paths, an unowned binary cannot be told from an \
                  owned one; reported rather than shown as clean".into(),
        });
        return;
    }

    let mut count = 0usize;
    for dir in SYSTEM_BIN_DIRS {
        let Some(rd) = cov.open(dir) else { continue };
        for ent in rd.flatten() {
            let path = ent.path();
            let Ok(meta) = ent.metadata() else { continue };

            if !meta.file_type().is_file() || meta.permissions().mode() & 0o111 == 0 {
                continue;
            }
            let p = path.to_string_lossy().to_string();
            if is_dpkg_owned(&p, &owned) {
                continue;
            }
            count += 1;
            findings.push(Finding {
                severity: Severity::Warn,
                subject: format!("unpackaged binary {p}"),
                what: "an executable in a package-managed system directory that no dpkg package \
                       owns"
                    .into(),
                why: "system bin dirs are owned by packages; an executable here that dpkg does not \
                      account for was placed by hand — legitimate for a locally-built tool, but \
                      also exactly how an attacker drops a payload into a trusted PATH location. \
                      Confirm what installed it (/usr/local is the correct home for hand-installed \
                      tools)".into(),
            });
        }
    }
    rep.unpackaged = count;
}

fn dpkg_owned_paths() -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let Ok(dir) = fs::read_dir("/var/lib/dpkg/info") else {
        return out;
    };
    for ent in dir.flatten() {
        let name = ent.file_name();
        let name = name.to_string_lossy();
        if !name.ends_with(".list") {
            continue;
        }
        if let Some(text) = crate::saferead::read_scan_target(&ent.path()) {
            for line in text.lines() {
                let p = line.trim();
                if p.starts_with('/') {
                    out.insert(p.to_string());
                }
            }
        }
    }
    out
}

fn is_dpkg_owned(path: &str, owned: &BTreeSet<String>) -> bool {
    if owned.contains(path) {
        return true;
    }
    for (a, b) in [("/usr/bin/", "/bin/"), ("/usr/sbin/", "/sbin/")] {
        if let Some(rest) = path.strip_prefix(a) {
            if owned.contains(&format!("{b}{rest}")) {
                return true;
            }
        }
        if let Some(rest) = path.strip_prefix(b) {
            if owned.contains(&format!("{a}{rest}")) {
                return true;
            }
        }
    }
    false
}

fn run_service_scan(findings: &mut Vec<Finding>, rep: &mut Report, cov: &mut Coverage) {
    let mut scanned = 0usize;
    for dir in UNIT_DIRS {
        let Some(rd) = cov.open(dir) else { continue };
        for ent in rd.flatten() {
            let name = ent.file_name();
            let name = name.to_string_lossy();
            if !name.ends_with(".service") {
                continue;
            }
            let Some(body) = crate::saferead::read_scan_target(&ent.path()) else { continue };
            scanned += 1;
            let unit = format!("{dir}/{name}");
            for (directive, value) in unit_exec_lines(&body) {
                if let Some(shape) = reverse_shell_shape(&value) {
                    findings.push(Finding {
                        severity: Severity::Critical,
                        subject: format!("service {name}"),
                        what: format!("{directive} reads as a reverse shell ({shape}): {}", trunc(&value, 200)),
                        why: format!(
                            "a systemd unit at {unit} runs a command matching a known \
                             reverse/bind-shell shape; a service that dials out to a shell is a \
                             persistence + C2 mechanism, not a legitimate daemon. Stop and \
                             disable the unit and hunt the operator"
                        ),
                    });
                    continue;
                }
                if let Some(bin) = exec_start_binary(&value) {
                    if is_writable_path(&bin) {
                        findings.push(Finding {
                            severity: Severity::Warn,
                            subject: format!("service {name}"),
                            what: format!("{directive} runs {bin}, in a writable path"),
                            why: format!(
                                "a unit at {unit} executes a binary from a world/user-writable \
                                 location; a legitimate service runs from a package or /opt/ /usr/local \
                                 path, so an ExecStart under /tmp, /dev/shm, /home or /var/tmp is a \
                                 lead a responder should run down"
                            ),
                        });
                    }
                }
            }
        }
    }
    rep.units_scanned = scanned;
}

fn run_writable_path_scan(findings: &mut Vec<Finding>, cov: &mut Coverage) {
    for dir in SYSTEM_BIN_DIRS {
        let Some(rd) = cov.open(dir) else { continue };
        for ent in rd.flatten() {
            let Ok(meta) = ent.metadata() else { continue };
            if !meta.file_type().is_file() {
                continue;
            }

            if meta.permissions().mode() & 0o002 != 0 {
                let p = ent.path().to_string_lossy().to_string();
                findings.push(Finding {
                    severity: Severity::Warn,
                    subject: format!("world-writable command {p}"),
                    what: "a file in a PATH directory is writable by any user".into(),
                    why: "a world-writable file in a system bin dir lets any local account replace \
                          a trusted command with their own — a privilege-escalation and \
                          persistence primitive. Restrict its mode and check whether it was \
                          already tampered with".into(),
                });
            }
        }
    }
}

fn run_process_scan(findings: &mut Vec<Finding>, cov: &mut Coverage) {
    let Some(rd) = cov.open("/proc") else {
        findings.push(Finding {
            severity: Severity::Note,
            subject: "running programs".into(),
            what: "DID NOT RUN: /proc could not be listed".into(),
            why: "without /proc the running-process checks cannot run; reported rather than shown \
                  as clean".into(),
        });
        return;
    };
    let self_pid = std::process::id();
    for ent in rd.flatten() {
        let Some(pid) = ent.file_name().to_str().and_then(|n| n.parse::<u32>().ok()) else {
            continue;
        };
        if pid == self_pid {
            continue;
        }

        let exe = fs::read_link(format!("/proc/{pid}/exe")).ok();
        let cmdline = read_cmdline(pid);

        if let Some(shape) = cmdline.as_deref().and_then(reverse_shell_shape) {
            findings.push(Finding {
                severity: Severity::Critical,
                subject: format!("pid {pid}"),
                what: format!(
                    "command line reads as a reverse shell ({shape}): {}",
                    trunc(cmdline.as_deref().unwrap_or(""), 200)
                ),
                why: "a running process whose command line matches a known reverse/bind-shell \
                      shape is very likely an attacker's interactive channel; capture it (its \
                      /proc/<pid>/exe, environ, and open sockets) before killing it".into(),
            });
            continue;
        }

        if let Some(exe) = exe {
            let exe_s = exe.to_string_lossy();

            let real = exe_s.strip_suffix(" (deleted)").unwrap_or(&exe_s);
            if is_writable_path(real) {
                findings.push(Finding {
                    severity: Severity::Warn,
                    subject: format!("pid {pid}"),
                    what: format!("running from a writable path: {real}"),
                    why: "a process whose executable lives under /tmp, /dev/shm, /home, or \
                          /var/tmp is unusual for a server workload and is where dropped payloads \
                          run from; confirm what it is and who started it".into(),
                });
            }
        }
    }
}

fn read_cmdline(pid: u32) -> Option<String> {

    let (raw, _) = crate::saferead::read_proc(
        std::path::Path::new(&format!("/proc/{pid}/cmdline")),
        crate::saferead::MAX_PROC_BYTES,
    )
    .ok()?;
    if raw.is_empty() {
        return None;
    }
    let joined = raw
        .split(|b| *b == 0)
        .filter(|s| !s.is_empty())
        .map(|s| String::from_utf8_lossy(s).into_owned())
        .collect::<Vec<_>>()
        .join(" ");
    if joined.is_empty() {
        None
    } else {
        Some(joined)
    }
}

fn trunc(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let head: String = s.chars().take(max).collect();
        format!("{head}…")
    }
}
