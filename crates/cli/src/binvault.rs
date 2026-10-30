use std::path::{Path, PathBuf};

use hemostat_sensor_linux::safewrite::Pinned;
use hemostat_sensor_linux::saferead;
use sha2::{Digest, Sha256};

pub(crate) const VAULT: &str = "/var/lib/hemostat/arrival-bin";

const MANIFEST_NAME: &str = "manifest.tsv";

pub(crate) const MAX_BINARY_BYTES: u64 = 256 * 1024 * 1024;

pub(crate) const NOT_PRESENT: &str = "not present";

const NO_VAULT: &str = "no arrival binary vault — run `mahoraga remediate --seal-binaries` at arrival first";

pub(crate) const CRITICAL_BINARIES: &[&str] = &[

    "/usr/sbin/sshd",
    "/usr/sbin/vsftpd",
    "/usr/sbin/pure-ftpd",
    "/usr/sbin/proftpd",
    "/usr/sbin/mariadbd",
    "/usr/sbin/mysqld",
    "/usr/libexec/mysqld",

    "/usr/bin/sudo",
    "/usr/bin/su",
    "/bin/su",
    "/usr/bin/passwd",
];

pub(crate) fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex(&h.finalize())
}

fn vault_name(orig: &str) -> String {
    sha256_hex(orig.as_bytes())
}

fn manifest_file() -> PathBuf {
    Path::new(VAULT).join(MANIFEST_NAME)
}

pub(crate) fn is_sealed() -> bool {
    manifest_file().exists()
}

fn open_vault(create: bool) -> std::io::Result<Pinned> {
    let path = Path::new(VAULT);
    let vault = if create { Pinned::create(path, 0o700)? } else { Pinned::open(path)? };
    vault.require_root_only()?;
    Ok(vault)
}

pub(crate) struct Sealed {
    pub path: String,

    pub outcome: Result<String, String>,
}

pub(crate) fn seal_critical() -> Result<Vec<Sealed>, String> {
    let vault = open_vault(true).map_err(|e| format!("{VAULT}: {e}"))?;

    vault.set_mode(0o700).map_err(|e| format!("{VAULT}: {e}"))?;
    let (results, manifest) = seal_into(&vault, CRITICAL_BINARIES);
    vault
        .replace(MANIFEST_NAME, manifest.as_bytes(), 0o600)
        .map_err(|e| format!("{}: {e}", manifest_file().display()))?;
    Ok(results)
}

fn seal_into(vault: &Pinned, candidates: &[&str]) -> (Vec<Sealed>, String) {
    let mut results = Vec::new();
    let mut manifest = String::from("# hemostat arrival-bin manifest v1\n");
    for &p in candidates {
        let outcome = seal_one(vault, p);
        if let Ok(sha) = &outcome {
            manifest.push_str(&format!("{sha}\t{p}\n"));
        }
        results.push(Sealed { path: p.to_string(), outcome });
    }
    (results, manifest)
}

fn seal_one(vault: &Pinned, p: &str) -> Result<String, String> {
    let bytes = match saferead::read_bytes(Path::new(p), MAX_BINARY_BYTES) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(NOT_PRESENT.into()),
        Err(e) => return Err(format!("not sealed: {e}")),
    };
    let sha = sha256_hex(&bytes);
    vault
        .replace(&vault_name(p), &bytes, 0o600)
        .map_err(|e| format!("vault write failed: {e}"))?;
    Ok(sha)
}

pub(crate) fn sealed_good(orig: &str) -> Result<(Vec<u8>, String), String> {
    let vault = match open_vault(false) {
        Ok(v) => v,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(NO_VAULT.to_string()),
        Err(e) => return Err(format!("refusing to restore from {VAULT}: {e}")),
    };
    sealed_good_in(&vault, orig)
}

fn sealed_good_in(vault: &Pinned, orig: &str) -> Result<(Vec<u8>, String), String> {
    let manifest = match vault.entry_path(MANIFEST_NAME).and_then(|p| saferead::read_text(&p)) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(NO_VAULT.to_string()),
        Err(e) => {
            return Err(format!(
                "the vault manifest {} could not be read ({e}), so no sealed copy can be checked",
                manifest_file().display()
            ))
        }
    };
    let want = manifest_sha(&manifest, orig)
        .ok_or_else(|| format!("{orig} was not sealed at arrival (not in the vault manifest)"))?;
    let bytes = vault
        .entry_path(&vault_name(orig))
        .and_then(|p| saferead::read_bytes(&p, MAX_BINARY_BYTES))
        .map_err(|e| format!("the sealed copy of {orig} is unreadable: {e}"))?;
    let got = sha256_hex(&bytes);
    if got != want {
        return Err(format!(
            "the sealed copy of {orig} no longer matches its recorded hash — the vault may have \
             been tampered with. Refusing to write it over the live binary"
        ));
    }
    Ok((bytes, got))
}

pub(crate) fn manifest_sha(manifest: &str, orig: &str) -> Option<String> {
    manifest
        .lines()
        .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
        .find_map(|l| {
            let (sha, path) = l.split_once('\t')?;
            (path == orig).then(|| sha.to_string())
        })
}
