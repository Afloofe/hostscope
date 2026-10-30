use std::path::{Path, PathBuf};

use hemostat_sensor_linux::safewrite::Pinned;
use hemostat_sensor_linux::saferead;
use sha2::{Digest, Sha256};

pub(crate) const VAULT: &str = "/var/lib/hemostat/arrival-bin";

const MANIFEST_NAME: &str = "manifest.tsv";

const MANIFEST_HEADER: &str = "# hemostat arrival-bin manifest v2\n";

pub(crate) const MAX_BINARY_BYTES: u64 = hemostat_enforce_linux::MAX_VAULT_BYTES;

pub(crate) const NOT_PRESENT: &str = "not present";

const NO_VAULT: &str = "no arrival binary vault — run `mahoraga remediate --seal-binaries` at arrival first";

pub(crate) const CRITICAL_BINARIES: &[&str] = &[

    "/usr/sbin/sshd",
    "/usr/sbin/vsftpd",
    "/usr/sbin/pure-ftpd",
    "/usr/sbin/proftpd",

    "/usr/libexec/mariadbd",
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

    pub link_to: Option<String>,

    pub outcome: Result<String, String>,
}

pub(crate) fn copies(results: &[Sealed]) -> usize {
    let mut files: Vec<&str> = results
        .iter()
        .filter(|r| r.outcome.is_ok())
        .map(|r| r.link_to.as_deref().unwrap_or(&r.path))
        .collect();
    files.sort_unstable();
    files.dedup();
    files.len()
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
    let mut manifest = String::from(MANIFEST_HEADER);

    let mut done: Vec<(String, Result<String, String>)> = Vec::new();
    for &p in candidates {
        let real = match real_file(p) {
            Ok(real) => real,
            Err(why) => {
                results.push(Sealed { path: p.to_string(), link_to: None, outcome: Err(why) });
                continue;
            }
        };
        let outcome = match done.iter().find(|(r, _)| *r == real) {
            Some((_, prior)) => prior.clone(),
            None => {
                let fresh = seal_one(vault, &real);
                if let Ok(sha) = &fresh {
                    manifest.push_str(&format!("{sha}\t{real}\n"));
                }
                done.push((real.clone(), fresh.clone()));
                fresh
            }
        };
        if real == p {
            results.push(Sealed { path: p.to_string(), link_to: None, outcome });
            continue;
        }

        let outcome = match outcome {
            Err(e) if e == NOT_PRESENT => Err("not sealed: what it leads to is not there".to_string()),
            other => other,
        };
        if let Ok(sha) = &outcome {
            manifest.push_str(&format!("{sha}\t{p}\t{real}\n"));
        }
        results.push(Sealed { path: p.to_string(), link_to: Some(real), outcome });
    }
    (results, manifest)
}

fn real_file(p: &str) -> Result<String, String> {
    match std::fs::symlink_metadata(p) {
        Ok(md) if md.file_type().is_symlink() => {}
        Ok(_) => return Ok(p.to_string()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(NOT_PRESENT.into()),
        Err(e) => return Err(format!("not sealed: {e}")),
    }
    let real = std::fs::canonicalize(p)
        .map_err(|e| format!("not sealed: it is a link that does not lead to a file ({e})"))?;
    match real.to_str() {
        Some(r) if !r.chars().any(char::is_control) => Ok(r.to_string()),
        _ => Err(format!(
            "not sealed: it is a link to {}, a name the manifest cannot hold",
            real.display()
        )),
    }
}

fn seal_one(vault: &Pinned, p: &str) -> Result<String, String> {
    let bytes = match read_regular(Path::new(p)) {
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

fn read_regular(path: &Path) -> std::io::Result<Vec<u8>> {
    use std::io::{Error, ErrorKind, Read as _};
    use std::os::unix::fs::MetadataExt as _;

    let judged = std::fs::symlink_metadata(path)?;
    if !judged.is_file() {
        return Err(Error::new(ErrorKind::InvalidInput, saferead::NOT_REGULAR));
    }
    let (f, md) = saferead::open_regular(path, saferead::NOT_REGULAR)?;
    if (md.dev(), md.ino()) != (judged.dev(), judged.ino()) {
        return Err(Error::new(ErrorKind::InvalidInput, "it was replaced while it was being read"));
    }
    if md.len() > MAX_BINARY_BYTES {
        return Err(Error::new(
            ErrorKind::InvalidData,
            format!("{} bytes, over the {MAX_BINARY_BYTES}-byte cap", md.len()),
        ));
    }
    let mut buf = Vec::with_capacity(usize::try_from(md.len()).unwrap_or(0));
    (&f).take(MAX_BINARY_BYTES).read_to_end(&mut buf)?;
    Ok(buf)
}

pub(crate) struct Good {

    pub target: String,

    pub bytes: Vec<u8>,

    pub sha: String,
}

pub(crate) fn sealed_good(orig: &str) -> Result<Good, String> {
    let vault = match open_vault(false) {
        Ok(v) => v,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(NO_VAULT.to_string()),
        Err(e) => return Err(format!("refusing to restore from {VAULT}: {e}")),
    };
    sealed_good_in(&vault, orig)
}

fn sealed_good_in(vault: &Pinned, orig: &str) -> Result<Good, String> {
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
    let rec = manifest_entry(&manifest, orig)
        .ok_or_else(|| format!("{orig} was not sealed at arrival (not in the vault manifest)"))?;
    let target = match rec.real {
        None => orig.to_string(),
        Some(real) => {

            match manifest_entry(&manifest, &real) {
                Some(Recorded { sha, real: None }) if sha == rec.sha => {}
                _ => {
                    return Err(format!(
                        "the vault manifest records {orig} as a link to {real}, and does not record \
                         {real} itself with the same hash. Refusing to restore from a manifest that \
                         disagrees with itself"
                    ))
                }
            }
            still_leads_to(orig, &real)?;
            real
        }
    };
    let bytes = vault
        .entry_path(&vault_name(&target))
        .and_then(|p| saferead::read_bytes(&p, MAX_BINARY_BYTES))
        .map_err(|e| format!("the sealed copy of {target} is unreadable: {e}"))?;
    let got = sha256_hex(&bytes);
    if got != rec.sha {
        return Err(format!(
            "the sealed copy of {target} no longer matches its recorded hash — the vault may have \
             been tampered with. Refusing to write it over the live binary"
        ));
    }
    Ok(Good { target, bytes, sha: got })
}

fn still_leads_to(asked: &str, real: &str) -> Result<(), String> {
    let now = match std::fs::symlink_metadata(asked) {
        Ok(md) if md.file_type().is_symlink() => match std::fs::canonicalize(asked) {
            Ok(p) if p == Path::new(real) => return Ok(()),
            Ok(p) => format!("now leads to {}", p.display()),
            Err(e) => format!("now leads to nothing ({e})"),
        },
        Ok(_) => "is no longer a link".to_string(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => "is not there now".to_string(),
        Err(e) => format!("cannot be examined now ({e})"),
    };
    Err(format!(
        "{asked} was a link to {real} when it was sealed, and {now}. Restoring {real} would not \
         undo that: restore {real} by its own name if it was tampered with, and put {asked} back \
         as a link to it by hand"
    ))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Recorded {

    pub sha: String,

    pub real: Option<String>,
}

pub(crate) fn manifest_entry(manifest: &str, orig: &str) -> Option<Recorded> {
    manifest
        .lines()
        .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
        .find_map(|l| {
            let mut fields = l.split('\t');
            let (sha, path, real) = (fields.next()?, fields.next()?, fields.next());
            (path == orig && fields.next().is_none())
                .then(|| Recorded { sha: sha.to_string(), real: real.map(str::to_string) })
        })
}
