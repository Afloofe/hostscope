#![allow(dead_code)]

#[cfg(target_os = "windows")]
use crate::render::h;
#[cfg(target_os = "windows")]
use crate::{EXIT_ENFORCER, EXIT_FAILED, EXIT_OK, EXIT_POLICY, EXIT_USAGE};

use sha2::{Digest, Sha256};

pub(crate) const CRITICAL_BINARIES: &[&str] = &[
    r"C:\Windows\System32\dns.exe",
    r"C:\Windows\System32\tlntsvr.exe",
    r"C:\Windows\System32\inetsrv\inetinfo.exe",
    r"C:\Windows\System32\inetsrv\w3wp.exe",
    r"C:\Windows\System32\OpenSSH\sshd.exe",
    r"C:\Windows\System32\WsmSvc.dll",
    r"C:\Windows\System32\srvsvc.dll",
];

pub(crate) fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    let mut hsh = Sha256::new();
    hsh.update(bytes);
    hex(&hsh.finalize())
}

pub(crate) fn vault_name(orig: &str) -> String {
    sha256_hex(orig.to_ascii_lowercase().as_bytes())
}

pub(crate) fn manifest_sha(manifest: &str, orig: &str) -> Option<String> {
    let want = orig.to_ascii_lowercase();
    manifest
        .lines()
        .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
        .find_map(|l| {
            let (sha, path) = l.split_once('\t')?;
            (path.to_ascii_lowercase() == want).then(|| sha.to_string())
        })
}

pub(crate) const VAULT_DIR: &str = "arrival-bin";

pub(crate) const MANIFEST_FILE: &str = "manifest.tsv";

pub(crate) const MAX_BINARY: u64 = 256 << 20;

pub(crate) const MAX_MANIFEST: u64 = 1 << 20;

pub(crate) fn short(sha: &str) -> &str {
    sha.get(..16).unwrap_or(sha)
}

pub(crate) fn unsealable(p: &str) -> Option<&'static str> {
    if p.chars().any(char::is_control) {
        return Some("a path with a control character in it");
    }
    let mut c = p.chars();
    let local = matches!((c.next(), c.next(), c.next()), (Some(d), Some(':'), Some('\\')) if d.is_ascii_alphabetic());
    (!local).then_some("not an absolute path on a local drive (X:\\…)")
}

#[cfg(target_os = "windows")]
pub(crate) fn vault_dir() -> std::path::PathBuf {
    crate::win_private::root().join(VAULT_DIR)
}

#[cfg(target_os = "windows")]
pub(crate) struct Sealed {
    pub path: String,

    pub outcome: Result<String, String>,
}

#[cfg(target_os = "windows")]
pub(crate) fn seal(args: &[String], extra: &[String], _json: bool) -> u8 {
    use crate::win_private::{read_regular, write_atomic, ReadError};

    let vault = match crate::win_private::ensure(&[VAULT_DIR]) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("hemostat remediate --seal-binaries: {}", h(&e));
            return EXIT_FAILED;
        }
    };
    if vault.join(MANIFEST_FILE).exists() && !args.iter().any(|a| a == "--replace") {
        eprintln!(
            "hemostat remediate --seal-binaries: the vault already holds a seal. The arrival seal is taken \
             once; `--replace` keeps the sha record and re-seals (use only if you are certain nothing has been \
             tampered since)"
        );
        return EXIT_USAGE;
    }
    let targets: Vec<String> = CRITICAL_BINARIES
        .iter()
        .map(|s| s.to_string())
        .chain(extra.iter().cloned())
        .collect();

    let mut manifest = String::from("# hemostat windows arrival-bin manifest v1\n");
    let (mut sealed, mut skipped) = (0u32, 0u32);
    for p in &targets {
        if let Some(why) = unsealable(p) {
            skipped += 1;
            eprintln!("  NOT sealed {}: {why}", h(p));
            continue;
        }

        match read_regular(std::path::Path::new(p), MAX_BINARY) {
            Ok(bytes) => {
                let sha = sha256_hex(&bytes);
                match write_atomic(&vault, &vault_name(p), &bytes) {
                    Ok(_) => {
                        manifest.push_str(&format!("{sha}\t{p}\n"));
                        sealed += 1;
                        println!("  sealed {}  ({}…)", h(p), short(&sha));
                    }
                    Err(e) => {
                        skipped += 1;
                        eprintln!("  NOT sealed {}: vault write failed: {}", h(p), h(&e));
                    }
                }
            }
            Err(ReadError::Absent) => {
                skipped += 1;

                println!("  absent {} (skipped)", h(p));
            }
            Err(e) => {
                skipped += 1;
                eprintln!("  NOT sealed {}: {}", h(p), h(&e.to_string()));
            }
        }
    }
    if let Err(e) = write_atomic(&vault, MANIFEST_FILE, manifest.as_bytes()) {
        eprintln!("hemostat remediate --seal-binaries: could not write the manifest: {}", h(&e));
        return EXIT_FAILED;
    }
    println!("\nsealed {sealed} binary(ies) into {} ({skipped} absent/skipped)", h(&vault.display().to_string()));
    EXIT_OK
}

#[cfg(target_os = "windows")]
pub(crate) fn sealed_good(orig: &str) -> Result<(Vec<u8>, String), String> {
    use crate::win_private::{private_file, read_regular, ReadError};
    const NO_VAULT: &str = "no arrival binary vault — run `mahoraga remediate --seal-binaries` at arrival first";
    let vault = match crate::win_private::verify(&[VAULT_DIR]) {
        Ok(Some(v)) => v,
        Ok(None) => return Err(NO_VAULT.to_string()),
        Err(e) => return Err(format!("the arrival binary vault cannot be trusted: {e}")),
    };
    let manifest_at = vault.join(MANIFEST_FILE);
    let manifest = match read_regular(&manifest_at, MAX_MANIFEST) {
        Ok(b) => String::from_utf8(b).map_err(|_| "the vault manifest is not text".to_string())?,
        Err(ReadError::Absent) => return Err(NO_VAULT.to_string()),
        Err(e) => return Err(format!("the vault manifest cannot be read: {e}")),
    };
    private_file(&manifest_at).map_err(|e| format!("the vault manifest cannot be trusted: {e}"))?;
    let want = manifest_sha(&manifest, orig)
        .ok_or_else(|| format!("{orig} was not sealed at arrival (not in the vault manifest)"))?;
    let copy_at = vault.join(vault_name(orig));
    let bytes = read_regular(&copy_at, MAX_BINARY).map_err(|e| format!("the sealed copy of {orig} is unreadable: {e}"))?;
    private_file(&copy_at).map_err(|e| format!("the sealed copy of {orig} cannot be trusted: {e}"))?;
    let got = sha256_hex(&bytes);
    if got != want {
        return Err(format!(
            "the sealed copy of {orig} no longer matches its recorded hash — the vault may have been tampered \
             with. Refusing to write it over the live binary"
        ));
    }
    Ok((bytes, got))
}

#[cfg(target_os = "windows")]
pub(crate) fn restore(args: &[String], path: &str, _json: bool) -> u8 {
    let (bytes, sha) = match sealed_good(path) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("hemostat remediate --restore-binary: {}", h(&e));
            return EXIT_POLICY;
        }
    };

    let live = match crate::win_private::read_regular(std::path::Path::new(path), MAX_BINARY) {
        Ok(b) => b,
        Err(crate::win_private::ReadError::NotRegular(why)) => {
            eprintln!(
                "hemostat remediate --restore-binary: refused — the live {} is {why}, not the file that was sealed. \
                 Nothing was changed",
                h(path)
            );
            return EXIT_POLICY;
        }
        Err(e) => {
            eprintln!("hemostat remediate --restore-binary: cannot read the live {}: {}", h(path), h(&e.to_string()));
            return EXIT_FAILED;
        }
    };
    let path_h = h(path);
    if sha256_hex(&live) == sha {
        println!("{path_h} already matches its arrival copy (sha {}…) — nothing to restore", short(&sha));
        return EXIT_OK;
    }
    let armed = args.iter().any(|a| a == "--arm");
    if !armed {
        println!("restore {path_h} from the arrival copy (sha {}…)", short(&sha));
        println!("  the live binary differs from arrival — it would be renamed aside (kept as evidence) and the");
        println!("  sealed bytes written back. Restart the service afterwards to run the clean binary.");
        println!("\nNothing was changed. Add --arm to apply.");
        return crate::EXIT_DRYRUN;
    }
    let secs = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs());
    let aside = format!("{path}.mahoraga-tampered-{secs}");
    let aside_h = h(&aside);

    if let Err(e) = std::fs::rename(path, &aside) {
        eprintln!("hemostat remediate --restore-binary: could not move the tampered {path_h} aside: {e}");
        return EXIT_ENFORCER;
    }

    if let Err(e) = write_new(path, &bytes) {
        eprintln!("hemostat remediate --restore-binary: could not write the arrival copy to {path_h}: {e}");

        let _ = std::fs::rename(&aside, path);
        return EXIT_ENFORCER;
    }
    crate::win_restore::audit_or_warn(&format!("restore-binary {} <- arrival (sha {}), tampered kept at {}", path, &sha[..16], aside));
    println!("restored {path_h} from its arrival copy (sha {}…)", short(&sha));
    println!("  the tampered binary is kept at {aside_h}");

    println!("  RESTART its service onto the clean binary: `sc stop <service>`, then `mahoraga services --restore --arm`,");
    println!("  which starts a scored service only while it is configured to run its stock binary (`sc qc <service>`)");
    println!("  undo: del \"{path_h}\" && ren \"{aside_h}\" \"<name>\"");
    EXIT_OK
}

#[cfg(target_os = "windows")]
fn write_new(path: &str, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;
    use std::os::windows::fs::OpenOptionsExt as _;

    const OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    let mut f = std::fs::OpenOptions::new().write(true).create_new(true).custom_flags(OPEN_REPARSE_POINT).open(path)?;
    f.write_all(bytes)?;
    f.sync_all()
}
