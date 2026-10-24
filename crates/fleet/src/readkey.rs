use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use hemostat_evcrypto::envelope::KeyPair;
use hemostat_evcrypto::secret::Secret32;

pub const READ_KEY_FILE: &str = "read.key";

fn path(base: &Path) -> PathBuf {
    base.join(READ_KEY_FILE)
}

pub fn load(base: &Path) -> Result<Option<Secret32>, String> {
    let p = path(base);
    match fs::symlink_metadata(&p) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("cannot look at the read key: {e}")),
        Ok(m) if !m.file_type().is_file() => Err("the read key is not a regular file; a human must look".to_string()),
        Ok(_) => {
            let mut bytes = fs::read(&p).map_err(|e| format!("cannot read the read key: {e}"))?;
            let key = <[u8; 32]>::try_from(bytes.as_slice()).map(Secret32::new);
            hemostat_evcrypto::secret::wipe_bytes(&mut bytes);
            key.map(Some).map_err(|_| "the read key is not 32 bytes; a human must look".to_string())
        }
    }
}

pub fn public(base: &Path) -> Result<Option<[u8; 32]>, String> {
    Ok(load(base)?.map(|s| KeyPair::from_seed(*s.expose()).public_bytes()))
}

pub fn make(base: &Path, entropy: &mut dyn FnMut() -> std::io::Result<[u8; 32]>) -> Result<([u8; 32], bool), String> {
    if let Some(pk) = public(base)? {
        return Ok((pk, false));
    }
    crate::shared_dir(base).map_err(|e| format!("cannot create {}: {e}", base.display()))?;
    let mut seed = entropy().map_err(|e| format!("cannot read entropy for the read key: {e}"))?;
    let pk = KeyPair::from_seed(seed).public_bytes();
    let p = path(base);
    let mut o = fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        o.mode(0o600);
    }
    let written = o
        .open(&p)
        .and_then(|mut f| f.write_all(&seed).and_then(|()| f.sync_all()))
        .map_err(|e| format!("cannot write the read key: {e}"));
    hemostat_evcrypto::secret::wipe_bytes(&mut seed);
    written?;

    crate::set_mode(&p, 0o640).map_err(|e| format!("cannot set the read key's mode: {e}"))?;
    Ok((pk, true))
}
