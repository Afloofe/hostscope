use std::fs;
use std::io::Write as _;
use std::path::Path;

pub const LINK_KEY: &str = "link.key";

pub const RECEIPT_KEY: &str = "receipt.key";

pub fn load(path: &Path) -> Result<[u8; 32], String> {
    let shown = path.display();
    let m = fs::symlink_metadata(path).map_err(|e| format!("cannot look at {shown}: {e}"))?;
    if !m.file_type().is_file() {
        return Err(format!("{shown} is not a regular file; a human must look"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if m.permissions().mode() & 0o077 != 0 {
            return Err(format!(
                "{shown} is readable by more than its owner (mode {:o}); a collector key others can read \
                 is not a secret, so it is refused",
                m.permissions().mode() & 0o777
            ));
        }
    }
    let bytes = fs::read(path).map_err(|e| format!("cannot read {shown}: {e}"))?;
    <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| format!("{shown} is {} bytes, not 32; a human must look", bytes.len()))
}

pub fn load_or_make(
    path: &Path,
    entropy: &mut dyn FnMut() -> std::io::Result<[u8; 32]>,
) -> Result<([u8; 32], bool), String> {
    match fs::symlink_metadata(path) {
        Ok(_) => load(path).map(|k| (k, false)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            if let Some(dir) = path.parent() {
                let mut b = fs::DirBuilder::new();
                b.recursive(true);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::DirBuilderExt as _;
                    b.mode(0o700);
                }
                b.create(dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
            }
            let seed = entropy().map_err(|e| format!("cannot read entropy for {}: {e}", path.display()))?;
            let mut o = fs::OpenOptions::new();
            o.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt as _;
                o.mode(0o600);
            }
            let mut f = o.open(path).map_err(|e| format!("cannot create {}: {e}", path.display()))?;
            f.write_all(&seed)
                .and_then(|()| f.sync_all())
                .map_err(|e| format!("cannot write {}: {e}", path.display()))?;
            Ok((seed, true))
        }
        Err(e) => Err(format!("cannot look at {}: {e}", path.display())),
    }
}

pub fn link_public(seed: [u8; 32]) -> [u8; 32] {
    let sk = hemostat_remote::StaticSecret::from(seed);
    *hemostat_remote::PublicKey::from(&sk).as_bytes()
}

pub fn receipt_public(seed: [u8; 32]) -> [u8; 32] {
    hemostat_evcrypto::receipt::ReceiptKey::from_seed(seed).public_bytes()
}
