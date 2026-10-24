use std::path::Path;

use hemostat_evcrypto::manifest::{verify_and_parse, Refused, Verified};

use crate::identity::parse_hex32;
use crate::render::hex32;

pub(crate) const MAX_MANIFEST_BYTES: u64 = 256 * 1024 * 1024;

pub(crate) const MAX_SIG_BYTES: u64 = 64 * 1024;

pub(crate) const MANIFEST_ENV: &str = "HEMOSTAT_MANIFEST";

pub(crate) fn pinned_manifest_key() -> Result<[u8; 32], String> {
    let built = option_env!("HEMOSTAT_MANIFEST_PUBKEY").and_then(parse_hex32);
    let run = std::env::var("HEMOSTAT_MANIFEST_PUBKEY").ok().as_deref().and_then(parse_hex32);
    match (built, run) {
        (Some(b), Some(r)) if b != r => Err(
            "$HEMOSTAT_MANIFEST_PUBKEY differs from the key this build pins; refusing both".into(),
        ),
        (Some(k), _) | (None, Some(k)) => Ok(k),
        (None, None) => Err(
            "no manifest key is pinned: build with HEMOSTAT_MANIFEST_PUBKEY set, or set it (64 \
             hex) at run time. An unpinned manifest is a list of hashes anyone could have written"
                .into(),
        ),
    }
}

#[cfg_attr(target_os = "freebsd", allow(dead_code))]
pub(crate) fn load_with(
    path: Option<&str>,
    read: impl Fn(&Path, u64) -> Option<Vec<u8>>,
) -> Result<Option<Verified>, String> {
    let env = std::env::var(MANIFEST_ENV).ok();
    let Some(path) = path.or(env.as_deref()) else { return Ok(None) };
    let key = pinned_manifest_key()?;
    let capped = |p: &str, max: u64| {
        read(Path::new(p), max)
            .ok_or_else(|| format!("cannot read {p} (missing, not a regular file, or over {max} bytes)"))
    };
    let body = capped(path, MAX_MANIFEST_BYTES)?;
    let sig = capped(&format!("{path}.sig"), MAX_SIG_BYTES)?;
    match verify_and_parse(&key, &body, &sig) {
        Ok(m) => Ok(Some(m)),
        Err(Refused::Signature) => Err(format!(
            "{path} is not signed by the pinned manifest key {} — refusing it",
            hex32(&key)
        )),
        Err(Refused::NotUtf8) => Err(format!("{path} is not UTF-8")),
        Err(Refused::Malformed(e)) => Err(format!("{path}: {e}")),
    }
}

#[allow(dead_code)]
pub(crate) fn meta_path_for(manifest: &str, given: Option<&str>) -> String {
    if let Some(g) = given {
        return g.to_string();
    }
    manifest.strip_suffix(".tsv").map_or_else(|| format!("{manifest}.meta"), |b| format!("{b}.meta"))
}

pub(crate) type OpenFn<'a> = &'a dyn Fn(&Path) -> std::io::Result<(std::fs::File, std::fs::Metadata)>;

fn read_sig(path: &str, open: OpenFn<'_>) -> Result<Vec<u8>, String> {
    use std::io::Read as _;
    let (f, md) = open(Path::new(path)).map_err(|e| format!("cannot read {path} ({e})"))?;
    if md.len() > MAX_SIG_BYTES {
        return Err(format!("{path} is over {MAX_SIG_BYTES} bytes"));
    }
    let mut sig = Vec::new();
    (&f).take(MAX_SIG_BYTES + 1).read_to_end(&mut sig).map_err(|e| format!("cannot read {path} ({e})"))?;
    Ok(sig)
}

fn body(
    path: &str,
    open: OpenFn<'_>,
) -> Result<(u64, impl FnOnce(&mut Vec<u8>) -> std::io::Result<()>), String> {
    use std::io::Read as _;
    let (f, md) = open(Path::new(path)).map_err(|e| format!("cannot read {path} ({e})"))?;
    let len = md.len();
    if len > MAX_MANIFEST_BYTES {
        return Err(format!("{path} is {len} bytes, over the {MAX_MANIFEST_BYTES}-byte cap"));
    }
    Ok((len, move |buf: &mut Vec<u8>| (&f).take(len + 1).read_to_end(buf).map(|_| ())))
}

#[allow(dead_code)]
pub(crate) fn load_in_place(path: Option<&str>, open: OpenFn<'_>) -> Result<Option<Verified>, String> {
    use hemostat_evcrypto::manifest::{read_and_parse, ReadRefused};
    let env = std::env::var(MANIFEST_ENV).ok();
    let Some(path) = path.or(env.as_deref()) else { return Ok(None) };
    let key = pinned_manifest_key()?;
    let sig = read_sig(&format!("{path}.sig"), open)?;
    let (len, fill) = body(path, open)?;
    match read_and_parse(&key, &sig, len, fill) {
        Ok(m) => Ok(Some(m)),
        Err(ReadRefused::Read(e)) => Err(format!("cannot read {path} ({e})")),
        Err(ReadRefused::Refused(Refused::Signature)) => Err(format!(
            "{path} is not signed by the pinned manifest key {} — refusing it",
            hex32(&key)
        )),
        Err(ReadRefused::Refused(Refused::NotUtf8)) => Err(format!("{path} is not UTF-8")),
        Err(ReadRefused::Refused(Refused::Malformed(e))) => Err(format!("{path}: {e}")),
    }
}

#[allow(dead_code)]
pub(crate) fn load_meta_in_place(
    path: &str,
    manifest: &Verified,
    open: OpenFn<'_>,
) -> Result<hemostat_evcrypto::manifest::meta::VerifiedMeta, String> {
    use hemostat_evcrypto::manifest::meta::{self, MetaRefused};
    let key = pinned_manifest_key()?;
    let sig = read_sig(&format!("{path}.sig"), open)?;
    let (len, fill) = body(path, open)?;
    meta::read_and_parse(&key, &sig, manifest, len, fill).map_err(|e| match e {
        MetaRefused::Signature => {
            format!("{path} is not a sidecar signed by the pinned manifest key {} — refusing it", hex32(&key))
        }
        MetaRefused::NotUtf8 => format!("{path} is not UTF-8"),
        MetaRefused::Malformed(e) => format!("{path}: {e}"),
        MetaRefused::Unbound(e) => format!("{path} is not this manifest's sidecar: {e}"),
        MetaRefused::Read(e) => format!("cannot read {path} ({e})"),
    })
}
