use hemostat_sensor_linux::rootkit::{Finding, Severity};
use hemostat_sensor_linux::vendor::{self, Manifest, Verified};
use hemostat_sensor_linux::{TriageFinding, TriageSeverity};

use crate::identity::parse_hex32;
use crate::render::{h, hex32, jesc, rootkit_row};
use crate::{EXIT_FAILED, EXIT_OK, EXIT_PARTIAL, EXIT_USAGE};

pub(crate) use crate::vendor_manifest::MANIFEST_ENV;
use crate::vendor_manifest::MAX_MANIFEST_BYTES;

fn read_capped(path: &str, max: u64) -> Result<Vec<u8>, String> {
    hemostat_sensor_linux::saferead::read_whole_file(std::path::Path::new(path), max)
        .ok_or_else(|| format!("cannot read {path} (missing, not a regular file, or over {max} bytes)"))
}

pub(crate) fn load_manifest(path: Option<&str>) -> Result<Option<Verified>, String> {
    crate::vendor_manifest::load_with(path, hemostat_sensor_linux::saferead::read_whole_file)
}

pub(crate) struct Reference {

    manifest: Option<Verified>,

    refused: Option<String>,
}

impl Reference {

    pub(crate) fn manifest(&self) -> Option<&Manifest> {
        self.manifest.as_deref()
    }

    pub(crate) fn refused(&self) -> Option<&str> {
        self.refused.as_deref()
    }

    pub(crate) fn finding(&self) -> Option<Finding> {
        self.refused().map(refused_finding)
    }

    pub(crate) fn triage_finding(&self, source: &str) -> Option<TriageFinding> {
        self.refused().map(|why| {
            let f = refused_finding(why);
            TriageFinding::flag(TriageSeverity::Critical, source, f.subject, f.what, f.why)
        })
    }

    pub(crate) fn exit(&self, code: u8) -> u8 {
        if self.refused.is_some() && code == EXIT_OK {
            EXIT_PARTIAL
        } else {
            code
        }
    }

    pub(crate) fn coverage(&self, r: &hemostat_sensor_linux::inventory::Report) -> crate::coverage::Covered {
        use crate::coverage::Covered;
        match (crate::coverage::from_flag(r.available, &r.reason), self.refused()) {
            (Covered::Fully, Some(why)) => Covered::InPart(format!(
                "the vendor manifest that was named was refused ({why}), so package integrity rested \
                 on this host's own database"
            )),
            (c, _) => c,
        }
    }
}

pub(crate) fn reference() -> Reference {
    reference_from(load_manifest(None))
}

fn reference_from(loaded: Result<Option<Verified>, String>) -> Reference {
    match loaded {
        Ok(manifest) => Reference { manifest, refused: None },
        Err(why) => Reference { manifest: None, refused: Some(why) },
    }
}

pub(crate) fn inventory() -> (hemostat_sensor_linux::inventory::Report, Reference) {
    let reference = reference();
    let mut r = hemostat_sensor_linux::inventory::report_with(reference.manifest());
    if let Some(f) = reference.finding() {
        r.findings.insert(0, f);
    }
    (r, reference)
}

pub(crate) fn refused_finding(why: &str) -> Finding {
    Finding {
        severity: Severity::Critical,
        subject: format!("vendor manifest refused (${MANIFEST_ENV})"),
        what: format!(
            "the vendor manifest that was named was refused: {why}. Package integrity rests on \
             this host's own package database instead"
        ),
        why: "a manifest is named because the host's own database cannot be trusted: a root that \
              trojans a package can rewrite the digests recorded for it, and one that breaks the \
              manifest's signature is hiding something from the check that would have caught it. \
              No package-integrity result here is clean until the manifest verifies"
            .to_string(),
    }
}

pub(crate) fn print_vendor(args: &[String], json: bool) -> u8 {
    let path = args.iter().position(|a| a == "--manifest").and_then(|i| args.get(i + 1));
    let m = match load_manifest(path.map(String::as_str)) {
        Ok(Some(m)) => m,
        Ok(None) => {
            eprintln!(
                "hemostat vendor: no manifest. Pass --manifest PATH (with PATH.sig beside it) or \
                 set ${MANIFEST_ENV}. Build one off-host with vm/manifest/build-manifest.sh and \
                 sign it with `hemostat manifest-sign`"
            );
            return EXIT_USAGE;
        }
        Err(e) => {
            eprintln!("hemostat vendor: {}", h(&e));
            return EXIT_FAILED;
        }
    };
    let r = vendor::sweep(&m);
    if json {
        let rows: Vec<String> = r.findings.iter().map(rootkit_row).collect();
        jprintln!(
            "{{\"release\":\"{}\",\"paths\":{},\"checked\":{},\"vendor\":{},\"absent\":{},\
             \"unreadable\":{},\"unverified_versions\":{},\"complete\":{},\"findings\":[{}]}}",
            jesc(&m.release),
            m.paths(),
            r.checked,
            r.vendor,
            r.absent,
            r.unreadable.len(),
            r.uncovered,
            r.complete(),
            rows.join(",")
        );
    } else {
        println!("vendor — files against the {} manifest", h(&m.release));
        if let Some(s) = &m.source {
            println!("  built from: {}", h(s));
        }
        println!(
            "  {} path(s) covered · {} on this host and judged · {} the vendor's · {} not installed · {} unreadable\n  \
             {} on a package version the manifest does not cover (unverified, not clean)\n",
            m.paths(),
            r.checked,
            r.vendor,
            r.absent,
            r.unreadable.len(),
            r.uncovered
        );
        for f in &r.findings {
            println!("  [{}] {}", f.severity.tag(), h(&f.subject));
            println!("        {}", h(&f.what));
            println!("        why: {}", h(&f.why));
        }
        if r.findings.is_empty() {
            println!("  every covered file on this host is one the vendor shipped.");
        }
    }
    if r.complete() {
        EXIT_OK
    } else {
        EXIT_PARTIAL
    }
}

fn manifest_seed() -> Result<[u8; 32], String> {
    if let Ok(path) = std::env::var("HEMOSTAT_MANIFEST_KEY_FILE") {
        if !path.trim().is_empty() {
            let bytes = read_capped(&path, 4096)?;
            let text = String::from_utf8(bytes).map_err(|_| format!("{path} does not hold a hex key"))?;
            return parse_hex32(text.trim()).ok_or_else(|| format!("{path} does not hold 64 hex characters"));
        }
    }
    std::env::var("HEMOSTAT_MANIFEST_KEY")
        .ok()
        .as_deref()
        .map(str::trim)
        .and_then(parse_hex32)
        .ok_or_else(|| {
            "set $HEMOSTAT_MANIFEST_KEY_FILE to a file holding the manifest signing seed (64 \
             hex), or $HEMOSTAT_MANIFEST_KEY to the seed. It stays on the signing host; only \
             the manifest and its .sig go anywhere. Make one with `manifest-sign --new-key PATH`"
                .to_string()
        })
}

fn new_manifest_key(path: &str) -> u8 {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let mut seed = match crate::identity::rand32() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("hemostat manifest-sign: no entropy for a key: {e}");
            return EXIT_FAILED;
        }
    };
    let public = hemostat_evcrypto::manifest::ManifestKey::from_seed(seed).public_bytes();
    let hex: String = seed.iter().map(|b| format!("{b:02x}")).collect();
    hemostat_evcrypto::secret::wipe_bytes(&mut seed);
    let written = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .and_then(|mut f| f.write_all(format!("{hex}\n").as_bytes()).and_then(|()| f.sync_all()));
    let mut hex = hex.into_bytes();
    hemostat_evcrypto::secret::wipe_bytes(&mut hex);
    match written {
        Ok(()) => {
            println!("new manifest signing key at {} (0600)", h(path));
            println!("  pin this on the agent: HEMOSTAT_MANIFEST_PUBKEY={}", hex32(&public));
            EXIT_OK
        }
        Err(e) => {
            eprintln!(
                "hemostat manifest-sign: cannot create {} ({e}) — an existing key is never \
                 overwritten; every agent that pinned it would stop trusting new manifests",
                h(path)
            );
            EXIT_FAILED
        }
    }
}

pub(crate) fn manifest_sign(args: &[String]) -> u8 {
    if let Some(path) = args.iter().position(|a| a == "--new-key").and_then(|i| args.get(i + 1)) {
        return new_manifest_key(path);
    }
    let seed = match manifest_seed() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("hemostat manifest-sign: {e}");
            return EXIT_USAGE;
        }
    };
    let Some(path) = args.iter().position(|a| a == "--in").and_then(|i| args.get(i + 1)) else {
        eprintln!("hemostat manifest-sign: --in <MANIFEST> names the file to sign");
        return EXIT_USAGE;
    };
    let body = match read_capped(path, MAX_MANIFEST_BYTES) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("hemostat manifest-sign: {}", h(&e));
            return EXIT_FAILED;
        }
    };
    let key = hemostat_evcrypto::manifest::ManifestKey::from_seed(seed);
    if body.starts_with(hemostat_evcrypto::manifest::meta::META_HEADER.as_bytes()) {
        return sign_meta(args, path, &body, &key);
    }

    let parsed = std::str::from_utf8(&body).map_err(|_| "not UTF-8".to_string()).and_then(Manifest::parse);
    let m = match parsed {
        Ok(m) => m,
        Err(e) => {
            eprintln!("hemostat manifest-sign: {} is not a valid manifest: {}", h(path), h(&e));
            return EXIT_FAILED;
        }
    };
    let sig_path = format!("{path}.sig");
    if let Err(e) = std::fs::write(&sig_path, key.sign(&body)) {
        eprintln!("hemostat manifest-sign: cannot write {}: {e}", h(&sig_path));
        return EXIT_FAILED;
    }
    println!("signed {} ({}, {} paths) → {}", h(path), h(&m.release), m.paths(), h(&sig_path));
    println!("  pin this on the agent: HEMOSTAT_MANIFEST_PUBKEY={}", hex32(&key.public_bytes()));
    EXIT_OK
}

fn sign_meta(args: &[String], path: &str, body: &[u8], key: &hemostat_evcrypto::manifest::ManifestKey) -> u8 {
    use hemostat_evcrypto::manifest::meta;
    let Some(mpath) = args.iter().position(|a| a == "--manifest").and_then(|i| args.get(i + 1)) else {
        eprintln!(
            "hemostat manifest-sign: {} is a meta sidecar; --manifest <MANIFEST> names the manifest \
             it was built beside, which it must be bound to",
            h(path)
        );
        return EXIT_USAGE;
    };
    let parsed = std::str::from_utf8(body).map_err(|_| "not UTF-8".to_string()).and_then(meta::Meta::parse);
    let m = match parsed {
        Ok(m) => m,
        Err(e) => {
            eprintln!("hemostat manifest-sign: {} is not a valid sidecar: {}", h(path), h(&e));
            return EXIT_FAILED;
        }
    };
    let mbody = match read_capped(mpath, MAX_MANIFEST_BYTES) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("hemostat manifest-sign: {}", h(&e));
            return EXIT_FAILED;
        }
    };
    let manifest = std::str::from_utf8(&mbody).map_err(|_| "not UTF-8".to_string()).and_then(Manifest::parse);
    let manifest = match manifest {
        Ok(x) => x,
        Err(e) => {
            eprintln!("hemostat manifest-sign: {} is not a valid manifest: {}", h(mpath), h(&e));
            return EXIT_FAILED;
        }
    };
    let digest: [u8; 32] = {
        use sha2::Digest as _;
        sha2::Sha256::digest(&mbody).into()
    };
    if let Err(e) = meta::bound(&m, &manifest.release, &digest).and_then(|()| meta::covers_exactly(&m, &manifest)) {
        eprintln!("hemostat manifest-sign: refusing {}: {}", h(path), h(&e));
        return EXIT_FAILED;
    }
    let sig_path = format!("{path}.sig");
    if let Err(e) = std::fs::write(&sig_path, key.sign_meta(body)) {
        eprintln!("hemostat manifest-sign: cannot write {}: {e}", h(&sig_path));
        return EXIT_FAILED;
    }
    println!(
        "signed {} (meta sidecar, {}, {} paths, bound to {}) → {}",
        h(path),
        h(&m.release),
        m.paths(),
        h(mpath),
        h(&sig_path)
    );
    println!("  pin this on the agent: HEMOSTAT_MANIFEST_PUBKEY={}", hex32(&key.public_bytes()));
    EXIT_OK
}
