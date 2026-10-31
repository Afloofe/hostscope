use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Known {

    pub name: &'static str,

    pub install_to: &'static str,

    pub gives: &'static str,

    pub costs: &'static str,
}

pub const CATALOGUE: &[Known] = &[
    Known {
        name: "sysmon",
        install_to: "/opt/sysmon/sysmon",
        gives: "process, network and file telemetry with parent lineage, which the procfs floor \
                samples and cannot stream. It is the single biggest gap this agent has on a \
                host with no eBPF",
        costs: "a resident service and a measurable event volume. It also writes its own \
                configuration, which an intruder with root can replace — `sysmon` the sweep \
                checks for exactly that",
    },
    Known {
        name: "auditd",
        install_to: "/sbin/auditd",
        gives: "a collector for the kernel audit records this host is already generating. \
                Without one the kernel produces them and drops them on the floor, which is what \
                the `audit` sweep reports as pid=0",
        costs: "disk, and a rule set somebody has to write. An auditd with no rules collects \
                almost nothing and looks like coverage",
    },
];

pub fn known(name: &str) -> Option<&'static Known> {
    CATALOGUE.iter().find(|k| k.name.eq_ignore_ascii_case(name))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Supplied {

    pub path: PathBuf,

    pub declared_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {

    Missing(PathBuf),

    Unreadable {

        path: PathBuf,

        why: String,
    },

    DigestMismatch {

        declared: String,

        found: String,
    },

    BadDigest(String),

    Occupied(PathBuf),

    Unknown(String),
}

impl Refusal {

    pub fn message(&self) -> String {
        match self {
            Refusal::Missing(p) => format!("{} is not there. Nothing was installed", p.display()),
            Refusal::Unreadable { path, why } => {
                format!("{} could not be read ({why}). Nothing was installed", path.display())
            }
            Refusal::DigestMismatch { declared, found } => format!(
                "the file does NOT match the digest you declared.\n  \
                 you said:  {declared}\n  \
                 it is:     {found}\n  \
                 Nothing was installed. On a host somebody else has root on, this is the \
                 outcome the check exists for — the bytes at that path are not the bytes you \
                 brought"
            ),
            Refusal::BadDigest(d) => format!(
                "`{d}` is not a SHA-256 (64 hex characters). The digest is not optional: \
                 without one this would install whatever is at a path on a host somebody else \
                 controls, as root, at your request"
            ),
            Refusal::Occupied(p) => format!(
                "{} already exists. Nothing was overwritten — if that is an older copy of the \
                 sidecar, move it aside deliberately, and if it is not, you have just learned \
                 something",
                p.display()
            ),
            Refusal::Unknown(n) => format!(
                "`{n}` is not a sidecar this knows where to put. It takes: {}",
                CATALOGUE.iter().map(|k| k.name).collect::<Vec<_>>().join(", ")
            ),
        }
    }
}

pub fn is_sha256(s: &str) -> bool {
    s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit())
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest as _, Sha256};
    let mut h = Sha256::new();
    h.update(bytes);
    format!("{:x}", h.finalize())
}

pub fn check(
    name: &str,
    supplied: &Supplied,
    bytes: Option<&[u8]>,
    destination_exists: bool,
) -> Result<&'static Known, Refusal> {
    let Some(k) = known(name) else {
        return Err(Refusal::Unknown(name.to_string()));
    };
    if !is_sha256(&supplied.declared_sha256) {
        return Err(Refusal::BadDigest(supplied.declared_sha256.clone()));
    }
    let Some(bytes) = bytes else {
        return Err(Refusal::Missing(supplied.path.clone()));
    };
    let found = sha256_hex(bytes);
    if !found.eq_ignore_ascii_case(supplied.declared_sha256.trim()) {
        return Err(Refusal::DigestMismatch {
            declared: supplied.declared_sha256.clone(),
            found,
        });
    }
    if destination_exists {
        return Err(Refusal::Occupied(PathBuf::from(k.install_to)));
    }
    Ok(k)
}

pub fn apply(
    name: &str,
    supplied: &Supplied,
    opts: &crate::ApplyOptions,
) -> crate::Outcome {

    const MAX_SIDECAR_BYTES: u64 = 256 * 1024 * 1024;
    let bytes = hemostat_sensor_linux::saferead::read_whole_file(&supplied.path, MAX_SIDECAR_BYTES);
    let known_or = check(
        name,
        supplied,
        bytes.as_deref(),
        known(name).is_some_and(|k| Path::new(k.install_to).exists()),
    );
    let k = match known_or {
        Ok(k) => k,
        Err(r) => {
            return crate::Outcome::Refused(crate::Refusal {
                action: format!("install the {name} sidecar"),
                cause: crate::RefuseCause::InvalidTarget("sidecar".into()),
                message: r.message(),
                suggested_alternative: None,
            })
        }
    };

    let Some(bytes) = bytes else {
        return crate::Outcome::Failed(crate::Failure {
            action: format!("install the {name} sidecar"),
            reason: "the file vanished between the check and the copy".into(),
        });
    };

    if !opts.armed {
        return crate::Outcome::Planned(crate::Plan {
            summary: format!("install the {} sidecar at {}", k.name, k.install_to),
            detail: format!(
                "Copy {} ({} bytes) to {}, verified against the digest you declared.\n\n  \
                 What it gives: {}\n  What it costs: {}\n\n  \
                 HEMOSTAT fetches nothing — these are the bytes you brought, and the digest is \
                 what makes where they currently sit irrelevant.",
                supplied.path.display(),
                bytes.len(),
                k.install_to,
                k.gives,
                k.costs
            ),
            undo: format!("delete {}", k.install_to),
            reversible: true,
            prefer_instead: None,
        });
    }
    install_at(name, k, supplied, &bytes, Path::new(k.install_to), &opts.vault_dir)
}

fn install_at(
    name: &str,
    k: &Known,
    supplied: &Supplied,
    bytes: &[u8],
    dest: &Path,
    vault_dir: &Path,
) -> crate::Outcome {
    let kept = match crate::strip::snapshot(dest, bytes, vault_dir) {
        Ok(v) => v,
        Err(why) => {
            return crate::Outcome::Failed(crate::Failure {
                action: format!("install the {name} sidecar"),
                reason: format!("{why}, so there would be no undo. Nothing was installed"),
            })
        }
    };

    let unkeep = || {
        let _ = std::fs::remove_file(&kept);
    };
    if let Some(parent) = dest.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            unkeep();
            return crate::Outcome::Failed(crate::Failure {
                action: format!("install the {name} sidecar"),
                reason: format!("could not create {}: {e}", parent.display()),
            });
        }
    }
    if let Err(e) = std::fs::write(dest, bytes) {
        unkeep();
        return crate::Outcome::Failed(crate::Failure {
            action: format!("install the {name} sidecar"),
            reason: format!("could not write {}: {e}", dest.display()),
        });
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if let Err(e) = std::fs::set_permissions(dest, std::fs::Permissions::from_mode(0o755)) {
            unkeep();
            return crate::Outcome::Failed(crate::Failure {
                action: format!("install the {name} sidecar"),
                reason: format!(
                    "written to {}, but it could not be made executable ({e}), so it is not \
                     installed in any sense that lets you start it. Remove it or fix the mode \
                     by hand",
                    dest.display()
                ),
            });
        }
    }

    crate::Outcome::Applied(crate::UndoRecord {
        did: format!(
            "installed the {} sidecar at {} ({} bytes, sha256 {}, matching the digest you \
             declared). It is NOT started: this puts the tool on the host and leaves running it \
             to you, because a telemetry service that appears without anyone deciding to start \
             it is a change to the host nobody chose",
            k.name,
            dest.display(),
            bytes.len(),
            supplied.declared_sha256.to_lowercase()
        ),
        undo: crate::UndoKind::RemoveCreatedFile { vault: kept, original: dest.to_path_buf() },
        reversible: true,
    })
}
