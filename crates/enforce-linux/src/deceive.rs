use std::path::{Path, PathBuf};

use crate::{ApplyOptions, Failure, Outcome, Plan, UndoKind, UndoRecord};

pub const MARKER: &str = "HEMOSTAT-CANARY-DO-NOT-USE";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {

    SshKey,

    CloudCredentials,

    DatabaseUrl,

    PasswordFile,
}

impl Kind {

    pub fn content(self) -> String {
        match self {
            Kind::SshKey => format!(
                "# {MARKER}\n\
                 # This is not a key. It is a tripwire planted during an incident response;\n\
                 # reading it raises an alert. It authenticates nothing, anywhere.\n\
                 -----BEGIN OPENSSH PRIVATE KEY-----\n\
                 {MARKER}THISISNOTAKEYTHISISNOTAKEYTHISISNOTAKEYTHISISNOTAKEY\n\
                 -----END OPENSSH PRIVATE KEY-----\n"
            ),
            Kind::CloudCredentials => format!(
                "# {MARKER}\n\
                 # Not real credentials. A tripwire planted during an incident response;\n\
                 # reading this file raises an alert. These identifiers refer to nothing.\n\
                 [default]\n\
                 aws_access_key_id = AKIA{MARKER}\n\
                 aws_secret_access_key = {MARKER}\n"
            ),
            Kind::DatabaseUrl => format!(
                "# {MARKER}\n\
                 # Not a real connection string. A tripwire planted during an incident\n\
                 # response; reading this file raises an alert. This host does not exist.\n\
                 DATABASE_URL=postgres://{MARKER}:{MARKER}@db.invalid:5432/none\n"
            ),
            Kind::PasswordFile => format!(
                "# {MARKER}\n\
                 # Not real passwords. A tripwire planted during an incident response;\n\
                 # reading this file raises an alert. None of these are used anywhere.\n\
                 admin:{MARKER}\n\
                 root:{MARKER}\n\
                 backup:{MARKER}\n"
            ),
        }
    }

    pub const fn bait(self) -> &'static str {
        match self {
            Kind::SshKey => "a private key is a way onto another host",
            Kind::CloudCredentials => "cloud credentials are a way off this host entirely",
            Kind::DatabaseUrl => "a connection string is a way to the data",
            Kind::PasswordFile => "a password list is a way to everything else",
        }
    }
}

pub fn is_our_token(content: &str) -> bool {
    content.contains(MARKER)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Token {

    pub path: PathBuf,

    pub kind: Kind,
}

pub fn catalogue(home_dirs: &[PathBuf]) -> Vec<Token> {
    let mut out = vec![
        Token { path: PathBuf::from("/root/.aws/credentials"), kind: Kind::CloudCredentials },
        Token { path: PathBuf::from("/root/.ssh/id_rsa_backup"), kind: Kind::SshKey },
        Token { path: PathBuf::from("/opt/backup/.env"), kind: Kind::DatabaseUrl },
        Token { path: PathBuf::from("/root/passwords.txt"), kind: Kind::PasswordFile },
    ];
    for home in home_dirs {
        out.push(Token { path: home.join(".ssh/id_rsa_old"), kind: Kind::SshKey });
    }
    out
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {

    Occupied {

        path: PathBuf,

        ours: bool,
    },

    NoParent {

        path: PathBuf,
    },
}

impl Refusal {

    pub fn message(&self) -> String {
        match self {
            Refusal::Occupied { path, ours: true } => format!(
                "{} is already one of ours from an earlier run — left alone rather than \
                 rewritten, so its timestamps still say when it was planted",
                path.display()
            ),
            Refusal::Occupied { path, ours: false } => format!(
                "{} already exists and is NOT ours. Nothing is written: a fake credential over \
                 a real file is destroying the host's data to catch somebody, and the paths \
                 most attractive to an intruder are the ones most likely to be real",
                path.display()
            ),
            Refusal::NoParent { path } => format!(
                "{} does not exist. Creating it would change the shape of the host — a \
                 directory that was not there before is itself a signal, and one the intruder \
                 can read as easily as the file inside it",
                path.parent().map_or_else(
                    || path.display().to_string(),
                    |p| p.display().to_string()
                )
            ),
        }
    }
}

pub fn check(token: &Token, exists: Option<&str>, parent_exists: bool) -> Result<(), Refusal> {
    if let Some(content) = exists {
        return Err(Refusal::Occupied {
            path: token.path.clone(),
            ours: is_our_token(content),
        });
    }
    if !parent_exists {
        return Err(Refusal::NoParent { path: token.path.clone() });
    }
    Ok(())
}

pub fn apply(token: &Token, opts: &ApplyOptions) -> Outcome {

    let existing = match std::fs::symlink_metadata(&token.path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => {
            return Outcome::Refused(crate::Refusal {
                action: format!("plant a canary at {}", token.path.display()),
                cause: crate::RefuseCause::InvalidTarget("unknown".into()),
                message: format!(
                    "could not tell whether {} is free ({e}); a canary is only planted where \
                     nothing is",
                    token.path.display()
                ),
                suggested_alternative: None,
            })
        }
        Ok(md) if md.is_file() => {
            Some(hemostat_sensor_linux::saferead::read_scan_target(&token.path).unwrap_or_default())
        }
        Ok(_) => Some(String::new()),
    };

    let parent_exists = token
        .path
        .parent()
        .is_some_and(|p| std::fs::symlink_metadata(p).is_ok_and(|m| m.is_dir()));

    if let Err(r) = check(token, existing.as_deref(), parent_exists) {
        return Outcome::Refused(crate::Refusal {
            action: format!("plant a canary at {}", token.path.display()),
            cause: crate::RefuseCause::InvalidTarget("occupied".into()),
            message: r.message(),
            suggested_alternative: None,
        });
    }

    if !opts.armed {
        return Outcome::Planned(Plan {
            summary: format!("plant a canary at {}", token.path.display()),
            detail: format!(
                "Write an inert {:?} there — {}. It authenticates nothing and carries `{MARKER}` \
                 so this tool's own sweeps do not report it and you can find every one you \
                 left. Planting is half a deception: watch it with `deceive --watch`, or the \
                 file is just a file.",
                token.kind,
                token.kind.bait()
            ),
            undo: format!("delete {}", token.path.display()),
            reversible: true,
            prefer_instead: None,
        });
    }

    if let Err(e) = create_canary(&token.path, token.kind.content().as_bytes()) {
        return Outcome::Failed(Failure {
            action: format!("plant a canary at {}", token.path.display()),
            reason: format!(
                "could not create {}: {e}. Nothing was written: the file is created only if \
                 nothing — not a file, a link or a pipe — is already there, in a directory \
                 that is not itself a link",
                token.path.display()
            ),
        });
    }

    Outcome::Applied(UndoRecord {
        did: format!(
            "planted an inert {:?} canary at {} — it authenticates nothing and carries \
             `{MARKER}`. It is NOT watched by this action: a canary nobody watches is a file",
            token.kind,
            token.path.display()
        ),
        undo: UndoKind::RemoveCanary { path: token.path.clone() },
        reversible: true,
    })
}

fn create_canary(path: &Path, content: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;
    use std::os::fd::{AsRawFd as _, FromRawFd as _};
    use std::os::unix::ffi::OsStrExt as _;
    use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};

    let invalid = |m: &str| std::io::Error::new(std::io::ErrorKind::InvalidInput, m.to_string());
    let parent = path.parent().ok_or_else(|| invalid("no parent directory"))?;
    let name = path.file_name().ok_or_else(|| invalid("no file name"))?;
    let cname = std::ffi::CString::new(name.as_bytes()).map_err(|_| invalid("NUL in file name"))?;

    let dir = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(parent)?;

    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            cname.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600 as libc::c_uint,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }

    let mut f = unsafe { std::fs::File::from_raw_fd(fd) };
    let written = f
        .set_permissions(std::fs::Permissions::from_mode(0o600))
        .and_then(|()| f.write_all(content))
        .and_then(|()| f.sync_all());
    if let Err(e) = written {
        drop(f);

        let _ = std::fs::remove_file(path);
        return Err(e);
    }
    Ok(())
}

pub fn undo_remove(path: &Path, opts: &ApplyOptions) -> Outcome {
    let refuse = |message: String| {
        Outcome::Refused(crate::Refusal {
            action: format!("remove the canary at {}", path.display()),
            cause: crate::RefuseCause::InvalidTarget("not ours".into()),
            message,
            suggested_alternative: None,
        })
    };

    let Some(content) = hemostat_sensor_linux::saferead::read_scan_target(path) else {
        return refuse(format!(
            "{} could not be read, so whether it is one of ours cannot be established. Nothing \
             was deleted",
            path.display()
        ));
    };
    if !is_our_token(&content) {
        return refuse(format!(
            "{} does not carry `{MARKER}`, so it is NOT a canary this tool planted. Nothing was \
             deleted — a journal line is a plain text file on the host being cleaned, and \
             deleting whatever it names would be an arbitrary remove with an undo verb in front \
             of it",
            path.display()
        ));
    }

    if !opts.armed {
        return Outcome::Planned(Plan {
            summary: format!("remove the canary at {}", path.display()),
            detail: format!("Delete {}, which carries the marker.", path.display()),
            undo: "plant it again if needed".into(),
            reversible: true,
            prefer_instead: None,
        });
    }
    match std::fs::remove_file(path) {
        Ok(()) => Outcome::Applied(UndoRecord {
            did: format!("removed the canary at {}", path.display()),
            undo: UndoKind::Irreversible { note: "the canary is gone; plant again to restore".into() },
            reversible: false,
        }),
        Err(e) => Outcome::Failed(Failure {
            action: format!("remove the canary at {}", path.display()),
            reason: format!("could not delete {}: {e}", path.display()),
        }),
    }
}

pub fn find_planted(home_dirs: &[PathBuf]) -> Vec<PathBuf> {
    catalogue(home_dirs)
        .into_iter()
        .filter(|t| {
            hemostat_sensor_linux::saferead::read_scan_target(&t.path).is_some_and(|c| is_our_token(&c))
        })
        .map(|t| t.path)
        .collect()
}
