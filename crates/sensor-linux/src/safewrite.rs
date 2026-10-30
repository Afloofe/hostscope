use std::fs;
use std::io::{Error, ErrorKind, Write as _};
use std::os::fd::AsRawFd as _;
use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub struct Pinned {
    dir: fs::File,
    path: PathBuf,
}

impl Pinned {

    pub fn open(path: &Path) -> std::io::Result<Pinned> {
        let dir = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
            .open(path)
            .map_err(|e| match e.raw_os_error() {
                Some(libc::ELOOP | libc::ENOTDIR) => not_a_directory(path, &e),
                _ => e,
            })?;

        let held = dir.metadata()?;
        let via = fs::metadata(format!("/proc/self/fd/{}", dir.as_raw_fd())).map_err(|e| {
            Error::other(format!(
                "it could not be reached through /proc/self/fd ({e}), and nothing is written \
                 by its path instead"
            ))
        })?;
        if (via.dev(), via.ino()) != (held.dev(), held.ino()) {
            return Err(Error::other(
                "/proc/self/fd does not lead back to it, and nothing is written by its path instead",
            ));
        }
        Ok(Pinned { dir, path: path.to_path_buf() })
    }

    pub fn create(path: &Path, mode: u32) -> std::io::Result<Pinned> {
        let made = match fs::DirBuilder::new().mode(mode).create(path) {
            Ok(()) => true,
            Err(e) if e.kind() == ErrorKind::AlreadyExists => false,
            Err(e) if e.kind() == ErrorKind::NotFound => {
                fs::DirBuilder::new().recursive(true).mode(mode).create(path)?;
                true
            }
            Err(e) => return Err(e),
        };
        let pinned = Pinned::open(path)?;
        if made {
            pinned.set_mode(mode)?;
        }
        Ok(pinned)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn entry_path(&self, name: &str) -> std::io::Result<PathBuf> {
        if name.is_empty() || name == "." || name == ".." || name.contains(['/', '\0']) {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!("{name:?} is not one entry of a directory"),
            ));
        }
        Ok(PathBuf::from(format!("/proc/self/fd/{}/{name}", self.dir.as_raw_fd())))
    }

    pub fn require_root_only(&self) -> std::io::Result<()> {
        let md = self.dir.metadata()?;
        match not_root_only(md.uid(), md.mode()) {
            None => Ok(()),
            Some(why) => Err(Error::new(ErrorKind::PermissionDenied, why)),
        }
    }

    pub fn set_mode(&self, mode: u32) -> std::io::Result<()> {
        self.dir.set_permissions(fs::Permissions::from_mode(mode))
    }

    pub fn entry(&self, name: &str) -> std::io::Result<Option<fs::Metadata>> {
        match fs::symlink_metadata(self.entry_path(name)?) {
            Ok(md) => Ok(Some(md)),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    pub fn read_own(&self, name: &str, cap: u64) -> std::io::Result<Option<String>> {
        use std::io::Read as _;
        let Some(seen) = self.entry(name)? else {
            return Ok(None);
        };
        let judge = |md: &fs::Metadata| {
            own_file_refusal(md.file_type().is_symlink(), md.is_file(), md.nlink(), md.len(), cap)
        };
        if let Some(why) = judge(&seen) {
            return Err(Error::new(ErrorKind::InvalidInput, why));
        }
        let (f, md) = crate::saferead::open_regular(&self.entry_path(name)?, crate::saferead::NOT_REGULAR)?;

        if (md.dev(), md.ino()) != (seen.dev(), seen.ino()) {
            return Err(Error::new(ErrorKind::InvalidInput, "it was replaced while it was being read"));
        }
        if let Some(why) = judge(&md) {
            return Err(Error::new(ErrorKind::InvalidInput, why));
        }
        let mut buf = Vec::new();
        (&f).take(cap).read_to_end(&mut buf)?;
        Ok(Some(String::from_utf8_lossy(&buf).into_owned()))
    }

    pub fn replace(&self, name: &str, bytes: &[u8], mode: u32) -> std::io::Result<()> {
        let at = self.entry_path(name)?;
        let (tmp, mut f) = self.temp_beside(name, mode)?;
        let written = f
            .set_permissions(fs::Permissions::from_mode(mode))
            .and_then(|()| f.write_all(bytes))
            .and_then(|()| f.sync_all())
            .and_then(|()| fs::rename(&tmp, &at));
        if let Err(e) = written {
            let _ = fs::remove_file(&tmp);
            return Err(e);
        }

        let _ = self.dir.sync_all();
        Ok(())
    }

    pub fn remove(&self, name: &str) -> std::io::Result<()> {
        match fs::remove_file(self.entry_path(name)?) {
            Ok(()) => {
                let _ = self.dir.sync_all();
                Ok(())
            }
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
    }

    fn temp_beside(&self, name: &str, mode: u32) -> std::io::Result<(PathBuf, fs::File)> {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        for n in 0..16u32 {
            let tmp = self.entry_path(&format!(".{name}.{}.{stamp:x}.{n}.tmp", std::process::id()))?;
            match fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(mode)
                .custom_flags(libc::O_NOFOLLOW)
                .open(&tmp)
            {
                Ok(f) => return Ok((tmp, f)),
                Err(e) if e.kind() == ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(e),
            }
        }
        Err(Error::new(ErrorKind::AlreadyExists, format!("no free temporary name beside {name}")))
    }
}

pub fn not_root_only(uid: u32, mode: u32) -> Option<String> {
    if uid != 0 {
        return Some(format!("it belongs to uid {uid}, not to root, so that account decides what is in it"));
    }
    if mode & 0o022 != 0 {
        return Some(format!(
            "it is mode {:o}, so an account other than root can put a name in it",
            mode & 0o7777
        ));
    }
    None
}

pub fn own_file_refusal(is_link: bool, is_file: bool, nlink: u64, len: u64, cap: u64) -> Option<String> {
    if is_link {
        return Some("it is a link, and a link there is never followed".into());
    }
    if !is_file {
        return Some(
            "it is not a regular file — a named pipe, socket or device is never opened".into(),
        );
    }
    if nlink > 1 {
        return Some(format!(
            "it is one of {nlink} hard links to the same file, and what it holds belongs to the \
             other name as much as to this one"
        ));
    }
    if len > cap {
        return Some(format!("it is {len} bytes, over the {cap}-byte cap, which nothing this tool writes reaches"));
    }
    None
}

fn not_a_directory(path: &Path, e: &Error) -> Error {
    let what = match fs::symlink_metadata(path) {
        Ok(md) if md.file_type().is_symlink() => "it is a link, and a link there is never followed".to_string(),
        Ok(_) => "it is not a directory".to_string(),
        Err(_) => e.to_string(),
    };
    Error::new(ErrorKind::InvalidInput, what)
}
