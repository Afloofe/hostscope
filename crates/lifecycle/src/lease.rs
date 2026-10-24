#[derive(Debug)]
pub struct Lease {
    #[cfg(target_os = "linux")]
    _sock: std::os::unix::net::UnixListener,
}

#[must_use]
pub fn lease_name(digest: &str, argv: &[String]) -> String {

    let mut identity = digest.as_bytes().to_vec();
    for a in argv {
        identity.push(0);
        identity.extend_from_slice(a.as_bytes());
    }
    let h = crate::image::digest(&identity);
    format!("hemostat/sentinel/{}", h.get(..32).unwrap_or(&h))
}

#[cfg(target_os = "linux")]
impl Lease {

    pub fn try_acquire(digest: &str, argv: &[String]) -> Result<Option<Lease>, String> {
        use std::os::linux::net::SocketAddrExt as _;
        use std::os::unix::net::{SocketAddr, UnixListener};

        let name = lease_name(digest, argv);
        let addr = SocketAddr::from_abstract_name(name.as_bytes())
            .map_err(|e| format!("sentinel lease: cannot form the abstract name: {e}"))?;
        match UnixListener::bind_addr(&addr) {
            Ok(sock) => Ok(Some(Lease { _sock: sock })),

            Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => Ok(None),
            Err(e) => Err(format!("sentinel lease: bind failed: {e}")),
        }
    }
}
