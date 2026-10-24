use std::fs;
use std::io::Write as _;
use std::path::Path;

use hemostat_evfmt::StoreHeader;

use crate::enroll::Enrolled;
use crate::ingest::Layout;
use crate::{hex, shown};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Announced {

    pub genesis: [u8; 32],

    pub seal: Option<[u8; 32]>,

    pub agent_id: [u8; 16],

    pub at_ns: i64,

    pub from: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Recorded {

    Pinned(Announced),

    Repeat(Announced),

    Late(Announced),

    OtherKey {

        this: Announced,

        first: Announced,
    },

    Refused(String),
}

pub fn decode(bytes: &[u8]) -> Result<StoreHeader, String> {
    let (h, used) = StoreHeader::decode(bytes).map_err(|e| format!("not a store header: {e}"))?;
    if used != bytes.len() {
        return Err(format!("{} byte(s) after the store header", bytes.len() - used));
    }
    if h.encode() != bytes {
        return Err("the header is not in its one encoding".to_string());
    }
    Ok(h)
}

fn read_one(dir: &Path) -> Option<Announced> {
    let bytes = fs::read(dir.join(hemostat_evfmt::STORE_HEADER_FILE)).ok()?;
    let h = decode(&bytes).ok()?;
    let meta = fs::read_to_string(dir.join("meta")).ok()?;
    let get = |k: &str| meta.lines().find_map(|l| l.strip_prefix(k).and_then(|r| r.strip_prefix('='))).unwrap_or("");
    Some(Announced {
        genesis: h.genesis(),
        seal: hemostat_evcrypto::seal::decode_seal_pubkey(&h.variable_tail),
        agent_id: h.agent_id,
        at_ns: get("at_ns").parse().unwrap_or(0),
        from: get("from").to_string(),
    })
}

pub fn lookup(layout: &Layout, host: &[u8; 32], agent_id: &[u8; 16], genesis: &[u8; 32]) -> (Option<Announced>, Option<Announced>) {
    let dir = layout.announced().join(hex(host));
    let this = read_one(&dir.join(hex(genesis)));
    let mut other = None;
    if let Ok(rd) = fs::read_dir(&dir) {
        let mut all: Vec<Announced> = rd
            .flatten()
            .filter(|e| {
                let n = e.file_name().to_string_lossy().into_owned();
                n != hex(genesis) && !n.ends_with(".tmp")
            })
            .filter_map(|e| read_one(&e.path()))
            .filter(|a| &a.agent_id == agent_id)
            .collect();
        all.sort_by_key(|a| a.at_ns);
        other = all.into_iter().next();
    }
    (this, other)
}

pub fn record(layout: &Layout, engagement: &[u8; 16], header: &[u8], agent: &Enrolled, at_ns: i64) -> Result<Recorded, String> {
    let h = match decode(header) {
        Ok(h) => h,
        Err(why) => return Ok(Recorded::Refused(why)),
    };
    if h.host_id != agent.host {
        return Ok(Recorded::Refused(format!(
            "the agent enrolled as {} (host {}) announced a store of host {}",
            shown(&agent.label),
            hex(&agent.host),
            hex(&h.host_id)
        )));
    }
    if &h.engagement_id != engagement {
        return Ok(Recorded::Refused(format!("the store is from engagement {}", hex(&h.engagement_id))));
    }
    let seal = hemostat_evcrypto::seal::decode_seal_pubkey(&h.variable_tail);
    if seal.is_none() {
        return Ok(Recorded::Refused("the announced store carries no seal key".to_string()));
    }
    let a = Announced { genesis: h.genesis(), seal, agent_id: h.agent_id, at_ns, from: agent.label.clone() };
    let (same, other) = lookup(layout, &h.host_id, &h.agent_id, &a.genesis);
    if let Some(prev) = same {
        return Ok(Recorded::Repeat(prev));
    }
    if let Some(first) = other {
        return Ok(Recorded::OtherKey { this: a, first });
    }
    if fs::symlink_metadata(layout.hosts().join(hex(&h.host_id)).join(hex(&a.genesis))).is_ok() {
        return Ok(Recorded::Late(a));
    }
    let host_dir = layout.announced().join(hex(&h.host_id));
    crate::shared_dir(&host_dir).map_err(|e| format!("cannot create {}: {e}", host_dir.display()))?;
    let b = fs::DirBuilder::new();
    #[cfg(unix)]
    let b = {
        use std::os::unix::fs::DirBuilderExt as _;
        let mut b = b;
        b.mode(0o700);
        b
    };

    let tmp = host_dir.join(format!("{}.tmp", hex(&a.genesis)));
    let _ = fs::remove_dir_all(&tmp);
    b.create(&tmp).map_err(|e| format!("cannot create {}: {e}", tmp.display()))?;
    let write = |name: &str, bytes: &[u8]| -> Result<(), String> {
        let mut o = fs::OpenOptions::new();
        o.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            o.mode(0o600);
        }
        let mut f = o.open(tmp.join(name)).map_err(|e| format!("cannot create the pin: {e}"))?;
        f.write_all(bytes).and_then(|()| f.sync_all()).map_err(|e| format!("cannot write the pin: {e}"))
    };
    write(hemostat_evfmt::STORE_HEADER_FILE, header)?;
    write("meta", format!("at_ns={at_ns}\nfrom={}\n", agent.label).as_bytes())?;
    fs::rename(&tmp, host_dir.join(hex(&a.genesis))).map_err(|e| format!("cannot put the pin in place: {e}"))?;

    crate::share_finished(&host_dir.join(hex(&a.genesis)));
    if let Ok(d) = fs::File::open(&host_dir) {
        let _ = d.sync_all();
    }
    Ok(Recorded::Pinned(a))
}
