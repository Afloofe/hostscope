use hemostat_evfmt::{RecType, RunContext, StoreHeader, StoreWriter, StreamCrypto, StreamId};

use crate::render::hex32;

pub(crate) struct Ids {
    pub(crate) engagement: [u8; 16],
    pub(crate) host: [u8; 32],
    pub(crate) agent: [u8; 16],
    pub(crate) instance: [u8; 16],
    pub(crate) run: u32,
    pub(crate) boot: [u8; 16],
}

#[cfg_attr(not(target_os = "freebsd"), allow(dead_code))]
pub(crate) struct Sealed {
    pub(crate) seal_pub: [u8; 32],
    pub(crate) genesis: [u8; 32],
}

pub(crate) fn seal<R: AsRef<[u8]>>(
    dir: &str,
    seed: [u8; 32],
    records: impl IntoIterator<Item = R>,
    id: &Ids,
) -> Result<Sealed, String> {
    seal_typed(dir, seed, records.into_iter().map(|r| (RecType::CUSTODY, r)), id, true)
}

pub(crate) fn announce(header: &StoreHeader) {
    #[cfg(all(any(target_os = "linux", target_os = "windows"), feature = "mod-remote"))]
    if let Some(line) = crate::push::announce_opened(header) {
        eprintln!("{line}");
    }
    #[cfg(not(all(any(target_os = "linux", target_os = "windows"), feature = "mod-remote")))]
    let _ = header;
}

pub(crate) fn seal_typed<R: AsRef<[u8]>>(
    dir: &str,
    mut seed: [u8; 32],
    records: impl IntoIterator<Item = (RecType, R)>,
    id: &Ids,
    announce_it: bool,
) -> Result<Sealed, String> {
    use hemostat_evcrypto::seal::{encode_header_keys, HeaderKeys, SealKey};
    let key = SealKey::from_seed(seed);
    hemostat_evcrypto::secret::wipe_bytes(&mut seed);
    let seal_pub = key.public_bytes();
    let now_wall = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_nanos()).unwrap_or(i64::MAX))
        .unwrap_or(0);
    let header = StoreHeader {
        format_ver: 1,
        suite_id: 1,
        engagement_id: id.engagement,
        host_id: id.host,
        agent_id: id.agent,
        created_wall_ns: now_wall,

        created_mono_ns: 0,
        variable_tail: encode_header_keys(&HeaderKeys { seal_pub: Some(seal_pub), store_pub: None, store_wrap: None }),
    };
    let writer = StoreWriter::create(dir, header).map_err(|e| e.to_string())?;
    if announce_it {
        announce(writer.header());
    }
    let genesis = writer.genesis();
    let signer: hemostat_evfmt::SealSigner = Box::new(move |b| key.sign_footer(b));
    let mut c = writer
        .open_stream_with(
            StreamId::Custody,
            RunContext::new(id.instance, id.run, id.boot, 1),
            StreamCrypto { signer: Some(signer), cipher: None },
        )
        .map_err(|e| e.to_string())?;
    for (t, r) in records {
        c.append(t, 0, r.as_ref()).map_err(|e| e.to_string())?;
    }
    c.close().map_err(|e| e.to_string())?;
    Ok(Sealed { seal_pub, genesis })
}

pub(crate) struct Opened {
    pub(crate) records: Vec<Vec<u8>>,
    #[cfg_attr(not(any(feature = "mod-collector", target_os = "freebsd")), allow(dead_code))]
    pub(crate) seal_pub: [u8; 32],

    #[cfg_attr(not(all(target_os = "linux", feature = "mod-collector")), allow(dead_code))]
    pub(crate) host_id: [u8; 32],
}

pub(crate) fn open(dir: &str, pin: Option<[u8; 32]>) -> Result<Opened, String> {
    use hemostat_evfmt::{load_verified, read_store_header};
    let header = read_store_header(dir).map_err(|e| format!("{dir}: {e}"))?;
    let seal_pub = hemostat_evcrypto::seal::decode_seal_pubkey(&header.variable_tail)
        .ok_or("the store carries no seal key")?;
    if let Some(p) = pin {
        if p != seal_pub {
            return Err(format!(
                "the store is sealed with {} and the pin is {} — it was re-written, or it is not the \
                 store you took",
                hex32(&seal_pub),
                hex32(&p)
            ));
        }
    }
    let check = move |s: &[u8], sig: &[u8]| hemostat_evcrypto::seal::verify_footer(&seal_pub, s, sig);
    let verified = load_verified(dir, &header, StreamId::Custody, Some(&check))
        .map_err(|e| format!("the store does not verify: {e}"))?;

    if !(verified.report.sealed && verified.report.signed) {
        return Err(format!(
            "the store is not sealed — it was cut short or its seal was removed, and {} record(s) in \
             it are vouched for by no key",
            verified.report.unsealed_records
        ));
    }
    let records = verified.segments.into_iter().flat_map(|s| s.records.into_iter().map(|r| r.stored)).collect();
    Ok(Opened { records, seal_pub, host_id: header.host_id })
}
