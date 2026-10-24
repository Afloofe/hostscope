#![forbid(unsafe_code)]
#![allow(clippy::expect_used, clippy::unwrap_used, missing_docs)]

use std::io::Read as _;
use std::process::ExitCode;

use hemostat_evcrypto::seal::{decode_header_keys, encode_header_keys, HeaderKeys, SealKey};
use hemostat_evfmt::{load_stream, read_store_header, Parcel, RunContext, SealSigner, StoreWriter, StreamCrypto, StreamId};

fn main() -> ExitCode {
    let a: Vec<String> = std::env::args().skip(1).collect();
    match a.iter().map(String::as_str).collect::<Vec<_>>().as_slice() {
        ["pack", store, out] => {
            let (p, skipped) = Parcel::pack_dir(store).expect("pack");
            std::fs::write(out, p.encode()).expect("write");
            println!("packed {store} -> {out} ({} files, unchecked; skipped {skipped:?})", p.files.len());
            ExitCode::SUCCESS
        }
        ["reseal", store, out] => {
            let old = read_store_header(store).expect("header");
            let keys = decode_header_keys(&old.variable_tail);
            let mut seed = [0u8; 32];
            std::fs::File::open("/dev/urandom").and_then(|mut f| f.read_exact(&mut seed)).expect("entropy");
            let new_pub = SealKey::from_seed(seed).public_bytes();
            let mut header = old.clone();
            header.variable_tail =
                encode_header_keys(&HeaderKeys { seal_pub: Some(new_pub), store_pub: keys.store_pub, store_wrap: keys.store_wrap });
            let w = StoreWriter::create(out, header).expect("create");
            for stream in [StreamId::Evidence, StreamId::Custody, StreamId::Telemetry, StreamId::Journal] {
                let segs = load_stream(store, stream).expect("load");
                let Some(first) = segs.first() else { continue };
                let k = SealKey::from_seed(seed);
                let signer: SealSigner = Box::new(move |b| k.sign_footer(b));
                let h = &first.header;
                let mut s = w
                    .open_stream_with(stream, RunContext::new(h.instance_id, h.run_id, h.boot_id, h.suite_id), StreamCrypto {
                        signer: Some(signer),
                        cipher: None,
                    })
                    .expect("stream");
                for r in segs.iter().flat_map(|s| s.records.iter()) {
                    s.append(r.header.rec_type, r.header.flags & !hemostat_evfmt::header::flags::ENCRYPTED, &r.stored).expect("append");
                }
                s.close().expect("seal");
            }
            println!("re-sealed {store} -> {out}");
            println!("  old seal key {}", hex(&keys.seal_pub.unwrap_or_default()));
            println!("  new seal key {}", hex(&new_pub));
            println!("  agent id kept {}", hex(&old.agent_id));
            ExitCode::SUCCESS
        }
        _ => {
            eprintln!("usage: f1_tamper pack <STORE> <OUT.hpcl> | reseal <STORE> <NEW-STORE>");
            ExitCode::from(2)
        }
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
