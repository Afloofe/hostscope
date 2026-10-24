use crate::identity::recovery_key;
#[cfg(target_os = "linux")]
use crate::identity::{gather_identity, parse_hex32, rand32};
use crate::{EXIT_FAILED, EXIT_OK, EXIT_PARTIAL, EXIT_USAGE};
#[cfg(target_os = "linux")]
use crate::remedy::require_built;
#[cfg(target_os = "linux")]
use crate::{EXIT_NOT_BUILT, MANIFEST};
use crate::render::{h, hex16, hex32, jesc};

pub(crate) fn pinned_seal_pubkey() -> Result<Option<[u8; 32]>, String> {
    crate::identity::pinned_key("HEMOSTAT_SEAL_PUBKEY")
}

pub(crate) fn check_pinned_seal(pinned: Option<[u8; 32]>, embedded: Option<[u8; 32]>) -> Result<(), String> {
    match (pinned, embedded) {
        (None, _) => Ok(()),
        (Some(_), None) => Err(
            "a seal key was pinned via $HEMOSTAT_SEAL_PUBKEY, but this store carries no seal \
             signature — it is unsigned, or its seal was stripped (a downgrade)."
                .to_string(),
        ),
        (Some(want), Some(have)) if want != have => Err(format!(
            "the store is sealed under key {}, which does not match the pinned key {} — this is \
             not the store that was sealed, or it was re-sealed under a different key.",
            hex32(&have),
            hex32(&want)
        )),
        (Some(_), Some(_)) => Ok(()),
    }
}

pub(crate) fn verify_store(positional: &[&str], json: bool) -> u8 {
    use hemostat_evfmt::{load_verified, read_store_header, SealVerify, StreamId};

    let Some(dir) = positional.get(1) else {
        eprintln!("usage: hemostat verify <store-dir>");
        return EXIT_USAGE;
    };

    let header = match read_store_header(dir) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("hemostat verify: {}", h(&e.to_string()));
            return EXIT_FAILED;
        }
    };

    let seal_pub = hemostat_evcrypto::seal::decode_seal_pubkey(&header.variable_tail);

    let keys = hemostat_evcrypto::seal::decode_header_keys(&header.variable_tail);
    let snapshot_shaped = keys.seal_pub.is_some() && keys.store_pub.is_none() && keys.store_wrap.is_none();

    let pinned = match pinned_seal_pubkey() {
        Ok(p) => p,
        Err(msg) => {
            eprintln!("hemostat verify: refusing — {msg}");
            return EXIT_FAILED;
        }
    };
    if let Err(msg) = check_pinned_seal(pinned, seal_pub) {
        eprintln!("hemostat verify: refusing — {msg}");
        return EXIT_FAILED;
    }

    let verify_seal =
        seal_pub.map(|pk| move |signable: &[u8], sig: &[u8]| hemostat_evcrypto::seal::verify_footer(&pk, signable, sig));

    let streams = [
        ("evidence", StreamId::Evidence),
        ("custody", StreamId::Custody),
        ("telemetry", StreamId::Telemetry),
        ("journal", StreamId::Journal),
    ];

    let mut ok = true;
    let mut any = false;
    let mut any_open = false;

    let mut legacy = false;

    let mut snapshot = false;
    let mut json_streams: Vec<String> = Vec::new();

    if !json {
        println!("evidence store: {dir}");
        println!("  engagement {}", hex16(&header.engagement_id));

        println!("  host       {}", hex32(&header.host_id));
        println!("  agent      {}", hex16(&header.agent_id));
        println!("  genesis    {}", hex32(&header.genesis()));
        println!(
            "  seal       {}",
            match &seal_pub {
                Some(pk) => format!("Ed25519, key {}", hex32(pk)),
                None => "unsigned (plaintext slice)".to_string(),
            }
        );
        println!("  streams:");
    }

    let verify_one = |id: StreamId| load_verified(dir, &header, id, verify_seal.as_ref().map(|v| v as &SealVerify));
    let mut evidence_segs = Vec::new();
    let mut custody_segs = Vec::new();

    for (name, id) in streams {
        match verify_one(id) {
            Ok(v) if v.report.segments > 0 => {
                let rep = &v.report;
                any = true;
                if !rep.sealed {
                    any_open = true;
                }
                if json {
                    json_streams.push(format!(
                        "{{\"stream\":\"{name}\",\"ok\":true,\"segments\":{},\"records\":{},\
                         \"sealed\":{},\"unsealed_records\":{},\"tip\":\"{}\"}}",
                        rep.segments,
                        rep.records,
                        rep.sealed,
                        rep.unsealed_records,
                        hex32(&rep.tip)
                    ));
                } else {
                    if !rep.sealed {
                        any_open = true;
                    }
                    println!(
                        "    [{}] {name:<10} {} record(s) in {} segment(s), {}; tip {}",
                        if rep.sealed { "OK  " } else { "OPEN" },
                        rep.records,
                        rep.segments,
                        if rep.sealed {
                            "sealed".to_string()
                        } else {
                            format!(
                                "NOT SEALED — {} record(s) after the last seal, covered by no key; \
                                 see the note below",
                                rep.unsealed_records
                            )
                        },
                        hex32(&rep.tip)
                    );
                }
                match id {
                    StreamId::Evidence => evidence_segs = v.segments,
                    StreamId::Custody => custody_segs = v.segments,
                    _ => {}
                }
            }
            Ok(_) if id == StreamId::Evidence && snapshot_shaped => snapshot = true,

            Ok(_) if id == StreamId::Evidence => {
                any = true;
                ok = false;
                let why = "MISSING — every store `collect` writes has an evidence stream, \
                           so a store without one has lost its evidence";
                if json {
                    json_streams.push(format!(
                        "{{\"stream\":\"{name}\",\"ok\":false,\"error\":\"{}\"}}",
                        jesc(why)
                    ));
                } else {
                    println!("    [FAIL] {name:<10} {why}");
                }
            }

            Ok(_) if id == StreamId::Custody && ok => {
                if evidence_holds_custody(&evidence_segs) {
                    legacy = true;
                } else {
                    ok = false;
                    if json {
                        json_streams.push(format!(
                            "{{\"stream\":\"{name}\",\"ok\":false,\"error\":\"{}\"}}",
                            jesc(CUSTODY_MISSING)
                        ));
                    } else {
                        println!("    [FAIL] {name:<10} {CUSTODY_MISSING}");
                    }
                }
            }
            Ok(_) => {  }
            Err(e) => {
                any = true;
                ok = false;
                if json {
                    json_streams.push(format!(
                        "{{\"stream\":\"{name}\",\"ok\":false,\"error\":\"{}\"}}",
                        jesc(&e.to_string())
                    ));
                } else {

                    println!("    [FAIL] {name:<10} {}", h(&e.to_string()));
                }
            }
        }
    }

    if !any {
        eprintln!("hemostat verify: {dir} has a header but no stream data");
        return EXIT_FAILED;
    }

    let custody = if ok && !snapshot { custody_lines(&custody_segs) } else { Vec::new() };
    if !json && !custody.is_empty() {
        println!("  custody records (readable without the key):");
        for line in &custody {
            println!("    {}", h(line));
        }
    }

    if json {
        jprintln!(
            "{{\"store\":\"{}\",\"store_kind\":\"{}\",\"genesis\":\"{}\",\"signed\":{},\"pinned\":{},\
             \"ok\":{ok},\"streams\":[{}],\"custody\":[{}]}}",
            jesc(dir),
            if snapshot { "snapshot" } else { "collect" },
            hex32(&header.genesis()),
            seal_pub.is_some(),
            pinned.is_some(),
            json_streams.join(","),
            custody.iter().map(|c| format!("\"{}\"", jesc(c))).collect::<Vec<_>>().join(",")
        );
    } else {
        if let Some(kind) = kind_of(&custody_segs).filter(|_| snapshot) {
            println!(
                "\n  This is {kind}: one custody stream, signed and deliberately not encrypted. Its\n  \
                 records are not listed here.\n  \
                 Verified: chain continuity, per-segment seals, forward commitment, and the\n  \
                 Ed25519 seal signature on every sealed segment — against the key embedded in the\n  \
                 store. The key to pin is the one the verb printed."
            );
        } else if snapshot {
            println!(
                "\n  This is an arrival snapshot (`hemostat snapshot`), not a collection: one custody\n  \
                 stream, signed and deliberately not encrypted, which `drift` and `services` read\n  \
                 on the host. Its records are not listed here.\n  \
                 Verified: chain continuity, per-segment seals, forward commitment, and the\n  \
                 Ed25519 seal signature on every sealed segment — against the key embedded in the\n  \
                 store. The key to pin is the one `snapshot` printed."
            );
        } else if seal_pub.is_some() {
            println!(
                "\n  Verified: chain continuity, per-segment seals, forward commitment, and the\n  \
                 Ed25519 seal signature on every sealed segment — against the key embedded in the\n  \
                 store.\n  \
                 NOT checked: whether the payloads decrypt. Evidence payloads are AES-256-GCM under\n  \
                 a per-segment key sealed to the store key ({}), and `verify` deliberately needs no key\n  \
                 — that is what makes it the portable examiner. Use `hemostat read` with the\n  \
                 recovery key to decrypt, and keep that key: nothing else can read this store.\n  \
                 The seal proves integrity and authenticity, not confidentiality. And a software\n  \
                 seal key is forgeable by an adversary who scrapes it from the live agent — offline\n  \
                 media and already-anchored evidence are what it protects (design §4, §8).",
                if legacy {
                    "this store predates the custody stream, so its\n  \
                     custody records are encrypted with the findings"
                } else {
                    "custody records are in the clear, and\n  \
                     listed above"
                }
            );
        } else {
            println!(
                "\n  Verified: chain continuity, per-segment seals, and forward commitment.\n  \
                 This store carries NO seal key: its footers are unsigned, so the seal is not\n  \
                 forgery-resistant against someone who can rewrite the file, and payloads are\n  \
                 plaintext. (An older store from before the seal-key commit.)"
            );
        }

        if any_open {
            println!(
                "\n  NOTE — a stream above is NOT SEALED, and nothing after its last seal is\n  \
                 vouched for by any key. That is normal for a store a live agent is still\n  \
                 writing, and it is also what a tampered store looks like: deleting whole\n  \
                 segments off the end and the last footer with them leaves a chain that\n  \
                 verifies, and with the footer gone the records it covered are held only by\n  \
                 the chain, which needs no key to rebuild — they may have been rewritten or\n  \
                 invented, not only removed. This check cannot tell those apart. `collect`\n  \
                 seals both streams before it reports success, so in a store it finished an\n  \
                 open stream means a crash or tampering. To settle it, compare the tip above\n  \
                 against the one recorded when the store was closed, or the segment count\n  \
                 against your drop-time record."
            );
        }
        if pinned.is_none() {
            println!(
                "\n  Tip: to detect an offline re-seal, pin the key from your drop attestation:\n  \
                 HEMOSTAT_SEAL_PUBKEY=<64-hex> hemostat verify {dir}"
            );
        } else {
            println!("\n  Seal key matches the pinned $HEMOSTAT_SEAL_PUBKEY.");
        }
        println!(
            "\n{}",
            match (ok, any_open) {
                (false, _) => "FAIL — the store did not verify (see above).",
                (true, true) => "PARTIAL — the chains verify, but a stream is not sealed (see the note).",
                (true, false) => "PASS — the store verifies.",
            }
        );
    }

    match (ok, any_open) {
        (false, _) => EXIT_FAILED,
        (true, true) => EXIT_PARTIAL,
        (true, false) => EXIT_OK,
    }
}

const CUSTODY_MISSING: &str = "MISSING — every store `collect` writes has a custody stream, which \
                               records the sweeps that did not run; without it, which sweeps ran \
                               cannot be shown";

fn evidence_holds_custody(evidence: &[hemostat_evfmt::Segment]) -> bool {
    evidence
        .iter()
        .flat_map(|s| s.records.iter())
        .any(|r| r.header.rec_type == hemostat_evfmt::RecType::CUSTODY)
}

pub(crate) fn sealed_kind(records: &[&[u8]]) -> Option<&'static str> {
    let kind = records.iter().take(4).find_map(|r| r.strip_prefix(b"k"))?;
    match kind {
        b"pfsense-containment-evidence" => Some(
            "a containment evidence store (`fw block`, `fw confirm`, `undo` on the firewall): config.xml and\n  \
             the digest of every config-history file, sealed before a config write",
        ),
        b"hemostat-collector-ledger" => Some(
            "a run of the collector's ledger (`collector ingest`): every parcel it took, accepted, rejected or\n  \
             already held, and why, sealed under the ledger key the collector made for itself",
        ),
        b"hemostat-checkpoint" => Some(
            "an agent's CHECKPOINT store (`ship --to`): the collector's signed receipt for a store it pushed, kept\n  \
             verbatim. The receipt is checked against the collector's receipt key, not this store's seal",
        ),
        b"pfsense-statekill-evidence" => {
            Some("a state-kill evidence store (`fw statekill`): the pf states it matched, sealed before\n  it killed them")
        }
        _ => None,
    }
}

fn kind_of(segments: &[hemostat_evfmt::Segment]) -> Option<&'static str> {
    let recs: Vec<&[u8]> =
        segments.iter().flat_map(|s| s.records.iter()).filter(|r| !r.header.is_encrypted()).map(|r| r.stored.as_slice()).collect();
    sealed_kind(&recs)
}

fn custody_lines(segments: &[hemostat_evfmt::Segment]) -> Vec<String> {
    let mut out = Vec::new();
    for seg in segments {
        for rec in &seg.records {
            out.push(if rec.header.is_encrypted() {
                format!("(record {} is encrypted; custody records are written in the clear)", rec.header.seq)
            } else {
                String::from_utf8_lossy(&rec.stored).into_owned()
            });
        }
    }
    out
}

pub(crate) fn read_store(positional: &[&str], json: bool) -> u8 {
    use hemostat_evcrypto::envelope::{open_dek, unwrap_store_key};
    use hemostat_evcrypto::seal::{decode_header_keys, verify_footer};
    use hemostat_evfmt::{load_verified, read_store_header, SealVerify, StreamId};

    let Some(dir) = positional.get(1) else {
        eprintln!("usage: hemostat read <store-dir>   (set $HEMOSTAT_RECOVERY_KEY to decrypt)");
        return EXIT_USAGE;
    };

    let header = match read_store_header(dir) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("hemostat read: {}", h(&e.to_string()));
            return EXIT_FAILED;
        }
    };
    let keys = decode_header_keys(&header.variable_tail);

    let pinned = match pinned_seal_pubkey() {
        Ok(p) => p,
        Err(msg) => {
            eprintln!("hemostat read: refusing — {msg}");
            return EXIT_FAILED;
        }
    };
    if let Err(msg) = check_pinned_seal(pinned, keys.seal_pub) {
        eprintln!("hemostat read: refusing — {msg}");
        return EXIT_FAILED;
    }

    if let (None, Some(pk)) = (pinned, keys.seal_pub) {
        eprintln!(
            "hemostat read: NOTE — the seal key ({}) is not pinned, so a store re-sealed offline \
             under a key of someone else's reads the same as this one. Set \
             $HEMOSTAT_SEAL_PUBKEY to the key from your drop attestation.",
            hex32(&pk)
        );
    }

    let verify_seal = keys.seal_pub.map(|pk| move |s: &[u8], sig: &[u8]| verify_footer(&pk, s, sig));
    let verify_one = |id| load_verified(dir, &header, id, verify_seal.as_ref().map(|v| v as &SealVerify));
    let evidence = match verify_one(StreamId::Evidence) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("hemostat read: refusing to read — the store does not verify: {}", h(&e.to_string()));
            return EXIT_FAILED;
        }
    };

    let vrep = &evidence.report;
    if vrep.segments == 0 {

        let snapshot_shaped = keys.seal_pub.is_some() && keys.store_pub.is_none() && keys.store_wrap.is_none();
        if snapshot_shaped {
            match verify_one(StreamId::Custody) {
                Err(e) => {
                    eprintln!(
                        "hemostat read: refusing to read — the custody stream does not verify: {}",
                        h(&e.to_string())
                    );
                    return EXIT_FAILED;
                }
                Ok(c) if c.report.segments > 0 => {
                    match kind_of(&c.segments) {
                        Some(kind) => eprintln!(
                            "hemostat read: {dir} is {}, not a collection — it holds no findings to read. \
                             `hemostat verify` checks it.",
                            kind.replace("\n  ", " ")
                        ),
                        None => eprintln!(
                            "hemostat read: {dir} is an arrival snapshot (`hemostat snapshot`), not a \
                             collection — it holds no findings to read. `hemostat verify` checks it; \
                             `drift` and `services` read it."
                        ),
                    }
                    return EXIT_USAGE;
                }
                Ok(_) => {}
            }
        }
        eprintln!(
            "hemostat read: refusing to read — this store has no evidence stream. Every store \
             `collect` writes has one, so a store without it has lost its evidence"
        );
        return EXIT_FAILED;
    }
    let custody_stream = match verify_one(StreamId::Custody) {
        Ok(v) => v,
        Err(e) => {
            eprintln!(
                "hemostat read: refusing to read — the custody stream does not verify: {}",
                h(&e.to_string())
            );
            return EXIT_FAILED;
        }
    };

    let crep = &custody_stream.report;
    if crep.segments == 0 && !evidence_holds_custody(&evidence.segments) {
        eprintln!("hemostat read: refusing to read — custody {CUSTODY_MISSING}");
        return EXIT_FAILED;
    }

    let open: Vec<&str> = [("evidence", vrep), ("custody", crep)]
        .into_iter()
        .filter(|(_, r)| r.segments > 0 && !r.sealed)
        .map(|(n, _)| n)
        .collect();
    let unsealed = vrep.unsealed_records + crep.unsealed_records;
    if !open.is_empty() {
        eprintln!(
            "hemostat read: WARNING — the {} stream is NOT SEALED, and {unsealed} record(s) after its \
             last seal are vouched for by no key. `collect` seals both streams before it reports \
             success, so this store was cut short by a crash or tampered with, and those records \
             may have been rewritten or invented, not only removed. They are printed as they \
             stand; `hemostat verify {dir}` shows the tips to compare with the drop-time record.",
            open.join(" and ")
        );
    }

    let custody = custody_lines(&custody_stream.segments);

    let store_secret = match &keys.store_wrap {
        Some(wrap) => {
            let Some(rk) = recovery_key() else {
                eprintln!(
                    "hemostat read: this store is encrypted — point \
                     $HEMOSTAT_RECOVERY_KEY_FILE at a file holding the recovery key (64 hex \
                     chars), or set $HEMOSTAT_RECOVERY_KEY to it directly"
                );
                return EXIT_FAILED;
            };

            let rk = hemostat_evcrypto::secret::Secret32::new(rk);
            match unwrap_store_key(&rk, wrap) {
                Ok(sk) => Some(sk),
                Err(_) => {
                    eprintln!("hemostat read: the recovery key does not open this store");
                    return EXIT_FAILED;
                }
            }
        }
        None => None,
    };

    let segments = &evidence.segments;

    let mut json_items: Vec<String> = Vec::new();
    for text in custody {
        if json {
            json_items.push(text);
        } else {
            println!("{}", h(&text));
        }
    }
    for seg in segments {
        let dek = match &store_secret {
            Some(sk) => match open_dek(sk, &seg.header.variable_tail) {
                Ok(d) => Some(d),
                Err(_) => {
                    eprintln!("hemostat read: cannot open the key for segment {}", seg.header.segment_seq);
                    return EXIT_FAILED;
                }
            },
            None => None,
        };
        for rec in &seg.records {
            let pt = if rec.header.is_encrypted() {
                let Some(dek) = &dek else {
                    eprintln!("hemostat read: an encrypted record but no key was recovered");
                    return EXIT_FAILED;
                };
                match hemostat_evcrypto::envelope::aead_open(
                    dek,
                    &rec.header.nonce,
                    &rec.header.encode(),
                    &rec.stored,
                    &rec.tag,
                ) {
                    Ok(p) => p,
                    Err(_) => {
                        eprintln!("hemostat read: record {} failed to authenticate/decrypt", rec.header.seq);
                        return EXIT_FAILED;
                    }
                }
            } else if keys.store_wrap.is_some() {

                eprintln!(
                    "hemostat read: refusing — record {} is not encrypted, but this store encrypts \
                     every finding; `collect` did not write it",
                    rec.header.seq
                );
                return EXIT_FAILED;
            } else {
                rec.stored.clone()
            };

            let text = String::from_utf8_lossy(&pt).into_owned();
            if json {
                json_items.push(text);
            } else {
                println!("{}", h(&text));
            }
        }
    }
    if json {
        jprintln!(
            "{{\"sealed\":{},\"unsealed_records\":{unsealed},\"items\":[{}]}}",
            open.is_empty(),
            json_items.join(",")
        );
    }
    if open.is_empty() {
        EXIT_OK
    } else {
        EXIT_PARTIAL
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn collect(positional: &[&str], json: bool) -> u8 {

    if let Err(msg) = require_built(hemostat_buildinfo::ActionClass::Collect) {
        eprintln!("hemostat collect: {msg}");
        return EXIT_NOT_BUILT;
    }
    let dir = positional.get(1).copied().unwrap_or("hemostat-evidence");
    match collect_inner(dir) {
        Ok(s) => {
            let recovery_hex = s.generated_recovery.as_ref().map(|k| hex32(k.expose()));
            if json {
                jprintln!(
                    "{{\"store\":\"{}\",\"findings\":{},\"custody\":{},\"genesis\":\"{}\",\
                     \"seal_key\":\"{}\",\"sealed\":true,\"signed\":true,\"encrypted\":true,\
                     \"sweeps_did_not_run\":{},\"findings_shed\":{},\"complete\":{},\"read_key\":{},\"recovery_pub\":\"{}\"{}}}",
                    jesc(dir),
                    s.findings,
                    s.custody,
                    hex32(&s.genesis),
                    hex32(&s.seal_pub),
                    s.gaps,
                    s.shed.is_some(),
                    s.complete(),
                    s.read_pub.map_or("null".to_string(), |k| format!("\"{}\"", hex32(&k))),
                    hex32(&s.recovery_pub),
                    match &recovery_hex {
                        Some(h) => format!(",\"recovery_key\":\"{h}\""),
                        None => String::new(),
                    }
                );
            } else {
                println!(
                    "wrote {} finding(s) + {} custody record(s) to {dir}, sealed · signed · encrypted.\n  \
                     genesis   {}\n  \
                     seal key  {}\n  \
                     Footers are Ed25519-signed and record payloads are AES-256-GCM under a\n  \
                     per-segment key sealed to the store key.\n  \
                     Anchor the seal key off-host now; then verify later, bound to it, with:\n  \
                     HEMOSTAT_SEAL_PUBKEY={} hemostat verify {dir}",
                    s.findings,
                    s.custody,
                    hex32(&s.genesis),
                    hex32(&s.seal_pub),
                    hex32(&s.seal_pub),
                    dir = dir
                );

                println!("  recovery  {} (the public half of the key that reads it)", hex32(&s.recovery_pub));
                if let Some(k) = &s.read_pub {
                    println!(
                        "  read key  {}\n  \
                         The store key is also wrapped to this engagement read key, so the collector\n  \
                         that holds it can read the findings (RFC-003 decision 3).",
                        hex32(k)
                    );
                }

                if s.gaps > 0 {
                    println!(
                        "\n  {} sweep(s) did NOT run, or ran only in part, and are recorded in \
                         the chain as custody records — this store is not a complete picture of \
                         the host.\n  `hemostat read {dir}` lists them; most need root.",
                        s.gaps,
                        dir = dir
                    );
                }

                if let Some(why) = &s.shed {
                    println!(
                        "\n  NO FINDINGS were written: {}. The chain records the shedding as an \
                         `evidence-shed` custody record; free space and collect again.",
                        h(why)
                    );
                }
                if let Some(h) = &recovery_hex {

                    eprintln!(
                        "\n  ┌─ RECOVERY KEY ─ save this off-host; it is the ONLY key that can read this store ─┐\n  \
                         │  {h}\n  \
                         └──────────────────────────────────────────────────────────────────────────────────┘\n  \
                         Copy it off this host NOW, then read the store on the machine you took it to:\n  \
                         \x20   printf %s <key> > key.hex && chmod 600 key.hex\n  \
                         \x20   HEMOSTAT_RECOVERY_KEY_FILE=key.hex hemostat read {dir}\n\n  \
                         Do NOT read it back here: this key exists on a host you are treating as\n  \
                         compromised, and root on that host can read it out of any process that\n  \
                         holds it. It exists at all only because $HEMOSTAT_RECOVERY_PUBKEY was not\n  \
                         set — set it before `collect` to seal to a key you already hold, and no\n  \
                         readable key is ever created here."
                    );
                }
            }

            if let Some(h) = recovery_hex {
                hemostat_evcrypto::secret::wipe(h.into_bytes());
            }

            s.exit_code()
        }
        Err(e) => {
            eprintln!("hemostat collect: {e}");
            EXIT_FAILED
        }
    }
}

#[cfg(target_os = "linux")]
pub(crate) struct BootClock {
    last: std::sync::atomic::AtomicU64,
}

#[cfg(target_os = "linux")]
impl BootClock {
    pub(crate) fn new(first: u64) -> Self {
        BootClock { last: std::sync::atomic::AtomicU64::new(first) }
    }
}

#[cfg(target_os = "linux")]
impl hemostat_evfmt::Clock for BootClock {
    fn wall_ns(&self) -> i64 {
        hemostat_evfmt::SystemClock::new().wall_ns()
    }
    fn mono_ns(&self) -> u64 {
        use std::sync::atomic::Ordering;
        match hemostat_lifecycle::watch::boot_ns() {
            Some(ns) => self.last.fetch_max(ns, Ordering::Relaxed).max(ns),
            None => self.last.load(Ordering::Relaxed),
        }
    }
}

#[cfg(target_os = "linux")]
static SESSION_RECOVERY: std::sync::OnceLock<[u8; 32]> = std::sync::OnceLock::new();

#[cfg(target_os = "linux")]
pub(crate) fn collect_inner(dir: &str) -> std::result::Result<CollectSummary, String> {
    use hemostat_evcrypto::seal::HeaderKeys;
    use hemostat_evfmt::{RecType, RunContext, StoreHeader, StoreWriter, StreamCrypto, StreamId};

    let id = gather_identity().map_err(|e| format!("cannot establish identity: {e}"))?;

    if let Err(why) = crate::resources::apply_oom_score_adj(crate::authz::resource_profile("collect")) {
        eprintln!("hemostat collect: NOTE: {why}");
    }

    if let Some(why) = crate::resources::disk_refusal(std::path::Path::new(dir)) {
        return Err(format!("refusing to start an evidence store: {why}"));
    }
    let now_wall = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_nanos()).unwrap_or(i64::MAX))
        .unwrap_or(0);
    let now_boot = hemostat_lifecycle::watch::boot_ns()
        .ok_or("cannot read CLOCK_BOOTTIME, which orders the records in the store")?;

    let mut seal_seed = rand32().map_err(|e| format!("cannot read entropy for the seal key: {e}"))?;
    let seal = hemostat_evcrypto::seal::SealKey::from_seed(seal_seed);
    let seal_pub = seal.public_bytes();

    hemostat_evcrypto::secret::wipe_bytes(&mut seal_seed);

    let asked = std::env::var("HEMOSTAT_RECOVERY_PUBKEY")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .or_else(|| option_env!("HEMOSTAT_RECOVERY_PUBKEY").map(str::to_string).filter(|v| !v.trim().is_empty()));
    let (recovery_pub, generated_recovery) = match asked {
        Some(v) => match parse_hex32(&v) {
            Some(pk) => (pk, None),
            None => {
                return Err(format!(
                    "$HEMOSTAT_RECOVERY_PUBKEY is set but is not 64 hex characters (got {} \
                     usable hex digit(s)). Nothing was collected. Fix the value, or unset it \
                     to have a recovery key minted here — but note that minting it here puts \
                     the only key that can read this store on the host you are collecting \
                     from",
                    v.chars().filter(char::is_ascii_hexdigit).count()
                ));
            }
        },
        None => match SESSION_RECOVERY.get() {
            Some(pk) => (*pk, None),
            None => {
                let kp = hemostat_evcrypto::envelope::KeyPair::from_seed(
                    rand32().map_err(|e| format!("cannot read entropy for the recovery key: {e}"))?,
                );
                (kp.public_bytes(), Some(kp.secret_bytes()))
            }
        },
    };
    let store = hemostat_evcrypto::envelope::KeyPair::from_seed(
        rand32().map_err(|e| format!("cannot read entropy for the store key: {e}"))?,
    );
    let store_pub = store.public_bytes();
    let store_wrap = hemostat_evcrypto::envelope::wrap_store_key(
        &recovery_pub,
        &store.secret_bytes(),
        rand32().map_err(|e| format!("cannot read entropy to wrap the store key: {e}"))?,
    )
    .map_err(|e| format!("cannot wrap the store key: {e}"))?;

    let read_pub = match std::env::var("HEMOSTAT_READ_PUBKEY").ok().filter(|v| !v.trim().is_empty()) {
        None => None,
        Some(v) => Some(parse_hex32(&v).ok_or_else(|| {
            format!(
                "$HEMOSTAT_READ_PUBKEY is set but is not 64 hex characters (got {} usable hex digit(s)). \
                 Nothing was collected. It is the collector's engagement read key, as \
                 `hemostat collector read-key` printed it; fix the value, or unset it to seal to the \
                 recovery key alone",
                v.chars().filter(char::is_ascii_hexdigit).count()
            )
        })?),
    };
    let read_wrap = match &read_pub {
        None => None,
        Some(rp) => Some(
            hemostat_evcrypto::envelope::wrap_store_key_for_read(
                rp,
                &store.secret_bytes(),
                rand32().map_err(|e| format!("cannot read entropy to wrap the store key: {e}"))?,
            )
            .map_err(|e| format!("cannot wrap the store key to the read key: {e}"))?,
        ),
    };

    drop(store);

    let header = StoreHeader {
        format_ver: 1,
        suite_id: 1,
        engagement_id: id.engagement,
        host_id: id.host,
        agent_id: id.agent,
        created_wall_ns: now_wall,
        created_mono_ns: now_boot,
        variable_tail: hemostat_evcrypto::seal::encode_header_keys_with_read(
            &HeaderKeys { seal_pub: Some(seal_pub), store_pub: Some(store_pub), store_wrap: Some(store_wrap) },
            read_wrap.as_deref(),
        ),
    };

    let writer = StoreWriter::create(dir, header).map_err(|e| e.to_string())?;

    crate::sealed::announce(writer.header());
    let genesis = writer.genesis();
    let run = RunContext::new(id.instance, id.run_id, id.boot, 1);
    let seal = std::rc::Rc::new(seal);
    let evidence_seal = std::rc::Rc::clone(&seal);
    let signer: hemostat_evfmt::SealSigner = Box::new(move |signable| evidence_seal.sign_footer(signable));
    let crypto = StreamCrypto {
        signer: Some(signer),
        cipher: Some(Box::new(EnvelopeCipher { store_pub })),
    };
    let mut s = writer
        .open_stream_clocked(StreamId::Evidence, run.clone(), crypto, Box::new(BootClock::new(now_boot)))
        .map_err(|e| e.to_string())?;

    let custody_signer: hemostat_evfmt::SealSigner = Box::new(move |signable| seal.sign_footer(signable));
    let mut c = writer
        .open_stream_clocked(
            StreamId::Custody,
            run,
            StreamCrypto { signer: Some(custody_signer), cipher: None },
            Box::new(BootClock::new(now_boot)),
        )
        .map_err(|e| e.to_string())?;

    let opening = format!(
        "{{\"event\":\"collection-start\",\"tool\":\"hemostat\",\"version\":\"{}\",\
         \"variant\":\"{}\",\"host_id_source\":\"{}\",\"read_key\":{}}}",
        env!("CARGO_PKG_VERSION"),
        MANIFEST.variant,
        jesc(id.host_id_source),
        read_pub.map_or("null".to_string(), |k| format!("\"{}\"", hex32(&k))),
    );
    c.append(RecType::CUSTODY, 0, opening.as_bytes())
        .map_err(|e| e.to_string())?;
    let custody = 1usize;

    let mut findings = 0usize;

    let suid_r = hemostat_sensor_linux::suid::report();

    let manifest_load = crate::vendor::load_manifest(None);
    let manifest = manifest_load.as_ref().ok().and_then(Option::as_deref);
    let inventory_r = hemostat_sensor_linux::inventory::report_with(manifest);

    let reference = match &manifest_load {
        Ok(Some(m)) => format!(
            "{{\"event\":\"integrity-reference\",\"reference\":\"vendor-manifest\",\"release\":\"{}\"}}",
            jesc(&m.release)
        ),
        Ok(None) => "{\"event\":\"integrity-reference\",\"reference\":\"host-package-database\"}".to_string(),
        Err(e) => format!(
            "{{\"event\":\"integrity-reference\",\"reference\":\"host-package-database\",\"manifest_refused\":\"{}\"}}",
            jesc(e)
        ),
    };
    c.append(RecType::CUSTODY, 0, reference.as_bytes()).map_err(|e| e.to_string())?;
    let custody = custody + 1;
    let sysmap_r = hemostat_sensor_linux::sysmap::report();
    let kptr_r = hemostat_sensor_linux::kptrhooks::report();
    let kwalk_r = hemostat_sensor_linux::kwalk_report();
    let kernposture_r = hemostat_sensor_linux::kernposture_report();

    let accounts_r = hemostat_sensor_linux::account_report();

    let overview_r = hemostat_sensor_linux::overview_report();
    let persist_r = hemostat_sensor_linux::persist_report();
    let injected_r = hemostat_sensor_linux::hooked_report();

    let systemd_r = hemostat_sensor_linux::enablement::report();
    let rootkit_r = hemostat_sensor_linux::rootkit_report();

    let sshd_r = hemostat_sensor_linux::sshd::report();
    let sysctl_r = hemostat_sensor_linux::sysctlpolicy::report();
    let watchdog_r = hemostat_sensor_linux::watchdog::report();

    let trust_r = hemostat_sensor_linux::trust::report_with(&crate::snapshot::anchor_baseline(crate::snapshot::DEFAULT_STORE));

    use crate::coverage;

    let mut gaps = 0usize;
    for (source, covered) in [
        ("suid", coverage::from_flag(suid_r.available, &suid_r.reason)),
        ("inventory", coverage::from_flag(inventory_r.available, &inventory_r.reason)),
        ("sysmap", coverage::from_flag(sysmap_r.available, &sysmap_r.reason)),
        ("kptr-hooks", coverage::from_flag(kptr_r.available, &kptr_r.reason)),
        ("kwalk", coverage::kwalk(&kwalk_r)),
        ("kernel-posture", coverage::kernel_posture(&kernposture_r)),
        ("accounts", coverage::accounts(&accounts_r)),
        ("overview", coverage::overview(&overview_r)),
        ("persistence", coverage::persistence(&persist_r)),
        ("systemd", coverage::enablement(&systemd_r)),
        ("injected", coverage::injected(&injected_r)),
        ("rootkit", coverage::rootkit(&rootkit_r)),
        ("sshd", coverage::from_flag(sshd_r.available, &sshd_r.reason)),
        ("sysctl", coverage::from_flag(sysctl_r.available, &sysctl_r.reason)),
        ("watchdog", coverage::from_flag(watchdog_r.available, &watchdog_r.reason)),
        ("trust", coverage::trust(&trust_r)),
    ] {
        let Some(why) = covered.gap() else { continue };

        let event = if covered.ran() { "sweep-ran-in-part" } else { "sweep-did-not-run" };
        let p = format!(
            "{{\"event\":\"{}\",\"source\":\"{}\",\"reason\":\"{}\"}}",
            jesc(event),
            jesc(source),
            jesc(why),
        );
        c.append(RecType::CUSTODY, 0, p.as_bytes()).map_err(|e| e.to_string())?;
        gaps += 1;
    }

    if let Some(why) = crate::resources::disk_refusal(std::path::Path::new(dir)) {
        let p = format!(
            "{{\"event\":\"evidence-shed\",\"reason\":\"{}\"}}",
            jesc(&format!("no findings were written: {why}"))
        );
        c.append(RecType::CUSTODY, 0, p.as_bytes()).map_err(|e| e.to_string())?;
        s.close().map_err(|e| e.to_string())?;
        c.close().map_err(|e| e.to_string())?;
        return Ok(CollectSummary {
            findings: 0,
            gaps,
            shed: Some(why),
            custody: custody + gaps + 1,
            genesis,
            seal_pub,
            generated_recovery,
            recovery_pub,
            read_pub,
        });
    }

    let mut vouch = Vouch::default();

    {
        use hemostat_sensor_linux::rootkit::Finding as RFinding;
        let mut push = |source: &str, fs: &[RFinding]| -> std::result::Result<(), String> {
            for f in fs {
                let files = vouch.files(f.severity.tag(), &f.subject, &f.what);
                let p = with_files(detection_json(source, f.severity.tag(), &f.subject, "", &f.what, &f.why), &files);
                s.append(RecType::DETECTION, 0, p.as_bytes()).map_err(|e| e.to_string())?;
                findings += 1;
            }
            Ok(())
        };
        push("rootkit", &rootkit_r.findings)?;
        push("suid", &suid_r.findings)?;
        push("inventory", &inventory_r.findings)?;
        push("sysmap", &sysmap_r.findings)?;
        push("kptr-hooks", &kptr_r.findings)?;
        push("sshd", &sshd_r.findings)?;
        push("sysctl", &sysctl_r.findings)?;
        push("watchdog", &watchdog_r.findings)?;
    }

    for f in &accounts_r.findings {
        let p = detection_json("accounts", f.severity.tag(), &f.subject, "", &f.what, &f.why);
        s.append(RecType::DETECTION, 0, p.as_bytes()).map_err(|e| e.to_string())?;
        findings += 1;
    }

    {
        use hemostat_sensor_linux::TriageFinding;
        let mut push = |source: &str, fs: &[TriageFinding]| -> std::result::Result<(), String> {
            for f in fs {
                let files = vouch.files(f.severity.tag(), &f.locus, &f.what);
                let p = with_files(detection_json(source, f.severity.tag(), &f.subject, &f.locus, &f.what, &f.why), &files);
                s.append(RecType::DETECTION, 0, p.as_bytes()).map_err(|e| e.to_string())?;
                findings += 1;
            }
            Ok(())
        };
        push("overview", &overview_r.findings)?;
        push("persistence", &persist_r.findings)?;
        push("systemd", &systemd_r.findings)?;
        push("injected", &injected_r.findings)?;
        push("trust", &trust_r.findings)?;
        push("kernel-posture", &kernposture_r.findings)?;
        push("kwalk", &kwalk_r.findings)?;
    }

    s.close().map_err(|e| e.to_string())?;
    c.close().map_err(|e| e.to_string())?;
    Ok(CollectSummary {
        findings,
        gaps,
        shed: None,
        custody: custody + gaps,
        genesis,
        seal_pub,
        generated_recovery,
        recovery_pub,
        read_pub,
    })
}

#[cfg(target_os = "linux")]
pub(crate) struct CollectSummary {
    findings: usize,

    gaps: usize,

    shed: Option<String>,
    custody: usize,
    genesis: [u8; 32],

    seal_pub: [u8; 32],

    generated_recovery: Option<hemostat_evcrypto::secret::Secret32>,

    recovery_pub: [u8; 32],

    read_pub: Option<[u8; 32]>,
}

#[cfg(target_os = "linux")]
impl CollectSummary {

    fn complete(&self) -> bool {
        self.gaps == 0 && self.shed.is_none()
    }

    fn exit_code(&self) -> u8 {
        if self.complete() {
            EXIT_OK
        } else {
            EXIT_PARTIAL
        }
    }
}

#[cfg(target_os = "linux")]
pub(crate) struct EnvelopeCipher {
    store_pub: [u8; 32],
}

#[cfg(target_os = "linux")]
pub(crate) struct DekCipher {
    dek: hemostat_evcrypto::secret::Secret32,
}

#[cfg(target_os = "linux")]
pub(crate) type NamedFile = (String, String, Option<String>);

#[cfg(target_os = "linux")]
pub(crate) fn with_files(mut json: String, files: &[NamedFile]) -> String {
    if files.is_empty() || !json.ends_with('}') {
        return json;
    }
    json.pop();
    let items: Vec<String> = files
        .iter()
        .map(|(p, d, v)| {
            let vouched = v.as_deref().map_or(String::new(), |v| format!(",\"vouched\":\"{}\"", jesc(v)));
            format!("{{\"path\":\"{}\",\"sha256\":\"{d}\"{vouched}}}", jesc(p))
        })
        .collect();
    json.push_str(&format!(",\"files\":[{}]}}", items.join(",")));
    json
}

#[cfg(target_os = "linux")]
pub(crate) fn named_paths(locus: &str, what: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for text in [locus, what] {
        for w in text.split(|c: char| c.is_whitespace() || matches!(c, ',' | '`' | '\'' | '"' | '(' | ')' | '=' | ';')) {
            let w = w.trim_end_matches(['.', ':', ';', ')', ']']);
            if w.len() < 2 || !w.starts_with('/') || w.starts_with("//") {
                continue;
            }
            if ["/proc/", "/sys/", "/dev/", "/run/"].iter().any(|k| w.starts_with(k)) || w.contains('*') {
                continue;
            }
            if !out.iter().any(|o| o == w) {
                out.push(w.to_string());
            }
        }
    }
    out.truncate(4);
    out
}

#[cfg(target_os = "linux")]
#[derive(Default)]
struct Vouch {
    manager: Option<Option<hemostat_sensor_linux::pkg::Manager>>,

    drifted: std::collections::BTreeMap<String, Vec<std::path::PathBuf>>,

    hashed: usize,
}

#[cfg(target_os = "linux")]
impl Vouch {
    const MAX_FILES: usize = 256;

    fn files(&mut self, sev: &str, locus: &str, what: &str) -> Vec<NamedFile> {
        if !matches!(sev, "WARN" | "CRITICAL") {
            return Vec::new();
        }
        let mut out = Vec::new();
        for p in named_paths(locus, what) {
            if self.hashed >= Self::MAX_FILES {
                break;
            }
            self.hashed += 1;

            let Ok(d) = hemostat_sensor_linux::saferead::sha256_of(std::path::Path::new(&p)) else { continue };
            let vouched = self.vouched(&p);
            out.push((p, hex32(&d), vouched));
        }
        out
    }

    fn vouched(&mut self, p: &str) -> Option<String> {
        let pm = self.manager.get_or_insert_with(hemostat_sensor_linux::pkg::manager).as_ref()?;
        let path = std::path::Path::new(p);
        let pkg = pm.owner(path)?;
        let drifted = self.drifted.entry(pkg.clone()).or_insert_with(|| pm.drift(&pkg).into_iter().map(|d| d.path).collect());
        let real = path.canonicalize().ok();
        let changed = drifted.iter().any(|d| d == path || real.as_deref() == Some(d.as_path()) || d.canonicalize().ok() == real);
        (!changed).then_some(pkg)
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn detection_json(source: &str, sev: &str, subject: &str, locus: &str, what: &str, why: &str) -> String {
    let mut s = format!(
        "{{\"source\":\"{}\",\"severity\":\"{}\",\"subject\":\"{}\"",
        jesc(source),
        jesc(sev),
        jesc(subject)
    );
    if !locus.is_empty() {
        s.push_str(&format!(",\"locus\":\"{}\"", jesc(locus)));
    }
    s.push_str(&format!(",\"what\":\"{}\"", jesc(what)));
    if !why.is_empty() {
        s.push_str(&format!(",\"why\":\"{}\"", jesc(why)));
    }
    s.push('}');
    s
}

#[cfg(target_os = "linux")]
impl hemostat_evfmt::SegmentCipher for EnvelopeCipher {
    fn new_segment(
        &self,
        _seg_seq: u64,
    ) -> hemostat_evfmt::StoreResult<(Vec<u8>, Box<dyn hemostat_evfmt::RecordCipher>)> {
        let to_io = |m: String| hemostat_evfmt::StoreError::Io(std::io::Error::other(m));
        let dek = hemostat_evcrypto::secret::Secret32::new(
            rand32().map_err(|e| to_io(format!("entropy for a DEK: {e}")))?,
        );
        let eph = rand32().map_err(|e| to_io(format!("entropy to seal a DEK: {e}")))?;
        let tail = hemostat_evcrypto::envelope::seal_dek(&self.store_pub, &dek, eph)
            .map_err(|e| to_io(format!("sealing a DEK: {e}")))?;
        Ok((tail, Box::new(DekCipher { dek })))
    }
}

#[cfg(target_os = "linux")]
impl hemostat_evfmt::RecordCipher for DekCipher {
    fn seal(&self, nonce: &[u8; 12], aad: &[u8], pt: &[u8]) -> (Vec<u8>, Vec<u8>) {
        match hemostat_evcrypto::envelope::aead_seal(&self.dek, nonce, aad, pt) {
            Ok((ct, tag)) => (ct, tag.to_vec()),

            Err(_) => (Vec::new(), Vec::new()),
        }
    }
}

#[cfg(all(target_os = "linux", feature = "mod-tui"))]
pub(crate) const CONSOLE_EVIDENCE: &str = "/var/lib/hemostat/evidence";

#[cfg(all(target_os = "linux", feature = "mod-tui"))]
pub(crate) fn console_sealed(mut m: hemostat_tui::ConsoleModel) -> hemostat_tui::ConsoleModel {
    let (row, note) = console_seal();
    m.last_result = Some(match m.last_result.take() {
        Some(r) => format!("{r}  ·  {note}"),
        None => note,
    });
    m.findings.push(row);
    m
}

#[cfg(all(target_os = "linux", feature = "mod-tui"))]
fn console_seal() -> (hemostat_tui::FindingRow, String) {
    use hemostat_tui::{FindingRow, Sev};
    use std::os::unix::fs::DirBuilderExt as _;
    let row = |severity: Sev, subject: String, what: String, why: String, evidence: Vec<String>| FindingRow {
        severity,
        source: "evidence".into(),
        subject,
        what,
        why,
        remedy: None,
        evidence,
    };
    if let Err(e) = std::fs::DirBuilder::new().recursive(true).mode(0o700).create(CONSOLE_EVIDENCE) {
        let what = format!("this sweep was NOT sealed: {CONSOLE_EVIDENCE} could not be made ({e})");
        let note = "evidence NOT sealed (run the console as root)".to_string();
        return (row(Sev::Warn, CONSOLE_EVIDENCE.into(), what, "the findings on screen exist nowhere else".into(), vec![]), note);
    }
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let dir = format!("{CONSOLE_EVIDENCE}/console-{stamp}");
    match collect_inner(&dir) {
        Ok(s) => {
            let partial = if s.complete() { String::new() } else { " — PARTIAL: a sweep did not run in full, and the store says which".into() };
            let mut what = format!("this sweep sealed: {} finding(s), {} custody record(s){partial}", s.findings, s.custody);
            let mut evidence = vec![dir.clone(), format!("seal key {}", hex32(&s.seal_pub))];
            let mut why = "verify it with `hemostat verify` (no key needed); read it with the recovery key".to_string();
            if let Some(k) = &s.generated_recovery {
                let _ = SESSION_RECOVERY.set(s.recovery_pub);
                what.push_str(". A recovery key was minted here, because $HEMOSTAT_RECOVERY_PUBKEY is not set");
                evidence.push(format!("RECOVERY KEY {}", hex32(k.expose())));
                why = "WRITE THE RECOVERY KEY DOWN and keep it off this host: it is shown only here, every store \
                       this session seals uses it, and nothing else can read them"
                    .into();
            }
            (row(Sev::Note, dir.clone(), what, why, evidence), format!("evidence sealed to {dir}"))
        }
        Err(e) => {
            let note = "evidence NOT sealed (see the evidence row)".to_string();
            (row(Sev::Warn, dir, format!("this sweep was NOT sealed: {e}"), "the findings on screen exist nowhere else".into(), vec![]), note)
        }
    }
}
