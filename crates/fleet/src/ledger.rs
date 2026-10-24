use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use hemostat_evcrypto::seal::{encode_header_keys, HeaderKeys, SealKey};
use hemostat_evfmt::{
    load_verified, read_store_header, RecType, RunContext, SealSigner, StoreHeader, StoreWriter, StreamCrypto, StreamId,
    StreamWriter,
};

use crate::{hex, js};

pub const LEDGER_KIND: &[u8] = b"khemostat-collector-ledger";

pub const KEY_FILE: &str = "key";

#[derive(Debug, Clone)]
pub struct LedgerIds {

    pub engagement: [u8; 16],

    pub host: [u8; 32],

    pub agent: [u8; 16],

    pub instance: [u8; 16],

    pub run_id: u32,

    pub boot: [u8; 16],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunSummary {

    pub run: u64,

    pub genesis: [u8; 32],

    pub tip: [u8; 32],

    pub records: u64,

    pub sealed: bool,
}

pub struct Ledger {
    writer: StreamWriter,
    run: u64,
    dir: PathBuf,
    seal_pub: [u8; 32],
}

impl std::fmt::Debug for Ledger {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ledger").field("run", &self.run).field("dir", &self.dir).finish_non_exhaustive()
    }
}

fn run_name(n: u64) -> String {
    format!("{n:010}")
}

fn run_numbers(ledger_dir: &Path) -> Result<Vec<u64>, String> {
    let mut runs = Vec::new();
    let entries = fs::read_dir(ledger_dir).map_err(|e| format!("cannot list {}: {e}", ledger_dir.display()))?;
    for e in entries {
        let e = e.map_err(|e| format!("cannot list {}: {e}", ledger_dir.display()))?;
        let name = e.file_name().to_string_lossy().into_owned();
        if name == KEY_FILE {
            continue;
        }
        match name.parse::<u64>() {
            Ok(n) if name.len() == 10 && n > 0 => runs.push(n),
            _ => {
                return Err(format!(
                    "the ledger directory holds {}, which the collector does not write; a human must look \
                     before anything is appended",
                    crate::shown(&name)
                ))
            }
        }
    }
    runs.sort_unstable();
    for (i, n) in runs.iter().enumerate() {
        if *n != i as u64 + 1 {
            return Err(format!(
                "the ledger's runs are not numbered 1..{}: run {} is missing — a run was removed",
                runs.len(),
                i + 1
            ));
        }
    }
    Ok(runs)
}

fn ledger_key(ledger_dir: &Path, have_runs: bool, entropy: &mut dyn FnMut() -> std::io::Result<[u8; 32]>) -> Result<[u8; 32], String> {
    let path = ledger_dir.join(KEY_FILE);
    match fs::symlink_metadata(&path) {
        Ok(m) if m.file_type().is_file() => {
            let bytes = fs::read(&path).map_err(|e| format!("cannot read the ledger key: {e}"))?;
            <[u8; 32]>::try_from(bytes.as_slice())
                .map_err(|_| format!("the ledger key is {} bytes, not 32; a human must look", bytes.len()))
        }
        Ok(_) => Err("the ledger key is not a regular file; a human must look".to_string()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            if have_runs {
                return Err("the ledger key is gone and the ledger has runs sealed under it; refusing to start \
                            a second history under a new key"
                    .to_string());
            }
            let seed = entropy().map_err(|e| format!("cannot read entropy for the ledger key: {e}"))?;
            let mut o = fs::OpenOptions::new();
            o.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt as _;
                o.mode(0o600);
            }
            let mut f = o.open(&path).map_err(|e| format!("cannot create the ledger key: {e}"))?;
            f.write_all(&seed).and_then(|()| f.sync_all()).map_err(|e| format!("cannot write the ledger key: {e}"))?;

            crate::set_mode(&path, 0o640).map_err(|e| format!("cannot set the ledger key's mode: {e}"))?;
            Ok(seed)
        }
        Err(e) => Err(format!("cannot look at the ledger key: {e}")),
    }
}

pub fn ledger_public_key(ledger_dir: &Path) -> Result<[u8; 32], String> {
    if fs::symlink_metadata(ledger_dir.join(KEY_FILE)).is_err() {
        return Err(format!("no ledger key under {}: nothing has been ingested here", ledger_dir.display()));
    }
    let seed = ledger_key(ledger_dir, true, &mut || Err(std::io::Error::other("not made here")))?;
    Ok(SealKey::from_seed(seed).public_bytes())
}

#[derive(Debug, Clone)]
pub struct RunRecords {

    pub summary: RunSummary,

    pub records: Vec<Vec<u8>>,
}

fn link_record(run: u64, seal_pub: &[u8; 32], prev: Option<&RunSummary>) -> String {
    let prev = match prev {
        None => "null".to_string(),
        Some(p) => format!(
            "{{\"run\":{},\"genesis\":\"{}\",\"tip\":\"{}\",\"records\":{},\"sealed\":{}}}",
            p.run,
            hex(&p.genesis),
            hex(&p.tip),
            p.records,
            p.sealed
        ),
    };
    format!("{{\"kind\":\"ledger-link\",\"run\":{run},\"ledger_key\":\"{}\",\"prev\":{prev}}}", hex(seal_pub))
}

pub fn audit(ledger_dir: &Path, seal_pub: &[u8; 32]) -> Result<Vec<RunRecords>, String> {
    let runs = run_numbers(ledger_dir)?;
    let mut out: Vec<RunRecords> = Vec::with_capacity(runs.len());
    for n in runs {
        let dir = ledger_dir.join(run_name(n));
        let header = read_store_header(&dir).map_err(|e| format!("ledger run {n}: {e}"))?;
        let key = hemostat_evcrypto::seal::decode_seal_pubkey(&header.variable_tail);
        if key.as_ref() != Some(seal_pub) {
            return Err(format!("ledger run {n} is not sealed under this collector's ledger key"));
        }
        let pk = *seal_pub;
        let check = move |s: &[u8], sig: &[u8]| hemostat_evcrypto::seal::verify_footer(&pk, s, sig);
        let v = load_verified(&dir, &header, StreamId::Custody, Some(&check))
            .map_err(|e| format!("ledger run {n} does not verify: {e}"))?;
        let records: Vec<Vec<u8>> = v.segments.into_iter().flat_map(|s| s.records.into_iter().map(|r| r.stored)).collect();
        let summary = RunSummary {
            run: n,
            genesis: header.genesis(),
            tip: v.report.tip,
            records: v.report.records,
            sealed: v.report.sealed && v.report.signed && v.report.unsealed_records == 0,
        };

        if !records.is_empty() {
            if records.first().map(Vec::as_slice) != Some(LEDGER_KIND) {
                return Err(format!("ledger run {n}: record 0 is not the ledger's kind record"));
            }
            let want = link_record(n, seal_pub, out.last().map(|r| &r.summary));
            if records.get(1).map(Vec::as_slice) != Some(want.as_bytes()) {
                return Err(format!(
                    "ledger run {n}: its link does not match run {} as it verifies now — a run before it \
                     was rewritten, cut short or replaced",
                    n - 1
                ));
            }
        }
        out.push(RunRecords { summary, records });
    }
    Ok(out)
}

impl Ledger {

    pub fn open(
        ledger_dir: &Path,
        ids: &LedgerIds,
        entropy: &mut dyn FnMut() -> std::io::Result<[u8; 32]>,
    ) -> Result<Ledger, String> {
        crate::shared_dir(ledger_dir).map_err(|e| format!("cannot create {}: {e}", ledger_dir.display()))?;
        let have_runs = !run_numbers(ledger_dir)?.is_empty();
        let seed = ledger_key(ledger_dir, have_runs, entropy)?;
        let key = SealKey::from_seed(seed);
        let seal_pub = key.public_bytes();
        let history = audit(ledger_dir, &seal_pub)?;
        let prev = history.last().map(|r| r.summary.clone());
        let run = prev.as_ref().map_or(1, |p| p.run + 1);
        let dir = ledger_dir.join(run_name(run));

        let header = StoreHeader {
            format_ver: 1,
            suite_id: 1,
            engagement_id: ids.engagement,
            host_id: ids.host,
            agent_id: ids.agent,
            created_wall_ns: crate::now_ns(),
            created_mono_ns: 0,
            variable_tail: encode_header_keys(&HeaderKeys { seal_pub: Some(seal_pub), store_pub: None, store_wrap: None }),
        };
        let writer = StoreWriter::create(&dir, header).map_err(|e| format!("cannot start ledger run {run}: {e}"))?;
        let signer: SealSigner = Box::new(move |b| key.sign_footer(b));
        let writer = writer
            .open_stream_with(
                StreamId::Custody,
                RunContext::new(ids.instance, ids.run_id, ids.boot, 1),
                StreamCrypto { signer: Some(signer), cipher: None },
            )
            .map_err(|e| format!("cannot open ledger run {run}: {e}"))?;
        let mut ledger = Ledger { writer, run, dir, seal_pub };
        ledger.append_raw(LEDGER_KIND)?;
        let link = link_record(run, &seal_pub, prev.as_ref());
        ledger.append_raw(link.as_bytes())?;
        Ok(ledger)
    }

    fn append_raw(&mut self, rec: &[u8]) -> Result<(), String> {
        self.writer
            .append(RecType::CUSTODY, 0, rec)
            .map(|_| ())
            .map_err(|e| format!("cannot append to ledger run {}: {e}", self.run))
    }

    pub fn append(&mut self, json: &str) -> Result<(), String> {
        self.append_raw(json.as_bytes())
    }

    pub fn run(&self) -> u64 {
        self.run
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn seal_pub(&self) -> [u8; 32] {
        self.seal_pub
    }

    pub fn close(self) -> Result<(), String> {
        let run = self.run;
        let dir = self.dir.clone();
        self.writer.close().map_err(|e| format!("cannot seal ledger run {run}: {e}"))?;

        crate::share_finished(&dir);
        Ok(())
    }
}

pub fn run_record(verb: &str, actor: &str, source: &str) -> String {
    format!(
        "{{\"kind\":\"run\",\"verb\":{},\"actor\":{},\"source\":{},\"at_ns\":{}}}",
        js(verb),
        js(actor),
        js(source),
        crate::now_ns()
    )
}
