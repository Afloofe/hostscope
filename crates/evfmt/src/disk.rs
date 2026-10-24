use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use crate::header::{AeadAlg, CompAlg, HashAlg, RecType, RecordHeader};
use crate::record::{encode_record, record_hash, Record};
use crate::segment::{Segment, SealPayload, SegmentHeader, StreamId, FOOTER_MAGIC};
use crate::store::{StoreHeader, StoreView};
use crate::FormatError;

#[derive(Debug)]
pub enum StoreError {

    Io(std::io::Error),

    Format(FormatError),
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StoreError::Io(e) => write!(f, "evidence store I/O: {e}"),
            StoreError::Format(e) => write!(f, "evidence store format: {e}"),
        }
    }
}

impl std::error::Error for StoreError {}

impl From<std::io::Error> for StoreError {
    fn from(e: std::io::Error) -> Self {
        StoreError::Io(e)
    }
}

impl From<FormatError> for StoreError {
    fn from(e: FormatError) -> Self {
        StoreError::Format(e)
    }
}

pub type StoreResult<T> = core::result::Result<T, StoreError>;

pub const fn stream_dir_name(s: StreamId) -> &'static str {
    match s {
        StreamId::Evidence => "evidence",
        StreamId::Telemetry => "telemetry",
        StreamId::Journal => "journal",
        StreamId::Custody => "custody",
    }
}

pub const STORE_HEADER_FILE: &str = "store.hdr";

pub trait Clock {

    fn wall_ns(&self) -> i64;

    fn mono_ns(&self) -> u64;
}

#[derive(Debug)]
pub struct SystemClock {
    base: Instant,
}

impl SystemClock {

    pub fn new() -> Self {
        SystemClock { base: Instant::now() }
    }
}

impl Default for SystemClock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock for SystemClock {
    fn wall_ns(&self) -> i64 {
        match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(d) => i64::try_from(d.as_nanos()).unwrap_or(i64::MAX),

            Err(_) => 0,
        }
    }
    fn mono_ns(&self) -> u64 {
        u64::try_from(self.base.elapsed().as_nanos()).unwrap_or(u64::MAX)
    }
}

#[derive(Debug, Clone)]
pub struct RunContext {

    pub instance_id: [u8; 16],

    pub run_id: u32,

    pub boot_id: [u8; 16],

    pub suite_id: u16,

    pub rotate_every: u64,
}

impl RunContext {

    pub fn new(instance_id: [u8; 16], run_id: u32, boot_id: [u8; 16], suite_id: u16) -> Self {
        RunContext {
            instance_id,
            run_id,
            boot_id,
            suite_id,
            rotate_every: 4096,
        }
    }
}

pub trait RecordCipher {

    fn seal(&self, nonce: &[u8; 12], aad: &[u8], pt: &[u8]) -> (Vec<u8>, Vec<u8>);
}

pub trait SegmentCipher {

    fn new_segment(&self, seg_seq: u64) -> StoreResult<(Vec<u8>, Box<dyn RecordCipher>)>;
}

#[derive(Default)]
pub struct StreamCrypto {

    pub signer: Option<crate::SealSigner>,

    pub cipher: Option<Box<dyn SegmentCipher>>,
}

#[derive(Debug)]
pub struct StoreWriter {
    dir: PathBuf,
    header: StoreHeader,
    genesis: [u8; 32],
}

impl StoreWriter {

    pub fn create(dir: impl AsRef<Path>, header: StoreHeader) -> StoreResult<Self> {
        let dir = dir.as_ref().to_path_buf();
        create_dir_private(&dir)?;
        let hdr_path = dir.join(STORE_HEADER_FILE);
        if hdr_path.exists() {
            return Err(StoreError::Io(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                format!("{} already holds an evidence store", dir.display()),
            )));
        }
        write_file_synced(&hdr_path, &header.encode())?;
        sync_dir(&dir);
        let genesis = header.genesis();
        Ok(StoreWriter { dir, header, genesis })
    }

    pub fn header(&self) -> &StoreHeader {
        &self.header
    }

    pub fn genesis(&self) -> [u8; 32] {
        self.genesis
    }

    pub fn open_stream(&self, stream: StreamId, run: RunContext) -> StoreResult<StreamWriter> {
        self.open_stream_with(stream, run, StreamCrypto::default())
    }

    pub fn open_stream_with(
        &self,
        stream: StreamId,
        run: RunContext,
        crypto: StreamCrypto,
    ) -> StoreResult<StreamWriter> {
        self.open_stream_clocked(stream, run, crypto, Box::new(SystemClock::new()))
    }

    pub fn open_stream_clocked(
        &self,
        stream: StreamId,
        run: RunContext,
        crypto: StreamCrypto,
        clock: Box<dyn Clock>,
    ) -> StoreResult<StreamWriter> {
        let sdir = self.dir.join(stream_dir_name(stream));
        create_dir_private(&sdir)?;
        let mut w = StreamWriter {
            sdir,
            stream,
            engagement_id: self.header.engagement_id,
            agent_id: self.header.agent_id,
            genesis: self.genesis,
            run,
            clock,
            signer: crypto.signer,
            cipher: crypto.cipher,
            rec_cipher: None,
            seg_seq: 0,
            cur_header: None,
            file: None,
            records_in_seg: 0,
            seq_global: 0,
            counter: 0,
            tip: self.genesis,
            closed: false,
        };
        w.open_segment(0, self.genesis)?;
        Ok(w)
    }
}

pub struct StreamWriter {
    sdir: PathBuf,
    stream: StreamId,
    engagement_id: [u8; 16],
    agent_id: [u8; 16],
    genesis: [u8; 32],
    run: RunContext,
    clock: Box<dyn Clock>,
    signer: Option<crate::SealSigner>,
    cipher: Option<Box<dyn SegmentCipher>>,
    rec_cipher: Option<Box<dyn RecordCipher>>,
    seg_seq: u64,
    cur_header: Option<SegmentHeader>,
    file: Option<File>,
    records_in_seg: u64,
    seq_global: u64,
    counter: u64,
    tip: [u8; 32],
    closed: bool,
}

impl StreamWriter {
    fn seg_path(&self, seq: u64) -> PathBuf {
        self.sdir.join(format!("seg-{seq:010}.hcs"))
    }

    fn prepare_header(
        &self,
        seg_seq: u64,
        prev_tail: [u8; 32],
    ) -> StoreResult<(SegmentHeader, Option<Box<dyn RecordCipher>>)> {
        let (variable_tail, rec_cipher) = match &self.cipher {
            Some(c) => {
                let (tail, rc) = c.new_segment(seg_seq)?;
                (tail, Some(rc))
            }
            None => (Vec::new(), None),
        };
        let header = SegmentHeader {
            format_ver: 1,
            suite_id: self.run.suite_id,
            stream_id: self.stream,
            segment_seq: seg_seq,
            engagement_id: self.engagement_id,
            agent_id: self.agent_id,
            instance_id: self.run.instance_id,
            run_id: self.run.run_id,
            store_header_hash: self.genesis,
            prev_segment_tail_hash: prev_tail,
            created_wall_ns: self.clock.wall_ns(),
            created_mono_ns: self.clock.mono_ns(),
            boot_id: self.run.boot_id,
            variable_tail,
        };
        Ok((header, rec_cipher))
    }

    fn open_segment(&mut self, seg_seq: u64, prev_tail: [u8; 32]) -> StoreResult<()> {
        let (header, rec_cipher) = self.prepare_header(seg_seq, prev_tail)?;
        let mut f = create_new_file(&self.seg_path(seg_seq))?;
        f.write_all(&header.encode())?;
        f.sync_all()?;
        sync_dir(&self.sdir);
        self.tip = header.hash();
        self.cur_header = Some(header);
        self.file = Some(f);
        self.rec_cipher = rec_cipher;
        self.seg_seq = seg_seq;
        self.records_in_seg = 0;
        Ok(())
    }

    pub fn append(&mut self, rec_type: RecType, flags: u8, payload: &[u8]) -> StoreResult<u64> {
        if self.closed {
            return Err(StoreError::Io(std::io::Error::other("append to a closed stream")));
        }
        let len = u32::try_from(payload.len()).map_err(|_| {
            StoreError::Format(FormatError::TooLarge { len: payload.len() })
        })?;

        let mut nonce = [0u8; 12];
        nonce[0..4].copy_from_slice(&self.run.run_id.to_le_bytes());
        nonce[4..12].copy_from_slice(&self.counter.to_le_bytes());

        let encrypting = self.rec_cipher.is_some();
        let header = RecordHeader {
            rec_type,
            flags: if encrypting { flags | crate::header::flags::ENCRYPTED } else { flags },
            hash_alg: HashAlg::Sha256,
            aead_alg: if encrypting { AeadAlg::Aes256Gcm } else { AeadAlg::None },
            comp_alg: CompAlg::None,
            seq: self.seq_global,
            ts_wall_ns: self.clock.wall_ns(),
            ts_mono_ns: self.clock.mono_ns(),
            boot_id: self.run.boot_id,
            nonce,
            prev_hash: self.tip,
            payload_plain_len: len,
            payload_stored_len: len,
        };
        let (stored, tag) = match &self.rec_cipher {
            Some(rc) => rc.seal(&nonce, &header.encode(), payload),
            None => (payload.to_vec(), Vec::new()),
        };
        let rec = Record { header, stored, tag };
        let bytes = encode_record(&rec)?;

        let f = self.file.as_mut().ok_or_else(|| {
            StoreError::Io(std::io::Error::other("no open segment"))
        })?;
        f.write_all(&bytes)?;
        f.sync_all()?;

        self.tip = record_hash(&rec.header.encode(), &rec.stored, &rec.tag);
        let written = self.seq_global;
        self.seq_global += 1;
        self.counter += 1;
        self.records_in_seg += 1;

        if self.records_in_seg >= self.run.rotate_every {
            self.rotate()?;
        }
        Ok(written)
    }

    fn rotate(&mut self) -> StoreResult<()> {
        let next_seq = self.seg_seq + 1;

        let (next_header, next_rc) = self.prepare_header(next_seq, self.tip)?;
        let next_hash = next_header.hash();

        let mut f = create_new_file(&self.seg_path(next_seq))?;
        f.write_all(&next_header.encode())?;
        f.sync_all()?;
        sync_dir(&self.sdir);

        self.write_footer(Some(next_hash), false)?;
        self.tip = next_hash;
        self.cur_header = Some(next_header);
        self.file = Some(f);
        self.rec_cipher = next_rc;
        self.seg_seq = next_seq;
        self.records_in_seg = 0;
        Ok(())
    }

    fn write_footer(&mut self, next_header_hash: Option<[u8; 32]>, sealed_late: bool) -> StoreResult<()> {
        let cur = self.cur_header.as_ref().ok_or_else(|| {
            StoreError::Io(std::io::Error::other("no open segment to seal"))
        })?;
        let mut footer = SealPayload {
            segment_seq: self.seg_seq,
            record_count: self.records_in_seg,
            tip_hash: self.tip,
            header_hash: cur.hash(),
            next_header_hash,
            ts_sealed_wall: self.clock.wall_ns(),
            ts_sealed_mono: self.clock.mono_ns(),
            boot_id: self.run.boot_id,
            suite_id: self.run.suite_id,
            sealed_late,
            signature: Vec::new(),
        };

        if let Some(sign) = &self.signer {
            let sig = sign(&footer.signable_bytes());
            if sig.is_empty() {
                return Err(StoreError::Io(std::io::Error::other(
                    "seal signer produced an empty signature",
                )));
            }
            footer.signature = sig;
        }
        let f = self.file.as_mut().ok_or_else(|| {
            StoreError::Io(std::io::Error::other("no open segment file"))
        })?;
        f.write_all(&footer.encode())?;
        f.sync_all()?;
        Ok(())
    }

    pub fn close(mut self) -> StoreResult<()> {
        if !self.closed {
            self.write_footer(None, false)?;
            self.closed = true;
        }
        Ok(())
    }

    pub fn records_written(&self) -> u64 {
        self.seq_global
    }

    pub fn tip(&self) -> [u8; 32] {
        self.tip
    }
}

fn frame_runs_past_eof(rest: &[u8]) -> bool {
    let Some(prefix) = rest.get(0..4).and_then(|b| <[u8; 4]>::try_from(b).ok()) else {
        return false;
    };
    (u32::from_le_bytes(prefix) as usize)
        .checked_add(8)
        .is_none_or(|total| total > rest.len())
}

fn record_ends_at_eof(rest: &[u8]) -> bool {
    let Some(prefix) = rest.get(0..4).and_then(|b| <[u8; 4]>::try_from(b).ok()) else {
        return false;
    };
    let body_len = u32::from_le_bytes(prefix) as usize;
    body_len
        .checked_add(8)
        .is_some_and(|total| total == rest.len())
}

pub fn parse_segment(bytes: &[u8]) -> StoreResult<Segment> {
    let (header, mut off) = SegmentHeader::decode(bytes)?;

    let encoded = header.encode();
    if bytes.get(..off) != Some(encoded.as_slice()) {
        return Err(StoreError::Format(FormatError::SealMismatch {
            segment_seq: header.segment_seq,
            what: "the header bytes on disk are not what this header re-encodes to — \
                   a byte outside the modelled fields has been set",
        }));
    }
    let mut records = Vec::new();

    loop {
        let rest = bytes.get(off..).unwrap_or_default();

        if rest.len() < 4 {
            return Ok(Segment { header, records, footer: None });
        }
        if rest.starts_with(&FOOTER_MAGIC) {
            let (footer, n) = match SealPayload::decode(rest) {
                Ok(f) => f,

                Err(FormatError::Truncated { .. }) => {
                    return Ok(Segment { header, records, footer: None });
                }
                Err(e) => return Err(e.into()),
            };

            if rest.get(..n) != Some(footer.encode().as_slice()) {
                return Err(StoreError::Format(FormatError::SealMismatch {
                    segment_seq: header.segment_seq,
                    what: "the footer bytes on disk are not what this footer re-encodes to",
                }));
            }

            if rest.len() != n {
                return Err(StoreError::Format(FormatError::SealMismatch {
                    segment_seq: header.segment_seq,
                    what: "there are bytes after the seal",
                }));
            }
            return Ok(Segment { header, records, footer: Some(footer) });
        }
        match crate::record::decode_record(rest) {
            Ok((rec, n)) => {
                records.push(rec);
                off += n;
            }

            Err(FormatError::Truncated { .. }) if frame_runs_past_eof(rest) => {
                return Ok(Segment { header, records, footer: None });
            }

            Err(FormatError::BadCrc { .. }) if record_ends_at_eof(rest) => {
                return Ok(Segment { header, records, footer: None });
            }
            Err(e) => return Err(e.into()),
        }
    }
}

pub fn read_store_header(dir: impl AsRef<Path>) -> StoreResult<StoreHeader> {
    let bytes = read_regular(&dir.as_ref().join(STORE_HEADER_FILE))?;
    let (header, n) = StoreHeader::decode(&bytes)?;

    if n != bytes.len() || bytes != header.encode() {
        return Err(StoreError::Format(FormatError::NotCanonical { what: "store header" }));
    }
    Ok(header)
}

pub(crate) fn read_regular(path: &Path) -> std::io::Result<Vec<u8>> {
    use std::io::Read as _;
    let not_regular = |what: &str| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("{} is {what}, not a regular file; refusing to read it", path.display()),
        )
    };
    let before = fs::symlink_metadata(path)?;
    let ft = before.file_type();
    if ft.is_symlink() {
        return Err(not_regular("a symlink"));
    }
    if !ft.is_file() {
        return Err(not_regular("a special file"));
    }
    let mut f = File::open(path)?;
    let after = f.metadata()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        if (before.dev(), before.ino()) != (after.dev(), after.ino()) {
            return Err(not_regular("a different file from the one checked"));
        }
    }
    if !after.is_file() {
        return Err(not_regular("a special file"));
    }
    let mut bytes = Vec::with_capacity(usize::try_from(after.len()).unwrap_or(0));
    f.read_to_end(&mut bytes)?;
    Ok(bytes)
}

pub fn load_stream(dir: impl AsRef<Path>, stream: StreamId) -> StoreResult<Vec<Segment>> {
    let sdir = dir.as_ref().join(stream_dir_name(stream));

    match fs::metadata(&sdir) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e.into()),
        Ok(m) if !m.is_dir() => {
            return Err(StoreError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("{} is not a directory", sdir.display()),
            )))
        }
        Ok(_) => {}
    }
    let files = segment_files(fs::read_dir(&sdir)?.map(|e| e.map(|e| e.path())))?;

    let mut segments: Vec<Segment> = Vec::with_capacity(files.len());
    let last = files.len().saturating_sub(1);
    for (i, p) in files.into_iter().enumerate() {
        let bytes = read_regular(&p)?;

        if i == last
            && matches!(SegmentHeader::decode(&bytes), Err(FormatError::Truncated { .. }))
            && segments.last().is_some_and(|prev| prev.footer.is_none())
        {
            break;
        }
        let seg = parse_segment(&bytes)?;

        if seg.header.stream_id != stream {
            return Err(FormatError::SegmentDiscontinuity {
                segment_seq: seg.header.segment_seq,
                what: "segment stream_id does not match the stream it was loaded from",
            }
            .into());
        }
        segments.push(seg);
    }
    Ok(segments)
}

fn segment_files(entries: impl Iterator<Item = std::io::Result<PathBuf>>) -> std::io::Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    for entry in entries {
        let p = entry?;
        if p.file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.starts_with("seg-") && n.ends_with(".hcs"))
        {
            files.push(p);
        }
    }

    files.sort();
    Ok(files)
}

#[derive(Debug, Clone)]
pub struct VerifyReport {

    pub stream: StreamId,

    pub segments: usize,

    pub records: u64,

    pub tip: [u8; 32],

    pub sealed: bool,

    pub signed: bool,

    pub unsealed_records: u64,
}

pub fn verify_stream_dir(dir: impl AsRef<Path>, stream: StreamId) -> StoreResult<VerifyReport> {
    verify_stream_dir_impl(dir, stream, None)
}

pub fn verify_stream_dir_signed(
    dir: impl AsRef<Path>,
    stream: StreamId,
    verify_seal: &crate::SealVerify,
) -> StoreResult<VerifyReport> {
    verify_stream_dir_impl(dir, stream, Some(verify_seal))
}

fn verify_stream_dir_impl(
    dir: impl AsRef<Path>,
    stream: StreamId,
    verify_seal: Option<&crate::SealVerify>,
) -> StoreResult<VerifyReport> {
    let header = read_store_header(&dir)?;
    Ok(load_verified(dir, &header, stream, verify_seal)?.report)
}

#[derive(Debug, Clone)]
pub struct VerifiedStream {

    pub report: VerifyReport,

    pub segments: Vec<Segment>,
}

pub fn load_verified(
    dir: impl AsRef<Path>,
    header: &StoreHeader,
    stream: StreamId,
    verify_seal: Option<&crate::SealVerify>,
) -> StoreResult<VerifiedStream> {
    let segments = load_stream(&dir, stream)?;
    let view = StoreView {
        header,
        segments: &segments,
    };
    let tip = match verify_seal {
        Some(v) => view.verify_signed(v)?,
        None => view.verify()?,
    };
    let records = segments.iter().map(|s| s.records.len() as u64).sum();
    let sealed = segments.last().is_some_and(|s| s.footer.is_some());
    let signed = segments
        .last()
        .and_then(|s| s.footer.as_ref())
        .is_some_and(|f| !f.signature.is_empty());

    let unsealed_records = segments
        .iter()
        .filter(|s| s.footer.is_none())
        .map(|s| s.records.len() as u64)
        .sum();
    let report = VerifyReport {
        stream,
        segments: segments.len(),
        records,
        tip,
        sealed,
        signed,
        unsealed_records,
    };
    Ok(VerifiedStream { report, segments })
}

pub(crate) fn create_new_file(path: &Path) -> std::io::Result<File> {
    let mut o = fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        o.mode(0o600);
    }
    o.open(path).map_err(|e| {

        if e.kind() == std::io::ErrorKind::AlreadyExists {
            let what = match fs::symlink_metadata(path) {
                Ok(m) if m.file_type().is_symlink() => {
                    " — it is a SYMLINK, which is how an attacker redirects a write to a \
                     file they want destroyed; nothing was written"
                }
                Ok(_) => " — it already exists; nothing was written",
                Err(_) => " — it already exists; nothing was written",
            };
            return std::io::Error::new(
                e.kind(),
                format!("refusing to create {}{what}", path.display()),
            );
        }
        e
    })
}

pub(crate) fn create_dir_private(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt as _, PermissionsExt as _};
        let mut missing = Vec::new();
        let mut p = path;
        while !p.as_os_str().is_empty() && fs::symlink_metadata(p).is_err() {
            missing.push(p);
            p = p.parent().unwrap_or(Path::new(""));
        }
        for d in missing.into_iter().rev() {
            match fs::DirBuilder::new().mode(0o700).create(d) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(e),
            }
            let f = File::open(d)?;
            if f.metadata()?.is_dir() {
                f.set_permissions(fs::Permissions::from_mode(0o700))?;
            }
        }

        fs::DirBuilder::new().recursive(true).create(path)
    }
    #[cfg(not(unix))]
    {
        fs::create_dir_all(path)
    }
}

pub(crate) fn write_file_synced(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut f = create_new_file(path)?;
    f.write_all(bytes)?;
    f.sync_all()
}

pub(crate) fn sync_dir(dir: &Path) {
    if let Ok(f) = File::open(dir) {
        let _ = f.sync_all();
    }
}
