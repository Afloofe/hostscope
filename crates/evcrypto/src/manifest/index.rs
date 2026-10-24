use coset::iana;
use coset::{CborSerializable as _, CoseSign1, RegisteredLabelWithPrivate};
use ed25519_dalek::{Signature, VerifyingKey};

const BLOCK: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct Paths {
    data: Vec<u8>,

    blocks: Vec<u32>,
    len: usize,
}

fn put_varint(out: &mut Vec<u8>, mut n: usize) {
    loop {
        let b = (n & 0x7f) as u8;
        n >>= 7;
        if n == 0 {
            out.push(b);
            return;
        }
        out.push(b | 0x80);
    }
}

fn get_varint(data: &[u8], at: &mut usize) -> usize {
    let mut n = 0usize;
    let mut shift = 0;
    while let Some(&b) = data.get(*at) {
        *at += 1;
        n |= usize::from(b & 0x7f) << shift;
        if b & 0x80 == 0 {
            break;
        }
        shift += 7;
    }
    n
}

impl Paths {

    pub(crate) fn from_sorted<'a>(sorted: impl Iterator<Item = &'a str>) -> Result<Paths, String> {
        let mut p = Paths::default();
        let mut prev: &str = "";
        for s in sorted {
            if p.len % BLOCK == 0 {
                p.blocks.push(u32::try_from(p.data.len()).map_err(|_| "the paths exceed 4 GiB")?);
                put_varint(&mut p.data, s.len());
                p.data.extend_from_slice(s.as_bytes());
            } else {
                let shared = prev.bytes().zip(s.bytes()).take_while(|(a, b)| a == b).count();
                put_varint(&mut p.data, shared);
                let rest = s.as_bytes().get(shared..).unwrap_or_default();
                put_varint(&mut p.data, rest.len());
                p.data.extend_from_slice(rest);
            }
            prev = s;
            p.len += 1;
        }
        p.data.shrink_to_fit();
        p.blocks.shrink_to_fit();
        Ok(p)
    }

    pub(crate) fn len(&self) -> usize {
        self.len
    }

    fn scan_block(&self, b: usize, mut f: impl FnMut(usize, &[u8]) -> bool) {
        let Some(&start) = self.blocks.get(b) else { return };
        let mut at = start as usize;
        let mut cur: Vec<u8> = Vec::with_capacity(128);
        for k in 0..BLOCK {
            let i = b * BLOCK + k;
            if i >= self.len {
                return;
            }
            if k == 0 {
                let n = get_varint(&self.data, &mut at);
                cur.clear();
                cur.extend_from_slice(self.data.get(at..at + n).unwrap_or_default());
                at += n;
            } else {
                let shared = get_varint(&self.data, &mut at);
                let n = get_varint(&self.data, &mut at);
                cur.truncate(shared);
                cur.extend_from_slice(self.data.get(at..at + n).unwrap_or_default());
                at += n;
            }
            if !f(i, &cur) {
                return;
            }
        }
    }

    fn head(&self, b: usize) -> &[u8] {
        let Some(&start) = self.blocks.get(b) else { return &[] };
        let mut at = start as usize;
        let n = get_varint(&self.data, &mut at);
        self.data.get(at..at + n).unwrap_or_default()
    }

    #[cfg(test)]
    pub(crate) fn get(&self, i: usize) -> String {
        let mut out = String::new();
        self.scan_block(i / BLOCK, |j, p| {
            if j == i {
                out = String::from_utf8_lossy(p).into_owned();
                return false;
            }
            true
        });
        out
    }

    pub(crate) fn find(&self, path: &str) -> Option<usize> {
        let want = path.as_bytes();

        let (mut lo, mut hi) = (0usize, self.blocks.len());
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            if self.head(mid) <= want {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        let b = lo.checked_sub(1)?;
        let mut found = None;
        self.scan_block(b, |i, p| match p.cmp(want) {
            core::cmp::Ordering::Less => true,
            core::cmp::Ordering::Equal => {
                found = Some(i);
                false
            }
            core::cmp::Ordering::Greater => false,
        });
        found
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = String> + '_ {
        let mut at = 0usize;
        let mut cur: Vec<u8> = Vec::new();
        (0..self.len).map(move |i| {
            if i % BLOCK == 0 {
                let n = get_varint(&self.data, &mut at);
                cur.clear();
                cur.extend_from_slice(self.data.get(at..at + n).unwrap_or_default());
                at += n;
            } else {
                let shared = get_varint(&self.data, &mut at);
                let n = get_varint(&self.data, &mut at);
                cur.truncate(shared);
                cur.extend_from_slice(self.data.get(at..at + n).unwrap_or_default());
                at += n;
            }
            String::from_utf8_lossy(&cur).into_owned()
        })
    }
}

#[derive(Debug)]
pub struct Signed {
    buf: Vec<u8>,
    start: usize,
}

impl Signed {

    pub fn payload(&self) -> &[u8] {
        self.buf.get(self.start..).unwrap_or_default()
    }
}

#[derive(Debug)]
pub enum SignedRead {

    Read(String),

    Signature,
}

fn cbor_head(major: u8, n: u64, out: &mut Vec<u8>) {
    let m = major << 5;
    match n {
        0..=23 => out.push(m | n as u8),
        24..=0xff => out.extend_from_slice(&[m | 24, n as u8]),
        0x100..=0xffff => {
            out.push(m | 25);
            out.extend_from_slice(&(n as u16).to_be_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            out.push(m | 26);
            out.extend_from_slice(&(n as u32).to_be_bytes());
        }
        _ => {
            out.push(m | 27);
            out.extend_from_slice(&n.to_be_bytes());
        }
    }
}

pub(crate) fn sig_prefix(protected: &[u8], context: &[u8], len: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(32 + protected.len() + context.len());
    cbor_head(4, 4, &mut out);
    cbor_head(3, 10, &mut out);
    out.extend_from_slice(b"Signature1");
    cbor_head(2, protected.len() as u64, &mut out);
    out.extend_from_slice(protected);
    cbor_head(2, context.len() as u64, &mut out);
    out.extend_from_slice(context);
    cbor_head(2, len, &mut out);
    out
}

pub fn read_signed(
    public: &[u8; 32],
    cose: &[u8],
    context: &[u8],
    len: u64,
    fill: impl FnOnce(&mut Vec<u8>) -> std::io::Result<()>,
) -> Result<Signed, SignedRead> {
    let vk = VerifyingKey::from_bytes(public).map_err(|_| SignedRead::Signature)?;
    let sign1 = CoseSign1::from_slice(cose).map_err(|_| SignedRead::Signature)?;
    if !matches!(sign1.protected.header.alg, Some(RegisteredLabelWithPrivate::Assigned(iana::Algorithm::EdDSA)))
        || sign1.payload.is_some()
    {
        return Err(SignedRead::Signature);
    }
    let protected = sign1.protected.original_data.as_deref().ok_or(SignedRead::Signature)?;
    let sig = Signature::from_slice(&sign1.signature).map_err(|_| SignedRead::Signature)?;
    let mut buf = sig_prefix(protected, context, len);
    let start = buf.len();
    let cap = usize::try_from(len).map_err(|_| SignedRead::Read("too large for this platform".into()))?;
    buf.try_reserve_exact(cap).map_err(|e| SignedRead::Read(e.to_string()))?;
    fill(&mut buf).map_err(|e| SignedRead::Read(e.to_string()))?;
    if (buf.len() - start) as u64 != len {
        return Err(SignedRead::Read(format!("read {} bytes, expected {len}", buf.len() - start)));
    }
    vk.verify_strict(&buf, &sig).map_err(|_| SignedRead::Signature)?;
    Ok(Signed { buf, start })
}

pub(crate) fn verify_bytes(public: &[u8; 32], payload: &[u8], cose: &[u8], context: &[u8]) -> bool {
    read_signed(public, cose, context, payload.len() as u64, |b| {
        b.extend_from_slice(payload);
        Ok(())
    })
    .is_ok()
}
