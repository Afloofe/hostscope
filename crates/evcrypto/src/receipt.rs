use coset::iana;
use coset::{CborSerializable as _, CoseSign1Builder, HeaderBuilder};
use ed25519_dalek::{Signer as _, SigningKey};

pub const RECEIPT_CONTEXT: &[u8] = b"hemostat/receipt/v1";

const PAYLOAD_MAGIC: &[u8; 4] = b"HRC1";

const FIXED: usize = 4 + 16 + 32 + 32 + 8 + 1;

const PER_STREAM: usize = 1 + 8 + 32;

pub const MAX_STREAMS: usize = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReceiptStream {

    pub stream: u8,

    pub max_seq: u64,

    pub tip: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Receipt {

    pub engagement_id: [u8; 16],

    pub host_id: [u8; 32],

    pub genesis: [u8; 32],

    pub received_ns: i64,

    pub streams: Vec<ReceiptStream>,
}

impl Receipt {

    pub fn payload(&self) -> Option<Vec<u8>> {
        if self.streams.is_empty() || self.streams.len() > MAX_STREAMS {
            return None;
        }
        if self.streams.windows(2).any(|w| matches!(w, [a, b] if a.stream >= b.stream)) {
            return None;
        }
        let mut out = Vec::with_capacity(FIXED + PER_STREAM * self.streams.len());
        out.extend_from_slice(PAYLOAD_MAGIC);
        out.extend_from_slice(&self.engagement_id);
        out.extend_from_slice(&self.host_id);
        out.extend_from_slice(&self.genesis);
        out.extend_from_slice(&self.received_ns.to_be_bytes());
        out.push(u8::try_from(self.streams.len()).ok()?);
        for s in &self.streams {
            out.push(s.stream);
            out.extend_from_slice(&s.max_seq.to_be_bytes());
            out.extend_from_slice(&s.tip);
        }
        Some(out)
    }

    fn decode(p: &[u8]) -> Result<Receipt, Refused> {
        fn take<const N: usize>(p: &[u8], at: &mut usize) -> Result<[u8; N], Refused> {
            let b = p.get(*at..at.saturating_add(N)).ok_or(Refused::Shape("the payload ends mid-field"))?;
            *at += N;
            <[u8; N]>::try_from(b).map_err(|_| Refused::Shape("the payload ends mid-field"))
        }
        let mut at = 0;
        if &take::<4>(p, &mut at)? != PAYLOAD_MAGIC {
            return Err(Refused::Shape("not a receipt payload this version reads"));
        }
        let engagement_id = take::<16>(p, &mut at)?;
        let host_id = take::<32>(p, &mut at)?;
        let genesis = take::<32>(p, &mut at)?;
        let received_ns = i64::from_be_bytes(take::<8>(p, &mut at)?);
        let [n] = take::<1>(p, &mut at)?;
        let n = usize::from(n);
        if n == 0 || n > MAX_STREAMS {
            return Err(Refused::Shape("a receipt names one to four streams"));
        }
        if p.len() != FIXED + PER_STREAM * n {
            return Err(Refused::Shape("the payload is not the length its stream count gives"));
        }
        let mut streams = Vec::with_capacity(n);
        for _ in 0..n {
            let [stream] = take::<1>(p, &mut at)?;
            let max_seq = u64::from_be_bytes(take::<8>(p, &mut at)?);
            let tip = take::<32>(p, &mut at)?;
            streams.push(ReceiptStream { stream, max_seq, tip });
        }
        if streams.windows(2).any(|w| matches!(w, [a, b] if a.stream >= b.stream)) {
            return Err(Refused::Shape("the streams are not strictly ascending"));
        }
        Ok(Receipt { engagement_id, host_id, genesis, received_ns, streams })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refused {

    Framing(&'static str),

    Signature,

    Shape(&'static str),
}

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Refused::Framing(w) => write!(f, "not a receipt: {w}"),
            Refused::Signature => write!(
                f,
                "the receipt does not verify under the pinned receipt key; nothing in it was read \
                 (it is not from the collector this agent pinned, or it was changed in flight)"
            ),
            Refused::Shape(w) => write!(f, "the receipt verified and its payload is malformed: {w}"),
        }
    }
}

pub struct ReceiptKey {
    signing: SigningKey,
}

impl ReceiptKey {

    pub fn from_seed(mut seed: [u8; 32]) -> Self {
        let signing = SigningKey::from_bytes(&seed);
        seed.fill(0);
        ReceiptKey { signing }
    }

    pub fn public_bytes(&self) -> [u8; 32] {
        self.signing.verifying_key().to_bytes()
    }

    pub fn sign(&self, r: &Receipt) -> Option<Vec<u8>> {
        let payload = r.payload()?;
        let protected = HeaderBuilder::new().algorithm(iana::Algorithm::EdDSA).build();
        let cose = CoseSign1Builder::new()
            .protected(protected)
            .create_detached_signature(&payload, RECEIPT_CONTEXT, |tbs| self.signing.sign(tbs).to_vec())
            .build()
            .to_vec()
            .ok()?;
        let mut out = Vec::with_capacity(4 + payload.len() + cose.len());
        out.extend_from_slice(&u32::try_from(payload.len()).ok()?.to_be_bytes());
        out.extend_from_slice(&payload);
        out.extend_from_slice(&cose);
        Some(out)
    }
}

pub const MAX_WIRE: usize = 4096;

pub fn open(receipt_key: &[u8; 32], wire: &[u8]) -> Result<Receipt, Refused> {
    if wire.len() > MAX_WIRE {
        return Err(Refused::Framing("over the receipt size bound"));
    }
    let len = wire.get(..4).and_then(|b| <[u8; 4]>::try_from(b).ok()).ok_or(Refused::Framing("too short"))?;
    let len = u32::from_be_bytes(len) as usize;
    let payload = wire.get(4..4usize.saturating_add(len)).ok_or(Refused::Framing("the payload length runs past the end"))?;
    let cose = wire.get(4 + len..).unwrap_or_default();
    if cose.is_empty() {
        return Err(Refused::Framing("no signature"));
    }
    if !crate::manifest::verify_with(receipt_key, payload, cose, RECEIPT_CONTEXT) {
        return Err(Refused::Signature);
    }

    let canonical = coset::CoseSign1::from_slice(cose).ok().and_then(|c| c.to_vec().ok());
    if canonical.as_deref() != Some(cose) {
        return Err(Refused::Framing("the signature is not in the one encoding the collector writes"));
    }
    Receipt::decode(payload)
}
