use coset::iana;
use coset::{CborSerializable as _, CoseSign1, CoseSign1Builder, HeaderBuilder, RegisteredLabelWithPrivate};
use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};

pub const TICKET_CONTEXT: &[u8] = b"hemostat/ticket/v1";

pub const TICKET_CONTEXT_V2: &[u8] = b"hemostat/ticket/v2";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Op {

    Action = 1,

    Lift = 2,

    Uninstall = 3,

    Undo = 4,

    Export = 5,
}

impl Op {

    pub const fn code(self) -> u8 {
        self as u8
    }

    pub const fn from_code(c: u8) -> Option<Self> {
        match c {
            1 => Some(Op::Action),
            2 => Some(Op::Lift),
            3 => Some(Op::Uninstall),
            4 => Some(Op::Undo),
            5 => Some(Op::Export),
            _ => None,
        }
    }

    pub const fn token(self) -> &'static str {
        match self {
            Op::Action => "action",
            Op::Lift => "lift",
            Op::Uninstall => "uninstall",
            Op::Undo => "undo",
            Op::Export => "export",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Claims {

    pub version: u8,

    pub op: Op,

    pub class: u8,

    pub engagement: [u8; 16],

    pub host: [u8; 32],

    pub nonce: [u8; 16],

    pub not_after: i64,
}

pub const NO_CLASS: u8 = 0xFF;

pub const CLAIMS_LEN: usize = 1 + 1 + 1 + 16 + 32 + 16 + 8;

impl Claims {

    pub fn encode(&self) -> [u8; CLAIMS_LEN] {
        let mut out = [0u8; CLAIMS_LEN];
        out[0] = self.version;
        out[1] = self.op.code();
        out[2] = self.class;
        out[3..19].copy_from_slice(&self.engagement);
        out[19..51].copy_from_slice(&self.host);
        out[51..67].copy_from_slice(&self.nonce);
        out[67..75].copy_from_slice(&self.not_after.to_be_bytes());
        out
    }

    pub fn decode(b: &[u8]) -> Option<Self> {
        if b.len() != CLAIMS_LEN {
            return None;
        }
        let mut engagement = [0u8; 16];
        let mut host = [0u8; 32];
        let mut nonce = [0u8; 16];
        engagement.copy_from_slice(b.get(3..19)?);
        host.copy_from_slice(b.get(19..51)?);
        nonce.copy_from_slice(b.get(51..67)?);
        let mut na = [0u8; 8];
        na.copy_from_slice(b.get(67..75)?);
        Some(Claims {
            version: *b.first()?,
            op: Op::from_code(*b.get(1)?)?,
            class: *b.get(2)?,
            engagement,
            host,
            nonce,
            not_after: i64::from_be_bytes(na),
        })
    }
}

pub const VERSION: u8 = 1;

pub const VERSION_V2: u8 = 2;

pub const CLAIMS_LEN_V2: usize = CLAIMS_LEN + 32;

pub const PERIMETER_CLASSES: [u8; 2] = [22, 23];

pub const fn requires_v2(class: u8) -> bool {
    class == PERIMETER_CLASSES[0] || class == PERIMETER_CLASSES[1]
}

pub const fn claims_len(version: u8) -> Option<usize> {
    match version {
        VERSION => Some(CLAIMS_LEN),
        VERSION_V2 => Some(CLAIMS_LEN_V2),
        _ => None,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Dir {

    Out = 1,

    In = 2,
}

impl Dir {

    pub const fn code(self) -> u8 {
        self as u8
    }

    pub const fn token(self) -> &'static str {
        match self {
            Dir::Out => "out",
            Dir::In => "in",
        }
    }
}

pub fn operand(class: u8, host: &[u8; 32], alias: &str, dir: Dir, cidr: &str) -> [u8; 32] {
    use sha2::{Digest as _, Sha256};
    let len16 = |s: &str| u16::try_from(s.len()).unwrap_or(u16::MAX).to_be_bytes();
    let mut h = Sha256::new();
    h.update([class]);
    h.update(host);
    h.update(len16(alias));
    h.update(alias.as_bytes());
    h.update([dir.code()]);
    h.update(len16(cidr));
    h.update(cidr.as_bytes());
    h.finalize().into()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClaimsV2 {

    pub claims: Claims,

    pub operand: [u8; 32],
}

impl ClaimsV2 {

    pub fn encode(&self) -> [u8; CLAIMS_LEN_V2] {
        let mut out = [0u8; CLAIMS_LEN_V2];
        let mut base = self.claims;
        base.version = VERSION_V2;
        out[..CLAIMS_LEN].copy_from_slice(&base.encode());
        out[CLAIMS_LEN..].copy_from_slice(&self.operand);
        out
    }

    pub fn decode(b: &[u8]) -> Option<Self> {
        if b.len() != CLAIMS_LEN_V2 || b.first() != Some(&VERSION_V2) {
            return None;
        }

        let claims = Claims::decode(b.get(..CLAIMS_LEN)?)?;
        let mut operand = [0u8; 32];
        operand.copy_from_slice(b.get(CLAIMS_LEN..)?);
        Some(ClaimsV2 { claims, operand })
    }
}

pub struct ResponderKey {
    signing: SigningKey,
}

impl ResponderKey {

    pub fn from_seed(seed: [u8; 32]) -> Self {
        ResponderKey { signing: SigningKey::from_bytes(&seed) }
    }

    pub fn public_bytes(&self) -> [u8; 32] {
        self.signing.verifying_key().to_bytes()
    }

    pub fn mint(&self, claims: &Claims) -> Vec<u8> {
        let protected = HeaderBuilder::new().algorithm(iana::Algorithm::EdDSA).build();
        CoseSign1Builder::new()
            .protected(protected)
            .create_detached_signature(&claims.encode(), TICKET_CONTEXT, |tbs| {
                self.signing.sign(tbs).to_vec()
            })
            .build()
            .to_vec()
            .unwrap_or_default()
    }

    pub fn mint_v2(&self, claims: &ClaimsV2) -> Vec<u8> {
        let protected = HeaderBuilder::new().algorithm(iana::Algorithm::EdDSA).build();
        CoseSign1Builder::new()
            .protected(protected)
            .create_detached_signature(&claims.encode(), TICKET_CONTEXT_V2, |tbs| {
                self.signing.sign(tbs).to_vec()
            })
            .build()
            .to_vec()
            .unwrap_or_default()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refused {

    Malformed,

    Version(u8),

    BadSignature,

    WrongSubject,

    Expired {

        not_after: i64,

        now: i64,
    },

    Replayed,

    WrongOp,

    NeedsV2,

    HostClassIsV1,

    WrongOperand,
}

impl Refused {

    pub fn message(&self) -> String {
        match self {
            Refused::Malformed => "the ticket did not decode, or names an operation this build \
                                   does not know"
                .into(),
            Refused::Version(v) => format!(
                "the ticket is format version {v}; this build accepts {VERSION} for host classes \
                 and {VERSION_V2} for the perimeter classes"
            ),
            Refused::BadSignature => "the ticket is not signed by the pinned responder key, or \
                                      does not use EdDSA"
                .into(),
            Refused::WrongSubject => "the ticket was minted for a different engagement or a \
                                      different host"
                .into(),
            Refused::Expired { not_after, now } => format!(
                "the ticket expired at {not_after} and it is now {now}. A short expiry is what \
                 makes a stolen ticket a bounded loss"
            ),
            Refused::Replayed => "this ticket's nonce has been presented before. One ticket \
                                  authorises one operation"
                .into(),
            Refused::WrongOp => "the ticket authorises a different operation or class than the \
                                 one being attempted"
                .into(),
            Refused::NeedsV2 => "a perimeter action needs a version 2 ticket, which binds the \
                                 alias, direction and CIDR; a version 1 ticket names only the \
                                 class, and would let its holder choose what is blocked"
                .into(),
            Refused::HostClassIsV1 => "a version 2 ticket is for the perimeter classes only; a \
                                       host class takes a version 1 ticket"
                .into(),
            Refused::WrongOperand => "the ticket authorises a different alias, direction or CIDR \
                                      than the one being attempted"
                .into(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Asked {

    pub op: Op,

    pub class: u8,

    pub engagement: [u8; 16],

    pub host: [u8; 32],
}

pub fn verify(
    responder_pub: &[u8; 32],
    claims_bytes: &[u8],
    cose: &[u8],
    asked: &Asked,
    now: i64,
    fresh: impl FnMut(&[u8; 16]) -> bool,
) -> Result<Claims, Refused> {
    let claims = Claims::decode(claims_bytes).ok_or(Refused::Malformed)?;
    if claims.version != VERSION {
        return Err(Refused::Version(claims.version));
    }

    if requires_v2(asked.class) || requires_v2(claims.class) {
        return Err(Refused::NeedsV2);
    }
    check_signature(responder_pub, claims_bytes, cose, TICKET_CONTEXT)?;
    check_claims(&claims, asked, now, fresh)
}

pub fn verify_v2(
    responder_pub: &[u8; 32],
    claims_bytes: &[u8],
    cose: &[u8],
    asked: &Asked,
    operand: &[u8; 32],
    now: i64,
    fresh: impl FnMut(&[u8; 16]) -> bool,
) -> Result<ClaimsV2, Refused> {
    match claims_bytes.first() {
        None => return Err(Refused::Malformed),
        Some(&VERSION) => return Err(Refused::NeedsV2),
        Some(&v) if v != VERSION_V2 => return Err(Refused::Version(v)),
        Some(_) => {}
    }
    let c2 = ClaimsV2::decode(claims_bytes).ok_or(Refused::Malformed)?;
    if !requires_v2(asked.class) || !requires_v2(c2.claims.class) {
        return Err(Refused::HostClassIsV1);
    }
    check_signature(responder_pub, claims_bytes, cose, TICKET_CONTEXT_V2)?;

    if c2.claims.engagement != asked.engagement || c2.claims.host != asked.host {
        return Err(Refused::WrongSubject);
    }
    if c2.claims.op != asked.op || c2.claims.class != asked.class {
        return Err(Refused::WrongOp);
    }
    if &c2.operand != operand {
        return Err(Refused::WrongOperand);
    }
    check_claims(&c2.claims, asked, now, fresh)?;
    Ok(c2)
}

fn check_signature(responder_pub: &[u8; 32], claims_bytes: &[u8], cose: &[u8], context: &[u8]) -> Result<(), Refused> {

    let vk = VerifyingKey::from_bytes(responder_pub).map_err(|_| Refused::BadSignature)?;
    let sign1 = CoseSign1::from_slice(cose).map_err(|_| Refused::BadSignature)?;

    if !matches!(
        sign1.protected.header.alg,
        Some(RegisteredLabelWithPrivate::Assigned(iana::Algorithm::EdDSA))
    ) {
        return Err(Refused::BadSignature);
    }

    if sign1.payload.is_some() {
        return Err(Refused::BadSignature);
    }
    sign1
        .verify_detached_signature(claims_bytes, context, |sig, tbs| {
            let s = Signature::from_slice(sig).map_err(|_| ())?;
            vk.verify_strict(tbs, &s).map_err(|_| ())
        })
        .map_err(|_| Refused::BadSignature)
}

fn check_claims(claims: &Claims, asked: &Asked, now: i64, mut fresh: impl FnMut(&[u8; 16]) -> bool) -> Result<Claims, Refused> {
    if claims.engagement != asked.engagement || claims.host != asked.host {
        return Err(Refused::WrongSubject);
    }
    if claims.op != asked.op || claims.class != asked.class {
        return Err(Refused::WrongOp);
    }
    if claims.not_after <= now {
        return Err(Refused::Expired { not_after: claims.not_after, now });
    }

    if !fresh(&claims.nonce) {
        return Err(Refused::Replayed);
    }
    Ok(*claims)
}
