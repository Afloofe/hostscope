use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

use crate::{CryptoError, Result};

const KEM_ID: u16 = 0x0020;

const KDF_ID: u16 = 0x0001;

const AEAD_ID: u16 = 0x0002;

const MODE_BASE: u8 = 0x00;

const MODE_AUTH: u8 = 0x02;

pub const NSECRET: usize = 32;

pub const NK: usize = 32;

pub const NN: usize = 12;

pub const NENC: usize = 32;

fn kem_suite_id() -> [u8; 5] {
    let mut s = [0u8; 5];
    s[0..3].copy_from_slice(b"KEM");
    s[3..5].copy_from_slice(&KEM_ID.to_be_bytes());
    s
}

fn hpke_suite_id() -> [u8; 10] {
    let mut s = [0u8; 10];
    s[0..4].copy_from_slice(b"HPKE");
    s[4..6].copy_from_slice(&KEM_ID.to_be_bytes());
    s[6..8].copy_from_slice(&KDF_ID.to_be_bytes());
    s[8..10].copy_from_slice(&AEAD_ID.to_be_bytes());
    s
}

fn labeled_extract(suite_id: &[u8], salt: &[u8], label: &[u8], ikm: &[u8]) -> [u8; 32] {
    let mut labeled = Vec::with_capacity(7 + suite_id.len() + label.len() + ikm.len());
    labeled.extend_from_slice(b"HPKE-v1");
    labeled.extend_from_slice(suite_id);
    labeled.extend_from_slice(label);
    labeled.extend_from_slice(ikm);
    let (prk, _) = Hkdf::<Sha256>::extract(Some(salt), &labeled);

    labeled.zeroize();
    prk.into()
}

fn labeled_expand(
    suite_id: &[u8],
    prk: &[u8; 32],
    label: &[u8],
    info: &[u8],
    out: &mut [u8],
) -> Result<()> {
    let l = u16::try_from(out.len()).map_err(|_| CryptoError::Internal("expand length"))?;
    let mut labeled = Vec::with_capacity(9 + suite_id.len() + label.len() + info.len());
    labeled.extend_from_slice(&l.to_be_bytes());
    labeled.extend_from_slice(b"HPKE-v1");
    labeled.extend_from_slice(suite_id);
    labeled.extend_from_slice(label);
    labeled.extend_from_slice(info);
    Hkdf::<Sha256>::from_prk(prk)
        .map_err(|_| CryptoError::Internal("hkdf prk"))?
        .expand(&labeled, out)
        .map_err(|_| CryptoError::Internal("hkdf expand"))
}

fn extract_and_expand(dh: &[u8], kem_context: &[u8]) -> Result<[u8; NSECRET]> {
    let suite = kem_suite_id();
    let mut eae_prk = labeled_extract(&suite, b"", b"eae_prk", dh);
    let mut shared = [0u8; NSECRET];
    let r = labeled_expand(&suite, &eae_prk, b"shared_secret", kem_context, &mut shared);

    eae_prk.zeroize();
    r?;
    Ok(shared)
}

#[derive(Clone, PartialEq, Eq)]
pub struct Context {

    pub key: [u8; NK],

    pub base_nonce: [u8; NN],
}

impl core::fmt::Debug for Context {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Context { key: redacted, base_nonce: redacted }")
    }
}

impl Drop for Context {
    fn drop(&mut self) {
        self.key.zeroize();
        self.base_nonce.zeroize();
    }
}

pub fn key_schedule(shared_secret: &[u8; NSECRET], info: &[u8]) -> Result<Context> {
    key_schedule_mode(MODE_BASE, shared_secret, info)
}

fn key_schedule_mode(mode: u8, shared_secret: &[u8; NSECRET], info: &[u8]) -> Result<Context> {
    let suite = hpke_suite_id();

    let psk_id_hash = labeled_extract(&suite, b"", b"psk_id_hash", b"");
    let info_hash = labeled_extract(&suite, b"", b"info_hash", info);

    let mut ks_context = Vec::with_capacity(1 + 32 + 32);
    ks_context.push(mode);
    ks_context.extend_from_slice(&psk_id_hash);
    ks_context.extend_from_slice(&info_hash);

    let mut secret = labeled_extract(&suite, shared_secret, b"secret", b"");

    let mut key = [0u8; NK];
    let a = labeled_expand(&suite, &secret, b"key", &ks_context, &mut key);
    let mut base_nonce = [0u8; NN];
    let b = labeled_expand(&suite, &secret, b"base_nonce", &ks_context, &mut base_nonce);

    secret.zeroize();
    a?;
    b?;

    Ok(Context { key, base_nonce })
}

pub fn encap_deterministic(
    sk_e: &StaticSecret,
    pk_r: &PublicKey,
) -> Result<([u8; NSECRET], [u8; NENC])> {
    let pk_e = PublicKey::from(sk_e);
    let dh = sk_e.diffie_hellman(pk_r);

    if dh.as_bytes().iter().all(|b| *b == 0) {
        return Err(CryptoError::InvalidPeerKey);
    }

    let mut kem_context = [0u8; NENC * 2];
    kem_context[..NENC].copy_from_slice(pk_e.as_bytes());
    kem_context[NENC..].copy_from_slice(pk_r.as_bytes());

    let shared = extract_and_expand(dh.as_bytes(), &kem_context)?;
    Ok((shared, *pk_e.as_bytes()))
}

pub fn encap<R: rand_core::RngCore + rand_core::CryptoRng>(
    rng: &mut R,
    pk_r: &PublicKey,
) -> Result<([u8; NSECRET], [u8; NENC])> {
    let mut raw = [0u8; 32];
    rng.fill_bytes(&mut raw);
    let sk_e = StaticSecret::from(raw);
    encap_deterministic(&sk_e, pk_r)
}

pub fn seal_deterministic(
    sk_e: &StaticSecret,
    pk_r: &PublicKey,
    info: &[u8],
    aad: &[u8],
    pt: &[u8],
) -> Result<([u8; NENC], Vec<u8>)> {
    use aes_gcm::aead::{Aead, KeyInit, Payload};
    use aes_gcm::{Aes256Gcm, Key, Nonce};

    let (mut shared, enc) = encap_deterministic(sk_e, pk_r)?;
    let ctx = key_schedule(&shared, info);
    shared.zeroize();
    let ctx = ctx?;

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&ctx.key));
    let ct = cipher
        .encrypt(Nonce::from_slice(&ctx.base_nonce), Payload { msg: pt, aad })
        .map_err(|_| CryptoError::Internal("aead seal"))?;
    Ok((enc, ct))
}

pub fn open(
    sk_r: &StaticSecret,
    enc: &[u8; NENC],
    info: &[u8],
    aad: &[u8],
    ct: &[u8],
) -> Result<Vec<u8>> {
    use aes_gcm::aead::{Aead, KeyInit, Payload};
    use aes_gcm::{Aes256Gcm, Key, Nonce};

    let mut shared = decap(sk_r, enc)?;
    let ctx = key_schedule(&shared, info);
    shared.zeroize();
    let ctx = ctx?;

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&ctx.key));
    cipher
        .decrypt(Nonce::from_slice(&ctx.base_nonce), Payload { msg: ct, aad })
        .map_err(|_| CryptoError::AuthenticationFailed)
}

pub fn decap(sk_r: &StaticSecret, enc: &[u8; NENC]) -> Result<[u8; NSECRET]> {
    let pk_e = PublicKey::from(*enc);
    let dh = sk_r.diffie_hellman(&pk_e);
    if dh.as_bytes().iter().all(|b| *b == 0) {
        return Err(CryptoError::InvalidPeerKey);
    }

    let pk_r = PublicKey::from(sk_r);
    let mut kem_context = [0u8; NENC * 2];
    kem_context[..NENC].copy_from_slice(enc);
    kem_context[NENC..].copy_from_slice(pk_r.as_bytes());

    extract_and_expand(dh.as_bytes(), &kem_context)
}

pub fn auth_encap_deterministic(
    sk_e: &StaticSecret,
    pk_r: &PublicKey,
    sk_s: &StaticSecret,
) -> Result<([u8; NSECRET], [u8; NENC])> {
    let pk_e = PublicKey::from(sk_e);
    let pk_s = PublicKey::from(sk_s);
    let dh_e = sk_e.diffie_hellman(pk_r);
    let dh_s = sk_s.diffie_hellman(pk_r);
    if dh_e.as_bytes().iter().all(|b| *b == 0) || dh_s.as_bytes().iter().all(|b| *b == 0) {
        return Err(CryptoError::InvalidPeerKey);
    }
    let mut dh = [0u8; 64];
    dh[..32].copy_from_slice(dh_e.as_bytes());
    dh[32..].copy_from_slice(dh_s.as_bytes());
    let mut kem_context = [0u8; NENC * 3];
    kem_context[..NENC].copy_from_slice(pk_e.as_bytes());
    kem_context[NENC..NENC * 2].copy_from_slice(pk_r.as_bytes());
    kem_context[NENC * 2..].copy_from_slice(pk_s.as_bytes());
    let shared = extract_and_expand(&dh, &kem_context);
    dh.zeroize();
    Ok((shared?, *pk_e.as_bytes()))
}

pub fn auth_decap(sk_r: &StaticSecret, enc: &[u8; NENC], pk_s: &PublicKey) -> Result<[u8; NSECRET]> {
    let pk_e = PublicKey::from(*enc);
    let dh_e = sk_r.diffie_hellman(&pk_e);
    let dh_s = sk_r.diffie_hellman(pk_s);
    if dh_e.as_bytes().iter().all(|b| *b == 0) || dh_s.as_bytes().iter().all(|b| *b == 0) {
        return Err(CryptoError::InvalidPeerKey);
    }
    let pk_r = PublicKey::from(sk_r);
    let mut dh = [0u8; 64];
    dh[..32].copy_from_slice(dh_e.as_bytes());
    dh[32..].copy_from_slice(dh_s.as_bytes());
    let mut kem_context = [0u8; NENC * 3];
    kem_context[..NENC].copy_from_slice(enc);
    kem_context[NENC..NENC * 2].copy_from_slice(pk_r.as_bytes());
    kem_context[NENC * 2..].copy_from_slice(pk_s.as_bytes());
    let shared = extract_and_expand(&dh, &kem_context);
    dh.zeroize();
    shared
}

pub fn seal_auth_deterministic(
    sk_e: &StaticSecret,
    pk_r: &PublicKey,
    sk_s: &StaticSecret,
    info: &[u8],
    aad: &[u8],
    pt: &[u8],
) -> Result<([u8; NENC], Vec<u8>)> {
    use aes_gcm::aead::{Aead, KeyInit, Payload};
    use aes_gcm::{Aes256Gcm, Key, Nonce};

    let (mut shared, enc) = auth_encap_deterministic(sk_e, pk_r, sk_s)?;
    let ctx = key_schedule_mode(MODE_AUTH, &shared, info);
    shared.zeroize();
    let ctx = ctx?;
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&ctx.key));
    let ct = cipher
        .encrypt(Nonce::from_slice(&ctx.base_nonce), Payload { msg: pt, aad })
        .map_err(|_| CryptoError::Internal("aead seal"))?;
    Ok((enc, ct))
}

pub fn open_auth(
    sk_r: &StaticSecret,
    pk_s: &PublicKey,
    enc: &[u8; NENC],
    info: &[u8],
    aad: &[u8],
    ct: &[u8],
) -> Result<Vec<u8>> {
    use aes_gcm::aead::{Aead, KeyInit, Payload};
    use aes_gcm::{Aes256Gcm, Key, Nonce};

    let mut shared = auth_decap(sk_r, enc, pk_s)?;
    let ctx = key_schedule_mode(MODE_AUTH, &shared, info);
    shared.zeroize();
    let ctx = ctx?;
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&ctx.key));
    cipher
        .decrypt(Nonce::from_slice(&ctx.base_nonce), Payload { msg: ct, aad })
        .map_err(|_| CryptoError::AuthenticationFailed)
}
