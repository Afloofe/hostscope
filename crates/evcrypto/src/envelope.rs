use crate::composed::{open, seal_deterministic, NENC};
use crate::secret::{wipe, Secret32};
use crate::{CryptoError, Result};
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use x25519_dalek::{PublicKey, StaticSecret};

pub const DEK_LEN: usize = 32;

pub const TAG_LEN: usize = 16;

const DEK_INFO: &[u8] = b"hemostat/dek/v1";

const STOREKEY_INFO: &[u8] = b"hemostat/storekey/v1";

const READKEY_INFO: &[u8] = b"hemostat/storekey-read/v1";

pub struct KeyPair {
    secret: StaticSecret,
    public: PublicKey,
}

impl KeyPair {

    pub fn from_seed(seed: [u8; 32]) -> Self {
        let secret = StaticSecret::from(seed);
        let public = PublicKey::from(&secret);
        KeyPair { secret, public }
    }

    pub fn public_bytes(&self) -> [u8; 32] {
        *self.public.as_bytes()
    }

    pub fn secret_bytes(&self) -> Secret32 {
        Secret32::new(self.secret.to_bytes())
    }
}

pub fn seal_to(
    recipient_pub: &[u8; 32],
    info: &[u8],
    aad: &[u8],
    pt: &[u8],
    eph_seed: [u8; 32],
) -> Result<Vec<u8>> {
    let sk_e = StaticSecret::from(eph_seed);
    let pk_r = PublicKey::from(*recipient_pub);
    let (enc, ct) = seal_deterministic(&sk_e, &pk_r, info, aad, pt)?;
    let mut out = Vec::with_capacity(NENC + ct.len());
    out.extend_from_slice(&enc);
    out.extend_from_slice(&ct);
    Ok(out)
}

pub fn open_from(recipient_secret: &[u8; 32], info: &[u8], aad: &[u8], wire: &[u8]) -> Result<Vec<u8>> {
    let enc: [u8; NENC] = wire
        .get(0..NENC)
        .and_then(|s| s.try_into().ok())
        .ok_or(CryptoError::Internal("envelope: truncated enc"))?;
    let ct = wire.get(NENC..).unwrap_or_default();
    let sk_r = StaticSecret::from(*recipient_secret);
    open(&sk_r, &enc, info, aad, ct)
}

pub fn seal_dek(store_pub: &[u8; 32], dek: &Secret32, eph_seed: [u8; 32]) -> Result<Vec<u8>> {
    seal_to(store_pub, DEK_INFO, &[], dek.expose(), eph_seed)
}

pub fn open_dek(store_secret: &Secret32, wire: &[u8]) -> Result<Secret32> {
    let pt = open_from(store_secret.expose(), DEK_INFO, &[], wire)?;
    let out: core::result::Result<[u8; DEK_LEN], _> = pt.as_slice().try_into();
    wipe(pt);
    Ok(Secret32::new(
        out.map_err(|_| CryptoError::Internal("envelope: DEK wrong length"))?,
    ))
}

pub fn wrap_store_key(
    recovery_pub: &[u8; 32],
    store_secret: &Secret32,
    eph_seed: [u8; 32],
) -> Result<Vec<u8>> {
    seal_to(recovery_pub, STOREKEY_INFO, &[], store_secret.expose(), eph_seed)
}

pub fn unwrap_store_key(recovery_secret: &Secret32, wrap: &[u8]) -> Result<Secret32> {
    let pt = open_from(recovery_secret.expose(), STOREKEY_INFO, &[], wrap)?;
    let out: core::result::Result<[u8; 32], _> = pt.as_slice().try_into();
    wipe(pt);
    Ok(Secret32::new(
        out.map_err(|_| CryptoError::Internal("envelope: store key wrong length"))?,
    ))
}

pub fn wrap_store_key_for_read(read_pub: &[u8; 32], store_secret: &Secret32, eph_seed: [u8; 32]) -> Result<Vec<u8>> {
    seal_to(read_pub, READKEY_INFO, &[], store_secret.expose(), eph_seed)
}

pub fn unwrap_store_key_for_read(read_secret: &Secret32, wrap: &[u8]) -> Result<Secret32> {
    let pt = open_from(read_secret.expose(), READKEY_INFO, &[], wrap)?;
    let out: core::result::Result<[u8; 32], _> = pt.as_slice().try_into();
    wipe(pt);
    Ok(Secret32::new(out.map_err(|_| CryptoError::Internal("envelope: store key wrong length"))?))
}

pub fn aead_seal(dek: &Secret32, nonce: &[u8; 12], aad: &[u8], pt: &[u8]) -> Result<(Vec<u8>, [u8; TAG_LEN])> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(dek.expose()));
    let mut ct = cipher
        .encrypt(Nonce::from_slice(nonce), Payload { msg: pt, aad })
        .map_err(|_| CryptoError::Internal("record aead seal"))?;

    let tag_start = ct.len().checked_sub(TAG_LEN).ok_or(CryptoError::Internal("record aead: short ct"))?;
    let tag: [u8; TAG_LEN] = ct
        .split_off(tag_start)
        .try_into()
        .map_err(|_| CryptoError::Internal("record aead: tag len"))?;
    Ok((ct, tag))
}

pub fn aead_open(
    dek: &Secret32,
    nonce: &[u8; 12],
    aad: &[u8],
    ct: &[u8],
    tag: &[u8],
) -> Result<Vec<u8>> {
    if tag.len() != TAG_LEN {
        return Err(CryptoError::Internal("record aead: tag len"));
    }
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(dek.expose()));

    let mut buf = Vec::with_capacity(ct.len() + TAG_LEN);
    buf.extend_from_slice(ct);
    buf.extend_from_slice(tag);
    cipher
        .decrypt(Nonce::from_slice(nonce), Payload { msg: &buf, aad })
        .map_err(|_| CryptoError::AuthenticationFailed)
}
