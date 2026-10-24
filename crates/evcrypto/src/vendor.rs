use hpke::aead::AesGcm256;
use hpke::kdf::HkdfSha256;
use hpke::kem::X25519HkdfSha256;
use hpke::{Deserializable, Kem as KemTrait, OpModeR, OpModeS, Serializable};
use rand_core::{CryptoRng, RngCore};

use crate::{CryptoError, Result};

type Kem = X25519HkdfSha256;

pub fn seal<R: RngCore + CryptoRng>(
    rng: &mut R,
    pk_r_bytes: &[u8; 32],
    info: &[u8],
    aad: &[u8],
    pt: &[u8],
) -> Result<([u8; 32], Vec<u8>)> {
    let pk_r = <Kem as KemTrait>::PublicKey::from_bytes(pk_r_bytes)
        .map_err(|_| CryptoError::InvalidPeerKey)?;

    let (enc, ct) = hpke::single_shot_seal::<AesGcm256, HkdfSha256, Kem, _>(
        &OpModeS::Base,
        &pk_r,
        info,
        pt,
        aad,
        rng,
    )
    .map_err(|_| CryptoError::Internal("hpke seal"))?;

    let mut enc_bytes = [0u8; 32];
    enc_bytes.copy_from_slice(&enc.to_bytes());
    Ok((enc_bytes, ct))
}

pub fn open(
    sk_r_bytes: &[u8; 32],
    enc: &[u8; 32],
    info: &[u8],
    aad: &[u8],
    ct: &[u8],
) -> Result<Vec<u8>> {
    let sk_r = <Kem as KemTrait>::PrivateKey::from_bytes(sk_r_bytes)
        .map_err(|_| CryptoError::InvalidPeerKey)?;
    let enc = <Kem as KemTrait>::EncappedKey::from_bytes(enc)
        .map_err(|_| CryptoError::InvalidPeerKey)?;

    hpke::single_shot_open::<AesGcm256, HkdfSha256, Kem>(
        &OpModeR::Base,
        &sk_r,
        &enc,
        info,
        ct,
        aad,
    )
    .map_err(|_| CryptoError::AuthenticationFailed)
}

pub fn seal_auth<R: RngCore + CryptoRng>(
    rng: &mut R,
    pk_r_bytes: &[u8; 32],
    sk_s_bytes: &[u8; 32],
    info: &[u8],
    aad: &[u8],
    pt: &[u8],
) -> Result<([u8; 32], Vec<u8>)> {
    let pk_r = <Kem as KemTrait>::PublicKey::from_bytes(pk_r_bytes)
        .map_err(|_| CryptoError::InvalidPeerKey)?;
    let sk_s = <Kem as KemTrait>::PrivateKey::from_bytes(sk_s_bytes)
        .map_err(|_| CryptoError::InvalidPeerKey)?;
    let pk_s = <Kem as KemTrait>::sk_to_pk(&sk_s);
    let (enc, ct) = hpke::single_shot_seal::<AesGcm256, HkdfSha256, Kem, _>(
        &OpModeS::Auth((sk_s, pk_s)),
        &pk_r,
        info,
        pt,
        aad,
        rng,
    )
    .map_err(|_| CryptoError::Internal("hpke seal"))?;
    let mut enc_bytes = [0u8; 32];
    enc_bytes.copy_from_slice(&enc.to_bytes());
    Ok((enc_bytes, ct))
}

pub fn open_auth(
    sk_r_bytes: &[u8; 32],
    pk_s_bytes: &[u8; 32],
    enc: &[u8; 32],
    info: &[u8],
    aad: &[u8],
    ct: &[u8],
) -> Result<Vec<u8>> {
    let sk_r = <Kem as KemTrait>::PrivateKey::from_bytes(sk_r_bytes)
        .map_err(|_| CryptoError::InvalidPeerKey)?;
    let pk_s = <Kem as KemTrait>::PublicKey::from_bytes(pk_s_bytes)
        .map_err(|_| CryptoError::InvalidPeerKey)?;
    let enc = <Kem as KemTrait>::EncappedKey::from_bytes(enc)
        .map_err(|_| CryptoError::InvalidPeerKey)?;
    hpke::single_shot_open::<AesGcm256, HkdfSha256, Kem>(
        &OpModeR::Auth(pk_s),
        &sk_r,
        &enc,
        info,
        ct,
        aad,
    )
    .map_err(|_| CryptoError::AuthenticationFailed)
}
