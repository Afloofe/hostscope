use coset::{
    iana, CborSerializable, CoseSign1, CoseSign1Builder, HeaderBuilder,
    RegisteredLabelWithPrivate,
};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

pub const SEAL_CONTEXT: &[u8] = b"hemostat/seal/v1";

pub struct SealKey {
    signing: SigningKey,
}

impl SealKey {

    pub fn from_seed(mut seed: [u8; 32]) -> Self {
        let signing = SigningKey::from_bytes(&seed);

        seed.fill(0);
        SealKey { signing }
    }

    pub fn public_bytes(&self) -> [u8; 32] {
        self.signing.verifying_key().to_bytes()
    }

    pub fn sign_footer(&self, signable: &[u8]) -> Vec<u8> {
        let protected = HeaderBuilder::new()
            .algorithm(iana::Algorithm::EdDSA)
            .build();
        CoseSign1Builder::new()
            .protected(protected)
            .create_detached_signature(signable, SEAL_CONTEXT, |tbs| self.signing.sign(tbs).to_vec())
            .build()
            .to_vec()
            .unwrap_or_default()
    }
}

const HDR_SEAL_ALG: u8 = 1;

const HDR_SEAL_PUB: u8 = 2;

const HDR_STORE_PUB: u8 = 3;

const HDR_STORE_WRAP: u8 = 4;

const HDR_READ_WRAP: u8 = 5;

#[derive(Debug, Clone, Default)]
pub struct HeaderKeys {

    pub seal_pub: Option<[u8; 32]>,

    pub store_pub: Option<[u8; 32]>,

    pub store_wrap: Option<Vec<u8>>,
}

pub fn encode_header_keys(keys: &HeaderKeys) -> Vec<u8> {
    encode_header_keys_with_read(keys, None)
}

pub fn encode_header_keys_with_read(keys: &HeaderKeys, read_wrap: Option<&[u8]>) -> Vec<u8> {
    use ciborium::value::{Integer, Value};
    let mut entries = Vec::new();
    if let Some(sp) = &keys.seal_pub {
        entries.push((Value::Integer(Integer::from(HDR_SEAL_ALG)), Value::Text("Ed25519".into())));
        entries.push((Value::Integer(Integer::from(HDR_SEAL_PUB)), Value::Bytes(sp.to_vec())));
    }
    if let Some(kp) = &keys.store_pub {
        entries.push((Value::Integer(Integer::from(HDR_STORE_PUB)), Value::Bytes(kp.to_vec())));
    }
    if let Some(w) = &keys.store_wrap {
        entries.push((Value::Integer(Integer::from(HDR_STORE_WRAP)), Value::Bytes(w.clone())));
    }
    if let Some(w) = read_wrap {
        entries.push((Value::Integer(Integer::from(HDR_READ_WRAP)), Value::Bytes(w.to_vec())));
    }
    let mut out = Vec::new();

    let _ = ciborium::into_writer(&Value::Map(entries), &mut out);
    out
}

pub fn decode_header_keys(tail: &[u8]) -> HeaderKeys {
    use ciborium::value::{Integer, Value};
    let mut keys = HeaderKeys::default();
    if tail.is_empty() {
        return keys;
    }
    let Ok(Value::Map(map)) = ciborium::from_reader::<Value, _>(tail) else {
        return keys;
    };
    let get_bytes = |want: u8| -> Option<Vec<u8>> {
        map.iter().find_map(|(k, v)| {
            (k == &Value::Integer(Integer::from(want)))
                .then(|| v.as_bytes().cloned())
                .flatten()
        })
    };
    let arr = |b: Option<Vec<u8>>| -> Option<[u8; 32]> { b.and_then(|v| v.as_slice().try_into().ok()) };

    let seal_alg_ok = map.iter().any(|(k, v)| {
        k == &Value::Integer(Integer::from(HDR_SEAL_ALG)) && v.as_text() == Some("Ed25519")
    });
    if seal_alg_ok {
        keys.seal_pub = arr(get_bytes(HDR_SEAL_PUB));
    }
    keys.store_pub = arr(get_bytes(HDR_STORE_PUB));
    keys.store_wrap = get_bytes(HDR_STORE_WRAP);
    keys
}

pub fn decode_read_wrap(tail: &[u8]) -> Option<Vec<u8>> {
    use ciborium::value::{Integer, Value};
    let Ok(Value::Map(map)) = ciborium::from_reader::<Value, _>(tail) else {
        return None;
    };
    map.iter().find_map(|(k, v)| (k == &Value::Integer(Integer::from(HDR_READ_WRAP))).then(|| v.as_bytes().cloned()).flatten())
}

pub fn decode_seal_pubkey(tail: &[u8]) -> Option<[u8; 32]> {
    decode_header_keys(tail).seal_pub
}

pub fn verify_footer(public_key: &[u8; 32], signable: &[u8], cose: &[u8]) -> bool {
    let Ok(vk) = VerifyingKey::from_bytes(public_key) else {
        return false;
    };
    let Ok(sign1) = CoseSign1::from_slice(cose) else {
        return false;
    };

    if !matches!(
        sign1.protected.header.alg,
        Some(RegisteredLabelWithPrivate::Assigned(iana::Algorithm::EdDSA))
    ) {
        return false;
    }

    if sign1.payload.is_some() {
        return false;
    }
    sign1
        .verify_detached_signature(signable, SEAL_CONTEXT, |sig, tbs| {
            let s = Signature::from_slice(sig).map_err(|_| ())?;
            vk.verify_strict(tbs, &s).map_err(|_| ())
        })
        .is_ok()
}
