use coset::iana;
use coset::{CborSerializable as _, CoseSign1, CoseSign1Builder, HeaderBuilder, RegisteredLabelWithPrivate};
use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};

pub const POLICY_CONTEXT: &[u8] = b"hemostat/policy/v1";

pub const VERSION: u8 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PolicyProfile {

    It = 1,

    Ot = 2,
}

impl PolicyProfile {

    pub const fn code(self) -> u8 {
        self as u8
    }

    pub const fn from_code(c: u8) -> Option<Self> {
        match c {
            1 => Some(PolicyProfile::It),
            2 => Some(PolicyProfile::Ot),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {

    pub version: u8,

    pub epoch: u32,

    pub profile: PolicyProfile,

    pub engagement: [u8; 16],

    pub not_after: i64,

    pub bulk_threshold: u16,

    pub allowed_actions: Vec<u8>,

    pub scope: Vec<[u8; 32]>,
}

impl Policy {

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(64 + self.allowed_actions.len() + self.scope.len() * 32);
        out.push(self.version);
        out.extend_from_slice(&self.epoch.to_be_bytes());
        out.push(self.profile.code());
        out.extend_from_slice(&self.engagement);
        out.extend_from_slice(&self.not_after.to_be_bytes());
        out.extend_from_slice(&self.bulk_threshold.to_be_bytes());

        let mut actions = self.allowed_actions.clone();
        actions.sort_unstable();
        actions.dedup();
        out.extend_from_slice(&u16::try_from(actions.len()).unwrap_or(u16::MAX).to_be_bytes());
        out.extend_from_slice(&actions);

        let mut scope = self.scope.clone();
        scope.sort_unstable();
        scope.dedup();
        out.extend_from_slice(&u16::try_from(scope.len()).unwrap_or(u16::MAX).to_be_bytes());
        for h in &scope {
            out.extend_from_slice(h);
        }
        out
    }

    pub fn decode(b: &[u8]) -> Option<Self> {
        let mut i = 0usize;
        let take = |i: &mut usize, n: usize| -> Option<&[u8]> {
            let s = b.get(*i..i.checked_add(n)?)?;
            *i += n;
            Some(s)
        };

        let version = *take(&mut i, 1)?.first()?;
        let epoch = u32::from_be_bytes(take(&mut i, 4)?.try_into().ok()?);
        let profile = PolicyProfile::from_code(*take(&mut i, 1)?.first()?)?;
        let mut engagement = [0u8; 16];
        engagement.copy_from_slice(take(&mut i, 16)?);
        let not_after = i64::from_be_bytes(take(&mut i, 8)?.try_into().ok()?);
        let bulk_threshold = u16::from_be_bytes(take(&mut i, 2)?.try_into().ok()?);

        let n_actions = u16::from_be_bytes(take(&mut i, 2)?.try_into().ok()?) as usize;
        let allowed_actions = take(&mut i, n_actions)?.to_vec();

        let n_scope = u16::from_be_bytes(take(&mut i, 2)?.try_into().ok()?) as usize;
        let mut scope = Vec::with_capacity(n_scope.min(1024));
        for _ in 0..n_scope {
            let mut h = [0u8; 32];
            h.copy_from_slice(take(&mut i, 32)?);
            scope.push(h);
        }

        if i != b.len() {
            return None;
        }
        Some(Policy {
            version,
            epoch,
            profile,
            engagement,
            not_after,
            bulk_threshold,
            allowed_actions,
            scope,
        })
    }

    pub fn permits(&self, class_code: u8) -> bool {
        self.allowed_actions.contains(&class_code)
    }

    pub fn covers(&self, host: &[u8; 32]) -> bool {
        self.scope.is_empty() || self.scope.contains(host)
    }
}

pub struct RootKey {
    signing: SigningKey,
}

impl RootKey {

    pub fn from_seed(seed: [u8; 32]) -> Self {
        RootKey { signing: SigningKey::from_bytes(&seed) }
    }

    pub fn public_bytes(&self) -> [u8; 32] {
        self.signing.verifying_key().to_bytes()
    }

    pub fn sign(&self, policy: &Policy) -> Vec<u8> {
        let protected = HeaderBuilder::new().algorithm(iana::Algorithm::EdDSA).build();
        CoseSign1Builder::new()
            .protected(protected)
            .create_detached_signature(&policy.encode(), POLICY_CONTEXT, |tbs| {
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

    WrongEngagement,

    OutOfScope,

    Expired {

        not_after: i64,

        now: i64,
    },

    OtWithoutScope,

    RolledBack {

        offered: u32,

        floor: u32,
    },
}

impl Refused {

    pub fn message(&self) -> String {
        match self {
            Refused::Malformed => "the policy did not decode, or names a profile this build \
                                   does not know"
                .into(),
            Refused::Version(v) => {
                format!("the policy is format version {v}, and this build accepts {VERSION}")
            }
            Refused::BadSignature => "the policy is not signed by the pinned engagement root \
                                      key, or does not use EdDSA"
                .into(),
            Refused::WrongEngagement => "the policy is for a different engagement".into(),
            Refused::OutOfScope => "this host is not in the policy's scope. Acting outside the \
                                    scope somebody signed is the one thing a scope is for"
                .into(),
            Refused::Expired { not_after, now } => format!(
                "the policy expired at {not_after} and it is now {now}"
            ),
            Refused::OtWithoutScope => "the policy is for an OT engagement and names no hosts. \
                                        OT authority has to list the machines it covers; an \
                                        empty scope would cover every host the key can reach"
                .into(),
            Refused::RolledBack { offered, floor } => format!(
                "the policy is epoch {offered} and this agent has already seen {floor}. An old \
                 policy is a correctly signed, unexpired, more permissive one — the epoch is \
                 what stops it being replayed"
            ),
        }
    }
}

pub fn verify(
    root_pub: &[u8; 32],
    policy_bytes: &[u8],
    cose: &[u8],
    engagement: &[u8; 16],
    host: &[u8; 32],
    now: i64,
    floor: u32,
) -> Result<Policy, Refused> {
    let policy = Policy::decode(policy_bytes).ok_or(Refused::Malformed)?;
    if policy.version != VERSION {
        return Err(Refused::Version(policy.version));
    }

    let vk = VerifyingKey::from_bytes(root_pub).map_err(|_| Refused::BadSignature)?;
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
        .verify_detached_signature(policy_bytes, POLICY_CONTEXT, |sig, tbs| {
            let s = Signature::from_slice(sig).map_err(|_| ())?;
            vk.verify_strict(tbs, &s).map_err(|_| ())
        })
        .map_err(|_| Refused::BadSignature)?;

    if policy.engagement != *engagement {
        return Err(Refused::WrongEngagement);
    }
    if policy.profile == PolicyProfile::Ot && policy.scope.is_empty() {
        return Err(Refused::OtWithoutScope);
    }
    if !policy.covers(host) {
        return Err(Refused::OutOfScope);
    }
    if policy.not_after <= now {
        return Err(Refused::Expired { not_after: policy.not_after, now });
    }
    if policy.epoch < floor {
        return Err(Refused::RolledBack { offered: policy.epoch, floor });
    }
    Ok(policy)
}
