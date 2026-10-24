use core::fmt;

macro_rules! opaque_id {
    ($(#[$meta:meta])* $name:ident, $label:literal, $n:literal) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name([u8; $n]);

        impl $name {

            pub const LEN: usize = $n;

            #[doc = concat!("Construct a ", $label, " from its raw bytes.")]
            pub const fn from_bytes(b: [u8; $n]) -> Self {
                Self(b)
            }

            pub const fn as_bytes(&self) -> &[u8; $n] {
                &self.0
            }
        }

        impl fmt::Display for $name {

            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                for b in &self.0 {
                    write!(f, "{b:02x}")?;
                }
                Ok(())
            }
        }
    };
}

opaque_id!(

    EngagementId,
    "engagement id",
    16
);

opaque_id!(

    HostId,
    "host id",
    32
);

opaque_id!(

    AgentId,
    "agent id",
    16
);

opaque_id!(

    InstanceId,
    "instance id",
    16
);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Kid([u8; 16]);

impl Kid {

    pub const fn from_bytes(b: [u8; 16]) -> Self {
        Self(b)
    }

    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl fmt::Display for Kid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in &self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Origin {

    pub engagement: EngagementId,

    pub host: HostId,

    pub agent: AgentId,

    pub instance: InstanceId,
}

impl Origin {

    pub fn same_drop(&self, other: &Origin) -> bool {
        self.engagement == other.engagement
            && self.host == other.host
            && self.agent == other.agent
    }
}

impl fmt::Display for Origin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}/{}", self.engagement, self.host, self.agent)
    }
}
