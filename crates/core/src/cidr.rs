use core::fmt;
use core::str::FromStr;
use std::net::IpAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Cidr {
    addr: IpAddr,
    prefix: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CidrError {

    Address(String),

    Prefix(String),

    HostBits {

        given: String,

        network: String,
    },

    Zone,

    Mapped(String),
}

impl fmt::Display for CidrError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CidrError::Address(s) => write!(f, "{s:?} is not an IPv4 or IPv6 address"),
            CidrError::Prefix(s) => write!(f, "{s:?} is not a prefix length for this address family"),
            CidrError::HostBits { given, network } => write!(
                f,
                "{given} has host bits set: it is a member of {network}, not a network. Name the \
                 network, or the host as a /32 or /128 — a block does not guess which was meant"
            ),
            CidrError::Zone => f.write_str(
                "a scope zone (%if) cannot be blocked: pf tables hold none, and link-local \
                 addresses are protected anyway",
            ),
            CidrError::Mapped(v4) => write!(
                f,
                "an IPv4-mapped IPv6 address is matched by pf as IPv6, never as {v4}; write {v4} \
                 instead"
            ),
        }
    }
}

impl std::error::Error for CidrError {}

fn width(a: &IpAddr) -> u8 {
    if a.is_ipv4() {
        32
    } else {
        128
    }
}

fn bits(a: &IpAddr) -> u128 {
    match a {
        IpAddr::V4(v) => u128::from(u32::from(*v)),
        IpAddr::V6(v) => u128::from(*v),
    }
}

fn mask(width: u8, prefix: u8) -> u128 {
    let all: u128 = if width == 32 { u128::from(u32::MAX) } else { u128::MAX };
    match u32::from(width - prefix) {
        0 => all,
        n if n >= 128 => 0,
        n => all & !((1u128 << n) - 1),
    }
}

impl Cidr {

    pub fn parse(s: &str) -> Result<Cidr, CidrError> {
        let (a, p) = match s.split_once('/') {
            Some((a, p)) => (a, Some(p)),
            None => (s, None),
        };
        if a.contains('%') {
            return Err(CidrError::Zone);
        }
        let addr = IpAddr::from_str(a).map_err(|_| CidrError::Address(a.to_string()))?;
        if let IpAddr::V6(v6) = addr {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return Err(CidrError::Mapped(v4.to_string()));
            }
        }
        let w = width(&addr);
        let prefix = match p {
            None => w,
            Some(p) => {
                if p.is_empty() || p.len() > 3 || !p.bytes().all(|b| b.is_ascii_digit()) {
                    return Err(CidrError::Prefix(p.to_string()));
                }
                match p.parse::<u8>() {
                    Ok(n) if n <= w => n,
                    _ => return Err(CidrError::Prefix(p.to_string())),
                }
            }
        };
        let c = Cidr { addr, prefix };
        let net = c.network_bits();
        if net != bits(&addr) {
            return Err(CidrError::HostBits {
                given: format!("{addr}/{prefix}"),
                network: Cidr { addr: from_bits(&addr, net), prefix }.to_string(),
            });
        }
        Ok(c)
    }

    pub fn host(a: IpAddr) -> Cidr {
        Cidr { addr: a, prefix: width(&a) }
    }

    pub fn addr(&self) -> IpAddr {
        self.addr
    }

    pub fn prefix(&self) -> u8 {
        self.prefix
    }

    pub fn is_v4(&self) -> bool {
        self.addr.is_ipv4()
    }

    pub fn is_everything(&self) -> bool {
        self.prefix == 0
    }

    fn network_bits(&self) -> u128 {
        bits(&self.addr) & mask(width(&self.addr), self.prefix)
    }

    pub fn contains(&self, a: &IpAddr) -> bool {
        a.is_ipv4() == self.addr.is_ipv4()
            && bits(a) & mask(width(a), self.prefix) == self.network_bits()
    }

    pub fn overlaps(&self, other: &Cidr) -> bool {
        if self.is_v4() != other.is_v4() {
            return false;
        }
        let p = self.prefix.min(other.prefix);
        let m = mask(width(&self.addr), p);
        bits(&self.addr) & m == bits(&other.addr) & m
    }
}

fn from_bits(like: &IpAddr, b: u128) -> IpAddr {
    match like {
        IpAddr::V4(_) => IpAddr::V4(std::net::Ipv4Addr::from(u32::try_from(b).unwrap_or(0))),
        IpAddr::V6(_) => IpAddr::V6(std::net::Ipv6Addr::from(b)),
    }
}

impl fmt::Display for Cidr {

    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix)
    }
}

impl FromStr for Cidr {
    type Err = CidrError;
    fn from_str(s: &str) -> Result<Cidr, CidrError> {
        Cidr::parse(s)
    }
}
