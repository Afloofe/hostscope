use std::net::IpAddr;

pub const MAX_LINE: usize = 1024;

pub const MAX_FIELDS: usize = 48;

pub const MAX_TRACKER: usize = 64;

pub const MAX_IFACE: usize = 15;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Action {

    Pass,

    Block,

    Other,
}

impl Action {

    pub fn label(self) -> &'static str {
        match self {
            Action::Pass => "pass",
            Action::Block => "block",
            Action::Other => "other",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Dir {

    In,

    Out,

    Other,
}

impl Dir {

    pub fn label(self) -> &'static str {
        match self {
            Dir::In => "in",
            Dir::Out => "out",
            Dir::Other => "?",
        }
    }
}

pub mod proto {

    pub const ICMP: u8 = 1;

    pub const TCP: u8 = 6;

    pub const UDP: u8 = 17;

    pub const ICMP6: u8 = 58;

    pub fn name(p: u8) -> String {
        match p {
            ICMP => "icmp".into(),
            TCP => "tcp".into(),
            UDP => "udp".into(),
            ICMP6 => "icmp6".into(),
            n => format!("proto-{n}"),
        }
    }

    pub fn parse(s: &str) -> Option<u8> {
        match s.to_ascii_lowercase().as_str() {
            "icmp" => Some(ICMP),
            "tcp" => Some(TCP),
            "udp" => Some(UDP),
            "icmp6" | "ipv6-icmp" => Some(ICMP6),
            other => other.strip_prefix("proto-").unwrap_or(other).parse().ok(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Line {

    pub ts: String,

    pub rule: Option<u32>,

    pub tracker: String,

    pub iface: String,

    pub reason: String,

    pub action: Action,

    pub dir: Dir,

    pub proto: u8,

    pub src: IpAddr,

    pub dst: IpAddr,

    pub sport: Option<u16>,

    pub dport: Option<u16>,

    pub tcp_flags: Option<String>,

    pub icmp: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Reject {

    Oversize,

    NotPrintable,

    NotFilterlog,

    TooManyFields,

    Short,

    BadField,

    BadVersion,
}

impl Reject {

    pub const ALL: [Reject; 7] = [
        Reject::Oversize,
        Reject::NotPrintable,
        Reject::NotFilterlog,
        Reject::TooManyFields,
        Reject::Short,
        Reject::BadField,
        Reject::BadVersion,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Reject::Oversize => "oversize",
            Reject::NotPrintable => "not printable",
            Reject::NotFilterlog => "not filterlog",
            Reject::TooManyFields => "too many fields",
            Reject::Short => "short",
            Reject::BadField => "bad field",
            Reject::BadVersion => "bad ip version",
        }
    }
}

fn split_syslog(line: &str) -> Result<(&str, &str), Reject> {
    let body = match line.strip_prefix('<') {
        Some(rest) => {
            let end = rest.find('>').ok_or(Reject::NotFilterlog)?;
            let pri = rest.get(..end).ok_or(Reject::NotFilterlog)?;
            if pri.is_empty() || pri.len() > 3 || !pri.bytes().all(|b| b.is_ascii_digit()) {
                return Err(Reject::NotFilterlog);
            }
            rest.get(end + 1..).ok_or(Reject::NotFilterlog)?
        }
        None => line,
    };
    if let Some(rest) = body.strip_prefix("1 ") {

        let mut it = rest.splitn(7, ' ');
        let ts = it.next().ok_or(Reject::NotFilterlog)?;
        let _host = it.next().ok_or(Reject::NotFilterlog)?;
        if it.next() != Some("filterlog") {
            return Err(Reject::NotFilterlog);
        }
        let _pid = it.next().ok_or(Reject::NotFilterlog)?;
        let _msgid = it.next().ok_or(Reject::NotFilterlog)?;
        let _sd = it.next().ok_or(Reject::NotFilterlog)?;
        let csv = it.next().ok_or(Reject::NotFilterlog)?;
        return Ok((ts, csv));
    }

    let at = body.find(" filterlog[").ok_or(Reject::NotFilterlog)?;
    let before = body.get(..at).ok_or(Reject::NotFilterlog)?;
    let after = body.get(at + " filterlog[".len()..).ok_or(Reject::NotFilterlog)?;
    let close = after.find("]: ").ok_or(Reject::NotFilterlog)?;
    let pid = after.get(..close).ok_or(Reject::NotFilterlog)?;
    if pid.is_empty() || !pid.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Reject::NotFilterlog);
    }
    let csv = after.get(close + 3..).ok_or(Reject::NotFilterlog)?;

    let ts = match before.get(..15) {
        Some(t) if is_bsd_time(t) && before.get(15..).is_none_or(|r| r.is_empty() || r.starts_with(' ')) => t,
        _ => match before.split_once(' ') {
            Some((t, _host)) => t,
            None => before,
        },
    };
    if ts.is_empty() || ts.len() > 40 {
        return Err(Reject::NotFilterlog);
    }
    Ok((ts, csv))
}

fn is_bsd_time(t: &str) -> bool {
    let b = t.as_bytes();
    let months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    b.len() == 15
        && months.iter().any(|m| t.starts_with(m))
        && b.get(3) == Some(&b' ')
        && t.get(4..6).is_some_and(|d| d.trim_start().parse::<u8>().is_ok_and(|d| (1..=31).contains(&d)))
        && b.get(6) == Some(&b' ')
        && t.get(7..15).is_some_and(|c| c.len() == 8 && c.bytes().enumerate().all(|(i, x)| if i == 2 || i == 5 { x == b':' } else { x.is_ascii_digit() }))
}

fn num<T: std::str::FromStr>(s: &str) -> Result<T, Reject> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) || s.len() > 10 {
        return Err(Reject::BadField);
    }
    s.parse().map_err(|_| Reject::BadField)
}

fn opt_num<T: std::str::FromStr>(s: &str) -> Result<Option<T>, Reject> {
    if s.is_empty() {
        Ok(None)
    } else {
        num(s).map(Some)
    }
}

fn token(s: &str, max: usize) -> Result<String, Reject> {
    let ok = s.len() <= max && s.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'(' | b')'));
    if ok {
        Ok(s.to_string())
    } else {
        Err(Reject::BadField)
    }
}

fn addr(s: &str) -> Result<IpAddr, Reject> {
    s.parse().map_err(|_| Reject::BadField)
}

pub fn parse_line(raw: &[u8]) -> Result<Line, Reject> {
    let raw = raw.strip_suffix(b"\n").unwrap_or(raw);
    let raw = raw.strip_suffix(b"\r").unwrap_or(raw);
    if raw.len() > MAX_LINE {
        return Err(Reject::Oversize);
    }
    if !raw.iter().all(|b| (0x20..0x7f).contains(b)) {
        return Err(Reject::NotPrintable);
    }
    let line = std::str::from_utf8(raw).map_err(|_| Reject::NotPrintable)?;
    let (ts, csv) = split_syslog(line)?;
    let f: Vec<&str> = csv.splitn(MAX_FIELDS + 1, ',').collect();
    if f.len() > MAX_FIELDS {
        return Err(Reject::TooManyFields);
    }
    let get = |i: usize| f.get(i).copied().ok_or(Reject::Short);

    let rule = opt_num::<u32>(get(0)?)?;
    let tracker = token(get(3)?, MAX_TRACKER)?;
    let iface = token(get(4)?, MAX_IFACE)?;
    let reason = token(get(5)?, 32)?;
    let action = match get(6)? {
        "pass" => Action::Pass,
        "block" => Action::Block,
        other => {
            token(other, 16)?;
            Action::Other
        }
    };
    let dir = match get(7)? {
        "in" => Dir::In,
        "out" => Dir::Out,
        other => {
            token(other, 16)?;
            Dir::Other
        }
    };

    let (proto_at, src_at) = match get(8)? {
        "4" => (15, 18),
        "6" => (13, 15),
        _ => return Err(Reject::BadVersion),
    };
    let proto = num::<u8>(get(proto_at)?)?;

    let text_at = if proto_at == 15 { 16 } else { 12 };
    if let Some(p) = proto::parse(get(text_at)?) {
        let alias = matches!((p, proto), (proto::ICMP6, proto::ICMP6) | (proto::ICMP, proto::ICMP6));
        if p != proto && !alias {
            return Err(Reject::BadField);
        }
    }
    let src = addr(get(src_at)?)?;
    let dst = addr(get(src_at + 1)?)?;
    if src.is_ipv4() != (proto_at == 15) || dst.is_ipv4() != (proto_at == 15) {
        return Err(Reject::BadField);
    }
    let tail = src_at + 2;
    let (mut sport, mut dport, mut tcp_flags, mut icmp) = (None, None, None, None);
    match proto {
        proto::TCP | proto::UDP => {
            sport = Some(num::<u16>(get(tail)?)?);
            dport = Some(num::<u16>(get(tail + 1)?)?);
            if proto == proto::TCP {
                let fl = get(tail + 3)?;
                if fl.len() > 12 || !fl.bytes().all(|b| b.is_ascii_uppercase()) {
                    return Err(Reject::BadField);
                }
                tcp_flags = Some(fl.to_string());
            }
        }
        proto::ICMP | proto::ICMP6 => {

            icmp = Some(token(get(tail)?, 24)?);
        }
        _ => {}
    }
    Ok(Line {
        ts: ts.to_string(),
        rule,
        tracker,
        iface,
        reason,
        action,
        dir,
        proto,
        src,
        dst,
        sport,
        dport,
        tcp_flags,
        icmp,
    })
}

pub fn parse_all(text: &[u8]) -> (Vec<Line>, Vec<(Reject, usize)>) {
    let mut out = Vec::new();
    let mut counts = [0usize; Reject::ALL.len()];
    for l in text.split(|b| *b == b'\n') {
        if l.is_empty() {
            continue;
        }
        match parse_line(l) {
            Ok(x) => out.push(x),
            Err(r) => {
                if let Some(i) = Reject::ALL.iter().position(|x| *x == r) {
                    if let Some(c) = counts.get_mut(i) {
                        *c += 1;
                    }
                }
            }
        }
    }
    let rejects = Reject::ALL.iter().copied().zip(counts).filter(|(_, n)| *n > 0).collect();
    (out, rejects)
}
