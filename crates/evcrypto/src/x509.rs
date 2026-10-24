use sha2::{Digest as _, Sha256};

pub const MAX_CERT_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cert {

    pub sha256: [u8; 32],

    pub sha1: [u8; 20],

    pub subject: String,

    pub issuer: String,

    pub self_issued: bool,

    pub serial: String,

    pub version: u8,

    pub not_before: i64,

    pub not_after: i64,

    pub ca: Option<bool>,

    pub path_len: Option<u32>,

    pub key_cert_sign: Option<bool>,

    pub eku: Option<Vec<String>>,

    pub name_constraints: bool,

    pub key_alg: String,

    pub sig_alg: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {

    Info,

    Note,

    Warn,

    Critical,
}

impl Level {

    pub fn tag(self) -> &'static str {
        match self {
            Level::Info => "info",
            Level::Note => "note",
            Level::Warn => "WARN",
            Level::Critical => "CRITICAL",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {

    Vendor,

    VendorModified,

    Local,

    BundleOnly,

    Redirected,

    Added,

    Distrusted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Arrival {

    Present,

    Added,

    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Grade {

    pub level: Level,

    pub signs_any: bool,

    pub interception: Option<String>,

    pub reasons: Vec<String>,
}

pub const RECENT_SECS: i64 = 90 * 86_400;

pub const SHORT_LIVED_SECS: i64 = 3 * 365 * 86_400;

pub const PROXY_HINTS: &[&str] = &[
    "mitmproxy",
    "portswigger",
    "burp",
    "fiddler",
    "do_not_trust",
    "charles proxy",
    "charlesproxy",
    "proxyman",
    "http toolkit",
    "httptoolkit",
    "owasp zap",
    "zed attack proxy",
    "sslsplit",
    "bettercap",
    "polarproxy",
    "mitm",
];

pub const EKU_SERVER_AUTH: &str = "1.3.6.1.5.5.7.3.1";

pub const EKU_ANY: &str = "2.5.29.37.0";

pub fn grade(cert: &Cert, origin: Origin, arrival: Arrival, now: i64) -> Grade {
    let signs_any = signs_any(cert);
    let interception = interception(cert);
    let mut reasons = Vec::new();
    let expired = cert.not_after < now;
    let age = now - cert.not_before;
    let recent = !expired && (0..RECENT_SECS).contains(&age);
    let future = cert.not_before > now + 86_400;
    let span = cert.not_after - cert.not_before;
    let short = !expired && span < SHORT_LIVED_SECS;

    let base = match origin {
        Origin::Vendor => {
            reasons.push("shipped by the vendor, and the vendor's record still matches it".to_string());
            if arrival == Arrival::Added {
                reasons.push("new since the arrival snapshot, which is what a package update does".into());
                Level::Note
            } else {
                Level::Info
            }
        }
        Origin::Distrusted => {
            reasons.push("listed to be distrusted, so it takes trust away rather than adding it".into());
            Level::Note
        }
        Origin::VendorModified => {
            reasons.push(
                "it sits in a file the vendor shipped, and the file no longer matches what the vendor \
                 shipped there: no update or administrator edits a distribution's anchor in place"
                    .into(),
            );
            Level::Warn
        }
        Origin::Local => {
            reasons.push(
                "no package or vendor record accounts for it: an administrator put it here, or an \
                 adversary did, and the two look exactly alike"
                    .into(),
            );
            Level::Warn
        }
        Origin::BundleOnly => {
            reasons.push(
                "it is in a bundle the host's TLS reads and in none of the sources the bundle is built \
                 from, so the bundle was edited directly rather than through the store's own tooling"
                    .into(),
            );
            Level::Warn
        }
        Origin::Redirected => {
            reasons.push(
                "TLS is pointed at it by an environment variable or a tool's configuration rather than \
                 the system store, so the programs that read that setting trust it"
                    .into(),
            );
            Level::Warn
        }
        Origin::Added => {
            reasons.push("it was added to a store that ships empty".into());
            Level::Warn
        }
    };
    if matches!(origin, Origin::Vendor | Origin::Distrusted) {
        return Grade { level: base, signs_any, interception, reasons };
    }

    match arrival {
        Arrival::Present => reasons.push("it was already here when the arrival snapshot was taken".into()),
        Arrival::Added => reasons.push("it was NOT here when the arrival snapshot was taken: it was added since".into()),
        Arrival::Unknown => reasons.push(
            "there is no arrival snapshot of the trust store to say whether it was here before the \
             responders were"
                .into(),
        ),
    }
    if signs_any {
        reasons.push(
            "it is a CA with no name constraints and no purpose that excludes TLS servers, so it can \
             sign a certificate for any name — every HTTPS site this host visits"
                .into(),
        );
    } else if cert.name_constraints {
        reasons.push("its name constraints limit what it can sign for".into());
    } else if cert.ca == Some(false) || cert.key_cert_sign == Some(false) {
        reasons.push("it is not a CA, so it vouches only for the names in itself".into());
    } else {
        reasons.push("its purposes exclude TLS servers".into());
    }
    if expired {
        reasons.push(format!("it expired {} ago, so most TLS libraries reject what it signs", days(now - cert.not_after)));
    }
    if future {
        reasons.push(format!("it is not valid until {} from now", days(cert.not_before - now)));
    }
    if recent {
        reasons.push(format!("it was issued {} ago", days(age.max(0))));
    }
    if short {
        reasons.push(format!("it is valid for only {} in all, short for a CA", days(span.max(0))));
    }
    if let Some(why) = &interception {
        reasons.push(why.clone());
    }

    let critical = signs_any
        && (arrival == Arrival::Added
            || recent
            || short
            || interception.is_some()
            || origin == Origin::VendorModified);
    let level = if critical { Level::Critical } else { base };
    if !critical && signs_any && origin != Origin::VendorModified {
        reasons.push(
            "a legitimate enterprise or TLS-inspection CA looks exactly like this: confirm it with \
             whoever runs that PKI before trusting the host's TLS"
                .into(),
        );
    }
    Grade { level, signs_any, interception, reasons }
}

pub fn signs_any(cert: &Cert) -> bool {
    let ca = match cert.ca {
        Some(c) => c,
        None => cert.version == 1 && cert.self_issued,
    };
    let eku_ok = cert
        .eku
        .as_ref()
        .is_none_or(|e| e.iter().any(|o| o == EKU_SERVER_AUTH || o == EKU_ANY));
    ca && cert.key_cert_sign != Some(false) && !cert.name_constraints && eku_ok
}

pub fn interception(cert: &Cert) -> Option<String> {
    let text = format!("{} {}", cert.subject, cert.issuer).to_ascii_lowercase();
    let hint = PROXY_HINTS.iter().find(|h| text.contains(*h));
    let shaped = cert.self_issued
        && cert.ca == Some(true)
        && cert.eku.as_ref().is_some_and(|e| e.iter().any(|o| o == EKU_SERVER_AUTH));
    match (hint, shaped) {
        (Some(h), true) => Some(format!(
            "it is shaped like an interception proxy's CA (a root that names TLS server \
             authentication as its purpose), and its name contains `{h}`"
        )),
        (Some(h), false) => Some(format!("its name contains `{h}`, which interception proxies use")),
        (None, true) => Some(
            "it is shaped like an interception proxy's CA: a root that names TLS server \
             authentication as its purpose, which distribution and enterprise roots almost never do"
                .into(),
        ),
        (None, false) => None,
    }
}

fn days(secs: i64) -> String {
    if secs < 2 * 86_400 {
        format!("{} hour(s)", secs / 3600)
    } else {
        format!("{} days", secs / 86_400)
    }
}

impl Cert {

    pub fn parse(der: &[u8]) -> Result<Cert, String> {
        let (cert, rest) = Cert::parse_prefix(der)?;
        if !rest.is_empty() {
            return Err(format!("{} byte(s) after the certificate", rest.len()));
        }
        Ok(cert)
    }

    pub fn parse_prefix(der: &[u8]) -> Result<(Cert, &[u8]), String> {
        let outer = tlv(der)?;
        if outer.tag != SEQUENCE {
            return Err("not a DER SEQUENCE".into());
        }
        if outer.whole.len() > MAX_CERT_BYTES {
            return Err(format!("{} bytes, larger than any certificate", outer.whole.len()));
        }
        let whole = outer.whole;
        let tbs = tlv(outer.content)?;
        if tbs.tag != SEQUENCE {
            return Err("no tbsCertificate".into());
        }
        let sig = tlv(tbs.rest)?;
        if sig.tag != SEQUENCE {
            return Err("no signatureAlgorithm".into());
        }
        let sig_value = tlv(sig.rest)?;
        if sig_value.tag != BIT_STRING || !sig_value.rest.is_empty() {
            return Err("no signatureValue".into());
        }
        let sig_alg = alg_name(sig.content)?;

        let mut t = tbs.content;
        let mut version = 1u8;
        let first = tlv(t)?;
        if first.tag == 0xa0 {
            let v = tlv(first.content)?;
            if v.tag != INTEGER || v.content.len() != 1 {
                return Err("a version that is not a small INTEGER".into());
            }
            version = v.content.first().copied().unwrap_or(0).saturating_add(1);
            t = first.rest;
        }
        let serial = tlv(t)?;
        if serial.tag != INTEGER {
            return Err("no serialNumber".into());
        }
        let alg = tlv(serial.rest)?;
        if alg.tag != SEQUENCE {
            return Err("no signature algorithm in tbsCertificate".into());
        }
        let issuer = tlv(alg.rest)?;
        if issuer.tag != SEQUENCE {
            return Err("no issuer".into());
        }
        let validity = tlv(issuer.rest)?;
        if validity.tag != SEQUENCE {
            return Err("no validity".into());
        }
        let nb = tlv(validity.content)?;
        let na = tlv(nb.rest)?;
        let not_before = time(nb.tag, nb.content)?;
        let not_after = time(na.tag, na.content)?;
        let subject = tlv(validity.rest)?;
        if subject.tag != SEQUENCE {
            return Err("no subject".into());
        }
        let spki = tlv(subject.rest)?;
        if spki.tag != SEQUENCE {
            return Err("no subjectPublicKeyInfo".into());
        }
        let key_alg_seq = tlv(spki.content)?;
        if key_alg_seq.tag != SEQUENCE {
            return Err("no public key algorithm".into());
        }
        let key_alg = alg_name(key_alg_seq.content)?;

        let mut cert = Cert {
            sha256: Sha256::digest(whole).into(),
            sha1: sha1(whole),
            subject: name(subject.content)?,
            issuer: name(issuer.content)?,
            self_issued: subject.content == issuer.content,
            serial: hex(serial.content),
            version,
            not_before,
            not_after,
            ca: None,
            path_len: None,
            key_cert_sign: None,
            eku: None,
            name_constraints: false,
            key_alg,
            sig_alg,
        };

        let mut rest = spki.rest;
        while !rest.is_empty() {
            let f = tlv(rest)?;
            rest = f.rest;
            if f.tag == 0xa3 {
                let exts = tlv(f.content)?;
                if exts.tag != SEQUENCE {
                    return Err("extensions that are not a SEQUENCE".into());
                }
                extensions(exts.content, &mut cert)?;
            }
        }
        Ok((cert, outer.rest))
    }

    pub fn sha256_hex(&self) -> String {
        hex(&self.sha256)
    }

    pub fn thumbprint(&self) -> String {
        hex(&self.sha1).to_ascii_uppercase()
    }

    pub fn short(&self) -> String {
        self.sha256_hex().chars().take(16).collect()
    }

    pub fn describe(&self) -> String {
        if self.self_issued {
            format!("{} (self-issued)", self.subject)
        } else {
            format!("{} (issued by {})", self.subject, self.issuer)
        }
    }

    pub fn validity(&self) -> String {
        format!("{} → {}", ymd(self.not_before), ymd(self.not_after))
    }
}

const BOOLEAN: u8 = 0x01;
const INTEGER: u8 = 0x02;
const BIT_STRING: u8 = 0x03;
const OCTET_STRING: u8 = 0x04;
const OID: u8 = 0x06;
const SEQUENCE: u8 = 0x30;

struct Tlv<'a> {
    tag: u8,
    content: &'a [u8],
    rest: &'a [u8],
    whole: &'a [u8],
}

fn tlv(b: &[u8]) -> Result<Tlv<'_>, String> {
    let (&tag, after) = b.split_first().ok_or("truncated: no tag")?;
    if tag & 0x1f == 0x1f {
        return Err("a high-number tag, which no certificate field uses".into());
    }
    let (&l0, after) = after.split_first().ok_or("truncated: no length")?;
    let (len, after) = if l0 < 0x80 {
        (usize::from(l0), after)
    } else {
        let n = usize::from(l0 & 0x7f);
        if n == 0 || n > 4 {
            return Err("an indefinite or oversized length".into());
        }
        let (bytes, after) = after.split_at_checked(n).ok_or("truncated length")?;
        let len = bytes.iter().fold(0usize, |a, b| (a << 8) | usize::from(*b));
        if len < 0x80 || bytes.first() == Some(&0) {
            return Err("a length not in its shortest form".into());
        }
        (len, after)
    };
    let (content, rest) = after.split_at_checked(len).ok_or("truncated content")?;
    let header = b.len() - after.len();
    let whole = b.get(..header + len).ok_or("truncated")?;
    Ok(Tlv { tag, content, rest, whole })
}

fn each(mut b: &[u8]) -> Result<Vec<Tlv<'_>>, String> {
    let mut out = Vec::new();
    while !b.is_empty() {
        let t = tlv(b)?;
        b = t.rest;
        out.push(t);
    }
    Ok(out)
}

fn oid(b: &[u8]) -> Result<String, String> {
    let (&first, rest) = b.split_first().ok_or("an empty OID")?;
    let mut parts: Vec<u64> = if first < 80 {
        vec![u64::from(first / 40), u64::from(first % 40)]
    } else {

        if first & 0x80 != 0 {
            return Err("an OID whose first arc is not in one byte".into());
        }
        vec![2, u64::from(first - 80)]
    };
    let mut acc: u64 = 0;
    let mut open = false;
    for &x in rest {
        if acc > (u64::MAX >> 7) {
            return Err("an OID arc too large".into());
        }
        acc = (acc << 7) | u64::from(x & 0x7f);
        open = x & 0x80 != 0;
        if !open {
            parts.push(acc);
            acc = 0;
        }
    }
    if open {
        return Err("a truncated OID".into());
    }
    Ok(parts.iter().map(u64::to_string).collect::<Vec<_>>().join("."))
}

fn alg_name(content: &[u8]) -> Result<String, String> {
    let t = tlv(content)?;
    if t.tag != OID {
        return Err("an AlgorithmIdentifier with no OID".into());
    }
    let o = oid(t.content)?;
    let name = match o.as_str() {
        "1.2.840.113549.1.1.1" => "rsaEncryption",
        "1.2.840.10045.2.1" => "id-ecPublicKey",
        "1.3.101.112" => "Ed25519",
        "1.3.101.113" => "Ed448",
        "1.2.840.113549.1.1.5" => "sha1WithRSAEncryption",
        "1.2.840.113549.1.1.11" => "sha256WithRSAEncryption",
        "1.2.840.113549.1.1.12" => "sha384WithRSAEncryption",
        "1.2.840.113549.1.1.13" => "sha512WithRSAEncryption",
        "1.2.840.113549.1.1.10" => "RSASSA-PSS",
        "1.2.840.113549.1.1.4" => "md5WithRSAEncryption",
        "1.2.840.10045.4.3.2" => "ecdsa-with-SHA256",
        "1.2.840.10045.4.3.3" => "ecdsa-with-SHA384",
        "1.2.840.10045.4.3.4" => "ecdsa-with-SHA512",
        "1.2.840.10040.4.1" => "dsa",
        _ => return Ok(o),
    };
    Ok(name.to_string())
}

fn name(content: &[u8]) -> Result<String, String> {
    let mut parts: Vec<String> = Vec::new();
    for rdn in each(content)? {
        if rdn.tag != 0x31 {
            return Err("a Name whose element is not a SET".into());
        }
        for atv in each(rdn.content)? {
            if atv.tag != SEQUENCE {
                return Err("an attribute that is not a SEQUENCE".into());
            }
            let ty = tlv(atv.content)?;
            if ty.tag != OID {
                return Err("an attribute with no type".into());
            }
            let val = tlv(ty.rest)?;
            let key = match oid(ty.content)?.as_str() {
                "2.5.4.3" => "CN".to_string(),
                "2.5.4.10" => "O".to_string(),
                "2.5.4.11" => "OU".to_string(),
                "2.5.4.6" => "C".to_string(),
                "2.5.4.7" => "L".to_string(),
                "2.5.4.8" => "ST".to_string(),
                "2.5.4.5" => "serialNumber".to_string(),
                "1.2.840.113549.1.9.1" => "emailAddress".to_string(),
                "0.9.2342.19200300.100.1.25" => "DC".to_string(),
                other => other.to_string(),
            };
            parts.push(format!("{key}={}", string(val.tag, val.content)));
        }
    }
    parts.reverse();
    if parts.is_empty() {
        return Ok("(empty name)".into());
    }
    Ok(parts.join(", "))
}

fn string(tag: u8, b: &[u8]) -> String {
    let s: String = match tag {

        0x1e => {
            let (pairs, _) = b.as_chunks::<2>();
            String::from_utf16_lossy(&pairs.iter().map(|p| u16::from_be_bytes(*p)).collect::<Vec<_>>())
        }

        0x1c => {
            let (quads, _) = b.as_chunks::<4>();
            quads.iter().map(|q| char::from_u32(u32::from_be_bytes(*q)).unwrap_or('?')).collect()
        }

        0x14 => b.iter().map(|&c| char::from(c)).collect(),
        _ => String::from_utf8_lossy(b).into_owned(),
    };
    s.chars().map(|c| if c.is_control() { '?' } else { c }).take(256).collect()
}

fn time(tag: u8, b: &[u8]) -> Result<i64, String> {
    let s = std::str::from_utf8(b).map_err(|_| "a time that is not ASCII")?;
    let s = s.strip_suffix('Z').ok_or("a time that is not UTC")?;

    let s = s.split('.').next().unwrap_or(s);
    if !s.bytes().all(|c| c.is_ascii_digit()) {
        return Err("a time with a non-digit in it".into());
    }
    let n = |r: std::ops::Range<usize>| -> Result<i64, String> {
        s.get(r).and_then(|x| x.parse::<i64>().ok()).ok_or_else(|| "a short time".to_string())
    };
    let (y, rest) = match (tag, s.len()) {
        (0x17, 12) => {
            let yy = n(0..2)?;
            (if yy >= 50 { 1900 + yy } else { 2000 + yy }, 2)
        }
        (0x18, 14) => (n(0..4)?, 4),
        _ => return Err("a time that is neither UTCTime nor GeneralizedTime".into()),
    };
    let (mo, d, h, mi, se) = (n(rest..rest + 2)?, n(rest + 2..rest + 4)?, n(rest + 4..rest + 6)?, n(rest + 6..rest + 8)?, n(rest + 8..rest + 10)?);
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || h > 23 || mi > 59 || se > 60 {
        return Err("a time out of range".into());
    }
    Ok(days_from_civil(y, mo, d) * 86_400 + h * 3600 + mi * 60 + se)
}

fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

pub fn ymd(secs: i64) -> String {
    let z = secs.div_euclid(86_400) + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02}")
}

fn extensions(content: &[u8], cert: &mut Cert) -> Result<(), String> {
    for ext in each(content)? {
        if ext.tag != SEQUENCE {
            return Err("an extension that is not a SEQUENCE".into());
        }
        let id = tlv(ext.content)?;
        if id.tag != OID {
            return Err("an extension with no OID".into());
        }
        let mut next = tlv(id.rest)?;
        if next.tag == BOOLEAN {
            next = tlv(next.rest)?;
        }
        if next.tag != OCTET_STRING {
            return Err("an extension with no value".into());
        }
        let v = next.content;
        match oid(id.content)?.as_str() {
            "2.5.29.19" => {
                let bc = tlv(v)?;
                let mut ca = false;
                let mut path_len = None;
                for f in each(bc.content)? {
                    match f.tag {
                        BOOLEAN => ca = f.content.first().is_some_and(|b| *b != 0),
                        INTEGER if f.content.len() <= 4 => {
                            path_len = Some(f.content.iter().fold(0u32, |a, b| (a << 8) | u32::from(*b)));
                        }
                        _ => {}
                    }
                }
                cert.ca = Some(ca);
                cert.path_len = path_len;
            }
            "2.5.29.15" => {
                let ku = tlv(v)?;
                if ku.tag != BIT_STRING {
                    return Err("a keyUsage that is not a BIT STRING".into());
                }

                let bits = ku.content.get(1).copied().unwrap_or(0);
                cert.key_cert_sign = Some(bits & 0x04 != 0);
            }
            "2.5.29.37" => {
                let seq = tlv(v)?;
                let mut out = Vec::new();
                for o in each(seq.content)? {
                    if o.tag == OID {
                        out.push(oid(o.content)?);
                    }
                }
                cert.eku = Some(out);
            }
            "2.5.29.30" => cert.name_constraints = true,
            _ => {}
        }
    }
    Ok(())
}

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

pub fn sha1(data: &[u8]) -> [u8; 20] {
    let mut h: [u32; 5] = [0x6745_2301, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476, 0xc3d2_e1f0];
    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut msg = Vec::with_capacity(data.len() + 72);
    msg.extend_from_slice(data);
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());
    let (blocks, _) = msg.as_chunks::<64>();
    for block in blocks {
        let mut w = [0u32; 80];
        let (words, _) = block.as_chunks::<4>();
        for (slot, word) in w.iter_mut().zip(words) {
            *slot = u32::from_be_bytes(*word);
        }
        for i in 16..80 {
            let x = w.get(i - 3).copied().unwrap_or(0)
                ^ w.get(i - 8).copied().unwrap_or(0)
                ^ w.get(i - 14).copied().unwrap_or(0)
                ^ w.get(i - 16).copied().unwrap_or(0);
            if let Some(slot) = w.get_mut(i) {
                *slot = x.rotate_left(1);
            }
        }
        let [mut a, mut b, mut c, mut d, mut e] = h;
        for (i, wi) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | (!b & d), 0x5a82_7999),
                20..=39 => (b ^ c ^ d, 0x6ed9_eba1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8f1b_bcdc),
                _ => (b ^ c ^ d, 0xca62_c1d6),
            };
            let t = a.rotate_left(5).wrapping_add(f).wrapping_add(e).wrapping_add(k).wrapping_add(*wi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = t;
        }
        for (x, y) in h.iter_mut().zip([a, b, c, d, e]) {
            *x = x.wrapping_add(y);
        }
    }
    let mut out = [0u8; 20];
    for (chunk, v) in out.chunks_mut(4).zip(h) {
        chunk.copy_from_slice(&v.to_be_bytes());
    }
    out
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pem {

    pub label: String,

    pub der: Vec<u8>,

    pub reject: Vec<String>,

    pub first_line: usize,

    pub last_line: usize,

    pub start: usize,

    pub end: usize,
}

pub fn pem_blocks(text: &[u8]) -> (Vec<Pem>, usize) {
    let mut out = Vec::new();
    let mut bad = 0usize;
    let mut open: Option<(String, usize, usize, String)> = None;
    let mut pos = 0usize;
    for (i, raw) in text.split_inclusive(|b| *b == b'\n').enumerate() {
        let start = pos;
        pos += raw.len();
        let line = String::from_utf8_lossy(raw);
        let line = line.trim();
        if let Some(label) = line.strip_prefix("-----BEGIN ").and_then(|l| l.strip_suffix("-----")) {
            if label.contains("CERTIFICATE") && !label.contains("REQUEST") {
                if open.is_some() {
                    bad += 1;
                }
                open = Some((label.to_string(), i + 1, start, String::new()));
            }
            continue;
        }
        if let Some(label) = line.strip_prefix("-----END ").and_then(|l| l.strip_suffix("-----")) {
            if let Some((l, first, s, body)) = open.take() {
                if l != label {
                    bad += 1;
                    continue;
                }
                match b64(&body).and_then(|der| split_trusted(&l, der)) {
                    Some((der, reject)) => out.push(Pem { label: l, der, reject, first_line: first, last_line: i + 1, start: s, end: pos }),
                    None => bad += 1,
                }
            }
            continue;
        }
        if let Some((_, _, _, body)) = open.as_mut() {

            if !line.contains(':') {
                body.push_str(line);
            }
        }
    }
    if open.is_some() {
        bad += 1;
    }
    (out, bad)
}

fn split_trusted(label: &str, der: Vec<u8>) -> Option<(Vec<u8>, Vec<String>)> {
    let t = tlv(&der).ok()?;
    if label != "TRUSTED CERTIFICATE" {
        return t.rest.is_empty().then(|| (der.clone(), Vec::new()));
    }
    let cert = t.whole.to_vec();
    let mut reject = Vec::new();

    if let Ok(aux) = tlv(t.rest) {
        for f in each(aux.content).unwrap_or_default() {
            if f.tag == 0xa0 {
                for o in each(f.content).unwrap_or_default() {
                    if o.tag == OID {
                        if let Ok(s) = oid(o.content) {
                            reject.push(s);
                        }
                    }
                }
            }
        }
    }
    Some((cert, reject))
}

pub fn b64(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() / 4 * 3);
    let (mut acc, mut bits) = (0u32, 0u32);
    for c in s.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' => break,
            b' ' | b'\t' | b'\r' | b'\n' => continue,
            _ => return None,
        };
        acc = ((acc << 6) | u32::from(v)) & 0x00ff_ffff;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((acc >> bits) & 0xff) as u8);
        }
    }
    Some(out)
}

pub fn scan_der(b: &[u8]) -> Vec<(usize, Cert)> {
    let mut out = Vec::new();
    let mut i = 0usize;

    while let Some(off) = b.get(i..).and_then(|s| s.windows(2).position(|w| w[0] == SEQUENCE && matches!(w[1], 0x81 | 0x82))) {
        let at = i + off;
        let tail = b.get(at..).unwrap_or_default();
        match Cert::parse_prefix(tail) {
            Ok((c, rest)) => {
                let used = tail.len() - rest.len();
                out.push((at, c));
                i = at + used.max(1);
            }
            Err(_) => i = at + 1,
        }
    }
    out
}

pub type Blocks = Vec<(Pem, Result<Cert, String>)>;

pub fn certs_in(bytes: &[u8]) -> (Blocks, usize) {
    let (blocks, bad) = pem_blocks(bytes);
    if !blocks.is_empty() || bad > 0 {
        let out = blocks
            .into_iter()
            .map(|p| {
                let c = Cert::parse(&p.der);
                (p, c)
            })
            .collect();
        return (out, bad);
    }
    if bytes.first() == Some(&SEQUENCE) {
        if let Ok(c) = Cert::parse(bytes) {
            let lines = bytes.iter().filter(|b| **b == b'\n').count().max(1);
            let p = Pem {
                label: "DER".into(),
                der: bytes.to_vec(),
                reject: Vec::new(),
                first_line: 1,
                last_line: lines,
                start: 0,
                end: bytes.len(),
            };
            return (vec![(p, Ok(c))], 0);
        }
    }
    (Vec::new(), 0)
}
