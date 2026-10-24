use std::fmt;

use quick_xml::events::Event;
use quick_xml::{Reader, XmlVersion};

pub const CONFIG_PATH: &str = "/cf/conf/config.xml";

pub const MAX_BYTES: u64 = 16 * 1024 * 1024;

pub const MAX_DEPTH: usize = 32;

pub const MAX_ELEMENTS: usize = 1_000_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {

    TooLarge(u64),

    NotUtf8(usize),

    DocType,

    TooDeep(String),

    TooManyElements,

    Entity(String),

    Malformed(String),

    Root(String),

    Empty,
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Refusal::TooLarge(n) => write!(f, "config.xml is {n} bytes, over the {MAX_BYTES}-byte cap"),
            Refusal::NotUtf8(at) => write!(f, "config.xml is not UTF-8 (at byte {at})"),
            Refusal::DocType => f.write_str(
                "config.xml declares a DOCTYPE, which pfSense never writes; refused unread, since \
                 a DTD is how a document defines entities a reader would expand",
            ),
            Refusal::TooDeep(at) => write!(f, "config.xml nests deeper than {MAX_DEPTH} elements (at <{at}>)"),
            Refusal::TooManyElements => write!(f, "config.xml has more than {MAX_ELEMENTS} elements"),
            Refusal::Entity(e) => write!(f, "config.xml uses an undeclared entity &{e};"),
            Refusal::Malformed(why) => write!(f, "config.xml is not well-formed: {why}"),
            Refusal::Root(name) => write!(f, "config.xml's root element is <{name}>, not <pfsense>"),
            Refusal::Empty => f.write_str("config.xml has no root element"),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Element {

    pub name: String,

    pub attrs: Vec<(String, String)>,

    pub text: String,

    pub children: Vec<Element>,
}

impl Element {

    pub fn child(&self, name: &str) -> Option<&Element> {
        self.children.iter().find(|c| c.name == name)
    }

    pub fn all<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a Element> + 'a {
        self.children.iter().filter(move |c| c.name == name)
    }

    pub fn get(&self, path: &str) -> Option<&Element> {
        path.split('/').filter(|s| !s.is_empty()).try_fold(self, |e, step| e.child(step))
    }

    pub fn text_at(&self, path: &str) -> Option<&str> {
        self.get(path).map(|e| e.text.as_str())
    }

    pub fn has(&self, path: &str) -> bool {
        self.get(path).is_some()
    }

    pub fn is_leaf(&self) -> bool {
        self.children.is_empty()
    }

    pub fn leaves(&self) -> Vec<(String, String)> {
        let mut out = Vec::new();
        for c in &self.children {
            c.leaves_into(&c.name, &mut out);
        }
        out
    }

    fn leaves_into(&self, at: &str, out: &mut Vec<(String, String)>) {
        for (k, v) in &self.attrs {
            out.push((format!("{at}@{k}"), v.clone()));
        }
        if self.children.is_empty() {
            out.push((at.to_string(), self.text.clone()));
            return;
        }
        if !self.text.is_empty() {
            out.push((at.to_string(), self.text.clone()));
        }
        for c in &self.children {
            c.leaves_into(&format!("{at}/{}", c.name), out);
        }
    }
}

fn xml_trim(s: &str) -> &str {
    s.trim_matches(|c| matches!(c, ' ' | '\t' | '\r' | '\n'))
}

pub fn parse(bytes: &[u8]) -> Result<Config, Refusal> {
    let len = bytes.len() as u64;
    if len > MAX_BYTES {
        return Err(Refusal::TooLarge(len));
    }
    let text = std::str::from_utf8(bytes).map_err(|e| Refusal::NotUtf8(e.valid_up_to()))?;
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let mut reader = Reader::from_str(text);
    {
        let c = reader.config_mut();
        c.check_end_names = true;
        c.check_comments = true;
        c.allow_unmatched_ends = false;
        c.expand_empty_elements = false;
    }
    let mut stack: Vec<Element> = Vec::new();
    let mut root: Option<Element> = None;
    let mut count = 0usize;
    let malformed = |r: &Reader<&[u8]>, why: String| Refusal::Malformed(format!("{why} (near byte {})", r.buffer_position()));
    loop {
        let ev = reader.read_event().map_err(|e| malformed(&reader, e.to_string()))?;
        match ev {
            Event::DocType(_) => return Err(Refusal::DocType),
            Event::Start(s) | Event::Empty(s) if root.is_some() && stack.is_empty() => {
                return Err(malformed(&reader, format!("a second root element <{}>", s.name().as_ref())));
            }
            Event::Start(s) => {
                let el = open(&s, &mut count, stack.len())?;
                stack.push(el);
            }
            Event::Empty(s) => {
                let el = open(&s, &mut count, stack.len())?;
                close(el, &mut stack, &mut root);
            }
            Event::End(_) => {
                let Some(el) = stack.pop() else {
                    return Err(malformed(&reader, "an end tag with nothing open".into()));
                };
                close(el, &mut stack, &mut root);
            }
            Event::Text(t) => {
                let s = t.xml10_content();
                match stack.last_mut() {
                    Some(top) => top.text.push_str(&s),
                    None if xml_trim(&s).is_empty() => {}
                    None => return Err(malformed(&reader, "text outside the root element".into())),
                }
            }
            Event::CData(c) => match stack.last_mut() {
                Some(top) => top.text.push_str(&c.xml10_content()),
                None => return Err(malformed(&reader, "CDATA outside the root element".into())),
            },
            Event::GeneralRef(r) => {
                let ch = match r.resolve_char_ref() {
                    Ok(Some(ch)) => ch.to_string(),
                    Ok(None) => match quick_xml::escape::resolve_predefined_entity(r.as_ref()) {
                        Some(s) => s.to_string(),
                        None => return Err(Refusal::Entity(r.as_ref().chars().take(64).collect())),
                    },
                    Err(e) => return Err(malformed(&reader, e.to_string())),
                };
                match stack.last_mut() {
                    Some(top) => top.text.push_str(&ch),
                    None => return Err(malformed(&reader, "a reference outside the root element".into())),
                }
            }
            Event::Decl(_) | Event::PI(_) | Event::Comment(_) => {}
            Event::Eof => break,
        }
    }
    if let Some(open) = stack.last() {
        return Err(Refusal::Malformed(format!("<{}> is never closed", open.name)));
    }
    let root = root.ok_or(Refusal::Empty)?;
    if root.name != "pfsense" {
        return Err(Refusal::Root(root.name.chars().take(64).collect()));
    }
    Ok(Config { root, bytes: bytes.len() })
}

fn open(s: &quick_xml::events::BytesStart<'_>, count: &mut usize, depth: usize) -> Result<Element, Refusal> {
    let name = s.name().as_ref().to_string();
    if depth >= MAX_DEPTH {
        return Err(Refusal::TooDeep(name.chars().take(64).collect()));
    }
    *count += 1;
    if *count > MAX_ELEMENTS {
        return Err(Refusal::TooManyElements);
    }
    let mut attrs = Vec::new();
    for a in s.attributes() {
        let a = a.map_err(|e| Refusal::Malformed(format!("an attribute of <{name}>: {e}")))?;
        let v = a.normalized_value(XmlVersion::Implicit1_0).map_err(|e| match e {
            quick_xml::Error::Escape(quick_xml::escape::EscapeError::UnrecognizedEntity(_, ent)) => Refusal::Entity(ent),
            other => Refusal::Malformed(format!("an attribute of <{name}>: {other}")),
        })?;
        attrs.push((a.key.as_ref().to_string(), v.into_owned()));
    }
    Ok(Element { name, attrs, text: String::new(), children: Vec::new() })
}

fn close(mut el: Element, stack: &mut [Element], root: &mut Option<Element>) {
    let t = xml_trim(&el.text);
    if t.len() != el.text.len() {
        el.text = t.to_string();
    }
    match stack.last_mut() {
        Some(parent) => parent.children.push(el),
        None => *root = Some(el),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    root: Element,
    bytes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Revision {

    pub time: String,

    pub description: String,

    pub username: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct User {

    pub name: String,

    pub uid: String,

    pub scope: String,

    pub groupname: String,

    pub privs: Vec<String>,

    pub disabled: bool,

    pub expires: String,

    pub password: Option<(String, String)>,

    pub authorized_keys: Option<Result<String, String>>,
}

impl User {

    pub fn privileged(&self) -> bool {
        self.privs.iter().any(|p| PRIVILEGED_PRIVS.contains(&p.as_str()))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Group {

    pub name: String,

    pub gid: String,

    pub scope: String,

    pub members: Vec<String>,

    pub privs: Vec<String>,
}

impl Group {

    pub fn privileged(&self) -> bool {
        self.name == "admins" || self.privs.iter().any(|p| PRIVILEGED_PRIVS.contains(&p.as_str()))
    }
}

pub const PRIVILEGED_PRIVS: &[&str] = &["page-all", "user-shell-access"];

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Endpoint {

    pub any: bool,

    pub network: Option<String>,

    pub address: Option<String>,

    pub port: Option<String>,

    pub not: bool,
}

impl Endpoint {
    fn from(e: Option<&Element>) -> Endpoint {
        let Some(e) = e else { return Endpoint::default() };
        Endpoint {
            any: e.has("any"),
            network: e.text_at("network").map(str::to_string),
            address: e.text_at("address").map(str::to_string),
            port: e.text_at("port").map(str::to_string),
            not: e.has("not"),
        }
    }

    pub fn render(&self) -> String {
        let mut s = String::new();
        if self.not {
            s.push('!');
        }
        match (&self.network, &self.address) {
            (Some(n), _) => s.push_str(n),
            (None, Some(a)) => s.push_str(a),
            (None, None) => s.push_str("any"),
        }
        if let Some(p) = &self.port {
            s.push_str(" port ");
            s.push_str(p);
        }
        s
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {

    pub index: usize,

    pub tracker: Option<String>,

    pub kind: String,

    pub interfaces: Vec<String>,

    pub floating: bool,

    pub quick: bool,

    pub disabled: bool,

    pub ipprotocol: String,

    pub protocol: String,

    pub source: Endpoint,

    pub destination: Endpoint,

    pub descr: String,

    pub fields: Vec<(String, String)>,
}

impl Rule {

    pub fn is_pass_on(&self, wan: &[String]) -> bool {
        self.kind == "pass" && !self.disabled && self.interfaces.iter().any(|i| wan.contains(i))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CronItem {

    pub when: [String; 5],

    pub who: String,

    pub command: String,
}

impl CronItem {

    pub fn line(&self) -> String {
        format!("{}\t{}\t{}", self.when.join("\t"), self.who, self.command)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ShellKind {

    Early,

    Late,

    AfterBootup,
}

impl ShellKind {

    pub const ALL: [ShellKind; 3] = [ShellKind::Early, ShellKind::Late, ShellKind::AfterBootup];

    pub fn element(self) -> &'static str {
        match self {
            ShellKind::Early => "earlyshellcmd",
            ShellKind::Late => "shellcmd",
            ShellKind::AfterBootup => "afterbootupshellcmd",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShellCmd {

    pub kind: ShellKind,

    pub command: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Package {

    pub name: String,

    pub version: String,

    pub configurationfile: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SudoRow {

    pub username: String,

    pub runas: String,

    pub nopasswd: bool,

    pub cmdlist: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cert {

    pub refid: String,

    pub descr: String,

    pub crt: String,

    pub has_private_key: bool,

    pub trust: bool,
}

fn texts(e: &Element, name: &str) -> Vec<String> {
    e.all(name).map(|c| c.text.clone()).filter(|t| !t.is_empty()).collect()
}

fn text(e: &Element, path: &str) -> String {
    e.text_at(path).unwrap_or_default().to_string()
}

pub const PASSWORD_FIELDS: &[&str] = &["bcrypt-hash", "sha512-hash", "md5-hash", "password"];

impl Config {

    pub fn root(&self) -> &Element {
        &self.root
    }

    pub fn bytes(&self) -> usize {
        self.bytes
    }

    pub fn version(&self) -> Option<&str> {
        self.root.text_at("version")
    }

    pub fn revision(&self) -> Option<Revision> {
        let r = self.root.child("revision")?;
        Some(Revision { time: text(r, "time"), description: text(r, "description"), username: text(r, "username") })
    }

    pub fn users(&self) -> Vec<User> {
        let Some(sys) = self.root.child("system") else { return Vec::new() };
        sys.all("user")
            .map(|u| User {
                name: text(u, "name"),
                uid: text(u, "uid"),
                scope: text(u, "scope"),
                groupname: text(u, "groupname"),
                privs: texts(u, "priv"),
                disabled: u.has("disabled"),
                expires: text(u, "expires"),
                password: PASSWORD_FIELDS
                    .iter()
                    .find_map(|f| u.child(f).map(|e| ((*f).to_string(), e.text.clone()))),
                authorized_keys: u
                    .child("authorizedkeys")
                    .filter(|e| !e.text.is_empty())
                    .map(|e| base64_text(&e.text)),
            })
            .collect()
    }

    pub fn groups(&self) -> Vec<Group> {
        let Some(sys) = self.root.child("system") else { return Vec::new() };
        sys.all("group")
            .map(|g| Group {
                name: text(g, "name"),
                gid: text(g, "gid"),
                scope: text(g, "scope"),
                members: texts(g, "member"),
                privs: texts(g, "priv"),
            })
            .collect()
    }

    pub fn rules(&self) -> Vec<Rule> {
        let Some(filter) = self.root.child("filter") else { return Vec::new() };
        filter
            .all("rule")
            .enumerate()
            .map(|(index, r)| Rule {
                index,
                tracker: r.text_at("tracker").filter(|t| !t.is_empty()).map(str::to_string),
                kind: r.text_at("type").filter(|t| !t.is_empty()).unwrap_or("pass").to_string(),
                interfaces: text(r, "interface").split(',').map(str::trim).filter(|s| !s.is_empty()).map(str::to_string).collect(),
                floating: r.text_at("floating").is_some_and(|f| f == "yes"),
                quick: r.has("quick"),
                disabled: r.has("disabled"),
                ipprotocol: text(r, "ipprotocol"),
                protocol: text(r, "protocol"),
                source: Endpoint::from(r.child("source")),
                destination: Endpoint::from(r.child("destination")),
                descr: text(r, "descr"),
                fields: r
                    .children
                    .iter()
                    .filter(|c| c.name != "created" && c.name != "updated")
                    .flat_map(|c| {
                        let mut v = Vec::new();
                        c.leaves_into(&c.name, &mut v);
                        v
                    })
                    .collect(),
            })
            .collect()
    }

    pub fn wan_interfaces(&self) -> Vec<String> {
        let mut out = vec!["wan".to_string()];
        if let Some(ifs) = self.root.child("interfaces") {
            for i in &ifs.children {
                let upstream = matches!(i.text_at("ipaddr"), Some("dhcp" | "pppoe" | "pptp" | "l2tp"))
                    || i.text_at("gateway").is_some_and(|g| !g.is_empty());
                if upstream && !out.contains(&i.name) {
                    out.push(i.name.clone());
                }
            }
        }
        out
    }

    pub fn cron_items(&self) -> Vec<CronItem> {
        let Some(cron) = self.root.child("cron") else { return Vec::new() };
        cron.all("item")
            .map(|i| CronItem {
                when: ["minute", "hour", "mday", "month", "wday"].map(|f| text(i, f)),
                who: text(i, "who"),
                command: text(i, "command"),
            })
            .collect()
    }

    pub fn shellcmds(&self) -> Vec<ShellCmd> {
        let Some(sys) = self.root.child("system") else { return Vec::new() };
        ShellKind::ALL
            .iter()
            .flat_map(|&kind| {
                sys.all(kind.element())
                    .filter(|e| !e.text.is_empty())
                    .map(move |e| ShellCmd { kind, command: e.text.clone() })
            })
            .collect()
    }

    pub fn packages(&self) -> Vec<Package> {
        let Some(ip) = self.root.child("installedpackages") else { return Vec::new() };
        ip.all("package")
            .map(|p| Package {
                name: text(p, "name"),
                version: text(p, "version"),
                configurationfile: text(p, "configurationfile"),
            })
            .collect()
    }

    pub fn has_package(&self, name: &str) -> bool {
        self.packages().iter().any(|p| p.name == name)
    }

    pub fn sudo_rows(&self) -> Vec<SudoRow> {
        let Some(cfg) = self.root.get("installedpackages/sudo/config") else { return Vec::new() };
        cfg.all("row")
            .map(|r| SudoRow {
                username: text(r, "username"),
                runas: text(r, "runas"),
                nopasswd: r.text_at("nopasswd").is_some_and(|v| v.eq_ignore_ascii_case("on")),
                cmdlist: text(r, "cmdlist"),
            })
            .collect()
    }

    pub fn certs(&self, which: CertKind) -> Vec<Cert> {
        self.root
            .all(which.element())
            .map(|c| Cert {
                refid: text(c, "refid"),
                descr: text(c, "descr"),
                crt: text(c, "crt"),
                has_private_key: c.text_at("prv").is_some_and(|p| !p.is_empty()),
                trust: c.text_at("trust").is_some_and(|t| t.trim() == "enabled"),
            })
            .collect()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertKind {

    Cert,

    Ca,
}

impl CertKind {

    pub fn element(self) -> &'static str {
        match self {
            CertKind::Cert => "cert",
            CertKind::Ca => "ca",
        }
    }
}

pub fn base64_decode(s: &str) -> Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity(s.len() / 4 * 3);
    let mut acc = 0u32;
    let mut bits = 0u32;
    let mut pad = 0usize;
    for (i, c) in s.bytes().enumerate() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' => {
                pad += 1;
                continue;
            }
            b' ' | b'\t' | b'\r' | b'\n' => continue,
            _ => return Err(format!("byte {i} is not base64")),
        };
        if pad > 0 {
            return Err("data after base64 padding".into());
        }
        acc = (acc << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((acc >> bits) & 0xff) as u8);
        }
    }
    if pad > 2 || bits >= 6 {
        return Err("base64 of a length no encoder produces".into());
    }
    Ok(out)
}

pub fn base64_text(s: &str) -> Result<String, String> {
    let b = base64_decode(s)?;
    String::from_utf8(b).map_err(|_| "base64 that does not decode to text".to_string())
}
