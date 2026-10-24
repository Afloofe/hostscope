use std::fs;
use std::io::Write as _;
use std::path::Path;

use crate::ingest::Layout;
use crate::ledger::Ledger;
use crate::{hex, js};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Enrolled {

    pub label: String,

    pub host: [u8; 32],

    pub link: Option<[u8; 32]>,

    pub digest: [u8; 32],

    pub enrolled_ns: i64,

    pub actor: String,
}

pub fn valid_label(label: &str) -> bool {
    !label.is_empty() && label.len() <= 64 && label.bytes().all(|b| (0x21..0x7f).contains(&b) && b != b'=')
}

fn parse32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, o) in out.iter_mut().enumerate() {
        *o = u8::from_str_radix(s.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

impl Enrolled {

    fn encode(&self) -> String {
        format!(
            "label={}\nhost={}\nlink={}\ndigest={}\nenrolled_ns={}\nactor={}\n",
            self.label,
            hex(&self.host),
            self.link.map_or_else(|| "none".to_string(), |k| hex(&k)),
            hex(&self.digest),
            self.enrolled_ns,
            crate::shown(&self.actor),
        )
    }

    fn decode(text: &str) -> Result<Enrolled, String> {
        let field = |k: &str| {
            text.lines()
                .find_map(|l| l.strip_prefix(k).and_then(|r| r.strip_prefix('=')))
                .ok_or_else(|| format!("no {k}= line"))
        };
        let label = field("label")?.to_string();
        if !valid_label(&label) {
            return Err("the label is not one `enroll` writes".to_string());
        }
        let host = parse32(field("host")?).ok_or("host= is not 64 hex")?;
        let link = match field("link")? {
            "none" => None,
            k => Some(parse32(k).ok_or("link= is not 64 hex")?),
        };
        let digest = parse32(field("digest")?).ok_or("digest= is not 64 hex")?;
        let enrolled_ns = field("enrolled_ns")?.parse().map_err(|_| "enrolled_ns= is not a number")?;
        let actor = field("actor")?.to_string();
        Ok(Enrolled { label, host, link, digest, enrolled_ns, actor })
    }

    pub fn to_json(&self) -> String {
        format!(
            "{{\"kind\":\"enroll\",\"label\":{},\"host\":\"{}\",\"link\":{},\"digest\":\"{}\",\"enrolled_ns\":{},\"actor\":{}}}",
            js(&self.label),
            hex(&self.host),
            self.link.map_or_else(|| "null".to_string(), |k| format!("\"{}\"", hex(&k))),
            hex(&self.digest),
            self.enrolled_ns,
            js(&self.actor),
        )
    }
}

pub fn read_dir(dir: &Path) -> Result<Vec<Enrolled>, String> {
    let mut out = Vec::new();
    let rd = match fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
        Err(e) => return Err(format!("cannot list {}: {e}", dir.display())),
    };
    for e in rd {
        let e = e.map_err(|e| format!("cannot list {}: {e}", dir.display()))?;
        let name = e.file_name().to_string_lossy().into_owned();
        if name.ends_with(".tmp") {

            continue;
        }
        let Some(host) = parse32(&name) else {
            return Err(format!("{} holds {}, which `enroll` does not write; a human must look", dir.display(), crate::shown(&name)));
        };
        if !e.file_type().map(|t| t.is_file()).unwrap_or(false) {
            return Err(format!("enroll/{name} is not a regular file; a human must look"));
        }
        let text = fs::read_to_string(e.path()).map_err(|err| format!("cannot read enroll/{name}: {err}"))?;
        let en = Enrolled::decode(&text).map_err(|why| format!("enroll/{name} does not read: {why}"))?;
        if en.host != host {
            return Err(format!("enroll/{name} names another host inside it; a human must look"));
        }
        out.push(en);
    }
    out.sort_by_key(|e| e.host);
    Ok(out)
}

pub fn enrolled(layout: &Layout) -> Result<Vec<Enrolled>, String> {
    read_dir(&layout.enroll())
}

pub fn enroll(layout: &Layout, e: &Enrolled, ledger: &mut Ledger) -> Result<(), String> {
    if !valid_label(&e.label) {
        return Err("a label is 1 to 64 bytes of printable ASCII with no spaces and no `=`".to_string());
    }
    let all = enrolled(layout)?;
    if let Some(prev) = all.iter().find(|p| p.host == e.host) {
        return Err(format!(
            "host {} is already enrolled, as {} (enrolled_ns {}, by {}). Re-keying a host is a human's \
             decision with the ledger in front of them; nothing was changed",
            hex(&e.host),
            crate::shown(&prev.label),
            prev.enrolled_ns,
            crate::shown(&prev.actor)
        ));
    }
    if let Some(k) = e.link {
        if let Some(prev) = all.iter().find(|p| p.link == Some(k)) {
            return Err(format!(
                "link key {} is already enrolled for host {} ({}); one agent key is one host",
                hex(&k),
                hex(&prev.host),
                crate::shown(&prev.label)
            ));
        }
    }
    if let Some(prev) = all.iter().find(|p| p.label == e.label) {
        return Err(format!("the label {} is already host {}", crate::shown(&e.label), hex(&prev.host)));
    }
    let dir = layout.enroll();
    let final_path = dir.join(hex(&e.host));
    let tmp = dir.join(format!("{}.tmp", hex(&e.host)));
    let _ = fs::remove_file(&tmp);
    let mut o = fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        o.mode(0o600);
    }
    let mut f = o.open(&tmp).map_err(|err| format!("cannot create {}: {err}", tmp.display()))?;
    f.write_all(e.encode().as_bytes())
        .and_then(|()| f.sync_all())
        .map_err(|err| format!("cannot write {}: {err}", tmp.display()))?;
    ledger.append(&e.to_json())?;
    fs::rename(&tmp, &final_path).map_err(|err| format!("cannot put the enrollment in place: {err}"))?;

    crate::share_finished(&final_path);
    if let Ok(d) = fs::File::open(&dir) {
        let _ = d.sync_all();
    }
    Ok(())
}
