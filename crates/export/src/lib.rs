#![forbid(unsafe_code)]

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {

    Info,

    Note,

    Warn,

    Critical,
}

impl Severity {

    pub const fn token(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Note => "note",
            Severity::Warn => "warn",
            Severity::Critical => "critical",
        }
    }

    pub const fn stix_confidence(self) -> u8 {
        match self {
            Severity::Info => 10,
            Severity::Note => 30,
            Severity::Warn => 60,
            Severity::Critical => 85,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {

    pub severity: Severity,

    pub subject: String,

    pub locus: String,

    pub what: String,

    pub why: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Coverage {

    pub established: usize,

    pub total: usize,

    pub unreadable: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Export {

    pub host_id: String,

    pub engagement: String,

    pub when: String,

    pub agent_rev: String,

    pub findings: Vec<Finding>,

    pub coverage: Coverage,

    pub surface: String,
}

impl Export {

    pub fn is_complete(&self) -> bool {
        self.coverage.total > 0
            && self.coverage.established == self.coverage.total
            && self.coverage.unreadable.is_empty()
    }

    pub fn count_at_least(&self, s: Severity) -> usize {
        self.findings.iter().filter(|f| f.severity >= s).count()
    }
}

pub fn json_str(v: &str) -> String {
    let mut s = String::with_capacity(v.len() + 2);
    s.push('"');
    for c in v.chars() {
        match c {
            '"' => s.push_str("\\\""),
            '\\' => s.push_str("\\\\"),
            '\n' => s.push_str("\\n"),
            '\r' => s.push_str("\\r"),
            '\t' => s.push_str("\\t"),
            c if (c as u32) < 0x20 => s.push_str(&format!("\\u{:04x}", c as u32)),
            c => s.push(c),
        }
    }
    s.push('"');
    s
}

pub fn to_jsonl(e: &Export) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "{{\"record\":\"coverage\",\"host\":{},\"engagement\":{},\"when\":{},\"agent\":{},\
         \"surface\":{},\"established\":{},\"total\":{},\"unreadable\":{},\"complete\":{}}}\n",
        json_str(&e.host_id),
        json_str(&e.engagement),
        json_str(&e.when),
        json_str(&e.agent_rev),
        json_str(&e.surface),
        e.coverage.established,
        e.coverage.total,
        e.coverage.unreadable.len(),
        e.is_complete()
    ));
    for f in &e.findings {
        out.push_str(&format!(
            "{{\"record\":\"finding\",\"host\":{},\"severity\":\"{}\",\"subject\":{},\
             \"locus\":{},\"what\":{},\"why\":{}}}\n",
            json_str(&e.host_id),
            f.severity.token(),
            json_str(&f.subject),
            json_str(&f.locus),
            json_str(&f.what),
            json_str(&f.why)
        ));
    }
    out
}

pub fn to_stix(e: &Export) -> String {
    let when = json_str(&stix_time(&e.when));
    let identity = format!("identity--{}", uuid_from(&["identity", &e.host_id]));
    let mut objs: Vec<String> = Vec::new();

    let mut observables = std::collections::BTreeSet::new();

    objs.push(format!(
        "{{\"type\":\"identity\",\"spec_version\":\"2.1\",\"id\":\"{identity}\",\
         \"created\":{when},\"modified\":{when},\"name\":{},\"identity_class\":\"system\"}}",
        json_str(&e.host_id)
    ));

    for f in &e.findings {

        let id = uuid_from(&["observed-data", &e.host_id, &f.subject, &f.locus, &f.what]);
        let note_id = uuid_from(&["note", &e.host_id, &f.subject, &f.locus, &f.what]);

        let about = match split_path(&f.locus) {
            Some((dir, name)) => {
                let dir_id = format!("directory--{}", uuid_from(&["directory", dir]));
                let file_id = format!("file--{}", uuid_from(&["file", name, &dir_id]));
                if observables.insert(dir_id.clone()) {
                    objs.push(format!(
                        "{{\"type\":\"directory\",\"spec_version\":\"2.1\",\"id\":\"{dir_id}\",\
                         \"path\":{}}}",
                        json_str(dir)
                    ));
                }
                if observables.insert(file_id.clone()) {
                    objs.push(format!(
                        "{{\"type\":\"file\",\"spec_version\":\"2.1\",\"id\":\"{file_id}\",\
                         \"name\":{},\"parent_directory_ref\":\"{dir_id}\"}}",
                        json_str(name)
                    ));
                }
                objs.push(format!(
                    "{{\"type\":\"observed-data\",\"spec_version\":\"2.1\",\"id\":\"observed-data--{id}\",\
                     \"created\":{when},\"modified\":{when},\"first_observed\":{when},\
                     \"last_observed\":{when},\"number_observed\":1,\
                     \"created_by_ref\":\"{identity}\",\
                     \"object_refs\":[\"{file_id}\",\"{dir_id}\"],\"labels\":[\"{}\",{}]}}",
                    f.severity.token(),
                    json_str(&f.subject)
                ));
                format!("observed-data--{id}")
            }
            None => identity.clone(),
        };
        objs.push(format!(
            "{{\"type\":\"note\",\"spec_version\":\"2.1\",\"id\":\"note--{note_id}\",\
             \"created\":{when},\"modified\":{when},\"created_by_ref\":\"{identity}\",\
             \"abstract\":{},\"content\":{},\"confidence\":{},\"labels\":[\"{}\",{}],\
             \"object_refs\":[\"{about}\"]}}",
            json_str(&f.what),
            json_str(&format!(
                "{}\nat {}",
                if f.why.is_empty() { &f.what } else { &f.why },
                f.locus
            )),
            f.severity.stix_confidence(),
            f.severity.token(),
            json_str(&f.subject)
        ));
    }

    objs.push(format!(
        "{{\"type\":\"note\",\"spec_version\":\"2.1\",\"id\":\"note--{}\",\
         \"created\":{when},\"modified\":{when},\"created_by_ref\":\"{identity}\",\
         \"abstract\":\"coverage\",\"content\":{},\"object_refs\":[\"{identity}\"]}}",
        uuid_from(&["coverage", &e.host_id, &e.when]),
        json_str(&coverage_sentence(e)),
    ));

    format!(
        "{{\"type\":\"bundle\",\"id\":\"bundle--{}\",\"objects\":[{}]}}",
        uuid_from(&["bundle", &e.host_id, &e.when]),
        objs.join(",")
    )
}

fn split_path(locus: &str) -> Option<(&str, &str)> {
    let p = locus.trim_end_matches('/');
    if !p.starts_with('/') {
        return None;
    }
    let (dir, name) = p.rsplit_once('/')?;
    Some((if dir.is_empty() { "/" } else { dir }, name))
}

fn stix_time(when: &str) -> String {
    let Some(t) = when.strip_suffix('Z') else {
        return when.to_string();
    };
    let (secs, frac) = t.split_once('.').unwrap_or((t, ""));
    format!("{secs}.{frac:0<3}Z")
}

pub fn to_misp(e: &Export) -> String {
    let mut loci: Vec<(&str, Vec<String>)> = Vec::new();
    let mut at: std::collections::BTreeMap<&str, usize> = std::collections::BTreeMap::new();
    for f in e.findings.iter().filter(|f| f.severity > Severity::Info) {
        let mut line = format!("[{}] {} — {}", f.severity.token(), f.subject, f.what);
        if !f.why.is_empty() {
            line.push_str(&format!(" — {}", f.why));
        }
        let i = *at.entry(&f.locus).or_insert_with(|| {
            loci.push((&f.locus, Vec::new()));
            loci.len() - 1
        });
        if let Some((_, lines)) = loci.get_mut(i) {
            lines.push(line);
        }
    }

    let mut attrs: Vec<String> = Vec::new();
    for (locus, lines) in &loci {

        let (category, kind) = match split_path(locus) {
            Some(_) => ("Persistence mechanism", "filename"),
            None => ("Other", "text"),
        };
        attrs.push(format!(
            "{{\"category\":\"{category}\",\"type\":\"{kind}\",\"to_ids\":false,\
             \"value\":{},\"comment\":{}}}",
            json_str(locus),
            json_str(&lines.join("\n"))
        ));
    }
    attrs.push(format!(
        "{{\"category\":\"Other\",\"type\":\"comment\",\"to_ids\":false,\"value\":{},\
         \"comment\":\"sweep coverage\"}}",
        json_str(&coverage_sentence(e))
    ));

    format!(
        "{{\"Event\":{{\"info\":{},\"date\":{},\"threat_level_id\":\"{}\",\"analysis\":\"2\",\
         \"Attribute\":[{}]}}}}",
        json_str(&format!("HEMOSTAT sweep of {} ({})", e.host_id, e.engagement)),
        json_str(e.when.split('T').next().unwrap_or(&e.when)),
        misp_threat_level(e),
        attrs.join(",")
    )
}

fn misp_threat_level(e: &Export) -> u8 {
    if e.count_at_least(Severity::Critical) > 0 {
        1
    } else if e.count_at_least(Severity::Warn) > 0 {
        2
    } else if e.is_complete() {
        3
    } else {
        4
    }
}

pub fn to_report(e: &Export) -> String {
    let mut out = String::new();
    out.push_str(&format!("HEMOSTAT — {}\n", e.host_id));
    out.push_str(&format!("engagement {}   swept {}   agent {}\n", e.engagement, e.when, e.agent_rev));
    out.push_str(&"=".repeat(72));
    out.push('\n');

    out.push_str(&format!("\n{}\n", coverage_sentence(e)));
    if !e.coverage.unreadable.is_empty() {
        out.push_str("\nCould NOT be read — these surfaces are unchecked, not clean:\n");
        for u in &e.coverage.unreadable {
            out.push_str(&format!("  - {u}\n"));
        }
    }

    for sev in [Severity::Critical, Severity::Warn, Severity::Note] {
        let group: Vec<&Finding> = e.findings.iter().filter(|f| f.severity == sev).collect();
        if group.is_empty() {
            continue;
        }
        out.push_str(&format!("\n{} ({})\n", sev.token().to_uppercase(), group.len()));
        out.push_str(&"-".repeat(72));
        out.push('\n');
        for f in group {
            out.push_str(&format!("\n  {}\n", f.what));
            out.push_str(&format!("    at {}\n", f.locus));
            if !f.why.is_empty() {
                out.push_str(&format!("    {}\n", f.why));
            }
        }
    }

    if e.count_at_least(Severity::Note) == 0 {
        let surface = if e.surface.is_empty() { "this sweep" } else { &e.surface };
        out.push_str(&format!("\nNothing in {surface} matched a shape worth explaining.\n"));

        out.push_str(&format!(
            "That is a statement about {surface}, not about this host.\n"
        ));
        if !e.is_complete() {

            out.push_str("Nor is it a clean one — see the coverage above.\n");
        }
    }
    out
}

fn coverage_sentence(e: &Export) -> String {
    let surface = if e.surface.is_empty() { "this sweep" } else { &e.surface };
    let found = e.count_at_least(Severity::Note);
    let mut s = format!(
        "{surface}: {} of {} mechanism(s) established; {found} finding(s)",
        e.coverage.established, e.coverage.total,
    );
    let inventory = e.findings.len().saturating_sub(found);
    if inventory > 0 {
        s.push_str(&format!(" and {inventory} inventory row(s)"));
    }
    if !e.coverage.unreadable.is_empty() {
        s.push_str(&format!(
            "; {} surface(s) could not be read and are unchecked rather than clean",
            e.coverage.unreadable.len()
        ));
    }
    if !e.is_complete() {
        s.push_str(". This sweep is PARTIAL");
    }
    s
}

fn uuid_from(parts: &[&str]) -> String {
    let joined = parts.join("\u{1f}");
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in joined.bytes() {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }

    let mut g: u64 = 0x84222325_cbf29ce4;
    for b in joined.bytes().rev() {
        g ^= u64::from(b);
        g = g.wrapping_mul(0x0000_0100_0000_01b3);
    }
    let mut b = [0u8; 16];
    b[..8].copy_from_slice(&h.to_be_bytes());
    b[8..].copy_from_slice(&g.to_be_bytes());
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let hex: String = b.iter().map(|x| format!("{x:02x}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}
