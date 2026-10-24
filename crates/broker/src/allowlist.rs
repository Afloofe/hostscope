use std::fmt;

use hemostat_buildinfo::ActionClass;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {

    pub class: Option<ActionClass>,

    pub target: String,

    pub reason: String,

    pub who: String,

    pub until: i64,

    pub line: usize,
}

impl fmt::Display for Entry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "line {}: {} {} — {} (added by {}, until {})",
            self.line,
            self.class.map_or("*".to_string(), |c| c.name().to_string()),
            self.target,
            self.reason,
            self.who,
            date_of(self.until)
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Malformed {

    pub line: usize,

    pub text: String,

    pub problem: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Allowlist {

    pub entries: Vec<Entry>,

    pub malformed: Vec<Malformed>,
}

fn parse_until(s: &str) -> Option<i64> {
    let mut it = s.splitn(3, '-');
    let y: i64 = it.next()?.parse().ok()?;
    let m: i64 = it.next()?.parse().ok()?;
    let d: i64 = it.next()?.parse().ok()?;
    if !(1970..=9999).contains(&y) || !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return None;
    }
    let days = days_from_civil(y, m, d);

    if date_of((days + 1) * 86_400) != format!("{y:04}-{m:02}-{d:02}") {
        return None;
    }
    Some((days + 1) * 86_400)
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

fn date_of(until: i64) -> String {
    let z = until / 86_400 - 1 + 719_468;
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

pub const DEFAULT_PATH: &str = "/etc/hemostat/allow";

const MAX_ALLOWLIST_BYTES: u64 = 1024 * 1024;

impl Allowlist {

    pub fn parse(text: &str) -> Allowlist {
        let mut out = Allowlist::default();
        for (i, raw) in text.lines().enumerate() {
            let line = i + 1;
            let t = raw.trim();
            if t.is_empty() || t.starts_with('#') {
                continue;
            }
            let mut parts = t.split_whitespace();
            let (Some(class_tok), Some(target)) = (parts.next(), parts.next()) else {
                out.malformed.push(Malformed {
                    line,
                    text: raw.to_string(),
                    problem: "an entry is `<class|*> <target> until=YYYY-MM-DD <reason> | <who>`".into(),
                });
                continue;
            };
            let class = if class_tok == "*" {
                None
            } else {
                match ActionClass::ALL.iter().find(|c| c.name().eq_ignore_ascii_case(class_tok)) {
                    Some(c) => Some(*c),
                    None => {
                        out.malformed.push(Malformed {
                            line,
                            text: raw.to_string(),
                            problem: format!(
                                "`{class_tok}` is not an action class. Use `*` for every class, \
                                 or one of the names `build-info` prints"
                            ),
                        });
                        continue;
                    }
                }
            };
            let until = match parts.next().and_then(|t| t.strip_prefix("until=")).map(parse_until) {
                Some(Some(u)) => u,
                Some(None) => {
                    out.malformed.push(Malformed {
                        line,
                        text: raw.to_string(),
                        problem: "`until=` must be a date, YYYY-MM-DD".into(),
                    });
                    continue;
                }
                None => {
                    out.malformed.push(Malformed {
                        line,
                        text: raw.to_string(),
                        problem: "there is no `until=YYYY-MM-DD` after the target. Every \
                                  exemption ends; one that does not outlives its reason"
                            .into(),
                    });
                    continue;
                }
            };
            let rest: String = parts.collect::<Vec<_>>().join(" ");
            let Some((reason, who)) = rest.split_once('|') else {
                out.malformed.push(Malformed {
                    line,
                    text: raw.to_string(),
                    problem: "there is no `| who` at the end. An entry with no reason and no \
                              author is one nobody can review, and an allowlist nobody reviews \
                              is a place to hide"
                        .into(),
                });
                continue;
            };
            let (reason, who) = (reason.trim().to_string(), who.trim().to_string());
            if reason.is_empty() || who.is_empty() {
                out.malformed.push(Malformed {
                    line,
                    text: raw.to_string(),
                    problem: "both a reason and an author are required".into(),
                });
                continue;
            }
            out.entries.push(Entry { class, target: target.to_string(), reason, who, until, line });
        }
        out
    }

    pub fn expire(&mut self, now: i64) {
        let (live, lapsed): (Vec<Entry>, Vec<Entry>) =
            std::mem::take(&mut self.entries).into_iter().partition(|e| e.until > now);
        self.entries = live;
        for e in lapsed {
            self.malformed.push(Malformed {
                line: e.line,
                text: e.to_string(),
                problem: format!(
                    "expired on {} — it suppresses nothing now. Renew it deliberately with a new \
                     date, or remove it",
                    date_of(e.until)
                ),
            });
        }
    }

    #[cfg(unix)]
    fn read_config(path: &str) -> std::io::Result<String> {
        use std::os::unix::fs::OpenOptionsExt as _;
        let f = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(path)?;
        if !f.metadata()?.is_file() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "not a regular file — a named pipe or a device cannot be an allowlist, and \
                 opening one is how this load is made to wait forever",
            ));
        }
        let mut s = String::new();
        std::io::Read::read_to_string(
            &mut std::io::Read::take(&f, MAX_ALLOWLIST_BYTES),
            &mut s,
        )?;
        Ok(s)
    }

    #[cfg(not(unix))]
    fn read_config(path: &str) -> std::io::Result<String> {
        let f = std::fs::File::open(path)?;
        if !f.metadata()?.is_file() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "not a regular file — a pipe or a device cannot be an allowlist",
            ));
        }
        let mut s = String::new();
        std::io::Read::read_to_string(
            &mut std::io::Read::take(&f, MAX_ALLOWLIST_BYTES),
            &mut s,
        )?;
        Ok(s)
    }

    pub fn load() -> (Allowlist, Option<String>) {
        Self::load_from(std::env::var("HEMOSTAT_ALLOWLIST").ok().as_deref())
    }

    fn load_from(named: Option<&str>) -> (Allowlist, Option<String>) {
        let named = named.filter(|p| !p.trim().is_empty());
        let path = named.map_or_else(|| DEFAULT_PATH.to_string(), str::to_string);
        match Self::read_config(&path) {
            Ok(t) => {
                let mut a = Allowlist::parse(&t);
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(i64::MAX, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX));
                a.expire(now);
                (a, Some(path))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound && named.is_none() => {
                (Allowlist::default(), None)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (
                Allowlist {
                    entries: Vec::new(),
                    malformed: vec![Malformed {
                        line: 0,
                        text: path.clone(),
                        problem: "the allowlist $HEMOSTAT_ALLOWLIST names does not exist. \
                                  Nothing is suppressed, which is the safe direction, but it is \
                                  not the configured one"
                            .into(),
                    }],
                },
                Some(path),
            ),
            Err(e) => (
                Allowlist {
                    entries: Vec::new(),
                    malformed: vec![Malformed {
                        line: 0,
                        text: path.clone(),
                        problem: format!(
                            "the allowlist exists and could not be read ({e}). Nothing is \
                             suppressed, which is the safe direction, but it is not the \
                             configured one"
                        ),
                    }],
                },
                Some(path),
            ),
        }
    }

    pub fn judge(&self, class: ActionClass, target: &str, from_a_rule: bool) -> Option<&Entry> {

        if !from_a_rule {
            return None;
        }
        self.entries
            .iter()
            .find(|e| e.class.is_none_or(|c| c == class) && matches(&e.target, target))
    }

    pub fn coverage(&self, path: Option<&str>) -> String {
        let where_ = path.map_or_else(
            || "no allowlist file (none is not an error)".to_string(),
            |p| format!("{} entry(ies) from {p}", self.entries.len()),
        );
        if self.malformed.is_empty() {
            return where_;
        }
        format!(
            "{where_} — {} line(s) could NOT be read and suppress NOTHING, so anything they \
             were meant to cover will be acted on: {}",
            self.malformed.len(),
            self.malformed
                .iter()
                .map(|m| format!("line {} ({})", m.line, m.problem))
                .collect::<Vec<_>>()
                .join("; ")
        )
    }
}

pub fn matches(pattern: &str, value: &str) -> bool {
    let pat: Vec<char> = pattern.to_lowercase().chars().collect();
    let val: Vec<char> = value.to_lowercase().chars().collect();
    let (mut p, mut v) = (0_usize, 0_usize);
    let (mut star, mut resume) = (usize::MAX, 0_usize);
    while v < val.len() {
        if p < pat.len() && pat[p] == '%' {
            star = p;
            p += 1;
            resume = v;
            continue;
        }
        if p < pat.len() && pat[p] == val[v] {
            p += 1;
            v += 1;
            continue;
        }
        if star == usize::MAX {
            return false;
        }
        p = star + 1;
        resume += 1;
        v = resume;
    }
    while p < pat.len() && pat[p] == '%' {
        p += 1;
    }
    p == pat.len()
}
