#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use hs_core::event::{Event, FieldValue};

use crate::yaml::MapGet as _;

pub mod correlate;
pub mod yaml;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoadError {

    Yaml {

        problem: String,

        line: usize,
    },

    Missing {

        key: &'static str,
    },

    Modifier {

        field: String,

        modifier: String,

        needs: &'static str,
    },

    Condition {

        expr: String,

        problem: String,
    },

    UnknownSelection {

        name: String,
    },
}

impl LoadError {

    pub fn message(&self) -> String {
        match self {
            LoadError::Yaml { problem, line } => {
                format!("could not be parsed (line {line}): {problem}")
            }
            LoadError::Missing { key } => format!("has no `{key}` block"),
            LoadError::Modifier { field, modifier, needs } => format!(
                "uses the `{modifier}` modifier on `{field}`, which this engine does not \
                 implement ({needs}). The rule was NOT evaluated"
            ),
            LoadError::Condition { expr, problem } => format!(
                "has a condition this engine does not implement: `{expr}` — {problem}. The rule \
                 was NOT evaluated"
            ),
            LoadError::UnknownSelection { name } => format!(
                "its condition names `{name}`, which is not defined in its detection block"
            ),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Match {

    Equals(String),

    Contains(String),

    StartsWith(String),

    EndsWith(String),

    Exists,

    Absent,

    Glob(String),
}

pub fn glob_matches(pattern: &str, value: &str) -> bool {
    let pat: Vec<char> = pattern.to_lowercase().chars().collect();
    let val: Vec<char> = value.to_lowercase().chars().collect();

    let (mut p, mut v) = (0_usize, 0_usize);

    let (mut star, mut resume) = (usize::MAX, 0_usize);

    while v < val.len() {

        let escaped = p + 1 < pat.len()
            && pat[p] == '\\'
            && matches!(pat[p + 1], '*' | '?' | '\\');
        let lit = if escaped { Some(pat[p + 1]) } else { None };

        if let Some(c) = lit {
            if c == val[v] {
                p += 2;
                v += 1;
                continue;
            }
        } else if p < pat.len() && pat[p] == '*' {
            star = p;
            p += 1;
            resume = v;
            continue;
        } else if p < pat.len() && (pat[p] == '?' || pat[p] == val[v]) {
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

    while p < pat.len() && pat[p] == '*' {
        p += 1;
    }
    p == pat.len()
}

pub fn has_wildcard(pattern: &str) -> bool {
    let chars: Vec<char> = pattern.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '\\' {
            i += 2;
            continue;
        }
        if chars[i] == '*' || chars[i] == '?' {
            return true;
        }
        i += 1;
    }
    false
}

pub fn has_escape(pattern: &str) -> bool {
    let chars: Vec<char> = pattern.chars().collect();
    let mut i = 0;
    while i + 1 < chars.len() {
        if chars[i] == '\\' && matches!(chars[i + 1], '*' | '?' | '\\') {
            return true;
        }
        i += 1;
    }
    false
}

impl Match {

    pub fn accepts(&self, value: &str) -> bool {
        let v = value.to_lowercase();
        match self {
            Match::Equals(want) => v == want.to_lowercase(),
            Match::Contains(want) => v.contains(&want.to_lowercase()),
            Match::StartsWith(want) => v.starts_with(&want.to_lowercase()),
            Match::EndsWith(want) => v.ends_with(&want.to_lowercase()),
            Match::Exists => true,
            Match::Absent => false,
            Match::Glob(p) => glob_matches(p, value),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldTest {

    pub field: String,

    pub any_of: Vec<Match>,
}

pub type Clause = Vec<FieldTest>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Selection {

    pub name: String,

    pub clauses: Vec<Clause>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Condition {

    Named(String),

    AllOf(String),

    AnyOf(String),

    Not(Box<Condition>),

    And(Box<Condition>, Box<Condition>),

    Or(Box<Condition>, Box<Condition>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub enum Level {

    Informational,

    Low,

    #[default]
    Medium,

    High,

    Critical,
}

impl Level {

    pub fn parse(s: &str) -> Level {
        match s.trim().to_ascii_lowercase().as_str() {
            "informational" => Level::Informational,
            "low" => Level::Low,
            "high" => Level::High,
            "critical" => Level::Critical,
            _ => Level::Medium,
        }
    }

    pub const fn token(self) -> &'static str {
        match self {
            Level::Informational => "informational",
            Level::Low => "low",
            Level::Medium => "medium",
            Level::High => "high",
            Level::Critical => "critical",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {

    pub title: String,

    pub id: Option<String>,

    pub level: Level,

    pub logsource: BTreeMap<String, String>,

    pub selections: Vec<Selection>,

    pub condition: Condition,
}

impl Rule {

    pub fn fields(&self) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for sel in &self.selections {
            for clause in &sel.clauses {
                for test in clause {
                    if !out.contains(&test.field) {
                        out.push(test.field.clone());
                    }
                }
            }
        }
        out.sort();
        out
    }

    pub fn could_match(&self, available: &[&str]) -> bool {
        self.satisfiable(&self.condition, available)
    }

    fn satisfiable(&self, c: &Condition, available: &[&str]) -> bool {
        let field_ok = |t: &FieldTest| {
            available.iter().any(|a| a.eq_ignore_ascii_case(&t.field))
                || t.any_of.iter().any(|m| matches!(m, Match::Absent))
        };
        let sel_ok = |s: &Selection| s.clauses.iter().any(|c| c.iter().all(field_ok));
        match c {
            Condition::Named(n) => self.selections.iter().find(|s| &s.name == n).is_some_and(sel_ok),

            Condition::AllOf(p) => {
                let named: Vec<&Selection> =
                    self.selections.iter().filter(|s| s.name.starts_with(p.as_str())).collect();
                !named.is_empty() && named.into_iter().all(sel_ok)
            }
            Condition::AnyOf(p) => {
                self.selections.iter().filter(|s| s.name.starts_with(p.as_str())).any(sel_ok)
            }
            Condition::Not(_) => true,
            Condition::And(a, b) => self.satisfiable(a, available) && self.satisfiable(b, available),
            Condition::Or(a, b) => self.satisfiable(a, available) || self.satisfiable(b, available),
        }
    }

    #[must_use]
    pub fn unavailable_fields(&self, available: &[&str]) -> Vec<String> {
        self.fields()
            .into_iter()
            .filter(|f| !available.iter().any(|a| a.eq_ignore_ascii_case(f)))
            .collect()
    }
}

const KNOWN_MODIFIERS: &[&str] = &["contains", "startswith", "endswith", "all"];

const REFUSED_MODIFIERS: &[(&str, &str)] = &[
    ("re", "a regular-expression engine, which is a dependency this build does not carry"),
    ("base64", "base64 decoding of the field before matching"),
    ("base64offset", "the three-offset base64 encoding Sigma uses for embedded strings"),
    ("utf16", "UTF-16 re-encoding of the pattern before matching"),
    ("utf16le", "UTF-16LE re-encoding of the pattern before matching"),
    ("utf16be", "UTF-16BE re-encoding of the pattern before matching"),
    ("wide", "UTF-16LE re-encoding of the pattern before matching"),
    ("cidr", "CIDR containment, which needs the field parsed as an address"),
    ("lt", "numeric comparison"),
    ("lte", "numeric comparison"),
    ("gt", "numeric comparison"),
    ("gte", "numeric comparison"),
    ("fieldref", "resolving the pattern as another field's value"),
    ("expand", "placeholder expansion from a configuration file"),
];

pub fn load(doc: &yaml::Value) -> Result<Rule, LoadError> {
    let map = doc.as_map().ok_or(LoadError::Missing { key: "detection" })?;

    let title = map
        .get("title")
        .and_then(yaml::Value::as_str)
        .unwrap_or("(untitled)")
        .to_string();
    let id = map.get("id").and_then(yaml::Value::as_str).map(str::to_string);
    let level = map.get("level").and_then(yaml::Value::as_str).map_or(Level::default(), Level::parse);

    let mut logsource = BTreeMap::new();
    if let Some(ls) = map.get("logsource").and_then(yaml::Value::as_map) {
        for (k, v) in ls {
            if let Some(s) = v.as_str() {
                logsource.insert(k.clone(), s.to_string());
            }
        }
    }

    let det = map
        .get("detection")
        .and_then(yaml::Value::as_map)
        .ok_or(LoadError::Missing { key: "detection" })?;

    let condition_text = det
        .get("condition")
        .and_then(yaml::Value::as_str)
        .ok_or(LoadError::Missing { key: "detection.condition" })?
        .to_string();

    let mut selections = Vec::new();
    for (name, value) in det {
        if name == "condition" || name == "timeframe" {
            continue;
        }
        selections.push(Selection { name: name.clone(), clauses: clauses_of(name, value)? });
    }

    let condition = parse_condition(&condition_text)?;
    check_names(&condition, &selections)?;

    Ok(Rule { title, id, level, logsource, selections, condition })
}

fn clauses_of(name: &str, value: &yaml::Value) -> Result<Vec<Clause>, LoadError> {
    match value {

        yaml::Value::Map(entries) => Ok(vec![clause_of(entries)?]),

        yaml::Value::List(items) => {
            let mut out = Vec::new();
            for item in items {
                match item {
                    yaml::Value::Map(entries) => out.push(clause_of(entries)?),
                    _ => {
                        return Err(LoadError::Condition {
                            expr: name.to_string(),
                            problem: "it is a keyword list, which searches every field of an \
                                      event. This engine matches named fields only"
                                .into(),
                        })
                    }
                }
            }
            Ok(out)
        }
        _ => Err(LoadError::Condition {
            expr: name.to_string(),
            problem: "a selection must be a map or a list of maps".into(),
        }),
    }
}

fn clause_of(entries: &[(String, yaml::Value)]) -> Result<Clause, LoadError> {
    let mut out = Vec::new();
    for (key, value) in entries {
        let mut parts = key.split('|');
        let field = parts.next().unwrap_or(key).to_string();
        let mods: Vec<&str> = parts.collect();

        let mut require_all = false;
        let mut compare: Option<&str> = None;
        for m in &mods {
            let lower = m.to_ascii_lowercase();
            if lower == "all" {
                require_all = true;
                continue;
            }
            if let Some((_, needs)) = REFUSED_MODIFIERS.iter().find(|(n, _)| *n == lower) {
                return Err(LoadError::Modifier {
                    field: key.clone(),
                    modifier: lower,
                    needs,
                });
            }
            if !KNOWN_MODIFIERS.contains(&lower.as_str()) {
                return Err(LoadError::Modifier {
                    field: key.clone(),
                    modifier: lower,
                    needs: "a modifier this engine has never seen — it may be newer than this \
                            build, and guessing at it would produce a match nobody can justify",
                });
            }
            compare = Some(match lower.as_str() {
                "contains" => "contains",
                "startswith" => "startswith",
                _ => "endswith",
            });
        }

        let values = match value {
            yaml::Value::List(items) => items.clone(),
            other => vec![other.clone()],
        };
        let mut any_of = Vec::new();
        for v in &values {
            any_of.push(match v {
                yaml::Value::Null => Match::Absent,
                other => {
                    let text = other.scalar_text();
                    match compare {
                        Some("contains") => Match::Contains(text),
                        Some("startswith") => Match::StartsWith(text),
                        Some("endswith") => Match::EndsWith(text),

                        _ if has_wildcard(&text) || has_escape(&text) => Match::Glob(text),
                        _ => Match::Equals(text),
                    }
                }
            });
        }

        if require_all {
            for m in any_of {
                out.push(FieldTest { field: field.clone(), any_of: vec![m] });
            }
        } else {
            out.push(FieldTest { field, any_of });
        }
    }
    Ok(out)
}

pub const MAX_CONDITION_TOKENS: usize = 512;

pub fn parse_condition(expr: &str) -> Result<Condition, LoadError> {
    let refuse = |problem: &str| LoadError::Condition {
        expr: expr.to_string(),
        problem: problem.to_string(),
    };
    if expr.contains('|') {
        return Err(refuse(
            "it contains an aggregation (`|`), which needs counting across events. This engine \
             evaluates one event at a time",
        ));
    }
    if expr.to_ascii_lowercase().contains(" near ") {
        return Err(refuse("`near` correlates events in time, which this engine does not do"));
    }

    let tokens = tokenise(expr);
    if tokens.len() > MAX_CONDITION_TOKENS {

        let head: String = expr.chars().take(60).collect();
        return Err(LoadError::Condition {
            expr: format!("{head}…"),
            problem: format!(
                "it is {} tokens long, over the {MAX_CONDITION_TOKENS} this engine evaluates — \
                 every level of nesting is a stack frame, and a stack overflow aborts the agent",
                tokens.len()
            ),
        });
    }
    let mut at = 0;
    let c = parse_or(&tokens, &mut at, expr)?;
    if at != tokens.len() {
        return Err(refuse(&format!("unexpected `{}` after the expression", tokens[at])));
    }
    Ok(c)
}

fn tokenise(expr: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    for ch in expr.chars() {
        match ch {
            '(' | ')' => {
                if !cur.trim().is_empty() {
                    out.push(cur.trim().to_string());
                }
                cur.clear();
                out.push(ch.to_string());
            }
            c if c.is_whitespace() => {
                if !cur.trim().is_empty() {
                    out.push(cur.trim().to_string());
                }
                cur.clear();
            }
            c => cur.push(c),
        }
    }
    if !cur.trim().is_empty() {
        out.push(cur.trim().to_string());
    }
    out
}

fn parse_or(t: &[String], at: &mut usize, expr: &str) -> Result<Condition, LoadError> {
    let mut left = parse_and(t, at, expr)?;
    while t.get(*at).is_some_and(|s| s.eq_ignore_ascii_case("or")) {
        *at += 1;
        let right = parse_and(t, at, expr)?;
        left = Condition::Or(Box::new(left), Box::new(right));
    }
    Ok(left)
}

fn parse_and(t: &[String], at: &mut usize, expr: &str) -> Result<Condition, LoadError> {
    let mut left = parse_unary(t, at, expr)?;
    while t.get(*at).is_some_and(|s| s.eq_ignore_ascii_case("and")) {
        *at += 1;
        let right = parse_unary(t, at, expr)?;
        left = Condition::And(Box::new(left), Box::new(right));
    }
    Ok(left)
}

fn parse_unary(t: &[String], at: &mut usize, expr: &str) -> Result<Condition, LoadError> {
    let refuse = |problem: String| LoadError::Condition { expr: expr.to_string(), problem };

    let Some(tok) = t.get(*at) else {
        return Err(refuse("the expression ends where a selection was expected".into()));
    };
    if tok.eq_ignore_ascii_case("not") {
        *at += 1;
        return Ok(Condition::Not(Box::new(parse_unary(t, at, expr)?)));
    }
    if tok == "(" {
        *at += 1;
        let inner = parse_or(t, at, expr)?;
        if t.get(*at).map(String::as_str) != Some(")") {
            return Err(refuse("a parenthesis is not closed".into()));
        }
        *at += 1;
        return Ok(inner);
    }

    if tok.eq_ignore_ascii_case("all") || tok == "1" || tok.eq_ignore_ascii_case("any") {
        let all = tok.eq_ignore_ascii_case("all");
        if t.get(*at + 1).is_some_and(|s| s.eq_ignore_ascii_case("of")) {
            let Some(pat) = t.get(*at + 2) else {
                return Err(refuse("`of` is not followed by a selection pattern".into()));
            };
            *at += 3;
            let prefix = pat.trim_end_matches('*').to_string();
            return Ok(if all { Condition::AllOf(prefix) } else { Condition::AnyOf(prefix) });
        }
    }

    if tok.chars().all(|c| c.is_ascii_digit()) {
        return Err(refuse(format!(
            "`{tok} of ...` needs a count of matching selections, which this engine does not \
             evaluate. Only `1 of` and `all of` are implemented"
        )));
    }
    *at += 1;
    Ok(Condition::Named(tok.clone()))
}

fn check_names(c: &Condition, sels: &[Selection]) -> Result<(), LoadError> {
    match c {
        Condition::Named(n) => {
            if sels.iter().any(|s| &s.name == n) {
                Ok(())
            } else {
                Err(LoadError::UnknownSelection { name: n.clone() })
            }
        }
        Condition::AllOf(p) | Condition::AnyOf(p) => {
            if sels.iter().any(|s| s.name.starts_with(p.as_str())) {
                Ok(())
            } else {
                Err(LoadError::UnknownSelection { name: format!("{p}*") })
            }
        }
        Condition::Not(inner) => check_names(inner, sels),
        Condition::And(a, b) | Condition::Or(a, b) => {
            check_names(a, sels)?;
            check_names(b, sels)
        }
    }
}

fn field_text(e: &Event, name: &str) -> Option<String> {
    e.fields.iter().find(|(n, _)| n.as_str().eq_ignore_ascii_case(name)).map(|(_, v)| match v {
        FieldValue::Str(s) => s.clone(),
        FieldValue::U64(n) => n.to_string(),
        FieldValue::I64(n) => n.to_string(),
        FieldValue::Bool(b) => b.to_string(),
    })
}

fn clause_matches(c: &Clause, e: &Event) -> bool {
    c.iter().all(|t| match field_text(e, &t.field) {
        Some(v) => t.any_of.iter().any(|m| m.accepts(&v)),

        None => t.any_of.iter().any(|m| matches!(m, Match::Absent)),
    })
}

fn selection_matches(s: &Selection, e: &Event) -> bool {
    s.clauses.iter().any(|c| clause_matches(c, e))
}

impl Rule {

    pub fn matches(&self, e: &Event) -> bool {
        self.eval(&self.condition, e)
    }

    fn eval(&self, c: &Condition, e: &Event) -> bool {
        match c {
            Condition::Named(n) => {
                self.selections.iter().find(|s| &s.name == n).is_some_and(|s| selection_matches(s, e))
            }
            Condition::AllOf(p) => {
                let mut any = false;
                for s in self.selections.iter().filter(|s| s.name.starts_with(p.as_str())) {
                    any = true;
                    if !selection_matches(s, e) {
                        return false;
                    }
                }
                any
            }
            Condition::AnyOf(p) => self
                .selections
                .iter()
                .filter(|s| s.name.starts_with(p.as_str()))
                .any(|s| selection_matches(s, e)),
            Condition::Not(inner) => !self.eval(inner, e),
            Condition::And(a, b) => self.eval(a, e) && self.eval(b, e),
            Condition::Or(a, b) => self.eval(a, e) || self.eval(b, e),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rejected {

    pub source: String,

    pub title: Option<String>,

    pub error: LoadError,
}

#[derive(Debug, Clone, Default)]
pub struct RuleSet {

    pub rules: Vec<Rule>,

    pub rejected: Vec<Rejected>,
}

impl Rule {

    #[must_use]
    pub fn unknown_fields(&self) -> Vec<String> {
        let mut out: Vec<String> = self
            .selections
            .iter()
            .flat_map(|s| s.clauses.iter())
            .flat_map(|c| c.iter())
            .filter(|t| !hs_core::event::fields::is_known(&t.field))
            .map(|t| t.field.clone())
            .collect();
        out.sort_unstable();
        out.dedup();
        out
    }
}

impl RuleSet {

    #[must_use]
    pub fn rules_naming_unknown_fields(&self) -> Vec<(String, Vec<String>)> {
        self.rules
            .iter()
            .filter_map(|r| {
                let unknown = r.unknown_fields();
                (!unknown.is_empty()).then(|| (r.title.clone(), unknown))
            })
            .collect()
    }

    pub fn coverage(&self) -> String {
        if self.rejected.is_empty() {
            return format!("{} rule(s) loaded, all of them evaluated", self.rules.len());
        }
        format!(
            "{} rule(s) evaluated, {} NOT evaluated — the second group did not run at all, so \
             nothing below says anything about what they would have found",
            self.rules.len(),
            self.rejected.len()
        )
    }

    pub fn inapplicable(&self, available: &[&str]) -> Vec<&Rule> {
        self.rules.iter().filter(|r| !r.could_match(available)).collect()
    }

    pub const fn complete(&self) -> bool {
        self.rejected.is_empty()
    }

    pub fn from_documents(docs: &[(String, String)]) -> RuleSet {
        let mut set = RuleSet::default();
        for (source, text) in docs {
            match yaml::parse(text) {
                Ok(v) => {
                    let title = v
                        .as_map()
                        .and_then(|m| m.get("title"))
                        .and_then(yaml::Value::as_str)
                        .map(str::to_string);
                    match load(&v) {
                        Ok(r) => set.rules.push(r),
                        Err(e) => set.rejected.push(Rejected {
                            source: source.clone(),
                            title,
                            error: e,
                        }),
                    }
                }
                Err(e) => set.rejected.push(Rejected {
                    source: source.clone(),
                    title: None,
                    error: e,
                }),
            }
        }
        set
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hit {

    pub title: String,

    pub id: Option<String>,

    pub level: Level,

    pub seq: u64,
}

pub fn run(set: &RuleSet, events: &[Event]) -> Vec<Hit> {
    let mut out = Vec::new();
    for e in events {
        for r in &set.rules {
            if r.matches(e) {
                out.push(Hit {
                    title: r.title.clone(),
                    id: r.id.clone(),
                    level: r.level,
                    seq: e.seq,
                });
            }
        }
    }

    out.sort_by(|a, b| b.level.cmp(&a.level).then(a.seq.cmp(&b.seq)));
    out
}
