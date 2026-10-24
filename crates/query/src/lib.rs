#![forbid(unsafe_code)]

pub mod tables;

use std::collections::BTreeMap;
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Cell {

    Text(String),

    Int(i64),

    Null,
}

impl fmt::Display for Cell {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Cell::Text(s) => f.write_str(s),
            Cell::Int(n) => write!(f, "{n}"),
            Cell::Null => f.write_str(""),
        }
    }
}

impl Cell {

    pub fn as_text(&self) -> String {
        self.to_string()
    }

    pub const fn as_int(&self) -> Option<i64> {
        match self {
            Cell::Int(n) => Some(*n),
            _ => None,
        }
    }
}

pub type Row = BTreeMap<String, Cell>;

pub trait Table {

    fn name(&self) -> &'static str;

    fn columns(&self) -> &'static [&'static str];

    fn describe(&self) -> &'static str;

    fn rows(&self) -> TableRows;
}

#[derive(Debug, Clone, Default)]
pub struct TableRows {

    pub rows: Vec<Row>,

    pub gaps: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QueryError {

    Unsupported {

        construct: String,

        because: String,
    },

    Syntax(String),

    NoTable {

        name: String,

        available: Vec<String>,
    },

    NoColumn {

        name: String,

        table: String,

        available: Vec<String>,
    },
}

impl QueryError {

    pub fn message(&self) -> String {
        match self {
            QueryError::Unsupported { construct, because } => format!(
                "`{construct}` is not implemented by this engine: {because}. Nothing was run — \
                 an engine that guessed at it would return rows you did not ask for, and you \
                 would have no way to notice"
            ),
            QueryError::Syntax(s) => format!("could not parse the query: {s}"),
            QueryError::NoTable { name, available } => format!(
                "there is no table called `{name}`. This build has: {}",
                available.join(", ")
            ),
            QueryError::NoColumn { name, table, available } => format!(
                "`{table}` has no column `{name}`. It has: {}",
                available.join(", ")
            ),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {

    Eq,

    Ne,

    Lt,

    Le,

    Gt,

    Ge,

    Like,

    NotLike,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Compare {

    pub column: String,

    pub op: Op,

    pub value: Cell,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Predicate {

    Cmp(Compare),

    And(Box<Predicate>, Box<Predicate>),

    Or(Box<Predicate>, Box<Predicate>),

    Not(Box<Predicate>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Query {

    pub columns: Vec<String>,

    pub table: String,

    pub filter: Option<Predicate>,

    pub order: Option<(String, bool)>,

    pub limit: Option<usize>,
}

const REFUSED: &[(&str, &str)] = &[
    ("join", "joining two tables, which needs a join planner and a second scan"),
    ("group", "grouping, which needs aggregation across rows"),
    ("having", "a post-aggregation filter, which needs aggregation first"),
    ("union", "combining two result sets"),
    ("insert", "this engine is read-only — it reads host state and never changes it"),
    ("update", "this engine is read-only — it reads host state and never changes it"),
    ("delete", "this engine is read-only — it reads host state and never changes it"),
    ("create", "this engine is read-only, and its tables are the host rather than storage"),
    ("drop", "this engine is read-only, and its tables are the host rather than storage"),
    ("with", "a common table expression, which needs a query planner"),
    ("distinct", "de-duplication across rows"),
];

pub fn parse(sql: &str) -> Result<Query, QueryError> {
    let trimmed = sql.trim().trim_end_matches(';').trim();
    if trimmed.is_empty() {
        return Err(QueryError::Syntax("the query is empty".into()));
    }
    let lower = trimmed.to_ascii_lowercase();

    let scanned = blank_string_literals(&lower);
    for (word, because) in REFUSED {

        if scanned.split(|c: char| !c.is_ascii_alphanumeric()).any(|w| w == *word) {
            return Err(QueryError::Unsupported {
                construct: (*word).to_ascii_uppercase(),
                because: (*because).to_string(),
            });
        }
    }
    if !lower.starts_with("select") {
        return Err(QueryError::Syntax(
            "a query starts with SELECT — this engine reads and does not write".into(),
        ));
    }

    let toks = tokenise(trimmed);

    for t in &toks {
        let q = t.chars().next().filter(|c| *c == '\'' || *c == '"');
        if let Some(q) = q {
            if t.chars().count() < 2 || !t.ends_with(q) {
                return Err(QueryError::Syntax(format!(
                    "a string literal is not closed: {t} — add the matching {q}"
                )));
            }
        }
    }
    let mut at = 1_usize;

    let mut columns = Vec::new();
    while at < toks.len() && !toks[at].eq_ignore_ascii_case("from") {
        let t = &toks[at];
        if t == "," {
            at += 1;
            continue;
        }
        if t == "*" {
            columns.clear();
            at += 1;
            continue;
        }
        if t == "(" || t == ")" {
            return Err(QueryError::Unsupported {
                construct: "a function call in the column list".into(),
                because: "expressions and functions need an evaluator this engine does not have"
                    .to_string(),
            });
        }
        columns.push(unquote(t));
        at += 1;
    }
    if at >= toks.len() {
        return Err(QueryError::Syntax("the query has no FROM clause".into()));
    }
    at += 1;
    let Some(table) = toks.get(at).map(|t| unquote(t)) else {
        return Err(QueryError::Syntax("FROM is not followed by a table name".into()));
    };
    at += 1;

    let mut filter = None;
    let mut order = None;
    let mut limit = None;

    while at < toks.len() {
        let kw = toks[at].to_ascii_lowercase();
        match kw.as_str() {
            "where" => {
                at += 1;
                filter = Some(parse_or(&toks, &mut at)?);
            }
            "order" => {
                at += 1;
                if !toks.get(at).is_some_and(|t| t.eq_ignore_ascii_case("by")) {
                    return Err(QueryError::Syntax("ORDER must be followed by BY".into()));
                }
                at += 1;
                let Some(col) = toks.get(at).map(|t| unquote(t)) else {
                    return Err(QueryError::Syntax("ORDER BY names no column".into()));
                };
                at += 1;
                let desc = toks.get(at).is_some_and(|t| t.eq_ignore_ascii_case("desc"));
                if desc || toks.get(at).is_some_and(|t| t.eq_ignore_ascii_case("asc")) {
                    at += 1;
                }
                order = Some((col, desc));
            }
            "limit" => {
                at += 1;
                let Some(n) = toks.get(at).and_then(|t| t.parse::<usize>().ok()) else {
                    return Err(QueryError::Syntax("LIMIT is not followed by a number".into()));
                };
                at += 1;
                limit = Some(n);
            }
            other => {
                return Err(QueryError::Syntax(format!("unexpected `{other}`")));
            }
        }
    }

    Ok(Query { columns, table, filter, order, limit })
}

fn blank_string_literals(sql: &str) -> String {
    let mut out = String::with_capacity(sql.len());
    let mut quote: Option<char> = None;
    for c in sql.chars() {
        match quote {
            None => {
                if c == '\'' || c == '"' {
                    quote = Some(c);
                }
                out.push(c);
            }
            Some(q) => {
                if c == q {
                    quote = None;
                    out.push(c);
                } else {

                    for _ in 0..c.len_utf8() {
                        out.push(' ');
                    }
                }
            }
        }
    }
    out
}

fn tokenise(sql: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut chars = sql.chars().peekable();
    let flush = |cur: &mut String, out: &mut Vec<String>| {
        if !cur.is_empty() {
            out.push(std::mem::take(cur));
        }
    };
    while let Some(c) = chars.next() {
        match c {
            '\'' | '"' => {
                flush(&mut cur, &mut out);
                let quote = c;
                let mut lit = String::new();
                lit.push(quote);
                for c2 in chars.by_ref() {
                    lit.push(c2);
                    if c2 == quote {
                        break;
                    }
                }
                out.push(lit);
            }
            c if c.is_whitespace() => flush(&mut cur, &mut out),
            ',' | '(' | ')' | '*' => {
                flush(&mut cur, &mut out);
                out.push(c.to_string());
            }
            '=' | '<' | '>' | '!' => {
                flush(&mut cur, &mut out);
                let mut op = c.to_string();
                if chars.peek() == Some(&'=') {
                    op.push('=');
                    chars.next();
                }
                out.push(op);
            }
            c => cur.push(c),
        }
    }
    flush(&mut cur, &mut out);
    out
}

fn parse_or(toks: &[String], at: &mut usize) -> Result<Predicate, QueryError> {
    let mut left = parse_and(toks, at)?;
    while toks.get(*at).is_some_and(|t| t.eq_ignore_ascii_case("or")) {
        *at += 1;
        let right = parse_and(toks, at)?;
        left = Predicate::Or(Box::new(left), Box::new(right));
    }
    Ok(left)
}

fn parse_and(toks: &[String], at: &mut usize) -> Result<Predicate, QueryError> {
    let mut left = parse_unary(toks, at)?;
    while toks.get(*at).is_some_and(|t| t.eq_ignore_ascii_case("and")) {
        *at += 1;
        let right = parse_unary(toks, at)?;
        left = Predicate::And(Box::new(left), Box::new(right));
    }
    Ok(left)
}

fn parse_unary(toks: &[String], at: &mut usize) -> Result<Predicate, QueryError> {
    if toks.get(*at).is_some_and(|t| t.eq_ignore_ascii_case("not")) {
        *at += 1;
        return Ok(Predicate::Not(Box::new(parse_unary(toks, at)?)));
    }
    if toks.get(*at).map(String::as_str) == Some("(") {
        *at += 1;
        let inner = parse_or(toks, at)?;
        if toks.get(*at).map(String::as_str) != Some(")") {
            return Err(QueryError::Syntax("a parenthesis is not closed".into()));
        }
        *at += 1;
        return Ok(inner);
    }
    let Some(column) = toks.get(*at).map(|t| unquote(t)) else {
        return Err(QueryError::Syntax("the WHERE clause ends where a column was expected".into()));
    };
    *at += 1;

    let Some(raw) = toks.get(*at) else {
        return Err(QueryError::Syntax(format!("`{column}` is not followed by an operator")));
    };
    let mut op = match raw.as_str() {
        "=" | "==" => Op::Eq,
        "!=" | "<>" => Op::Ne,
        "<" => Op::Lt,
        "<=" => Op::Le,
        ">" => Op::Gt,
        ">=" => Op::Ge,
        o if o.eq_ignore_ascii_case("like") => Op::Like,
        o if o.eq_ignore_ascii_case("not") => {

            if toks.get(*at + 1).is_some_and(|t| t.eq_ignore_ascii_case("like")) {
                *at += 1;
                Op::NotLike
            } else {
                return Err(QueryError::Syntax(format!("`{column} NOT ...` needs LIKE")));
            }
        }
        o if o.eq_ignore_ascii_case("in") => {
            return Err(QueryError::Unsupported {
                construct: "IN".into(),
                because: "a value list, which this engine does not evaluate — write it as a \
                          chain of ORs"
                    .to_string(),
            })
        }
        o if o.eq_ignore_ascii_case("is") => {
            return Err(QueryError::Unsupported {
                construct: "IS NULL".into(),
                because: "three-valued logic. An absent value compares equal to the empty \
                          string here, which is a different thing and is said rather than \
                          quietly assumed"
                    .to_string(),
            })
        }
        other => return Err(QueryError::Syntax(format!("`{other}` is not an operator"))),
    };
    *at += 1;

    let Some(lit) = toks.get(*at) else {
        return Err(QueryError::Syntax("the comparison has no value".into()));
    };
    *at += 1;
    let value = literal(lit);

    if matches!(op, Op::Like | Op::NotLike) && matches!(value, Cell::Int(_)) {
        op = if matches!(op, Op::Like) { Op::Eq } else { Op::Ne };
    }
    Ok(Predicate::Cmp(Compare { column, op, value }))
}

fn literal(tok: &str) -> Cell {
    let t = unquote(tok);
    if tok.starts_with('\'') || tok.starts_with('"') {
        return Cell::Text(t);
    }
    if t.eq_ignore_ascii_case("null") {
        return Cell::Null;
    }
    t.parse::<i64>().map_or(Cell::Text(t), Cell::Int)
}

fn unquote(t: &str) -> String {
    if t.len() >= 2
        && ((t.starts_with('\'') && t.ends_with('\'')) || (t.starts_with('"') && t.ends_with('"')))
    {
        return t[1..t.len() - 1].to_string();
    }
    t.to_string()
}

pub fn like(pattern: &str, value: &str) -> bool {
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
        if p < pat.len() && (pat[p] == '_' || pat[p] == val[v]) {
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

fn holds(p: &Predicate, row: &Row) -> bool {
    match p {
        Predicate::And(a, b) => holds(a, row) && holds(b, row),
        Predicate::Or(a, b) => holds(a, row) || holds(b, row),
        Predicate::Not(a) => !holds(a, row),
        Predicate::Cmp(c) => {
            let Some(cell) = row.get(&c.column) else { return false };
            match c.op {
                Op::Like => like(&c.value.as_text(), &cell.as_text()),
                Op::NotLike => !like(&c.value.as_text(), &cell.as_text()),
                _ => {

                    let ord = match (cell.as_int(), c.value.as_int()) {
                        (Some(a), Some(b)) => a.cmp(&b),
                        _ => cell.as_text().to_lowercase().cmp(&c.value.as_text().to_lowercase()),
                    };
                    match c.op {
                        Op::Eq => ord.is_eq(),
                        Op::Ne => ord.is_ne(),
                        Op::Lt => ord.is_lt(),
                        Op::Le => ord.is_le(),
                        Op::Gt => ord.is_gt(),
                        Op::Ge => ord.is_ge(),
                        Op::Like | Op::NotLike => unreachable!("handled above"),
                    }
                }
            }
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct Answer {

    pub columns: Vec<String>,

    pub rows: Vec<Vec<Cell>>,

    pub gaps: Vec<String>,

    pub scanned: usize,
}

impl Answer {

    pub const fn complete(&self) -> bool {
        self.gaps.is_empty()
    }

    pub fn coverage(&self) -> String {
        let base = format!("{} row(s) from {} scanned", self.rows.len(), self.scanned);
        if self.gaps.is_empty() {
            return base;
        }
        format!(
            "{base} — the table was INCOMPLETE, so an empty or short result does not mean the \
             host has nothing matching: {}",
            self.gaps.join("; ")
        )
    }
}

pub fn run(q: &Query, tables: &[&dyn Table]) -> Result<Answer, QueryError> {
    let Some(table) = tables.iter().find(|t| t.name().eq_ignore_ascii_case(&q.table)) else {
        return Err(QueryError::NoTable {
            name: q.table.clone(),
            available: tables.iter().map(|t| t.name().to_string()).collect(),
        });
    };
    let available: Vec<String> = table.columns().iter().map(|c| (*c).to_string()).collect();

    let mut named: Vec<String> = q.columns.clone();
    if let Some(f) = &q.filter {
        collect_columns(f, &mut named);
    }
    if let Some((c, _)) = &q.order {
        named.push(c.clone());
    }
    for c in &named {
        if !available.iter().any(|a| a.eq_ignore_ascii_case(c)) {
            return Err(QueryError::NoColumn {
                name: c.clone(),
                table: table.name().to_string(),
                available,
            });
        }
    }

    let canonical = |c: &str| -> String {
        available
            .iter()
            .find(|a| a.eq_ignore_ascii_case(c))
            .map_or_else(|| c.to_string(), Clone::clone)
    };
    let mut q = q.clone();
    for c in &mut q.columns {
        *c = canonical(c);
    }
    if let Some(f) = &mut q.filter {
        canonicalise_columns(f, &canonical);
    }
    if let Some((c, _)) = &mut q.order {
        *c = canonical(c);
    }
    let q = &q;

    let produced = table.rows();
    let scanned = produced.rows.len();
    let mut kept: Vec<Row> = produced
        .rows
        .into_iter()
        .filter(|r| q.filter.as_ref().is_none_or(|f| holds(f, r)))
        .collect();

    if let Some((col, desc)) = &q.order {
        kept.sort_by(|a, b| {
            let (x, y) = (a.get(col), b.get(col));
            let ord = match (x.and_then(Cell::as_int), y.and_then(Cell::as_int)) {
                (Some(i), Some(j)) => i.cmp(&j),
                _ => x.map(Cell::as_text).cmp(&y.map(Cell::as_text)),
            };
            if *desc {
                ord.reverse()
            } else {
                ord
            }
        });
    }
    if let Some(n) = q.limit {
        kept.truncate(n);
    }

    let columns: Vec<String> =
        if q.columns.is_empty() { available.clone() } else { q.columns.clone() };
    let rows = kept
        .into_iter()
        .map(|r| {
            columns
                .iter()
                .map(|c| {
                    r.iter()
                        .find(|(k, _)| k.eq_ignore_ascii_case(c))
                        .map_or(Cell::Null, |(_, v)| v.clone())
                })
                .collect()
        })
        .collect();

    Ok(Answer { columns, rows, gaps: produced.gaps, scanned })
}

fn canonicalise_columns(p: &mut Predicate, f: &impl Fn(&str) -> String) {
    match p {
        Predicate::Cmp(c) => c.column = f(&c.column),
        Predicate::Not(a) => canonicalise_columns(a, f),
        Predicate::And(a, b) | Predicate::Or(a, b) => {
            canonicalise_columns(a, f);
            canonicalise_columns(b, f);
        }
    }
}

fn collect_columns(p: &Predicate, out: &mut Vec<String>) {
    match p {
        Predicate::Cmp(c) => out.push(c.column.clone()),
        Predicate::Not(a) => collect_columns(a, out),
        Predicate::And(a, b) | Predicate::Or(a, b) => {
            collect_columns(a, out);
            collect_columns(b, out);
        }
    }
}
