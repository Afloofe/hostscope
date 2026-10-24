use crate::LoadError;

pub const MAX_NESTING: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {

    Str(String),

    Null,

    Map(Vec<(String, Value)>),

    List(Vec<Value>),
}

impl Value {

    pub fn as_map(&self) -> Option<&Vec<(String, Value)>> {
        match self {
            Value::Map(m) => Some(m),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::Str(s) => Some(s),
            _ => None,
        }
    }

    pub fn scalar_text(&self) -> String {
        match self {
            Value::Str(s) => s.clone(),
            Value::Null => String::new(),
            Value::Map(_) => "<map>".into(),
            Value::List(_) => "<list>".into(),
        }
    }
}

pub trait MapGet {

    fn get(&self, key: &str) -> Option<&Value>;
}

impl MapGet for Vec<(String, Value)> {
    fn get(&self, key: &str) -> Option<&Value> {
        self.iter().find(|(k, _)| k == key).map(|(_, v)| v)
    }
}

struct Line {
    number: usize,
    indent: usize,
    text: String,
}

fn lines_of(src: &str) -> Result<Vec<Line>, LoadError> {
    let mut out = Vec::new();
    for (i, raw) in src.lines().enumerate() {
        let number = i + 1;
        if raw.contains('\t') && raw.trim_start().len() != raw.len() {
            return Err(LoadError::Yaml {
                problem: "a tab is used for indentation, which YAML forbids and whose effect on \
                          an indentation-sensitive parse depends on the tab width"
                    .into(),
                line: number,
            });
        }
        let no_comment = strip_comment(raw);
        let text = no_comment.trim_end();
        if text.trim().is_empty() || text.trim() == "---" {
            continue;
        }
        let indent = text.len() - text.trim_start().len();
        let body = text.trim_start().to_string();

        if let Some(what) = anchor_or_alias(&body) {
            return Err(LoadError::Yaml {
                problem: format!(
                    "{what} are not supported — a rule that reuses a selection through an alias \
                     means something specific, and ignoring it would produce a rule that is not \
                     the author's"
                ),
                line: number,
            });
        }
        if body.ends_with(": |") || body.ends_with(": >") || body == "|" || body == ">" {
            return Err(LoadError::Yaml {
                problem: "block scalars (`|`, `>`) are not supported".into(),
                line: number,
            });
        }
        out.push(Line { number, indent, text: body });
    }
    Ok(out)
}

fn anchor_or_alias(body: &str) -> Option<&'static str> {
    let sigil = |t: &str| {
        let t = t.trim();

        let declares_anchor = t.starts_with('&');
        let uses_alias = t.starts_with('*') && t.len() > 1;
        (declares_anchor || uses_alias).then_some("anchors and aliases")
    };
    if let Some(w) = sigil(body) {
        return Some(w);
    }
    if let Some(rest) = body.strip_prefix("- ") {
        if let Some(w) = sigil(rest) {
            return Some(w);
        }
    }

    if let Some(i) = unquoted_colon(body) {
        if let Some(w) = sigil(&body[i + 1..]) {
            return Some(w);
        }
    }
    None
}

fn strip_comment(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut quote: Option<char> = None;
    let mut prev_escape = false;
    for c in line.chars() {
        match quote {
            Some(q) => {
                out.push(c);
                if prev_escape {
                    prev_escape = false;
                } else if c == '\\' && q == '"' {
                    prev_escape = true;
                } else if c == q {
                    quote = None;
                }
            }
            None => {
                if c == '"' || c == '\'' {
                    quote = Some(c);
                    out.push(c);
                } else if c == '#' {

                    if out.is_empty() || out.ends_with(' ') {
                        break;
                    }
                    out.push(c);
                } else {
                    out.push(c);
                }
            }
        }
    }
    out
}

pub fn parse(src: &str) -> Result<Value, LoadError> {
    let lines = lines_of(src)?;
    if lines.is_empty() {
        return Err(LoadError::Yaml { problem: "the document is empty".into(), line: 1 });
    }
    let mut at = 0;
    let v = parse_block(&lines, &mut at, lines[0].indent, 0)?;
    if at != lines.len() {
        return Err(LoadError::Yaml {
            problem: format!("unexpected content: `{}`", lines[at].text),
            line: lines[at].number,
        });
    }
    Ok(v)
}

fn parse_block(
    lines: &[Line],
    at: &mut usize,
    indent: usize,
    depth: usize,
) -> Result<Value, LoadError> {
    if depth > MAX_NESTING {
        return Err(LoadError::Yaml {
            problem: format!("blocks are nested more than {MAX_NESTING} levels deep"),
            line: lines.get(*at).map_or(0, |l| l.number),
        });
    }
    if lines.get(*at).is_some_and(|l| l.text.starts_with("- ") || l.text == "-") {
        return parse_list(lines, at, indent, depth);
    }
    let mut map: Vec<(String, Value)> = Vec::new();
    while let Some(line) = lines.get(*at) {
        if line.indent < indent {
            break;
        }
        if line.indent > indent {
            return Err(LoadError::Yaml {
                problem: "this line is indented further than the block it is in".into(),
                line: line.number,
            });
        }
        if line.text.starts_with("- ") {
            break;
        }
        let (key, rest) = split_key(&line.text, line.number)?;
        let number = line.number;
        *at += 1;

        let value = if rest.is_empty() {

            match lines.get(*at) {
                Some(next) if next.indent > indent => {
                    parse_block(lines, at, next.indent, depth + 1)?
                }

                _ => Value::Null,
            }
        } else {
            scalar(&rest, number)?
        };
        map.push((key, value));
    }
    Ok(Value::Map(map))
}

fn parse_list(
    lines: &[Line],
    at: &mut usize,
    indent: usize,
    depth: usize,
) -> Result<Value, LoadError> {
    let mut items = Vec::new();
    while let Some(line) = lines.get(*at) {
        if line.indent != indent || !(line.text.starts_with("- ") || line.text == "-") {
            break;
        }
        let body = line.text.strip_prefix("- ").unwrap_or("").trim().to_string();
        let number = line.number;
        *at += 1;

        if body.is_empty() {

            match lines.get(*at) {
                Some(next) if next.indent > indent => {
                    items.push(parse_block(lines, at, next.indent, depth + 1)?);
                }
                _ => items.push(Value::Null),
            }
            continue;
        }

        if let Some(colon) = unquoted_colon(&body) {
            let key = body[..colon].trim().to_string();
            let rest = body[colon + 1..].trim().to_string();
            let mut entries = vec![(key, if rest.is_empty() { Value::Null } else { scalar(&rest, number)? })];
            let inner_indent = indent + 2;
            while let Some(next) = lines.get(*at) {
                if next.indent < inner_indent || next.text.starts_with("- ") {
                    break;
                }
                let (k, r) = split_key(&next.text, next.number)?;
                let n = next.number;
                *at += 1;
                let v = if r.is_empty() {
                    match lines.get(*at) {
                        Some(deeper) if deeper.indent > next.indent => {
                            parse_block(lines, at, deeper.indent, depth + 1)?
                        }
                        _ => Value::Null,
                    }
                } else {
                    scalar(&r, n)?
                };
                entries.push((k, v));
            }
            items.push(Value::Map(entries));
            continue;
        }

        items.push(scalar(&body, number)?);
    }
    Ok(Value::List(items))
}

fn split_key(text: &str, line: usize) -> Result<(String, String), LoadError> {
    let Some(colon) = unquoted_colon(text) else {
        return Err(LoadError::Yaml {
            problem: format!("expected `key: value`, found `{text}`"),
            line,
        });
    };
    let key = unquote(text[..colon].trim());
    Ok((key, text[colon + 1..].trim().to_string()))
}

fn unquoted_colon(text: &str) -> Option<usize> {
    let bytes: Vec<char> = text.chars().collect();
    let mut quote: Option<char> = None;
    for (i, c) in bytes.iter().enumerate() {
        match quote {
            Some(q) => {
                if *c == q {
                    quote = None;
                }
            }
            None => {
                if *c == '"' || *c == '\'' {
                    quote = Some(*c);
                } else if *c == ':' {
                    let next = bytes.get(i + 1);
                    if next.is_none() || next.is_some_and(|n| n.is_whitespace()) {

                        return Some(text.char_indices().nth(i).map_or(i, |(b, _)| b));
                    }
                }
            }
        }
    }
    None
}

fn scalar(text: &str, line: usize) -> Result<Value, LoadError> {
    let t = text.trim();
    if t.is_empty() || t == "~" || t.eq_ignore_ascii_case("null") {
        return Ok(Value::Null);
    }
    if let Some(inner) = t.strip_prefix('[').and_then(|x| x.strip_suffix(']')) {
        let mut items = Vec::new();
        for part in split_flow(inner) {
            let p = part.trim();
            if p.is_empty() {
                continue;
            }

            if p.starts_with('[') {
                return Err(LoadError::Yaml {
                    problem: "nested flow sequences (`[[a]]`) are not supported — a Sigma value \
                              is a scalar or a list of them"
                        .into(),
                    line,
                });
            }
            items.push(scalar(p, line)?);
        }
        return Ok(Value::List(items));
    }
    if t.starts_with('{') {
        return Err(LoadError::Yaml {
            problem: "inline flow mappings (`{a: b}`) are not supported".into(),
            line,
        });
    }
    Ok(Value::Str(unquote(t)))
}

fn split_flow(inner: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quote: Option<char> = None;
    for c in inner.chars() {
        match quote {
            Some(q) => {
                cur.push(c);
                if c == q {
                    quote = None;
                }
            }
            None => {
                if c == '"' || c == '\'' {
                    quote = Some(c);
                    cur.push(c);
                } else if c == ',' {
                    out.push(std::mem::take(&mut cur));
                } else {
                    cur.push(c);
                }
            }
        }
    }
    if !cur.trim().is_empty() {
        out.push(cur);
    }
    out
}

fn unquote(t: &str) -> String {
    if t.len() >= 2 && t.starts_with('\'') && t.ends_with('\'') {
        return t[1..t.len() - 1].replace("''", "'");
    }
    if t.len() >= 2 && t.starts_with('"') && t.ends_with('"') {
        let inner = &t[1..t.len() - 1];
        let mut out = String::with_capacity(inner.len());
        let mut chars = inner.chars().peekable();
        while let Some(c) = chars.next() {
            if c == '\\' {
                match chars.peek() {
                    Some('\\') => {
                        out.push('\\');
                        chars.next();
                    }
                    Some('"') => {
                        out.push('"');
                        chars.next();
                    }

                    _ => out.push('\\'),
                }
            } else {
                out.push(c);
            }
        }
        return out;
    }
    t.to_string()
}

pub fn documents(src: &str) -> Vec<String> {
    let mut docs = Vec::new();
    let mut cur = String::new();
    for line in src.lines() {
        if line.trim() == "---" {
            if !cur.trim().is_empty() {
                docs.push(std::mem::take(&mut cur));
            }
            continue;
        }
        cur.push_str(line);
        cur.push('\n');
    }
    if !cur.trim().is_empty() {
        docs.push(cur);
    }
    docs
}
