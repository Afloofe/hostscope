use std::collections::BTreeMap;

pub const MAX_DEPTH: usize = 32;

pub const MAX_INPUT: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq)]
pub enum Value {

    Null,

    Bool(bool),

    Number(String),

    Str(String),

    Array(Vec<Value>),

    Object(BTreeMap<String, Value>),
}

impl Value {

    pub fn get(&self, key: &str) -> Option<&Value> {
        match self {
            Value::Object(m) => m.get(key),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::Str(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Value::Number(n) => n.parse().ok(),
            _ => None,
        }
    }

    pub fn as_object(&self) -> Option<&BTreeMap<String, Value>> {
        match self {
            Value::Object(m) => Some(m),
            _ => None,
        }
    }
}

pub fn parse(text: &str) -> Result<Value, String> {
    if text.len() > MAX_INPUT {
        return Err(format!("{} bytes of JSON, over the {MAX_INPUT}-byte cap", text.len()));
    }
    let mut p = Parser { b: text.as_bytes(), at: 0 };
    let v = p.value(0)?;
    p.ws();
    if p.at != p.b.len() {
        return Err(format!("trailing bytes after the document at offset {}", p.at));
    }
    Ok(v)
}

struct Parser<'a> {
    b: &'a [u8],
    at: usize,
}

impl Parser<'_> {
    fn peek(&self) -> Option<u8> {
        self.b.get(self.at).copied()
    }

    fn ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.at += 1;
        }
    }

    fn err<T>(&self, what: &str) -> Result<T, String> {
        Err(format!("{what} at offset {}", self.at))
    }

    fn lit(&mut self, word: &str, v: Value) -> Result<Value, String> {
        if self.b.get(self.at..self.at + word.len()) == Some(word.as_bytes()) {
            self.at += word.len();
            Ok(v)
        } else {
            self.err("an unknown literal")
        }
    }

    fn value(&mut self, depth: usize) -> Result<Value, String> {
        if depth > MAX_DEPTH {
            return self.err("nesting deeper than is read");
        }
        self.ws();
        match self.peek() {
            Some(b'{') => self.object(depth),
            Some(b'[') => self.array(depth),
            Some(b'"') => self.string().map(Value::Str),
            Some(b't') => self.lit("true", Value::Bool(true)),
            Some(b'f') => self.lit("false", Value::Bool(false)),
            Some(b'n') => self.lit("null", Value::Null),
            Some(b'-' | b'0'..=b'9') => self.number(),
            Some(_) => self.err("an unexpected byte"),
            None => self.err("the end of the input"),
        }
    }

    fn object(&mut self, depth: usize) -> Result<Value, String> {
        self.at += 1;
        let mut m = BTreeMap::new();
        self.ws();
        if self.peek() == Some(b'}') {
            self.at += 1;
            return Ok(Value::Object(m));
        }
        loop {
            self.ws();
            if self.peek() != Some(b'"') {
                return self.err("an object key that is not a string");
            }
            let k = self.string()?;
            self.ws();
            if self.peek() != Some(b':') {
                return self.err("a missing ':'");
            }
            self.at += 1;
            let v = self.value(depth + 1)?;
            m.insert(k, v);
            self.ws();
            match self.peek() {
                Some(b',') => self.at += 1,
                Some(b'}') => {
                    self.at += 1;
                    return Ok(Value::Object(m));
                }
                _ => return self.err("an object not closed"),
            }
        }
    }

    fn array(&mut self, depth: usize) -> Result<Value, String> {
        self.at += 1;
        let mut v = Vec::new();
        self.ws();
        if self.peek() == Some(b']') {
            self.at += 1;
            return Ok(Value::Array(v));
        }
        loop {
            v.push(self.value(depth + 1)?);
            self.ws();
            match self.peek() {
                Some(b',') => self.at += 1,
                Some(b']') => {
                    self.at += 1;
                    return Ok(Value::Array(v));
                }
                _ => return self.err("an array not closed"),
            }
        }
    }

    fn number(&mut self) -> Result<Value, String> {
        let start = self.at;
        while matches!(self.peek(), Some(b'-' | b'+' | b'.' | b'e' | b'E' | b'0'..=b'9')) {
            self.at += 1;
        }
        let text = std::str::from_utf8(self.b.get(start..self.at).unwrap_or_default()).unwrap_or("");
        if text.is_empty() || text == "-" {
            return self.err("a malformed number");
        }
        Ok(Value::Number(text.to_string()))
    }

    fn hex4(&mut self) -> Result<u32, String> {
        let s = self.b.get(self.at..self.at + 4).and_then(|s| std::str::from_utf8(s).ok());
        let Some(n) = s.and_then(|s| u32::from_str_radix(s, 16).ok()) else {
            return self.err("a malformed \\u escape");
        };
        self.at += 4;
        Ok(n)
    }

    fn string(&mut self) -> Result<String, String> {
        self.at += 1;
        let mut out: Vec<u8> = Vec::new();
        loop {
            match self.peek() {
                None => return self.err("a string not closed"),
                Some(b'"') => {
                    self.at += 1;

                    return Ok(String::from_utf8_lossy(&out).into_owned());
                }
                Some(b'\\') => {
                    self.at += 1;
                    let Some(e) = self.peek() else { return self.err("a string not closed") };
                    self.at += 1;
                    match e {
                        b'"' => out.push(b'"'),
                        b'\\' => out.push(b'\\'),
                        b'/' => out.push(b'/'),
                        b'b' => out.push(8),
                        b'f' => out.push(12),
                        b'n' => out.push(b'\n'),
                        b'r' => out.push(b'\r'),
                        b't' => out.push(b'\t'),
                        b'u' => {
                            let mut c = self.hex4()?;
                            if (0xD800..0xDC00).contains(&c) && self.b.get(self.at..self.at + 2) == Some(b"\\u") {
                                self.at += 2;
                                let lo = self.hex4()?;
                                if (0xDC00..0xE000).contains(&lo) {
                                    c = 0x10000 + ((c - 0xD800) << 10) + (lo - 0xDC00);
                                }
                            }
                            let ch = char::from_u32(c).unwrap_or('\u{FFFD}');
                            let mut buf = [0u8; 4];
                            out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
                        }
                        _ => return self.err("an unknown escape"),
                    }
                }
                Some(c) => {
                    out.push(c);
                    self.at += 1;
                }
            }
        }
    }
}
