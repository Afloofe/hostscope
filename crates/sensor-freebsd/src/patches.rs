pub const MAX_CONFIG_BYTES: u64 = 16 * 1024 * 1024;

pub const MAX_DEPTH: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Record {

    pub descr: String,

    pub uniqid: String,

    pub patch: Vec<u8>,

    pub pathstrip: usize,

    pub basedir: String,

    pub autoapply: bool,
}

pub fn records_from_config(xml: &str) -> Result<Vec<Record>, String> {
    let mut out = Vec::new();
    let mut stack: Vec<String> = Vec::new();
    let mut cur: Option<Vec<(String, String)>> = None;
    let mut text = String::new();
    let b = xml.as_bytes();
    let mut i = 0usize;
    let rest = |i: usize| xml.get(i..).unwrap_or_default();
    while i < b.len() {
        let r = rest(i);
        if let Some(t) = r.strip_prefix("<!--") {
            let end = t.find("-->").ok_or("an unclosed comment")?;
            i += 4 + end + 3;
        } else if let Some(t) = r.strip_prefix("<![CDATA[") {
            let end = t.find("]]>").ok_or("an unclosed CDATA section")?;
            text.push_str(t.get(..end).unwrap_or_default());
            i += 9 + end + 3;
        } else if r.starts_with("<!") {
            return Err("config.xml has a DOCTYPE or entity declaration; refused".into());
        } else if let Some(t) = r.strip_prefix("<?") {
            let end = t.find("?>").ok_or("an unclosed processing instruction")?;
            i += 2 + end + 2;
        } else if let Some(t) = r.strip_prefix("</") {
            let end = t.find('>').ok_or("an unclosed end tag")?;
            let name = t.get(..end).unwrap_or_default().trim();
            if stack.last().map(String::as_str) != Some(name) {
                return Err(format!("config.xml: </{name}> closes {:?}", stack.last()));
            }
            close(&stack, &mut cur, &mut text, &mut out)?;
            stack.pop();
            i += 2 + end + 1;
        } else if let Some(t) = r.strip_prefix('<') {
            let end = tag_end(t).ok_or("an unclosed start tag")?;
            let inner = t.get(..end).unwrap_or_default();
            let selfclose = inner.ends_with('/');
            let name: String = inner.trim_end_matches('/').split_whitespace().next().unwrap_or("").to_string();
            if name.is_empty() {
                return Err("config.xml: a tag with no name".into());
            }
            text.clear();
            stack.push(name);
            if stack.len() > MAX_DEPTH {
                return Err(format!("config.xml nests deeper than {MAX_DEPTH}"));
            }
            if in_item(&stack) && cur.is_none() && stack.len() == 4 {
                cur = Some(Vec::new());
            }
            if selfclose {
                close(&stack, &mut cur, &mut text, &mut out)?;
                stack.pop();
            }
            i += 1 + end + 1;
        } else {
            let end = r.find('<').unwrap_or(r.len());
            text.push_str(&decode_entities(r.get(..end).unwrap_or_default())?);
            i += end;
        }
    }
    if !stack.is_empty() {
        return Err(format!("config.xml ends inside <{}>", stack.join("><")));
    }
    Ok(out)
}

fn in_item(stack: &[String]) -> bool {
    matches!(stack, [_, a, b, c, ..] if a == "installedpackages" && b == "patches" && c == "item")
}

fn close(
    stack: &[String],
    cur: &mut Option<Vec<(String, String)>>,
    text: &mut String,
    out: &mut Vec<Record>,
) -> Result<(), String> {
    if !in_item(stack) {
        text.clear();
        return Ok(());
    }
    match stack.len() {
        5 => {
            if let (Some(fields), Some(name)) = (cur.as_mut(), stack.last()) {
                fields.push((name.clone(), std::mem::take(text)));
            }
        }
        4 => {
            if let Some(fields) = cur.take() {
                out.push(record(&fields)?);
            }
        }
        _ => {}
    }
    text.clear();
    Ok(())
}

fn record(fields: &[(String, String)]) -> Result<Record, String> {
    let get = |k: &str| fields.iter().find(|(n, _)| n == k).map(|(_, v)| v.trim().to_string());
    let patch = match get("patch") {
        Some(b64) => base64_decode(&b64).ok_or("a patch record's patch is not base64")?,
        None => Vec::new(),
    };
    let pathstrip = match get("pathstrip") {
        Some(s) if !s.is_empty() => s.parse().map_err(|_| format!("pathstrip `{s}`"))?,
        _ => 1,
    };
    Ok(Record {
        descr: get("descr").unwrap_or_default(),
        uniqid: get("uniqid").unwrap_or_default(),
        patch,
        pathstrip,
        basedir: get("basedir").filter(|s| !s.is_empty()).unwrap_or_else(|| "/".into()),
        autoapply: get("autoapply").is_some_and(|v| !v.is_empty()),
    })
}

fn tag_end(t: &str) -> Option<usize> {
    let mut quote = None;
    for (i, c) in t.char_indices() {
        match (quote, c) {
            (None, '"' | '\'') => quote = Some(c),
            (Some(q), c) if c == q => quote = None,
            (None, '>') => return Some(i),
            _ => {}
        }
    }
    None
}

fn decode_entities(s: &str) -> Result<String, String> {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(at) = rest.find('&') {
        out.push_str(rest.get(..at).unwrap_or_default());
        let tail = rest.get(at + 1..).unwrap_or_default();
        let end = tail.find(';').ok_or("an unterminated entity")?;
        let name = tail.get(..end).unwrap_or_default();
        let c = match name {
            "lt" => '<',
            "gt" => '>',
            "amp" => '&',
            "quot" => '"',
            "apos" => '\'',
            n if n.starts_with("#x") => n
                .get(2..)
                .and_then(|h| u32::from_str_radix(h, 16).ok())
                .and_then(char::from_u32)
                .ok_or_else(|| format!("entity &{n};"))?,
            n if n.starts_with('#') => n
                .get(1..)
                .and_then(|d| d.parse().ok())
                .and_then(char::from_u32)
                .ok_or_else(|| format!("entity &{n};"))?,
            n => return Err(format!("config.xml uses an entity it does not declare: &{n};")),
        };
        out.push(c);
        rest = tail.get(end + 1..).unwrap_or_default();
    }
    out.push_str(rest);
    Ok(out)
}

pub fn base64_decode(s: &str) -> Option<Vec<u8>> {
    let val = |c: u8| -> Option<u32> {
        Some(match c {
            b'A'..=b'Z' => u32::from(c - b'A'),
            b'a'..=b'z' => u32::from(c - b'a') + 26,
            b'0'..=b'9' => u32::from(c - b'0') + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        })
    };
    let clean: Vec<u8> = s.bytes().filter(|c| !c.is_ascii_whitespace()).collect();
    let body = clean.strip_suffix(b"==").or_else(|| clean.strip_suffix(b"=")).unwrap_or(&clean);
    if body.contains(&b'=') || clean.len() % 4 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(body.len() * 3 / 4);
    let (mut acc, mut bits) = (0u32, 0u32);
    for &c in body {
        acc = (acc << 6) | val(c)?;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((acc >> bits) & 0xff) as u8);
        }
    }
    Some(out)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilePatch {

    pub path: String,
    hunks: Vec<Hunk>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Hunk {

    new_start: usize,

    new: Vec<Vec<u8>>,

    old: Vec<Vec<u8>>,
}

pub fn parse_diff(diff: &[u8], pathstrip: usize, basedir: &str) -> Result<Vec<FilePatch>, String> {
    let lines: Vec<&[u8]> = diff.split_inclusive(|&c| c == b'\n').collect();
    let mut out: Vec<FilePatch> = Vec::new();
    let mut i = 0usize;
    while i < lines.len() {
        let l = lines.get(i).copied().unwrap_or_default();
        if l.starts_with(b"--- ") && lines.get(i + 1).is_some_and(|n| n.starts_with(b"+++ ")) {
            let new_name = lines.get(i + 1).copied().unwrap_or_default();
            let path = target_path(new_name, pathstrip, basedir)?;
            out.push(FilePatch { path, hunks: Vec::new() });
            i += 2;
            continue;
        }
        if l.starts_with(b"@@ ") {
            let fp = out.last_mut().ok_or("a hunk before any file header")?;
            let (old_len, new_start, new_len) = hunk_header(l)?;
            let mut h = Hunk { new_start, new: Vec::new(), old: Vec::new() };
            i += 1;
            while h.old.len() < old_len || h.new.len() < new_len {
                let Some(&body) = lines.get(i) else { return Err("a hunk ends early".into()) };
                let (tag, rest) = body.split_first().ok_or("an empty hunk line")?;
                match tag {
                    b' ' => {
                        h.old.push(rest.to_vec());
                        h.new.push(rest.to_vec());
                    }
                    b'-' => h.old.push(rest.to_vec()),
                    b'+' => h.new.push(rest.to_vec()),
                    b'\\' => strip_newline(&mut h, lines.get(i.wrapping_sub(1)).and_then(|p| p.first()).copied()),

                    b'\n' => {
                        h.old.push(b"\n".to_vec());
                        h.new.push(b"\n".to_vec());
                    }
                    _ => return Err(format!("a hunk line starts with {:?}", char::from(*tag))),
                }
                i += 1;
            }
            if h.old.len() != old_len || h.new.len() != new_len {
                return Err("a hunk's line counts do not match its header".into());
            }

            while let Some(&nl) = lines.get(i) {
                if !nl.starts_with(b"\\") {
                    break;
                }
                strip_newline(&mut h, lines.get(i.wrapping_sub(1)).and_then(|p| p.first()).copied());
                i += 1;
            }
            fp.hunks.push(h);
            continue;
        }
        i += 1;
    }
    if out.iter().any(|f| f.hunks.is_empty()) {
        return Err("a file header with no hunks".into());
    }
    Ok(out)
}

fn strip_newline(h: &mut Hunk, prev_tag: Option<u8>) {
    let sides: Vec<&mut Vec<Vec<u8>>> = match prev_tag {
        Some(b'+') => vec![&mut h.new],
        Some(b'-') => vec![&mut h.old],
        _ => vec![&mut h.new, &mut h.old],
    };
    for s in sides {
        if let Some(last) = s.last_mut() {
            if last.last() == Some(&b'\n') {
                last.pop();
            }
        }
    }
}

fn target_path(header: &[u8], pathstrip: usize, basedir: &str) -> Result<String, String> {
    let text = std::str::from_utf8(header).map_err(|_| "a file name that is not UTF-8")?;
    let name = text.trim_start_matches("+++ ").trim_end_matches(['\n', '\r']);
    let name = name.split('\t').next().unwrap_or(name);
    let parts: Vec<&str> = name.split('/').filter(|c| !c.is_empty()).collect();
    let kept = parts.get(pathstrip..).ok_or_else(|| format!("{name}: fewer components than pathstrip {pathstrip}"))?;
    if kept.is_empty() || kept.iter().any(|c| *c == "." || *c == "..") {
        return Err(format!("{name}: not a path a patch may name"));
    }
    let base = basedir.trim_end_matches('/');
    Ok(format!("{base}/{}", kept.join("/")))
}

fn hunk_header(l: &[u8]) -> Result<(usize, usize, usize), String> {
    let t = std::str::from_utf8(l).map_err(|_| "a hunk header that is not UTF-8")?;
    let inner = t.strip_prefix("@@ -").and_then(|s| s.split(" @@").next()).ok_or("a malformed hunk header")?;
    let (old, new) = inner.split_once(" +").ok_or("a malformed hunk header")?;
    let range = |r: &str| -> Result<(usize, usize), String> {
        let (s, n) = r.split_once(',').unwrap_or((r, "1"));
        Ok((s.parse().map_err(|_| "a hunk start")?, n.parse().map_err(|_| "a hunk length")?))
    };
    let (_, old_len) = range(old)?;
    let (new_start, new_len) = range(new)?;
    Ok((old_len, new_start, new_len))
}

pub fn reverse(content: &[u8], patches: &[&FilePatch]) -> Option<Vec<u8>> {
    let mut lines: Vec<Vec<u8>> = content.split_inclusive(|&c| c == b'\n').map(<[u8]>::to_vec).collect();
    for fp in patches.iter().rev() {

        for h in fp.hunks.iter().rev() {
            let start = if h.new.is_empty() { h.new_start } else { h.new_start.checked_sub(1)? };
            let end = start.checked_add(h.new.len())?;
            if lines.get(start..end)? != h.new.as_slice() {
                return None;
            }
            lines.splice(start..end, h.old.iter().cloned());
        }
    }
    Some(lines.concat())
}
