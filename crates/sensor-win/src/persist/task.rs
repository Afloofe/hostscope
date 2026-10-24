pub fn decode_task(bytes: &[u8]) -> String {
    if bytes.first() == Some(&0xFF) && bytes.get(1) == Some(&0xFE) {
        let (pairs, _odd) = bytes.get(2..).unwrap_or_default().as_chunks::<2>();
        let units: Vec<u16> = pairs.iter().copied().map(u16::from_le_bytes).collect();
        return String::from_utf16_lossy(&units);
    }
    String::from_utf8_lossy(bytes).into_owned()
}

pub fn task_commands(xml: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = xml;
    while let Some(i) = rest.find("<Command>") {
        let after = rest.get(i + "<Command>".len()..).unwrap_or_default();
        let Some(end) = after.find("</Command>") else { break };
        let cmd = unescape(after.get(..end).unwrap_or_default().trim());
        let tail = after.get(end..).unwrap_or_default();

        let next = tail.find("<Command>").unwrap_or(tail.len());
        let window = tail.get(..next).unwrap_or_default();
        let args = window
            .find("<Arguments>")
            .and_then(|a| {
                let from = window.get(a + "<Arguments>".len()..)?;
                let to = from.find("</Arguments>")?;
                Some(unescape(from.get(..to)?.trim()))
            })
            .unwrap_or_default();

        out.push(if args.is_empty() { cmd } else { format!("{cmd} {args}") });
        rest = tail;
    }
    out
}

pub(super) fn unescape(s: &str) -> String {
    s.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")

        .replace("&amp;", "&")
}
