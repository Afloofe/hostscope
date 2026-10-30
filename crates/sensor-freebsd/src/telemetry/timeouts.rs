use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Timeouts {

    pub values: BTreeMap<String, u64>,
}

const MAX_LINE: usize = 128;

const MAX_ENTRIES: usize = 64;

pub fn parse(text: &str) -> Result<Timeouts, String> {
    let mut t = Timeouts::default();
    for line in text.lines() {
        if line.trim().is_empty() {
            continue;
        }
        if line.len() > MAX_LINE || t.values.len() >= MAX_ENTRIES {
            return Err("pfctl -st printed more than its timeouts".into());
        }
        let w: Vec<&str> = line.split_whitespace().collect();
        let bad = || format!("pfctl -st: {line:?} is not a timeout line");
        let (name, value) = match w.as_slice() {
            [n, v] => (*n, v.strip_suffix('s').ok_or_else(bad)?),
            [n, v, "states"] => (*n, *v),
            _ => return Err(bad()),
        };
        if !name.bytes().all(|b| b.is_ascii_lowercase() || b == b'.' || b == b'_') {
            return Err(bad());
        }
        t.values.insert(name.to_string(), value.parse().map_err(|_| bad())?);
    }
    if !t.values.contains_key("tcp.established") {
        return Err("pfctl -st did not print tcp.established".into());
    }
    Ok(t)
}

impl Timeouts {

    fn key(proto: u8, stage: &str) -> Option<&'static str> {
        use super::filterlog::proto as p;
        let (a, b) = stage.split_once(':')?;
        match proto {
            p::TCP if a == "ESTABLISHED" && b == "ESTABLISHED" => Some("tcp.established"),
            p::UDP => match (a, b) {
                ("MULTIPLE", "MULTIPLE") => Some("udp.multiple"),
                ("SINGLE", _) | (_, "SINGLE") if a != "NO_TRAFFIC" && b != "NO_TRAFFIC" => Some("udp.single"),
                _ => Some("udp.first"),
            },
            _ => None,
        }
    }

    fn scale(&self, n: u64) -> (u64, u64) {
        let start = self.values.get("adaptive.start").copied().unwrap_or(0);
        let end = self.values.get("adaptive.end").copied().unwrap_or(0);
        if start == 0 || end <= start || n <= start {
            return (1, 1);
        }
        (end.saturating_sub(n), end - start)
    }

    pub fn idle(&self, proto: u8, stage: &str, expires: Option<u64>, states: u64, own_timeouts: bool) -> Option<u64> {
        if own_timeouts {
            return None;
        }
        let base = *self.values.get(Self::key(proto, stage)?)?;
        let (num, den) = self.scale(states);
        let timeout = base.checked_mul(num)? / den.max(1);
        let left = expires?;

        if left > timeout.saturating_add(1) {
            return None;
        }
        Some(timeout.saturating_sub(left))
    }
}
