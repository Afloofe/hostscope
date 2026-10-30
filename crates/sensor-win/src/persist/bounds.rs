#![cfg_attr(not(target_os = "windows"), allow(dead_code))]

use std::io::Read;

pub(super) const MAX_TASK_BYTES: u64 = 1024 * 1024;

pub(super) fn read_task(r: impl Read, len: u64) -> Result<Vec<u8>, String> {
    let over = |n: u64| format!("{n} bytes, more than the {MAX_TASK_BYTES} a task definition is read to; not read");
    if len > MAX_TASK_BYTES {
        return Err(over(len));
    }
    let mut buf = Vec::new();
    r.take(MAX_TASK_BYTES.saturating_add(1)).read_to_end(&mut buf).map_err(|e| e.to_string())?;
    if buf.len() as u64 > MAX_TASK_BYTES {
        return Err(over(buf.len() as u64));
    }
    Ok(buf)
}

pub(super) fn past_cap(what: &str, cap: u32) -> String {
    format!("more than {cap} {what}; the rest were not read")
}
