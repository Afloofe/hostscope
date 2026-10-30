use super::{decode_task, task_commands, Entry, Mechanism, Probe};
use windows_sys::Win32::Foundation::{ERROR_MORE_DATA, ERROR_NO_MORE_ITEMS, ERROR_SUCCESS};
use windows_sys::Win32::System::Registry::{
    RegCloseKey, RegEnumKeyExW, RegEnumValueW, RegOpenKeyExW, HKEY, HKEY_LOCAL_MACHINE,
    HKEY_USERS, KEY_READ, REG_EXPAND_SZ, REG_MULTI_SZ, REG_SZ,
};

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(core::iter::once(0)).collect()
}

fn from_wide(buf: &[u16]) -> String {
    let end = buf.iter().position(|c| *c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(buf.get(..end).unwrap_or_default())
}

fn open(sub: &str) -> Result<HKEY, u32> {
    open_in(HKEY_LOCAL_MACHINE, sub)
}

fn open_in(root: HKEY, sub: &str) -> Result<HKEY, u32> {
    let sub = wide(sub);
    let mut h: HKEY = core::ptr::null_mut();

    let rc = unsafe { RegOpenKeyExW(root, sub.as_ptr(), 0, KEY_READ, core::ptr::addr_of_mut!(h)) };
    if rc == ERROR_SUCCESS {
        Ok(h)
    } else {
        Err(rc)
    }
}

fn unopened(locus: &str, rc: u32) -> (Vec<Entry>, Vec<String>, bool) {
    match super::key_refusal(locus, rc) {
        None => (Vec::new(), Vec::new(), false),
        Some(why) => (Vec::new(), vec![why], true),
    }
}

fn directory(dir: &str) -> Result<bool, String> {
    match std::fs::metadata(dir) {
        Ok(md) => Ok(md.is_dir()),
        Err(e) => super::dir_refusal(dir, &e).map_or(Ok(false), Err),
    }
}

const MAX_VALUES_PER_KEY: u32 = 4096;

const MAX_SUBKEYS_PER_KEY: u32 = 16_384;

const MAX_VALUE_BYTES: u32 = 16 * 1024 * 1024;

fn values(h: HKEY) -> (Vec<(String, String)>, Vec<String>) {
    let mut out = Vec::new();
    let mut unread = Vec::new();

    let mut name = vec![0u16; 16_384];
    let mut data = vec![0u16; 16_384];

    for i in 0..=MAX_VALUES_PER_KEY {
        let mut name_len = 0u32;
        let mut data_len = 0u32;
        let mut kind: u32 = 0;
        let mut rc = ERROR_MORE_DATA;

        for _ in 0..2 {
            name_len = name.len() as u32;
            data_len = (data.len() * 2) as u32;

            rc = unsafe {
                RegEnumValueW(
                    h,
                    i,
                    name.as_mut_ptr(),
                    core::ptr::addr_of_mut!(name_len),
                    core::ptr::null_mut(),
                    core::ptr::addr_of_mut!(kind),
                    data.as_mut_ptr().cast(),
                    core::ptr::addr_of_mut!(data_len),
                )
            };
            if rc != ERROR_MORE_DATA || data_len > MAX_VALUE_BYTES {
                break;
            }
            data.resize((data_len as usize).div_ceil(2), 0);
        }
        if rc == ERROR_NO_MORE_ITEMS {
            break;
        }
        if i == MAX_VALUES_PER_KEY {
            unread.push(super::bounds::past_cap("values", MAX_VALUES_PER_KEY));
            break;
        }
        if rc != ERROR_SUCCESS {

            unread.push(if rc == ERROR_MORE_DATA {
                format!("value #{i}: {data_len} bytes, more than this sweep reads")
            } else {
                format!("value #{i} (error {rc})")
            });
            continue;
        }
        if kind != REG_SZ && kind != REG_EXPAND_SZ && kind != REG_MULTI_SZ {
            continue;
        }
        let n = from_wide(name.get(..name_len as usize).unwrap_or_default());
        let chars = (data_len as usize) / 2;
        let raw = data.get(..chars).unwrap_or_default();
        if kind == REG_MULTI_SZ {

            for member in super::multi_strings(raw) {
                out.push((n.clone(), member));
            }
        } else {
            out.push((n, from_wide(raw)));
        }
    }
    (out, unread)
}

fn subkeys(h: HKEY) -> (Vec<String>, Vec<String>) {
    let mut out = Vec::new();
    let mut unread = Vec::new();

    let mut name = vec![0u16; 256];
    for i in 0..=MAX_SUBKEYS_PER_KEY {
        let mut len = name.len() as u32;

        let rc = unsafe {
            RegEnumKeyExW(
                h,
                i,
                name.as_mut_ptr(),
                core::ptr::addr_of_mut!(len),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
            )
        };
        if rc == ERROR_NO_MORE_ITEMS {
            break;
        }
        if i == MAX_SUBKEYS_PER_KEY {
            unread.push(super::bounds::past_cap("subkeys", MAX_SUBKEYS_PER_KEY));
            break;
        }
        if rc != ERROR_SUCCESS {

            unread.extend(super::key_refusal(&format!("subkey #{i}"), rc));
            continue;
        }
        out.push(from_wide(name.get(..len as usize).unwrap_or_default()));
    }
    (out, unread)
}

pub(super) fn mechanism(m: &Mechanism) -> (Vec<Entry>, Vec<String>, bool) {
    let mut entries = Vec::new();
    let mut refused = Vec::new();
    match m.probe {
        Probe::KeyValues(sub) => {
            let h = match open(sub) {
                Ok(h) => h,

                Err(rc) => return unopened(&format!(r"HKLM\{sub}"), rc),
            };
            let (found, unread) = values(h);
            for (name, command) in found {
                entries.push(Entry {
                    mechanism: m.id,
                    category: m.category,
                    locus: format!(r"HKLM\{sub}"),
                    name,
                    command,
                });
            }
            refused.extend(unread.into_iter().map(|v| format!(r"HKLM\{sub}: {v}")));

            unsafe { RegCloseKey(h) };
        }
        Probe::NamedValues(sub, wanted) => {
            let h = match open(sub) {
                Ok(h) => h,
                Err(rc) => return unopened(&format!(r"HKLM\{sub}"), rc),
            };
            let (found, unread) = values(h);
            for (name, command) in found {
                if wanted.iter().any(|w| w.eq_ignore_ascii_case(&name)) {
                    entries.push(Entry {
                        mechanism: m.id,
                        category: m.category,
                        locus: format!(r"HKLM\{sub}"),
                        name,
                        command,
                    });
                }
            }

            refused.extend(unread.into_iter().map(|v| format!(r"HKLM\{sub}: {v}")));

            unsafe { RegCloseKey(h) };
        }
        Probe::SubkeyValue(sub, want) => {
            let h = match open(sub) {
                Ok(h) => h,
                Err(rc) => return unopened(&format!(r"HKLM\{sub}"), rc),
            };
            let (names, unlisted) = subkeys(h);

            unsafe { RegCloseKey(h) };
            refused.extend(unlisted.into_iter().map(|v| format!(r"HKLM\{sub}: {v}")));
            for child in names {
                let path = format!(r"{sub}\{child}");
                let ch = match open(&path) {
                    Ok(ch) => ch,

                    Err(rc) => {
                        refused.extend(super::key_refusal(&format!(r"HKLM\{path}"), rc));
                        continue;
                    }
                };
                let (found, unread) = values(ch);
                for (name, command) in found {
                    if name.eq_ignore_ascii_case(want) && !command.trim().is_empty() {
                        entries.push(Entry {
                            mechanism: m.id,
                            category: m.category,
                            locus: format!(r"HKLM\{path}"),
                            name: child.clone(),
                            command,
                        });
                    }
                }

                refused.extend(unread.into_iter().map(|v| format!(r"HKLM\{path}: {v}")));

                unsafe { RegCloseKey(ch) };
            }
        }
        Probe::UserValues(sub, wanted) => {

            let (sids, unlisted) = subkeys(HKEY_USERS);
            refused.extend(unlisted.into_iter().map(|v| format!(r"HKU: {v}")));
            for sid in sids.into_iter().filter(|k| super::is_user_hive(k)) {
                let path = format!(r"{sid}\{sub}");
                let h = match open_in(HKEY_USERS, &path) {
                    Ok(h) => h,
                    Err(rc) => {
                        refused.extend(super::key_refusal(&format!(r"HKU\{path}"), rc));
                        continue;
                    }
                };
                let (found, unread) = values(h);
                for (name, command) in found {
                    if wanted.iter().any(|w| w.eq_ignore_ascii_case(&name)) {
                        entries.push(Entry {
                            mechanism: m.id,
                            category: m.category,
                            locus: format!(r"HKU\{path}"),
                            name: sid.clone(),
                            command,
                        });
                    }
                }
                refused.extend(unread.into_iter().map(|v| format!(r"HKU\{path}: {v}")));

                unsafe { RegCloseKey(h) };
            }
        }
        Probe::TaskFiles(dir) => {
            match directory(dir) {
                Ok(true) => {}
                Ok(false) => return (entries, Vec::new(), false),
                Err(why) => return (entries, vec![why], true),
            }
            walk_tasks(std::path::Path::new(dir), m, &mut entries, &mut refused, 0);
        }
        Probe::Directory(dir) => {
            match directory(dir) {
                Ok(true) => {}
                Ok(false) => return (entries, Vec::new(), false),
                Err(why) => return (entries, vec![why], true),
            }
            match std::fs::read_dir(dir) {
                Ok(rd) => {
                    for e in rd.flatten() {
                        let p = e.path();

                        if p.file_name().is_some_and(|n| n.eq_ignore_ascii_case("desktop.ini")) {
                            continue;
                        }
                        entries.push(Entry {
                            mechanism: m.id,
                            category: m.category,
                            locus: dir.to_string(),
                            name: p
                                .file_name()
                                .map(|n| n.to_string_lossy().into_owned())
                                .unwrap_or_default(),
                            command: p.display().to_string(),
                        });
                    }
                }
                Err(e) => refused.push(format!("{dir}: {e}")),
            }
        }
    }
    (entries, refused, true)
}

fn task_file(p: &std::path::Path) -> Result<Vec<u8>, String> {
    let f = std::fs::File::open(p).map_err(|e| e.to_string())?;
    let len = f.metadata().map_err(|e| e.to_string())?.len();
    super::bounds::read_task(f, len)
}

fn walk_tasks(
    dir: &std::path::Path,
    m: &Mechanism,
    entries: &mut Vec<Entry>,
    refused: &mut Vec<String>,
    depth: usize,
) {
    if depth > 8 {
        refused.push(format!("{}: deeper than this walk goes", dir.display()));
        return;
    }
    let rd = match std::fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(e) => {
            refused.push(format!("{}: {e}", dir.display()));
            return;
        }
    };
    for e in rd.flatten() {
        let p = e.path();
        match std::fs::symlink_metadata(&p) {
            Ok(md) if md.is_dir() => walk_tasks(&p, m, entries, refused, depth + 1),
            Ok(md) if md.is_file() => match task_file(&p) {
                Ok(bytes) => {
                    let text = decode_task(&bytes);
                    for command in task_commands(&text) {
                        entries.push(Entry {
                            mechanism: m.id,
                            category: m.category,
                            locus: p.display().to_string(),
                            name: p
                                .file_name()
                                .map(|n| n.to_string_lossy().into_owned())
                                .unwrap_or_default(),
                            command,
                        });
                    }
                }
                Err(e) => refused.push(format!("{}: {e}", p.display())),
            },

            Ok(_) => {}
            Err(e) => refused.push(format!("{}: {e}", p.display())),
        }
    }
}
