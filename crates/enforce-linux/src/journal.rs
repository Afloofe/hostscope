use std::path::{Path, PathBuf};

use hemostat_evfmt::tsvjournal::{self, decode_pairs, encode_pairs, esc, unesc, PAIR_SEP};

use crate::{UndoKind, UndoRecord};

pub const HEADER: &str = "# hemostat undo journal v1";

pub fn unique_path(dir: &Path) -> Option<PathBuf> {
    tsvjournal::unique_path(dir, "undo")
}

pub fn line(r: &UndoRecord) -> String {
    let rev = if r.reversible { "1" } else { "0" };
    let head = match &r.undo {
        UndoKind::ResumeProcess { pid, start_time } => {
            format!("resume-process\t{rev}\t{pid}\t{start_time}\t-")
        }
        UndoKind::UnmaskService { unit, was_active } => format!(
            "unmask-service\t{rev}\t{}\t{}\t-",
            esc(unit),
            match was_active {
                Some(true) => "1",
                Some(false) => "0",
                None => "-",
            }
        ),

        UndoKind::RestoreServiceState { unit, was_enabled, was_active } => {
            let tri = |b: &Option<bool>| match b {
                Some(true) => "1",
                Some(false) => "0",
                None => "-",
            };
            format!(
                "restore-service-state\t{rev}\t{}\t{}\t{}",
                esc(unit),
                tri(was_enabled),
                tri(was_active)
            )
        }
        UndoKind::RestoreFile { vault, original, moved } => format!(
            "restore-file\t{rev}\t{}\t{}\t{}",
            esc(&vault.to_string_lossy()),
            esc(&original.to_string_lossy()),
            if *moved { "1" } else { "0" }
        ),
        UndoKind::RestoreUnit { vault, original, unit } => format!(
            "restore-unit\t{rev}\t{}\t{}\t{}",
            esc(&vault.to_string_lossy()),
            esc(&original.to_string_lossy()),
            esc(unit)
        ),
        UndoKind::RestoreMode { path, mode } => format!(
            "restore-mode\t{rev}\t{}\t{:o}\t-",
            esc(&path.to_string_lossy()),
            mode & 0o7777
        ),

        UndoKind::UnlockAccount { user, shell, was_locked } => format!(
            "unlock-account\t{rev}\t{}\t{}\t{}",
            esc(user),
            shell.as_deref().map_or_else(|| "-".to_string(), esc),
            match was_locked {
                Some(true) => "1",
                Some(false) => "0",
                None => "-",
            }
        ),
        UndoKind::RemoveCreatedFile { vault, original } => format!(
            "remove-created-file\t{rev}\t{}\t{}\t-",
            esc(&vault.to_string_lossy()),
            esc(&original.to_string_lossy())
        ),
        UndoKind::RestoreSysctl { was } => {
            format!("restore-sysctl\t{rev}\t{}\t-\t-", esc(&encode_pairs(was)))
        }
        UndoKind::Irreversible { note } => {
            format!("irreversible\t{rev}\t{}\t-\t-", esc(note))
        }

        UndoKind::Nothing => format!("nothing\t{rev}\t-\t-\t-"),

        UndoKind::RestoreBootParams { vault, original, generator, output } => format!(
            "restore-boot-params\t{rev}\t{}\t{}\t{}",
            esc(&vault.to_string_lossy()),
            esc(&original.to_string_lossy()),
            esc(&format!("{generator}{PAIR_SEP}{}", output.to_string_lossy()))
        ),
        UndoKind::RemoveCanary { path } => {
            format!("remove-canary\t{rev}\t{}\t-\t-", esc(&path.to_string_lossy()))
        }

        UndoKind::RemoveNftAllow { family, table, chain, comment } => format!(
            "remove-nft-allow\t{rev}\t{}\t{}\t{}",
            esc(family),
            esc(table),
            esc(&format!("{chain}{PAIR_SEP}{comment}"))
        ),
        UndoKind::UnmountExecBlock { path } => format!(
            "unmount-exec-block\t{rev}\t{}\t-\t-",
            esc(&path.to_string_lossy())
        ),
        UndoKind::RejoinGroup { user, group } => {
            format!("rejoin-group\t{rev}\t{}\t{}\t-", esc(user), esc(group))
        }
        UndoKind::RestorePasswordAge { user, last_change } => format!(
            "restore-password-age\t{rev}\t{}\t{}\t-",
            esc(user),
            esc(last_change)
        ),

        UndoKind::RestoreStripped { vault, original, line_no, line_sha256, before, after, mode, uid, gid } => {
            let pairs: Vec<(String, String)> = vec![
                ("line".into(), line_no.to_string()),
                ("line-sha256".into(), line_sha256.clone()),
                ("before".into(), before.clone()),
                ("after".into(), after.clone()),
                ("mode".into(), format!("{:o}", mode & 0o7777)),
                ("uid".into(), uid.to_string()),
                ("gid".into(), gid.to_string()),
            ];
            format!(
                "restore-stripped\t{rev}\t{}\t{}\t{}",
                esc(&vault.to_string_lossy()),
                esc(&original.to_string_lossy()),
                esc(&encode_pairs(&pairs))
            )
        }

        UndoKind::RestoreAnchor { vault, original, cert_sha256, before, after, mode, uid, gid, rebuild, bundle_before } => {
            let pairs: Vec<(String, String)> = vec![
                ("cert".into(), cert_sha256.clone()),
                ("before".into(), before.clone()),
                ("after".into(), after.clone()),
                ("mode".into(), format!("{:o}", mode & 0o7777)),
                ("uid".into(), uid.to_string()),
                ("gid".into(), gid.to_string()),
                ("rebuild".into(), rebuild.clone()),
                ("bundle-before".into(), bundle_before.clone()),
            ];
            format!(
                "restore-anchor\t{rev}\t{}\t{}\t{}",
                esc(&vault.to_string_lossy()),
                esc(&original.to_string_lossy()),
                esc(&encode_pairs(&pairs))
            )
        }
    };
    format!("{head}\t{}\n", esc(&r.did))
}

pub struct Appender {
    inner: tsvjournal::Appender,
}

impl Appender {

    pub fn new(dir: &Path) -> Self {

        Appender { inner: tsvjournal::Appender::new(dir, "undo", HEADER) }
    }

    pub fn path(&self) -> &Path {
        self.inner.path()
    }

    pub fn started(&self) -> bool {
        self.inner.started()
    }

    pub fn append(&mut self, r: &UndoRecord) -> std::io::Result<()> {
        self.inner.append(&line(r))
    }
}

pub fn encode(records: &[UndoRecord]) -> String {
    let mut out = String::from(HEADER);
    out.push('\n');
    for r in records {
        out.push_str(&line(r));
    }
    out
}

pub fn split_torn(text: &str) -> (&str, Option<&str>) {
    if text.ends_with('\n') {
        return (text, None);
    }
    let Some((whole, torn)) = text.rfind('\n').and_then(|i| text.split_at_checked(i + 1)) else {
        return (text, None);
    };
    if torn.trim().is_empty() || torn.starts_with('#') {
        return (text, None);
    }
    (whole, Some(torn))
}

pub fn decode(text: &str) -> Result<Vec<UndoRecord>, String> {
    let mut out = Vec::new();
    for (n, line) in tsvjournal::records(text, HEADER, "an undo journal")? {
        let f: Vec<&str> = line.split('\t').collect();

        let [kind, reversible_flag, arg1, arg2, arg3, did_field]: [&str; 6] =
            f.as_slice()
                .try_into()
                .map_err(|_| format!("line {n}: expected 6 fields, found {}", f.len()))?;
        let reversible = reversible_flag == "1";
        let did = unesc(did_field);
        let undo = match kind {
            "resume-process" => {
                let pid = arg1
                    .parse::<u32>()
                    .map_err(|_| format!("line {n}: bad pid {:?}", arg1))?;
                let start_time = arg2
                    .parse::<u64>()
                    .map_err(|_| format!("line {n}: bad start_time {:?}", arg2))?;
                UndoKind::ResumeProcess { pid, start_time }
            }

            "unmask-service" => UndoKind::UnmaskService {
                unit: unesc(arg1),
                was_active: match arg2 {
                    "1" => Some(true),
                    "0" => Some(false),
                    _ => None,
                },
            },
            "restore-service-state" => UndoKind::RestoreServiceState {
                unit: unesc(arg1),
                was_enabled: match arg2 {
                    "1" => Some(true),
                    "0" => Some(false),
                    _ => None,
                },
                was_active: match arg3 {
                    "1" => Some(true),
                    "0" => Some(false),
                    _ => None,
                },
            },
            "restore-file" => UndoKind::RestoreFile {
                vault: PathBuf::from(unesc(arg1)),
                original: PathBuf::from(unesc(arg2)),
                moved: arg3 == "1",
            },
            "restore-unit" => UndoKind::RestoreUnit {
                vault: PathBuf::from(unesc(arg1)),
                original: PathBuf::from(unesc(arg2)),
                unit: unesc(arg3),
            },
            "restore-mode" => UndoKind::RestoreMode {
                path: PathBuf::from(unesc(arg1)),
                mode: u32::from_str_radix(arg2, 8)
                    .map_err(|_| format!("line {n}: bad mode {:?}", arg2))?,
            },
            "unlock-account" => UndoKind::UnlockAccount {
                user: unesc(arg1),

                shell: if arg2 == "-" { None } else { Some(unesc(arg2)) },

                was_locked: match arg3 {
                    "1" => Some(true),
                    "0" => Some(false),
                    _ => None,
                },
            },
            "remove-created-file" => UndoKind::RemoveCreatedFile {
                vault: PathBuf::from(unesc(arg1)),
                original: PathBuf::from(unesc(arg2)),
            },
            "restore-sysctl" => UndoKind::RestoreSysctl { was: decode_pairs(&unesc(arg1)) },
            "irreversible" => UndoKind::Irreversible { note: unesc(arg1) },
            "nothing" => UndoKind::Nothing,
            "restore-boot-params" => {
                let joined = unesc(arg3);
                let (generator, output) = joined.split_once(PAIR_SEP).ok_or_else(|| {
                    format!("line {n}: restore-boot-params needs a generator and an output path")
                })?;
                UndoKind::RestoreBootParams {
                    vault: PathBuf::from(unesc(arg1)),
                    original: PathBuf::from(unesc(arg2)),
                    generator: generator.to_string(),
                    output: PathBuf::from(output),
                }
            }
            "remove-canary" => UndoKind::RemoveCanary { path: PathBuf::from(unesc(arg1)) },
            "remove-nft-allow" => {
                let joined = unesc(arg3);
                let (chain, comment) = joined.split_once(PAIR_SEP).ok_or_else(|| {
                    format!("line {n}: remove-nft-allow needs a chain and a comment")
                })?;
                UndoKind::RemoveNftAllow {
                    family: unesc(arg1),
                    table: unesc(arg2),
                    chain: chain.to_string(),
                    comment: comment.to_string(),
                }
            }
            "unmount-exec-block" => {
                UndoKind::UnmountExecBlock { path: PathBuf::from(unesc(arg1)) }
            }
            "rejoin-group" => {
                UndoKind::RejoinGroup { user: unesc(arg1), group: unesc(arg2) }
            }
            "restore-password-age" => {
                UndoKind::RestorePasswordAge { user: unesc(arg1), last_change: unesc(arg2) }
            }
            "restore-stripped" => {
                let pairs = decode_pairs(&unesc(arg3));
                let get = |k: &str| {
                    pairs
                        .iter()
                        .find(|(key, _)| key == k)
                        .map(|(_, v)| v.clone())
                        .ok_or_else(|| format!("line {n}: restore-stripped has no {k}"))
                };
                let num = |k: &str, radix: u32| {
                    get(k).and_then(|v| {
                        u32::from_str_radix(&v, radix).map_err(|_| format!("line {n}: bad {k} {v:?}"))
                    })
                };
                UndoKind::RestoreStripped {
                    vault: PathBuf::from(unesc(arg1)),
                    original: PathBuf::from(unesc(arg2)),
                    line_no: get("line")?
                        .parse()
                        .map_err(|_| format!("line {n}: bad line number"))?,
                    line_sha256: get("line-sha256")?,
                    before: get("before")?,
                    after: get("after")?,
                    mode: num("mode", 8)?,
                    uid: num("uid", 10)?,
                    gid: num("gid", 10)?,
                }
            }
            "restore-anchor" => {
                let pairs = decode_pairs(&unesc(arg3));
                let get = |k: &str| {
                    pairs
                        .iter()
                        .find(|(key, _)| key == k)
                        .map(|(_, v)| v.clone())
                        .ok_or_else(|| format!("line {n}: restore-anchor has no {k}"))
                };
                let num = |k: &str, radix: u32| {
                    get(k).and_then(|v| {
                        u32::from_str_radix(&v, radix).map_err(|_| format!("line {n}: bad {k} {v:?}"))
                    })
                };
                UndoKind::RestoreAnchor {
                    vault: PathBuf::from(unesc(arg1)),
                    original: PathBuf::from(unesc(arg2)),
                    cert_sha256: get("cert")?,
                    before: get("before")?,
                    after: get("after")?,
                    mode: num("mode", 8)?,
                    uid: num("uid", 10)?,
                    gid: num("gid", 10)?,
                    rebuild: get("rebuild")?,
                    bundle_before: get("bundle-before")?,
                }
            }
            other => return Err(format!("line {n}: unknown record kind {other:?}")),
        };
        out.push(UndoRecord { did, undo, reversible });
    }
    Ok(out)
}
