use std::path::{Path, PathBuf};

use crate::{
    resolve_tool, run_tool, snapshot, ApplyOptions, Failure, Outcome, Plan, RefuseCause, Refusal,
    UndoKind, UndoRecord,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Param {

    pub spelling: &'static str,

    pub key: &'static str,

    pub buys: &'static str,

    pub breaks: &'static str,
}

pub const CATALOGUE: &[Param] = &[
    Param {
        spelling: "module.sig_enforce=1",
        key: "module.sig_enforce",
        buys: "the kernel refuses to load an unsigned module. This is the gate a kernel rootkit \
               LKM walks through, and `kernel-posture` reports it open on most hosts",
        breaks: "every unsigned module stops loading at the next boot — locally built drivers \
                 (DKMS graphics, VirtualBox, ZFS) are the usual casualties. The ones loaded \
                 right now are listed before this is applied",
    },
    Param {
        spelling: "lockdown=integrity",
        key: "lockdown",
        buys: "closes the routes that write to a running kernel without loading a module: \
               /dev/mem, kexec, raw PCI access, and BPF writes to kernel memory",
        breaks: "hibernation stops working, and anything that legitimately writes to /dev/mem \
                 or loads an unsigned module fails. Needs a kernel built with the lockdown LSM \
                 and that LSM enabled, which not every distribution does",
    },
    Param {
        spelling: "init_on_alloc=1",
        key: "init_on_alloc",
        buys: "zeroes heap pages on allocation, which turns a whole class of kernel \
               use-after-free info-leaks into reads of zeroes",
        breaks: "a small, measurable throughput cost on allocation-heavy work. Nothing stops \
                 working",
    },
    Param {
        spelling: "slab_nomerge",
        key: "slab_nomerge",
        buys: "stops the kernel merging slab caches of similar size, which is what heap \
               exploitation relies on to put a controllable object next to a target one",
        breaks: "a few megabytes more kernel memory. Nothing stops working",
    },
    Param {
        spelling: "randomize_kstack_offset=1",
        key: "randomize_kstack_offset",
        buys: "randomises the kernel stack offset per syscall, so an attacker cannot rely on a \
               fixed layout between calls",
        breaks: "a very small per-syscall cost. Nothing stops working",
    },
    Param {
        spelling: "vsyscall=none",
        key: "vsyscall",
        buys: "removes the legacy vsyscall page, which sits at a fixed address in every process \
               and is a standing source of ROP gadgets",
        breaks: "static binaries built against glibc older than about 2013 stop running. On \
                 anything current, nothing",
    },
];

pub fn param(spelling: &str) -> Option<&'static Param> {
    CATALOGUE.iter().find(|p| p.spelling == spelling)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Bootloader {

    Grub {

        defaults: PathBuf,

        generator: PathBuf,

        output: PathBuf,
    },

    SystemdBoot {

        entries: Vec<PathBuf>,
    },

    Refind {

        config: PathBuf,

        uki: bool,
    },

    Unknown,
}

const ESP_MOUNTS: &[&str] = &["boot", "efi", "boot/efi"];

pub fn detect() -> Bootloader {
    detect_in(Path::new("/"))
}

pub fn detect_in(root: &Path) -> Bootloader {
    let defaults = root.join("etc/default/grub");
    if defaults.is_file() {

        if let Some(g) = resolve_tool(&["/usr/sbin/update-grub", "/sbin/update-grub"]) {
            return Bootloader::Grub {
                defaults,
                generator: g,
                output: root.join("boot/grub/grub.cfg"),
            };
        }
        if let Some(g) = resolve_tool(&[
            "/usr/bin/grub-mkconfig",
            "/usr/sbin/grub-mkconfig",
            "/usr/bin/grub2-mkconfig",
            "/usr/sbin/grub2-mkconfig",
        ]) {
            let out = ["boot/grub/grub.cfg", "boot/grub2/grub.cfg"]
                .iter()
                .map(|p| root.join(p))
                .find(|p| p.is_file())
                .unwrap_or_else(|| root.join("boot/grub/grub.cfg"));
            return Bootloader::Grub { defaults, generator: g, output: out };
        }
    }
    for esp in ESP_MOUNTS {
        let base = root.join(esp);
        let entries = base.join("loader/entries");
        if entries.is_dir() {
            let mut found: Vec<PathBuf> = std::fs::read_dir(&entries)
                .map(|d| {
                    d.flatten()
                        .map(|e| e.path())
                        .filter(|p| p.extension().is_some_and(|x| x == "conf"))
                        .collect()
                })
                .unwrap_or_default();

            if !found.is_empty() {
                found.sort();
                return Bootloader::SystemdBoot { entries: found };
            }
        }
        let refind = base.join("refind_linux.conf");
        if refind.is_file() {
            let uki = base.join("EFI/Linux").is_dir();
            return Bootloader::Refind { config: refind, uki };
        }
        if base.join("EFI/refind/refind.conf").is_file() {
            return Bootloader::Refind {
                config: base.join("EFI/refind/refind.conf"),
                uki: base.join("EFI/Linux").is_dir(),
            };
        }
    }
    Bootloader::Unknown
}

pub fn unsigned_among(taints: &[(String, String)]) -> Vec<String> {
    taints
        .iter()
        .filter(|(_, t)| t.contains('E'))
        .map(|(n, _)| n.clone())
        .collect()
}

pub fn unsigned_loaded_modules() -> Option<Vec<String>> {
    let dir = std::fs::read_dir("/sys/module").ok()?;
    let pairs: Vec<(String, String)> = dir
        .flatten()
        .filter_map(|e| {
            let name = e.file_name().to_str()?.to_string();
            let taint = std::fs::read_to_string(e.path().join("taint")).ok()?;
            Some((name, taint.trim().to_string()))
        })
        .collect();
    let mut out = unsigned_among(&pairs);
    out.sort();
    Some(out)
}

pub fn set_in_grub_defaults(text: &str, key: &str, spelling: &str) -> Result<(String, bool), String> {
    const VAR: &str = "GRUB_CMDLINE_LINUX";
    let mut out: Vec<String> = Vec::new();
    let mut seen = false;
    let mut changed = false;

    for line in text.lines() {
        let trimmed = line.trim_start();

        if !trimmed.starts_with(&format!("{VAR}=")) || trimmed.starts_with('#') {
            out.push(line.to_string());
            continue;
        }
        seen = true;
        let Some(eq) = line.find('=') else {
            return Err(format!("malformed line in the bootloader defaults: {line:?}"));
        };
        let rhs = line.get(eq + 1..).unwrap_or("").trim();
        let quote = rhs.chars().next().filter(|c| *c == '"' || *c == '\'');
        let inner = match quote {
            Some(q) => rhs.strip_prefix(q).and_then(|r| r.strip_suffix(q)).ok_or_else(|| {
                format!("the {VAR} line is not closed by a matching quote: {line:?}")
            })?,
            None => rhs,
        };

        let mut parts: Vec<String> = inner.split_whitespace().map(str::to_string).collect();
        let already = parts.iter().position(|p| p == spelling).is_some();

        parts.retain(|p| p == spelling || (p != key && !p.starts_with(&format!("{key}="))));
        if !already {
            parts.push(spelling.to_string());
            changed = true;
        } else if parts.len() != inner.split_whitespace().count() {
            changed = true;
        }
        let q = quote.unwrap_or('"');
        out.push(format!("{}{VAR}={q}{}{q}", &line[..line.len() - trimmed.len()], parts.join(" ")));
    }

    if !seen {
        out.push(format!("{VAR}=\"{spelling}\""));
        changed = true;
    }
    let mut joined = out.join("\n");
    if text.ends_with('\n') {
        joined.push('\n');
    }
    Ok((joined, changed))
}

pub fn clear_in_grub_defaults(text: &str, key: &str) -> String {
    const VAR: &str = "GRUB_CMDLINE_LINUX";
    let mut out: Vec<String> = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim_start();
        if !trimmed.starts_with(&format!("{VAR}=")) || trimmed.starts_with('#') {
            out.push(line.to_string());
            continue;
        }
        let Some(eq) = line.find('=') else {
            out.push(line.to_string());
            continue;
        };
        let rhs = line.get(eq + 1..).unwrap_or("").trim();
        let quote = rhs.chars().next().filter(|c| *c == '"' || *c == '\'');
        let inner = match quote {
            Some(q) => rhs.strip_prefix(q).and_then(|r| r.strip_suffix(q)).unwrap_or(rhs),
            None => rhs,
        };
        let kept: Vec<&str> = inner
            .split_whitespace()
            .filter(|p| *p != key && !p.starts_with(&format!("{key}=")))
            .collect();
        let q = quote.unwrap_or('"');
        out.push(format!("{}{VAR}={q}{}{q}", &line[..line.len() - trimmed.len()], kept.join(" ")));
    }
    let mut joined = out.join("\n");
    if text.ends_with('\n') {
        joined.push('\n');
    }
    joined
}

pub fn not_yet() -> &'static str {
    "This changes NOTHING about the host you are on. A kernel parameter is read once, by the \
     kernel, at boot — the hardening exists after the next restart and not before it."
}

pub fn preflight(p: &Param) -> String {
    if p.key != "module.sig_enforce" {
        return String::new();
    }
    let Some(unsigned) = unsigned_loaded_modules() else {
        return "Pre-flight: /sys/module could NOT be read, so whether any loaded module is \
                unsigned was not established. This is the parameter that stops unsigned \
                modules loading at the next boot; if one of them is a storage or network \
                driver, the host does not come back. Check by hand before arming this."
            .to_string();
    };
    if unsigned.is_empty() {
        return "Pre-flight: every module loaded right now carries a valid signature, so none of \
                them will stop loading. That is the common case on a stock distribution kernel \
                and it is checked rather than assumed."
            .to_string();
    }
    format!(
        "Pre-flight: {} module(s) loaded right now are UNSIGNED and will NOT load after the \
         reboot — {}. Each is something built on this host rather than shipped by the \
         distribution. If one of them is a storage or network driver, the host does not come \
         back. Sign them, or do not set this.",
        unsigned.len(),
        unsigned.join(", ")
    )
}

pub fn apply(p: &Param, opts: &ApplyOptions, loader: &Bootloader) -> Outcome {
    let refuse = |message: String| {
        Outcome::Refused(Refusal {
            action: format!("set {}", p.spelling),
            cause: RefuseCause::InvalidTarget("bootloader".into()),
            message,
            suggested_alternative: None,
        })
    };

    let (defaults, generator, output) = match loader {
        Bootloader::Grub { defaults, generator, output } => (defaults, generator, output),
        Bootloader::SystemdBoot { entries } => {
            return refuse(format!(
                "this host boots with systemd-boot ({} entry file(s) under /boot/loader/entries). \
                 That is recognised and deliberately not edited here: hardening has to go on \
                 EVERY entry, and one entry missed is a menu row that still boots un-hardened \
                 while the manifest says the host is hardened. Add `{}` to the `options` line of \
                 each entry by hand: {}",
                entries.len(),
                p.spelling,
                entries
                    .iter()
                    .map(|e| e.display().to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            ))
        }
        Bootloader::Refind { config, uki } => {
            let extra = if *uki {
                " This host also boots a unified kernel image, which can carry its own built-in \
                 command line — check /proc/cmdline after the reboot rather than assuming the \
                 edit took."
            } else {
                ""
            };
            return refuse(format!(
                "this host boots with rEFInd. Its command lines are in {}, one per menu entry, \
                 and they are not edited here for the same reason systemd-boot's are not: a \
                 line missed is an entry that still boots un-hardened while the manifest says \
                 the host is hardened. Add `{}` to each command line in that file by hand.{extra}",
                config.display(),
                p.spelling
            ))
        }
        Bootloader::Unknown => {
            return refuse(format!(
                "no bootloader this module understands was found — there is no \
                 /etc/default/grub and no /boot/loader/entries. Writing to a file nothing reads \
                 would report a host as hardened that is not. Add `{}` to this host's kernel \
                 command line by whatever configures it, and confirm with /proc/cmdline after \
                 the reboot",
                p.spelling
            ))
        }
    };

    if p.key == "module.sig_enforce" && unsigned_loaded_modules().is_none() {
        return refuse(
            "/sys/module could not be read, so whether any loaded module is unsigned was not \
             established. This parameter stops unsigned modules loading at the next boot; if \
             one of them is a storage or network driver, the host does not come back. Refusing \
             rather than setting it blind — check by hand, then set it"
                .to_string(),
        );
    }

    let before = match hemostat_sensor_linux::saferead::read_text(std::path::Path::new(defaults)) {
        Ok(t) => t,
        Err(e) => {
            return Outcome::Failed(Failure {
                action: format!("set {}", p.spelling),
                reason: format!("could not read {}: {e}", defaults.display()),
            })
        }
    };
    let (after, changed) = match set_in_grub_defaults(&before, p.key, p.spelling) {
        Ok(v) => v,
        Err(why) => return refuse(why),
    };

    if !changed && in_effect(p) {
        return refuse(format!(
            "`{}` is already on the kernel command line and already in {}. Nothing to do",
            p.spelling,
            defaults.display()
        ));
    }

    if !opts.armed {
        let mut detail = format!(
            "Set `{}` in {}, then run `{}` and read the generated config back to confirm the \
             parameter is in it. {}\n\n  What it buys: {}\n  What it costs: {}",
            p.spelling,
            defaults.display(),
            generator.display(),
            not_yet(),
            p.buys,
            p.breaks
        );
        let pre = preflight(p);
        if !pre.is_empty() {
            detail.push_str("\n\n  ");
            detail.push_str(&pre);
        }
        return Outcome::Planned(Plan {
            summary: format!("set the kernel parameter `{}` (takes effect at the next boot)", p.spelling),
            detail,
            undo: format!(
                "hemostat undo <journal> — restores {} and re-runs the generator",
                defaults.display()
            ),
            reversible: true,
            prefer_instead: None,
        });
    }

    let vault = match snapshot(defaults, &before, &opts.vault_dir) {
        Ok(v) => v,
        Err(reason) => {
            return Outcome::Failed(Failure {
                action: format!("set {}", p.spelling),
                reason: format!(
                    "could not snapshot {} into the vault ({reason}), so this was NOT applied — \
                     a kernel command line with no way back is not a change worth making",
                    defaults.display()
                ),
            })
        }
    };

    if let Err(e) = std::fs::write(defaults, &after) {
        return Outcome::Failed(Failure {
            action: format!("set {}", p.spelling),
            reason: format!("could not write {}: {e}", defaults.display()),
        });
    }

    let rollback = |reason: String| -> Outcome {
        let put_back = std::fs::write(defaults, &before);
        let tail = if put_back.is_ok() {
            format!("{} has been put back as it was", defaults.display())
        } else {
            format!(
                "AND {} could NOT be put back — restore it from the vault copy at {} before \
                 rebooting this host",
                defaults.display(),
                vault.display()
            )
        };

        let _ = run_tool(generator, &generator_args(generator, output));
        Outcome::Failed(Failure { action: format!("set {}", p.spelling), reason: format!("{reason}. {tail}") })
    };

    if let Err(reason) = run_tool(generator, &generator_args(generator, output)) {
        return rollback(format!("`{}` failed: {reason}", generator.display()));
    }
    match hemostat_sensor_linux::saferead::read_text(std::path::Path::new(output)) {
        Ok(cfg) if cfg.contains(p.spelling) => {}
        Ok(_) => {
            return rollback(format!(
                "`{}` ran, but `{}` is not in the config it generated ({}). The parameter would \
                 not be on the command line at the next boot",
                generator.display(),
                p.spelling,
                output.display()
            ))
        }
        Err(e) => {
            return rollback(format!(
                "the generated config {} could not be read back ({e}), so there is no evidence \
                 the parameter would take effect",
                output.display()
            ))
        }
    }

    let mut did = format!(
        "set the kernel parameter `{}` in {} and confirmed it in {}. {}",
        p.spelling,
        defaults.display(),
        output.display(),
        not_yet()
    );
    let pre = preflight(p);
    if !pre.is_empty() {
        did.push(' ');
        did.push_str(&pre);
    }
    Outcome::Applied(UndoRecord {
        did,
        undo: UndoKind::RestoreBootParams {
            vault,
            original: defaults.clone(),
            generator: generator.display().to_string(),
            output: output.clone(),
        },
        reversible: true,
    })
}

fn generator_args<'a>(generator: &Path, output: &'a Path) -> Vec<&'a str> {
    let name = generator.file_name().and_then(|n| n.to_str()).unwrap_or("");
    if name == "update-grub" {
        Vec::new()
    } else {
        vec!["-o", output.to_str().unwrap_or("/boot/grub/grub.cfg")]
    }
}

pub fn in_effect(p: &Param) -> bool {
    std::fs::read_to_string("/proc/cmdline")
        .is_ok_and(|c| c.split_whitespace().any(|w| w == p.spelling))
}

pub fn undo_restore(
    vault: &Path,
    original: &Path,
    generator: &str,
    output: &Path,
    opts: &ApplyOptions,
) -> Outcome {
    if !opts.armed {
        return Outcome::Planned(Plan {
            summary: format!("restore {}", original.display()),
            detail: format!(
                "Restore {} from {}, then run `{generator}` so the generated config matches it \
                 again.",
                original.display(),
                vault.display()
            ),
            undo: "Set the parameter again if needed.".into(),
            reversible: true,
            prefer_instead: None,
        });
    }
    let kept = match crate::revert::restore_in_place(vault, original) {
        Ok(kept) => kept,
        Err(reason) => {
            return Outcome::Failed(Failure { action: format!("restore {}", original.display()), reason })
        }
    };
    let gen_path = PathBuf::from(generator);
    match run_tool(&gen_path, &generator_args(&gen_path, output)) {
        Ok(()) => Outcome::Applied(UndoRecord {
            did: format!(
                "restored {} and regenerated {} — the parameter is gone from the next boot{}",
                original.display(),
                output.display(),
                crate::revert::kept_note(kept.as_deref())
            ),
            undo: UndoKind::Irreversible { note: "restoring is the undo".into() },
            reversible: false,
        }),
        Err(reason) => Outcome::Failed(Failure {
            action: format!("restore {}", original.display()),
            reason: format!(
                "{} was restored, but `{generator}` failed ({reason}), so {} still carries the \
                 parameter and the host will still boot with it. Run the generator by hand \
                 before rebooting",
                original.display(),
                output.display()
            ),
        }),
    }
}
