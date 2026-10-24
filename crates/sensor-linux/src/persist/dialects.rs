use super::places::{hidden_under_system_dir, suspicious_location};
use crate::triage::Severity;

pub(super) fn directives(text: &str) -> Vec<&str> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#') && !l.starts_with(';'))
        .collect()
}

pub(super) const EXEC_KEYS: &[&str] = &[
    "ExecStart=", "ExecStartPre=", "ExecStartPost=", "ExecStop=", "ExecStopPost=",
    "ExecReload=", "ExecCondition=", "RUN+=", "RUN=", "PROGRAM=", "IMPORT{program}=",
    "Exec=", "TryExec=", "install ", "AuthorizedKeysCommand ", "ForceCommand ",
];

pub(super) fn payload_of(line: &str) -> Option<&str> {
    for key in EXEC_KEYS {
        if let Some(rest) = line.split(key).nth(1) {
            return Some(rest);
        }
    }

    if let Some((key, _)) = line.split_once('=') {
        let looks_like_a_setting = !key.is_empty()
            && key.len() <= 64
            && key
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.');
        if looks_like_a_setting {
            return None;
        }
    }
    Some(line)
}

const APT_HOOK_DIRECTIVES: &[&str] = &["pre-invoke", "post-invoke", "pre-install-pkgs"];

pub(super) fn apt_hook_commands(line: &str) -> Vec<String> {
    let t = line.trim();
    let key_end = t.find(|c| c == '{' || c == '"').unwrap_or(t.len());
    let key = t[..key_end].to_ascii_lowercase();
    if !APT_HOOK_DIRECTIVES.iter().any(|d| key.contains(d)) {
        return Vec::new();
    }

    let mut out = Vec::new();
    let mut rest = &t[key_end..];
    while let Some(open) = rest.find('"') {
        rest = &rest[open + 1..];
        match rest.find('"') {
            Some(close) => {
                let cmd = rest[..close].trim();
                if !cmd.is_empty() {
                    out.push(cmd.to_string());
                }
                rest = &rest[close + 1..];
            }
            None => break,
        }
    }
    out
}

pub(super) const KNOWN_NSS_MODULES: &[&str] = &[
    "files", "altfiles", "compat", "dns", "db", "cache", "nis", "nisplus",
    "myhostname", "mymachines", "resolve", "systemd", "hesiod",
    "ldap", "sss", "sssd", "winbind", "wins", "extrausers",
    "mdns", "mdns4", "mdns6", "mdns_minimal", "mdns4_minimal", "mdns6_minimal",
    "docker", "libvirt", "libvirt_guest", "gw_name", "role", "kubernetes",
];

pub(super) fn unknown_nss_modules(line: &str) -> Vec<String> {
    let t = line.trim();
    if t.starts_with('#') {
        return Vec::new();
    }
    let Some((_db, rest)) = t.split_once(':') else { return Vec::new() };
    let mut out = Vec::new();
    let mut in_brackets = false;
    for tok in rest.split_whitespace() {

        if tok.starts_with('[') {
            in_brackets = !tok.ends_with(']');
            continue;
        }
        if in_brackets {
            in_brackets = !tok.ends_with(']');
            continue;
        }
        let name = tok.trim_matches(|c: char| !c.is_ascii_alphanumeric() && c != '_' && c != '-');
        if name.is_empty() || KNOWN_NSS_MODULES.contains(&name) {
            continue;
        }
        out.push(name.to_string());
    }
    out
}

pub(super) fn command_severity(value: &str) -> Severity {
    let program = value.split_whitespace().next().unwrap_or(value);

    if suspicious_location(program).is_some() || hidden_under_system_dir(program) {
        Severity::Critical
    } else {
        Severity::Warn
    }
}

pub(super) fn sshd_directive(key: &str, value: &str) -> Option<(Severity, String, String)> {
    let v = value.trim();
    let lower = v.to_lowercase();
    let set = !lower.is_empty() && lower != "none";
    match key.to_lowercase().as_str() {
        "permitrootlogin" if lower == "yes" => Some((
            Severity::Critical,
            "permits direct root login over SSH".into(),
            "no current distribution ships this — the default is `prohibit-password` or \
             `no`. Set to `yes`, a guessed or reused root password is a root shell from \
             the network, and every action taken through it is attributable to nobody"
                .into(),
        )),
        "permitemptypasswords" if lower == "yes" => Some((
            Severity::Critical,
            "accepts an empty password".into(),
            "any account whose password field is blank becomes a remote login with no \
             credential at all"
                .into(),
        )),

        "authorizedkeyscommand" if set => Some((
            command_severity(v),
            format!("runs `{v}` to decide which keys may log in"),
            "this command's output *is* the authorised-keys list, so whoever controls it \
             controls who may log in, and no `authorized_keys` file anywhere will show \
             it. Distributions integrating systemd-userdb set this legitimately, so \
             confirm the command by provenance"
                .into(),
        )),
        "forcecommand" if set => Some((
            command_severity(v),
            format!("runs `{v}` on every login"),
            "a ForceCommand runs for every session whatever the client asked for, which \
             makes it a persistence mechanism that inspecting keys will never reveal. \
             Restricted-shell and rsync-only setups use it legitimately"
                .into(),
        )),
        "permituserenvironment" if lower == "yes" => Some((
            Severity::Warn,
            "lets the client set environment variables at login".into(),
            "with a writable `authorized_keys` or `~/.ssh/environment` this is an \
             LD_PRELOAD injected into the login session"
                .into(),
        )),
        "passwordauthentication" if lower == "yes" => Some((
            Severity::Note,
            "allows password authentication".into(),
            "the default on several distributions, so this is context rather than a \
             finding: it is what makes a guessed or reused password sufficient, and it \
             is worth reading next to PermitRootLogin"
                .into(),
        )),
        _ => None,
    }
}

pub(super) fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let cut: String = s.chars().take(max).collect();
    format!("{cut}…")
}
