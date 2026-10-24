use std::path::Path;

pub(super) const WORLD_WRITABLE: &[&str] = &["/tmp/", "/var/tmp/", "/dev/shm/", "/run/user/", "/var/spool/samba/"];

pub(super) const STOCK_HIDDEN_FILES: &[&str] = &[".placeholder"];

pub(super) fn lexically_normal(path: &str) -> String {
    if !path.contains("//") && !path.contains("/./") && !path.starts_with("./") {
        return path.to_string();
    }
    let lead = if path.starts_with('/') { "/" } else { "" };
    let body: Vec<&str> = path
        .split('/')
        .filter(|c| !c.is_empty() && *c != ".")
        .collect();
    let joined = body.join("/");

    let trail = if path.ends_with('/') && !joined.is_empty() { "/" } else { "" };
    format!("{lead}{joined}{trail}")
}

pub fn suspicious_location(path: &str) -> Option<String> {
    let path = &lexically_normal(path);
    if let Some(dir) = WORLD_WRITABLE.iter().find(|d| path.starts_with(*d)) {
        return Some(format!("lives under {dir}, which any local user can write"));
    }

    if is_system_path(path)
        && Path::new(path)
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| {
                n.starts_with('.') && n.len() > 1 && !STOCK_HIDDEN_FILES.contains(&n)
            })
    {
        return Some("has a hidden filename inside a system configuration directory".into());
    }
    None
}

pub(super) const SYSTEM_PREFIXES: &[&str] =
    &["/etc/", "/usr/", "/lib/", "/lib64/", "/bin/", "/sbin/", "/opt/", "/srv/", "/boot/"];

pub(super) fn is_system_path(path: &str) -> bool {
    let path = lexically_normal(path);
    SYSTEM_PREFIXES.iter().any(|p| path.starts_with(p))
}

pub(super) fn hidden_under_system_dir(command: &str) -> bool {

    let tokens: Vec<&str> = command
        .split_whitespace()
        .flat_map(|w| w.split(['"', '\'', '=', '(', ')']))
        .filter(|w| !w.is_empty())
        .collect();

    let mut expect_command = true;
    for t in tokens {
        if expect_command && is_system_path(t) && has_hidden_component(t) {
            return true;
        }

        expect_command = is_separator(t) || runs_what_follows(t);
    }
    false
}

pub(super) fn is_separator(t: &str) -> bool {
    matches!(t, ";" | "&&" | "||" | "|" | "&") || t.ends_with(';') || t.ends_with('|')
}

pub(super) fn runs_what_follows(t: &str) -> bool {
    if matches!(t, "exec" | "source" | "." | "sudo" | "eval" | "nohup" | "setsid" | "env") {
        return true;
    }

    let base = t.rsplit('/').next().unwrap_or(t);
    let base = base.strip_suffix(".exe").unwrap_or(base);
    matches!(
        base,
        "sh" | "bash" | "dash" | "zsh" | "ksh" | "ash" | "busybox"
            | "python" | "python2" | "python3" | "perl" | "ruby" | "php" | "lua"
            | "node" | "nodejs" | "awk" | "gawk"
    ) || base.starts_with("python3.")
}

pub(super) fn has_hidden_component(p: &str) -> bool {
    p.split('/').any(|part| part.starts_with('.') && part != "." && part != "..")
}
