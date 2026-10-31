use super::places::{hidden_under_system_dir, is_system_path, WORLD_WRITABLE};

pub(super) fn bare(w: &str) -> &str {
    w.trim_matches(|c: char| matches!(c, '"' | '\'' | '(' | ')' | ';' | '`' | ','))
}

pub(super) fn invokes_tool(command: &str, tool: &str) -> bool {
    command
        .split_whitespace()
        .any(|w| bare(w).rsplit('/').next().is_some_and(|b| b == tool))
}

pub(super) fn has_flag(command: &str, flag: &str) -> bool {
    command.split_whitespace().any(|w| bare(w) == flag)
}

pub(super) fn tool_flag(command: &str, tool: &str, flag: &str) -> bool {
    flag_after(command, flag, |b| b == tool)
}

pub(super) fn tool_flag_versioned(command: &str, tool: &str, flag: &str) -> bool {
    flag_after(command, flag, |b| versioned(b, tool))
}

fn versioned(base: &str, tool: &str) -> bool {
    base == tool
        || base
            .strip_prefix(tool)
            .is_some_and(|v| v.chars().all(|c| c.is_ascii_digit() || c == '.'))
}

fn words_at(command: &str) -> Vec<(usize, &str)> {
    let mut out = Vec::new();
    let mut start = None;
    for (i, ch) in command.char_indices() {
        match (ch.is_whitespace(), start) {
            (true, Some(s)) => {
                out.extend(command.get(s..i).map(|w| (s, w)));
                start = None;
            }
            (false, None) => start = Some(i),
            _ => {}
        }
    }
    if let Some(s) = start {
        out.extend(command.get(s..).map(|w| (s, w)));
    }
    out
}

fn inline_programs<'a>(command: &'a str, tool: &str, flag: &str) -> Vec<Option<&'a str>> {
    let words = words_at(command);
    let short = flag.strip_prefix('-').filter(|f| f.len() == 1);
    let mut out = Vec::new();
    let mut i = 0;
    while let Some(&(_, w)) = words.get(i) {
        i += 1;
        if !bare(w).rsplit('/').next().is_some_and(|b| versioned(b, tool)) {
            continue;
        }
        let mut programs = Vec::new();
        let mut other_flags = false;
        while let Some(&(_, next)) = words.get(i) {
            let next = bare(next);
            if next == "--" || !next.starts_with('-') {
                break;
            }
            i += 1;
            if next != flag {
                let glued = short.is_some_and(|f| {
                    !next.starts_with("--") && next.get(1..).is_some_and(|rest| rest.contains(f))
                });
                if glued {
                    programs.push(None);
                } else {
                    other_flags = true;
                }
                continue;
            }
            let Some(&(at, arg)) = words.get(i) else {
                programs.push(None);
                break;
            };
            let rest = command.get(at..).unwrap_or_default();
            let (program, end) = match rest.chars().next() {
                Some(q @ ('\'' | '"')) => match rest.get(1..).and_then(|r| r.find(q)) {
                    Some(k) => {
                        let end = at + k + 2;

                        let ends_word = command
                            .get(end..)
                            .and_then(|after| after.chars().next())
                            .is_none_or(|ch| ch.is_whitespace() || ";&|)`".contains(ch));
                        (rest.get(1..=k).filter(|_| ends_word), end)
                    }
                    None => (None, command.len()),
                },
                _ => (Some(arg), at + arg.len()),
            };
            programs.push(program);
            while words.get(i).is_some_and(|&(o, _)| o < end) {
                i += 1;
            }
        }
        if other_flags {
            programs.iter_mut().for_each(|p| *p = None);
        }
        out.extend(programs);
    }
    out
}

fn only_sleeps(program: &str) -> bool {
    const DELAY: &[&str] = &["sleep", "int", "rand", "random", "randint", "uniform", "import", "time"];
    let words: Vec<&str> = program
        .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .filter(|w| !w.is_empty())
        .collect();
    words.contains(&"sleep")
        && words
            .iter()
            .all(|w| DELAY.contains(w) || w.chars().all(|c| c.is_ascii_digit()))
        && program
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || " \t();.,*+-/".contains(c))
}

fn loads_code_from_environment(c: &str) -> bool {
    const LOADERS: &[&str] = &[
        "perl5opt", "perl5lib", "perllib", "pythonpath", "pythonstartup", "pythonhome",
        "rubyopt", "rubylib", "phprc", "php_ini_scan_dir", "ld_preload", "ld_audit",
        "ld_library_path",
    ];
    c.split_whitespace().any(|w| {
        let mut parts: Vec<&str> = w.split('=').collect();
        parts.pop();
        parts.iter().any(|k| LOADERS.contains(&k.trim_start_matches(['-', '\'', '"', '(', ';', '`'])))
    })
}

pub(super) fn flag_after(command: &str, flag: &str, is_tool: impl Fn(&str) -> bool) -> bool {
    let words: Vec<&str> = command.split_whitespace().map(bare).collect();
    let short = flag.strip_prefix('-').filter(|f| f.len() == 1 && !f.starts_with('-'));
    for (i, w) in words.iter().enumerate() {
        if !w.rsplit('/').next().is_some_and(&is_tool) {
            continue;
        }
        for next in &words[i + 1..] {
            if *next == "--" || !next.starts_with('-') {
                break;
            }
            if next == &flag {
                return true;
            }

            if let Some(f) = short {
                if !next.starts_with("--") && next[1..].contains(f) {
                    return true;
                }
            }
        }
    }
    false
}

pub(super) fn arg_under_world_writable(command: &str) -> Option<&'static str> {
    under_world_writable(command.split_whitespace())?;
    simple_commands(command)
        .iter()
        .filter(|(_, words)| !names_without_running(effective(words)))
        .find_map(|(_, words)| under_world_writable(words.iter().copied()))
        .or_else(|| {
            substitution_bodies(command)
                .iter()
                .find_map(|b| under_world_writable(b.split_whitespace()))
        })
        .or_else(|| {
            process_substitutions(command)
                .iter()
                .find_map(|&(_, b)| under_world_writable(b.split_whitespace()))
        })
}

fn under_world_writable<'w>(words: impl IntoIterator<Item = &'w str>) -> Option<&'static str> {
    words.into_iter().find_map(|w| {
        let w = bare(w);
        WORLD_WRITABLE.iter().find(|d| w.starts_with(**d)).copied()
    })
}

fn names_without_running(e: &[&str]) -> bool {
    let Some((&head, args)) = e.split_first() else { return false };
    if under_world_writable([head]).is_some() {
        return false;
    }
    match basename(head) {
        "[" | "[[" | "test" | "mountpoint" | "umount" | "mkdir" | "rmdir" => true,
        "mount" => args
            .split_last()
            .is_some_and(|(_, sources)| under_world_writable(sources.iter().copied()).is_none()),
        "chmod" => {

            let recursive = args.iter().any(|a| {
                *a == "--recursive" || (a.starts_with('-') && !a.starts_with("--") && a.contains(['R', 'r']))
            });
            !recursive
                && args.iter().all(|a| match under_world_writable([*a]) {
                    Some(dir) => bare(a).trim_end_matches('/') == dir.trim_end_matches('/'),
                    None => true,
                })
        }
        _ => false,
    }
}

pub(super) fn routable_ip_literal(word: &str) -> bool {
    let host = word
        .trim_start_matches("http://")
        .trim_start_matches("https://")
        .split(['/', ':', '?'])
        .next()
        .unwrap_or("");
    let octets: Vec<&str> = host.split('.').collect();
    if octets.len() != 4 {
        return false;
    }
    if !octets.iter().all(|o| !o.is_empty() && o.len() <= 3 && o.chars().all(|c| c.is_ascii_digit()))
    {
        return false;
    }
    !(host.starts_with("127.") || host.starts_with("169.254.") || host == "0.0.0.0")
}

pub(super) fn beacon_shape(command: &str) -> Option<String> {
    let c = command.to_lowercase();
    let fetchers = ["curl ", "wget ", "fetch "];
    if !fetchers.iter().any(|f| c.contains(f)) {
        return None;
    }

    let piped = c.replace("||", "\u{1}");
    let segments: Vec<&str> = piped.split('|').collect();
    let at = segments
        .iter()
        .position(|seg| fetchers.iter().any(|f| seg.contains(f)))?;

    if at + 1 < segments.len() {
        return None;
    }
    let seg = segments.get(at)?;
    if !(seg.contains(">/dev/null")
        || seg.contains("> /dev/null")
        || seg.contains("-o /dev/null")
        || seg.contains("-o/dev/null"))
    {
        return None;
    }
    c.split_whitespace()
        .find(|w| routable_ip_literal(bare(w)))
        .map(|w| {
            format!(
                "fetches {} — a routable address written as digits, not a name — and discards \
                 the response. Nothing is being retrieved: the request itself is the message, \
                 which is the shape of a check-in",
                bare(w)
            )
        })
}

const SHELLS: [&str; 4] = ["bash", "sh", "zsh", "dash"];

fn piped_into_a_program(c: &str, is_source: impl Fn(&str) -> bool) -> bool {

    let piped = c.replace("||", "\u{1}");
    let stages: Vec<&str> = piped.split('|').collect();
    let Some(at) = stages.iter().position(|s| is_source(s)) else {
        return false;
    };
    stages.iter().skip(at + 1).any(|stage| {

        let mut words = stage.trim_start_matches(|ch: char| ch == '&' || ch.is_whitespace())
            .split_whitespace()
            .map(bare);
        let Some(cmd) = words.next() else { return false };
        let base = cmd.rsplit('/').next().unwrap_or(cmd);
        if SHELLS.contains(&base) {
            return true;
        }
        if !versioned(base, "python") {
            return false;
        }

        while let Some(w) = words.next() {
            if w == "-" {
                return true;
            }
            if !w.starts_with('-') {
                return false;
            }
            if !w.starts_with("--") && (w.contains('c') || w.contains('m')) {
                return false;
            }

            if w == "-w" || w == "-x" {
                words.next();
            }
        }
        true
    })
}

fn hands_connection_to_a_command(c: &str) -> bool {
    c.split_whitespace().map(bare).any(|w| {
        w.split("!!").any(|a| ["exec:", "system:", "shell:"].iter().any(|t| a.starts_with(t)))
            || ["--exec", "--sh-exec", "--lua-exec"]
                .iter()
                .any(|o| w.strip_prefix(o).is_some_and(|r| r.is_empty() || r.starts_with('=')))
    })
}

const NETCATS: [&str; 4] = ["nc", "ncat", "netcat", "socat"];

fn netcat_shell_flag(command: &str) -> bool {
    let words: Vec<&str> = command.split_whitespace().collect();
    words.iter().enumerate().any(|(i, w)| {
        if !["nc", "ncat", "netcat"].contains(&basename(bare(w))) {
            return false;
        }
        for next in words.iter().skip(i + 1) {
            if [";", "|", "||", "&&", "&", "|&"].contains(next) {
                return false;
            }
            let f = bare(next);
            let cluster = f.len() > 2
                && f.starts_with('-')
                && !f.starts_with("--")
                && f.chars().skip(1).all(|ch| ch.is_ascii_alphabetic())
                && f.ends_with('c');
            if f == "-c" || cluster {
                return true;
            }
            if next.ends_with([';', '|', '&', '\'', '"', ')', '`']) {
                return false;
            }
        }
        false
    })
}

const FETCH_TOOLS: [&str; 4] = ["curl", "wget", "fetch", "ftp"];

fn basename(w: &str) -> &str {
    w.rsplit('/').next().unwrap_or(w)
}

fn runs_its_argument(word: &str) -> bool {
    let base = basename(word);
    base == "source"
        || base == "."
        || SHELLS.contains(&base)
        || ["python", "perl", "ruby", "php", "node"].iter().any(|t| versioned(base, t))
}

fn process_substitutions(c: &str) -> Vec<(usize, &str)> {
    let b = c.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if b.get(i) == Some(&b'<') && b.get(i + 1) == Some(&b'(') {
            let start = i + 2;
            let mut depth = 1usize;
            let mut j = start;
            while j < b.len() && depth > 0 {
                match b.get(j) {
                    Some(&b'(') => depth += 1,
                    Some(&b')') => depth -= 1,
                    _ => {}
                }
                j += 1;
            }
            let end = if depth == 0 { j.saturating_sub(1) } else { b.len() };
            out.push((i, c.get(start..end).unwrap_or_default()));
            i = end;
        } else {
            i += 1;
        }
    }
    out
}

fn receiver_of(c: &str, at: usize) -> Option<&str> {
    c.get(..at)?
        .split_whitespace()
        .rev()
        .map(bare)
        .find(|w| !(w.is_empty() || w.starts_with('-') || *w == "<"))
}

fn download_substituted_into_a_runner(c: &str, fetchers: &[&str]) -> bool {
    process_substitutions(c).iter().any(|&(at, body)| {
        fetchers.iter().any(|f| body.contains(f)) && receiver_of(c, at).is_some_and(runs_its_argument)
    })
}

fn simple_commands(c: &str) -> Vec<(bool, Vec<&str>)> {
    let b = c.as_bytes();
    let mut out = Vec::new();
    let mut piped = false;
    let mut start = 0;
    let mut i = 0;
    while i < b.len() {
        let (here, prev, next) = (b.get(i), i.checked_sub(1).and_then(|p| b.get(p)), b.get(i + 1));
        let op = match (here, next) {
            (Some(b'|'), Some(b'|')) | (Some(b'&'), Some(b'&')) => Some((2, false)),
            (Some(b'|'), Some(b'&')) => Some((2, true)),
            (Some(b'|'), _) => Some((1, true)),
            (Some(b';' | b'\n'), _) => Some((1, false)),
            (Some(b'&'), _) if prev != Some(&b'>') && next != Some(&b'>') => Some((1, false)),
            _ => None,
        };
        let Some((len, pipe)) = op else {
            i += 1;
            continue;
        };
        let words = c.get(start..i).unwrap_or_default().split_whitespace().map(bare);
        out.push((piped, words.filter(|w| !w.is_empty()).collect()));
        piped = pipe;
        i += len;
        start = i;
    }
    let words = c.get(start..).unwrap_or_default().split_whitespace().map(bare);
    out.push((piped, words.filter(|w| !w.is_empty()).collect()));
    out
}

fn effective<'a, 'w>(mut w: &'a [&'w str]) -> &'a [&'w str] {
    const PREFIXES: &[&str] = &[
        "exec", "nohup", "sudo", "env", "setsid", "nice", "command", "builtin", "time", "if",
        "then", "else", "elif", "do", "while", "until", "!", "{", "}",
    ];
    loop {
        let Some(&first) = w.first() else { return w };
        let skip = if PREFIXES.contains(&first) {

            1 + w.iter().skip(1).take_while(|f| f.starts_with('-')).count()
        } else if first.contains('=') && !first.starts_with('-') {
            1
        } else if SHELLS.contains(&basename(first)) {
            let flags: Vec<&&str> =
                w.iter().skip(1).take_while(|f| f.starts_with('-') && **f != "--").collect();
            if !flags.iter().any(|f| !f.starts_with("--") && f.contains('c')) {
                return w;
            }
            1 + flags.len()
        } else {
            return w;
        };
        w = w.get(skip..).unwrap_or_default();
    }
}

fn url_basename(url: &str) -> String {
    let path = url.split_once("://").map_or(url, |(_, rest)| rest);
    let path = path.split(['?', '#']).next().unwrap_or(path);
    match path.split_once('/').map(|(_, p)| basename(p)) {
        Some(name) if !name.is_empty() => name.to_string(),
        _ => "index.html".to_string(),
    }
}

fn redirect_targets<'w>(e: &[&'w str]) -> Vec<&'w str> {
    let mut out = Vec::new();
    let mut words = e.iter();
    while let Some(&w) = words.next() {
        let value = if [">", ">>", "1>", "1>>", "&>", "&>>"].contains(&w) {
            words.next().copied()
        } else {
            ["&>>", "&>", "1>>", "1>", ">>", ">"].iter().find_map(|p| w.strip_prefix(p))
        };
        out.extend(value.filter(|v| !v.is_empty() && !v.starts_with('&') && !v.starts_with("/dev/")));
    }
    out
}

fn fetch_outputs(e: &[&str]) -> Vec<String> {
    let mut out: Vec<String> = redirect_targets(e).into_iter().map(str::to_string).collect();
    let mut named = !out.is_empty();
    let mut prefix: Option<&str> = None;
    let mut i = 1;
    while let Some(&w) = e.get(i) {
        i += 1;
        let mut take_next = || {
            let v = e.get(i).copied();
            i += 1;
            v
        };
        let value = if w == "--output" || w == "--output-document" {
            take_next()
        } else if let Some(v) = w.strip_prefix("--output=").or_else(|| w.strip_prefix("--output-document=")) {
            Some(v)
        } else if w == "-p" || w == "--directory-prefix" {
            prefix = take_next();
            continue;
        } else if let Some(v) = w.strip_prefix("--directory-prefix=") {
            prefix = Some(v);
            continue;
        } else if w.starts_with('-') && !w.starts_with("--") {

            match w.find('o').map(|k| w.get(k + 1..).unwrap_or_default()) {
                Some("") => take_next(),
                Some(glued) => Some(glued),
                None => None,
            }
        } else {
            None
        };
        let Some(v) = value else { continue };
        named = true;
        if v.contains("://") {
            out.push(url_basename(v));
        } else if !(v.is_empty() || v == "-" || v.starts_with("/dev/")) {
            out.push(v.to_string());
        }
    }
    if !named && e.first().is_some_and(|h| basename(h) == "wget") {
        for url in e.iter().filter(|w| w.contains("://")) {
            let name = url_basename(url);
            out.push(prefix.map_or(name.clone(), |p| format!("{}/{name}", p.trim_end_matches('/'))));
        }
    }
    out
}

fn names_a_written_file<'f>(word: &str, written: &'f [String]) -> Option<&'f str> {
    written
        .iter()
        .find(|f| {
            let f = f.trim_start_matches("./");
            word == f || word.strip_prefix("./") == Some(f)
        })
        .map(String::as_str)
}

fn grants_execute(mode: &str) -> bool {
    if (3..=4).contains(&mode.len()) && mode.chars().all(|d| ('0'..='7').contains(&d)) {
        return mode.bytes().rev().take(3).any(|d| (d - b'0') & 1 == 1);
    }
    !mode.starts_with('-')
        && mode.split(',').any(|clause| {
            clause.find(['+', '=']).and_then(|k| clause.get(k + 1..)).is_some_and(|p| p.contains('x'))
        })
}

fn runs_what_it_downloaded(c: &str) -> Option<String> {
    let mut written: Vec<String> = Vec::new();
    let mut fetch_in_pipeline = false;
    for (piped, words) in simple_commands(c) {
        fetch_in_pipeline &= piped;
        let e = effective(&words);
        let Some(&head) = e.first() else { continue };
        let args = e.get(1..).unwrap_or_default();
        if let Some(f) = names_a_written_file(head, &written) {
            return Some(format!("fetches from the network into {f} and then runs it"));
        }
        if runs_its_argument(head) {
            if let Some(f) = args.iter().find(|a| !a.starts_with('-')).and_then(|a| names_a_written_file(a, &written)) {
                return Some(format!("fetches from the network into {f} and then runs it"));
            }
        }
        if basename(head) == "chmod" && args.iter().any(|a| grants_execute(a)) {
            if let Some(f) = args.iter().find_map(|a| names_a_written_file(a, &written)) {
                return Some(format!("fetches from the network into {f} and makes it executable"));
            }
        }

        let fetch = words.iter().position(|w| !w.contains("://") && FETCH_TOOLS.contains(&basename(w)));
        if let Some(at) = fetch {
            written.extend(fetch_outputs(words.get(at..).unwrap_or_default()));
            fetch_in_pipeline = true;
        } else if fetch_in_pipeline {

            written.extend(redirect_targets(e).into_iter().map(str::to_string));
            if basename(head) == "tee" {
                written.extend(args.iter().filter(|a| !a.starts_with('-')).map(|a| a.to_string()));
            }
        }
    }
    None
}

pub fn suspicion(command: &str) -> Option<String> {
    suspicion_at(&command.to_lowercase(), command, 0)
}

const MAX_EVAL_DEPTH: usize = 8;

const TOO_DEEP: &str = "nests eval on a command substitution more than eight levels deep, which no shell init \
                        does; what it evaluates past that depth was not read";

const _: () = assert!(MAX_EVAL_DEPTH == 8);

fn suspicion_at(c: &str, command: &str, depth: usize) -> Option<String> {

    let fetchers = ["curl ", "wget ", "fetch ", "ftp "];
    if fetchers.iter().any(|f| c.contains(f)) {
        if piped_into_a_program(c, |s| fetchers.iter().any(|f| s.contains(f))) {
            return Some("fetches from the network and pipes the result to a shell".into());
        }
        if SHELLS.iter().any(|t| tool_flag(c, t, "-c"))
            && substitution_bodies(c).iter().any(|b| fetchers.iter().any(|f| b.contains(f)))
        {
            return Some("fetches from the network and hands the result to a shell to run".into());
        }
        if download_substituted_into_a_runner(c, &fetchers) {
            return Some("fetches from the network and hands the result to a shell to run".into());
        }
        if let Some(why) = runs_what_it_downloaded(c) {
            return Some(why);
        }
    }

    if c.contains("base64 -d") || c.contains("base64 --decode") || c.contains("openssl enc -d") {
        return Some("decodes an encoded payload before running it".into());
    }

    if c.contains("eval") {
        let bodies = substitution_bodies(c);
        if depth >= MAX_EVAL_DEPTH && !bodies.is_empty() {
            return Some(TOO_DEEP.into());
        }
        for body in bodies {
            if let Some(why) = suspicion_at(&body, &body, depth + 1) {

                if why == TOO_DEEP {
                    return Some(why);
                }
                return Some(format!("evaluates a dynamically-built string that {why}"));
            }
        }
    }

    if c.contains("/dev/tcp/") || c.contains("/dev/udp/") {
        return Some("opens a raw network connection through bash's /dev/tcp".into());
    }

    if NETCATS.iter().any(|t| invokes_tool(c, t))
        && (has_flag(c, "-e")
            || hands_connection_to_a_command(c)
            || c.contains("mkfifo")
            || netcat_shell_flag(command)
            || piped_into_a_program(c, |s| NETCATS.iter().any(|t| invokes_tool(s, t))))
    {
        return Some("wires a network connection to a command — a shell handler shape".into());
    }
    if SHELLS.iter().any(|t| tool_flag(c, t, "-i")) {
        return Some("starts an interactive shell from a non-interactive context".into());
    }

    let primed = loads_code_from_environment(c);
    for (name, flag) in [("python", "-c"), ("perl", "-e"), ("ruby", "-e"), ("php", "-r")] {
        if tool_flag_versioned(c, name, flag) {
            let programs = inline_programs(c, name, flag);
            if primed
                || programs.is_empty()
                || !programs.iter().all(|p| p.is_some_and(only_sleeps))
            {
                return Some(format!("runs inline {name} code rather than a program on disk"));
            }
        }
    }

    if let Some(dir) = arg_under_world_writable(c) {
        return Some(format!("runs something from {dir}, which any local user can write"));
    }

    if hidden_under_system_dir(c) {
        return Some(
            "references a hidden path under a system directory — packaged software does not hide its files there"
                .into(),
        );
    }

    None
}

pub(super) fn substitution_bodies(c: &str) -> Vec<String> {
    let b = c.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {

        if b.get(i) == Some(&b'$') && b.get(i + 1) == Some(&b'(') {
            let start = i + 2;
            let mut depth = 1usize;
            let mut j = start;
            while j < b.len() && depth > 0 {
                match b.get(j) {
                    Some(&b'(') => depth += 1,
                    Some(&b')') => depth -= 1,
                    _ => {}
                }
                j += 1;
            }
            let end = if depth == 0 { j.saturating_sub(1) } else { b.len() };
            out.push(c.get(start..end).unwrap_or_default().to_string());
            i = end;
        } else if b.get(i) == Some(&b'`') {
            let start = i + 1;
            let end = c
                .get(start..)
                .and_then(|rest| rest.find('`'))
                .map_or(b.len(), |k| start + k);
            out.push(c.get(start..end).unwrap_or_default().to_string());
            i = end + 1;
        } else {
            i += 1;
        }
    }
    out
}

pub fn tmpfiles_suspicion(rule_file: &str, line: &str) -> Option<String> {
    let t = line.trim();
    if t.is_empty() || t.starts_with('#') {
        return None;
    }
    let mut f = t.split_whitespace();
    let kind = f.next()?;
    let target = f.next()?;

    let base = kind.trim_end_matches(['!', '+', '=', '-', '~', '^']);
    if !matches!(base, "C" | "L" | "w" | "f" | "F") {
        return None;
    }

    let source = f.nth(4);

    if let Some(src) = source {
        if let Some(dir) = WORLD_WRITABLE.iter().find(|d| src.starts_with(*d)) {
            return Some(format!(
                "copies from {src} on every boot, and {dir} is writable by any local user"
            ));
        }
    }

    let vendor_owned = rule_file.starts_with("/usr/lib/") || rule_file.starts_with("/lib/");
    if !vendor_owned && is_system_path(target) {
        return Some(format!(
            "a rule outside the package-owned directories places content at {target} on \
             every boot, so anything removed there returns at the next start"
        ));
    }
    None
}
