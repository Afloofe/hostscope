pub(super) const WRITABLE: &[&str] = &[
    r"c:\windows\temp",
    r"c:\temp",
    r"c:\users\public",
    r"c:\programdata\",
    r"\appdata\local\temp",
    r"\appdata\roaming",
    r"\downloads\",
];

pub(super) const ADMIN_ONLY: &[&str] = &[r"c:\programdata\microsoft\windows defender\platform\"];

pub(super) const INTERPRETERS: &[&str] =
    &["powershell", "pwsh", "cmd.exe", "wscript", "cscript", "mshta", "rundll32", "regsvr32"];

pub(super) const LOUD_ARGS: &[&str] = &[
    "-enc",
    "-encodedcommand",
    "-e ",
    "frombase64string",
    "downloadstring",
    "downloadfile",
    "invoke-expression",
    "iex(",
    "iex ",
    "-windowstyle hidden",
    "-w hidden",
    "-nop",
    "-noprofile",
    "bypass",
    "hidden",
];

pub(super) fn lc(s: &str) -> String {
    s.to_lowercase()
}

pub fn under_writable(command: &str) -> Option<&'static str> {
    let c = ADMIN_ONLY.iter().fold(lc(command), |c, a| {
        let after = c.find(a).and_then(|i| c.get(i + a.len()..));
        if after.is_some_and(climbs_out) {
            c
        } else {
            c.replace(a, "")
        }
    });
    WRITABLE.iter().copied().find(|w| c.contains(w))
}

fn climbs_out(text: &str) -> bool {
    text.split(['\\', '/']).any(|seg| {
        let s = seg.trim_matches(|c: char| c == '"' || c == ' ');
        s.len() >= 2 && s.bytes().all(|b| b == b'.')
    })
}

pub fn names_interpreter(command: &str) -> Option<&'static str> {
    let c = lc(command);
    INTERPRETERS.iter().copied().find(|i| c.contains(i))
}

pub fn loud_arguments(command: &str) -> Vec<&'static str> {
    let c = lc(command);
    let mut hits: Vec<&'static str> = LOUD_ARGS.iter().copied().filter(|a| c.contains(a)).collect();

    hits.sort_by_key(|a| std::cmp::Reverse(a.len()));
    let mut kept: Vec<&'static str> = Vec::new();
    for a in hits {
        if !kept.iter().any(|k| k.contains(a)) {
            kept.push(a);
        }
    }

    kept.sort_by_key(|a| LOUD_ARGS.iter().position(|l| l == a).unwrap_or(usize::MAX));
    kept
}

pub(super) const WINLOGON_STOCK: &[(&str, &[&str])] = &[
    ("userinit", &["userinit.exe"]),
    ("shell", &["explorer.exe"]),
];

pub(super) const LSA_STOCK: &[(&str, &[&str])] = &[
    ("authentication packages", &["msv1_0"]),
    ("notification packages", &["scecli", "rassfm"]),
    (
        "security packages",
        &[
            "\"\"", "kerberos", "msv1_0", "negoexts", "schannel", "wdigest", "tspkg", "pku2u",
            "cloudap", "livessp",
        ],
    ),
];

pub(super) fn lsa_package_is_stock(list: &str, member: &str) -> Option<bool> {
    let (_, stock) = LSA_STOCK.iter().find(|(n, _)| list.eq_ignore_ascii_case(n))?;
    let m = member.trim().to_ascii_lowercase();
    let m = m.strip_suffix(".dll").unwrap_or(&m);
    Some(m.is_empty() || stock.contains(&m))
}

const SMSS_FLAGS: &[&str] = &["autocheck", "async", "debug"];

pub(super) fn boot_execute_is_stock(member: &str) -> bool {
    let mut tokens = member.split(|c: char| c <= ' ').filter(|t| !t.is_empty()).peekable();
    if tokens.peek().is_none() {
        return true;
    }
    tokens
        .find(|t| !SMSS_FLAGS.iter().any(|f| t.eq_ignore_ascii_case(f)))
        .is_some_and(|image| {
            image.eq_ignore_ascii_case("autochk") || image.eq_ignore_ascii_case("autochk.exe")
        })
}

pub(super) fn winlogon_is_stock(name: &str, command: &str) -> Option<bool> {
    let (_, stock) = WINLOGON_STOCK.iter().find(|(n, _)| name.eq_ignore_ascii_case(n))?;

    let parts: Vec<&str> = command.split(',').map(str::trim).filter(|p| !p.is_empty()).collect();
    if parts.len() != 1 {
        return Some(false);
    }
    let leaf = parts[0]
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or(parts[0])
        .to_lowercase();
    Some(stock.iter().any(|s| leaf == *s))
}
