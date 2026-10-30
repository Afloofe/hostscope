#![allow(dead_code)]

#[cfg(target_os = "linux")]
use crate::render::h;
#[cfg(target_os = "linux")]
use crate::{EXIT_DRYRUN, EXIT_ENFORCER, EXIT_FAILED, EXIT_NOT_BUILT, EXIT_OK, EXIT_POLICY, EXIT_USAGE};

pub(crate) fn json_str_field(obj: &str, key: &str) -> Option<String> {
    let pat = format!("\"{key}\"");
    let i = obj.find(&pat)? + pat.len();
    let after_colon = obj[i..].find(':').map(|c| &obj[i + c + 1..])?;
    let q1 = after_colon.find('"')? + 1;
    let q2 = after_colon[q1..].find('"')?;
    Some(after_colon[q1..q1 + q2].to_string())
}

pub(crate) fn down_projects(ls_json: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for obj in ls_json.split('}') {
        let (Some(name), Some(status)) = (json_str_field(obj, "Name"), json_str_field(obj, "Status")) else {
            continue;
        };
        if status.starts_with("running") {
            continue;
        }

        let config = json_str_field(obj, "ConfigFiles").unwrap_or_default();
        let first = config.split(',').next().unwrap_or("").trim().to_string();
        out.push((name, first));
    }
    out
}

pub(crate) fn project_names(ls_json: &str) -> Vec<String> {
    ls_json
        .split('}')
        .filter(|obj| json_str_field(obj, "Status").is_some())
        .filter_map(|obj| json_str_field(obj, "Name"))
        .collect()
}

pub(crate) fn is_project_name(name: &str) -> bool {
    let mut cs = name.chars();
    cs.next().is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        && cs.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_')
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Named {

    File(String),

    Project(String),
}

pub(crate) fn named(operands: &[&str]) -> Result<Vec<Named>, String> {
    let mut out: Vec<Named> = Vec::new();
    for o in operands {
        let n = if o.contains('/') || o.ends_with(".yml") || o.ends_with(".yaml") {
            Named::File((*o).to_string())
        } else if is_project_name(o) {
            Named::Project((*o).to_string())
        } else {
            return Err((*o).to_string());
        };
        if !out.contains(&n) {
            out.push(n);
        }
    }
    Ok(out)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Step {

    Up {

        name: String,

        file: String,
    },

    Recreate {

        file: String,
    },

    Running {

        name: String,
    },

    Refused {

        what: String,

        why: String,
    },
}

pub(crate) fn plan(named: &[Named], ls_json: &str, is_file: impl Fn(&str) -> bool) -> Vec<Step> {
    let down = down_projects(ls_json);
    let known = project_names(ls_json);
    named
        .iter()
        .map(|n| match n {
            Named::File(f) if is_file(f) => Step::Recreate { file: f.clone() },
            Named::File(f) => Step::Refused { what: f.clone(), why: "it is not a compose file on this host".into() },
            Named::Project(p) => match down.iter().find(|(name, _)| name == p) {
                Some((_, file)) if file.starts_with('/') && is_file(file) => {
                    Step::Up { name: p.clone(), file: file.clone() }
                }
                Some((_, file)) if file.is_empty() => Step::Refused {
                    what: p.clone(),
                    why: "it has no compose file on record; name its compose file instead".into(),
                },
                Some((_, file)) => Step::Refused {
                    what: p.clone(),
                    why: format!("its compose file on record, {file}, is not an absolute path to a file on this host"),
                },
                None if known.contains(p) => Step::Running { name: p.clone() },
                None => Step::Refused {
                    what: p.clone(),
                    why: "the Docker daemon knows no project by that name — one `compose down` removed is \
                          gone from `compose ls`, so name its compose file instead"
                        .into(),
                },
            },
        })
        .collect()
}

pub(crate) fn down_hint(name: &str, ls_json: &str, is_file: impl Fn(&str) -> bool) -> String {
    if !is_project_name(name) {
        return format!(
            "not by name: `{name}` is not a name compose gives a project, so name its compose file instead"
        );
    }
    match plan(&[Named::Project(name.to_string())], ls_json, is_file).first() {
        Some(Step::Refused { why, .. }) => format!("not by name: {why}"),
        _ => format!("bring it up: mahoraga services --compose-up {name} --arm"),
    }
}

#[cfg(target_os = "linux")]
fn compose_argv() -> Option<Vec<String>> {
    let probe = |argv: &[&str]| {
        let mut c = std::process::Command::new(argv[0]);
        c.args(&argv[1..]).arg("version");
        c.output().map(|o| o.status.success()).unwrap_or(false)
    };
    if probe(&["docker", "compose"]) {
        Some(vec!["docker".into(), "compose".into()])
    } else if probe(&["docker-compose"]) {
        Some(vec!["docker-compose".into()])
    } else {
        None
    }
}

#[cfg(target_os = "linux")]
fn run(argv: &[String], extra: &[&str]) -> std::io::Result<std::process::Output> {
    let mut c = std::process::Command::new(&argv[0]);
    c.args(&argv[1..]).args(extra);
    c.output()
}

#[cfg(target_os = "linux")]
fn ls_json(argv: &[String]) -> Result<String, u8> {
    match run(argv, &["ls", "--all", "--format", "json"]) {
        Ok(o) if o.status.success() => Ok(String::from_utf8_lossy(&o.stdout).into_owned()),
        Ok(o) => {
            eprintln!("hemostat services --compose-up: `compose ls` failed: {}", h(String::from_utf8_lossy(&o.stderr).trim()));
            Err(EXIT_FAILED)
        }
        Err(e) => {
            eprintln!("hemostat services --compose-up: could not run compose: {e}");
            Err(EXIT_FAILED)
        }
    }
}

#[cfg(target_os = "linux")]
fn on_host(path: &str) -> bool {
    std::fs::metadata(path).is_ok_and(|m| m.is_file())
}

#[cfg(target_os = "linux")]
fn print_down(ls: &str) -> bool {
    let down = down_projects(ls);
    if down.is_empty() {
        return false;
    }
    println!("compose — projects that are not fully running:");
    for (name, file) in &down {
        println!("  DOWN `{}`  —  {}", h(name), if file.is_empty() { "no compose file on record".to_string() } else { h(file) });
        println!("       {}", h(&down_hint(name, ls, on_host)));
    }
    true
}

#[cfg(target_os = "linux")]
pub(crate) fn compose_up(args: &[String], _json: bool) -> u8 {
    if let Err(msg) = crate::remedy::require_built(hemostat_buildinfo::ActionClass::ServiceStart) {
        eprintln!("hemostat services: {msg}");
        return EXIT_NOT_BUILT;
    }
    let armed = args.iter().any(|a| a == "--arm");

    let operands = crate::operands(args, &["--service", "--store", "--start", "--every"]);
    let named = match named(&operands) {
        Ok(n) => n,
        Err(bad) => {
            eprintln!(
                "hemostat services --compose-up: `{}` is neither a compose file (a path) nor a compose \
                 project name (lowercase letters, digits, - and _)",
                h(&bad)
            );
            return EXIT_USAGE;
        }
    };
    let Some(argv) = compose_argv() else {
        eprintln!(
            "hemostat services --compose-up: no Docker Compose CLI found (neither `docker compose` \
             nor `docker-compose`). The daemon restart in `services --restore` still covers \
             restart-policy containers."
        );
        return EXIT_FAILED;
    };
    let cli = argv.join(" ");

    if named.is_empty() {
        let ls = match ls_json(&argv) {
            Ok(t) => t,
            Err(code) => return code,
        };
        if !print_down(&ls) {
            println!("compose — every project is up (nothing to bring up).");
            return EXIT_OK;
        }
        eprintln!(
            "\nhemostat services --compose-up: nothing is brought up unnamed, so nothing was changed. \
             Name each project to bring up, as above (several can be named in one run); for one \
             `compose down` removed, which is gone from this list, name its compose file: \
             `mahoraga services --compose-up /path/to/compose.yaml --arm`."
        );
        return EXIT_USAGE;
    }

    let ls = if named.iter().any(|n| matches!(n, Named::Project(_))) {
        match ls_json(&argv) {
            Ok(t) => t,
            Err(code) => return code,
        }
    } else {
        String::new()
    };
    let steps = plan(&named, &ls, on_host);
    let mut refused = false;
    for s in &steps {
        if let Step::Refused { what, why } = s {
            refused = true;
            eprintln!("hemostat services --compose-up: refused `{}`: {}", h(what), h(why));
        }
    }
    if refused {
        eprintln!("  Nothing was brought up: a run acts on all of what was named, or on none of it.");

        print_down(&ls);
        return EXIT_POLICY;
    }

    let mut acts: Vec<(Vec<String>, String, String, String)> = Vec::new();
    for s in &steps {
        match s {
            Step::Up { name, file } => acts.push((
                ["-p", name, "-f", file, "up", "-d"].iter().map(|a| (*a).to_string()).collect(),
                format!("compose project `{}`", h(name)),
                format!("{cli} -p {} -f \"{}\" up -d", h(name), h(file)),
                format!("{cli} -p {} -f \"{}\" down", h(name), h(file)),
            )),
            Step::Recreate { file } => acts.push((
                ["-f", file, "up", "-d"].iter().map(|a| (*a).to_string()).collect(),
                format!("the Docker Compose project at {}", h(file)),
                format!("{cli} -f \"{}\" up -d", h(file)),
                format!("{cli} -f \"{}\" down", h(file)),
            )),
            Step::Running { name } => println!("compose project `{}` is running already; nothing to do", h(name)),
            Step::Refused { .. } => {}
        }
    }
    if acts.is_empty() {
        return EXIT_OK;
    }

    let ticket = match crate::authz::armed_gate(
        "services",
        hemostat_buildinfo::ActionClass::ServiceStart,
        armed,
        acts.len(),
    ) {
        Ok(t) => t,
        Err(code) => return code,
    };
    if let Err(code) = crate::authz::spend_armed("services", armed, ticket) {
        return code;
    }

    if !armed {
        for (_, what, cmd, _) in &acts {
            println!("[plan] bring up {what}  —  {cmd}");
        }
        println!("\nNothing was changed. Add --arm to bring these up (reversible: `compose down`).");
        return EXIT_DRYRUN;
    }
    let (mut failed, mut unjournalled) = (0u32, 0u32);
    for (up, what, cmd, down) in &acts {
        let extra: Vec<&str> = up.iter().map(String::as_str).collect();
        match run(&argv, &extra) {
            Ok(o) if o.status.success() => {
                crate::actions::audit_fix(&format!("compose up: {what}; undo: {down}"));
                println!("brought up {what}");
                println!("  undo: {down}");

                let rec = hemostat_enforce_linux::UndoRecord {
                    did: format!("brought up {what} ({cmd})"),
                    undo: hemostat_enforce_linux::UndoKind::Irreversible {
                        note: format!("not replayed from the journal: to take it down again, run `{down}`"),
                    },
                    reversible: false,
                };
                if crate::actions::journal_or_fail(&rec) != EXIT_OK {
                    unjournalled += 1;
                }
            }
            Ok(o) => {
                failed += 1;
                eprintln!("hemostat services --compose-up: `up` failed for {what}: {}", h(String::from_utf8_lossy(&o.stderr).trim()));
            }
            Err(e) => {
                failed += 1;
                eprintln!("hemostat services --compose-up: could not run compose up for {what}: {e}");
            }
        }
    }
    if failed > 0 {
        EXIT_ENFORCER
    } else if unjournalled > 0 {
        EXIT_FAILED
    } else {
        EXIT_OK
    }
}
