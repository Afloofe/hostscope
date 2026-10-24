#![forbid(unsafe_code)]

use std::process::ExitCode;

use hemostat_buildinfo::{ActionClass, BuildManifest, Status};
use hemostat_modules as modules;

mod meta {
    include!(concat!(env!("OUT_DIR"), "/build_meta.rs"));
}

macro_rules! jprintln {
    ($($arg:tt)*) => {
        println!("{}", $crate::render::envelope(&format!($($arg)*)))
    };
}

mod crash;
mod render;

mod actions;
mod analysis;
mod authz;
mod kernel;
#[cfg(target_os = "linux")]
mod remediate_verb;
#[cfg(target_os = "linux")]
use crate::remediate_verb::undo_verb;
#[cfg(all(target_os = "linux", feature = "mod-enf-persistence"))]
use crate::remediate_verb::remediate;

#[cfg(all(target_os = "linux", feature = "mod-enf-persistence"))]
mod strip_verb;

#[cfg(all(target_os = "linux", feature = "mod-enf-persistence"))]
mod anchor_verb;

#[cfg(any(target_os = "linux", target_os = "windows"))]
mod trust_verb;
mod remedy;
mod sensors_win;
mod sentinel;
mod sweeps;
mod coverage;
mod views;

#[cfg(feature = "mod-tui")]
mod tui_verbs;

#[cfg(feature = "mod-detect-sigma")]
use crate::analysis::print_detect;
#[cfg(all(target_os = "linux", feature = "mod-correlation"))]
use crate::analysis::print_correlate;
#[cfg(all(target_os = "linux", feature = "mod-query"))]
use crate::analysis::print_query;
#[cfg(all(target_os = "linux", feature = "mod-scan-yara"))]
use crate::analysis::print_scan;
#[cfg(all(target_os = "linux", feature = "mod-sensor-audit"))]
use crate::analysis::print_audit;

#[cfg(all(target_os = "linux", feature = "mod-sensor-fanotify"))]
use crate::sweeps::print_fswatch;
#[cfg(all(feature = "mod-tui", not(target_os = "freebsd")))]
use crate::sweeps::print_posture;
#[cfg(target_os = "linux")]
use crate::sweeps::{
    print_accounts, print_ad, print_firewall, print_injected, print_inventory, print_overview,
    print_persistence, print_ps, print_suid, print_sysctl, print_watchdog, services_verb, watch,
};

#[cfg(all(target_os = "linux", feature = "mod-enf-persistence"))]
use crate::kernel::print_kmod;
#[cfg(target_os = "linux")]
use crate::kernel::{
    arm_selfprotect, print_bpfprog, print_crossview, print_ftrace_hooks, print_hooks,
    print_kernposture, print_kptrhooks, print_kwalk, print_rootkit, print_selfprotect,
    print_syscall_hooks, print_sysmap,
};

#[cfg(all(target_os = "linux", feature = "mod-acquire"))]
use crate::actions::print_acquire;
#[cfg(all(target_os = "linux", feature = "mod-deceive"))]
use crate::actions::print_deceive;
#[cfg(all(target_os = "linux", feature = "mod-sidecar"))]
use crate::actions::print_sidecar;
#[cfg(target_os = "linux")]
use crate::actions::{
    print_account, print_allowlist, print_exec_block, print_harden_boot, print_narrow,
    print_network, print_sshd, print_uninstall,
};

#[cfg(all(target_os = "windows", feature = "mod-sensor-evtlog"))]
use crate::sensors_win::print_evtlog;
#[cfg(all(target_os = "windows", feature = "mod-sensor-sysmon"))]
use crate::sensors_win::print_sysmon;
#[cfg(all(target_os = "windows", feature = "mod-sensor-usn"))]
use crate::sensors_win::print_usn;
#[cfg(target_os = "windows")]
use crate::sensors_win::{
    print_com, print_dll_hijack, print_etw, print_modules, print_signature, print_streams,
    print_win_accounts, print_win_overview, print_win_persistence, print_win_probe, print_wmi,
};

mod evidence;

mod fleet;

#[cfg(any(target_os = "freebsd", test))]
mod freebsd;

#[cfg(any(target_os = "freebsd", test, all(target_os = "linux", feature = "mod-collector")))]
mod freebsd_drift;

#[cfg(all(target_os = "linux", any(feature = "mod-collector", test)))]
mod rejudge;

#[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "windows", test))]
mod sealed;

#[cfg(any(target_os = "windows", test))]
mod win_drift;

#[cfg(all(feature = "mod-detect-sigma", any(target_os = "windows", test)))]
mod win_detect;

#[cfg(target_os = "linux")]
mod hostexport;

#[cfg(all(target_os = "linux", any(feature = "mod-collector", test)))]
mod collector;

#[cfg(all(any(target_os = "linux", target_os = "windows"), feature = "mod-remote"))]
mod push;

#[cfg(all(target_os = "linux", feature = "mod-collector"))]
mod wire;

#[cfg(all(target_os = "linux", feature = "mod-collector"))]
mod queue_verb;

#[cfg(any(target_os = "freebsd", test, all(target_os = "linux", feature = "mod-collector")))]
mod boxowned;

#[cfg(any(target_os = "freebsd", test))]
mod freebsd_fw;

#[cfg(any(target_os = "freebsd", test, all(target_os = "linux", feature = "mod-collector")))]
mod freebsd_sweeps;

#[cfg(any(target_os = "freebsd", test))]
mod freebsd_telemetry;

#[cfg(any(target_os = "freebsd", test))]
mod freebsd_block;

#[cfg(any(target_os = "freebsd", test))]
mod freebsd_contain;
#[cfg(target_os = "linux")]
mod resources;
#[cfg(target_os = "linux")]
mod vendor;

#[cfg(any(target_os = "linux", target_os = "freebsd"))]
mod vendor_manifest;
#[cfg(target_os = "linux")]
mod snapshot;
mod identity;

#[cfg(target_os = "linux")]
use crate::render::{h, hex32, jesc, rootkit_row};

#[cfg(target_os = "linux")]
use crate::authz::mint_ticket;

#[cfg(target_os = "linux")]
use crate::sentinel::{guard_pid, print_sentinel, register_sentinels, watch_agent};

#[cfg(all(target_os = "linux", feature = "mod-tui"))]
use crate::remedy::apply_remedy;

#[cfg(all(target_os = "windows", feature = "mod-tui"))]
use crate::remedy::apply_remedy;

#[cfg(all(target_os = "linux", feature = "mod-tui"))]
use crate::views::{console_model, posture_model};
#[cfg(all(target_os = "windows", feature = "mod-tui"))]
use crate::views::{console_model, posture_model};
#[cfg(all(target_os = "freebsd", feature = "mod-tui"))]
use crate::freebsd::{apply_remedy, console_model, posture_model};

use crate::evidence::{read_store, verify_store};
#[cfg(target_os = "linux")]
use crate::evidence::collect;
#[cfg(target_os = "linux")]
use crate::identity::gather_identity;
#[cfg(all(target_os = "linux", feature = "mod-remote"))]
use crate::identity::{parse_hex32, rand32};

#[cfg(target_os = "linux")]
use crate::render::rfc3339_now;

pub(crate) const MANIFEST: BuildManifest = BuildManifest {
    manifest_ver: 1,
    variant: meta::VARIANT,
    modules: modules::MODULES,
    toolchain: meta::TOOLCHAIN,
    source_rev: meta::SOURCE_REV,
    source_dirty: meta::SOURCE_DIRTY,
    source_date_epoch: meta::SOURCE_DATE_EPOCH,
};

pub(crate) const EXIT_OK: u8 = 0;
pub(crate) const EXIT_USAGE: u8 = 2;

pub(crate) const EXIT_FAILED: u8 = 1;

#[cfg(any(target_os = "linux", target_os = "freebsd"))]
pub(crate) const EXIT_AUTHZ: u8 = 3;

#[cfg(any(target_os = "linux", target_os = "freebsd"))]
pub(crate) const EXIT_POLICY: u8 = 4;

#[cfg(any(target_os = "linux", target_os = "freebsd"))]
pub(crate) const EXIT_DRYRUN: u8 = 5;

#[cfg(target_os = "linux")]
pub(crate) const EXIT_ENFORCER: u8 = 6;

pub(crate) const EXIT_PARTIAL: u8 = 7;

pub(crate) const EXIT_NOT_BUILT: u8 = 8;

#[cfg(target_os = "linux")]
pub(crate) fn repeated_flag_values(args: &[String], flag: &str) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    for (i, a) in args.iter().enumerate() {
        if a != flag {
            continue;
        }
        match args.get(i + 1) {
            Some(v) if !v.starts_with("--") => out.push(v.clone()),
            _ => return Err(flag.to_string()),
        }
    }
    Ok(out)
}

#[cfg(any(target_os = "linux", target_os = "windows"))]
const MAX_WINDOW_SECS: u64 = u32::MAX as u64;

#[cfg(any(target_os = "linux", target_os = "windows"))]
fn window_secs(args: &[String], flag: &str) -> Result<Option<u64>, String> {
    let Some(i) = args.iter().position(|a| a == flag) else {
        return Ok(None);
    };
    let Some(v) = args.get(i + 1).filter(|v| !v.starts_with("--")) else {
        return Err(format!("{flag} takes a number of seconds, and none was given"));
    };
    match v.parse::<u64>() {
        Ok(n) if n <= MAX_WINDOW_SECS => Ok(Some(n)),
        Ok(_) => Err(format!("{flag} takes at most {MAX_WINDOW_SECS} seconds, not {v}")),
        Err(_) => Err(format!("{flag} takes a whole number of seconds, not {v:?}")),
    }
}

#[cfg(all(feature = "mod-detect-sigma", target_os = "windows"))]
fn detect_window(args: &[String]) -> Result<Option<u64>, String> {
    window_secs(args, "--watch")
}

#[cfg(all(feature = "mod-detect-sigma", any(target_os = "linux", target_os = "freebsd", target_os = "macos")))]
fn detect_window(_args: &[String]) -> Result<Option<u64>, String> {
    Ok(None)
}

#[cfg(any(target_os = "windows", test))]
fn etw_window(args: &[String]) -> Result<Option<u64>, String> {
    let bare = args
        .iter()
        .position(|a| a == "--watch")
        .is_some_and(|i| args.get(i + 1).is_none_or(|v| v.starts_with("--")));
    if bare {
        Ok(Some(10))
    } else {
        window_secs(args, "--watch")
    }
}

#[cfg(target_os = "linux")]
type Narrowing = (Option<u32>, Option<String>);

#[cfg(target_os = "linux")]
fn narrowing_request(args: &[String]) -> Result<Option<Narrowing>, String> {
    let once = |flag: &str, what: &str| match repeated_flag_values(args, flag) {
        Err(_) => Err(format!("{flag} takes {what}, and none was given")),
        Ok(v) if v.len() > 1 => Err(format!("{flag} was given {} times; name one", v.len())),
        Ok(v) => Ok(v.into_iter().next()),
    };
    let pid = once("--block-pid", "a process id")?;
    let dest = once("--block-dest", "an address")?;
    if pid.is_none() && dest.is_none() {
        return Ok(None);
    }

    let pid = match pid {
        None => None,
        Some(v) => Some(
            v.parse::<u32>()
                .map_err(|_| format!("--block-pid takes a process id, not {v:?}"))?,
        ),
    };
    Ok(Some((pid, dest)))
}

fn flags_for(verb: &str) -> &'static [&'static str] {
    match verb {
        "remediate" => &[
            "--arm",
            "--protect",
            "--allow-listener",
            "--lines",
            "--strip-line",
            "--auth",
            "--operator-key",
            "--session-key-unknown",
            "--last-admin-key",
            "--anchors",
            "--remove-anchor",
        ],
        "network" => &[
            "--arm",
            "--confirm",
            "--revert",
            "--egress",
            "--block-pid",
            "--block-dest",
        ],
        "exec-block" => &["--arm", "--pid", "--lift"],
        "harden-boot" => &["--arm", "--set"],
        "fswatch" => &["--seconds", "--all"],
        "audit" => &[],

        "detect" => if cfg!(target_os = "windows") { &["--rules", "--watch"] } else { &["--rules"] },
        #[cfg(feature = "mod-collector")]
        "correlate" => &["--fw", "--fw-pin", "--host", "--host-pin", "--manifest", "--skew", "--offset"],
        #[cfg(not(feature = "mod-collector"))]
        "correlate" => &[],
        #[cfg(target_os = "linux")]
        "overview" => &["--export"],
        "query" => &["--tables"],
        "allowlist" => &["--check"],
        "uninstall" => &["--arm"],
        "acquire" => &["--arm", "--pid", "--into"],
        "deceive" => &["--arm", "--watch", "--remove", "--list"],
        "kmod" => &["--arm", "--unload"],
        "sidecar" => &["--arm", "--install", "--from", "--sha256"],

        "remote" => &["--beacon", "--console-key", "--listen", "--seconds"],
        "ship" => &["--to", "--collector-key", "--receipt-key", "--link-key", "--checkpoints", "--identity"],
        "collector" => &["--root", "--engagement", "--seal-key", "--spool", "--follow", "--seconds"],
        "enroll" => &["--root", "--engagement", "--label", "--host-id", "--digest", "--link-key"],
        "queue" => &["--root", "--engagement", "--as", "--reason", "--export", "--out", "--once", "--manifest", "--operator-key"],
        "evtlog" => &["--quick"],
        "usn" => &["--volume"],
        "sysmon" => &[],
        "account" => &[
            "--arm",
            "--end-sessions",
            "--purge-tickets",
            "--expire-password",
            "--drop-group",
        ],
        "services" => &["--service", "--baseline", "--store", "--start", "--arm"],

        "console" => if cfg!(target_os = "windows") { &["--once", "--rules"] } else { &["--once", "--every"] },
        "watchdog" => &["--watch"],
        "scan" => &["--rules"],
        "ticket" => &["--op", "--class", "--engagement", "--host", "--ttl", "--out", "--alias", "--cidr"],
        "policy" => &["--engagement", "--epoch", "--allow", "--scope", "--profile", "--bulk", "--ttl", "--out"],

        "vendor" => &["--manifest", "--meta"],

        #[cfg(target_os = "freebsd")]
        "probe" => &["--manifest", "--meta"],

        #[cfg(target_os = "freebsd")]
        "posture" => &["--manifest"],
        "snapshot" => &["--store", "--replace"],
        "drift" => &["--store"],

        #[cfg(target_os = "linux")]
        "trust" => &["--all", "--store"],
        #[cfg(target_os = "windows")]
        "trust" => &["--all"],
        #[cfg(target_os = "freebsd")]
        "trust" => &["--manifest", "--store"],

        "fw" => &[
            "--store", "--manifest", "--src", "--dst", "--limit", "--alias", "--tracker", "--protect",
            "--meta", "--dry-run", "--arm", "--deadline", "--manifest-pubkey",
        ],

        #[cfg(target_os = "freebsd")]
        "undo" => &["--manifest", "--meta"],

        #[cfg(target_os = "linux")]
        "undo" => &["--auth"],
        "manifest-sign" => &["--in", "--new-key", "--manifest"],

        #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
        "persistence" => &["--all"],

        #[cfg(target_os = "freebsd")]
        "persistence" => &["--manifest", "--store"],
        #[cfg(target_os = "freebsd")]
        "accounts" => &["--manifest", "--store", "--operator-key"],
        "selfprotect" => &["--arm"],
        "sentinel" => &["--guard", "--persist", "--register", "--watch"],
        "etw" => &["--watch"],
        "ad" => &[],
        "export" => &[],
        "streams" => &[],
        "dll-hijack" => &[],
        "modules" => &[],
        "wmi" => &[],
        "com" => &[],
        "signature" => &[],
        _ => &[],
    }
}

pub(crate) const NO_JSON_YET: &[&str] = &[
    "sysctl", "network", "posture", "console", "tui", "uninstall", "sidecar", "deceive",
    "acquire", "remote", "harden-boot", "exec-block", "account", "ticket", "policy", "manifest-sign",
];

fn check_flags(verb: &str, args: &[String]) -> Result<(), String> {
    let allowed = flags_for(verb);
    for a in args.iter().filter(|a| a.starts_with("--")) {
        if a == "--json" || allowed.contains(&a.as_str()) {
            continue;
        }

        let mut takes: Vec<&str> = allowed.to_vec();
        takes.push("--json");
        return Err(format!(
            "hemostat {verb}: unknown flag {a}\n  {verb} takes: {}",
            takes.join(" ")
        ));
    }
    Ok(())
}

fn main() -> ExitCode {

    #[cfg(target_os = "linux")]
    hemostat_sensor_linux::sigpipe::restore_default();

    #[cfg(target_os = "windows")]
    let _ = hemostat_sensor_win::console::use_utf8_output();

    let args: Vec<String> = std::env::args().skip(1).collect();

    crash::install(
        args.iter()
            .find(|a| !a.starts_with("--"))
            .cloned()
            .unwrap_or_else(|| "(no verb)".to_string()),
        MANIFEST.variant,
        MANIFEST.source_rev,
        MANIFEST.source_dirty,
    );

    let json = args.iter().any(|a| a == "--json");
    let positional: Vec<&str> = args
        .iter()
        .map(String::as_str)
        .filter(|a| !a.starts_with("--"))
        .collect();

    if is_help_request(&args, &positional) {
        println!("{}", usage_text());
        return ExitCode::from(EXIT_OK);
    }

    if let Some(verb) = positional.first().copied() {
        if let Err(msg) = check_flags(verb, &args) {
            eprintln!("{msg}");
            return ExitCode::from(EXIT_USAGE);
        }

        let has_json = cfg!(target_os = "freebsd") && verb == "posture";
        if json && NO_JSON_YET.contains(&verb) && !has_json {
            eprintln!(
                "hemostat {verb}: --json is not implemented for this verb yet — printing the \
                 human rendering. Do not parse it."
            );
        }
    }

    dispatch(&positional, &args, json)
}

fn is_help_request(args: &[String], positional: &[&str]) -> bool {
    args.iter().any(|a| a == "--help" || a == "-h") || positional.first() == Some(&"help")
}

fn dispatch(positional: &[&str], args: &[String], json: bool) -> ExitCode {
    let verb = positional.first().copied();
    render::set_kind(verb.unwrap_or("hemostat"));

    #[cfg(all(target_os = "linux", feature = "mod-collector"))]
    if verb == Some("correlate") {
        return ExitCode::from(collector::run(args, json));
    }

    if verb == Some("remote") && args.iter().any(|a| a == "--listen") {
        eprintln!("{REMOTE_LISTEN_REMOVED}");
        return ExitCode::from(EXIT_USAGE);
    }
    if let Some(code) = dispatch_portable(verb, positional, args, json) {
        return code;
    }
    #[cfg(target_os = "windows")]
    if let Some(code) = dispatch_windows(verb, args, json) {
        return code;
    }
    #[cfg(target_os = "linux")]
    if let Some(code) = dispatch_linux(verb, positional, args, json) {
        return code;
    }
    #[cfg(target_os = "freebsd")]
    if let Some(code) = dispatch_freebsd(verb, args, json) {
        return code;
    }

    match verb {
        Some(unknown) => {
            eprintln!("hemostat: unknown verb {unknown:?}");
            usage();
            ExitCode::from(EXIT_USAGE)
        }

        None => {
            #[cfg(feature = "mod-tui")]
            {
                use std::io::IsTerminal as _;
                if args.is_empty() && std::io::stdout().is_terminal() && std::io::stdin().is_terminal() {
                    eprintln!("hemostat: sweeping this host…");
                    let verbs = crate::tui_verbs::verbs(crate::tui_verbs::this_platform());
                    return match hemostat_tui::run_console(live_console_model(), live_console_model, apply_remedy, verbs) {
                        Ok(()) => ExitCode::from(EXIT_OK),
                        Err(e) => {
                            eprintln!("hemostat: terminal error: {e}");
                            ExitCode::from(EXIT_USAGE)
                        }
                    };
                }
            }
            usage();
            ExitCode::from(EXIT_USAGE)
        }
    }
}

#[cfg(feature = "mod-tui")]
fn live_console_model() -> hemostat_tui::ConsoleModel {
    let m = console_model();
    #[cfg(target_os = "linux")]
    let m = crate::evidence::console_sealed(m);
    m
}

fn dispatch_portable(verb: Option<&str>, positional: &[&str], args: &[String], json: bool) -> Option<ExitCode> {
    match verb {
        Some("build-info") => Some({
            print_build_info(json);
            ExitCode::from(EXIT_OK)
        }),
        #[cfg(feature = "mod-tui")]
        Some("tui") => Some({

            match hemostat_tui::run(posture_model(), posture_model, crate::tui_verbs::verbs(crate::tui_verbs::this_platform())) {
                Ok(()) => ExitCode::from(EXIT_OK),
                Err(e) => {
                    eprintln!("hemostat: terminal error: {e}");
                    ExitCode::from(EXIT_USAGE)
                }
            }
        }),
        #[cfg(feature = "mod-tui")]
        Some("console") => Some({

            #[cfg(all(target_os = "windows", feature = "mod-detect-sigma"))]
            crate::win_detect::set_console_rules(
                args.iter().position(|a| a == "--rules").and_then(|i| args.get(i + 1)).cloned(),
            );
            if args.iter().any(|a| a == "--once") {
                let m = console_model();
                print!("{}", hemostat_tui::to_text_console(&m, 100, once_height(&m)));

                if !m.findings.is_empty() {
                    for g in &m.gaps {
                        println!("  {}: {}", render::h(&g.source), render::h(&g.reason));
                    }
                }

                ExitCode::from(if m.gaps.is_empty() { EXIT_OK } else { EXIT_PARTIAL })
            } else {

                #[cfg(all(target_os = "windows", feature = "mod-detect-sigma"))]
                let ran = {
                    crate::win_detect::console_live_start();
                    hemostat_tui::run_console_live(
                        console_model(),
                        console_model,
                        apply_remedy,
                        crate::win_detect::console_live_tick,
                        crate::tui_verbs::verbs(crate::tui_verbs::this_platform()),
                    )
                };
                #[cfg(not(all(target_os = "windows", feature = "mod-detect-sigma")))]
                let ran = {

                    let every = match args.iter().position(|a| a == "--every") {
                        None => None,
                        Some(i) => match args.get(i + 1).filter(|v| !v.starts_with("--")).and_then(|v| v.parse::<u64>().ok()) {
                            Some(n) => Some(n),
                            None => {
                                eprintln!("hemostat console: --every takes a whole number of seconds");
                                return Some(ExitCode::from(EXIT_USAGE));
                            }
                        },
                    };
                    let verbs = crate::tui_verbs::verbs(crate::tui_verbs::this_platform());
                    match every {
                        Some(secs) => hemostat_tui::run_console_every(
                            live_console_model(),
                            live_console_model,
                            console_model,
                            apply_remedy,
                            std::time::Duration::from_secs(secs.max(5)),
                            verbs,
                        ),
                        None => hemostat_tui::run_console(live_console_model(), live_console_model, apply_remedy, verbs),
                    }
                };
                match ran {
                    Ok(()) => ExitCode::from(EXIT_OK),
                    Err(e) => {
                        eprintln!("hemostat: terminal error: {e}");
                        ExitCode::from(EXIT_USAGE)
                    }
                }
            }
        }),

        #[cfg(all(feature = "mod-tui", not(target_os = "freebsd")))]
        Some("posture") => Some({
            print_posture();
            ExitCode::from(EXIT_OK)
        }),
        #[cfg(not(all(target_os = "linux", feature = "mod-remote")))]
        Some("remote") => Some({
            let (why, code) = remote_unavailable(cfg!(feature = "mod-remote"));
            eprintln!("{why}");
            ExitCode::from(code)
        }),
        #[cfg(feature = "mod-detect-sigma")]
        Some("detect") => Some({
            let rules = args
                .iter()
                .position(|a| a == "--rules")
                .and_then(|i| args.get(i + 1))
                .map(String::as_str);
            match detect_window(args) {
                Ok(watch) => ExitCode::from(print_detect(json, rules, watch)),
                Err(msg) => {
                    eprintln!("hemostat detect: {msg}");
                    ExitCode::from(EXIT_USAGE)
                }
            }
        }),
        #[cfg(not(feature = "mod-detect-sigma"))]
        Some("detect") => Some({
            eprintln!(
                "{}",
                modules::module_refusal(hemostat_buildinfo::ModuleId::DetectSigma, MANIFEST.variant)
            );
            ExitCode::from(EXIT_NOT_BUILT)
        }),

        Some("verify") => Some(ExitCode::from(verify_store(positional, json))),

        Some("read") => Some(ExitCode::from(read_store(positional, json))),

        Some("ship") => Some(ExitCode::from(crate::fleet::ship(args, json))),

        #[cfg(all(target_os = "linux", feature = "mod-collector"))]
        Some("collector") => Some(ExitCode::from(crate::fleet::collector(args, json))),
        #[cfg(all(target_os = "linux", feature = "mod-collector"))]
        Some("queue") => Some(ExitCode::from(crate::queue_verb::queue(args, json))),
        #[cfg(not(all(target_os = "linux", feature = "mod-collector")))]
        Some("queue") => Some({
            let (why, code) = if cfg!(feature = "mod-collector") {
                (
                    format!("hemostat queue: the collector is in this image (variant {}), and it runs on Linux only", MANIFEST.variant),
                    EXIT_USAGE,
                )
            } else {
                (modules::module_refusal(hemostat_buildinfo::ModuleId::Collector, MANIFEST.variant), EXIT_NOT_BUILT)
            };
            eprintln!("{why}");
            ExitCode::from(code)
        }),
        #[cfg(not(all(target_os = "linux", feature = "mod-collector")))]
        Some("collector") => Some({
            let (why, code) = if cfg!(feature = "mod-collector") {
                (
                    format!(
                        "hemostat collector: the collector is in this image (variant {}), and it runs on \
                         Linux only",
                        MANIFEST.variant
                    ),
                    EXIT_USAGE,
                )
            } else {
                (
                    modules::module_refusal(hemostat_buildinfo::ModuleId::Collector, MANIFEST.variant),
                    EXIT_NOT_BUILT,
                )
            };
            eprintln!("{why}");
            ExitCode::from(code)
        }),

        #[cfg(all(target_os = "linux", feature = "mod-collector"))]
        Some("enroll") => Some(ExitCode::from(crate::fleet::enroll(args, json))),
        #[cfg(not(all(target_os = "linux", feature = "mod-collector")))]
        Some("enroll") => Some({
            let (why, code) = if cfg!(feature = "mod-collector") {
                (format!("hemostat enroll: the collector runs on Linux only (variant {})", MANIFEST.variant), EXIT_USAGE)
            } else {
                (
                    modules::module_refusal(hemostat_buildinfo::ModuleId::Collector, MANIFEST.variant),
                    EXIT_NOT_BUILT,
                )
            };
            eprintln!("{why}");
            ExitCode::from(code)
        }),
        _ => None,
    }
}

#[cfg(feature = "mod-tui")]
fn once_height(m: &hemostat_tui::ConsoleModel) -> u16 {
    let rows = m.findings.len().max(m.gaps.len() + 2);
    u16::try_from(rows.saturating_add(14)).unwrap_or(u16::MAX).max(44)
}

const REMOTE_LISTEN_REMOVED: &str = "hemostat remote: --listen was removed by RFC-003 (owner \
     decision 1, 2026-10-13). An agent never listens: no port is opened on the host, and no \
     message from a console is carried to it, let alone acted on. The agent dials out only — \
     `remote --beacon HOST:PORT` sends the heartbeat whose absence a console alarms on — and \
     a response is a verb a responder runs at the host, with a ticket.";

#[cfg(any(test, not(all(target_os = "linux", feature = "mod-remote"))))]
fn remote_unavailable(module_built: bool) -> (String, u8) {
    if module_built {
        (
            format!(
                "hemostat remote: the console link is in this image (variant {}), but the \
                 agent's half of `remote` — its identity and its entropy — is Linux-only in \
                 this tree. No build runs it on this platform.",
                MANIFEST.variant
            ),
            EXIT_USAGE,
        )
    } else {
        (
            modules::module_refusal(hemostat_buildinfo::ModuleId::Remote, MANIFEST.variant),
            EXIT_NOT_BUILT,
        )
    }
}

#[cfg(target_os = "freebsd")]
fn dispatch_freebsd(verb: Option<&str>, args: &[String], json: bool) -> Option<ExitCode> {
    match verb {
        Some("probe") => Some(ExitCode::from(crate::freebsd::print_probe(args, json))),
        Some("snapshot") => Some(ExitCode::from(crate::freebsd_drift::take_snapshot(args, json))),
        Some("drift") => Some(ExitCode::from(crate::freebsd_drift::drift(args, json))),
        Some("posture") => Some(ExitCode::from(crate::freebsd::print_posture_sweep(args, json))),
        Some("vendor") => Some(ExitCode::from(crate::freebsd::print_vendor(args, json))),
        Some("fw") => Some(ExitCode::from(crate::freebsd_fw::fw(args, json))),
        Some("accounts") => Some(ExitCode::from(crate::freebsd_sweeps::accounts(args, json))),
        Some("persistence") => Some(ExitCode::from(crate::freebsd_sweeps::persistence(args, json))),
        Some("trust") => Some(ExitCode::from(crate::freebsd_sweeps::trust(args, json))),

        Some("undo") => Some(ExitCode::from(crate::freebsd_contain::undo(args, json))),
        _ => None,
    }
}

#[cfg(target_os = "windows")]
fn dispatch_windows(verb: Option<&str>, args: &[String], json: bool) -> Option<ExitCode> {
    match verb {

        Some("probe") => Some(ExitCode::from(print_win_probe(json))),

        Some("persistence") => Some(ExitCode::from(print_win_persistence(json))),

        Some("etw") => Some(match etw_window(args) {
            Ok(secs) => ExitCode::from(print_etw(json, secs)),
            Err(msg) => {
                eprintln!("hemostat etw: {msg}");
                ExitCode::from(EXIT_USAGE)
            }
        }),
        Some("streams") => Some({
            let extra: Vec<String> = operands(args, &[]).into_iter().map(String::from).collect();
            ExitCode::from(print_streams(json, &extra))
        }),
        Some("dll-hijack") => Some(ExitCode::from(print_dll_hijack(json))),
        Some("modules") => Some(ExitCode::from(print_modules(json))),
        #[cfg(feature = "mod-sensor-usn")]
        Some("usn") => Some({
            let vol = args
                .iter()
                .position(|a| a == "--volume")
                .and_then(|i| args.get(i + 1))
                .map_or("C:", String::as_str);
            ExitCode::from(print_usn(json, vol))
        }),
        #[cfg(not(feature = "mod-sensor-usn"))]
        Some("usn") => Some({
            eprintln!(
                "{}",
                modules::module_refusal(hemostat_buildinfo::ModuleId::SensorUsn, MANIFEST.variant)
            );
            ExitCode::from(EXIT_NOT_BUILT)
        }),
        #[cfg(feature = "mod-sensor-sysmon")]
        Some("sysmon") => Some(ExitCode::from(print_sysmon(json))),
        #[cfg(not(feature = "mod-sensor-sysmon"))]
        Some("sysmon") => Some({
            eprintln!(
                "{}",
                modules::module_refusal(
                    hemostat_buildinfo::ModuleId::SensorSysmon,
                    MANIFEST.variant
                )
            );
            ExitCode::from(EXIT_NOT_BUILT)
        }),
        #[cfg(feature = "mod-sensor-evtlog")]
        Some("evtlog") => Some({
            ExitCode::from(print_evtlog(json, !args.iter().any(|a| a == "--quick")))
        }),
        #[cfg(not(feature = "mod-sensor-evtlog"))]
        Some("evtlog") => Some({
            eprintln!(
                "{}",
                modules::module_refusal(
                    hemostat_buildinfo::ModuleId::SensorEvtlog,
                    MANIFEST.variant
                )
            );
            ExitCode::from(EXIT_NOT_BUILT)
        }),
        Some("wmi") => Some(ExitCode::from(print_wmi(json))),
        Some("com") => Some(ExitCode::from(print_com(json))),
        Some("signature") => Some({
            let paths: Vec<String> = operands(args, &[]).into_iter().map(String::from).collect();
            ExitCode::from(print_signature(json, &paths))
        }),
        Some("accounts") => Some(ExitCode::from(print_win_accounts(json))),
        Some("overview") => Some(ExitCode::from(print_win_overview(json))),

        Some("snapshot") => Some(ExitCode::from(crate::win_drift::take_snapshot(args, json))),
        Some("drift") => Some(ExitCode::from(crate::win_drift::drift(args, json))),
        Some("trust") => Some(ExitCode::from(crate::trust_verb::print_win_trust(args, json))),
        _ => None,
    }
}

#[cfg(target_os = "linux")]
fn dispatch_linux(verb: Option<&str>, positional: &[&str], args: &[String], json: bool) -> Option<ExitCode> {
    match verb {
        Some("probe") => Some(ExitCode::from(print_probe(json))),
        Some("firewall") => Some(ExitCode::from(print_firewall(json))),
        Some("export") => Some({

            let fmt = positional.get(1).copied().unwrap_or("report");

            if json && fmt == "report" {
                eprintln!(
                    "hemostat export: --json does not choose a format, so this is the human \
                     `report`. Do not parse it — name `jsonl`, `stix` or `misp` for a document."
                );
            }
            ExitCode::from(print_export(fmt))
        }),
        Some("ad") => Some(ExitCode::from(print_ad(json))),
        Some("sentinel") => Some({

            let pid_after = |flag: &str| {
                args.iter()
                    .position(|a| a == flag)
                    .map(|i| args.get(i + 1).and_then(|p| p.parse::<u32>().ok()))
            };

            let spec = args
                .iter()
                .position(|a| a == "--watch")
                .map(|i| args.get(i + 1).and_then(|v| hemostat_lifecycle::watch::decode_argv(v)));
            match (spec, pid_after("--guard"), pid_after("--register")) {
                (Some(Some(argv)), _, _) => ExitCode::from(watch_agent(&argv, json)),
                (Some(None), _, _) => {
                    eprintln!(
                        "sentinel: --watch needs an agent spec from `--register`, not a pid"
                    );
                    ExitCode::from(EXIT_USAGE)
                }
                (_, Some(Some(pid)), _) => ExitCode::from(guard_pid(pid, json)),
                (_, _, Some(Some(pid))) => {
                    ExitCode::from(register_sentinels(pid, json, args.iter().any(|a| a == "--persist")))
                }
                (_, Some(None), _) | (_, _, Some(None)) => {
                    eprintln!("sentinel: --guard and --register each need a pid");
                    ExitCode::from(EXIT_USAGE)
                }
                (None, None, None) => {
                    print_sentinel(json);
                    ExitCode::from(EXIT_OK)
                }
            }
        }),
        Some("selfprotect") => Some({

            if args.iter().any(|a| a == "--arm") {
                ExitCode::from(arm_selfprotect(json))
            } else {
                print_selfprotect(json);
                ExitCode::from(EXIT_OK)
            }
        }),
        Some("overview") => Some(ExitCode::from(if args.iter().any(|a| a == "--export") {
            hostexport::run(args, json)
        } else {
            print_overview(json)
        })),
        Some("injected") => Some(ExitCode::from(print_injected(json))),
        Some("persistence") => {
            Some(ExitCode::from(print_persistence(json, args.iter().any(|a| a == "--all"))))
        }
        Some("rootkit") => Some(ExitCode::from(print_rootkit(json))),
        Some("kernel-posture") => Some({
            print_kernposture(json);
            ExitCode::from(EXIT_OK)
        }),
        Some("kwalk") => Some(ExitCode::from(print_kwalk(json))),
        #[cfg(feature = "mod-enf-persistence")]
        Some("kmod") => Some({
            let name = args
                .iter()
                .position(|a| a == "--unload")
                .and_then(|i| args.get(i + 1))
                .map(String::as_str);
            ExitCode::from(print_kmod(json, name, args.iter().any(|a| a == "--arm")))
        }),
        #[cfg(not(feature = "mod-enf-persistence"))]
        Some("kmod") => Some({
            eprintln!(
                "{}",
                modules::module_refusal(
                    hemostat_buildinfo::ModuleId::EnfPersistence,
                    MANIFEST.variant
                )
            );
            ExitCode::from(EXIT_NOT_BUILT)
        }),
        Some("crossview") => Some(ExitCode::from(print_crossview(json))),
        Some("bpf-progs") => Some(ExitCode::from(print_bpfprog(json))),
        Some("syscall-hooks") => Some(ExitCode::from(print_syscall_hooks(json))),
        Some("ftrace-hooks") => Some(ExitCode::from(print_ftrace_hooks(json))),
        Some("sysctl") => Some(ExitCode::from(print_sysctl())),
        Some("network") => Some({
            let arg = |name: &str| {
                args.iter().position(|a| a == name).and_then(|i| args.get(i + 1))
            };
            let armed = args.iter().any(|a| a == "--arm");
            let secs = arg("--arm").and_then(|v| v.parse::<u64>().ok()).unwrap_or(120);

            match narrowing_request(args) {
                Err(msg) => {
                    eprintln!("hemostat network: {msg}");
                    ExitCode::from(EXIT_USAGE)
                }
                Ok(Some((pid, dest))) => print_narrow(pid, dest.as_deref(), armed),
                Ok(None) => print_network(
                    armed,
                    secs,
                    args.iter().any(|a| a == "--confirm"),
                    args.iter().any(|a| a == "--revert"),
                    args.iter().any(|a| a == "--egress"),
                ),
            }
        }),
        Some("allowlist") => Some({
            let check = args.iter().position(|a| a == "--check").and_then(|i| args.get(i + 1));
            ExitCode::from(print_allowlist(json, check.map(String::as_str)))
        }),
        #[cfg(feature = "mod-remote")]
        Some("remote") => Some({
            let v = |n: &str| args.iter().position(|a| a == n).and_then(|i| args.get(i + 1));
            match window_secs(args, "--seconds") {
                Err(msg) => {
                    eprintln!("hemostat remote: {msg}");
                    ExitCode::from(EXIT_USAGE)
                }
                Ok(seconds) => ExitCode::from(print_remote(
                    v("--beacon").map(String::as_str),
                    v("--console-key").map(String::as_str),
                    seconds.unwrap_or(300),
                )),
            }
        }),
        #[cfg(feature = "mod-sidecar")]
        Some("sidecar") => Some({
            let v = |n: &str| args.iter().position(|a| a == n).and_then(|i| args.get(i + 1));
            ExitCode::from(print_sidecar(
                v("--install").map(String::as_str),
                v("--from").map(String::as_str),
                v("--sha256").map(String::as_str),
                args.iter().any(|a| a == "--arm"),
            ))
        }),
        #[cfg(not(feature = "mod-sidecar"))]
        Some("sidecar") => Some({
            eprintln!(
                "{}",
                modules::module_refusal(hemostat_buildinfo::ModuleId::Sidecar, MANIFEST.variant)
            );
            ExitCode::from(EXIT_NOT_BUILT)
        }),
        #[cfg(feature = "mod-deceive")]
        Some("deceive") => Some({

            let secs = match window_secs(args, "--watch") {
                Ok(s) => s,
                Err(msg) => {
                    eprintln!("hemostat deceive: {msg}");
                    return Some(ExitCode::from(EXIT_USAGE));
                }
            };
            ExitCode::from(print_deceive(
                args.iter().any(|a| a == "--arm"),
                secs,
                args.iter().any(|a| a == "--remove"),
                args.iter().any(|a| a == "--list"),
            ))
        }),
        #[cfg(not(feature = "mod-deceive"))]
        Some("deceive") => Some({
            eprintln!(
                "{}",
                modules::module_refusal(hemostat_buildinfo::ModuleId::Deceive, MANIFEST.variant)
            );
            ExitCode::from(EXIT_NOT_BUILT)
        }),
        #[cfg(feature = "mod-acquire")]
        Some("acquire") => Some({
            let val = |n: &str| args.iter().position(|a| a == n).and_then(|i| args.get(i + 1));
            ExitCode::from(print_acquire(
                val("--pid").and_then(|v| v.parse::<u32>().ok()),
                val("--into").map_or("/var/lib/hemostat/acquired", String::as_str),
                args.iter().any(|a| a == "--arm"),
            ))
        }),
        #[cfg(not(feature = "mod-acquire"))]
        Some("acquire") => Some({
            eprintln!(
                "{}",
                modules::module_refusal(hemostat_buildinfo::ModuleId::Acquire, MANIFEST.variant)
            );
            ExitCode::from(EXIT_NOT_BUILT)
        }),
        Some("uninstall") => Some(ExitCode::from(print_uninstall(args.iter().any(|a| a == "--arm")))),
        #[cfg(feature = "mod-query")]
        Some("query") => Some({
            let sql: Vec<&str> = positional.get(1..).unwrap_or_default().to_vec();
            ExitCode::from(print_query(json, &sql.join(" "), args.iter().any(|a| a == "--tables")))
        }),
        #[cfg(not(feature = "mod-query"))]
        Some("query") => Some({
            eprintln!(
                "{}",
                modules::module_refusal(hemostat_buildinfo::ModuleId::Query, MANIFEST.variant)
            );
            ExitCode::from(EXIT_NOT_BUILT)
        }),
        #[cfg(feature = "mod-correlation")]
        Some("correlate") => Some(ExitCode::from(print_correlate(json))),
        #[cfg(not(feature = "mod-correlation"))]
        Some("correlate") => Some({
            eprintln!(
                "{}",
                modules::module_refusal(hemostat_buildinfo::ModuleId::Correlation, MANIFEST.variant)
            );
            ExitCode::from(EXIT_NOT_BUILT)
        }),
        #[cfg(feature = "mod-sensor-audit")]
        Some("audit") => Some(ExitCode::from(print_audit(json))),
        #[cfg(not(feature = "mod-sensor-audit"))]
        Some("audit") => Some({
            eprintln!(
                "{}",
                modules::module_refusal(hemostat_buildinfo::ModuleId::SensorAudit, MANIFEST.variant)
            );
            ExitCode::from(EXIT_NOT_BUILT)
        }),

        #[cfg(feature = "mod-sensor-fanotify")]
        Some("fswatch") => Some(match window_secs(args, "--seconds") {
            Ok(_) => ExitCode::from(print_fswatch(args, json)),
            Err(msg) => {
                eprintln!("hemostat fswatch: {msg}");
                ExitCode::from(EXIT_USAGE)
            }
        }),
        #[cfg(not(feature = "mod-sensor-fanotify"))]
        Some("fswatch") => Some({
            eprintln!(
                "{}",
                modules::module_refusal(
                    hemostat_buildinfo::ModuleId::SensorFanotify,
                    MANIFEST.variant
                )
            );
            ExitCode::from(EXIT_NOT_BUILT)
        }),
        Some("harden-boot") => Some(ExitCode::from(print_harden_boot(args))),
        Some("exec-block") => Some(ExitCode::from(print_exec_block(args, positional.get(1..).unwrap_or_default()))),
        Some("account") => Some({
            ExitCode::from(print_account(args, operands(args, &["--drop-group"]).first().copied()))
        }),
        Some("sshd") => Some(ExitCode::from(print_sshd(json))),
        Some("trust") => Some(ExitCode::from(crate::trust_verb::print_trust(args, json))),
        Some("watchdog") => Some(match window_secs(args, "--watch") {
            Ok(secs) => ExitCode::from(print_watchdog(json, secs)),
            Err(msg) => {
                eprintln!("hemostat watchdog: {msg}");
                ExitCode::from(EXIT_USAGE)
            }
        }),

        #[cfg(feature = "mod-scan-yara")]
        Some("scan") => Some({
            let rules = args
                .iter()
                .position(|a| a == "--rules")
                .and_then(|i| args.get(i + 1))
                .map(String::as_str);
            ExitCode::from(print_scan(json, &operands(args, &["--rules"]), rules))
        }),
        #[cfg(not(feature = "mod-scan-yara"))]
        Some("scan") => Some({
            eprintln!(
                "{}",
                modules::module_refusal(hemostat_buildinfo::ModuleId::ScanYara, MANIFEST.variant)
            );
            eprintln!(
                "content scanning is not in this image: `mod-scan-yara` was not compiled in, \n\
                 so the engine is absent rather than disabled. Nothing was scanned and \n\
                 nothing is claimed about this host's files."
            );
            ExitCode::from(EXIT_NOT_BUILT)
        }),

        Some("ticket") => Some(ExitCode::from(mint_ticket(args))),

        Some("policy") => Some(ExitCode::from(crate::authz::mint_policy(args))),
        Some("vendor") => Some(ExitCode::from(vendor::print_vendor(args, json))),
        Some("snapshot") => Some(ExitCode::from(snapshot::take_snapshot(args, json))),
        Some("drift") => Some(ExitCode::from(snapshot::drift(args, json))),
        Some("manifest-sign") => Some(ExitCode::from(vendor::manifest_sign(args))),
        Some("suid") => Some(ExitCode::from(print_suid(json))),
        Some("inventory") => Some(ExitCode::from(print_inventory(json))),
        Some("services") => Some(ExitCode::from(services_verb(args, json))),
        Some("sysmap") => Some(ExitCode::from(print_sysmap(json))),
        Some("kptr-hooks") => Some(ExitCode::from(print_kptrhooks(json))),
        Some("watch") => Some(ExitCode::from(watch(json))),
        Some("accounts") => Some(ExitCode::from(print_accounts(json))),
        Some("hooks") => Some({
            print_hooks(json);
            ExitCode::from(EXIT_OK)
        }),
        Some("ps") => Some({
            print_ps(json);
            ExitCode::from(EXIT_OK)
        }),

        #[cfg(feature = "mod-enf-persistence")]
        Some("remediate") => Some(ExitCode::from(remediate(args, json))),

        #[cfg(not(feature = "mod-enf-persistence"))]
        Some("remediate") => Some({
            eprintln!(
                "{}",
                modules::module_refusal(
                    hemostat_buildinfo::ModuleId::EnfPersistence,
                    MANIFEST.variant
                )
            );
            ExitCode::from(EXIT_NOT_BUILT)
        }),
        Some("undo") => Some(ExitCode::from(undo_verb(positional, args, json))),
        Some("collect") => Some(ExitCode::from(collect(positional, json))),
        _ => None,
    }
}

#[cfg(any(target_os = "linux", target_os = "windows", test))]
fn operands<'a>(args: &'a [String], valued: &[&str]) -> Vec<&'a str> {
    let mut out = Vec::new();
    let mut verb_seen = false;
    let mut value_next = false;
    for a in args {
        if std::mem::take(&mut value_next) {
            continue;
        }
        if a.starts_with("--") {
            value_next = valued.contains(&a.as_str());
        } else if verb_seen {
            out.push(a.as_str());
        } else {
            verb_seen = true;
        }
    }
    out
}

#[cfg(target_os = "linux")]
fn print_export(format: &str) -> u8 {
    use hemostat_export as ex;

    let r = hemostat_sensor_linux::persist::report();

    let findings: Vec<ex::Finding> = r
        .findings
        .iter()
        .map(|f| ex::Finding {
            severity: match f.severity {
                hemostat_sensor_linux::triage::Severity::Critical => ex::Severity::Critical,
                hemostat_sensor_linux::triage::Severity::Warn => ex::Severity::Warn,
                hemostat_sensor_linux::triage::Severity::Note => ex::Severity::Note,
                hemostat_sensor_linux::triage::Severity::Info => ex::Severity::Info,
            },
            subject: f.subject.clone(),
            locus: f.locus.clone(),
            what: f.what.clone(),
            why: f.why.clone(),
        })
        .collect();

    let unreadable: Vec<String> = r
        .observations
        .iter()
        .filter(|o| !o.coverage.established())
        .map(|o| o.id.to_string())
        .collect();

    let id = match gather_identity() {
        Ok(i) => i,
        Err(e) => {
            eprintln!("export: cannot establish identity: {e}");
            return EXIT_PARTIAL;
        }
    };

    let e = ex::Export {
        host_id: hex32(&id.host),
        engagement: id.engagement.iter().map(|b| format!("{b:02x}")).collect(),
        when: rfc3339_now(),
        agent_rev: MANIFEST.source_rev.to_string(),
        findings,
        coverage: ex::Coverage {
            established: r.established,
            total: r.total,
            unreadable,
        },

        surface: "the persistence catalogue".into(),
    };

    match format {
        "jsonl" => print!("{}", ex::to_jsonl(&e)),
        "stix" => println!("{}", ex::to_stix(&e)),
        "misp" => println!("{}", ex::to_misp(&e)),
        "report" => print!("{}", sanitised_report(&e)),
        other => {
            eprintln!("export: unknown format {other}; use jsonl, stix, misp or report");
            return EXIT_USAGE;
        }
    }

    if e.is_complete() {
        EXIT_OK
    } else {
        EXIT_PARTIAL
    }
}

#[cfg(target_os = "linux")]
fn sanitised_report(e: &hemostat_export::Export) -> String {
    let mut shown = e.clone();
    for f in &mut shown.findings {
        for v in [&mut f.subject, &mut f.locus, &mut f.what, &mut f.why] {
            *v = h(v);
        }
    }
    for u in &mut shown.coverage.unreadable {
        *u = h(u);
    }
    hemostat_export::to_report(&shown)
}

fn usage() {
    eprintln!("{}", usage_text());
}

fn usage_text() -> String {
    format!(
        "hemostat {} — incident-response agent\n\n\
         USAGE:\n    \
         hemostat <verb> [--json]\n\nEXIT CODES (design §13):\n    \
         0   the sweep ran\n    \
         1   the operation failed — entropy unavailable, a file unwritable,\n        \
             an evidence store that did not verify\n    \
         2   usage error\n    \
         3   authorization denied — a presented ticket was refused (§13.4.3)\n    \
         4   policy refusal — permitted by authority, outside the engagement scope\n    \
         5   dry run — the plan printed and nothing was applied; `--arm` applies it\n    \
         6   the enforcer failed — an action was attempted and did not take effect.\n        \
             NOT success, and never \"contained\"\n    \
         7   the sweep could NOT run — a partial result, not a clean one (§13.4.7)\n    \
         8   NOT-BUILT — this variant does not contain the module the verb needs;\n        \
             a different build, not a different flag\n\n\
         VERBS:\n    \
         build-info    What this image is: variant, modules, action-class status\n    \
         probe         What this host and this process can actually do.\n                   \
         On Linux the enforcement tier and the boot line; on Windows whether\n                   \
         the adversary is actually confined to user mode (§6.13.2); on FreeBSD\n                   \
         whether every base tool the agent runs verifies against the signed\n                   \
         manifest (its signed sidecar beside it, or --meta, for package\n                   \
         links), the host id, and where the evidence store would sit\n                   \
         flags: --manifest <PATH>, --meta <PATH> (FreeBSD)\n    \
         hooks         Which LSM hooks this kernel declares, and what each buys (Linux)\n    \
         accounts      Local account posture: structural findings (Linux). On FreeBSD:\n                   master.passwd, group, every key file, sudo and doas held to\n                   config.xml, sealed before it is judged — NOPASSWD, a key\n                   config lacks, a second uid 0. Advice only\n                   flags: --manifest <PATH>, --store <DIR>, --operator-key <SHA256:FP>\n    \
         overview      What this host is, and what it is listening to (Linux).\n                   `--export DIR` seals the host's half of `correlate`: every\n                   socket in every namespace, the MACs and addresses, conntrack,\n                   and which namespaces and sockets it could NOT read\n                   flags: --export <DIR> (Linux)\n    \
         injected      Every process something is inside: hooks, preloads, tracers (Linux)\n    \
         persistence   EVERY catalogued persistence mechanism and its status (Linux).\n                   On FreeBSD: cron against cron/item, both rc.d trees, periodic,\n                   loader modules, devd, boot commands and packages, held to the\n                   signed manifest and sealed before they are judged\n                   flags: --all (Linux); --manifest <PATH>, --store <DIR> (FreeBSD)\n    \
         rootkit       Rootkit-surface checks vs the IRSeC red team's tools (Linux)\n    \
         syscall-hooks Read kernel text (/proc/kcore): inline hooks + table redirection (Linux, root)\n    \
         ftrace-hooks  Read tracefs: ftrace/BPF-based syscall hooks the inline scan can't see (Linux, root)\n    \
         selfprotect   Prove the task_kill deny refuses a SIGKILL; --arm holds it over\n                   this process so a red-team kill is refused (Linux, root)\n                   flags: --arm\n    \
         firewall      Host firewall ruleset, with its trust tag (Linux)\n    \
         posture       The operator posture view, printed once (Linux). On FreeBSD the\n                   \
         sweep: every process image and kernel file hashed against the signed\n                   \
         manifest, every listener checked against pfSense's own services, the\n                   \
         raw input sealed before the verdict\n                   \
         flags: --manifest <PATH> (FreeBSD)\n    \
         tui           The operator posture view, live (Linux)\n    \
     console       Every detection sweep in one live findings view; --once dumps a frame,\n                   every finding in it, and exits 7 if a sweep did not run in full.\n                   On Windows `--rules DIR` (default: rules\\ beside the executable)\n                   feeds its detect row, and the live view adds a detect-live\n                   row for process starts written while it is open\n                   flags: --once, --rules <DIR> (Windows)\n    \
     sysctl        Kernel tunables against their hardened values, read from the\n                   running kernel. Fixes write ONE key at a time to /proc/sys —\n                   never `sysctl --system` (Linux)\n    \
     network       The inbound surface, and a default-deny plan that keeps every\n                   port something is listening on plus whatever you named in\n                   /etc/hemostat/network-allow (a port named there with a source\n                   range is open from that range only). Shows the plan; `--arm N`\n                   applies it with an automatic rollback in N seconds unless you\n                   `--confirm`. `--block-pid N` or `--block-dest ADDR` narrows\n                   egress instead of isolating: NEW connections from that process\n                   (or to that address) are refused without taking the host off\n                   the network. Connections already open stay up, so stop the\n                   process to end a live shell (Linux, root)\n                   flags: --arm <N>, --block-dest <ADDR>, --block-pid <N>, --confirm, --egress, --revert\n    \
     allowlist     What this host will NOT respond to, and who said so. Reads the\n                   suppression file the broker consults; `--check TARGET` says\n                   whether anything covers it. Never writes: a tool that could\n                   append an exemption is one an intruder could use (Linux)\n                   flags: --check <TARGET>\n    \
     remote        The console link, outbound only: `--beacon HOST:PORT` sends a\n                   heartbeat whose ABSENCE is the durable evidence the agent was\n                   killed. Frames are HPKE-sealed with this tree's own crypto — no\n                   TLS, no certificate authority. The console key is pinned. There\n                   is no listen mode: `--listen` is refused, naming RFC-003 (Linux,\n                   needs mod-remote)\n                   flags: --beacon <HOST:PORT>, --console-key <HEX>, --seconds <N>\n    \
     sidecar       Install a tool you brought with you, verified against a digest\n                   you declared before you arrived. The digest is not optional:\n                   every path on a compromised host is under somebody else's\n                   control. Fetches nothing (Linux, root, needs mod-sidecar)\n                   flags: --arm, --from <DIR>, --install <NAME>, --sha256 <HEX>\n    \
     deceive       Plant inert honeytokens where an intruder looks, and watch them\n                   for reads. A canary read needs no rule and no baseline: the\n                   legitimate access rate is zero. `--watch N` holds the\n                   tripwire; `--list` and `--remove` take them away again\n                   (Linux, root, needs mod-deceive)\n                   flags: --arm, --list, --remove, --watch <SECS>\n    \
     acquire       Collect what exists nowhere else: the image of a process whose\n                   file has been unlinked, and executable memory with no file\n                   behind it. Both stop existing when the process does.\n                   `--pid N` (Linux, root, needs mod-acquire)\n                   flags: --arm, --into <DIR>, --pid <N>\n    \
     uninstall     Take the agent off this host. Removes its binary and service\n                   and deliberately LEAVES the evidence store, the undo journals\n                   and the snapshots they point at. Dry run by default (Linux)\n                   flags: --arm\n    \
     query         A SQL subset over live host state: `query 'SELECT pid, exe FROM\n                   processes WHERE uid = 0'`. `--tables` lists what there is.\n                   Says when a table could not be read in full, so an empty\n                   result is not mistaken for a clean host (Linux, needs\n                   mod-query)\n                   flags: --tables\n    \
     correlate     Which findings are about the same things. Six rows from six\n                   sweeps can be one intrusion; this groups them by what they\n                   share, and names the entities that appear in too much of the\n                   sweep to link anything (Linux, needs mod-correlation). On the\n                   collector: the firewall's sealed `fw` store against a host's\n                   `overview --export`, joined by host and flow — a live flow the\n                   host has no socket for is a CONTRADICTION, and so is a state on\n                   the firewall its own sockets do not hold (needs mod-collector)\n                   flags: --fw <DIR>, --fw-pin <HEX>, --host <DIR>, --host-pin <HEX>,\n                   --manifest <PATH>, --offset <SECS>, --skew <SECS> (collector)\n    \
     detect        Sigma rules over what this agent can see. `--rules DIR` points\n                   at a rule repository; none is compiled in (rules/sigma in the\n                   source tree is a starting set). Says how many rules did NOT\n                   run and why — a rule that could not be evaluated is never\n                   counted as one that found nothing. On Linux, one sample of\n                   the processes running now; on Windows, the Security 4688 and\n                   Sysmon 1 records already in the log, or with `--watch SECS`\n                   (Windows) those written during the next SECS seconds, with\n                   each subscription's health; exits 7 if a source faulted or\n                   records were dropped (needs mod-detect-sigma)\n                   flags: --rules <DIR>, --watch <SECS> (Windows)\n    \
     audit         Can this host's audit trail be believed? Asks the kernel\n                   directly: is anything collecting, how many records has it\n                   already dropped, are the rules on disk still loaded, and can\n                   they still be wiped without a reboot. Exits 7 if the kernel\n                   would not answer (Linux, root, needs mod-sensor-audit)\n    \
     fswatch       Live filesystem sensor with no eBPF behind it: writes and\n                   executions under the persistence directories, as they happen.\n                   Closes the gap every scan has — a boot rule that re-plants\n                   after the sweep. `--seconds N` (Linux, root, needs\n                   mod-sensor-fanotify)\n                   flags: --all, --seconds <N>\n    \
     harden-boot   Kernel parameters that only take effect after a restart, and\n                   what each costs on THIS host — including which loaded modules\n                   would stop loading under module.sig_enforce. Lists by default;\n                   `--set P --arm` edits the bootloader config, regenerates it\n                   and reads it back (Linux, root)\n                   flags: --arm, --set <PARAM>\n    \
     exec-block    Stop one binary from starting again. Bind-mounts /dev/null over\n                   it, which leaves the file byte-identical for an examiner;\n                   clears the execute bits only where no bind mount is possible.\n                   `--pid N` resolves the path from a process. Dry run by\n                   default; `--arm` applies, `--lift` removes (Linux, root)\n                   flags: --arm, --lift, --pid <N>\n    \
     account       The four account containment classes, one per flag:\n                   `--end-sessions`, `--purge-tickets`, `--expire-password`,\n                   `--drop-group G`. Dry run by default; `--arm` applies. The two\n                   that change what an account IS are never fired by a rule —\n                   an operator types the flag (Linux, root)\n                   flags: --arm, --drop-group <GROUP>, --end-sessions, --expire-password, --purge-tickets\n    \
     sshd          The SSH daemon's EFFECTIVE config, from `sshd -T` rather than\n                   from the file — first-value-wins and Include order make the file\n                   misleading — plus what overrides it, which a bare `sshd -T` does\n                   not apply: each Match block, and each `-o` from the unit's\n                   environment file or a running root daemon's command line. A\n                   daemon started with `-f` on another config is judged on that\n                   file. Needs root (Linux)\n    \
     watchdog      What would put an implant back: mutual guard pairs and restart\n                   loops. `--watch N` also waits N seconds and reports what\n                   actually respawned in that window (Linux)\n                   flags: --watch <SECS>\n    \
     trust         The TLS trust store: every CA this host believes about any name,\n                   where each one came from, and whether its vendor ships it. A CA\n                   nothing vendor-shipped explains is WARN — an enterprise CA is that,\n                   and is shown with that said — and CRITICAL when it can sign for any\n                   name and was added since the arrival snapshot, was issued days ago,\n                   is short-lived, or is shaped like an interception proxy's root.\n                   Reads the store's sources, its bundles and hashed directories, NSS\n                   databases and SSL_CERT_FILE-style redirections (Linux); the OS store\n                   and config.xml's CAs, sealed first (FreeBSD); the machine and user\n                   certificate stores (Windows). Detection only; on Linux\n                   `remediate --anchors` offers a removal for a person to arm\n                   flags: --all, --store <DIR>, --manifest <PATH> (FreeBSD)\n    \
     suid          SUID/SGID, file-capability and immutable-attribute backdoor scan (Linux)\n    \
     scan          Content-match files against YARA rules. With no paths: every running\n                   process's executable plus /etc/ld.so.preload, which is where the\n                   shape sensors already point. `--rules DIR` adds a feed you trust\n                   (Linux, needs mod-scan-yara)\n                   flags: --rules <DIR>\n    \
     inventory     Package integrity, unpackaged binaries, suspicious services (Linux)\n    \
     vendor        Every file a signed vendor manifest covers, hashed and checked\n                   against what the vendor shipped at that path. The reference\n                   was built off this host, so nothing here can edit it (Linux;\n                   on FreeBSD also every file under the RFC-002 roots, graded\n                   with the signed sidecar `--meta`, default beside the manifest)\n                   flags: --manifest <PATH>, --meta <PATH>\n    \
     snapshot      Record the host on arrival — accounts, password fingerprints,\n                   groups, sudoers, authorized_keys, sshd, PAM, cron, units,\n                   listeners, the firewall (from the kernel), declared services —\n                   into its own sealed store,\n                   and print the seal key to keep off-host (Linux). On FreeBSD:\n                   config.xml, sealed raw, into /root/hemostat/snapshot. On Windows:\n                   services, tasks, autostarts, WMI subscriptions, accounts and\n                   privileged groups, listeners, shares and security settings,\n                   into C:\\ProgramData\\hemostat\\snapshot\n                   flags: --replace, --store <DIR>\n    \
     drift         Every change since the arrival snapshot, graded: a new user, a\n                   reset password, a key added, a sudoers line, a new listener (Linux).\n                   On FreeBSD: config.xml, sealed before it is judged — a boot\n                   command, noantilockout, a moved rule, a new WAN pass rule. On Windows:\n                   a new service, task, Run value or WMI binding is CRITICAL unless\n                   its binary is signed and its signer named (WARN); a new\n                   Administrators or Remote Desktop member is CRITICAL (advice only)\n                   flags: --store <DIR>\n    \
     fw rules      Every rule pf is running, in every anchor, traced to config.xml or\n                   to pfSense's own ridentifier ranges: a rule loaded by hand into\n                   userrules/*, a tracker the config does not have. The listings\n                   are sealed before they are judged (FreeBSD)\n                   flags: --store <DIR>\n    \
     fw flows      What is leaving an outward interface now, what filter.log recorded\n                   passing and blocking, leases the neighbour table disagrees\n                   with, and the box's own states against its own sockets (a live\n                   one no socket holds is a CONTRADICTION). filter.log is followed by inode and offset across rotation;\n                   the raw input is sealed before anything is judged (FreeBSD)\n                   flags: --manifest <PATH>, --dst <ADDR>, --limit <N>\n    \
     fw verdict    `fw verdict ADDR[:PORT][/PROTO]`: LEFT, BLOCKED or UNKNOWN for that\n                   destination and each flow to it, with the evidence and its limits.\n                   UNKNOWN is not \"did not leave\": pfSense's LAN rule logs nothing,\n                   so a passed flow lasts only as long as its state (FreeBSD)\n                   flags: --manifest <PATH>, --src <ADDR>\n    \
     fw block      `fw block CIDR --alias NAME --tracker N`: every stage a block\n                   passes — preflight (alias, rule, anti-lockout, table, CARP, the\n                   .inc files), the protect-set, the signed policy's scope, the v2\n                   ticket — then the evidence sealed, the ticket spent, the entry\n                   live in pf's table, and a watcher that lifts it at the deadline\n                   (120 s) unless confirmed. A dry run that stops before the write\n                   unless `--arm` (FreeBSD)\n                   flags: --alias <HEMOSTAT_OUT|HEMOSTAT_IN>, --tracker <N>, --protect <CIDR>, --manifest <PATH>, --meta <PATH>, --deadline <SECS>, --arm, --dry-run\n    \
     fw confirm    `fw confirm ID`: make a live block persistent — the stages again,\n                   the same ticket, then config.xml through pfSense's own PHP (one\n                   revision, \"HEMOSTAT block CIDR ID\"), a filter reload, the\n                   re-add, and the proof from disk (FreeBSD, not observe-only)\n                   flags: --manifest <PATH>, --meta <PATH>\n    \
     fw status     HEMOSTAT's containment journal: each block's state, deadline,\n                   revision, and whether pf's table holds it now (FreeBSD)\n                   flags: --manifest <PATH>, --meta <PATH>\n    \
     fw watch      The watcher `fw block` starts under daemon(8); not run by hand\n                   (FreeBSD)\n    \
     fw statekill  `fw statekill CIDR --alias NAME`: kill every pf state to the CIDR\n                   (HEMOSTAT_OUT) or from it (HEMOSTAT_IN) — its own class and v2\n                   ticket, the protect-set first, the matching states sealed before\n                   `pfctl -k`. Cannot be undone; refused under the ot profile. A dry\n                   run unless `--arm` (FreeBSD, not ot-safe or observe-only)\n                   flags: --alias <HEMOSTAT_OUT|HEMOSTAT_IN>, --protect <CIDR>, --manifest <PATH>, --meta <PATH>, --arm, --dry-run\n    \
     manifest-sign Sign a vendor manifest on the signing host with the key in\n                   $HEMOSTAT_MANIFEST_KEY_FILE, writing <PATH>.sig and printing the key\n                   to pin; `--new-key PATH` creates that key; a meta sidecar is signed\n                   only with `--manifest PATH`, the manifest it is bound to (Linux)\n                   flags: --in <PATH>, --new-key <PATH>, --manifest <PATH>\n    \
     services      The services THIS host must keep, named by you, and whether\n                   anything has touched them. Declare them in /etc/hemostat/critical;\n                   their files are compared against the arrival snapshot (`snapshot`);\n                   `--start UNIT --arm` enables and starts a declared\n                   unit that is down (dry run without `--arm`; `undo` restores its prior\n                   state); `--baseline` is retired (Linux)\n                   flags: --arm, --baseline, --service <NAME>, --start <UNIT>, --store <DIR>\n    \
     sysmap        Corroborate /proc/kallsyms against on-disk System.map, KASLR-aware (Linux, root)\n    \
     kptr-hooks    Kernel seq_file/VFS function-pointer integrity via /proc/kcore (Linux, root)\n    \
     watch         Live eBPF exec sensor: alert on reverse-shell-shaped execs (Linux, root)\n    \
     crossview     Cheap /proc cross-views: DKOM hidden-task, raw/AF_PACKET C2, io_uring (Linux)\n    \
     kernel-posture Can a rootkit LKM load, and is a privileged agent being blinded? (Linux)\n    \
     kwalk         Ground truth: walk the kernel's task/module lists via /proc/kcore (Linux, root)\n    \
     kmod          What the kernel says is loaded, cross-checked against /proc/modules.\n                   `--unload <name> --arm` removes a module that is hiding (Linux, root)\n                   flags: --arm, --unload <NAME>\n    \
     bpf-progs     Enumerate loaded eBPF programs: census + interception/LSM classes (Linux, root)\n    \
         ps            Processes seen through the procfs floor (Linux)\n    \
     remediate     Offer a reversible removal for every catalogued persistence\n                   finding. A unit systemd holds with no catalogued file (a\n                   transient one) is listed as left to you, never removed.\n                   Dry run by default; `--arm` applies and writes an undo\n                   journal. The authentication surface is never removed\n                   automatically (Linux). A finding that is one line in a\n                   shared file is offered as that line: `--lines <FILE>` lists a\n                   file's lines with tokens, `--strip-line <TOKEN>` removes the\n                   one chosen (dry run until --arm; sudoers, PAM, sshd and\n                   authorized_keys also need --auth). A TLS trust anchor `trust`\n                   found is offered the same way: `--anchors` lists them with\n                   tokens, `--remove-anchor <TOKEN>` takes one out and rebuilds\n                   the store (dry run until --arm)\n                   flags: --allow-listener <UNIT>, --arm, --protect <UNIT>,\n                   --lines <FILE>, --strip-line <TOKEN>, --auth, --operator-key\n                   <SHA256:FP>, --session-key-unknown, --last-admin-key,\n                   --anchors, --remove-anchor <TOKEN>\n    \
     streams       Alternate data streams: content a directory listing does not\n                   show and a file's size does not include (Windows)\n    \
     dll-hijack    Where the loader could be made to find the wrong library:\n                   writable PATH entries, KnownDLLs, SafeDllSearchMode (Windows)\n    \
     signature     Is this file signed, and how was that established: embedded\n                   Authenticode or a system catalog (Windows)\n    \
     com           What the registered shell and COM handlers actually load, and\n                   per-user registrations shadowing machine ones (Windows)\n    \
     usn           The NTFS change journal: what was on this volume and is not\n                   any more. The only record of a payload that deleted itself,\n                   and of the journal having been deleted to hide one.\n                   `--volume D:` (Windows, Administrator, needs mod-sensor-usn)\n                   flags: --volume <DRIVE>\n    \
     etw           Which ETW providers this host can be asked to report, and what each\n                   buys. `--watch <SECS>` opens a session and counts what actually arrives\n                   (Windows)\n                   flags: --watch <SECS>\n    \
     sysmon        Is Sysmon there, and is it recording? A service whose driver\n                   has been unloaded still reports RUNNING and sees nothing, so\n                   the loaded-driver list is asked directly (Windows,\n                   needs mod-sensor-sysmon)\n    \
     evtlog        Whether this host's event log can be believed: cleared logs,\n                   holes in the record numbering where individual records were\n                   deleted, channels shrunk until they roll over, and whether\n                   4688 carries command lines. `--quick` skips the record count\n                   (Windows, needs mod-sensor-evtlog)\n                   flags: --quick\n    \
     wmi           Persistent WMI event subscriptions: persistence that writes no\n                   file and creates no registry autorun (Windows)\n    \
     modules       What is actually mapped into system processes — the cross-view\n                   that needs no registry key to be honest (Windows)\n    \
     export        Hand the persistence findings to the rest of the response:\n                   `export jsonl|stix|misp|report`. Covers the persistence\n                   catalogue only — `collect` sweeps the other nine. Every\n                   format names that surface beside its coverage, so\n                   `complete` is never read as a clean host (Linux)\n    \
     ad            Domain credentials this host holds: Kerberos keytabs, ticket\n                   caches, and whether the KDC belongs to the realm (Linux)\n    \
     sentinel      What would put THIS agent back if it were killed: which launch\n                   routes this host offers under systemd, runit or neither, and how\n                   many survive a cgroup kill. `--register PID` starts one sentinel\n                   per usable mechanism; `--guard PID` makes this process one.\n                   `--watch SPEC` is what a registered supervisor runs, written by\n                   `--register` — an agent identity, not a duration (Linux)\n                   flags: --guard <PID>, --persist, --register <PID>, --watch <SPEC>\n    \
     ticket        Mint an authorization ticket for a responder key:\n                   `ticket --op <OP> --ttl <SECS> --out <FILE>`. An armed verb checks\n                   one when $HEMOSTAT_TICKET names it; with none it still runs, and\n                   says the authorization stage was not performed (Linux)\n                   A perimeter class (PerimeterBlock) mints version 2, bound to\n                   --alias and --cidr: the one range it may block\n                   flags: --alias <HEMOSTAT_OUT|HEMOSTAT_IN>, --cidr <NET/LEN>, --class <CLASS>, --engagement <ID>, --host <HOST>, --op <OP>, --out <FILE>, --ttl <SECS>\n    \
     policy        Mint a signed engagement policy with the root seed in\n                   $HEMOSTAT_ENGAGEMENT_KEY: which classes, which host ids, until\n                   when, under which profile and epoch. The firewall's perimeter\n                   stage needs one whose scope lists its host id (Linux)\n                   flags: --allow <CLASS[,CLASS]>, --bulk <N>, --engagement <ID>, --epoch <N>, --out <FILE>, --profile <it|ot>, --scope <HOST[,HOST]>, --ttl <SECS>\n    \
     undo          Reverse an armed remediation: `undo <JOURNAL>` (Linux). On the\n                   firewall, `undo [ID]` lifts what `fw block` applied — only\n                   entries the journal and the box show are HEMOSTAT's — in every\n                   variant, observe-only included (FreeBSD). `--auth` lets a stripped\n                   line go back into a login or privilege file (Linux)\n                   flags: --manifest <PATH>, --meta <PATH> (FreeBSD), --auth (Linux)\n    \
     collect       Run the sweeps and write findings to a sealed, hash-chained\n                   evidence store: `collect [DIR]` (default ./hemostat-evidence).\n                   Exits 7, with the store still written, if any sweep did not\n                   run in full or the findings were shed at the disk ceiling (Linux)\n    \
     verify        Validate an evidence store's chain and seals, no key needed:\n                   `verify <DIR>` (portable — the standalone examiner)\n    \
     read          Verify then decrypt a store's findings: `read <DIR>` with the\n                   recovery key in $HEMOSTAT_RECOVERY_KEY (portable)\n    \
         ship          Copy sealed stores off the host as parcels: \n                   \
         `ship --to <HOST:PORT> --collector-key <HEX> --receipt-key <HEX>\n                   \
         <STORE>...` pushes each to a pinned collector and keeps its signed\n                   \
         receipt in a CHECKPOINT store, skipping a store already receipted\n                   \
         (Linux, needs mod-remote). `ship --identity` prints what the collector\n                   \
         enrolls. Refuses a store that is not sealed; never removes one\n                   \
         flags: --to <HOST:PORT>, --collector-key <HEX>,\n                   \
         --receipt-key <HEX>, --link-key <PATH>, --checkpoints <DIR>, --identity\n    \
         collector     The fleet collector (RFC-003; Linux, needs mod-collector).\n                   \
         `collector ingest <DIR>` verifies every parcel on the media, keeps each\n                   \
         accepted store and each rejected parcel byte-identical, and records\n                   \
         which, and why, in the collector's sealed ledger; `collector ledger`\n                   \
         audits the ledger and lists it; `collector read-key` makes the\n                   \
         engagement read key once and prints the public half for `collect`'s\n                   \
         $HEMOSTAT_READ_PUBKEY. Exits 1 if any parcel was rejected.\n                   \
         `collector keys` makes the link and receipt keys; `collector listen\n                   \
         <ADDR:PORT>` is the listener role, opening only enrolled agents' frames;\n                   \
         `collector ingest --spool [--follow]` judges what it spooled and signs\n                   \
         the receipts. Sends nothing to any host but a receipt\n                   \
         flags: --root <DIR>, --engagement <HEX>, --seal-key <HEX> (repeatable),\n                   \
         --spool, --follow, --seconds <N>\n    \
         enroll        Enroll a host on the collector, a human step (RFC-003 §2.2):\n                   \
         its label, host id, binary digest and agent link key, in the ledger\n                   \
         (Linux, needs mod-collector)\n                   \
         flags: --label <NAME>, --host-id <HEX>, --digest <HEX>, --link-key <HEX>,\n                   \
         --root <DIR>, --engagement <HEX>\n    \
         queue         The collector's alert queue (RFC-003 §4; Linux, needs\n                   \
         mod-collector): one alert per problem per host, folded from the ledger\n                   \
         and every store it holds. Bare, the TUI (queue, hosts, detail,\n                   \
         cluster; a ack, i investigating, r resolve, n note); `--once` prints\n                   \
         one frame. `list`, `show <ID>`, `ack <ID>`, `investigate <ID>`,\n                   \
         `resolve <ID> --as true-positive|false-positive|benign --reason <TEXT>`,\n                   \
         `note <ID> --reason <TEXT>`. Each change is a ledger record naming your\n                   \
         login; refused as root. Never closes, lowers or deletes an alert, and\n                   \
         sends nothing to any host. `--export report|jsonl` writes a static\n                   \
         HTML page or JSON lines, to `--out <FILE>` (a new file) or stdout. The\n                   \
         firewall's stores are judged here again (RFC-003 F7) against\n                   \
         `--manifest <PATH>`, or the signed pair under <engagement>/manifests/;\n                   \
         the firewall's accounts store with `--operator-key SHA256:FP` (or\n                   \
         $HEMOSTAT_OPERATOR_KEY) as your own key, which the store does not carry\n                   \
         flags: --root <DIR>, --engagement <HEX>, --as <RESOLUTION>, --reason <TEXT>,\n                   \
         --export <FORMAT>, --out <FILE>, --once, --manifest <PATH>,\n                   \
         --operator-key <SHA256:FP>\n",
        env!("CARGO_PKG_VERSION")
    )
}

fn print_build_info(json: bool) {
    if json {
        jprintln!("{}", MANIFEST.to_json());
        return;
    }

    println!("hemostat {}", env!("CARGO_PKG_VERSION"));
    println!("  variant:   {}", MANIFEST.variant);
    println!("  toolchain: {}", MANIFEST.toolchain);
    println!(
        "  source:    {}{}",
        MANIFEST.source_rev,
        if MANIFEST.source_dirty { " (DIRTY — built from uncommitted changes)" } else { "" }
    );
    println!(
        "  reproducible build: {}",
        if MANIFEST.source_date_epoch == 0 {
            "no (SOURCE_DATE_EPOCH unset)".to_string()
        } else {
            format!("yes (SOURCE_DATE_EPOCH={})", MANIFEST.source_date_epoch)
        }
    );

    let built: Vec<_> = MANIFEST.built().collect();
    let registered = built
        .iter()
        .filter(|m| matches!(modules::implementation_for(m.id), modules::Implementation::Registered(_)))
        .count();
    println!(
        "\nmodules: {} of {} compiled in, {registered} with an implementation registered",
        built.len(),
        MANIFEST.modules.len()
    );

    for m in &built {
        let imp = modules::implementation_for(m.id);
        match imp {
            modules::Implementation::Registered(where_) => {
                println!("  {:<24} {:<12} {:<14} {where_}", m.id.feature(), m.status, imp.token());
            }
            modules::Implementation::Declared | modules::Implementation::NotOnThisOs => {
                println!("  {:<24} {:<12} {}", m.id.feature(), m.status, imp.token());
            }
        }
    }

    let absent: Vec<_> = MANIFEST
        .modules
        .iter()
        .filter(|m| m.status == Status::NotBuilt)
        .collect();
    if !absent.is_empty() {
        println!("\nabsent from this image ({}):", absent.len());
        for m in &absent {
            println!("  {:<24} {}", m.id.feature(), m.status);
        }
    }

    println!("\naction classes:");
    println!("  {:<24} {:<12} CAN ACTUATE", "CLASS", "BUILD");
    for class in ActionClass::ALL {
        match modules::action_build_status(class) {

            Status::NotBuilt => println!(
                "  {:<24} {:<12} — not in variant {}",
                class.name(),
                Status::NotBuilt,
                MANIFEST.variant
            ),
            built => println!(
                "  {:<24} {:<12} {}",
                class.name(),
                built,
                modules::executor_for(class)
            ),
        }
    }

    let verbs: Vec<&str> = ActionClass::ALL
        .iter()
        .filter(|c| matches!(modules::executor_for(**c), modules::Executor::Reachable))
        .map(|c| match c {
            ActionClass::PersistenceNeutralize => "`remediate` neutralises persistence",
            ActionClass::Lift => "`undo` lifts what was applied",
            ActionClass::Kill | ActionClass::Suspend => {
                "`console` freezes and removes a watchdog group"
            }
            ActionClass::Quarantine => "`console` clears a set-user-ID bit",
            ActionClass::AccountDisable => "`console` locks an account",
            ActionClass::SessionKill => "`account --end-sessions` ends a user's logins",
            ActionClass::TicketPurge => "`account --purge-tickets` destroys their Kerberos caches",
            ActionClass::CredRotate => "`account --expire-password` forces a password change",
            ActionClass::GroupDrop => "`account --drop-group` removes a group membership",
            ActionClass::ExecBlock => "`exec-block` stops a binary starting again",

            ActionClass::Collect if cfg!(target_os = "freebsd") => {
                "`snapshot`, `drift` and `fw rules` seal what they read into their own stores"
            }
            ActionClass::Collect => "`collect` writes the sealed evidence store",
            ActionClass::Allowlist => "`allowlist` reads what will not be responded to",
            ActionClass::Uninstall => "`uninstall` takes the agent off and leaves the evidence",
            ActionClass::Acquire => "`acquire` collects an unlinked image or injected memory",
            ActionClass::Deception => "`deceive` plants honeytokens and watches them",
            ActionClass::SidecarInstall => "`sidecar` installs a tool you brought, by digest",

            ActionClass::Harden if cfg!(target_os = "windows") => {
                "`console` sets WDigest off or the vulnerable-driver blocklist on"
            }
            ActionClass::Harden => "`console` applies a kernel tunable or an sshd drop-in",
            ActionClass::IsolateInbound => {
                "`network --arm` applies a default-deny inbound ruleset with a rollback window"
            }
            ActionClass::Isolate => {
                "`network --arm --egress` denies outbound but for DNS, DHCP and established"
            }

            ActionClass::ProcBlock => "`network --block-pid` refuses new egress from one cgroup",
            ActionClass::DestBlock => "`network --block-dest` refuses new connections to one address",

            ActionClass::PerimeterBlock => {
                "`fw block` adds a source or destination to an enrolled alias, until confirmed"
            }
            ActionClass::PerimeterStateKill => "`fw statekill` kills the matching pf states, sealed first",

            ActionClass::ServiceStart => "`service --start` enables and starts a declared unit that is down",

        })
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();

    let reachable = modules::reachable_action_count();
    let listed = match verbs.split_last() {
        None => String::new(),
        Some((last, [])) => (*last).to_string(),
        Some((last, rest)) => format!("{}, and {last}", rest.join(", ")),
    };
    match verbs.len() {
        0 => println!(
            "\n  Nothing here can act: this image observes and reports. BUILD above is\n  \
             what the variant asked for, not what the binary can do (README §9)."
        ),
        _ => println!(
            "\n  {reachable} class(es) can act: {}. Everything else observes and reports —\n  \
             BUILD above is what the variant asked for, not what the binary can do (README §9).",
            listed
        ),
    }
}

#[cfg(target_os = "linux")]
fn print_probe(json: bool) -> u8 {
    let r = hemostat_sensor_linux::probe();
    let covered = crate::coverage::probe(&crate::coverage::linux_probe_unread(&r));

    if json {
        let findings = r
            .findings
            .iter()
            .map(|f| {
                format!(
                    "{{\"check\":\"{}\",\"ok\":{},\"detail\":\"{}\"}}",
                    f.check,
                    f.ok,
                    jesc(&f.detail)
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        jprintln!(
            "{{\"effective_tier\":\"{}\",\"host_supports\":\"{}\",\"process_can\":\"{}\",\
             \"provisional\":{},\"capabilities_known\":{},\"limited_by_privilege\":{},\
             \"l1\":\"{}\",\"reboot_would_enable_l1\":{},\"lsm_boot_line\":\"{}\",\
             \"lsm_dropped\":[{}],\"trial\":\"{}\",\"trial_errno\":{},\
             \"findings\":[{findings}]}}",
            r.effective(),
            r.host_supports,
            r.process_can,
            r.provisional,
            r.capabilities_known,
            r.limited_by_privilege(),
            match &r.l1 {
                hemostat_sensor_linux::L1Availability::Active => "active",
                hemostat_sensor_linux::L1Availability::NeedsReboot { .. } => "needs-reboot",
                hemostat_sensor_linux::L1Availability::NotInKernel => "not-in-kernel",
                hemostat_sensor_linux::L1Availability::Unknown => "unknown",
            },
            matches!(r.l1, hemostat_sensor_linux::L1Availability::NeedsReboot { .. }),
            match &r.lsm_boot_line {
                hemostat_sensor_linux::LsmBootLine::Default => "default",
                hemostat_sensor_linux::LsmBootLine::Complete => "complete",
                hemostat_sensor_linux::LsmBootLine::Narrowed { .. } => "narrowed",
                hemostat_sensor_linux::LsmBootLine::Unknown => "unknown",
            },
            match &r.lsm_boot_line {
                hemostat_sensor_linux::LsmBootLine::Narrowed { dropped } => dropped
                    .iter()
                    .map(|m| format!("\"{m}\""))
                    .collect::<Vec<_>>()
                    .join(","),
                _ => String::new(),
            },

            match &r.trial {
                None => "not-attempted",
                Some(hemostat_sensor_linux::TrialAttach::Attached) => "attached",
                Some(hemostat_sensor_linux::TrialAttach::Refused { .. }) => "refused",
            },
            match &r.trial {
                Some(hemostat_sensor_linux::TrialAttach::Refused { errno, .. }) => *errno,
                _ => 0,
            }
        );
        return covered.exit_code();
    }

    println!("effective tier: {}  — {}", r.effective(), r.effective().describe());
    println!("  host supports: {}", r.host_supports);
    println!("  this process:  {}", r.process_can);
    println!(
        "  tier permits deny: {}",
        if r.effective().can_deny() { "yes" } else { "no — observe only" }
    );
    println!("  this build denies: {}", hemostat_sensor_linux::probe::BUILT_DENY);
    if r.limited_by_privilege() {
        println!(
            "\n  NOTE: the ceiling here is privilege, not the host. This host would\n\
             \x20       support {}; re-run with the required capabilities to reach it.",
            r.host_supports
        );
    }
    if !r.capabilities_known {
        println!(
            "\n  WARNING: /proc/self/status was unreadable, so the process ceiling below\n\
             \x20         is a pessimistic default, not a measurement. Is /proc mounted?"
        );
    }
    if r.provisional {
        println!(
            "\n  PROVISIONAL: preconditions only — no attach was attempted, so this\n\
             \x20             verdict is inference rather than measurement (§7.1.2)."
        );
    }

    if let Some(warning) = r.lsm_boot_line.warning() {
        println!("\n--- boot line ---\n{warning}");
    }
    if let Some(advice) = r.l1.remediation() {
        println!("\n--- remediation ---\n{advice}");
    }

    let hooks = hemostat_sensor_linux::hook_report();
    let usable = hooks.iter().filter(|h| h.state.usable()).count();
    let undetermined = hooks
        .iter()
        .filter(|h| h.state == hemostat_sensor_linux::HookState::Undetermined)
        .count();
    if undetermined == hooks.len() {
        println!("\n  hooks:         undetermined — the kernel's BTF could not be walked");
    } else {
        println!(
            "\n  hooks:         {usable} of {} usable{}  (see `hemostat hooks`)",
            hooks.len(),
            if usable == hooks.len() { "" } else { " — some capabilities degrade" }
        );
    }

    println!("\nchecks:");
    for f in &r.findings {
        println!("  [{}] {:<32} {}", if f.ok { "ok" } else { "--" }, f.check, h(&f.detail));
    }

    if let crate::coverage::Covered::InPart(why) = &covered {
        println!("\n  PARTIAL (exit 7): {why}");
    }
    covered.exit_code()
}

#[cfg(target_os = "linux")]
pub(crate) fn print_findings(
    label: &str,
    available: bool,
    reason: Option<&str>,
    findings: &[hemostat_sensor_linux::rootkit::Finding],
    json: bool,
) -> u8 {
    use hemostat_sensor_linux::rootkit::Severity;
    let code = if available { EXIT_OK } else { EXIT_PARTIAL };
    if json {
        let f = findings
            .iter()
            .map(|f| {
                rootkit_row(f)
            })
            .collect::<Vec<_>>()
            .join(",");
        jprintln!(
            "{{\"check\":\"{}\",\"available\":{},\"reason\":\"{}\",\"findings\":[{f}]}}",
            jesc(label),
            available,
            jesc(reason.unwrap_or(""))
        );
        return code;
    }
    if !available {
        println!("{label}: DID NOT RUN");
        println!("  {}", reason.unwrap_or("unavailable"));
        return code;
    }
    let crit = findings.iter().filter(|f| f.severity == Severity::Critical).count();
    let warn = findings.iter().filter(|f| f.severity == Severity::Warn).count();
    println!("{label}: {} finding(s), {crit} CRITICAL, {warn} WARN", findings.len());
    println!();
    for f in findings {
        println!("  [{}] {}", f.severity.tag(), h(&f.subject));
        println!("      {}", h(&f.what));
        println!("      why: {}", h(&f.why));
    }
    code
}

#[cfg(all(target_os = "linux", feature = "mod-remote"))]
pub(crate) const LINK_KEY: &str = "/var/lib/hemostat/link.key";

#[cfg(all(target_os = "windows", feature = "mod-remote"))]
pub(crate) const LINK_KEY: &str = r"C:\ProgramData\hemostat\link.key";

#[cfg(all(target_os = "linux", feature = "mod-remote"))]
pub(crate) fn load_or_create_link_key(path: &std::path::Path) -> Result<([u8; 32], Option<String>), String> {
    use std::io::{Read as _, Write as _};
    use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _, PermissionsExt as _};

    let shown = path.display();
    match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
    {
        Ok(mut f) => {
            let md = f.metadata().map_err(|e| format!("cannot examine {shown}: {e}"))?;
            if !md.is_file() || md.len() != 32 {
                return Err(format!(
                    "{shown} is not a 32-byte key file. Refusing to use it; remove it to have a \
                     new key generated, and re-pin the console"
                ));
            }
            if md.permissions().mode() & 0o077 != 0 {
                return Err(format!(
                    "{shown} is readable by more than its owner (mode {:o}). A link key others \
                     can read is not a secret; refusing to use it",
                    md.permissions().mode() & 0o777
                ));
            }
            let mut key = [0_u8; 32];
            f.read_exact(&mut key).map_err(|e| format!("cannot read {shown}: {e}"))?;
            Ok((key, None))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let key = crate::identity::rand32().map_err(|e| {
                format!("no entropy for the link key ({e}); refusing to make one up")
            })?;
            let kept = (|| -> std::io::Result<()> {
                if let Some(dir) = path.parent() {
                    std::fs::DirBuilder::new().recursive(true).mode(0o700).create(dir)?;
                }
                let mut f = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .custom_flags(libc::O_NOFOLLOW)
                    .open(path)?;
                f.write_all(&key)?;
                f.sync_all()
            })();
            Ok((
                key,
                kept.err().map(|e| {
                    format!(
                        "the key could not be kept at {shown} ({e}), so it lasts for this run \
                         only — a console that pins it will have to re-pin after a restart"
                    )
                }),
            ))
        }
        Err(e) => Err(format!(
            "cannot open {shown} ({e}). A link where the key should be is refused, not followed"
        )),
    }
}

#[cfg(all(target_os = "windows", feature = "mod-remote"))]
pub(crate) fn load_or_create_link_key(path: &std::path::Path) -> Result<([u8; 32], Option<String>), String> {
    use hemostat_sensor_win::acl;
    use std::io::{Read as _, Write as _};
    use std::os::windows::fs::OpenOptionsExt as _;

    const OPEN_REPARSE_POINT: u32 = 0x0020_0000;

    let shown = path.display();
    let text = path.to_str().ok_or_else(|| format!("{shown} is not valid UTF-16 text"))?;
    let beyond = |what: &str, p: &str| -> Result<(), String> {
        match acl::dacl_of_read(p) {
            Ok(aces) => match acl::grantee_beyond_admins(&aces) {
                None => Ok(()),
                Some(sid) => Err(format!(
                    "{what} {p} grants access to {sid}, not only to SYSTEM and Administrators. A link key \
                     others can read is not a secret"
                )),
            },
            Err(rc) => Err(format!("the DACL of {what} {p} could not be read (error {rc})")),
        }
    };
    match std::fs::OpenOptions::new().read(true).custom_flags(OPEN_REPARSE_POINT).open(path) {
        Ok(mut f) => {
            let md = f.metadata().map_err(|e| format!("cannot examine {shown}: {e}"))?;
            if md.file_type().is_symlink() || !md.is_file() || md.len() != 32 {
                return Err(format!(
                    "{shown} is not a 32-byte key file. Refusing to use it; remove it to have a \
                     new key generated, and re-pin the console"
                ));
            }
            beyond("the key file", text).map_err(|e| format!("{e}; refusing to use it"))?;
            let mut key = [0_u8; 32];
            f.read_exact(&mut key).map_err(|e| format!("cannot read {shown}: {e}"))?;
            Ok((key, None))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let key = crate::identity::rand32().map_err(|e| {
                format!("no entropy for the link key ({e}); refusing to make one up")
            })?;
            let kept = (|| -> Result<(), String> {
                let dir = path.parent().and_then(std::path::Path::to_str).filter(|d| !d.is_empty()).ok_or("it has no directory")?;
                crate::push::private_dir(dir)?;
                beyond("its directory", dir)?;
                let mut f = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(path)
                    .map_err(|e| e.to_string())?;
                f.write_all(&key).map_err(|e| e.to_string())?;
                f.sync_all().map_err(|e| e.to_string())
            })();
            Ok((
                key,
                kept.err().map(|e| {
                    format!(
                        "the key could not be kept at {shown} ({e}), so it lasts for this run \
                         only — a collector that enrolls it will refuse this host after a restart"
                    )
                }),
            ))
        }
        Err(e) => Err(format!("cannot open {shown} ({e})")),
    }
}

#[cfg(all(target_os = "linux", feature = "mod-remote"))]
fn print_remote(beacon: Option<&str>, key: Option<&str>, seconds: u64) -> u8 {
    use hemostat_remote::{link, liveness, Message, BEACON_INTERVAL};
    use hemostat_remote::{PublicKey, StaticSecret};

    let Some(key_hex) = key else {
        eprintln!(
            "hemostat remote --console-key <64 hex> --beacon HOST:PORT [--seconds N]\n\n  \
             The console's X25519 public key is pinned and not optional. On a compromised host \
             \"whoever answers on that port\" is not an identity, and a link that accepts the \
             key it is offered is a link to whoever got there first.\n\n  \
             Frames are HPKE-sealed in auth mode (RFC 9180, X25519 + AES-256-GCM) using this\n  \
             tree's own crypto, so each end opens only what the other's pinned key sent. There is no TLS and no certificate authority: a console for this speaks\n  \
             this protocol and nothing else.\n\n  \
             --beacon sends a heartbeat every {}s. The gap when it stops is the durable\n  \
             evidence that the agent was killed — it is what an on-box attacker cannot\n  \
             suppress, because it is an absence somewhere they are not.",
            BEACON_INTERVAL.as_secs()
        );
        return EXIT_USAGE;
    };
    let Some(console_pk) = parse_hex32(key_hex).map(PublicKey::from) else {
        eprintln!("hemostat remote: --console-key must be 64 hex characters");
        return EXIT_USAGE;
    };

    let (seed, not_kept) = match load_or_create_link_key(std::path::Path::new(LINK_KEY)) {
        Ok(k) => k,
        Err(why) => {
            eprintln!("hemostat remote: {why}");
            return EXIT_FAILED;
        }
    };
    let agent_sk = StaticSecret::from(seed);
    let agent_pk = PublicKey::from(&agent_sk);

    println!("remote — the console link\n");
    println!("  this agent's public key: {}", hex32(agent_pk.as_bytes()));
    println!("  pin that at the console, the way you pinned its key here.\n");
    if let Some(note) = not_kept {
        println!("  NOTE: {note}\n");
    }

    let Some(to) = beacon else {
        eprintln!(
            "hemostat remote: give --beacon HOST:PORT. The agent only ever dials out; there is \
             no listen mode (RFC-003)"
        );
        return EXIT_USAGE;
    };

    println!("  beaconing to {to} every {}s for {seconds}s.", BEACON_INTERVAL.as_secs());
    println!(
        "  If these stop arriving for {}s, the console should treat this host as compromised\n           and the agent as gone.\n",
        liveness::Liveness::dead_after().as_secs()
    );

    let Ok(run_seed) = rand32() else {
        eprintln!("hemostat remote: no entropy for a run id; not beaconing");
        return EXIT_ENFORCER;
    };
    let run = u64::from_be_bytes([
        run_seed[0], run_seed[1], run_seed[2], run_seed[3], run_seed[4], run_seed[5], run_seed[6], run_seed[7],
    ]);
    let started = std::time::Instant::now();
    let deadline = started + std::time::Duration::from_secs(seconds);
    let mut seq = 0_u64;
    let mut sent = 0_usize;
    let mut failed = 0_usize;
    while std::time::Instant::now() < deadline {
        seq += 1;

        let Ok(eph_seed) = rand32() else {
            eprintln!("hemostat remote: no entropy for an ephemeral key; stopping");
            return EXIT_ENFORCER;
        };
        let eph = StaticSecret::from(eph_seed);
        let msg = Message::Heartbeat {
            run,
            seq,
            uptime_secs: started.elapsed().as_secs(),

            wall_ns: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| i64::try_from(d.as_nanos()).unwrap_or(i64::MAX))
                .unwrap_or(0),
        };
        match link::beacon(to, &console_pk, &agent_sk, &msg, &eph) {
            Ok(()) => sent += 1,
            Err(e) => {
                failed += 1;
                eprintln!("  beacon {seq} failed: {}", h(&e.message()));
            }
        }
        std::thread::sleep(BEACON_INTERVAL);
    }

    println!();
    println!("{sent} beacon(s) sent, {failed} failed.");
    if failed == 0 {
        EXIT_OK
    } else {
        EXIT_PARTIAL
    }
}
