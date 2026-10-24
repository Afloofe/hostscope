#[cfg(target_os = "linux")]
use std::process::ExitCode;
#[cfg(target_os = "linux")]
use crate::remedy::require_built;
#[cfg(target_os = "linux")]
use crate::views::journal_one;
#[cfg(target_os = "linux")]
use crate::{EXIT_DRYRUN, EXIT_ENFORCER, EXIT_FAILED, EXIT_NOT_BUILT, EXIT_POLICY};
#[cfg(target_os = "linux")]
use crate::render::{h, json_str, rootkit_row};
#[cfg(all(target_os = "linux", feature = "mod-sidecar"))]
use crate::render::hl;
#[cfg(target_os = "linux")]
use crate::{EXIT_OK, EXIT_PARTIAL, EXIT_USAGE};

#[cfg(target_os = "linux")]
pub(crate) fn print_allowlist(json: bool, check: Option<&str>) -> u8 {
    use hemostat_broker::allowlist::Allowlist;

    if let Err(msg) = require_built(hemostat_buildinfo::ActionClass::Allowlist) {
        eprintln!("hemostat allowlist: {msg}");
        return EXIT_NOT_BUILT;
    }

    let (a, path) = Allowlist::load();

    if json {
        let rows: Vec<String> = a
            .entries
            .iter()
            .map(|e| {
                format!(
                    "{{\"class\":{},\"target\":{},\"reason\":{},\"who\":{},\"line\":{}}}",
                    e.class.map_or("null".to_string(), |c| json_str(c.name())),
                    json_str(&e.target),
                    json_str(&e.reason),
                    json_str(&e.who),
                    e.line
                )
            })
            .collect();
        jprintln!(
            "{{\"path\":{},\"entries\":[{}],\"malformed\":{}}}",
            path.as_ref().map_or("null".to_string(), |p| json_str(p)),
            rows.join(","),
            a.malformed.len()
        );
        return if a.malformed.is_empty() { EXIT_OK } else { EXIT_PARTIAL };
    }

    println!("allowlist — what this host will NOT respond to, and who said so\n");
    println!("  {}\n", h(&a.coverage(path.as_deref())));

    for e in &a.entries {
        println!("  {}", h(&e.to_string()));
    }
    if a.entries.is_empty() {
        println!("  (no entries — every finding gets the response its class would normally get)");
    }
    if !a.malformed.is_empty() {
        println!();
        println!("  LINES THAT SUPPRESS NOTHING:");
        for m in &a.malformed {
            println!("    line {}: {}", m.line, h(&m.problem));
            println!("      {}", h(m.text.trim()));
        }
    }

    if let Some(target) = check {
        println!();
        let mut covered = false;
        for class in hemostat_buildinfo::ActionClass::ALL {
            if let Some(e) = a.judge(class, target, true) {
                println!("  {target}: a rule-fired {} would be SUPPRESSED by {}", class.name(), h(&e.to_string()));
                covered = true;
            }
        }
        if !covered {
            println!("  {target}: nothing here covers it — every class would be responded to");
        }
        println!(
            "  (an OPERATOR is never suppressed: a responder who types a command has already \
             decided, and a file somebody wrote last week is not a second opinion.)"
        );
    }

    println!();
    println!(
        "  Entries are added with an editor, by a person. This verb does not write them:\n  \
         a tool that could append an exemption is a tool an intruder could use to write\n  \
         themselves one."
    );
    if a.malformed.is_empty() {
        EXIT_OK
    } else {
        EXIT_PARTIAL
    }
}

#[cfg(all(target_os = "linux", feature = "mod-sidecar"))]
pub(crate) fn print_sidecar(name: Option<&str>, from: Option<&str>, sha: Option<&str>, armed: bool) -> u8 {
    use hemostat_enforce_linux::sidecar::{self, Supplied};
    use hemostat_enforce_linux::{ApplyOptions, Outcome};

    if let Err(msg) = require_built(hemostat_buildinfo::ActionClass::SidecarInstall) {
        eprintln!("hemostat sidecar: {msg}");
        return EXIT_NOT_BUILT;
    }

    let (Some(name), Some(from), Some(sha)) = (name, from, sha) else {
        println!("sidecar — install a tool you brought with you\n");
        for k in sidecar::CATALOGUE {
            println!("  {}  ->  {}", k.name, k.install_to);
            println!("    gives: {}", h(k.gives));
            println!("    costs: {}", h(k.costs));
        }
        println!();
        println!(
            "  hemostat sidecar --install <name> --from <path> --sha256 <digest> [--arm]\n\n  \
             The digest is NOT optional. This agent runs on a host somebody else currently has\n  \
             root on, so every path here is under their control — including the one you just\n  \
             copied your tools to. Installing from a path on the host you are responding to is\n  \
             installing whatever they left there, as root, at your request. A digest you had\n  \
             before you arrived makes where the bytes sit irrelevant, which is why it is the\n  \
             only rule.\n\n  \
             HEMOSTAT fetches nothing. There is no download and no mirror."
        );
        return EXIT_USAGE;
    };

    let supplied = Supplied {
        path: std::path::PathBuf::from(from),
        declared_sha256: sha.to_string(),
    };
    let ticket = match crate::authz::armed_gate("sidecar", hemostat_buildinfo::ActionClass::SidecarInstall, armed, 1) {
        Ok(t) => t,
        Err(code) => return code,
    };
    if let Err(code) = crate::authz::spend_armed("sidecar", armed, ticket) {
        return code;
    }
    let opts = if armed { ApplyOptions::armed() } else { ApplyOptions::dry_run() };
    match sidecar::apply(name, &supplied, &opts) {
        Outcome::Planned(p) => {
            println!("{}", h(&p.summary));
            println!("  {}", hl(&p.detail));
            println!();
            println!("Nothing was installed. Add --arm.");
            EXIT_DRYRUN
        }
        Outcome::Applied(rec) => journal_or_fail(&rec),
        Outcome::Refused(r) => {
            eprintln!("hemostat sidecar: {}", hl(&r.message));
            EXIT_POLICY
        }
        Outcome::Failed(f) => {
            eprintln!("hemostat sidecar: {}", hl(&f.reason));
            EXIT_ENFORCER
        }
    }
}

#[cfg(all(target_os = "linux", feature = "mod-deceive"))]
pub(crate) fn print_deceive(armed: bool, watch_secs: Option<u64>, remove: bool, list: bool) -> u8 {
    use hemostat_enforce_linux::deceive::{self, MARKER};
    use hemostat_enforce_linux::{ApplyOptions, Outcome};

    if let Err(msg) = require_built(hemostat_buildinfo::ActionClass::Deception) {
        eprintln!("hemostat deceive: {msg}");
        return EXIT_NOT_BUILT;
    }

    let homes: Vec<std::path::PathBuf> = hemostat_sensor_linux::saferead::read_scan_target(std::path::Path::new("/etc/passwd"))
        .unwrap_or_default()
        .lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split(':').collect();
            let uid: u32 = f.get(2)?.parse().ok()?;
            if !(1000..60_000).contains(&uid) {
                return None;
            }
            f.get(5).map(std::path::PathBuf::from)
        })
        .filter(|p| p.is_dir())
        .collect();

    if list || remove {
        let planted = deceive::find_planted(&homes);
        if planted.is_empty() {
            println!("No canary planted by this tool is still on the host.");
            return EXIT_OK;
        }
        println!("{} canary/canaries still planted:\n", planted.len());
        for p in &planted {
            println!("  {}", h(&p.display().to_string()));
        }
        if !remove {
            println!("\n  `--remove --arm` deletes them. Leaving one behind is litter with a");
            println!("  plausible story attached, and the next person to find it will not know.");
            return EXIT_OK;
        }
        println!();
        let opts = if armed { ApplyOptions::armed() } else { ApplyOptions::dry_run() };
        let mut left = 0_usize;
        for p in &planted {
            match deceive::undo_remove(p, &opts) {
                Outcome::Applied(rec) => println!("  {}", h(&rec.did)),
                Outcome::Planned(pl) => println!("  would: {}", h(&pl.summary)),
                Outcome::Refused(r) => {
                    left += 1;
                    println!("  [refused] {}", h(&r.message));
                }
                Outcome::Failed(f) => {
                    left += 1;
                    eprintln!("  [FAILED] {}", h(&f.reason));
                }
            }
        }
        if !armed {
            println!("\nNothing was removed. Add --arm.");
            return EXIT_DRYRUN;
        }
        return if left == 0 { EXIT_OK } else { EXIT_PARTIAL };
    }

    println!("deceive — inert credentials an intruder reads, and a tripwire on the reading\n");

    let only_watching = watch_secs.is_some() && !armed;

    let mut planting = EXIT_OK;
    if !only_watching {
        let tokens = deceive::catalogue(&homes);
        let ticket = match crate::authz::armed_gate("deceive", hemostat_buildinfo::ActionClass::Deception, armed, 1) {
            Ok(t) => t,
            Err(code) => return code,
        };
        if let Err(code) = crate::authz::spend_armed("deceive", armed, ticket) {
            return code;
        }
        let opts = if armed { ApplyOptions::armed() } else { ApplyOptions::dry_run() };
        let mut unjournalled = false;
        let (mut planted, mut failed) = (0_usize, 0_usize);
        for t in &tokens {
            match deceive::apply(t, &opts) {
                Outcome::Applied(rec) => {
                    planted += 1;
                    if journal_or_fail(&rec) != EXIT_OK {
                        unjournalled = true;
                    }
                }
                Outcome::Planned(p) => println!("  would plant: {}", h(&p.summary)),
                Outcome::Refused(r) => println!("  [skipped] {}", h(&r.message)),
                Outcome::Failed(f) => {
                    failed += 1;
                    eprintln!("  [FAILED] {}", h(&f.reason));
                }
            }
        }
        println!();
        println!(
            "  Every token carries `{MARKER}`, authenticates nothing, and is listed by\n  \
             `deceive --list`. Remove them all with `deceive --remove --arm` before you leave."
        );

        if !armed {
            println!("\nNothing was planted. Add --arm.");
            return EXIT_DRYRUN;
        }
        if unjournalled {
            eprintln!("  A canary was planted without an undo record; `deceive --list` still finds it.");
            return EXIT_FAILED;
        }
        planting = planting_exit(planted, failed);
        if failed > 0 {
            eprintln!("\n  {failed} of {} canaries could NOT be planted (above).", planted + failed);
        }
    }

    let Some(secs) = watch_secs else {
        println!();
        println!(
            "  NOT WATCHED. A canary nobody watches is a file — add `--watch N` to hold a\n  \
             read-watch on them for N seconds, or arrange your own monitoring of these paths."
        );
        return planting;
    };

    let all = deceive::find_planted(&homes);
    if all.is_empty() && planting == EXIT_ENFORCER {
        eprintln!("\nhemostat deceive: nothing to watch — every canary failed to plant.");
        return EXIT_ENFORCER;
    }
    if all.is_empty() {
        eprintln!(
            "\nhemostat deceive: there is nothing planted to watch. Plant with `--arm` first — \
             a watch over no files would sit quietly for {secs}s and tell you nothing, which \
             reads exactly like a watch that saw nothing happen"
        );
        return EXIT_PARTIAL;
    }
    let watch = match hemostat_sensor_linux::fanotify::arm_files(&all) {
        Ok(w) => w,
        Err(e) => {
            eprintln!("\nhemostat deceive: the tripwire could not be armed — {}", h(&e.message()));
            eprintln!("The tokens ARE planted; nothing is watching them.");
            return EXIT_PARTIAL;
        }
    };
    println!();
    println!("  {}", h(&watch.coverage()));
    println!("  Anything below is a read of a file nothing legitimate opens.\n");

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(secs);
    let mut hits = 0_usize;
    let mut lost_said = 0_u32;
    while std::time::Instant::now() < deadline {
        let events = watch.drain(500);
        if watch.overflowed() > lost_said {
            lost_said = watch.overflowed();
            println!(
                "  !! reads LOST here: the kernel's event queue overflowed and dropped what did \
                 not fit. A canary read may be among them."
            );
        }
        for ev in events {
            hits += 1;
            println!("{}", canary_line(&ev.path, ev.pid, &comm_of(ev.pid)));
        }
    }
    println!();
    println!("{hits} canary read(s) in {secs}s.");

    if watch.overflowed() > 0 {
        println!(
            "Reads were LOST: the kernel's event queue overflowed {} time(s), so this is a \
             PARTIAL result.",
            watch.overflowed()
        );
        return if planting == EXIT_OK { EXIT_PARTIAL } else { planting };
    }
    planting
}

#[cfg(all(target_os = "linux", feature = "mod-deceive"))]
fn planting_exit(planted: usize, failed: usize) -> u8 {
    match (planted, failed) {
        (_, 0) => EXIT_OK,
        (0, _) => EXIT_ENFORCER,
        _ => EXIT_PARTIAL,
    }
}

#[cfg(all(target_os = "linux", feature = "mod-deceive"))]
fn canary_line(path: &std::path::Path, pid: u32, who: &str) -> String {
    format!(
        "  *** CANARY READ: {} by pid {pid} ({}) ***",
        h(&path.display().to_string()),
        h(who)
    )
}

#[cfg(all(target_os = "linux", any(feature = "mod-deceive", feature = "mod-sensor-fanotify")))]
pub(crate) fn comm_of(pid: u32) -> String {
    std::fs::read(format!("/proc/{pid}/comm"))
        .map_or_else(|_| "?".into(), |c| String::from_utf8_lossy(&c).trim().to_string())
}

#[cfg(all(target_os = "linux", feature = "mod-acquire"))]
pub(crate) fn print_acquire(pid: Option<u32>, into: &str, armed: bool) -> u8 {
    use hemostat_enforce_linux::acquire::{self, Subject};
    use hemostat_enforce_linux::{ApplyOptions, Outcome};

    if let Err(msg) = require_built(hemostat_buildinfo::ActionClass::Acquire) {
        eprintln!("hemostat acquire: {msg}");
        return EXIT_NOT_BUILT;
    }

    let Some(pid) = pid else {
        eprintln!(
            "hemostat acquire --pid N [--into DIR] [--arm]\n\n  \
             Collects the two things a filesystem sweep cannot: the image of a process whose\n  \
             file has been unlinked, and executable memory with no file behind it. Both stop\n  \
             existing when the process does. Find candidates with:\n    \
             hemostat query 'SELECT pid, comm FROM processes WHERE deleted = 1'\n    \
             hemostat query 'SELECT pid, comm FROM memory_regions WHERE executable = 1 AND \
             anonymous = 1'"
        );
        return EXIT_USAGE;
    };

    let acquire::Survey { subjects, gap } = match acquire::survey(pid) {
        Ok(s) => s,
        Err(why) => {
            eprintln!("hemostat acquire: {why}");
            return EXIT_POLICY;
        }
    };

    if let Some(gap) = &gap {
        println!("  [partial] {}\n", h(gap));
    }

    let urgent: Vec<&Subject> = subjects
        .iter()
        .filter(|s| {
            matches!(s, Subject::Image { deleted: true, .. } | Subject::AnonymousExec { .. })
        })
        .collect();
    if urgent.is_empty() && gap.is_some() {

        println!(
            "nothing that only exists here was found in the part of pid {pid}'s map that was read.\n\
             The rest was not examined, so this is not a clean result."
        );
        return EXIT_PARTIAL;
    }
    if urgent.is_empty() {
        println!(
            "pid {pid} has nothing that only exists here: its image is on disk and it has no\n\
             executable memory without a file behind it. Collect the binary from the filesystem\n\
             instead — this verb is for what a sweep cannot reach."
        );
        return EXIT_OK;
    }

    let dir = std::path::Path::new(into);
    println!("acquire — pid {pid}, {} artefact(s)\n", urgent.len());

    let ticket = match crate::authz::armed_gate("acquire", hemostat_buildinfo::ActionClass::Acquire, armed, 1) {
        Ok(t) => t,
        Err(code) => return code,
    };
    if let Err(code) = crate::authz::spend_armed("acquire", armed, ticket) {
        return code;
    }
    let opts = if armed { ApplyOptions::armed() } else { ApplyOptions::dry_run() };
    let mut failed = 0_usize;
    let mut taken = 0_usize;
    let mut refused = 0_usize;
    for s in &urgent {
        match acquire::apply(pid, s, dir, &opts) {
            Outcome::Planned(p) => {
                println!("  {}", h(&p.summary));
                println!("    {}", h(&p.detail));
            }
            Outcome::Applied(rec) => {
                taken += 1;
                println!("  {}", h(&rec.did));
            }
            Outcome::Refused(r) => {
                refused += 1;
                println!("  [refused] {}", h(&r.message));
            }
            Outcome::Failed(f) => {
                failed += 1;
                eprintln!("  [FAILED] {}", h(&f.reason));
            }
        }
        println!();
    }

    if !armed {
        println!("Nothing was read. Add --arm to collect.");
        return EXIT_DRYRUN;
    }
    println!("{taken} artefact(s) written to {into}.");
    if failed > 0 {
        println!(
            "{failed} could NOT be read, so this collection is INCOMPLETE — and what it could \
             not reach may be the part that mattered."
        );
    }
    if refused > 0 {
        println!(
            "{refused} artefact(s) refused and NOT collected, so this collection is INCOMPLETE \
             — each [refused] line above says why, and what to do instead before the process \
             exits."
        );
    }
    if gap.is_some() {
        println!(
            "pid {pid}'s map was examined only in part, so this collection may be INCOMPLETE — \
             see [partial] above."
        );
    }
    match acquire_exit(taken, failed, refused) {
        EXIT_OK if gap.is_some() => EXIT_PARTIAL,
        code => code,
    }
}

#[cfg(all(target_os = "linux", feature = "mod-acquire"))]
fn acquire_exit(taken: usize, failed: usize, refused: usize) -> u8 {
    match (taken, failed, refused) {
        (_, 0, 0) => EXIT_OK,
        (0, 0, _) => EXIT_POLICY,
        _ => EXIT_PARTIAL,
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn print_uninstall(armed: bool) -> u8 {
    use hemostat_enforce_linux::{uninstall, ApplyOptions, Outcome};

    if let Err(msg) = require_built(hemostat_buildinfo::ActionClass::Uninstall) {
        eprintln!("hemostat uninstall: {msg}");
        return EXIT_NOT_BUILT;
    }

    match crate::authz::reversal_authority(hemostat_evcrypto::ticket::Op::Uninstall, armed) {
        Ok(None) => {}
        Ok(Some(gap)) => eprintln!("hemostat uninstall: NOTE: {gap}"),
        Err((code, why)) => {
            eprintln!("hemostat uninstall: {why}");
            return code;
        }
    }

    let s = uninstall::survey();
    let opts = if armed { ApplyOptions::armed() } else { ApplyOptions::dry_run() };
    match uninstall::apply(&s, &opts) {
        Outcome::Planned(p) => {
            println!("{}", h(&p.summary));
            println!("  {}", h(&p.detail));
            println!();
            if s.is_empty() {
                return EXIT_OK;
            }
            println!("Nothing was changed. Add --arm to remove them.");
            EXIT_DRYRUN
        }
        Outcome::Applied(rec) => journal_or_fail(&rec),
        Outcome::Refused(r) => {
            eprintln!("hemostat uninstall: {}", h(&r.message));
            EXIT_POLICY
        }
        Outcome::Failed(f) => {
            eprintln!("hemostat uninstall: {}", h(&f.reason));
            EXIT_ENFORCER
        }
    }
}

#[cfg(target_os = "linux")]
fn harden_boot_build_gate() -> Result<(), String> {
    use hemostat_buildinfo::ModuleId::HardenReboot;
    if hemostat_modules::is_built(HardenReboot) {
        Ok(())
    } else {
        Err(hemostat_modules::module_refusal(HardenReboot, crate::MANIFEST.variant))
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn print_harden_boot(args: &[String]) -> u8 {
    use hemostat_enforce_linux::bootparam as bp;
    use hemostat_enforce_linux::{ApplyOptions, Outcome};

    if let Err(msg) = harden_boot_build_gate() {
        eprintln!("hemostat harden-boot: {msg}");
        return EXIT_NOT_BUILT;
    }

    let loader = bp::detect();
    let want = args
        .iter()
        .position(|a| a == "--set")
        .and_then(|i| args.get(i + 1))
        .map(String::as_str);

    let Some(want) = want else {
        println!("Kernel parameters, and whether this host already boots with them:");
        println!();
        for p in bp::CATALOGUE {
            println!("  [{}] {}", if bp::in_effect(p) { "on " } else { "OFF" }, p.spelling);
            println!("        buys:  {}", p.buys);
            println!("        costs: {}", p.breaks);
        }
        println!();
        match &loader {
            bp::Bootloader::Grub { defaults, generator, .. } => println!(
                "Bootloader: GRUB — {}, regenerated with {}",
                h(&defaults.display().to_string()),
                h(&generator.display().to_string())
            ),
            bp::Bootloader::SystemdBoot { entries } => println!(
                "Bootloader: systemd-boot, {} entry file(s). These are NOT edited here — see \
                 `--set` for why.",
                entries.len()
            ),
            bp::Bootloader::Refind { config, uki } => println!(
                "Bootloader: rEFInd — command lines in {}{}. These are NOT edited here; see \
                 `--set` for why.",
                h(&config.display().to_string()),
                if *uki { ", booting a unified kernel image" } else { "" }
            ),
            bp::Bootloader::Unknown => println!(
                "Bootloader: not recognised. Nothing here can be applied on this host; the \
                 parameters above still say what to add by hand."
            ),
        }
        println!();
        println!("{}", bp::not_yet());
        println!();
        println!("To set one:  hemostat harden-boot --set <parameter> [--arm]");
        return EXIT_OK;
    };

    let Some(p) = bp::param(want) else {
        eprintln!(
            "hemostat harden-boot: `{want}` is not in the catalogue. This verb does not take \
             free text: a typo on the kernel command line is a host that does not boot, and \
             there is no way to validate an arbitrary parameter against a kernel that is not \
             running yet.\n  It takes: {}",
            bp::CATALOGUE.iter().map(|p| p.spelling).collect::<Vec<_>>().join(", ")
        );
        return EXIT_USAGE;
    };

    let armed = args.iter().any(|a| a == "--arm");
    let ticket = match crate::authz::armed_gate_at_boot("harden-boot", hemostat_buildinfo::ActionClass::Harden, armed, 1) {
        Ok(t) => t,
        Err(code) => return code,
    };
    if let Err(code) = crate::authz::spend_armed("harden-boot", armed, ticket) {
        return code;
    }
    let opts = if armed { ApplyOptions::armed() } else { ApplyOptions::dry_run() };
    match bp::apply(p, &opts, &loader) {
        Outcome::Planned(plan) => {
            println!("{}", h(&plan.summary));
            println!("  {}", h(&plan.detail));
            println!("  undo: {}", h(&plan.undo));
            println!();
            println!("Nothing was changed. Add --arm to apply.");
            EXIT_DRYRUN
        }
        Outcome::Refused(r) => {
            eprintln!("hemostat harden-boot: {}", h(&r.message));
            EXIT_POLICY
        }
        Outcome::Failed(f) => {
            eprintln!("hemostat harden-boot: {} failed: {}", h(&f.action), h(&f.reason));
            EXIT_ENFORCER
        }
        Outcome::Applied(rec) => journal_or_fail(&rec),
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn print_exec_block(args: &[String], operands: &[&str]) -> u8 {
    use hemostat_enforce_linux::exec;
    use hemostat_enforce_linux::{ApplyOptions, Outcome, ProtectSet};

    let has = |f: &str| args.iter().any(|a| a == f);
    let val = |f: &str| {
        args.iter().position(|a| a == f).and_then(|i| args.get(i + 1)).map(String::as_str)
    };

    if let Err(msg) = require_built(hemostat_buildinfo::ActionClass::ExecBlock) {
        eprintln!("hemostat exec-block: {msg}");
        return EXIT_NOT_BUILT;
    }

    let typed = match val("--pid") {
        Some(p) => {
            let Ok(pid) = p.parse::<u32>() else {
                eprintln!("hemostat exec-block: --pid takes a number, not {p:?}");
                return EXIT_USAGE;
            };
            match exec::image_of(pid) {
                Ok(p) => p,
                Err(why) => {
                    eprintln!("hemostat exec-block: {why}");
                    return EXIT_POLICY;
                }
            }
        }
        None => match operands.iter().find(|a| !a.starts_with("--")) {
            Some(p) => std::path::PathBuf::from(*p),
            None => {
                eprintln!(
                    "hemostat exec-block <path> [--arm]\n\
                     hemostat exec-block --pid <pid> [--arm]   resolve the path from a process\n\
                     hemostat exec-block <path> --lift         remove a bind-mount block"
                );
                return EXIT_USAGE;
            }
        },
    };

    let path = exec::resolve(&typed);
    if path != typed {
        println!(
            "{} resolves to {} — that is the file judged and acted on.\n",
            h(&typed.display().to_string()),
            h(&path.display().to_string())
        );
    }

    let armed = has("--arm");

    if has("--lift") {
        match crate::authz::reversal_authority(hemostat_evcrypto::ticket::Op::Lift, armed) {
            Ok(None) => {}
            Ok(Some(gap)) => eprintln!("hemostat exec-block: NOTE: {gap}"),
            Err((code, why)) => {
                eprintln!("hemostat exec-block: {why}");
                return code;
            }
        }
    } else {
        let ticket = match crate::authz::armed_gate("exec-block", hemostat_buildinfo::ActionClass::ExecBlock, armed, 1) {
            Ok(t) => t,
            Err(code) => return code,
        };
        if let Err(code) = crate::authz::spend_armed("exec-block", armed, ticket) {
            return code;
        }
    }
    let opts = if armed { ApplyOptions::armed() } else { ApplyOptions::dry_run() };
    let protect = ProtectSet::gather();

    let mechanism = exec::judge_mechanism(exec::can_bind_mount());
    let outcome = if has("--lift") {
        exec::undo_unmount(&path, &opts)
    } else {
        exec::apply(&path, &opts, &protect, mechanism)
    };

    match outcome {
        Outcome::Planned(plan) => {
            println!("{}", h(&plan.summary));
            println!("  {}", h(&plan.detail));
            println!("  undo: {}", h(&plan.undo));
            println!();
            println!("Nothing was changed. Add --arm to apply.");
            EXIT_DRYRUN
        }
        Outcome::Refused(r) => {
            eprintln!("hemostat exec-block: {}", h(&r.message));
            EXIT_POLICY
        }
        Outcome::Failed(f) => {
            eprintln!("hemostat exec-block: {} failed: {}", h(&f.action), h(&f.reason));
            EXIT_ENFORCER
        }
        Outcome::Applied(rec) => {
            let code = journal_or_fail(&rec);

            if !has("--lift") {
                println!("{}", exec::evidence_note(&path, mechanism));
            }
            code
        }
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn start_service(unit: &str, args: &[String]) -> u8 {
    use hemostat_enforce_linux::{ApplyOptions, Outcome, ProtectSet, RemovalAction};

    if let Err(msg) = require_built(hemostat_buildinfo::ActionClass::ServiceStart) {
        eprintln!("hemostat services: {msg}");
        return EXIT_NOT_BUILT;
    }

    let armed = args.iter().any(|a| a == "--arm");
    let ticket =
        match crate::authz::armed_gate("services", hemostat_buildinfo::ActionClass::ServiceStart, armed, 1) {
            Ok(t) => t,
            Err(code) => return code,
        };
    if let Err(code) = crate::authz::spend_armed("services", armed, ticket) {
        return code;
    }

    let opts = if armed { ApplyOptions::armed() } else { ApplyOptions::dry_run() };
    let protect = ProtectSet::gather();
    match (RemovalAction::StartService { unit: unit.to_string() }).apply(&opts, &protect) {
        Outcome::Planned(plan) => {
            println!("{}", h(&plan.summary));
            println!("  {}", h(&plan.detail));
            println!("  undo: {}", h(&plan.undo));
            println!();
            println!("Nothing was changed. Add --arm to apply.");
            EXIT_DRYRUN
        }
        Outcome::Refused(r) => {
            eprintln!("hemostat services: {}", h(&r.message));
            EXIT_POLICY
        }
        Outcome::Failed(f) => {
            eprintln!("hemostat services: {} failed: {}", h(&f.action), h(&f.reason));
            EXIT_ENFORCER
        }
        Outcome::Applied(rec) => journal_or_fail(&rec),
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn print_account(args: &[String], user: Option<&str>) -> u8 {
    use hemostat_buildinfo::ActionClass;
    use hemostat_enforce_linux::account::{self, AccountAction};
    use hemostat_enforce_linux::{ApplyOptions, Outcome, ProtectSet};

    let has = |f: &str| args.iter().any(|a| a == f);
    let val = |f: &str| {
        args.iter().position(|a| a == f).and_then(|i| args.get(i + 1)).map(String::as_str)
    };

    let Some(user) = user.filter(|u| !u.starts_with("--")) else {
        eprintln!(
            "hemostat account <user> --end-sessions | --purge-tickets | --expire-password | \
             --drop-group <group> [--arm]"
        );
        return EXIT_USAGE;
    };

    let Some(uid) = account::uid_of(user) else {
        eprintln!(
            "hemostat account: no account named `{user}` in /etc/passwd. Nothing was attempted — \
             every refusal this verb makes is a uid comparison, and there is no uid to compare"
        );
        return EXIT_USAGE;
    };

    let action = if has("--end-sessions") {
        AccountAction::SessionKill { user: user.to_string(), uid }
    } else if has("--purge-tickets") {
        AccountAction::TicketPurge { user: user.to_string(), uid }
    } else if has("--expire-password") {
        AccountAction::CredRotate {
            user: user.to_string(),
            uid,

            previous_last_change: account::read_last_change(user),
        }
    } else if let Some(group) = val("--drop-group") {
        AccountAction::GroupDrop { user: user.to_string(), uid, group: group.to_string() }
    } else {
        eprintln!(
            "hemostat account {user}: name one of --end-sessions, --purge-tickets, \
             --expire-password or --drop-group <group>"
        );
        return EXIT_USAGE;
    };

    let class = match &action {
        AccountAction::SessionKill { .. } => ActionClass::SessionKill,
        AccountAction::TicketPurge { .. } => ActionClass::TicketPurge,
        AccountAction::CredRotate { .. } => ActionClass::CredRotate,
        AccountAction::GroupDrop { .. } => ActionClass::GroupDrop,
    };
    if let Err(msg) = require_built(class) {
        eprintln!("hemostat account: {msg}");
        return EXIT_NOT_BUILT;
    }

    let protect = ProtectSet::gather();
    let armed = has("--arm");
    let ticket = match crate::authz::armed_gate("account", class, armed, 1) {
        Ok(t) => t,
        Err(code) => return code,
    };
    if let Err(code) = crate::authz::spend_armed("account", armed, ticket) {
        return code;
    }
    let opts = if armed { ApplyOptions::armed() } else { ApplyOptions::dry_run() };

    match account::apply(&action, &opts, &account::operator_uids(), &protect) {
        Outcome::Planned(plan) => {
            println!("{}", h(&plan.summary));
            println!("  {}", h(&plan.detail));
            println!("  undo: {}", h(&plan.undo));
            if plan.reversible {
                println!("  the reversal is journaled, and `hemostat undo` prints it rather than");
                println!("  running it: a permission change comes back through a person.");
            }
            if action.changes_the_account() {
                println!();
                println!("  This changes what the account IS, not what it is doing. Nothing in");
                println!("  this tool fires it automatically, and nothing should.");
            }
            println!();
            println!("Nothing was changed. Add --arm to apply.");
            EXIT_DRYRUN
        }
        Outcome::Refused(r) => {
            eprintln!("hemostat account: {}", h(&r.message));
            EXIT_POLICY
        }
        Outcome::Failed(f) => {
            eprintln!("hemostat account: {} failed: {}", h(&f.action), h(&f.reason));
            EXIT_ENFORCER
        }
        Outcome::Applied(rec) => journal_or_fail(&rec),
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn print_narrow(pid: Option<u32>, dest: Option<&str>, armed: bool) -> ExitCode {
    use hemostat_buildinfo::ActionClass;
    use hemostat_sensor_linux::netnarrow as nn;

    if pid.is_some() && dest.is_some() {
        eprintln!(
            "hemostat network: --block-pid and --block-dest are separate actions, judged \
             separately — run one, then the other. Nothing was changed"
        );
        return ExitCode::from(EXIT_USAGE);
    }
    let class = if pid.is_some() { ActionClass::ProcBlock } else { ActionClass::DestBlock };
    if let Err(msg) = require_built(class) {
        eprintln!("hemostat network: {msg}");
        return ExitCode::from(EXIT_NOT_BUILT);
    }

    let mut narrowing = nn::Narrowing::default();

    if let Some(pid) = pid {
        let Ok(text) = std::fs::read_to_string(format!("/proc/{pid}/cgroup")) else {
            eprintln!(
                "hemostat network: pid {pid} has no /proc/{pid}/cgroup — it has exited, or this \
                 run cannot read it. Nothing was changed"
            );
            return ExitCode::from(EXIT_POLICY);
        };
        let cgroup = match nn::cgroup_of(&text) {
            Ok(c) => c,
            Err(why) => {
                eprintln!("hemostat network: {why}");
                return ExitCode::from(EXIT_POLICY);
            }
        };
        narrowing.processes.push(nn::occupancy(pid, &cgroup, &nn::read_cgroups()));
    }

    if let Some(d) = dest {

        if let Err(why) = nn::render_dest_block(d, "operator") {
            eprintln!("hemostat network: {why}");
            return ExitCode::from(EXIT_USAGE);
        }
        narrowing
            .destinations
            .push((d.to_string(), "named by the operator".to_string()));
    }

    if narrowing.is_empty() {
        eprintln!("hemostat network: nothing to narrow — name a --block-pid or a --block-dest");
        return ExitCode::from(EXIT_USAGE);
    }

    println!("Egress narrowing — this does NOT isolate the host.\n");
    for o in &narrowing.processes {
        println!("  {}", h(&o.caveat()));
    }
    for c in narrowing.caveats() {
        if !narrowing.processes.iter().any(|o| o.caveat() == c) {
            println!("  {}", h(&c));
        }
    }
    println!();

    let ruleset = match narrowing.render_nft() {
        Ok(r) => r,
        Err(why) => {
            eprintln!("hemostat narrow: {}", h(&why));
            eprintln!("  Nothing was changed, and nothing was loaded.");
            return ExitCode::from(EXIT_USAGE);
        }
    };
    println!("The ruleset this would load:\n");
    for line in ruleset.lines() {
        println!("  {line}");
    }
    println!();

    let ticket = match crate::authz::armed_gate("network", class, armed, 1) {
        Ok(t) => t,
        Err(code) => return ExitCode::from(code),
    };
    if let Err(code) = crate::authz::spend_armed("network", armed, ticket) {
        return ExitCode::from(code);
    }
    if !armed {
        println!("Nothing was changed. Add --arm to load it.");
        return ExitCode::from(EXIT_DRYRUN);
    }

    match hemostat_sensor_linux::netpolicy::arm_ruleset(&ruleset, 120) {
        Ok(a) => {
            println!(
                "loaded. It rolls back in {}s unless you confirm ({}). The snapshot is at {}.",
                a.seconds, a.how, a.snapshot
            );
            ExitCode::from(EXIT_OK)
        }
        Err(e) => {
            eprintln!("hemostat network: {e}");
            ExitCode::from(EXIT_ENFORCER)
        }
    }
}

#[cfg(target_os = "linux")]
fn network_build_gate(egress: bool) -> Result<(), String> {
    require_built(hemostat_buildinfo::ActionClass::IsolateInbound)?;
    if egress {
        require_built(hemostat_buildinfo::ActionClass::Isolate)?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn journal_or_fail(rec: &hemostat_enforce_linux::UndoRecord) -> u8 {
    match journal_one(rec) {
        Ok(line) => {
            println!("{line}");
            EXIT_OK
        }
        Err(line) => {
            eprintln!("{line}");
            EXIT_FAILED
        }
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn print_network(arm: bool, seconds: u64, confirm: bool, revert: bool, egress: bool) -> ExitCode {
    use hemostat_sensor_linux::netpolicy as np;

    if confirm {
        return match np::confirm() {
            Ok(m) => {
                println!("{m}");
                ExitCode::from(EXIT_OK)
            }
            Err(e) => {
                eprintln!("hemostat: {e}");

                let armed_once = std::path::Path::new(np::SNAPSHOT).exists();
                let token = match hemostat_sensor_linux::saferead::read_text(std::path::Path::new(np::CONFIRM)) {
                    Ok(t) => Some(t),
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
                    Err(_) => Some(String::new()),
                };
                let code = confirm_failure_exit(armed_once, token.as_deref());
                if code == EXIT_ENFORCER && token.is_none() {
                    eprintln!(
                        "hemostat network: the rollback is still scheduled and WILL put the old \
                         ruleset back — this policy is not being kept"
                    );
                }
                ExitCode::from(code)
            }
        };
    }
    if revert {
        return match np::revert() {
            Ok(m) => {
                println!("{m}");
                ExitCode::from(EXIT_OK)
            }

            Err(e) => {
                eprintln!("hemostat: {e}");
                ExitCode::from(EXIT_ENFORCER)
            }
        };
    }

    if let Err(msg) = network_build_gate(egress) {
        eprintln!("hemostat network: {msg}");
        return ExitCode::from(EXIT_NOT_BUILT);
    }

    let surface = np::survey();
    let listening = surface.services.clone();
    let attributed = surface.attributed;
    let (declared, egress_declared, bad, declarations_unknown) = match network_declarations(
        hemostat_sensor_linux::saferead::read_text(std::path::Path::new(np::DECLARATION)),
    ) {
        Ok((d, e, b)) => (d, e, b, None),
        Err(why) => (Vec::new(), Vec::new(), Vec::new(), Some(why)),
    };
    let session = np::session_port(std::env::var("SSH_CONNECTION").ok().as_deref());
    let plan = np::plan(&listening, &declared, session);

    println!("Inbound policy plan — default deny, with these exceptions:");
    println!();
    for a in &plan.allows {
        println!("  {:<4}/{:<6} {:<18} {}",
            a.proto.token(),
            a.port,
            a.from.as_deref().unwrap_or("from anywhere"),
            np::describe(&a.origin));
    }
    println!();
    println!("Always applied and not listed above: loopback, ESTABLISHED/RELATED (this is what");
    println!("keeps your current session alive across the change), and ICMP. Outbound and");
    println!("forwarding are not touched.");

    if !bad.is_empty() {
        println!();
        println!("PROBLEMS IN {}:", np::DECLARATION);
        for b in &bad {
            println!("  {b}");
        }
        println!("  Each unparsed line is a port that will NOT be kept open, or a destination");
        println!("  that will NOT be reachable under --egress.");
    }
    if !surface.ephemeral.is_empty() {
        println!();
        println!(
            "Left out: {} UDP socket(s) in the ephemeral range {}-{}.",
            surface.ephemeral.len(),
            np::ephemeral_range().0,
            np::ephemeral_range().1
        );
        println!("  These are the local ends of OUTBOUND conversations, not services — a browser");
        println!("  doing QUIC holds a couple of dozen. Their replies already come back through");
        println!("  the ESTABLISHED,RELATED rule, so they need no hole. If one of them really is");
        println!("  a service, name it in {} and it gets a rule.", np::DECLARATION);
        for (pr, port, what) in surface.ephemeral.iter().take(6) {
            println!("    {}/{:<6} {}", pr.token(), port, what);
        }
        if surface.ephemeral.len() > 6 {
            println!("    ... and {} more", surface.ephemeral.len() - 6);
        }
    }
    let blind = surface.refusal();
    if let Some(why) = &blind {
        println!();
        println!("WARNING: {}", h(why));
    }
    if !attributed && !listening.is_empty() {
        println!();
        println!("No socket could be matched to a process — that needs root. Every port above is");
        println!("still kept open, but you are deciding what to close without knowing what is");
        println!("behind each one. Re-run as root before narrowing anything.");
    }
    for w in &plan.warnings {
        println!();
        println!("WARNING: {w}");
    }

    let eplan = egress.then(|| {
        np::egress_plan(&np::resolvers(), &egress_declared, np::uses_dhcp(), &np::resolved_upstreams())
    });

    if let Some(eg) = &eplan {
        println!();
        println!("Egress policy plan — default deny outbound, with these exceptions:");
        println!();
        for a in &eg.allows {
            println!(
                "  {:<4}/{:<6} {:<22} {}",
                a.proto.token(),
                a.port.map_or_else(|| "any".to_string(), |p| p.to_string()),
                a.to.clone().unwrap_or_else(|| "anywhere".into()),
                np::describe(&a.origin)
            );
        }
        println!();
        println!("Always applied and not listed: loopback, ESTABLISHED/RELATED and ICMP. The");
        println!("established rule is what keeps your current session alive across the change.");
        for w in &eg.warnings {
            println!();
            println!("WARNING: {w}");
        }
    }

    if !arm {
        println!();
        println!("Nothing has been changed. To declare extra ports, write {}:", np::DECLARATION);
        println!("    tcp/443");
        println!("    tcp/3306  10.0.0.0/8   # only from the internal range");
        if egress {
            println!("  and the destinations egress isolation must still reach, such as the");
            println!("  console and the domain controllers:");
            println!("    egress tcp/443  10.0.5.10    # the console");
            println!("    egress tcp/*    10.0.1.2     # the domain controller, every port");
        }
        println!();
        println!("To apply:  hemostat network --arm 120");
        println!("  The ruleset loads, and rolls itself back in 120s unless you run");
        println!("  `hemostat network --confirm`. Open a SECOND connection and check it works");
        println!("  before confirming — that check is the point, not a formality.");
        println!("  On a VM you can reach by console, that console is your way back regardless.");
        if let Some(why) = &declarations_unknown {
            println!();
            println!("WARNING: {why}");
        }

        return ExitCode::from(EXIT_DRYRUN);
    }

    if let Some(why) = declarations_unknown {
        eprintln!("hemostat network: {why}");
        return ExitCode::from(EXIT_POLICY);
    }
    if let Some(why) = blind {
        eprintln!("hemostat network: {}. Nothing was changed", h(&why));
        return ExitCode::from(EXIT_POLICY);
    }

    if let Some(role) = hemostat_enforce_linux::infrastructure_role() {
        eprintln!(
            "hemostat network: this host runs {role}. Isolating a cluster node cuts its \
             heartbeat and gets it fenced by its peers; that needs dual control (design \
             §11.9.2), which this build does not have. Nothing was changed"
        );
        return ExitCode::from(EXIT_POLICY);
    }

    let class = if egress {
        hemostat_buildinfo::ActionClass::Isolate
    } else {
        hemostat_buildinfo::ActionClass::IsolateInbound
    };
    let ticket = match crate::authz::armed_gate("network", class, true, 1) {
        Ok(t) => t,
        Err(code) => return ExitCode::from(code),
    };
    if egress {
        if let Err(code) = inbound_half_admitted(ticket.is_some()) {
            return ExitCode::from(code);
        }
    }
    if let Err(code) = crate::authz::spend_armed("network", true, ticket) {
        return ExitCode::from(code);
    }

    match np::arm_with_egress(&plan, eplan.as_ref(), seconds) {
        Ok(a) => {
            println!();
            if eplan.is_some() {
                println!("APPLIED inbound AND egress. Rolling back in {}s unless confirmed.", a.seconds);
            } else {
                println!("APPLIED. Rolling back in {}s unless confirmed.", a.seconds);
            }
            println!("  rollback: {}", a.how);
            println!("  previous ruleset saved to {}", a.snapshot);
            println!();
            println!("NOW: open a second connection to this host. If it works, run");
            println!("     hemostat network --confirm");
            println!("If you cannot, do nothing and the host will put itself back.");
            ExitCode::from(EXIT_OK)
        }
        Err(e) => {
            eprintln!("hemostat: {e}");
            ExitCode::from(EXIT_ENFORCER)
        }
    }
}

#[cfg(target_os = "linux")]
const OPERATOR_CONFIRMED: &str = "confirmed by the operator";
#[cfg(target_os = "linux")]
const OPERATOR_REVERTED: &str = "reverted by the operator";

#[cfg(target_os = "linux")]
fn confirm_failure_exit(armed_once: bool, token: Option<&str>) -> u8 {
    if !armed_once {
        return EXIT_USAGE;
    }
    match token.map(str::trim) {
        Some(t) if t == OPERATOR_CONFIRMED || t == OPERATOR_REVERTED => EXIT_USAGE,
        _ => EXIT_ENFORCER,
    }
}

#[cfg(target_os = "linux")]
fn inbound_half_admitted(ticket_verified: bool) -> Result<(), u8> {
    use hemostat_broker::Authority;
    let sanction = crate::authz::loaded_sanction().map_err(|why| {
        eprintln!("hemostat network: {why}");
        EXIT_POLICY
    })?;
    let authority = if ticket_verified { Authority::Verified } else { Authority::None };
    let class = hemostat_buildinfo::ActionClass::IsolateInbound;
    match crate::authz::broker_class(class, false, true, authority, &sanction, 1) {
        Ok(_) => Ok(()),
        Err((stage, why)) => {
            eprintln!("hemostat network: {why}");
            Err(crate::authz::exit_for_refusal(stage))
        }
    }
}

#[cfg(target_os = "linux")]
type Declarations = (
    Vec<hemostat_sensor_linux::netpolicy::Allow>,
    Vec<hemostat_sensor_linux::netpolicy::EgressAllow>,
    Vec<String>,
);

#[cfg(target_os = "linux")]
fn network_declarations(read: std::io::Result<String>) -> Result<Declarations, String> {
    use hemostat_sensor_linux::netpolicy as np;
    match read {
        Ok(t) => {
            let (inbound, mut bad) = np::parse_declaration(&t);
            let (egress, egress_bad) = np::parse_egress_declaration(&t);
            bad.extend(egress_bad);
            Ok((inbound, egress, bad))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok((Vec::new(), Vec::new(), Vec::new())),
        Err(e) => Err(format!(
            "{} could not be read ({e}), so which ports it keeps open is not known. Arming \
             default-deny now would close them; fix the file's permissions or remove it",
            np::DECLARATION
        )),
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn print_sshd(json: bool) -> u8 {

    let r = hemostat_sensor_linux::sshd::report();

    let code = if r.available { EXIT_OK } else { EXIT_PARTIAL };

    if json {

        let rows: Vec<String> = r.findings.iter().map(rootkit_row).collect();
        jprintln!(
            "{{\"available\":{},\"findings\":[{}]}}",
            r.available,
            rows.join(",")
        );
        return code;
    }

    if !r.available {
        println!("sshd: DID NOT RUN.");
        println!();
        println!("  {}", h(r.reason.as_deref().unwrap_or("no reason given")));
        println!();
        println!("  There is deliberately no fallback to reading /etc/ssh/sshd_config as text.");
        println!("  OpenSSH takes the FIRST value it obtains for a keyword, an Include below a");
        println!("  Match block scopes everything it pulls in, and some distributions ship no");
        println!("  Include at all — so the file routinely says something the daemon does not do.");
        println!("  Reporting a guess beside real findings would be worse than reporting nothing.");
        return code;
    }

    if r.findings.is_empty() {
        println!("sshd: nothing to report — every checked directive is at its hardened value.");
        println!("({} directives checked against `sshd -T`.)", hemostat_sensor_linux::sshd::CONTROLS.len());
        return code;
    }

    for f in &r.findings {
        println!("[{:?}] {}", f.severity, h(&f.subject));
        println!("    {}", h(&f.what));
        println!("    {}", h(&f.why));
        println!();
    }

    println!(
        "{} finding(s) across {} checked directives.",
        r.findings.len(),
        hemostat_sensor_linux::sshd::CONTROLS.len()
    );
    println!("Fix one from the console (`hemostat console`). It stages the change and verifies");
    println!("it with `sshd -T`; it does NOT restart the daemon.");
    code
}
