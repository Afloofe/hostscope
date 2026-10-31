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
    hemostat_sensor_linux::saferead::read_pid_text(format!("/proc/{pid}/comm"))
        .map_or_else(|_| "?".into(), |c| c.trim().to_string())
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

    let protect = ProtectSet::gather().declaring_scored(crate::golden::scored_units_here());

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
fn apply_one_restart(
    unit: &str,
    opts: &hemostat_enforce_linux::ApplyOptions,
    protect: &hemostat_enforce_linux::ProtectSet,
) -> (&'static str, bool, String) {
    use hemostat_enforce_linux::{Outcome, RemovalAction};
    match (RemovalAction::StartService { unit: unit.to_string() }).apply(opts, protect) {
        Outcome::Planned(p) => ("planned", false, p.detail),
        Outcome::Applied(rec) => {
            let journalled = journal_or_fail(&rec) == EXIT_OK;
            (if journalled { "applied" } else { "failed" }, true, rec.did)
        }
        Outcome::Refused(r) => ("refused", false, r.message),
        Outcome::Failed(f) => ("failed", false, f.reason),
    }
}

#[cfg(target_os = "linux")]
const FIXES_DIR: &str = "/var/log/hemostat";

#[cfg(target_os = "linux")]
pub(crate) fn audit_fix(what: &str) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let dir = std::path::Path::new(FIXES_DIR);
    if let Err(why) = append_fixes_line(dir, 0, &fixes_log_line(now, what)) {
        eprintln!("hemostat: the fix stands, but {FIXES_DIR}/fixes.log was not written: {}", h(&why));
    }
}

#[cfg(target_os = "linux")]
fn fixes_log_line(epoch: u64, what: &str) -> String {
    format!("{}  {}\n", crate::remediate_verb::epoch_to_utc(epoch), what.replace(['\n', '\r'], " "))
}

#[cfg(target_os = "linux")]
fn append_fixes_line(dir: &std::path::Path, owner: u32, line: &str) -> Result<(), String> {
    use std::io::Write as _;
    use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _, OpenOptionsExt as _};

    match std::fs::DirBuilder::new().mode(0o700).create(dir) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(format!("{} could not be created ({e})", dir.display())),
    }
    let dmd = std::fs::symlink_metadata(dir)
        .map_err(|e| format!("{} could not be examined ({e})", dir.display()))?;
    if let Some(why) = dir_refusal(dmd.file_type().is_symlink(), dmd.is_dir(), dmd.uid(), dmd.mode(), owner) {
        return Err(format!("{}: {why}", dir.display()));
    }
    let path = dir.join("fixes.log");
    let mut f = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(&path)
        .map_err(|e| format!("{} could not be opened without following a link ({e})", path.display()))?;
    let md = f.metadata().map_err(|e| format!("{} could not be examined ({e})", path.display()))?;
    if let Some(why) = file_refusal(md.file_type().is_symlink(), md.is_file(), md.uid(), md.nlink(), owner) {
        return Err(format!("{}: {why}", path.display()));
    }
    f.write_all(line.as_bytes()).map_err(|e| format!("{} could not be appended to ({e})", path.display()))
}

#[cfg(target_os = "linux")]
fn dir_refusal(is_link: bool, is_dir: bool, uid: u32, mode: u32, owner: u32) -> Option<String> {
    if is_link {
        return Some("it is a symbolic link, and what is written through one lands wherever it points".into());
    }
    if !is_dir {
        return Some("it is not a directory".into());
    }
    if uid != owner {
        return Some(format!("it is owned by uid {uid}, not {owner}"));
    }
    if mode & 0o022 != 0 {
        return Some(format!(
            "its group or everyone can write it (mode {:o}), so anyone could put a link at the name",
            mode & 0o7777
        ));
    }
    None
}

#[cfg(target_os = "linux")]
fn file_refusal(is_link: bool, is_file: bool, uid: u32, nlink: u64, owner: u32) -> Option<String> {
    if is_link {
        return Some("it is a symbolic link, and what is written through one lands wherever it points".into());
    }
    if !is_file {
        return Some("it is not a regular file".into());
    }
    if uid != owner {
        return Some(format!("it is owned by uid {uid}, not {owner}"));
    }
    if nlink > 1 {
        return Some(format!(
            "it is one of {nlink} hard links to the same file, and a write here lands in every one"
        ));
    }
    None
}

#[cfg(target_os = "linux")]
pub(crate) fn restore_scored(args: &[String], json: bool) -> u8 {
    use hemostat_enforce_linux::{ApplyOptions, ProtectSet};

    if let Err(msg) = require_built(hemostat_buildinfo::ActionClass::ServiceStart) {
        eprintln!("hemostat services: {msg}");
        return EXIT_NOT_BUILT;
    }
    if !crate::golden::active() {
        eprintln!(
            "hemostat services --restore: the IRSeC golden baseline is off, so there is no \
             scored-service roster to restore. Set HEMOSTAT_GOLDEN=1 on a competition box."
        );
        return EXIT_POLICY;
    }

    let ov = hemostat_sensor_linux::overview::report();
    let report = crate::service_health::from_overview(&ov);
    let armed = args.iter().any(|a| a == "--arm");

    if let Some(why) = &report.not_checked {
        if json {
            jprintln!("{{\"restore\":{{\"golden\":true,\"armed\":{armed},\"not_checked\":{}}}}}", json_str(why));
        } else {
            println!("scored services — NOT CHECKED: {}\n  nothing was checked or restarted", h(why));
        }
        return EXIT_PARTIAL;
    }

    let role_json = crate::golden::role_json(report.role.as_ref());
    if let Some(r) = report.role.filter(|r| r.from_override) {
        if !json {
            println!("scored services — {}, not the hostname `{}`", crate::golden::role_said(&r), h(&ov.identity.hostname));
        }
    }
    let health = &report.services;
    let known = crate::uptime::known_service_units();

    let mut plan = Vec::new();
    let mut stuck: Vec<(crate::uptime::Restart, &'static str)> = Vec::new();
    for r in crate::uptime::plan_restarts(health, &known) {
        match crate::uptime::already_running(crate::uptime::unit_state(&r.unit)) {
            Some(why) => stuck.push((r, why)),
            None => plan.push(r),
        }
    }

    let unresolved: Vec<&'static crate::golden::ScoredService> = health
        .iter()
        .filter(|hh| hh.up == Some(false))
        .filter(|hh| crate::golden::pick_unit(crate::golden::units_for(hh.svc.probe), &known).is_none())
        .map(|hh| hh.svc)
        .collect();

    let port_json =
        |s: &crate::golden::ScoredService| s.port.map_or("null".to_string(), |p| p.to_string());
    let port_text = |s: &crate::golden::ScoredService| s.port.map_or_else(|| "its port".to_string(), |p| p.to_string());
    let stuck_json = || -> Vec<String> {
        stuck
            .iter()
            .map(|(r, why)| {
                format!(
                    "{{\"service\":{},\"host\":{},\"unit\":{},\"port\":{},\"outcome\":\"running-port-closed\",\"why\":{}}}",
                    json_str(r.svc.service), json_str(r.svc.host), json_str(&r.unit), port_json(r.svc), json_str(why)
                )
            })
            .collect()
    };
    let print_stuck = || {
        for (r, why) in &stuck {
            println!(
                "  [RUNNING, PORT CLOSED] {} → {}: {why}, but port {} is not listening where the scorer reaches it — a restart will not help; needs a human ({})",
                h(r.svc.service), h(&r.unit), port_text(r.svc), crate::uptime::port_closed_hint(r.svc.probe)
            );
        }
    };

    if plan.is_empty() {
        if json {
            let un: Vec<String> = unresolved
                .iter()
                .map(|s| format!("{{\"service\":{},\"host\":{},\"port\":{}}}", json_str(s.service), json_str(s.host), port_json(s)))
                .collect();
            jprintln!(
                "{{\"restore\":{{\"golden\":true,\"armed\":{armed}{role_json},\"planned\":[],\"needs_human\":[{}],\"unresolved\":[{}]}}}}",
                stuck_json().join(","), un.join(",")
            );
        } else if unresolved.is_empty() && stuck.is_empty() {
            println!("scored services — every service this box owns is up (nothing to restore)");
        } else {
            println!("scored services — down, and nothing here to start:");
            print_stuck();
            for s in &unresolved {
                println!("  [DOWN] {} — no recognised unit among {:?}; declare it and use `services --start`", h(s.service), crate::golden::units_for(s.probe));
            }
        }
        return if unresolved.is_empty() && stuck.is_empty() { EXIT_OK } else { EXIT_POLICY };
    }

    let ticket = match crate::authz::armed_gate("services", hemostat_buildinfo::ActionClass::ServiceStart, armed, plan.len()) {
        Ok(t) => t,
        Err(code) => return code,
    };
    if let Err(code) = crate::authz::spend_armed("services", armed, ticket) {
        return code;
    }

    let opts = if armed { ApplyOptions::armed() } else { ApplyOptions::dry_run() };

    let protect = ProtectSet::gather();

    let (mut any_failed, mut any_refused, mut any_planned) = (false, false, false);
    if !json {
        println!(
            "scored services — {} down service(s){}\n",
            plan.len(),
            if armed { "" } else { " (dry run — add --arm to apply)" }
        );
    }
    let mut rows: Vec<String> = Vec::new();
    for r in &plan {
        let (status, _applied, detail) = apply_one_restart(&r.unit, &opts, &protect);

        let status = match status {
            "applied" if crate::uptime::await_port(r.svc) != Some(true) => "started-port-closed",
            other => other,
        };
        match status {
            "planned" => {
                any_planned = true;
                if !json {
                    println!("  [plan] {} → {}\n         {}", h(r.svc.service), h(&r.unit), h(&detail));
                }
            }
            "applied" => {
                if !json {
                    println!("  [done] {} → {} enabled and started; port {} answers", h(r.svc.service), h(&r.unit), port_text(r.svc));
                }
            }
            "started-port-closed" => {
                any_failed = true;
                if !json {
                    eprintln!(
                        "  [not fixed] {} → {} started, but port {} did not answer within {}s — needs a human ({})",
                        h(r.svc.service), h(&r.unit), port_text(r.svc), crate::uptime::PORT_WAIT_SECS,
                        crate::uptime::port_closed_hint(r.svc.probe)
                    );
                }
            }
            "refused" => {
                any_refused = true;
                if !json {
                    eprintln!("  [refused] {} → {}: {}", h(r.svc.service), h(&r.unit), h(&detail));
                }
            }
            _ => {
                any_failed = true;
                if !json {
                    eprintln!("  [failed] {} → {}: {}", h(r.svc.service), h(&r.unit), h(&detail));
                }
            }
        }
        if json {
            rows.push(format!(
                "{{\"service\":{},\"host\":{},\"unit\":{},\"armed\":{armed},\"outcome\":\"{status}\"}}",
                json_str(r.svc.service), json_str(r.svc.host), json_str(&r.unit)
            ));
        }
    }
    if json {
        let un: Vec<String> = unresolved
            .iter()
            .map(|s| format!("{{\"service\":{},\"host\":{},\"port\":{}}}", json_str(s.service), json_str(s.host), port_json(s)))
            .collect();
        jprintln!(
            "{{\"restore\":{{\"golden\":true,\"armed\":{armed}{role_json},\"planned\":[{}],\"needs_human\":[{}],\"unresolved\":[{}]}}}}",
            rows.join(","), stuck_json().join(","), un.join(",")
        );
    } else {
        if !stuck.is_empty() {
            println!();
            print_stuck();
        }
        if !unresolved.is_empty() {
            println!("\n  down with no recognised unit (declare and `services --start`):");
            for s in &unresolved {
                println!("    [DOWN] {}", h(s.service));
            }
        }
    }

    if any_failed {
        EXIT_ENFORCER
    } else if any_refused {
        EXIT_POLICY
    } else if any_planned {
        EXIT_DRYRUN
    } else if !stuck.is_empty() || !unresolved.is_empty() {
        EXIT_POLICY
    } else {
        EXIT_OK
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn watch_restore(args: &[String], json: bool, every_secs: u64) -> u8 {
    use hemostat_enforce_linux::{ApplyOptions, ProtectSet};
    use hemostat_sensor_linux::firewall::Reach;

    if let Err(msg) = require_built(hemostat_buildinfo::ActionClass::ServiceStart) {
        eprintln!("hemostat services: {msg}");
        return EXIT_NOT_BUILT;
    }
    if !crate::golden::active() {
        eprintln!(
            "hemostat services --restore --every: the IRSeC golden baseline is off (set \
             HEMOSTAT_GOLDEN=1 on a competition box); there is no scored roster to watch."
        );
        return EXIT_POLICY;
    }

    let armed = args.iter().any(|a| a == "--arm");
    let every = every_secs.max(1);

    let ticket = match crate::authz::armed_gate(
        "services",
        hemostat_buildinfo::ActionClass::ServiceStart,
        armed,
        1,
    ) {
        Ok(t) => t,
        Err(code) => return code,
    };
    if let Err(code) = crate::authz::spend_armed("services", armed, ticket) {
        return code;
    }

    let mut gov = crate::uptime::Governor::default();

    let protect = ProtectSet::gather();
    let opts = if armed { ApplyOptions::armed() } else { ApplyOptions::dry_run() };

    if !json {
        println!(
            "mahoraga watchdog — scored-service uptime, every {every}s {}\n  {}\n  Ctrl-C to stop.\n",
            if armed { "(ARMED: auto-fix)" } else { "(dry run: reporting only — add --arm to auto-fix)" },
            if armed {
                "each fix is journalled and appended to /var/log/hemostat/fixes.log"
            } else {
                "nothing will be changed"
            },
        );

        if let Ok(r) = crate::golden::resolve_role(None, crate::golden::role_override().as_deref()) {
            println!("  {}: the hostname is not used\n", crate::golden::role_said(&r));
        }
    }

    let pause = |tick: std::time::Instant| {
        let remaining = every.saturating_sub(tick.elapsed().as_secs());
        if remaining > 0 {
            std::thread::sleep(std::time::Duration::from_secs(remaining));
        }
    };

    loop {
        let tick = std::time::Instant::now();
        let now = crate::remediate_verb::epoch_to_utc(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
        );

        let ov = hemostat_sensor_linux::overview::report();
        let report = crate::service_health::from_overview(&ov);

        if let Some(why) = &report.not_checked {
            if json {
                jprintln!("{{\"tick\":{},\"armed\":{armed},\"not_checked\":{}}}", json_str(&now), json_str(why));
            } else {
                println!("[{now}] NOT CHECKED  {} — nothing was checked or changed this tick", h(why));
            }
            pause(tick);
            continue;
        }
        let health = &report.services;
        let known = crate::uptime::known_service_units();

        for hh in health.iter().filter(|hh| hh.up == Some(true)) {
            if let Some(u) = crate::golden::pick_unit(crate::golden::units_for(hh.svc.probe), &known) {
                gov.seen_up(u);
            }
        }
        let (attempt, backed): (Vec<_>, Vec<_>) = crate::uptime::plan_restarts(health, &known)
            .into_iter()
            .partition(|r| gov.should_attempt(&r.unit));

        let (mut fixed, mut still_down, mut backed_names): (Vec<String>, Vec<String>, Vec<String>) =
            (Vec::new(), Vec::new(), Vec::new());
        let mut needs_human: Vec<String> = Vec::new();
        let port_of = |s: &crate::golden::ScoredService| s.port.map_or_else(|| "its port".to_string(), |p| p.to_string());

        for r in &backed {
            backed_names.push(r.unit.clone());
            if !json {
                println!("[{now}] BACKED-OFF {} → {} (restart keeps failing — needs a human)", h(r.svc.service), h(&r.unit));
            }
        }
        for r in &attempt {

            if let Some(why) = crate::uptime::already_running(crate::uptime::unit_state(&r.unit)) {
                if armed {
                    gov.record(&r.unit, false);
                }
                needs_human.push(r.unit.clone());
                if !json {
                    println!(
                        "[{now}] RUNNING, PORT CLOSED {} → {} ({why}, but port {} is not listening where the scorer reaches it — a restart will not help; needs a human: {})",
                        h(r.svc.service), h(&r.unit), port_of(r.svc), crate::uptime::port_closed_hint(r.svc.probe)
                    );
                }
                continue;
            }
            let (status, applied, detail) = apply_one_restart(&r.unit, &opts, &protect);

            let answering = applied && crate::uptime::await_port(r.svc) == Some(true);
            if armed {
                gov.record(&r.unit, answering);
                if applied {
                    audit_fix(&format!("restore {} → {} [{status}]", r.svc.service, r.unit));
                }
            }
            match status {
                "applied" if answering => fixed.push(r.unit.clone()),
                _ => still_down.push(r.unit.clone()),
            }
            if !json {
                let tag = match status {
                    "applied" if answering => "FIXED  ",
                    "applied" => "NOT FIXED",
                    "planned" => "DOWN   ",
                    "refused" => "REFUSED",
                    _ => "FAILED ",
                };
                let detail = if status == "applied" && !answering {
                    format!(
                        "{detail}, but port {} did not answer within {}s — needs a human: {}",
                        port_of(r.svc), crate::uptime::PORT_WAIT_SECS, crate::uptime::port_closed_hint(r.svc.probe)
                    )
                } else {
                    detail
                };
                println!("[{now}] {tag} {} → {}  {}", h(r.svc.service), h(&r.unit), h(&detail));
            }
        }

        let fw = hemostat_sensor_linux::firewall_report();
        let mut unreachable: Vec<String> = Vec::new();
        let mut reach_unknown: Vec<String> = Vec::new();
        for (s, reach) in crate::service_health::firewall_reach(&report, &fw) {
            let port = port_of(s);
            match reach {
                Reach::Blocked(by) => {
                    unreachable.push(s.service.to_string());
                    if !json {
                        println!("[{now}] UNREACH  {} → :{port} (the firewall drops it: {} — a restart will not help; remove the rule or open the port)", h(s.service), h(&by));
                    }
                }
                Reach::Unknown(why) => {
                    reach_unknown.push(s.service.to_string());
                    if !json {
                        println!("[{now}] UNKNOWN  {} → :{port} (listening, but whether the firewall lets the scorer through is not known: {})", h(s.service), h(&why));
                    }
                }
                Reach::Open => {}
            }
        }

        let unprobed: Vec<String> = health.iter().filter(|hh| hh.up.is_none()).map(|hh| hh.svc.service.to_string()).collect();
        if !unprobed.is_empty() && !json {
            println!("[{now}] NOT CHECKED  {} (no scored port to probe)", h(&unprobed.join(", ")));
        }

        let no_unit: Vec<&'static crate::golden::ScoredService> = health
            .iter()
            .filter(|hh| hh.up == Some(false))
            .filter(|hh| crate::golden::pick_unit(crate::golden::units_for(hh.svc.probe), &known).is_none())
            .map(|hh| hh.svc)
            .collect();
        if !json {
            for s in &no_unit {
                let why = if known.is_empty() {
                    "the installed units could not be listed (systemctl list-unit-files), so none is started".to_string()
                } else {
                    format!("no recognised unit among {:?} to start", crate::golden::units_for(s.probe))
                };
                println!(
                    "[{now}] DOWN     {} → :{} ({why} — needs a human: declare it and use `services --start`)",
                    h(s.service), port_of(s)
                );
            }
        }
        let unresolved: Vec<String> = no_unit.iter().map(|s| s.service.to_string()).collect();

        let all_seen = attempt.is_empty()
            && backed.is_empty()
            && unresolved.is_empty()
            && unreachable.is_empty()
            && reach_unknown.is_empty()
            && unprobed.is_empty();
        if all_seen && !json {
            println!("[{now}] all scored services up");
        }
        if json {
            let arr = |v: &[String]| v.iter().map(|s| json_str(s)).collect::<Vec<_>>().join(",");
            jprintln!(
                "{{\"tick\":{},\"armed\":{armed}{},\"fixed\":[{}],\"down\":[{}],\"backed_off\":[{}],\"needs_human\":[{}],\"unresolved\":[{}],\"unreachable\":[{}],\"reach_unknown\":[{}],\"unprobed\":[{}]}}",
                json_str(&now), crate::golden::role_json(report.role.as_ref()), arr(&fixed), arr(&still_down), arr(&backed_names),
                arr(&needs_human), arr(&unresolved), arr(&unreachable), arr(&reach_unknown), arr(&unprobed)
            );
        }

        pause(tick);
    }
}

#[cfg(target_os = "linux")]
const WATCHDOG_UNIT: &str = "/etc/systemd/system/mahoraga-watchdog.service";

#[cfg(target_os = "linux")]
const WATCHDOG_SERVICE: &str = "mahoraga-watchdog.service";

#[cfg(target_os = "linux")]
fn systemctl() -> Option<std::path::PathBuf> {
    ["/usr/bin/systemctl", "/bin/systemctl"].into_iter().map(std::path::PathBuf::from).find(|p| p.exists())
}

#[cfg(target_os = "linux")]
fn systemctl_run(sc: &std::path::Path, args: &[&str]) -> Result<(), String> {
    let o = std::process::Command::new(sc)
        .args(args)
        .env_clear()
        .output()
        .map_err(|e| format!("`systemctl {}` could not be run ({e})", args.join(" ")))?;
    if o.status.success() {
        Ok(())
    } else {
        Err(format!("`systemctl {}` failed: {}", args.join(" "), String::from_utf8_lossy(&o.stderr).trim()))
    }
}

#[cfg(target_os = "linux")]
fn watchdog_active(sc: &std::path::Path) -> Option<bool> {
    std::process::Command::new(sc)
        .args(["is-active", "--quiet", WATCHDOG_SERVICE])
        .env_clear()
        .status()
        .ok()
        .map(|s| s.success())
}

#[cfg(target_os = "linux")]
const WATCHDOG_ENV: [&str; 6] = [
    crate::authz::POLICY_ENV,
    "HEMOSTAT_ENGAGEMENT_PUBKEY",
    "HEMOSTAT_ENGAGEMENT_ID",
    "HEMOSTAT_EPOCH_FLOOR",
    "HEMOSTAT_PROFILE",
    "HEMOSTAT_ROLE",
];

#[cfg(target_os = "linux")]
const WATCHDOG_ENV_PATHS: [&str; 2] = [crate::authz::POLICY_ENV, "HEMOSTAT_EPOCH_FLOOR"];

#[cfg(target_os = "linux")]
fn unit_value_ok(v: &str) -> bool {
    !v.is_empty() && v.chars().all(|c| c.is_ascii_alphanumeric() || "._/+:@,=-".contains(c))
}

#[cfg(target_os = "linux")]
fn watchdog_exe(exe: std::io::Result<std::path::PathBuf>) -> Result<String, String> {
    let exe = exe.map_err(|e| {
        format!("this binary's own path could not be read ({e}), and a unit that runs a bare name runs whatever is found first")
    })?;
    let shown = exe.display().to_string();
    match exe.to_str() {
        Some(s) if s.starts_with('/') && unit_value_ok(s) => Ok(s.to_string()),
        _ => Err(format!(
            "this binary is at {shown}, which a unit file cannot name exactly (letters, digits and \
             ._/+:@,=- only, and not a file replaced since it started); copy it to a plain path, \
             such as /usr/local/sbin/mahoraga, and install from there"
        )),
    }
}

#[cfg(target_os = "linux")]
fn watchdog_env(get: impl Fn(&str) -> Option<String>) -> Result<Vec<(&'static str, String)>, String> {
    let mut out = Vec::new();
    for k in WATCHDOG_ENV {
        let Some(v) = get(k).filter(|v| !v.is_empty()) else { continue };
        if !unit_value_ok(&v) {
            return Err(format!(
                "${k} is set to something a unit file would read as something else; the watchdog \
                 must run under exactly the {k} you set, so give it a value of letters, digits and \
                 ._/+:@,=- only"
            ));
        }
        if WATCHDOG_ENV_PATHS.contains(&k) && !v.starts_with('/') {
            return Err(format!(
                "${k} is the relative path {v}, and the watchdog runs from / under systemd, where \
                 it names another file; give ${k} as an absolute path"
            ));
        }
        out.push((k, v));
    }
    Ok(out)
}

#[cfg(target_os = "linux")]
fn watchdog_unit_text(exe: &str, every: u64, env: &[(&str, String)]) -> String {
    let vars: String = std::iter::once("Environment=HEMOSTAT_GOLDEN=1\n".to_string())
        .chain(env.iter().map(|(k, v)| format!("Environment={k}={v}\n")))
        .collect();
    format!(
        "[Unit]\n\
         Description=Mahoraga scored-service uptime watchdog\n\
         After=network-online.target\n\
         Wants=network-online.target\n\n\
         [Service]\n\
         {vars}\
         ExecStart={exe} services --restore --every {every} --arm\n\
         Restart=always\n\
         RestartSec=5\n\n\
         [Install]\n\
         WantedBy=multi-user.target\n"
    )
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UnitAt {

    Absent,

    Ours,
}

#[cfg(target_os = "linux")]
fn watchdog_unit_at(path: &std::path::Path, want: &str, owner: u32) -> Result<UnitAt, String> {
    use std::io::Read as _;
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};

    let refuse = |why: String| format!("refusing to install over {}: {why}", path.display());
    let md = match std::fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(UnitAt::Absent),
        Err(e) => return Err(refuse(format!("it could not be examined ({e})"))),
    };
    if let Some(why) = file_refusal(md.file_type().is_symlink(), md.is_file(), md.uid(), md.nlink(), owner) {
        return Err(refuse(why));
    }

    let f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|e| refuse(format!("it could not be opened without following a link ({e})")))?;
    let md = f.metadata().map_err(|e| refuse(format!("it could not be examined ({e})")))?;
    if let Some(why) = file_refusal(false, md.is_file(), md.uid(), md.nlink(), owner) {
        return Err(refuse(why));
    }

    let cap = u64::try_from(want.len()).map_or(u64::MAX, |n| n.saturating_add(1));
    let mut have = Vec::new();
    (&f).take(cap).read_to_end(&mut have).map_err(|e| refuse(format!("it could not be read ({e})")))?;
    if have == want.as_bytes() {
        Ok(UnitAt::Ours)
    } else {
        Err(refuse(
            "a different unit is already there. If it is an earlier watchdog, `mahoraga services \
             --uninstall-watchdog --arm` takes it out; then install again"
                .into(),
        ))
    }
}

#[cfg(target_os = "linux")]
fn write_unit_file(path: &std::path::Path, body: &str, owner: u32) -> Result<(), String> {
    use std::io::Write as _;
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};

    let (Some(dir), Some(name)) = (path.parent().filter(|d| !d.as_os_str().is_empty()), path.file_name()) else {
        return Err(format!("{} names no file in a directory", path.display()));
    };
    let dmd = std::fs::symlink_metadata(dir).map_err(|e| format!("{} could not be examined ({e})", dir.display()))?;
    if let Some(why) = dir_refusal(dmd.file_type().is_symlink(), dmd.is_dir(), dmd.uid(), dmd.mode(), owner) {
        return Err(format!("{}: {why}", dir.display()));
    }
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let tmp = dir.join(format!(".{}.{}.{nonce}.tmp", name.to_string_lossy(), std::process::id()));
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&tmp)
        .map_err(|e| format!("{} could not be created ({e})", tmp.display()))?;
    let written = f
        .write_all(body.as_bytes())
        .and_then(|()| f.set_permissions(std::fs::Permissions::from_mode(0o644)))
        .and_then(|()| f.sync_all());
    drop(f);
    if let Err(e) = written.and_then(|()| std::fs::rename(&tmp, path)) {
        let _ = std::fs::remove_file(&tmp);
        return Err(format!("{} could not be written ({e})", path.display()));
    }
    if let Ok(d) = std::fs::File::open(dir) {
        let _ = d.sync_all();
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub(crate) fn install_watchdog(args: &[String], every: u64) -> u8 {
    use hemostat_enforce_linux::{journal, ApplyOptions, Outcome, ProtectSet, RemovalAction, UndoKind, UndoRecord};

    if let Err(msg) = require_built(hemostat_buildinfo::ActionClass::ServiceStart) {
        eprintln!("hemostat services: {msg}");
        return EXIT_NOT_BUILT;
    }
    let armed = args.iter().any(|a| a == "--arm");
    let exe = match watchdog_exe(std::env::current_exe()) {
        Ok(e) => e,
        Err(why) => {
            eprintln!("hemostat services: {}. Nothing was changed.", h(&why));
            return EXIT_USAGE;
        }
    };
    let env = match watchdog_env(|k| match std::env::var(k) {
        Ok(v) => Some(v),
        Err(std::env::VarError::NotPresent) => None,

        Err(std::env::VarError::NotUnicode(_)) => Some("\u{FFFD}".to_string()),
    }) {
        Ok(v) => v,
        Err(why) => {
            eprintln!("hemostat services: {}. Nothing was changed.", h(&why));
            return EXIT_USAGE;
        }
    };
    let unit = watchdog_unit_text(&exe, every, &env);
    let unit_path = std::path::Path::new(WATCHDOG_UNIT);

    let at = match watchdog_unit_at(unit_path, &unit, 0) {
        Ok(a) => a,
        Err(why) => {
            eprintln!("hemostat services: {}. Nothing was changed.", h(&why));
            return EXIT_POLICY;
        }
    };

    let ticket =
        match crate::authz::armed_gate("services", hemostat_buildinfo::ActionClass::ServiceStart, armed, 1) {
            Ok(t) => t,
            Err(code) => return code,
        };
    if let Err(code) = crate::authz::spend_armed("services", armed, ticket) {
        return code;
    }

    let carried: Vec<&str> = env.iter().map(|(k, _)| *k).collect();
    if !armed {
        match at {
            UnitAt::Absent => {
                println!("install the uptime watchdog as a systemd service ({WATCHDOG_UNIT}):\n");
                print!("{unit}");
            }
            UnitAt::Ours => println!(
                "the uptime watchdog unit is already at {WATCHDOG_UNIT}, exactly as this would write \
                 it; only the enable and the start are left"
            ),
        }
        println!(
            "\nIt runs `{exe} services --restore --every {every} --arm` with HEMOSTAT_GOLDEN=1{} and \
             restarts on boot. Then `systemctl enable --now {WATCHDOG_SERVICE}`, checked active; the \
             unit and the start are journaled together, so `hemostat undo` takes the install back out.",
            if carried.is_empty() { String::new() } else { format!(" and {}", carried.join(", ")) }
        );
        println!("\nNothing was changed. Add --arm to install (remove later with `services --uninstall-watchdog --arm`).");
        return EXIT_DRYRUN;
    }

    if systemctl().is_none() {
        eprintln!("hemostat services: systemctl not found; cannot install the watchdog service. Nothing was changed.");
        return EXIT_ENFORCER;
    }
    let vault = std::path::Path::new(hemostat_enforce_linux::DEFAULT_VAULT);
    let mut ledger = journal::Appender::new(vault);
    if at == UnitAt::Absent {

        let kept = match hemostat_enforce_linux::snapshot(unit_path, &unit, vault) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("hemostat services: {}. Nothing was changed.", h(&e));
                return EXIT_FAILED;
            }
        };
        if let Err(why) = write_unit_file(unit_path, &unit, 0) {
            eprintln!("hemostat services: {}. Nothing was changed.", h(&why));
            return EXIT_ENFORCER;
        }
        let wrote = UndoRecord {
            did: format!("wrote the uptime watchdog unit {WATCHDOG_UNIT}"),
            undo: UndoKind::RemoveCreatedFile { vault: kept, original: unit_path.to_path_buf() },
            reversible: true,
        };
        if let Err(e) = ledger.append(&wrote) {

            let left = match std::fs::remove_file(unit_path) {
                Ok(()) => "was taken back out".to_string(),
                Err(re) => format!("could not be taken back out ({re}): delete {WATCHDOG_UNIT} by hand"),
            };
            eprintln!(
                "hemostat services: the undo journal could not be written ({e}), so the unit {left}. \
                 The watchdog was not installed."
            );
            return EXIT_FAILED;
        }
    }

    if let Err(e) = hemostat_enforce_linux::daemon_reload() {
        let undo = if ledger.started() {
            format!(" — undo: hemostat undo {}", ledger.path().display())
        } else {
            String::new()
        };
        eprintln!("hemostat services: systemd was not reloaded ({}), so the watchdog was not started{undo}", h(&e));
        return EXIT_ENFORCER;
    }

    let protect = ProtectSet::gather();
    match (RemovalAction::StartService { unit: WATCHDOG_SERVICE.to_string() }).apply(&ApplyOptions::armed(), &protect) {
        Outcome::Applied(rec) => {
            let journalled = ledger.append(&rec);
            println!("installed and started the uptime watchdog ({WATCHDOG_SERVICE}, every {every}s)");
            println!("  status: systemctl status mahoraga-watchdog   logs: journalctl -u mahoraga-watchdog -f");
            println!("  remove: mahoraga services --uninstall-watchdog --arm");
            match journalled {
                Ok(()) => {
                    println!("{} — undo: hemostat undo {}", h(&rec.did), h(&ledger.path().display().to_string()));
                    EXIT_OK
                }
                Err(e) => {
                    eprintln!(
                        "{} — WARNING: the undo journal could not be written ({e}); `services \
                         --uninstall-watchdog --arm` still removes it",
                        h(&rec.did)
                    );
                    EXIT_FAILED
                }
            }
        }
        Outcome::Failed(f) => {
            eprintln!("hemostat services: {} failed: {}", h(&f.action), h(&f.reason));
            if ledger.started() {
                eprintln!("  the unit is written — undo: hemostat undo {}", h(&ledger.path().display().to_string()));
            }
            eprintln!("  `services --uninstall-watchdog --arm` takes out whatever of it is there.");
            EXIT_ENFORCER
        }
        Outcome::Refused(r) => {
            eprintln!("hemostat services: {}", h(&r.message));
            EXIT_POLICY
        }
        Outcome::Planned(_) => {
            eprintln!("hemostat services: an armed start came back as a plan; the watchdog was not started");
            EXIT_ENFORCER
        }
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn uninstall_watchdog(args: &[String]) -> u8 {
    use hemostat_enforce_linux::{UndoKind, UndoRecord};

    if let Err(msg) = require_built(hemostat_buildinfo::ActionClass::Uninstall) {
        eprintln!("hemostat services: {msg}");
        return EXIT_NOT_BUILT;
    }
    let armed = args.iter().any(|a| a == "--arm");
    match crate::authz::reversal_authority(hemostat_evcrypto::ticket::Op::Uninstall, armed) {
        Ok(None) => {}
        Ok(Some(gap)) => eprintln!("hemostat services: NOTE: {gap}"),
        Err((code, why)) => {
            eprintln!("hemostat services: {why}");
            return code;
        }
    }
    let Some(sc) = systemctl() else {
        eprintln!("hemostat services: systemctl not found; nothing was changed");
        return EXIT_ENFORCER;
    };
    let unit_path = std::path::Path::new(WATCHDOG_UNIT);
    let file = std::fs::symlink_metadata(unit_path).is_ok();
    let active = watchdog_active(&sc);
    if !file && active == Some(false) {
        println!("the watchdog service is not installed (nothing to remove)");
        return EXIT_OK;
    }
    if !armed {
        println!("remove the uptime watchdog service ({WATCHDOG_SERVICE}):");
        println!(
            "  stop it ({}) and disable it",
            match active {
                Some(true) => "it is running",
                Some(false) => "it is not running",
                None => "systemctl could not say whether it is running",
            }
        );
        if file {
            println!("  delete {WATCHDOG_UNIT}, then reload systemd");
        }
        println!("  The scored services it was keeping up are left as they are.");
        println!("\nNothing was changed. Add --arm to remove it.");
        return EXIT_DRYRUN;
    }

    let mut problems: Vec<String> = Vec::new();
    if let Err(e) = systemctl_run(&sc, &["stop", WATCHDOG_SERVICE]) {
        problems.push(e);
    }
    if file {
        if let Err(e) = systemctl_run(&sc, &["disable", WATCHDOG_SERVICE]) {
            problems.push(e);
        }
        if let Err(e) = std::fs::remove_file(unit_path) {
            problems.push(format!("{WATCHDOG_UNIT} could not be removed ({e})"));
        }
        if let Err(e) = hemostat_enforce_linux::daemon_reload() {
            problems.push(format!("systemd was not reloaded ({e})"));
        }
    }

    let _ = systemctl_run(&sc, &["reset-failed", WATCHDOG_SERVICE]);

    let mut left: Vec<&str> = Vec::new();
    match watchdog_active(&sc) {
        Some(false) => {}
        Some(true) => left.push("it is still running"),
        None => left.push("systemctl could not say whether it is still running"),
    }
    if std::fs::symlink_metadata(unit_path).is_ok() {
        left.push("its unit file is still there");
    }
    if !left.is_empty() {
        eprintln!("hemostat services: the uptime watchdog was NOT removed: {}", left.join("; "));
        for p in &problems {
            eprintln!("  {}", h(p));
        }
        return EXIT_ENFORCER;
    }
    for p in &problems {
        eprintln!("  note: {}", h(p));
    }
    journal_or_fail(&UndoRecord {
        did: format!("stopped, disabled and removed the uptime watchdog service ({WATCHDOG_SERVICE})"),
        undo: UndoKind::Irreversible {
            note: "the watchdog goes back with `mahoraga services --install-watchdog --arm`".into(),
        },
        reversible: false,
    })
}

#[cfg(target_os = "linux")]
pub(crate) fn firewall_allow(args: &[String], _json: bool) -> u8 {
    use hemostat_enforce_linux::{ApplyOptions, Outcome, ProtectSet, RemovalAction};

    if let Err(msg) = require_built(hemostat_buildinfo::ActionClass::IsolateInbound) {
        eprintln!("hemostat firewall: {msg}");
        return EXIT_NOT_BUILT;
    }
    let Some(i) = args.iter().position(|a| a == "--allow") else {
        eprintln!("hemostat firewall --allow <port> [--arm]: name the TCP port to allow inbound");
        return EXIT_USAGE;
    };
    let Some(port) = args.get(i + 1).and_then(|v| v.parse::<u16>().ok()).filter(|p| *p > 0) else {
        eprintln!("hemostat firewall --allow <port>: <port> must be a TCP port number, 1-65535");
        return EXIT_USAGE;
    };

    let armed = args.iter().any(|a| a == "--arm");
    let ticket = match crate::authz::armed_gate(
        "firewall",
        hemostat_buildinfo::ActionClass::IsolateInbound,
        armed,
        1,
    ) {
        Ok(t) => t,
        Err(code) => return code,
    };
    if let Err(code) = crate::authz::spend_armed("firewall", armed, ticket) {
        return code;
    }

    let opts = if armed { ApplyOptions::armed() } else { ApplyOptions::dry_run() };

    let protect = ProtectSet::gather().declaring_scored(crate::golden::scored_units_here());
    match (RemovalAction::AllowInboundPort { port }).apply(&opts, &protect) {
        Outcome::Planned(plan) => {
            println!("{}", h(&plan.summary));
            println!("  {}", h(&plan.detail));
            println!("  undo: {}", h(&plan.undo));
            println!();
            println!("Nothing was changed. Add --arm to apply.");
            EXIT_DRYRUN
        }
        Outcome::Refused(r) => {
            eprintln!("hemostat firewall: {}", h(&r.message));
            EXIT_POLICY
        }
        Outcome::Failed(f) => {
            eprintln!("hemostat firewall: {} failed: {}", h(&f.action), h(&f.reason));
            EXIT_ENFORCER
        }
        Outcome::Applied(rec) => journal_or_fail(&rec),
    }
}

#[cfg(all(target_os = "linux", feature = "mod-enf-persistence"))]
pub(crate) fn seal_binaries(args: &[String], json: bool) -> u8 {
    let replace = args.iter().any(|a| a == "--replace");
    if crate::binvault::is_sealed() && !replace {
        eprintln!(
            "hemostat remediate: an arrival binary vault already exists at {}. Re-seal with \
             --replace only if the binaries are still known-clean — re-sealing after a compromise \
             would capture tampered bytes as \"arrival\".",
            crate::binvault::VAULT
        );
        return EXIT_POLICY;
    }
    let results = match crate::binvault::seal_critical() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("hemostat remediate: could not seal binaries: {e}");
            return EXIT_FAILED;
        }
    };

    let sealed = crate::binvault::copies(&results);

    let unsealed = results
        .iter()
        .filter(|r| matches!(&r.outcome, Err(e) if e != crate::binvault::NOT_PRESENT))
        .count();
    if json {
        let rows: Vec<String> = results
            .iter()
            .map(|r| {
                format!(
                    "{{\"path\":{},\"link_to\":{},\"sealed\":{},\"detail\":{}}}",
                    json_str(&r.path),
                    r.link_to.as_deref().map_or_else(|| "null".to_string(), json_str),
                    r.outcome.is_ok(),
                    json_str(match &r.outcome {
                        Ok(s) => s,
                        Err(e) => e,
                    })
                )
            })
            .collect();
        jprintln!(
            "{{\"seal_binaries\":{{\"vault\":{},\"sealed\":{sealed},\"unsealed\":{unsealed},\"items\":[{}]}}}}",
            json_str(crate::binvault::VAULT),
            rows.join(",")
        );
    } else {
        println!(
            "arrival binary vault — sealed {sealed} critical binar{} into {}",
            if sealed == 1 { "y" } else { "ies" },
            crate::binvault::VAULT
        );
        for r in &results {

            let name = match &r.link_to {
                Some(real) => format!("{} -> {}", h(&r.path), h(real)),
                None => h(&r.path),
            };
            match &r.outcome {
                Ok(sha) if r.link_to.is_some() => {
                    println!("  [link]    {name}  sha256:{}", &sha[..16.min(sha.len())])
                }
                Ok(sha) => println!("  [sealed]  {name}  sha256:{}", &sha[..16.min(sha.len())]),

                Err(e) if e == crate::binvault::NOT_PRESENT => {}
                Err(e) => println!("  [skipped] {name} — {}", h(e)),
            }
        }
        if results.iter().any(|r| r.link_to.is_some() && r.outcome.is_ok()) {
            println!(
                "\nA [link] name was sealed as the real file it leads to, once; --restore-binary of \
                 the name restores that file, never through the link."
            );
        }
        if unsealed > 0 {
            let (y, is, it) = if unsealed == 1 { ("y", "is", "it") } else { ("ies", "are", "them") };
            println!(
                "\n{unsealed} critical binar{y} here {is} NOT sealed (see [skipped] above); a later \
                 --restore-binary of {it} will be refused."
            );
        }
        println!("\nRestore a tampered one with `mahoraga remediate --restore-binary <path> --arm`.");
    }
    if sealed == 0 || unsealed > 0 {
        EXIT_PARTIAL
    } else {
        EXIT_OK
    }
}

#[cfg(all(target_os = "linux", feature = "mod-enf-persistence"))]
pub(crate) fn restore_binary(path: &str, args: &[String]) -> u8 {
    use hemostat_enforce_linux::{ApplyOptions, Outcome, ProtectSet, RemovalAction};

    if let Err(msg) = require_built(hemostat_buildinfo::ActionClass::PersistenceNeutralize) {
        eprintln!("hemostat remediate: {msg}");
        return EXIT_NOT_BUILT;
    }
    let good = match crate::binvault::sealed_good(path) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("hemostat remediate: {}", h(&e));
            return EXIT_POLICY;
        }
    };

    if good.target != path {
        println!(
            "{} is a link to {}, as it was when sealed: the vault holds that real file, and this \
             writes it by its own name, never through the link.",
            h(path),
            h(&good.target)
        );
    }

    let armed = args.iter().any(|a| a == "--arm");
    let ticket = match crate::authz::armed_gate(
        "remediate",
        hemostat_buildinfo::ActionClass::PersistenceNeutralize,
        armed,
        1,
    ) {
        Ok(t) => t,
        Err(code) => return code,
    };
    if let Err(code) = crate::authz::spend_armed("remediate", armed, ticket) {
        return code;
    }

    let opts = if armed { ApplyOptions::armed() } else { ApplyOptions::dry_run() };

    let protect = ProtectSet::gather().declaring_scored(crate::golden::scored_units_here());
    let action = RemovalAction::RestoreKnownGood {
        path: std::path::PathBuf::from(&good.target),
        label: format!("{} (arrival vault copy)", good.target),
        content: good.bytes,
        want_sha256: good.sha,
    };
    match action.apply(&opts, &protect) {
        Outcome::Planned(plan) => {
            println!("{}", h(&plan.summary));
            println!("  {}", h(&plan.detail));
            println!("  undo: {}", h(&plan.undo));
            println!();
            println!("Nothing was changed. Add --arm to apply.");
            EXIT_DRYRUN
        }
        Outcome::Refused(r) => {
            eprintln!("hemostat remediate: {}", h(&r.message));
            EXIT_POLICY
        }
        Outcome::Failed(f) => {
            eprintln!("hemostat remediate: {} failed: {}", h(&f.action), h(&f.reason));
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
             --drop-group <group> | --lock [--arm]"
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
    } else if has("--lock") {

        AccountAction::Lock {
            user: user.to_string(),
            uid,
            prior_shell: account::read_shell(user),
            prior_locked: account::read_password_locked(user),
        }
    } else {
        eprintln!(
            "hemostat account {user}: name one of --end-sessions, --purge-tickets, \
             --expire-password, --drop-group <group> or --lock"
        );
        return EXIT_USAGE;
    };

    let class = match &action {
        AccountAction::SessionKill { .. } => ActionClass::SessionKill,
        AccountAction::TicketPurge { .. } => ActionClass::TicketPurge,
        AccountAction::CredRotate { .. } => ActionClass::CredRotate,
        AccountAction::GroupDrop { .. } => ActionClass::GroupDrop,
        AccountAction::Lock { .. } => ActionClass::AccountDisable,
    };
    if let Err(msg) = require_built(class) {
        eprintln!("hemostat account: {msg}");
        return EXIT_NOT_BUILT;
    }

    let protect = ProtectSet::gather().declaring_scored(crate::golden::scored_units_here());
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
pub(crate) fn print_narrow(
    pid: Option<u32>,
    dest: Option<&str>,
    armed: bool,
    subnet: bool,
    plan: Option<&str>,
) -> ExitCode {
    use hemostat_buildinfo::ActionClass;
    use hemostat_sensor_linux::netnarrow as nn;
    use hemostat_sensor_linux::netpolicy as np;

    if pid.is_some() && dest.is_some() {
        eprintln!(
            "hemostat network: --block-pid and --block-dest are separate actions, judged \
             separately — run one, then the other. Nothing was changed"
        );
        return ExitCode::from(EXIT_USAGE);
    }
    if subnet && dest.is_none() {
        eprintln!("hemostat network: --allow-subnet widens a --block-dest, and there is none. Nothing was changed");
        return ExitCode::from(EXIT_USAGE);
    }

    if subnet && crate::golden::active() {
        eprintln!(
            "hemostat network: REFUSED — --allow-subnet is refused while HEMOSTAT_GOLDEN is set: \
             the IRSeC packet (rule 15) allows blocks of single IP addresses only. Nothing was changed"
        );
        return ExitCode::from(EXIT_POLICY);
    }
    let class = if pid.is_some() { ActionClass::ProcBlock } else { ActionClass::DestBlock };
    if let Err(msg) = require_built(class) {
        eprintln!("hemostat network: {msg}");
        return ExitCode::from(EXIT_NOT_BUILT);
    }

    let mut narrowing = nn::Narrowing {
        width: if subnet { nn::Width::Subnet } else { nn::Width::Single },
        ..nn::Narrowing::default()
    };

    if let Some(pid) = pid {
        let Ok(text) = hemostat_sensor_linux::saferead::read_pid_text(format!("/proc/{pid}/cgroup")) else {
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
        let o = nn::occupancy(pid, &cgroup, &nn::read_cgroups());

        let covered = nn::read_covered(&o, hemostat_enforce_linux::account::owners_of);
        if let Some(why) = nn::covering_refusal(&o, &covered) {
            eprintln!("hemostat network: REFUSED — {}. Nothing was changed", h(&why));
            return ExitCode::from(EXIT_POLICY);
        }
        narrowing.processes.push(o);
    }

    if let Some(d) = dest {

        let c = match nn::parse_dest(d, narrowing.width) {
            Ok(c) => c,
            Err(why) => {
                eprintln!("hemostat network: {}", h(&why));
                return ExitCode::from(EXIT_USAGE);
            }
        };

        if let Some(why) = crate::golden::block_scope_here(&c, &crate::golden::own_addrs()) {
            eprintln!("hemostat network: REFUSED — {}. Nothing was changed", h(&why));
            return ExitCode::from(EXIT_POLICY);
        }

        narrowing.keep = match nn::read_syslog_targets() {
            Ok(k) => k,
            Err(why) => {
                eprintln!(
                    "hemostat network: the syslog configuration did not read ({}), so this cannot be \
                     shown not to cut this host's log forwarding. Nothing was changed",
                    h(&why)
                );
                return ExitCode::from(EXIT_POLICY);
            }
        };
        if let Some(why) = nn::kept_by(&c, &narrowing.keep) {
            eprintln!("hemostat network: REFUSED — {}. Nothing was changed", h(&why));
            return ExitCode::from(EXIT_POLICY);
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

    let digest = np::plan_digest(&ruleset);
    if armed {
        if let Err(why) = np::plan_matches(plan, &digest) {
            eprintln!("hemostat network: REFUSED — {}", h(&why));
            return ExitCode::from(if plan.is_none() { EXIT_USAGE } else { EXIT_POLICY });
        }
    }

    let ticket = match crate::authz::armed_gate("network", class, armed, 1) {
        Ok(t) => t,
        Err(code) => return ExitCode::from(code),
    };
    if let Err(code) = crate::authz::spend_armed("network", armed, ticket) {
        return ExitCode::from(code);
    }
    if !armed {
        let what = match (pid, dest) {
            (Some(p), _) => format!("--block-pid {p}"),
            (None, Some(d)) => format!("--block-dest {}{}", h(d.trim()), if subnet { " --allow-subnet" } else { "" }),
            (None, None) => String::new(),
        };
        println!("Nothing was changed. To load exactly this ruleset:");
        println!("    hemostat network {what} --arm --plan {digest}");
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
pub(crate) fn journal_or_fail(rec: &hemostat_enforce_linux::UndoRecord) -> u8 {
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
pub(crate) fn print_network(
    arm: bool,
    seconds: u64,
    confirm: bool,
    revert: bool,
    egress: bool,
    given: Option<&str>,
) -> ExitCode {
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
                for line in m.lines() {
                    println!("{}", h(line));
                }
                ExitCode::from(EXIT_OK)
            }

            Err(e) => {
                for (i, line) in e.lines().enumerate() {
                    eprintln!("{}{}", if i == 0 { "hemostat: " } else { "" }, h(line));
                }
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
    let (declared, mut egress_declared, bad, declarations_unknown) = match network_declarations(
        hemostat_sensor_linux::saferead::read_text(std::path::Path::new(np::DECLARATION)),
    ) {
        Ok((d, e, b)) => (d, e, b, None),
        Err(why) => (Vec::new(), Vec::new(), Vec::new(), Some(why)),
    };

    let golden_team = crate::golden::active()
        .then(|| crate::golden::team(std::env::var(crate::golden::TEAM_ENV).ok().as_deref(), &crate::golden::own_addrs()));

    let management_note = match (&golden_team, egress) {
        (_, false) => None,
        (None, true) => Some(
            "--egress refuses NEW outbound connections from this host, SSH, RDP and WinRM to other \
             boxes included (connections already open stay up). If you reach other boxes from here, \
             declare them first (`egress tcp/22 ADDR` in /etc/hemostat/network-allow), or set \
             HEMOSTAT_GOLDEN so the team's own boxes stay reachable."
                .to_string(),
        ),
        (Some(Ok(team)), true) => {
            egress_declared.extend(golden_management_allows(*team));
            None
        }
        (Some(Err(why)), true) => {
            Some(format!("--egress will refuse NEW outbound SSH, RDP and WinRM to the team's other boxes: {why}"))
        }
    };

    let netbird_refusal = match &golden_team {
        None => None,
        Some(Err(why)) => Some(format!(
            "the team is not known ({why}), so the NetBird egress (10.T.1.99), whose traffic the packet \
             says is never blocked, cannot be kept open: set {}",
            crate::golden::TEAM_ENV
        )),
        Some(Ok(_)) if hemostat_sensor_linux::netnarrow::netbird_runs() => Some(
            "NetBird's agent runs on this host (a process named `netbird`), and the packet says NetBird's \
             traffic is never blocked: a default-deny here could cut the tunnel the cloud boxes are reached \
             through. Contain one address or process with --block-dest or --block-pid instead"
                .to_string(),
        ),
        Some(Ok(_)) => None,
    };
    let session = np::session_port(std::env::var("SSH_CONNECTION").ok().as_deref());
    let mut plan = np::plan(&listening, &declared, session);
    if let Some(Ok(team)) = &golden_team {
        let egress_host = crate::golden::netbird_egress(*team);
        let why = format!("the NetBird egress {egress_host}: the packet says its traffic is never blocked");
        plan.trusted.push((egress_host, np::Origin::Mandatory(why)));
        egress_declared.extend(golden_netbird_allows(*team));
    }

    if golden_team.is_some() {
        for (addr, port) in crate::golden::INFRA_EXCEPTIONS {
            let why = format!("{addr}:{port}, competition infrastructure the organizers named; never cut");
            plan.trusted.push(((*addr).to_string(), np::Origin::Mandatory(why)));
        }
        egress_declared.extend(golden_infra_allows());
    }

    println!("Inbound policy plan — default deny, with these exceptions:");
    println!();
    for a in &plan.allows {
        println!("  {:<4}/{:<6} {:<18} {}",
            a.proto.token(),
            a.port,
            a.from.as_deref().unwrap_or("from anywhere"),
            np::describe(&a.origin));
    }
    for (from, origin) in &plan.trusted {
        println!("  {:<11} {:<18} {}", "every port", from, np::describe(origin));
    }
    println!();
    println!("Always applied and not listed above: loopback, ESTABLISHED/RELATED (this is what");
    println!("keeps your current session alive across the change), and ICMP. Outbound and");
    println!("forwarding are not touched.");

    let ftp = np::ftp_helper_lines(&plan);
    if !ftp.is_empty() {
        println!();
        println!("tcp/21 is kept, so the ruleset also attaches the kernel's FTP conntrack");
        println!("helper (nf_conntrack_ftp) to it. The passive data connections an FTP server");
        println!("opens then arrive as RELATED and pass; without it they are NEW and the deny");
        println!("drops them. A kernel that cannot load the helper fails the arm, which then");
        println!("rolls back with nothing applied. The lines it adds:");
        for l in &ftp {
            println!("  {l}");
        }
    }

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
        let accounts = hemostat_sensor_linux::saferead::read_text(std::path::Path::new("/etc/passwd"))
            .ok()
            .map(|t| hemostat_sensor_linux::accounts::parse_passwd(&t));
        np::egress_plan(&np::resolvers(), &egress_declared, np::uses_dhcp(), &np::resolved_upstreams(), accounts.as_deref())
    });

    if let Some(note) = &management_note {
        println!();
        println!("WARNING: {}", h(note));
    }
    if let Some(eg) = &eplan {
        println!();
        println!("Egress policy plan — default deny outbound, with these exceptions:");
        println!();
        for (uid, origin) in &eg.owners {
            println!("  {:<11} {:<22} {}", "any", format!("from uid {uid}"), np::describe(origin));
        }
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
        for b in &eg.blocked {
            println!();
            println!("REFUSED WHEN ARMED: {}", h(b));
        }
    }

    let digest = np::plan_digest(&np::render_nft_with_egress(&plan, eplan.as_ref()));

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
        println!("To apply, `--arm` with this plan's digest (the window is yours to choose).");
        println!("  The ruleset loads, and rolls itself back in that many seconds unless you run");
        println!("  `hemostat network --confirm`. Open a SECOND connection and check it works");
        println!("  before confirming — that check is the point, not a formality.");
        println!("  On a VM you can reach by console, that console is your way back regardless.");
        println!("  The armed run plans again from the host, and refuses if that plan is not");
        println!("  this one: a listener that came or went since is a different plan.");
        if let Some(why) = &declarations_unknown {
            println!();
            println!("WARNING: {why}");
        }
        if let Some(why) = &netbird_refusal {
            println!();
            println!("REFUSED WHEN ARMED: {}", h(why));
        }

        println!();
        println!(
            "To apply exactly this plan:  hemostat network --arm 120{} --plan {digest}",
            if egress { " --egress" } else { "" }
        );

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

    if let Some(b) = eplan.as_ref().and_then(|eg| eg.blocked.first()) {
        eprintln!("hemostat network: REFUSED — {}. Nothing was changed", h(b));
        return ExitCode::from(EXIT_POLICY);
    }
    if let Some(why) = &netbird_refusal {
        eprintln!("hemostat network: REFUSED — {}. Nothing was changed", h(why));
        return ExitCode::from(EXIT_POLICY);
    }

    if let Err(why) = np::plan_matches(given, &digest) {
        eprintln!("hemostat network: REFUSED — {}", h(&why));
        return ExitCode::from(if given.is_none() { EXIT_USAGE } else { EXIT_POLICY });
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
const MANAGEMENT_PORTS: [(u16, &str); 4] = [(22, "SSH"), (3389, "RDP"), (5985, "WinRM"), (5986, "WinRM over TLS")];

#[cfg(target_os = "linux")]
fn golden_management_allows(team: u8) -> Vec<hemostat_sensor_linux::netpolicy::EgressAllow> {
    use hemostat_sensor_linux::netpolicy as np;
    let ranges = [format!("10.{team}.1.0/24"), format!("192.168.{team}.0/24")];
    ranges
        .iter()
        .flat_map(|range| {
            MANAGEMENT_PORTS.iter().map(move |(port, what)| np::EgressAllow {
                proto: np::Proto::Tcp,
                port: Some(*port),
                to: Some(range.clone()),
                origin: np::Origin::Mandatory(format!(
                    "{what} to the team's boxes in {range}: the way to them from here (HEMOSTAT_GOLDEN, team {team})"
                )),
            })
        })
        .collect()
}

#[cfg(target_os = "linux")]
fn golden_infra_allows() -> Vec<hemostat_sensor_linux::netpolicy::EgressAllow> {
    use hemostat_sensor_linux::netpolicy as np;
    crate::golden::INFRA_EXCEPTIONS
        .iter()
        .flat_map(|(addr, port)| {
            [np::Proto::Tcp, np::Proto::Udp].into_iter().map(move |proto| np::EgressAllow {
                proto,
                port: Some(*port),
                to: Some((*addr).to_string()),
                origin: np::Origin::Mandatory(format!(
                    "{addr}:{port}, competition infrastructure the organizers named; never cut"
                )),
            })
        })
        .collect()
}

#[cfg(target_os = "linux")]
fn golden_netbird_allows(team: u8) -> Vec<hemostat_sensor_linux::netpolicy::EgressAllow> {
    use hemostat_sensor_linux::netpolicy as np;
    let host = crate::golden::netbird_egress(team);
    [np::Proto::Tcp, np::Proto::Udp]
        .into_iter()
        .map(|proto| np::EgressAllow {
            proto,
            port: None,
            to: Some(host.clone()),
            origin: np::Origin::Mandatory(format!("the NetBird egress {host}: the packet says its traffic is never blocked")),
        })
        .collect()
}

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

#[cfg(any(target_os = "windows", all(test, target_os = "linux")))]
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct WinWatchdogProcs {

    pub(crate) wrappers: Vec<(u32, String)>,

    pub(crate) children: Vec<(u32, String)>,

    pub(crate) alive: Vec<u32>,

    pub(crate) strays: Vec<(u32, String)>,
}

#[cfg(any(target_os = "windows", all(test, target_os = "linux")))]
pub(crate) fn win_watchdog_query(wrapper: &str, pids: &[u32]) -> String {
    let pids: Vec<String> = pids.iter().map(u32::to_string).collect();
    format!(
        "$ErrorActionPreference = 'Stop'\n\
         $w = '{w}'\n\
         $all = @(Get-CimInstance -ClassName Win32_Process)\n\
         $own = @()\n\
         foreach ($c in $all) {{\n\
         if ($c.Name -ne 'cmd.exe' -or -not $c.CommandLine) {{ continue }}\n\
         if ($c.CommandLine.IndexOf($w, [StringComparison]::OrdinalIgnoreCase) -lt 0) {{ continue }}\n\
         'TASK' + [char]9 + $c.ProcessId + [char]9 + $c.Name\n\
         $own += $c.ProcessId\n\
         foreach ($k in $all) {{ if ($k.ParentProcessId -eq $c.ProcessId -and $k.CreationDate -ge $c.CreationDate) {{ 'CHILD' + [char]9 + $k.ProcessId + [char]9 + $k.Name; $own += $k.ProcessId }} }}\n\
         }}\n\
         foreach ($k in $all) {{\n\
         if ($own -contains $k.ProcessId -or -not $k.CommandLine) {{ continue }}\n\
         if ($k.CommandLine -match ' services --restore --every [0-9]+ --arm\\s*$') {{ 'STRAY' + [char]9 + $k.ProcessId + [char]9 + $k.Name }}\n\
         }}\n\
         foreach ($p in @({pids})) {{ foreach ($k in $all) {{ if ($k.ProcessId -eq $p) {{ 'ALIVE' + [char]9 + $p }} }} }}\n\
         'END'\n",
        w = ps_single_quoted(wrapper),
        pids = pids.join(","),
    )
}

#[cfg(any(target_os = "windows", all(test, target_os = "linux")))]
fn ps_single_quoted(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if matches!(c, '\'' | '\u{2018}' | '\u{2019}' | '\u{201A}' | '\u{201B}') {
            out.push(c);
        }
        out.push(c);
    }
    out
}

#[cfg(any(target_os = "windows", all(test, target_os = "linux")))]
pub(crate) fn parse_win_watchdog_procs(out: &str) -> Result<WinWatchdogProcs, String> {
    let mut found = WinWatchdogProcs::default();
    let mut ended = false;
    for line in out.lines().map(str::trim).filter(|l| !l.is_empty()) {
        if ended {
            return Err(format!("the process query went on after END: {line}"));
        }
        let pid = |p: &str| p.parse::<u32>().map_err(|_| format!("the process query gave {p:?} for a pid"));
        let f: Vec<&str> = line.split('\t').collect();
        match f.as_slice() {
            ["END"] => ended = true,
            ["TASK", p, name] => found.wrappers.push((pid(p)?, (*name).to_string())),
            ["CHILD", p, name] => found.children.push((pid(p)?, (*name).to_string())),
            ["STRAY", p, name] => found.strays.push((pid(p)?, (*name).to_string())),
            ["ALIVE", p] => found.alive.push(pid(p)?),
            _ => return Err(format!("the process query gave a line it does not write: {line}")),
        }
    }
    if ended {
        Ok(found)
    } else {
        Err("the process query did not finish (no END)".into())
    }
}

#[cfg(any(target_os = "windows", all(test, target_os = "linux")))]
pub(crate) fn win_watchdog_kill_list(found: &WinWatchdogProcs, me: u32) -> Vec<u32> {
    let mut pids: Vec<u32> = found
        .wrappers
        .iter()
        .chain(&found.children)
        .map(|(p, _)| *p)
        .filter(|p| *p != me && *p > 4)
        .collect();
    pids.sort_unstable();
    pids.dedup();
    pids
}

#[cfg(any(target_os = "windows", all(test, target_os = "linux")))]
pub(crate) fn win_task_listed(csv: &str, name: &str) -> bool {
    let want = format!("\\{name}");
    csv.lines()
        .filter_map(|l| l.trim().strip_prefix('"').and_then(|r| r.split('"').next()))
        .any(|t| t.eq_ignore_ascii_case(&want))
}
