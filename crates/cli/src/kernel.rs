#[cfg(target_os = "linux")]
use crate::print_findings;
#[cfg(all(target_os = "linux", feature = "mod-enf-persistence"))]
use crate::authz::{broker_admits, class_of_action, exit_for_refusal, loaded_sanction, presented_authority};
#[cfg(all(target_os = "linux", feature = "mod-enf-persistence"))]
use crate::{EXIT_AUTHZ, EXIT_DRYRUN, EXIT_ENFORCER, EXIT_POLICY};
#[cfg(target_os = "linux")]
use crate::render::{finding_rows, h, jesc, json_array, triage_row};
#[cfg(all(target_os = "linux", feature = "mod-enf-persistence"))]
use crate::render::hl;
#[cfg(target_os = "linux")]
use crate::{EXIT_OK, EXIT_PARTIAL};

#[cfg(all(target_os = "linux", feature = "mod-enf-persistence"))]
pub(crate) fn print_kmod(json: bool, unload: Option<&str>, armed: bool) -> u8 {
    use hemostat_enforce_linux::{ApplyOptions, ModuleSighting, Outcome, ProtectSet, RemovalAction};

    let walk = hemostat_sensor_linux::kwalk_report();

    let Some(name) = unload else {

        if json {
            jprintln!(
                "{{\"available\":{},\"module_crossview_ran\":{},\"modules_walked\":{},\"hidden\":[{}]}}",
                walk.available,
                walk.module_crossview_ran,
                walk.modules_walked,
                walk.hidden_modules
                    .iter()
                    .map(|m| format!("\"{}\"", jesc(m)))
                    .collect::<Vec<_>>()
                    .join(",")
            );
        } else {
            println!("kmod — what the kernel says is loaded\n");
            if !walk.available {
                println!(
                    "  the kernel module list could not be walked: {}",
                    h(walk.reason.as_deref().unwrap_or("reason not recorded"))
                );
                println!(
                    "  this is NOT a clean answer. Without the walk, a module that hid itself\n                       from /proc/modules is indistinguishable from one that is not there."
                );
                return kmod_list_exit(&walk);
            }
            println!("  {} module(s) in the kernel's own list", walk.modules_walked);
            if !walk.module_crossview_ran {

                println!(
                    "  /proc/modules could NOT be read, so the kernel's list was not compared
                       against it. That is not an all-clear: a module hidden from /proc/modules
                       would look exactly like this. Re-run as root."
                );
                return kmod_list_exit(&walk);
            }
            if walk.hidden_modules.is_empty() {
                println!("  none of them are missing from /proc/modules.");
            } else {
                println!(
                    "\n  {} HIDDEN — in the kernel's list, filtered out of /proc/modules:",
                    walk.hidden_modules.len()
                );
                for m in &walk.hidden_modules {
                    println!("    {}", h(m));
                }
                println!(
                    "\n  Unload one with:  hemostat kmod --unload <name> --arm\n                       Read the plan first: without --arm it only prints what it would do."
                );
            }
        }
        return kmod_list_exit(&walk);
    };

    let in_sysfs = std::path::Path::new(&format!("/sys/module/{name}")).exists();
    let hidden = walk.hidden_modules.iter().any(|m| m == name);
    let seen = if in_sysfs {
        ModuleSighting::Sysfs
    } else if hidden {
        ModuleSighting::KernelListOnly
    } else if !walk.available {
        eprintln!(
            "hemostat kmod: `{name}` is not in /sys/module, and the kernel's module list could \
             not be walked ({}) — so nothing here can tell a hidden module from a name that is \
             simply wrong. Re-run as root.",
            h(walk.reason.as_deref().unwrap_or("reason not recorded"))
        );
        return EXIT_PARTIAL;
    } else {

        ModuleSighting::Sysfs
    };

    let action = RemovalAction::UnloadModule { name: name.to_string(), seen };
    let protect = ProtectSet::gather();

    let class = class_of_action(&action);
    let ticket_class = hemostat_buildinfo::ActionClass::ALL
        .iter()
        .position(|a| *a == class)
        .and_then(|i| u8::try_from(i).ok())
        .unwrap_or(hemostat_evcrypto::ticket::NO_CLASS);
    let (authority, ticket) = match presented_authority(hemostat_evcrypto::ticket::Op::Action, ticket_class) {
        Ok(a) => a,
        Err(why) => {
            eprintln!("hemostat kmod: {why}");
            return EXIT_AUTHZ;
        }
    };
    let sanction = match loaded_sanction() {
        Ok(s) => s,
        Err(why) => {
            eprintln!("hemostat kmod: {why}");
            return EXIT_POLICY;
        }
    };

    match broker_admits(&action, armed, authority, &sanction, 1) {
        Err((stage, why)) => {
            eprintln!("hemostat kmod: {why}");
            return exit_for_refusal(stage);
        }
        Ok(gaps) => {
            for g in gaps {
                eprintln!("  broker stage NOT performed: {} — {}", g.stage.token(), g.why);
            }
        }
    }

    let opts = if armed { ApplyOptions::armed() } else { ApplyOptions::default() };

    if armed {
        if let Some(t) = ticket {
            if let Err(why) = t.spend() {
                eprintln!("hemostat kmod: {why}");
                return why.exit_code();
            }
        }
    }
    match action.apply(&opts, &protect) {
        Outcome::Planned(p) => {
            println!("  would: {}", hl(&p.detail));
            println!("  undo:  {}", hl(&p.undo));
            println!("\n  Nothing was changed. Re-run with --arm to apply.");
            EXIT_DRYRUN
        }
        Outcome::Applied(rec) => {
            println!("  [done] {}", h(&rec.did));
            if let hemostat_enforce_linux::UndoKind::Irreversible { note } = &rec.undo {
                println!("  {}", hl(note));
            }
            EXIT_OK
        }
        Outcome::Refused(r) => {
            eprintln!("  [refused] {}", h(&r.message));
            EXIT_POLICY
        }
        Outcome::Failed(f) => {
            eprintln!("  [FAILED] {}", h(&f.reason));
            EXIT_ENFORCER
        }
    }
}

#[cfg(all(target_os = "linux", feature = "mod-enf-persistence"))]
fn kmod_list_exit(walk: &hemostat_sensor_linux::KwalkReport) -> u8 {
    if walk.available && walk.module_crossview_ran {
        EXIT_OK
    } else {
        EXIT_PARTIAL
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn print_kwalk(json: bool) -> u8 {
    let r = hemostat_sensor_linux::kwalk_report();

    let code = crate::coverage::kwalk(&r).exit_code();

    if json {
        let f = r
            .findings
            .iter()
            .map(|f| {
                triage_row(f)
            })
            .collect::<Vec<_>>()
            .join(",");
        jprintln!(
            "{{\"available\":{},\"reason\":\"{}\",\"module_crossview_ran\":{},\
             \"gaps\":{},\"findings\":[{f}]}}",
            r.available,
            jesc(r.reason.as_deref().unwrap_or("")),
            r.module_crossview_ran,
            json_array(&r.gaps),
        );
        return code;
    }

    if !r.available {
        println!("kernel-memory ground-truth walk: DID NOT RUN");
        println!("  {}", h(r.reason.as_deref().unwrap_or("unavailable")));
        println!("\nRun as root on a host whose kernel is not in lockdown-confidentiality.");
        return EXIT_PARTIAL;
    }
    println!(
        "kernel-memory ground-truth walk: {} finding(s)  ({} task leaders, {} modules walked)",
        r.findings.len(),
        r.tasks_walked,
        r.modules_walked
    );
    if r.findings.is_empty() {
        println!("  the kernel's task and module lists agree with /proc — nothing hidden at this depth.");
    }
    if !r.gaps.is_empty() {
        println!("  NOT A WHOLE WALK — {} part(s) did not run or did not finish:", r.gaps.len());
        for g in &r.gaps {
            println!("    {}", h(g));
        }
    }
    for f in &r.findings {
        println!("  [{}] {} — {}", f.severity.tag(), h(&f.subject), h(&f.locus));
        println!("      {}", h(&f.what));
        if !f.why.is_empty() {
            println!("      why: {}", h(&f.why));
        }
    }
    println!(
        "\nRead from /proc/kcore using the kernel's own BTF offsets: the task and module lists\n\
         as the kernel holds them, not as /proc renders them. Catches a getdents/open/stat or\n\
         /proc/modules-output hook that the userland views cannot. A full DKOM unlink from the\n\
         lists themselves is the remaining depth (the PID idr / mod_tree walk)."
    );
    code
}

#[cfg(target_os = "linux")]
pub(crate) fn print_kground(json: bool) -> u8 {
    let r = hemostat_sensor_linux::kground_report();
    let code = crate::coverage::kground(&r).exit_code();

    if json {
        let f = r.findings.iter().map(|f| triage_row(f)).collect::<Vec<_>>().join(",");
        jprintln!(
            "{{\"coverage\":\"{}\",\"reason\":\"{}\",\"tasks_walked\":{},\"processes_walked\":{},\
             \"procfs_processes\":{},\"hidden\":{},\"findings\":[{f}]}}",
            r.coverage.token(),
            jesc(r.reason.as_deref().unwrap_or("")),
            r.tasks_walked,
            r.processes_walked,
            r.procfs_processes,
            r.hidden.len(),
        );
        return code;
    }

    if matches!(r.coverage, hemostat_sensor_linux::Coverage::Unreadable) {
        println!("kernel task ground-truth cross-view: DID NOT RUN");
        println!("  {}", h(r.reason.as_deref().unwrap_or("the kernel task iterator could not run")));
        println!(
            "\nRun as root on a host with CONFIG_DEBUG_INFO_BTF and a kernel >= 5.8 (bpf_iter/task)."
        );
        return code;
    }
    println!(
        "kernel task ground-truth cross-view: {} finding(s)  ({} processes from the kernel's \
         iterator, {} listed by /proc)",
        r.findings.len(),
        r.processes_walked,
        r.procfs_processes,
    );
    if r.findings.is_empty() {
        println!(
            "  the kernel's task set agrees with /proc — no process the kernel runs is hidden \
             from a directory read."
        );
    }
    if let Some(reason) = &r.reason {
        println!("  NOT A WHOLE SWEEP — {}", h(reason));
    }
    for f in &r.findings {
        println!("  [{}] {} — {}", f.severity.tag(), h(&f.subject), h(&f.locus));
        println!("      {}", h(&f.what));
        if !f.why.is_empty() {
            println!("      why: {}", h(&f.why));
        }
    }
    println!(
        "\nThe task set from the kernel's own bpf_iter/task, below the /proc view a getdents or\n\
         DKOM rootkit manipulates. A process the kernel schedules that /proc does not list is\n\
         hidden; this is the kernel-level ground truth kwalk's /proc/kcore walk cannot guarantee."
    );
    code
}

#[cfg(target_os = "linux")]
pub(crate) fn print_kernposture(json: bool) {
    use hemostat_sensor_linux::TriageSeverity;
    let r = hemostat_sensor_linux::kernposture_report();

    if json {
        let f = r
            .findings
            .iter()
            .map(|f| {
                triage_row(f)
            })
            .collect::<Vec<_>>()
            .join(",");
        jprintln!("{{\"privileged\":{},\"findings\":[{f}]}}", r.privileged);
        return;
    }

    println!(
        "kernel defensive posture ({}):",
        if r.privileged { "privileged read" } else { "unprivileged — some checks are context-only" }
    );
    let crit = r.findings.iter().filter(|f| matches!(f.severity, TriageSeverity::Critical)).count();
    let warn = r.findings.iter().filter(|f| matches!(f.severity, TriageSeverity::Warn)).count();
    println!("  {} finding(s), {crit} critical, {warn} warn\n", r.findings.len());
    for f in &r.findings {
        println!("  [{}] {} — {}", f.severity.tag(), h(&f.subject), h(&f.locus));
        println!("      {}", h(&f.what));
        if !f.why.is_empty() {
            println!("      why: {}", h(&f.why));
        }
    }
    println!(
        "\nThis is the battlefield, not a hook scan: whether a kernel rootkit could load\n\
         (module signing, Secure Boot, modules_disabled), and whether one is blinding a\n\
         privileged agent right now. Trust: Syscall — a kernel rootkit can lie here too,\n\
         but a value that disagrees with our known privilege is itself the finding."
    );
}

#[cfg(target_os = "linux")]
pub(crate) fn print_sysmap(json: bool) -> u8 {
    let r = hemostat_sensor_linux::sysmap::report();
    print_findings(
        "System.map vs kallsyms corroboration",
        r.available,
        r.reason.as_deref(),
        &r.findings,
        json,
    );
    if r.available { EXIT_OK } else { EXIT_PARTIAL }
}

#[cfg(target_os = "linux")]
pub(crate) fn print_kptrhooks(json: bool) -> u8 {
    let r = hemostat_sensor_linux::kptrhooks::report();
    print_findings(
        "kernel function-pointer integrity (seq_file/VFS ops)",
        r.available,
        r.reason.as_deref(),
        &r.findings,
        json,
    );
    if r.available { EXIT_OK } else { EXIT_PARTIAL }
}

#[cfg(target_os = "linux")]
pub(crate) fn print_rootkit(json: bool) -> u8 {
    let r = hemostat_sensor_linux::rootkit_report();

    let code = crate::coverage::rootkit(&r).exit_code();

    if json {
        let f = finding_rows(&r.findings);
        let goofkit = match r.goofkit_getdents_hook {
            Some(true) => "true",
            Some(false) => "false",
            None => "null",
        };
        jprintln!(
            "{{\"cross_view_ran\":{},\"hidden_pids\":{},\"goofkit_getdents_hook\":{goofkit},\
             \"did_not_run\":{},\"findings\":[{f}]}}",
            r.cross_view_ran,
            r.hidden_pids.len(),
            json_array(&r.did_not_run),
        );
        return code;
    }

    let critical = r.findings.iter().filter(|f| f.severity == hemostat_sensor_linux::rootkit::Severity::Critical).count();
    println!(
        "rootkit surface: {} finding(s){}",
        r.findings.len(),
        if critical > 0 { format!(", {critical} CRITICAL") } else { String::new() }
    );
    println!();
    for f in &r.findings {
        println!("  [{}] {}", f.severity.tag(), h(&f.subject));
        println!("      {}", h(&f.what));
        println!("      why: {}", h(&f.why));
    }
    println!(
        "\nEvery check here runs in userspace, so a kernel rootkit can lie to all of\n\
         them. The process cross-view catches a rootkit that hides from the /proc\n\
         listing but not from stat (e.g. goofkit); the goofkit probe goes further,\n\
         creating a file named with that tool's own magic string and watching its\n\
         getdents hook hide it. Neither can see a rootkit that hooks stat as well.\n\
         Ground truth needs HEMOSTAT's own kernel module."
    );
    code
}

#[cfg(target_os = "linux")]
pub(crate) fn print_bpfprog(json: bool) -> u8 {
    let r = hemostat_sensor_linux::bpfprog_report();

    if json {
        let f = finding_rows(&r.findings);
        jprintln!(
            "{{\"available\":{},\"program_count\":{},\"interception_count\":{},\"lsm_count\":{},\
             \"nonroot_count\":{},\"pins\":{},\"findings\":[{f}]}}",
            r.available, r.program_count, r.interception_count, r.lsm_count,
            r.nonroot_count, r.pins.len()
        );
        return bpfprog_exit(&r);
    }

    if r.available {
        println!(
            "eBPF programs: {} loaded ({} interception-class, {} LSM, {} non-root-loaded); \
             {} bpffs pin(s)",
            r.program_count, r.interception_count, r.lsm_count, r.nonroot_count, r.pins.len()
        );
    } else {
        println!(
            "eBPF program walk did not run: {}",
            h(&r.reason.clone().unwrap_or_else(|| "unavailable".into()))
        );
        println!("  ({} bpffs pin(s) still enumerated without root)", r.pins.len());
    }
    println!();
    for f in &r.findings {
        println!("  [{}] {}", f.severity.tag(), h(&f.subject));
        println!("      {}", h(&f.what));
        println!("      why: {}", h(&f.why));
    }
    println!(
        "\nThis reads program metadata, not bytecode — it points you at the programs\n\
         to pull with `bpftool prog dump xlated id <id>`, it does not prove intent.\n\
         eBPF is dual-use, so nothing here is CRITICAL on presence alone. A program\n\
         that has subverted the kernel could hide its own id from this walk; ruling\n\
         that out needs HEMOSTAT's kernel module."
    );
    bpfprog_exit(&r)
}

#[cfg(target_os = "linux")]
fn bpfprog_exit(r: &hemostat_sensor_linux::BpfProgReport) -> u8 {
    if r.available && !r.census_incomplete {
        EXIT_OK
    } else {
        EXIT_PARTIAL
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn print_crossview(json: bool) -> u8 {
    let r = hemostat_sensor_linux::crossview_report();

    if json {
        let f = finding_rows(&r.findings);
        let loadavg = r.loadavg_total.map_or_else(|| "null".into(), |t| t.to_string());
        jprintln!(
            "{{\"available\":{},\"raw_sockets\":{},\"packet_sockets\":{},\"loadavg_total\":{loadavg},\
             \"tasks_seen\":{},\"io_uring_holders\":{},\"findings\":[{f}]}}",
            r.available, r.raw_sockets, r.packet_sockets, r.tasks_seen, r.io_uring_holders
        );
        return if r.available { EXIT_OK } else { EXIT_PARTIAL };
    }

    if !r.available {
        println!(
            "userland cross-views did not run: {}",
            h(&r.reason.unwrap_or_else(|| "unavailable".into()))
        );
        return EXIT_PARTIAL;
    }
    println!("userland cross-views: {} finding(s)", r.findings.len());
    println!();
    for f in &r.findings {
        println!("  [{}] {}", f.severity.tag(), h(&f.subject));
        println!("      {}", h(&f.what));
        println!("      why: {}", h(&f.why));
    }
    println!(
        "\nThese read /proc, so a kernel rootkit that lies to /proc lies to these too;\n\
         they catch the incomplete lie — a task hidden from the /proc walk but still\n\
         counted in loadavg, a C2 socket family the tcp/udp view skips, I/O routed\n\
         through io_uring past the syscall watches. `rootkit` runs these and the\n\
         root-only kernel-text scans together."
    );
    if r.available { EXIT_OK } else { EXIT_PARTIAL }
}

#[cfg(target_os = "linux")]
pub(crate) fn print_syscall_hooks(json: bool) -> u8 {
    let r = hemostat_sensor_linux::syscall_hook_report();

    if json {
        let f = finding_rows(&r.findings);
        let reason = r.reason.as_deref().unwrap_or("");
        jprintln!(
            "{{\"available\":{},\"functions_checked\":{},\"table_entries_checked\":{},\"reason\":\"{}\",\"findings\":[{f}]}}",
            r.available,
            r.functions_checked,
            r.table_entries_checked,
            jesc(reason)
        );
        return if r.available { EXIT_OK } else { EXIT_PARTIAL };
    }

    if !r.available {
        println!("kernel-text scan: DID NOT RUN");
        println!("  {}", h(r.reason.as_deref().unwrap_or("unavailable")));
        println!("\nRun as root on a host whose kernel is not in lockdown-confidentiality.");
        return EXIT_PARTIAL;
    }

    let critical = r.findings.iter()
        .filter(|f| f.severity == hemostat_sensor_linux::rootkit::Severity::Critical)
        .count();
    println!(
        "kernel-text scan: {} prologue(s) + {} table entries read from /proc/kcore; {} finding(s){}",
        r.functions_checked,
        r.table_entries_checked,
        r.findings.len(),
        if critical > 0 { format!(", {critical} CRITICAL") } else { String::new() }
    );
    println!();
    for f in &r.findings {
        println!("  [{}] {}", f.severity.tag(), h(&f.subject));
        println!("      {}", h(&f.what));
        println!("      why: {}", h(&f.why));
    }
    if r.findings.is_empty() {
        println!("  no inline hook or syscall-table redirection in the functions read.");
    }
    println!(
        "\nThis reads the kernel's own code, so it needs no magic string and a rootkit that\n\
         also hooks stat cannot hide from it. It covers DIRECT text patching (goofkit's\n\
         class) and table redirection — NOT ftrace/BPF-based hooks, which leave the\n\
         prologue legitimate. Ground truth below the kernel still needs the kernel module."
    );
    if r.available { EXIT_OK } else { EXIT_PARTIAL }
}

#[cfg(target_os = "linux")]
pub(crate) fn print_ftrace_hooks(json: bool) -> u8 {
    let r = hemostat_sensor_linux::ftrace_hook_report();

    if json {
        let f = finding_rows(&r.findings);
        let reason = r.reason.as_deref().unwrap_or("");
        jprintln!(
            "{{\"available\":{},\"traced_functions\":{},\"watched_traced\":{},\"reason\":\"{}\",\"findings\":[{f}]}}",
            r.available,
            r.traced_functions,
            r.watched_traced,
            jesc(reason)
        );
        return if r.available { EXIT_OK } else { EXIT_PARTIAL };
    }

    if !r.available {
        println!("ftrace-hook scan: DID NOT RUN");
        println!("  {}", h(r.reason.as_deref().unwrap_or("unavailable")));
        return EXIT_PARTIAL;
    }

    let critical = r.findings.iter()
        .filter(|f| f.severity == hemostat_sensor_linux::rootkit::Severity::Critical)
        .count();
    println!(
        "ftrace-hook scan: {} traced function(s), {} watched syscalls; {} finding(s){}",
        r.traced_functions,
        r.watched_traced,
        r.findings.len(),
        if critical > 0 { format!(", {critical} CRITICAL") } else { String::new() }
    );
    println!();
    for f in &r.findings {
        println!("  [{}] {}", f.severity.tag(), h(&f.subject));
        println!("      {}", h(&f.what));
        println!("      why: {}", h(&f.why));
    }
    if r.findings.is_empty() {
        println!("  no watched syscall is ftrace-hooked into a module or outside kernel text.");
    }
    println!(
        "\nThis catches what the inline-prologue scan cannot: a hook installed through ftrace\n\
         leaves the prologue as the compiler's legitimate call, and redirects in the callback.\n\
         A callback into a loaded module, on a syscall, is the rootkit shape; one merely outside\n\
         kernel text may be a BPF monitor or a live-patch — identify the tracer."
    );
    if r.available { EXIT_OK } else { EXIT_PARTIAL }
}

#[cfg(target_os = "linux")]
pub(crate) fn arm_selfprotect(json: bool) -> u8 {
    use hemostat_sensor_linux::selfprotect;

    #[cfg(feature = "mod-selfsandbox")]
    {
        use hemostat_sensor_linux::selfsandbox;
        let vault = std::path::PathBuf::from(hemostat_enforce_linux::DEFAULT_VAULT);
        let _ = std::fs::create_dir_all(&vault);
        match selfsandbox::Sandbox::build(&[vault, std::path::PathBuf::from("/tmp")])
            .and_then(selfsandbox::Sandbox::apply)
        {
            Ok(a) => {
                if !json {
                    println!("self-sandbox: APPLIED");
                    println!();
                    println!("  {}", h(&a.summary()));
                    println!();
                }
            }
            Err(e) => {
                if !json {

                    println!("self-sandbox: NOT applied — {}", h(&e.message()));
                    println!();
                }
            }
        }
    }

    let own = std::process::id();

    let measured = selfprotect::trial();

    match selfprotect::arm_resident(own) {

        Ok(armed) if !worth_holding(measured.verdict) => {
            let pid = armed.target;
            drop(armed);
            if json {
                jprintln!(
                    "{{\"armed\":false,\"pid\":{pid},\"enforcement\":\"{}\"}}",
                    measured.verdict.token()
                );
            } else {
                println!(
                    "self-protection (lsm/task_kill deny): ATTACHED BUT INERT — the program \
                     loaded and the kernel does not invoke the hook"
                );
                println!(
                    "  this host is NOT protected. Check the boot line: `bpf` must be in the \
                     active LSM list (/sys/kernel/security/lsm)"
                );
                println!("  detached: not holding a deny the kernel never invokes.");
            }
            crate::EXIT_ENFORCER
        }
        Ok(armed) => {
            if json {
                jprintln!(
                    "{{\"armed\":true,\"pid\":{},\"tgid_offset\":{},\"enforcement\":\"{}\"}}",
                    armed.target,
                    armed.tgid_offset,
                    measured.verdict.token()
                );
            } else {

                match measured.verdict {
                    selfprotect::Verdict::Denies => {
                        println!("self-protection (lsm/task_kill deny): ARMED and MEASURED DENYING");
                    }
                    v => {
                        println!(
                            "self-protection (lsm/task_kill deny): ARMED, enforcement {} — \
                             the attach succeeded and the deny was not demonstrated",
                            v.token()
                        );
                    }
                }
                println!();
                println!("  protecting   pid {} (this process)", armed.target);
                println!(
                    "  tgid offset  +{:#x}, read from this kernel's BTF",
                    armed.tgid_offset
                );

                println!(
                    "  denies SIGKILL SIGTERM SIGINT SIGQUIT SIGSTOP from any non-init sender"
                );
                println!(
                    "  does NOT deny other fatal signals (SIGHUP, SIGABRT, SIGUSR1/2, SIGRT*),
                     \x20              nor `cgroup.kill`, nor a ptrace-injected exit. This raises
                     \x20              the cost of a casual `kill -9`; it is not a boundary"
                );
                println!(
                    "  allows       tgid 1 of the initial PID namespace (this host's systemd,
                     \x20              so a shutdown or reboot is never blocked) and kernel-origin
                     \x20              signals (the OOM killer)"
                );
                println!("  lift with    kill -USR1 {}   (or reboot)", armed.target);
                println!();

                println!(
                    "holding — the deny is live only while this process runs. Ctrl-C at THIS
                     \x20              terminal still stops it: a tty-generated SIGINT is sent
                     \x20              with SEND_SIG_PRIV and never reaches the hook. A `kill -INT`
                     \x20              from anywhere else is refused."
                );
                println!("lift with the line above, or just Ctrl-C here.");
            }

            loop {
                std::thread::park();
            }
        }
        Err(e) => {
            if json {
                jprintln!(
                    "{{\"armed\":false,\"stage\":\"{}\",\"errno\":{}}}",
                    e.stage.token(),
                    e.errno
                );
            } else if e.stage == hemostat_sensor_linux::ArmStage::ShutdownPath {

                eprintln!("self-protection: NOT ARMED — refused, by design, on this host.");
                eprintln!();
                if let Some(why) = &e.verifier_log {
                    eprintln!("  {}", h(why));
                }
                eprintln!();
                eprintln!(
                    "  Arming here would leave the agent alive into the unmount phase of a
                       shutdown, which is data damage on a host with a database or a historian
                       on it. Detection is unaffected: every sweep still runs, and `hemostat
                       selfprotect` still measures whether this kernel would deny a kill."
                );
            } else {
                eprintln!(
                    "self-protection: NOT ARMED — refused at {} with errno {}",
                    e.stage.token(),
                    e.errno
                );
                eprintln!(
                    "arming needs root (CAP_BPF + CAP_SYS_ADMIN) on a kernel with BPF LSM active."
                );
                if let Some(log) = &e.verifier_log {
                    eprintln!("verifier: {log}");
                }
            }

            if e.stage == hemostat_sensor_linux::ArmStage::ShutdownPath {
                crate::EXIT_POLICY
            } else {
                crate::EXIT_ENFORCER
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn worth_holding(v: hemostat_sensor_linux::selfprotect::Verdict) -> bool {
    v != hemostat_sensor_linux::selfprotect::Verdict::AttachedButInert
}

#[cfg(target_os = "linux")]
pub(crate) fn print_selfprotect(json: bool) {
    use hemostat_sensor_linux::selfprotect::Verdict;

    let t = hemostat_sensor_linux::deny_trial();
    let (arm_stage, arm_errno) = match &t.armed {
        Ok(()) => ("attached", 0),
        Err(e) => (e.stage.token(), e.errno),
    };

    if json {
        jprintln!(
            "{{\"verdict\":\"{}\",\"arm_stage\":\"{}\",\"arm_errno\":{},\
             \"tgid_offset\":{},\"kill_errno\":{},\"survived\":{},\
             \"kill_after_detach\":{},\"died_of\":{},\"kernel_origin\":\"{}\",\
             \"verifier_log\":\"{}\"}}",
            t.verdict.token(),
            arm_stage,
            arm_errno,
            t.tgid_offset.map_or_else(|| "null".to_string(), |o| o.to_string()),
            t.kill_errno,
            t.survived,
            t.kill_after_detach,
            t.died_of,

            match t.kernel_origin_passes {
                Some(true) => "passes",
                Some(false) => "not-shown",
                None => "not-run",
            },

            jesc(
                t.armed
                    .as_ref()
                    .err()
                    .and_then(|e| e.verifier_log.as_deref())
                    .unwrap_or(""),
            ),
        );
        return;
    }

    println!("self-protection (lsm/task_kill deny): {}", t.verdict.token());
    println!();

    match &t.armed {
        Ok(()) => {
            if let Some(off) = t.tgid_offset {
                println!("  armed task_struct.tgid at +{off:#x}, read from this kernel's BTF");
            }
        }
        Err(e) => {
            println!("  not armed    refused at {} with errno {}", e.stage.token(), e.errno);
            if let Some(log) = &e.verifier_log {

                println!("  verifier     {log}");
            }
        }
    }

    if t.armed.is_ok() {
        println!(
            "  SIGKILL      {}",
            if t.kill_errno == 0 {
                "accepted by the kernel — the hook did not fire".to_string()
            } else {
                format!("refused with errno {} while the deny was armed", t.kill_errno)
            }
        );
        println!(
            "  target       {} after that kill",
            if t.survived { "still running" } else { "gone" }
        );
        println!(
            "  control once detached, the same kill from the same sender {}",
            if t.kill_after_detach { "succeeded" } else { "did NOT succeed" }
        );
        if t.died_of != 0 {
            println!("  outcome the target finally died of signal {}", t.died_of);
        }
        match t.kernel_origin_passes {
            Some(true) => println!(
                "  kernel-origin a SIGALRM from an expired timer killed a second target while a\n\
                 \x20              deny covering it was armed — kernel-originated signals bypass\n\
                 \x20              this hook, so the deny cannot wedge the OOM killer (§7.6.2)"
            ),
            Some(false) => println!(
                "  kernel-origin NOT SHOWN to pass. Treat the OOM-killer interaction as unmeasured\n\
                 \x20              on this kernel rather than as a blocked signal"
            ),
            None => {}
        }
    }

    println!();
    println!("{}", match t.verdict {
        Verdict::Denies =>
            "This kernel DOES deny. The refusal happened while the program was armed and\n\
             the identical kill succeeded once it was detached, so the hook is the cause.\n\
             §7.6.2's signal-resistance claim is measured, not assumed, on this kernel.",
        Verdict::AttachedButInert =>
            "The program attached and stopped nothing. This is the shape SPIKE-D measured:\n\
             the kernel accepts an LSM program and never invokes the hook, which is what a\n\
             boot line without `bpf` in the active LSM list produces. Signal resistance is\n\
             NOT available here — `probe` says whether the boot line is the reason.",
        Verdict::NotArmed =>
            "Nothing was measured, so nothing is claimed. Needs CAP_BPF and CAP_SYS_ADMIN\n\
             on a kernel with BPF LSM; the stage and errno above say which of those failed.",
        Verdict::Inconclusive =>
            "The harness did not behave, so no claim is made in either direction. This is\n\
             deliberately not reported as a denial and not as an absence.",
    });
}

#[cfg(target_os = "linux")]
pub(crate) fn print_hooks(json: bool) {
    use hemostat_sensor_linux::HookState;
    let hooks = hemostat_sensor_linux::hook_report();

    if json {
        let rows = hooks
            .iter()
            .map(|h| {
                let (state, params, variant) = match &h.state {
                    HookState::Available { variant, params } => ("available", *params as i64, *variant),
                    HookState::UnknownPrototype { params } => ("unknown-prototype", *params as i64, ""),
                    HookState::Missing => ("missing", -1, ""),
                    HookState::Undetermined => ("undetermined", -1, ""),
                };
                format!(
                    "{{\"hook\":\"{}\",\"state\":\"{state}\",\"params\":{params},\
                     \"variant\":\"{variant}\",\"capability\":\"{}\"}}",
                    h.name, h.capability
                )
            })
            .collect::<Vec<_>>()
            .join(",");

        let flat = hooks
            .iter()
            .filter_map(|h| match &h.state {
                HookState::Available { variant, .. } if *variant != "single" => Some(format!(
                    ",\"variant_{}\":\"{variant}\"",
                    h.name.strip_prefix("bpf_lsm_").unwrap_or(h.name)
                )),
                HookState::UnknownPrototype { params } => Some(format!(
                    ",\"variant_{}\":\"unknown-{params}\"",
                    h.name.strip_prefix("bpf_lsm_").unwrap_or(h.name)
                )),
                _ => None,
            })
            .collect::<String>();
        jprintln!(
            "{{\"usable\":{},\"total\":{},\"hooks_undetermined\":{}{flat},\"hooks\":[{rows}]}}",
            hooks.iter().filter(|h| h.state.usable()).count(),
            hooks.len(),

            hooks.iter().filter(|h| h.state == HookState::Undetermined).count()
        );
        return;
    }

    let usable = hooks.iter().filter(|h| h.state.usable()).count();
    println!("LSM hooks: {usable} of {} usable on this kernel\n", hooks.len());
    println!("{:<32} {:<10} WHAT IT BUYS", "HOOK", "STATE");
    for h in &hooks {
        let state = match &h.state {
            HookState::Available { variant, params } if *variant == "single" => {
                format!("ok ({params})")
            }
            HookState::Available { variant, .. } => format!("ok [{variant}]"),
            HookState::UnknownPrototype { params } => format!("SHAPE? ({params})"),
            HookState::Missing => "absent".to_string(),
            HookState::Undetermined => "unknown".to_string(),
        };
        println!("{:<32} {state:<10} {}", h.name, h.capability);
    }

    if hooks.iter().any(|h| matches!(h.state, HookState::UnknownPrototype { .. })) {
        println!(
            "\nSHAPE? means the kernel declares the hook with a prototype no shipped\n\
             program variant matches. That hook is skipped and its capability drops to\n\
             detect-only (§7.3.3); the tier is unaffected."
        );
    }
    if hooks.iter().any(|h| h.state == HookState::Undetermined) {
        println!(
            "\nunknown means the kernel's BTF could not be walked to the end, so nothing\n\
             can be concluded about these hooks. This is a limitation of this reader,\n\
             not a statement about the host."
        );
    }
}
