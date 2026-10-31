#[cfg(any(target_os = "windows", test))]
use crate::render::json_str;
#[cfg(target_os = "windows")]
use crate::render::{h, jesc, wrap_why};
#[cfg(target_os = "windows")]
use crate::EXIT_USAGE;

#[cfg(any(target_os = "windows", test))]
use crate::{EXIT_OK, EXIT_PARTIAL};

#[cfg(any(target_os = "windows", test))]
use crate::coverage::Covered;

#[cfg(any(target_os = "windows", test))]
fn finding_row(severity: &str, subject: &str, what: &str, why: &str, fix: Option<&str>) -> String {
    format!(
        "{{\"severity\":{},\"subject\":{},\"what\":{},\"why\":{},\"fix\":{}}}",
        json_str(severity),
        json_str(subject),
        json_str(what),
        json_str(why),
        fix.map_or_else(|| "null".to_string(), json_str)
    )
}

#[cfg(target_os = "windows")]
fn finding_rows(found: &[hemostat_sensor_win::posture::Finding]) -> String {
    found
        .iter()
        .map(|f| {
            finding_row(
                &format!("{:?}", f.severity),
                &f.subject,
                &f.what,
                &f.why,
                f.fix.as_deref(),
            )
        })
        .collect::<Vec<_>>()
        .join(",")
}

#[cfg(target_os = "windows")]
pub(crate) fn print_etw(json: bool, watch_secs: Option<u64>) -> u8 {
    use hemostat_sensor_win::etw::{catalog, consume, session};

    if let Some(secs) = watch_secs {
        let providers = catalog::providers_for(catalog::Lane::P0);
        let cpus = std::thread::available_parallelism().map_or(1, |n| n.get() as u32);
        let name = session::session_name(catalog::Lane::P0);

        if !json {
            println!("etw: opening the {name} session for {secs}s with {} provider(s)", providers.len());
        }
        return match consume::consume(catalog::Lane::P0, &providers, secs, cpus) {
            Ok(stats) => {
                let w = EtwWatch {
                    enabled: &stats.providers_enabled,
                    delivered: &stats.delivered,
                    not_enabled: &stats.providers_failed,
                    events: stats.events,
                    unattributed: stats.unattributed,
                    events_lost: stats.events_lost,
                    buffers_lost: stats.buffers_lost,
                };

                let summary = stats.summary();
                if json {
                    jprintln!("{}", w.json(name, secs, &summary));
                    return w.exit();
                }
                for f in &stats.providers_failed {
                    println!("  NOT ENABLED: {}", h(f));
                }
                for e in &stats.providers_enabled {
                    println!("  enabled: {}", h(e));
                }
                println!("\n  {}", h(&summary));
                w.exit()
            }
            Err(e) => {
                eprintln!("etw: {}", h(&e));
                if json {
                    jprintln!(
                        "{{\"session\":{},\"seconds\":{secs},\"error\":{},\"complete\":false}}",
                        json_str(name),
                        json_str(&e)
                    );
                }
                EXIT_PARTIAL
            }
        };
    }

    if json {
        let rows: Vec<String> = catalog::CATALOGUE
            .iter()
            .map(|p| {
                format!(
                    "{{\"id\":{},\"name\":{},\"guid\":{},\"lane\":\"{:?}\",\
                     \"consumable\":{},\"kernel_mode\":{},\"status\":\"{:?}\",\"buys\":{}}}",
                    json_str(p.id),
                    json_str(p.name),
                    json_str(p.guid.0),
                    p.lane,
                    matches!(p.consumption, catalog::Consumption::PrivateSession),
                    matches!(p.registration, catalog::Registration::KernelMode),
                    p.status,
                    json_str(p.buys)
                )
            })
            .collect();
        jprintln!("{{\"providers\":[{}]}}", rows.join(","));
        return EXIT_OK;
    }

    println!("etw — what this host can be asked to report\n");
    for lane in [catalog::Lane::P0, catalog::Lane::P1, catalog::Lane::P2] {
        let ps = catalog::providers_for(lane);
        let b = session::buffers_for(lane, 4);
        println!(
            "  {:?} ({}) — {} provider(s), {}KB buffers, flush {}s",
            lane,
            session::session_name(lane),
            ps.len(),
            b.size_kb,
            b.flush_secs
        );
        for p in ps {
            println!("      {:<20} {:?}", p.id, p.status);
            println!("          {}", h(p.buys));
        }
    }

    println!("\n  NOT available on a private session:");
    for p in catalog::CATALOGUE {
        match p.consumption {
            catalog::Consumption::PrivateSession => {}
            catalog::Consumption::EventLogOnly => println!(
                "      {:<20} read with EvtSubscribe instead — enabling it on a private\n                       {:<20} session is accepted and delivers nothing",
                p.id, ""
            ),
            catalog::Consumption::Unavailable(why) => {
                println!("      {:<20} {}", p.id, h(why));
            }
        }
    }
    EXIT_OK
}

#[cfg(any(target_os = "windows", test))]
#[derive(Clone, Copy)]
struct EtwWatch<'a> {
    enabled: &'a [String],

    delivered: &'a [u64],
    not_enabled: &'a [String],
    events: u64,
    unattributed: u64,
    events_lost: u32,
    buffers_lost: u32,
}

#[cfg(any(target_os = "windows", test))]
impl EtwWatch<'_> {

    fn exit(&self) -> u8 {
        let whole = !self.enabled.is_empty()
            && self.events > 0
            && self.not_enabled.is_empty()
            && self.events_lost == 0
            && self.buffers_lost == 0;
        if whole {
            EXIT_OK
        } else {
            EXIT_PARTIAL
        }
    }

    fn json(&self, session: &str, secs: u64, summary: &str) -> String {
        let kept = self.delivered.len() == self.enabled.len();
        let enabled: Vec<String> = self
            .enabled
            .iter()
            .enumerate()
            .map(|(i, p)| {
                let n = self.delivered.get(i).filter(|_| kept);
                format!(
                    "{{\"provider\":{},\"delivered\":{}}}",
                    json_str(p),
                    n.map_or_else(|| "null".to_string(), u64::to_string)
                )
            })
            .collect();
        let not_enabled: Vec<String> = self.not_enabled.iter().map(|f| json_str(f)).collect();
        format!(
            "{{\"session\":{},\"seconds\":{secs},\"enabled\":[{}],\"not_enabled\":[{}],\
             \"events\":{},\"unattributed\":{},\"events_lost\":{},\"buffers_lost\":{},\
             \"complete\":{},\"summary\":{}}}",
            json_str(session),
            enabled.join(","),
            not_enabled.join(","),
            self.events,
            self.unattributed,
            self.events_lost,
            self.buffers_lost,
            self.exit() == EXIT_OK,
            json_str(summary)
        )
    }
}

#[cfg(target_os = "windows")]
pub(crate) fn print_streams(json: bool, extra: &[String]) -> u8 {
    let w = streams_sweep(extra);
    let found = &w.findings;
    let (files_checked, dirs_checked) = (w.files_checked, w.dirs_checked);

    if json {
        let rows = finding_rows(found);
        jprintln!(
            "{{\"files_checked\":{files_checked},\"dirs_checked\":{dirs_checked},\
             \"unreadable\":{},\"findings\":[{}]}}",
            w.unreadable.len(),
            rows
        );
    } else {
        println!("alternate data streams — content a directory listing does not show\n");
        println!(
            "  {files_checked} file(s) and {dirs_checked} director(ies) checked across {} root(s)",
            w.roots
        );
        if !w.unreadable.is_empty() {

            println!(
                "  {} path(s) could NOT be read — their streams are unchecked, not clean",
                w.unreadable.len()
            );
        }
        if found.is_empty() {
            println!("\n  no stream matched a shape worth explaining.");
        }
        for f in found {
            println!("\n  [{:?}] {}", f.severity, h(&f.what));
            println!("      {}", h(&f.why));
            if let Some(fix) = &f.fix {
                println!("      fix: {}", h(fix));
            }
        }
    }

    streams_covered(&w.unreadable).exit_code()
}

#[cfg(target_os = "windows")]
pub(crate) struct StreamsSweep {
    pub(crate) findings: Vec<hemostat_sensor_win::posture::Finding>,
    pub(crate) unreadable: Vec<String>,
    roots: usize,
    files_checked: usize,
    dirs_checked: usize,
}

#[cfg(target_os = "windows")]
pub(crate) fn streams_sweep(extra: &[String]) -> StreamsSweep {
    use hemostat_sensor_win::streams;

    let mut roots: Vec<String> = vec![
        "C:\\Windows\\Temp".into(),
        "C:\\Users\\Public".into(),
        "C:\\ProgramData".into(),
        "C:\\Windows\\Tasks".into(),
    ];
    roots.extend(extra.iter().cloned());

    let mut found = Vec::new();
    let mut unreadable = Vec::new();
    let mut files_checked = 0usize;
    let mut dirs_checked = 0usize;

    let check = |path: String, found: &mut Vec<_>, unreadable: &mut Vec<String>| {
        match streams::streams_of(&path) {
            Some((list, cut_short)) => {
                if cut_short {
                    unreadable.push(path);
                }
                found.extend(list.iter().filter_map(streams::judge));
            }
            None => unreadable.push(path),
        }
    };

    for root in &roots {

        dirs_checked += 1;
        check(root.clone(), &mut found, &mut unreadable);
        let Ok(entries) = std::fs::read_dir(root) else {
            if !unreadable.contains(root) {
                unreadable.push(root.clone());
            }
            continue;
        };
        for e in entries.flatten() {
            let p = e.path();
            if p.is_file() {
                files_checked += 1;
                check(p.display().to_string(), &mut found, &mut unreadable);

            } else if e.file_type().is_ok_and(|t| t.is_dir()) {
                dirs_checked += 1;
                check(p.display().to_string(), &mut found, &mut unreadable);
            }
        }
    }
    StreamsSweep { findings: found, unreadable, roots: roots.len(), files_checked, dirs_checked }
}

#[cfg(any(target_os = "windows", test))]
fn streams_covered(unreadable: &[String]) -> Covered {
    if unreadable.is_empty() {
        Covered::Fully
    } else {
        Covered::InPart(format!(
            "{} path(s) could not be read, so their streams are unchecked: {}",
            unreadable.len(),
            unreadable.join(", ")
        ))
    }
}

#[cfg(target_os = "windows")]
pub(crate) fn print_dll_hijack(json: bool) -> u8 {
    let w = dll_hijack_sweep();
    let (findings, sideload, known_checked) = (&w.findings, &w.sideload, w.known_checked);
    let unread = &w.unreadable;

    if json {
        let all: Vec<_> = findings.iter().chain(&sideload.findings).cloned().collect();
        let rows = finding_rows(&all);

        let dirs: Vec<String> = unread.iter().map(|d| json_str(d)).collect();
        let side_unchecked: Vec<String> = sideload.unchecked.iter().map(|u| json_str(u)).collect();
        jprintln!(
            "{{\"path_entries\":{},\"knowndlls\":{known_checked},\
             \"unreadable_acl_dirs\":[{}],\"sideload_dirs\":{},\"sideload_unchecked\":[{}],\
             \"findings\":[{}]}}",
            w.path_entries,
            dirs.join(","),
            sideload.dirs_examined,
            side_unchecked.join(","),
            rows
        );
        return dll_hijack_covered(known_checked, unread, &sideload.unchecked).exit_code();
    }

    println!("dll-hijack — where the loader could be made to find the wrong library\n");
    println!(
        "  {} PATH entr(ies), {known_checked} KnownDLLs entr(ies) checked",
        w.path_entries
    );
    if !unread.is_empty() {
        println!(
            "  {} director(ies) had an unreadable ACL — their writability is UNCHECKED, not \n  \
             confirmed safe: {}",
            unread.len(),
            h(&unread.join(", "))
        );
    }
    if known_checked == 0 {

        println!(
            "  KnownDLLs could NOT be read — the protection that makes core libraries \n un-hijackable is unverified here, not confirmed"
        );
    }
    if findings.is_empty() {
        println!("\n  nothing in the search order matched a shape worth explaining.");
    }
    for f in findings {
        println!("\n  [{:?}] {}", f.severity, h(&f.what));
        println!("      {}", h(&f.why));
        if let Some(fix) = &f.fix {
            println!("      fix: {}", h(fix));
        }
    }
    println!(
        "\n  sideloading: {} writable director(ies) examined for a signed binary\n  \
         beside a DLL nothing trustworthy signed",
        sideload.dirs_examined
    );
    if !sideload.unchecked.is_empty() {
        println!(
            "      {} thing(s) could NOT be checked — a sideload there is UNCHECKED, not absent:",
            sideload.unchecked.len()
        );
        for u in &sideload.unchecked {
            println!("        {}", h(u));
        }
    }
    if sideload.findings.is_empty() {
        println!("      none found.");
    }
    for f in &sideload.findings {
        println!("\n  [{:?}] {}", f.severity, h(&f.what));
        println!("      {}", h(&f.why));
        if let Some(fix) = &f.fix {
            println!("      fix: {}", h(fix));
        }
    }
    dll_hijack_covered(known_checked, unread, &sideload.unchecked).exit_code()
}

#[cfg(target_os = "windows")]
pub(crate) struct DllHijackSweep {

    pub(crate) findings: Vec<hemostat_sensor_win::posture::Finding>,

    pub(crate) sideload: hemostat_sensor_win::dllhijack::SideloadSweep,

    pub(crate) unreadable: Vec<String>,
    pub(crate) known_checked: usize,
    path_entries: usize,
}

#[cfg(target_os = "windows")]
pub(crate) fn dll_hijack_sweep() -> DllHijackSweep {
    use hemostat_sensor_win::dllhijack as dh;

    let path = std::env::var("PATH").unwrap_or_default();

    let unreadable = std::cell::RefCell::new(Vec::<String>::new());
    let writable = |d: &str| -> bool {
        use hemostat_sensor_win::acl;
        match acl::dacl_of_read(d) {
            Ok(aces) => acl::grants_unprivileged_write(&aces),
            Err(rc) if acl::path_absent(rc) => false,
            Err(_) => {
                unreadable.borrow_mut().push(d.to_string());
                false
            }
        }
    };
    let exists = |d: &str| std::path::Path::new(d).is_dir();

    let entries = dh::order_path_entries(&path, &writable, &exists);
    let mut findings: Vec<_> = entries.iter().filter_map(dh::judge_path_entry).collect();

    if let Some(f) = dh::judge_safe_dll_search(hemostat_sensor_win::reg::hklm_dword(
        "SYSTEM\\CurrentControlSet\\Control\\Session Manager",
        "SafeDllSearchMode",
    )) {
        findings.push(f);
    }
    let mut known_checked = 0usize;
    for (name, value) in hemostat_sensor_win::reg::hklm_values(
        "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\KnownDLLs",
    ) {
        known_checked += 1;
        if let Some(f) = dh::judge_known_dll(&dh::KnownDll { name, value }) {
            findings.push(f);
        }
    }

    let writable_dirs: Vec<String> =
        entries.iter().filter(|e| e.exists && e.user_writable).map(|e| e.dir.clone()).collect();

    let list = |d: &str| -> Option<dh::Listing> {
        let mut out = dh::Listing::default();
        for (i, e) in std::fs::read_dir(d).ok()?.flatten().enumerate() {
            if i >= 65_536 {
                out.cut_short = true;
                break;
            }
            let p = e.path();
            if p.is_file() {
                out.files.push(p.display().to_string());
            }
        }
        Some(out)
    };
    let sideload = dh::sweep_sideloads(
        &writable_dirs,
        &list,
        &hemostat_sensor_win::authenticode::verify,
    );

    DllHijackSweep {
        findings,
        sideload,
        unreadable: unreadable.into_inner(),
        known_checked,
        path_entries: entries.len(),
    }
}

#[cfg(any(target_os = "windows", test))]
fn com_covered(refused: &[String], unloaded_profiles: &[String]) -> Covered {
    let mut gaps = Vec::new();
    if !refused.is_empty() {
        gaps.push(format!("{} key(s) would not enumerate: {}", refused.len(), refused.join(", ")));
    }
    if !unloaded_profiles.is_empty() {
        gaps.push(format!(
            "{} profile hive(s) not loaded, so their per-user registrations were not read: {}",
            unloaded_profiles.len(),
            unloaded_profiles.join(", ")
        ));
    }
    if gaps.is_empty() {
        Covered::Fully
    } else {
        Covered::InPart(gaps.join("; "))
    }
}

#[cfg(any(target_os = "windows", test))]
fn dll_hijack_covered(
    known_checked: usize,
    unreadable_acl_dirs: &[String],
    sideload_unchecked: &[String],
) -> Covered {
    let mut gaps = Vec::new();
    if known_checked == 0 {
        gaps.push("KnownDLLs could not be read".to_string());
    }
    if !unreadable_acl_dirs.is_empty() {
        gaps.push(format!(
            "{} director(ies) had an unreadable ACL: {}",
            unreadable_acl_dirs.len(),
            unreadable_acl_dirs.join(", ")
        ));
    }
    if !sideload_unchecked.is_empty() {
        gaps.push(format!(
            "{} sideload candidate(s) could not be checked: {}",
            sideload_unchecked.len(),
            sideload_unchecked.join("; ")
        ));
    }
    if gaps.is_empty() {
        Covered::Fully
    } else {
        Covered::InPart(gaps.join("; "))
    }
}

#[cfg(target_os = "windows")]
pub(crate) fn print_modules(json: bool) -> u8 {
    let w = modules_sweep();
    let expected = w.unopened.iter().filter(|(e, _)| *e).count();
    let unexpected = w.unopened.len() - expected;
    let covered = modules_covered(&w.unopened);

    if json {
        let rows = finding_rows(&w.findings);
        let unopened = w
            .unopened
            .iter()
            .map(|(e, why)| format!("{{\"expected\":{e},\"why\":{}}}", json_str(why)))
            .collect::<Vec<_>>()
            .join(",");
        let unread = w
            .unread
            .iter()
            .map(|(why, n)| format!("{{\"why\":{},\"mappings\":{n}}}", json_str(why)))
            .collect::<Vec<_>>()
            .join(",");
        jprintln!(
            "{{\"processes_inspected\":{},\"processes_unopened\":{},\
             \"processes_refused_expected\":{expected},\"processes_unopened_unexpected\":{unexpected},\
             \"unopened\":[{unopened}],\"files_read\":{},\"files_cached\":{},\"files_unread\":[{unread}],\
             \"complete\":{},\"findings\":[{}]}}",
            w.inspected,
            w.unopened.len(),
            w.reads,
            w.hits,
            covered == Covered::Fully,
            rows
        );
        return covered.exit_code();
    }

    println!("modules — what is actually loaded into this host's system processes\n");
    println!(
        "  {} system process(es) inspected{}",
        w.inspected,
        if w.debug_priv {
            ""
        } else {
            " (without SeDebugPrivilege — the most protected processes could not be opened)"
        }
    );
    println!(
        "  {} module file(s) read once each; {} further mapping(s) of the same files answered \
         from that read",
        w.reads, w.hits
    );

    if !w.unread.is_empty() {
        const SHOWN: usize = 20;
        let mappings: usize = w.unread.iter().map(|(_, n)| n).sum();
        println!(
            "  {mappings} mapping(s) were NOT read for what built them — only a file the kernel \n  \
             maps from a local fixed drive is opened. Their toolchain is unexamined; the path \n  \
             rules still judged them:"
        );
        for (why, n) in w.unread.iter().take(SHOWN) {
            println!("      {} ({n} mapping(s))", h(why));
        }
        if w.unread.len() > SHOWN {
            println!("      … and {} more reason(s); --json lists every one", w.unread.len() - SHOWN);
        }
    }

    if expected > 0 {
        println!(
            "  {expected} refused the walk as the kernel requires (protected processes, and the \n  \
             ones that refuse on every stock host). Their modules are unexamined — a stated \n  \
             limit without a driver, not a partial run:"
        );
        for (_, why) in w.unopened.iter().filter(|(e, _)| *e) {
            println!("      {}", h(why));
        }
    }
    if unexpected > 0 {
        println!(
            "  {unexpected} could NOT be opened for a reason that is NOT the kernel protecting \n  \
             them — their modules are unexamined, not clean, and this run is partial (exit 7):"
        );
        for (_, why) in w.unopened.iter().filter(|(e, _)| !*e) {
            println!("      {}", h(why));
        }
    }
    if w.findings.is_empty() {
        println!("\n  nothing mapped into a system process matched a shape worth explaining.");
    }
    for f in &w.findings {
        println!("\n  [{:?}] {}", f.severity, h(&f.what));
        println!("      {}", h(&f.why));
        if let Some(fix) = &f.fix {
            println!("      fix: {}", h(fix));
        }
    }
    covered.exit_code()
}

#[cfg(target_os = "windows")]
pub(crate) struct ModulesSweep {
    pub(crate) findings: Vec<hemostat_sensor_win::posture::Finding>,

    pub(crate) unopened: Vec<(bool, String)>,
    inspected: usize,
    debug_priv: bool,

    reads: usize,
    hits: usize,

    unread: Vec<(String, usize)>,
}

#[cfg(target_os = "windows")]
pub(crate) fn modules_sweep() -> ModulesSweep {
    use hemostat_sensor_win::modules;

    let debug_priv = modules::enable_debug_privilege();

    let procs = modules::processes();
    let mut findings = Vec::new();
    let mut inspected = 0usize;
    let mut unopened: Vec<(bool, String)> = Vec::new();

    let mut cache = modules::IdentCache::default();

    for (pid, name) in &procs {
        if !modules::is_system_process(name) {
            continue;
        }
        match modules::modules_of(*pid, name) {
            Ok(mods) => {
                inspected += 1;
                for m in mods {

                    let ident = cache.identify(&m);
                    if let Some(f) = modules::judge(&m, ident.as_ref()) {
                        findings.push(f);
                    }
                }
            }

            Err(code) => {
                let (expected, why) =
                    modules::open_failure_measured(name, code, modules::protection_of(*pid));
                unopened.push((expected, format!("pid {pid}: {why}")));
            }
        }
    }
    ModulesSweep {
        findings,
        unopened,
        inspected,
        debug_priv,
        reads: cache.reads,
        hits: cache.hits,
        unread: cache.unread.into_iter().collect(),
    }
}

#[cfg(any(target_os = "windows", test))]
fn modules_covered(unopened: &[(bool, String)]) -> Covered {
    let unexpected: Vec<&str> =
        unopened.iter().filter(|(expected, _)| !expected).map(|(_, why)| why.as_str()).collect();
    if unexpected.is_empty() {
        Covered::Fully
    } else {
        Covered::InPart(format!(
            "{} process(es) could not be opened for a reason that is not the kernel protecting \
             them: {}",
            unexpected.len(),
            unexpected.join("; ")
        ))
    }
}

#[cfg(all(target_os = "windows", feature = "mod-sensor-usn"))]
fn usn_own_dir() -> Option<hemostat_sensor_win::usn::OwnDir> {
    let dir = crate::win_private::verify(&[]).ok().flatten()?;
    Some(hemostat_sensor_win::usn::OwnDir {
        dir: dir.display().to_string(),
        names: vec![crate::win_private::WATCHDOG_WRAPPER.to_string()],
    })
}

#[cfg(all(target_os = "windows", feature = "mod-sensor-usn"))]
pub(crate) fn print_usn(json: bool, volume: &str) -> u8 {
    use hemostat_sensor_win::usn;

    let s = usn::sweep_with(volume, usn_own_dir());

    if json {
        let rows = finding_rows(&s.findings);
        jprintln!(
            "{{\"volume\":{},\"complete\":{},\"records\":{},\"findings\":[{}]}}",
            json_str(volume),
            s.complete(),
            s.records_read,
            rows
        );
        return usn_covered(&s).exit_code();
    }

    println!("usn — the NTFS change journal: files that were here and are not\n");
    println!("  {}\n", h(&s.coverage()));
    for f in &s.findings {
        println!("  [{:?}] {}", f.severity, h(&f.subject));
        println!("      {}", h(&f.what));
        if !f.why.is_empty() {
            println!("      why: {}", h(&f.why));
        }
        if let Some(fix) = &f.fix {
            println!("      fix: {}", h(fix));
        }
    }
    println!();
    println!(
        "  This is the only record of a file that was created and then deleted. A payload\n           that cleans up after itself leaves nothing for a filesystem sweep; the create and\n           delete records against one file reference number are what is left of it."
    );
    usn_covered(&s).exit_code()
}

#[cfg(all(target_os = "windows", feature = "mod-sensor-usn"))]
fn usn_covered(s: &hemostat_sensor_win::usn::Sweep) -> Covered {
    if s.complete() {
        Covered::Fully
    } else if s.records_read == 0 {
        Covered::NotAtAll(s.coverage())
    } else {
        Covered::InPart(s.coverage())
    }
}

#[cfg(all(target_os = "windows", feature = "mod-sensor-sysmon"))]
pub(crate) fn print_sysmon(json: bool) -> u8 {
    use hemostat_sensor_win::sysmon;

    let s = sysmon::sweep();

    if json {
        let rows = finding_rows(&s.findings);
        let traces = s.state.traces.iter().map(|t| json_str(t)).collect::<Vec<_>>().join(",");
        let gaps = s.gaps.iter().map(|g| json_str(g)).collect::<Vec<_>>().join(",");
        jprintln!(
            "{{\"installed\":{},\"service_state\":{},\"driver_loaded\":{},\"traces\":[{traces}],\
             \"gaps\":[{gaps}],\"complete\":{},\"findings\":[{}]}}",
            s.state.installed(),
            s.state
                .service_state
                .map_or("null".to_string(), |st| json_str(&sysmon::service_state_name(st))),
            s.state.driver_loaded.map_or("null".to_string(), |b| b.to_string()),
            s.complete(),
            rows
        );
        return sysmon_covered(&s).exit_code();
    }

    println!("sysmon — whether it is there, and whether it is actually recording\n");
    println!("  {}\n", h(&s.coverage()));
    for f in &s.findings {
        println!("  [{:?}] {}", f.severity, h(&f.subject));
        println!("      {}", h(&f.what));
        if !f.why.is_empty() {
            println!("      why: {}", h(&f.why));
        }
        if let Some(fix) = &f.fix {
            println!("      fix: {}", h(fix));
        }
    }
    println!();
    println!(
        "  Sysmon is a service and a driver. `fltmc unload SysmonDrv` separates them in one\n           command and leaves every check an administrator would run reporting healthy, so\n           the driver list is asked directly rather than inferred from the registry."
    );
    sysmon_covered(&s).exit_code()
}

#[cfg(all(target_os = "windows", feature = "mod-sensor-sysmon"))]
fn sysmon_covered(s: &hemostat_sensor_win::sysmon::Sweep) -> Covered {
    if s.complete() {
        Covered::Fully
    } else {
        Covered::InPart(s.coverage())
    }
}

#[cfg(all(target_os = "windows", feature = "mod-sensor-evtlog"))]
pub(crate) fn print_evtlog(json: bool, enumerate: bool) -> u8 {
    use hemostat_sensor_win::evtlog;

    let s = evtlog::sweep(enumerate);

    if json {
        let rows = finding_rows(&s.findings);
        jprintln!(
            "{{\"complete\":{},\"enumerated\":{},\"channels\":{},\"findings\":[{}]}}",
            s.complete(),
            s.enumerated,
            s.channels.len(),
            rows
        );
        return evtlog_covered(&s).exit_code();
    }

    println!("evtlog — whether what this host recorded can be believed\n");
    println!("  {}\n", h(&s.coverage()));

    for f in &s.findings {
        println!("  [{:?}] {}", f.severity, h(&f.subject));
        println!("      {}", h(&f.what));
        if !f.why.is_empty() {
            println!("      why: {}", h(&f.why));
        }
    }

    println!();
    let covered = evtlog_covered(&s);
    if covered == Covered::Fully {
        println!(
            "  Four ways an event log stops being evidence: cleared (1102/104), individual\n               records deleted (a hole in the record numbering), shrunk until it rolls over,\n               or never configured to record the thing you are looking for."
        );
    } else {
        println!(
            "  This sweep did NOT establish the posture of every channel — see the coverage\n               line above. Partial result (exit 7), not a clean one."
        );
    }
    covered.exit_code()
}

#[cfg(all(target_os = "windows", feature = "mod-sensor-evtlog"))]
fn evtlog_covered(s: &hemostat_sensor_win::evtlog::Sweep) -> Covered {
    if s.complete() {
        Covered::Fully
    } else {
        Covered::InPart(s.coverage())
    }
}

#[cfg(target_os = "windows")]
pub(crate) fn print_wmi(json: bool) -> u8 {
    use hemostat_sensor_win::wmi;

    let r = wmi::scan();
    let covered = wmi_covered(r.unreadable, r.live.is_some(), &r.live_gaps);

    if json {
        let rows = finding_rows(&r.findings);
        let gaps = r.live_gaps.iter().map(|g| json_str(g)).collect::<Vec<_>>().join(",");
        let (consumers, filters, bindings) = r
            .live
            .as_ref()
            .map_or((0, 0, 0), |l| (l.consumers.len(), l.filters.len(), l.bindings.len()));
        jprintln!(
            "{{\"queried\":{},\"consumers\":{consumers},\"executing\":{},\"filters\":{filters},\
             \"bindings\":{bindings},\"query_gaps\":[{gaps}],\"readable\":{},\"scanned_bytes\":{},\
             \"repository_consumers\":{},\"residue\":{},\"complete\":{},\"findings\":[{}]}}",
            r.live.is_some(),
            r.executing(),
            !r.unreadable,
            r.scanned,
            r.consumers.len(),
            r.residue.len(),
            covered == Covered::Fully,
            rows
        );
        return covered.exit_code();
    }

    println!("wmi — persistent event subscriptions, which leave no file and no autorun\n");
    match &r.live {
        Some(l) => println!(
            "  asked WMI ({}): {} consumer(s), {} of them executing; {} filter(s), {} binding(s)",
            wmi::LIVE_NAMESPACES.join(", "),
            l.consumers.len(),
            r.executing(),
            l.filters.len(),
            l.bindings.len()
        ),
        None => println!(
            "  WMI could NOT be asked, so what is subscribed NOW is UNKNOWN — only the repository\n  \
             bytes below were read, and absence there is weak evidence: a consumer whose command\n  \
             the scan cannot recover is indistinguishable from the class definition every host\n  \
             carries."
        ),
    }
    for g in &r.live_gaps {
        println!("  NOT READ: {}", h(g));
    }
    if r.unreadable {
        println!(
            "  the WMI repository could NOT be read, so a subscription that was created and then\n  \
             DELETED would not be seen. Live subscriptions above are unaffected."
        );
    } else {
        println!(
            "  {} byte(s) of repository scanned for deleted subscriptions: WMI does not compact it,\n  \
             so a removed consumer's command survives there. {} found that WMI no longer reports.",
            r.scanned,
            r.residue.len()
        );
    }

    if r.findings.is_empty() {
        println!("\n  no executing consumer, live or deleted.");
    }
    for f in &r.findings {
        println!("\n  [{:?}] {}", f.severity, h(&f.what));
        println!("      {}", h(&f.why));
        if let Some(fix) = &f.fix {
            println!("      fix: {}", h(fix));
        }
    }
    if covered != Covered::Fully {
        println!("\n  Partial result (exit 7), not a clean one.");
    }
    covered.exit_code()
}

#[cfg(any(target_os = "windows", test))]
fn wmi_covered(repository_unreadable: bool, queried: bool, query_gaps: &[String]) -> Covered {
    match (queried, repository_unreadable) {
        (false, true) => Covered::NotAtAll(format!(
            "WMI could not be asked ({}) and the repository could not be read",
            query_gaps.join("; ")
        )),
        (false, false) => Covered::InPart(format!(
            "WMI could not be asked ({}), so only the repository bytes were read",
            query_gaps.join("; ")
        )),
        (true, _) if !query_gaps.is_empty() => {
            Covered::InPart(format!("part of the WMI query did not finish: {}", query_gaps.join("; ")))
        }
        (true, true) => Covered::InPart(
            "the WMI repository could not be read, so deleted subscriptions were not looked for"
                .into(),
        ),
        (true, false) => Covered::Fully,
    }
}

#[cfg(target_os = "windows")]
pub(crate) fn print_com(json: bool) -> u8 {
    let w = com_sweep();
    let ComSweep { findings, resolved, unresolved, refused, unloaded, hives } = &w;
    let resolved = *resolved;

    if json {
        let rows = finding_rows(findings);
        let list = |v: &[String]| v.iter().map(|r| json_str(r)).collect::<Vec<_>>().join(",");
        let hive_rows: Vec<String> = hives.iter().map(|h| json_str(h)).collect();
        jprintln!(
            "{{\"resolved\":{resolved},\"unresolved\":{},\"user_hives\":[{}],\
             \"unloaded_profiles\":[{}],\"refused\":[{}],\"findings\":[{}]}}",
            unresolved.len(),
            hive_rows.join(","),
            list(unloaded),
            list(refused),
            rows
        );
        return com_covered(refused, unloaded).exit_code();
    }

    println!("com — what the registered handlers actually load\n");
    println!("  {resolved} CLSID(s) resolved to a server");
    println!(
        "  per-user registrations read from {} loaded profile(s): {}",
        hives.len(),
        h(&hives.join(", "))
    );
    if !unloaded.is_empty() {
        println!(
            "  {} profile(s) are not logged on, so their hive is not loaded and was NOT read —\n  \
             a per-user COM hijack there is UNCHECKED, not absent: {}",
            unloaded.len(),
            h(&unloaded.join(", "))
        );
    }
    if !refused.is_empty() {
        println!(
            "\n  {} key(s) could NOT be enumerated — whether a shell extension or a per-user\n               registration is there is UNKNOWN, not none:\n      {}",
            refused.len(),
            h(&refused.join("\n      "))
        );
    }
    if !unresolved.is_empty() {
        println!(
            "  {} registered handler(s) resolved to NO server — a stale registration or one \n  \
             whose server appears later, not an absence of handlers:",
            unresolved.len()
        );
        for u in unresolved {
            println!("      {}", h(u));
        }
    }
    if findings.is_empty() {
        println!("\n  every resolved handler loads from a location a COM server belongs in.");
    }
    for f in findings {
        println!("\n  [{:?}] {}", f.severity, h(&f.what));
        println!("      {}", h(&f.why));
        if let Some(fix) = &f.fix {
            println!("      fix: {}", h(fix));
        }
    }
    com_covered(refused, unloaded).exit_code()
}

#[cfg(target_os = "windows")]
pub(crate) struct ComSweep {
    pub(crate) findings: Vec<hemostat_sensor_win::posture::Finding>,
    resolved: usize,
    unresolved: Vec<String>,
    pub(crate) refused: Vec<String>,
    pub(crate) unloaded: Vec<String>,

    hives: Vec<String>,
}

#[cfg(target_os = "windows")]
pub(crate) fn com_sweep() -> ComSweep {
    use hemostat_sensor_win::{com, reg};

    const HANDLER_KEYS: &[(&str, &str)] = &[
        (
            "icon overlay handler",
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellIconOverlayIdentifiers",
        ),
        (
            "browser helper object",
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects",
        ),
        (
            "shell service object",
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad",
        ),
        (
            "shared task scheduler",
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\SharedTaskScheduler",
        ),
        (
            "shell execute hook",
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellExecuteHooks",
        ),
    ];

    let mut findings = Vec::new();
    let mut resolved = 0usize;
    let mut unresolved = Vec::new();

    let mut refused: Vec<String> = Vec::new();

    const PROFILE_LIST: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList";
    let loaded = reg::subkeys_read(reg::Hive::Users, "").unwrap_or_else(|rc| {
        refused.push(format!("HKEY_USERS (error {rc})"));
        Vec::new()
    });
    let profiles = match reg::subkeys_read(reg::Hive::Machine, PROFILE_LIST) {
        Ok(v) => v,
        Err(rc) if rc == reg::ABSENT => Vec::new(),
        Err(rc) => {
            refused.push(format!(r"HKLM\{PROFILE_LIST} (error {rc})"));
            Vec::new()
        }
    };

    let unloaded = com::unloaded_profiles(&profiles, &loaded);
    let mut users = Vec::new();
    for mut u in com::user_hives(&loaded) {
        match reg::subkeys_read(reg::Hive::Users, &format!(r"{}\CLSID", u.classes)) {
            Ok(c) => u.clsids = c,
            Err(rc) if rc == reg::ABSENT => {}
            Err(rc) => {
                refused.push(format!(r"HKU\{}\CLSID (error {rc})", u.classes));
                continue;
            }
        }
        users.push(u);
    }

    for (label, key) in HANDLER_KEYS {

        let subs = match reg::subkeys_read(reg::Hive::Machine, key) {
            Ok(v) => v,
            Err(rc) if rc == reg::ABSENT => Vec::new(),
            Err(rc) => {
                refused.push(format!(r"HKLM\{key} (error {rc})"));
                Vec::new()
            }
        };
        let mut candidates: Vec<String> = subs.clone();
        match reg::hklm_values_read(key) {
            Ok(vals) => {
                for (name, data) in vals {
                    candidates.push(name);
                    candidates.push(data);
                }
            }
            Err(rc) if rc == reg::ABSENT => {}
            Err(rc) => refused.push(format!(r"HKLM\{key} values (error {rc})")),
        }

        for sub in subs {
            if let Some(v) = reg::default_value(reg::Hive::Machine, &format!("{key}\\{sub}")) {
                candidates.push(v);
            }
        }

        candidates.retain(|c| com::is_clsid(c));
        candidates.sort();
        candidates.dedup();

        for clsid in candidates {
            let found = com::resolve(&clsid, &users);

            if found.is_empty() {
                unresolved.push(format!("{label} {clsid}"));
                continue;
            }
            resolved += 1;
            findings.extend(found.iter().filter_map(|r| com::judge(label, r)));
        }
    }
    ComSweep {
        hives: users.into_iter().map(|u| u.sid).collect(),
        findings,
        resolved,
        unresolved,
        refused,
        unloaded,
    }
}

#[cfg(target_os = "windows")]
pub(crate) fn print_signature(json: bool, paths: &[String]) -> u8 {
    use hemostat_sensor_win::authenticode as ac;

    if paths.is_empty() {
        eprintln!("signature: give it one or more file paths");
        return EXIT_USAGE;
    }

    let mut any_unknown = false;
    for path in paths {

        let full = std::path::absolute(path).map_or_else(|_| path.clone(), |p| p.to_string_lossy().into_owned());
        let (trust, embedded, catalog) = ac::verify_verbose(&full);
        if matches!(trust, ac::Trust::Unknown(_)) {
            any_unknown = true;
        }
        let detail = match &trust {
            ac::Trust::Valid => String::new(),
            ac::Trust::Unsigned => String::new(),
            ac::Trust::Broken(w) | ac::Trust::Untrusted(w) | ac::Trust::Unknown(w) => w.clone(),
        };
        if json {
            jprintln!("{}", signature_row(path, trust.token(), embedded, catalog, &detail));
        } else {
            println!("{:<12} {}", trust.token(), h(path));

            match (catalog, &trust) {

                (None, ac::Trust::Unknown(_)) if embedded == 0 => {
                    println!("             not verified: Authenticode was not asked about it")
                }
                (None, _) => println!("             embedded signature, status {embedded:#x}"),

                (Some(_), ac::Trust::Unsigned) => println!(
                    "             no embedded signature ({embedded:#x}); no catalog claims it"
                ),
                (Some(c), _) => println!(
                    "             no embedded signature ({embedded:#x}); verified as a catalog \
                     member (status {c:#x})"
                ),
            }
            if !detail.is_empty() {
                println!("             {}", h(&detail));
            }
        }
    }
    if any_unknown {
        EXIT_PARTIAL
    } else {
        EXIT_OK
    }
}

#[cfg(any(target_os = "windows", test))]
fn signature_row(
    path: &str,
    token: &str,
    embedded: i32,
    catalog: Option<i32>,
    detail: &str,
) -> String {
    format!(
        "{{\"path\":{},\"trust\":{},\"embedded_status\":\"{embedded:#x}\",\
         \"catalog_status\":{},\"detail\":{}}}",
        json_str(path),
        json_str(token),
        catalog.map_or_else(|| "null".to_string(), |c| format!("\"{c:#x}\"")),
        json_str(detail)
    )
}

#[cfg(target_os = "windows")]
pub(crate) fn print_win_probe(json: bool) -> u8 {
    use hemostat_sensor_win::Severity;

    let p = hemostat_sensor_win::report();

    let missed = p.facts.unreadable();
    let code = probe_covered(&p).exit_code();

    if json {
        let findings = p
            .findings
            .iter()
            .map(|f| {
                format!(
                    "{{\"severity\":\"{}\",\"subject\":\"{}\",\"what\":\"{}\"}}",
                    f.severity.tag(),
                    jesc(&f.subject),
                    jesc(&f.what)
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        let f = &p.facts;
        jprintln!(
            "{{\"standing\":\"{}\",\"agent\":\"{}\",\"adversary\":\"{}\",\
             \"integrity\":\"{}\",\"secure_boot\":\"{}\",\"hvci\":\"{}\",\"vbs\":\"{}\",\
             \"driver_blocklist\":\"{}\",\"lsa_ppl\":\"{}\",\"wdigest_plaintext\":\"{}\",\
             \"driver_blocklist_basis\":{},\
             \"defender_rtp\":\"{}\",\"critical\":{},\"findings\":[{findings}]}}",
            p.standing.token(),
            p.agent.token(),
            p.adversary.token(),
            f.integrity.token(),
            f.secure_boot.token(),
            f.hvci.token(),
            f.vbs.token(),
            f.driver_blocklist.token(),
            f.lsa_ppl.token(),
            f.wdigest_plaintext.token(),
            f.driver_blocklist_basis.as_deref().map_or_else(|| "\"read\"".to_string(), json_str),
            f.defender_rtp.token(),
            p.count_at_least(Severity::Critical),
        );
        return code;
    }

    println!("windows posture: {}", p.standing.token());
    println!("  agent reaches      {}", p.agent.token());
    println!("  adversary reaches  {}", p.adversary.token());
    println!();
    println!("{}", wrap_why(p.standing.meaning(), "  "));
    println!();

    let f = &p.facts;
    println!("--- what stops an attacker reaching the kernel ---");
    for (name, flag) in [
        ("Secure Boot", f.secure_boot),
        ("HVCI / Memory Integrity", f.hvci),
        ("VBS", f.vbs),
        ("vulnerable-driver blocklist", f.driver_blocklist),
    ] {
        println!("  {name:<30} {}", flag.token());
    }

    if let Some(basis) = &f.driver_blocklist_basis {
        println!("{}", wrap_why(&h(basis), "      blocklist: "));
    }
    println!();
    println!("--- credential exposure ---");
    println!("  {:<30} {}", "LSA protected process", f.lsa_ppl.token());
    println!("  {:<30} {}", "WDigest plaintext caching", f.wdigest_plaintext.token());
    println!();
    println!("--- Defender (read only; §1.4a forbids enabling it here) ---");
    println!("  {:<30} {}", "real-time protection", f.defender_rtp.token());
    println!("  {:<30} {}", "tamper protection", f.defender_tamper.token());

    if !p.findings.is_empty() {
        println!();
        println!("--- findings ---");
        for finding in &p.findings {
            println!("  [{}] {}", finding.severity.tag(), h(&finding.subject));
            println!("      {}", h(&finding.what));
            println!("{}", wrap_why(&h(&finding.why), "      why: "));
            if let Some(fix) = &finding.fix {
                println!("{}", wrap_why(&h(fix), "      fix: "));
            }
        }
    }

    for note in &f.notes {
        println!("\n  note: {}", h(note));
    }

    println!(
        "\nEvery reading above is trust `{:?}`: registry values and token queries, both of\n\
         which a SYSTEM attacker can rewrite or fake. This is the ceiling of a user-mode\n\
         probe on Windows, where HEMOSTAT ships no driver by design (D2). It is reported\n\
         rather than worked around.",
        f.trust()
    );

    if !missed.is_empty() {
        println!(
            "\n  {} reading(s) COULD NOT BE TAKEN: {}.\n  \
             Those are unchecked, not off. Re-run elevated; exit code 7 says the same thing\n  \
             to whatever ran this.",
            missed.len(),
            missed.join(", ")
        );
    }
    code
}

#[cfg(target_os = "windows")]
pub(crate) fn print_win_persistence(json: bool) -> u8 {
    use hemostat_sensor_win::persist;
    use hemostat_sensor_win::Severity;

    let r = persist::report();

    let code = persistence_covered(&r).exit_code();
    let all = persistence_findings(&r);
    let findings: Vec<_> = all.iter().collect();

    if json {
        let obs = r
            .observations
            .iter()
            .map(|o| {
                format!(
                    "{{\"id\":\"{}\",\"category\":\"{}\",\"coverage\":\"{}\",\"entries\":{},\
                     \"refused\":[{}]}}",
                    jesc(o.id),
                    o.category.token(),
                    o.coverage.token(),
                    o.entries,
                    o.refused
                        .iter()
                        .map(|r| format!("\"{}\"", jesc(r)))
                        .collect::<Vec<_>>()
                        .join(",")
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        let f = findings
            .iter()
            .map(|f| {
                format!(
                    "{{\"severity\":\"{}\",\"subject\":\"{}\",\"what\":\"{}\"}}",
                    f.severity.tag(),
                    jesc(&f.subject),
                    jesc(&f.what)
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        jprintln!(
            "{{\"established\":{},\"total\":{},\"entries\":{},\"observations\":[{obs}],\
             \"findings\":[{f}],\"complete\":{}}}",
            r.established,
            r.total,
            r.entries.len(),
            r.established == r.total
        );
        return code;
    }

    println!(
        "persistence: {} of {} mechanisms established, {} entr(ies) configured to run",
        r.established,
        r.total,
        r.entries.len()
    );
    if r.established < r.total {
        println!(
            "  {} mechanism(s) could NOT be read in full. Those surfaces are unchecked, \
             not clean.",
            r.total - r.established
        );
    }

    println!(
        "  NOT in this count: BITS jobs, Office add-ins, and per-user hives beyond the ones\n  \
         listed. The handler keys above record that a shell or COM extension is REGISTERED;\n  \
         resolving its CLSID to the DLL behind it is what the `com` verb does.\n  \
         Covered by their own verbs: alternate data streams (`streams`), the DLL search\n  \
         order (`dll-hijack`), what is mapped into processes (`modules`), persistent WMI\n  \
         subscriptions (`wmi`), and COM resolution and hijacking (`com`). A mechanism\n  \
         absent from a catalogue cannot appear here as a gap."
    );
    println!();

    for o in &r.observations {
        let count =
            if o.entries > 0 { format!("{} entr(ies)", o.entries) } else { String::new() };
        println!("  {:<22} {:<12} {:<12} {}", o.id, o.category.token(), o.coverage.token(), count);
    }

    let shown: Vec<_> = findings.into_iter().filter(|f| f.severity >= Severity::Warn).collect();
    if shown.is_empty() {
        println!("\n  nothing configured to run here matched a shape worth explaining.");
    } else {
        println!("\n--- findings ---");
        for f in shown {
            println!("  [{}] {}", f.severity.tag(), h(&f.subject));
            println!("      {}", h(&f.what));
            println!("{}", wrap_why(&h(&f.why), "      why: "));
            if let Some(fix) = &f.fix {
                println!("{}", wrap_why(&h(fix), "      fix: "));
            }
        }
    }
    code
}

#[cfg(target_os = "windows")]
fn persistence_findings(
    r: &hemostat_sensor_win::persist::Report,
) -> Vec<hemostat_sensor_win::posture::Finding> {
    let mut findings: Vec<_> = r
        .entries
        .iter()
        .filter_map(|e| {
            hemostat_sensor_win::streams::judge_autostart(&e.locus, &e.name, &e.command)
        })
        .chain(r.findings.iter().cloned())
        .collect();
    findings.sort_by_key(|f| std::cmp::Reverse(f.severity));
    findings
}

#[cfg(target_os = "windows")]
fn persistence_covered(r: &hemostat_sensor_win::persist::Report) -> Covered {
    if r.established == r.total {
        return Covered::Fully;
    }
    let unread: Vec<String> = r
        .observations
        .iter()
        .filter(|o| !o.coverage.established())
        .map(|o| format!("{} ({})", o.id, o.coverage.token()))
        .collect();
    Covered::InPart(format!(
        "{} of {} mechanisms could not be read in full: {}",
        r.total - r.established,
        r.total,
        unread.join(", ")
    ))
}

#[cfg(target_os = "windows")]
fn probe_covered(p: &hemostat_sensor_win::Posture) -> Covered {

    crate::coverage::probe(&p.facts.unreadable())
}

#[cfg(target_os = "windows")]
fn accounts_covered(r: &hemostat_sensor_win::accounts::Report) -> Covered {
    if r.available {
        Covered::Fully
    } else {
        Covered::NotAtAll(r.reason.clone().unwrap_or_else(|| "no reason given".into()))
    }
}

#[cfg(target_os = "windows")]
fn overview_covered(r: &hemostat_sensor_win::overview::Report) -> Covered {
    if !r.available {
        Covered::NotAtAll(r.reason.clone().unwrap_or_else(|| "no reason given".into()))
    } else if r.complete() {
        Covered::Fully
    } else {
        Covered::InPart(r.gaps.join("; "))
    }
}

#[cfg(target_os = "windows")]
pub(crate) fn print_win_accounts(json: bool) -> u8 {
    use hemostat_sensor_win::accounts;
    use hemostat_sensor_win::Severity;

    let r = accounts::report();

    if json {
        let accts = r
            .accounts
            .iter()
            .map(|a| {
                format!(
                    "{{\"name\":\"{}\",\"enabled\":{},\"administrator\":{},\
                     \"password_not_required\":{}}}",
                    jesc(&a.name),
                    a.enabled(),
                    a.administrator,
                    a.password_not_required()
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        let admins = r
            .admins
            .iter()
            .map(|m| {
                format!(
                    "{{\"name\":\"{}\",\"group\":{},\"sid\":{}}}",
                    jesc(&m.name),
                    m.is_group,
                    m.sid.as_deref().map_or_else(|| "null".to_string(), json_str)
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        let f = r
            .findings
            .iter()
            .map(|f| {
                format!(
                    "{{\"severity\":\"{}\",\"subject\":\"{}\",\"what\":\"{}\"}}",
                    f.severity.tag(),
                    jesc(&f.subject),
                    jesc(&f.what)
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        jprintln!(
            "{{\"available\":{},\"reason\":\"{}\",\"admin_group\":\"{}\",\
             \"accounts\":[{accts}],\"administrators\":[{admins}],\"findings\":[{f}]}}",
            r.available,
            jesc(r.reason.as_deref().unwrap_or("")),
            jesc(&r.admin_group)
        );
        return accounts_covered(&r).exit_code();
    }

    if !r.available {
        println!("accounts: DID NOT RUN — {}", h(r.reason.as_deref().unwrap_or("")));
        println!();
        println!("  Nothing is claimed about who can log in to this host, or who administers");
        println!("  it. That is not the same as a host with no extra administrators.");
        return accounts_covered(&r).exit_code();
    }

    println!(
        "accounts: {} local account(s), {} member(s) of `{}`",
        r.accounts.len(),
        r.admins.len(),
        r.admin_group
    );
    println!();
    for a in &r.accounts {
        let mut tags: Vec<&str> = Vec::new();
        if !a.enabled() {
            tags.push("disabled");
        }
        if a.administrator {
            tags.push("ADMIN");
        }
        if a.password_not_required() {
            tags.push("NO PASSWORD REQUIRED");
        }
        println!("  {:<28} {}", h(&a.name), tags.join(" · "));
    }

    let shown: Vec<_> = r.findings.iter().filter(|f| f.severity >= Severity::Note).collect();
    if shown.is_empty() {
        println!("\n  nothing about this account picture is worth explaining.");
    } else {
        println!("\n--- findings ---");
        for f in shown {
            println!("  [{}] {}", f.severity.tag(), h(&f.subject));
            println!("      {}", h(&f.what));
            println!("{}", wrap_why(&h(&f.why), "      why: "));
            if let Some(fix) = &f.fix {
                println!("{}", wrap_why(&h(fix), "      fix: "));
            }
        }
    }
    accounts_covered(&r).exit_code()
}

#[cfg(target_os = "windows")]
pub(crate) fn print_win_overview(json: bool) -> u8 {
    use hemostat_sensor_win::overview;
    use hemostat_sensor_win::Severity;

    let r = overview::report();

    let code = overview_covered(&r).exit_code();

    if json {
        let socks = r
            .sockets
            .iter()
            .map(|s| {
                format!(
                    "{{\"proto\":\"{}\",\"local\":\"{}\",\"port\":{},\"remote\":\"{}\",\
                     \"remote_port\":{},\"state\":\"{}\",\"pid\":{},\"image\":\"{}\"}}",
                    s.proto,
                    jesc(&s.local),
                    s.port,
                    jesc(&s.remote),
                    s.remote_port,
                    s.state,
                    s.pid,
                    jesc(s.image.as_deref().unwrap_or(""))
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        let f = r
            .findings
            .iter()
            .map(|f| {
                format!(
                    "{{\"severity\":\"{}\",\"subject\":\"{}\",\"what\":\"{}\"}}",
                    f.severity.tag(),
                    jesc(&f.subject),
                    jesc(&f.what)
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        let gaps = r.gaps.iter().map(|g| json_str(g)).collect::<Vec<_>>().join(",");
        jprintln!(
            "{{\"available\":{},\"complete\":{},\"named\":{},\"sockets\":[{socks}],\
             \"findings\":[{f}],\"note\":\"{}\",\"gaps\":[{gaps}],\"not_read\":[{}]}}",
            r.available,
            r.complete(),
            r.named,
            jesc(r.reason.as_deref().unwrap_or("")),
            json_str(overview::NOT_READ)
        );
        return code;
    }

    if !r.available {
        println!("overview: DID NOT RUN — {}", h(r.reason.as_deref().unwrap_or("")));
        println!();
        println!("  Nothing is claimed about what this host is listening to.");
        return code;
    }

    let listeners = r.sockets.iter().filter(|s| s.listening()).count();
    println!(
        "overview: {} socket(s), {} listening, {} owner(s) named",
        r.sockets.len(),
        listeners,
        r.named
    );
    println!();
    for s in &r.sockets {
        let who = match &s.image {
            Some(i) => format!("{} (pid {})", h(i), s.pid),
            None => format!("pid {} — NOT NAMED", s.pid),
        };
        let peer = if s.listening() {
            String::new()
        } else {
            format!(" -> {}:{}", h(&s.remote), s.remote_port)
        };
        println!(
            "  {:<5} {:<22} {:<12} {}{}",
            s.proto,
            format!("{}:{}", h(&s.local), s.port),
            s.state,
            who,
            peer
        );
    }

    let shown: Vec<_> = r.findings.iter().filter(|f| f.severity >= Severity::Note).collect();
    if shown.is_empty() {
        println!("\n  nothing reachable from off this host over TCP is worth explaining.");
    } else {
        println!("\n--- findings ---");
        for f in shown {
            println!("  [{}] {}", f.severity.tag(), h(&f.subject));
            println!("      {}", h(&f.what));
            println!("{}", wrap_why(&h(&f.why), "      why: "));
        }
    }

    println!("\n  NOTE: {}", h(overview::NOT_READ));
    for g in &r.gaps {
        println!("  NOT READ: {}", h(g));
    }
    if !r.complete() {
        println!("  Partial result (exit 7), not a clean one.");
    }
    code
}

#[cfg(all(target_os = "windows", feature = "mod-tui"))]
pub(crate) fn swept(
    source: crate::views::Source,
) -> (Vec<hemostat_sensor_win::posture::Finding>, Covered) {
    use crate::views::Source;
    use hemostat_sensor_win::Severity;
    match source {
        Source::Probe => {
            let p = hemostat_sensor_win::report();
            let c = probe_covered(&p);
            (p.findings, c)
        }
        Source::Persistence => {
            let r = hemostat_sensor_win::persist::report();

            let f = persistence_findings(&r).into_iter().filter(|f| f.severity >= Severity::Warn);
            (f.collect(), persistence_covered(&r))
        }
        Source::Accounts => {
            let r = hemostat_sensor_win::accounts::report();
            let c = accounts_covered(&r);
            (r.findings, c)
        }
        Source::Overview => {
            let r = hemostat_sensor_win::overview::report();
            let c = overview_covered(&r);
            (r.findings, c)
        }
        Source::Evtlog => evtlog_swept(),
        Source::Sysmon => sysmon_swept(),
        Source::Usn => usn_swept(),
        Source::Wmi => {
            let r = hemostat_sensor_win::wmi::scan();
            let c = wmi_covered(r.unreadable, r.live.is_some(), &r.live_gaps);
            (r.findings, c)
        }
        Source::Com => {
            let w = com_sweep();
            let c = com_covered(&w.refused, &w.unloaded);
            (w.findings, c)
        }
        Source::DllHijack => {
            let w = dll_hijack_sweep();
            let c = dll_hijack_covered(w.known_checked, &w.unreadable, &w.sideload.unchecked);
            let mut f = w.findings;
            f.extend(w.sideload.findings);
            (f, c)
        }
        Source::Modules => {
            let w = modules_sweep();
            let c = modules_covered(&w.unopened);
            (w.findings, c)
        }
        Source::Streams => {
            let w = streams_sweep(&[]);
            let c = streams_covered(&w.unreadable);
            (w.findings, c)
        }
        Source::Trust => {
            let r = hemostat_sensor_win::trust::report();
            let c = crate::trust_verb::win_covered(&r);
            (r.findings, c)
        }
        Source::Detect => detect_swept(),
    }
}

#[cfg(all(target_os = "windows", feature = "mod-tui", feature = "mod-detect-sigma"))]
fn detect_swept() -> (Vec<hemostat_sensor_win::posture::Finding>, Covered) {
    let (dir, looked) = crate::win_detect::console_rules_dir();
    let loaded = dir.map(|d| {
        let (docs, unreadable) = crate::analysis::collect_rule_documents(&d);
        (hemostat_detect::RuleSet::from_documents(&docs), unreadable)
    });
    crate::win_detect::console_result(
        loaded.as_ref().map(|(set, unreadable)| (set, unreadable.as_slice())),
        &looked,
        || {
            let input = crate::analysis::collect_events_for_detection();

            crate::win_detect::console_live_supersede(&input.about);
            input
        },
    )
}
#[cfg(all(target_os = "windows", feature = "mod-tui", not(feature = "mod-detect-sigma")))]
fn detect_swept() -> (Vec<hemostat_sensor_win::posture::Finding>, Covered) {
    not_built(hemostat_buildinfo::ModuleId::DetectSigma)
}

#[cfg(all(target_os = "windows", feature = "mod-tui"))]
#[cfg_attr(
    all(
        feature = "mod-sensor-evtlog",
        feature = "mod-sensor-sysmon",
        feature = "mod-sensor-usn",
        feature = "mod-detect-sigma"
    ),
    allow(dead_code)
)]
fn not_built(
    id: hemostat_buildinfo::ModuleId,
) -> (Vec<hemostat_sensor_win::posture::Finding>, Covered) {
    (Vec::new(), Covered::NotAtAll(hemostat_modules::module_refusal(id, crate::MANIFEST.variant)))
}

#[cfg(all(target_os = "windows", feature = "mod-tui", feature = "mod-sensor-evtlog"))]
fn evtlog_swept() -> (Vec<hemostat_sensor_win::posture::Finding>, Covered) {

    let s = hemostat_sensor_win::evtlog::sweep(true);
    let c = evtlog_covered(&s);
    (s.findings, c)
}
#[cfg(all(target_os = "windows", feature = "mod-tui", not(feature = "mod-sensor-evtlog")))]
fn evtlog_swept() -> (Vec<hemostat_sensor_win::posture::Finding>, Covered) {
    not_built(hemostat_buildinfo::ModuleId::SensorEvtlog)
}

#[cfg(all(target_os = "windows", feature = "mod-tui", feature = "mod-sensor-sysmon"))]
fn sysmon_swept() -> (Vec<hemostat_sensor_win::posture::Finding>, Covered) {
    let s = hemostat_sensor_win::sysmon::sweep();
    let c = sysmon_covered(&s);
    (s.findings, c)
}
#[cfg(all(target_os = "windows", feature = "mod-tui", not(feature = "mod-sensor-sysmon")))]
fn sysmon_swept() -> (Vec<hemostat_sensor_win::posture::Finding>, Covered) {
    not_built(hemostat_buildinfo::ModuleId::SensorSysmon)
}

#[cfg(all(target_os = "windows", feature = "mod-tui", feature = "mod-sensor-usn"))]
fn usn_swept() -> (Vec<hemostat_sensor_win::posture::Finding>, Covered) {

    let s = hemostat_sensor_win::usn::sweep_with("C:", usn_own_dir());
    let c = usn_covered(&s);
    (s.findings, c)
}
#[cfg(all(target_os = "windows", feature = "mod-tui", not(feature = "mod-sensor-usn")))]
fn usn_swept() -> (Vec<hemostat_sensor_win::posture::Finding>, Covered) {
    not_built(hemostat_buildinfo::ModuleId::SensorUsn)
}
