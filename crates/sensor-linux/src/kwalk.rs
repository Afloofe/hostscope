use std::collections::BTreeSet;
use std::fs;

use crate::syscallhook::{parse_kallsyms, parse_modules, Kcore};
use crate::triage::{rank, Finding, Severity};

const MODULE_NAME_LEN: usize = 56;

const TASK_COMM_LEN: usize = 16;

const WALK_CAP: usize = 65536;

const SYNTHETIC_TAGS: &[&str] = &["bpf"];

const SYNTHETIC_SYMBOLS: &[(&str, &str)] = &[
    ("__builtin__ftrace", "ftrace_trampoline"),
    ("__builtin__kprobes", "kprobe_insn_page"),
    ("__builtin__kprobes", "kprobe_optinsn_page"),
];

#[derive(Debug, Clone, Default)]
pub struct Report {

    pub findings: Vec<Finding>,

    pub available: bool,

    pub reason: Option<String>,

    pub tasks_walked: usize,

    pub modules_walked: usize,

    pub module_crossview_ran: bool,

    pub hidden_modules: Vec<String>,

    pub gaps: Vec<String>,
}

struct Offsets {
    module_list: u64,
    module_name: u64,
    task_tasks: u64,
    task_pid: u64,
    task_tgid: u64,
    task_comm: u64,
}

fn resolve_offsets() -> Option<Offsets> {
    let btf = crate::btf::vmlinux().ok()?;
    let m = |s: &str, f: &str| crate::btf::member_offset(&btf, s, f).ok().map(u64::from);
    Some(Offsets {
        module_list: m("module", "list")?,
        module_name: m("module", "name")?,
        task_tasks: m("task_struct", "tasks")?,
        task_pid: m("task_struct", "pid")?,
        task_tgid: m("task_struct", "tgid")?,
        task_comm: m("task_struct", "comm")?,
    })
}

fn read_u64(k: &mut Kcore, va: u64) -> Option<u64> {
    let mut b = [0u8; 8];
    k.read_at(va, &mut b).ok()?;
    Some(u64::from_le_bytes(b))
}

fn read_u32(k: &mut Kcore, va: u64) -> Option<u32> {
    let mut b = [0u8; 4];
    k.read_at(va, &mut b).ok()?;
    Some(u32::from_le_bytes(b))
}

fn read_cstr(k: &mut Kcore, va: u64, max: usize) -> Option<String> {
    let mut b = vec![0u8; max];
    k.read_at(va, &mut b).ok()?;
    let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    Some(crate::kmod::name_key(b.get(..end).unwrap_or(&b)).into_owned())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WalkEnd {

    Complete,

    ReadError,

    NullLink,

    Capped,
}

fn walk_list(k: &mut Kcore, head_va: u64, mut visit: impl FnMut(&mut Kcore, u64)) -> WalkEnd {

    let mut node = match read_u64(k, head_va) {
        Some(n) => n,
        None => return WalkEnd::ReadError,
    };
    let mut seen = 0usize;
    loop {
        if let Some(end) = step(node, head_va, seen) {
            return end;
        }
        visit(k, node);
        node = match read_u64(k, node) {
            Some(n) => n,
            None => return WalkEnd::ReadError,
        };
        seen += 1;
    }
}

fn step(node: u64, head_va: u64, seen: usize) -> Option<WalkEnd> {
    if node == head_va {
        Some(WalkEnd::Complete)
    } else if node == 0 {
        Some(WalkEnd::NullLink)
    } else if seen >= WALK_CAP {
        Some(WalkEnd::Capped)
    } else {
        None
    }
}

fn partial_walk(which: &str, end: WalkEnd, walked: usize) -> Option<Finding> {
    let why = match end {
        WalkEnd::Complete => return None,
        WalkEnd::ReadError => "a link could not be read",
        WalkEnd::NullLink => "a link was NULL, which a live list never holds",
        WalkEnd::Capped => "it passed the walk cap without returning to its start",
    };
    Some(Finding::flag(
        Severity::Warn,
        "kernel list walk",
        which.to_string(),
        format!("the {which} walk stopped after {walked} entr(y/ies): {why}"),
        "entries past that point were not compared with /proc, so this is a partial answer, \
         not a clean one. A list corrupted to stop a walker is itself a rootkit technique",
    ))
}

fn proc_pids() -> BTreeSet<u32> {
    let mut out = BTreeSet::new();
    if let Ok(rd) = fs::read_dir("/proc") {
        for e in rd.flatten() {
            if let Some(pid) = e.file_name().to_str().and_then(|n| n.parse::<u32>().ok()) {
                out.insert(pid);
            }
        }
    }
    out
}

pub(crate) fn in_nested_pid_namespace() -> bool {
    crate::saferead::read_pid_text("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find_map(|l| l.strip_prefix("NSpid:"))
                .map(|rest| rest.split_whitespace().count() > 1)
        })
        .unwrap_or(false)
}

fn kallsyms_module_tags(text: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for line in text.lines() {
        if let Some(start) = line.rfind('[') {
            if line.ends_with(']') {
                let name = &line[start + 1..line.len() - 1];
                let symbol = line.split_whitespace().nth(2).unwrap_or("");
                if !name.is_empty() && !SYNTHETIC_SYMBOLS.contains(&(name, symbol)) {
                    out.insert(name.to_string());
                }
            }
        }
    }
    out
}

fn proc_module_names() -> Option<BTreeSet<String>> {
    Some(module_names(&crate::kmod::name_key(&crate::saferead::read_kernel_bytes("/proc/modules").ok()?)))
}

fn module_names(text: &str) -> BTreeSet<String> {
    parse_modules(text).into_iter().map(|m| m.name).collect()
}

fn sys_module_names() -> Option<BTreeSet<String>> {
    use std::os::unix::ffi::OsStrExt as _;
    Some(
        fs::read_dir("/sys/module")
            .ok()?
            .flatten()

            .map(|e| crate::kmod::name_key(e.file_name().as_bytes()).into_owned())
            .collect(),
    )
}

fn tags_absent_from_both<'a>(
    tags: &'a BTreeSet<String>,
    proc_mods: Option<&BTreeSet<String>>,
    sys_mods: Option<&BTreeSet<String>>,
) -> Result<Vec<&'a String>, &'static str> {
    let (Some(proc_mods), Some(sys_mods)) = (proc_mods, sys_mods) else {
        return Err("/proc/modules or /sys/module could not be read, so a kallsyms tag \
                    could not be checked against them");
    };
    Ok(tags
        .iter()

        .filter(|t| !SYNTHETIC_TAGS.contains(&t.as_str()))
        .filter(|t| !proc_mods.contains(*t) && !sys_mods.contains(*t))
        .collect())
}

fn in_kernel_but_not_in_proc<'a>(
    in_kernel: &'a BTreeSet<String>,
    before: Option<&BTreeSet<String>>,
    after: Option<&BTreeSet<String>>,
) -> Result<Vec<&'a String>, &'static str> {
    let (Some(before), Some(after)) = (before, after) else {
        return Err("/proc/modules could not be read before or after the walk, so the \
                    kernel's module list had nothing to be compared against");
    };
    Ok(in_kernel
        .iter()
        .filter(|n| !before.contains(*n) && !after.contains(*n))
        .collect())
}

fn undecodable_names(text: &str) -> Option<Finding> {
    let bad: Vec<&str> = text.lines().filter(|l| l.contains('\u{fffd}')).collect();
    let first = bad.first()?;
    let owners: BTreeSet<&str> = bad
        .iter()
        .map(|l| {
            l.strip_suffix(']')
                .and_then(|l| l.rsplit_once('['))
                .map_or("core kernel", |(_, tag)| tag)
        })
        .collect();
    Some(Finding::flag(
        Severity::Warn,
        "kallsyms name not UTF-8",
        owners.into_iter().collect::<Vec<_>>().join(", "),
        format!(
            "{} kallsyms line(s) name a symbol or module with bytes that are not UTF-8 \
             (first: {})",
            bad.len(),
            first.split_whitespace().skip(2).collect::<Vec<_>>().join(" ")
        ),
        "the kernel prints these names as the module supplied them, and the kernel build never \
         produces one that is not UTF-8. Such a name breaks any tool that decodes kallsyms \
         strictly — which is a reason to plant one. Identify the module named here",
    ))
}

pub fn report() -> Report {
    let mut f = Vec::new();
    let mut hidden_modules: Vec<String> = Vec::new();
    let mut gaps: Vec<String> = Vec::new();

    let kallsyms_raw = match crate::saferead::read_kernel_bytes("/proc/kallsyms") {
        Ok(t) => t,

        Err(e) => return unavailable(&format!("/proc/kallsyms unreadable ({e})")),
    };

    let kallsyms_text = String::from_utf8_lossy(&kallsyms_raw);
    let kallsyms_keyed = crate::kmod::name_key(&kallsyms_raw);
    let (by_name, _) = parse_kallsyms(&kallsyms_text);
    if crate::syscallhook::kallsyms_is_restricted(&by_name) {
        return unavailable(
            "/proc/kallsyms returned only zeroed addresses — needs root (CAP_SYSLOG) and \
             kernel.kptr_restrict permitting symbol addresses",
        );
    }
    f.extend(undecodable_names(&kallsyms_text));

    let Some(off) = resolve_offsets() else {
        return unavailable(
            "could not resolve kernel struct offsets from BTF (/sys/kernel/btf/vmlinux) — \
             the walk needs module/task_struct field offsets",
        );
    };

    let mut kcore = match Kcore::open() {
        Ok(k) => k,
        Err(e) => return unavailable(&format!("/proc/kcore unreadable ({e}) — needs root and no lockdown-confidentiality")),
    };

    let mut modules_walked = 0usize;
    let mut tasks_walked = 0usize;
    let mut module_crossview_ran = false;

    let proc_mods = proc_module_names();
    let sys_mods = sys_module_names();
    match tags_absent_from_both(&kallsyms_module_tags(&kallsyms_keyed), proc_mods.as_ref(), sys_mods.as_ref()) {
        Ok(tags) => {
            for tag in tags {
                f.push(Finding::flag(
                    Severity::Critical,
                    "hidden module",
                    tag.clone(),
                    format!("module {tag:?} owns symbols in kallsyms but is absent from /proc/modules and /sys/module"),
                    "a module that unlinked from the module list and tore down its sysfs directory, \
                     but left its symbols tagged in kallsyms — the list_del+kobject_del hider that \
                     forgot its symbol table. Present in the kernel, hidden from both userland views",
                ));
            }
        }
        Err(why) => {
            gaps.push(format!("the kallsyms module cross-view did not run: {why}"));
            f.push(Finding::flag(
                Severity::Note,
                "kallsyms module cross-view",
                String::from("skipped"),
                format!("DID NOT RUN: {why}"),
                "this is 'could not look', not 'nothing there' — no finding in this report says \
                 whether a module has scrubbed its list entries while leaving its symbols behind",
            ));
        }
    }

    if let Some(&modules_head) = by_name.get("modules") {
        let mut in_kernel = BTreeSet::new();
        let end = walk_list(&mut kcore, modules_head, |k, node| {
            modules_walked += 1;
            let module_va = node.wrapping_sub(off.module_list);
            if let Some(name) = read_cstr(k, module_va.wrapping_add(off.module_name), MODULE_NAME_LEN) {
                if !name.is_empty() {
                    in_kernel.insert(name);
                }
            }
        });
        if let Some(p) = partial_walk("module-list", end, modules_walked) {
            gaps.push(p.what.clone());
            f.push(p);
        }

        match in_kernel_but_not_in_proc(&in_kernel, proc_mods.as_ref(), proc_module_names().as_ref()) {
            Ok(names) => {
                module_crossview_ran = true;
                for name in names {
                    hidden_modules.push(name.clone());
                    f.push(Finding::flag(
                        Severity::Critical,
                        "hidden module",
                        name.clone(),
                        format!("module {name:?} is in the kernel's module list but not in /proc/modules"),
                        "the module is linked in kernel memory yet filtered from the rendered \
                         /proc/modules — a hook on the module listing itself, which a sysfs \
                         cross-view cannot see because the module never unlinked",
                    ));
                }
            }
            Err(why) => {
                gaps.push(format!("the module-list cross-view did not run: {why}"));
                f.push(Finding::flag(
                    Severity::Note,
                    "module-list cross-view",
                    String::from("skipped"),
                    format!("DID NOT RUN: {why}"),
                    "this is 'could not look', not 'nothing there' — the kernel's own module \
                     list was walked, but nothing in this report says whether userland's view of \
                     it agrees",
                ));
            }
        }
    }

    if in_nested_pid_namespace() {
        gaps.push("the task-list cross-view did not run: this is a nested PID namespace".into());
        f.push(Finding::flag(
            Severity::Note,
            "task cross-view skipped",
            "nested PID namespace",
            "the kernel task-list vs /proc cross-view did not run",
            "this process is in a non-root PID namespace (a container): /proc lists only this \
             namespace's tasks while the /proc/kcore task_struct walk sees all host tasks, so \
             the cross-view would false-positive on nearly every host process. Run in the host's \
             root PID namespace to exercise it",
        ));
    } else if let Some(&init_task) = by_name.get("init_task") {
        let head = init_task.wrapping_add(off.task_tasks);

        let walk_leaders = |k: &mut Kcore| -> (std::collections::BTreeMap<u32, String>, WalkEnd) {
            let mut leaders = std::collections::BTreeMap::new();
            let end = walk_list(k, head, |k, node| {
                let task_va = node.wrapping_sub(off.task_tasks);
                let pid = read_u32(k, task_va.wrapping_add(off.task_pid)).unwrap_or(0);
                let tgid = read_u32(k, task_va.wrapping_add(off.task_tgid)).unwrap_or(0);
                if pid != 0 && pid == tgid {
                    let comm = read_cstr(k, task_va.wrapping_add(off.task_comm), TASK_COMM_LEN)
                        .unwrap_or_default();
                    leaders.insert(pid, comm);
                }
            });
            (leaders, end)
        };

        let (leaders1, end1) = walk_leaders(&mut kcore);
        tasks_walked = leaders1.len();
        let visible = proc_pids();
        let (leaders2, end2) = walk_leaders(&mut kcore);
        if let Some(p) =
            partial_walk("task-list", if end1 == WalkEnd::Complete { end2 } else { end1 }, tasks_walked)
        {
            gaps.push(p.what.clone());
            f.push(p);
        }

        if leaders1.is_empty() {
            gaps.push("the task-list walk found no processes at all".into());
            f.push(Finding::flag(
                Severity::Warn,
                "kernel list walk",
                "task-list".to_string(),
                "the task-list walk found no processes at all".to_string(),
                "a running kernel always has processes, so this walk read nothing it could use \
                 — the task cross-view did not effectively run",
            ));
        }
        for (pid, comm) in &leaders1 {
            if leaders2.contains_key(pid)
                && !visible.contains(pid)
                && fs::metadata(format!("/proc/{pid}")).is_err()
            {
                f.push(Finding::flag(
                    Severity::Critical,
                    "hidden process",
                    format!("pid {pid} ({comm})"),
                    "a process on the kernel task list is absent from /proc".to_string(),
                    "read from the kernel's own task_struct list via /proc/kcore, so a getdents \
                     or VFS hook hiding it from a /proc walk cannot conceal it here — and unlike \
                     the userland cross-view, this holds even if the rootkit also hooks open/stat \
                     on /proc/<pid>. A DKOM unlink from the task list itself would still evade it",
                ));
            }
        }
    }

    rank(&mut f);

    let module_walk_ran = by_name.contains_key("modules");
    let task_walk_ran = by_name.contains_key("init_task");
    if !module_walk_ran && !task_walk_ran {
        return unavailable(
            "neither `modules` nor `init_task` is in /proc/kallsyms, so no kernel list could \
             be walked. Both are ordinary exported symbols; their absence is itself worth \
             explaining, and until it is, this check has established nothing",
        );
    }

    if !module_walk_ran {
        gaps.push("the module-list walk did not run: kallsyms has no `modules` symbol".into());
        f.push(Finding::flag(
            Severity::Note,
            "module walk skipped",
            "kallsyms has no `modules` symbol".to_string(),
            "the kernel module-list walk did not run".to_string(),
            "the task-list walk below did run. A module hidden from both /proc/modules and \
             /sys/module would be caught only by this walk, so that half is unchecked rather \
             than clean",
        ));
    }
    if !task_walk_ran && !in_nested_pid_namespace() {
        gaps.push("the task-list walk did not run: kallsyms has no `init_task` symbol".into());
        f.push(Finding::flag(
            Severity::Note,
            "task walk skipped",
            "kallsyms has no `init_task` symbol".to_string(),
            "the kernel task-list walk did not run".to_string(),
            "the module-list walk above did run. A process unlinked from /proc but present on \
             the kernel task list would be caught only by this walk, so that half is unchecked \
             rather than clean",
        ));
    }

    Report {
        findings: f,
        available: true,
        reason: None,
        tasks_walked,
        modules_walked,
        module_crossview_ran,
        hidden_modules,
        gaps,
    }
}

fn unavailable(reason: &str) -> Report {
    Report {
        findings: Vec::new(),
        available: false,
        reason: Some(reason.to_string()),
        tasks_walked: 0,
        modules_walked: 0,
        module_crossview_ran: false,
        hidden_modules: Vec::new(),
        gaps: Vec::new(),
    }
}
