use hemostat_sensor_linux::kground;

fn main() {
    let p = kground::probe();
    print!("{p}");

    let r = kground::report();
    println!(
        "\nkground report: coverage={} tasks_walked={} processes_walked={} procfs_processes={} hidden={}",
        r.coverage.token(),
        r.tasks_walked,
        r.processes_walked,
        r.procfs_processes,
        r.hidden.len(),
    );
    if let Some(reason) = &r.reason {
        println!("  reason: {reason}");
    }
    for f in &r.findings {
        println!("  [{}] {} @ {} — {}", f.severity.tag(), f.subject, f.locus, f.what);
    }

    let ran = p.loaded && !matches!(r.coverage, hemostat_sensor_linux::triage::Coverage::Unreadable);
    std::process::exit(if ran { 0 } else { 1 });
}
