pub(crate) fn print_brief(json: bool) -> u8 {
    if json {

        eprintln!(
            "hemostat brief: this is a human report meant to paste into an inject; it ignores \
             --json. For machine output, run the individual sweeps (`overview`, `accounts`, \
             `persistence`, `firewall`) with --json."
        );
    }
    let bar = "=".repeat(72);
    println!("{bar}");
    println!("MAHORAGA — INJECT BRIEF   (read-only technical report)");
    println!("{bar}");
    println!(
        "The technical body for a Race-Control directive: host posture, a user audit, what\n\
         autostarts, and the firewall. It gathers facts only — the operator writes the\n\
         narrative and submits the PDF (packet rule 21). Response actions taken are a\n\
         reversible timeline under `mahoraga remediate --log`."
    );
    sections()
}

#[cfg(target_os = "linux")]
fn sections() -> u8 {
    section("1. HOST POSTURE — what this box is, and what it is listening to");
    let _ = crate::sweeps::print_overview(false);
    section("2. ACCOUNTS — login accounts, graded against the packet roster");
    let _ = crate::sweeps::print_accounts(false);
    section("3. AUTOSTART / PERSISTENCE — what runs without a login");
    let _ = crate::sweeps::print_persistence(false, false);
    section("4. FIREWALL — the host ruleset and its trust tag");
    let _ = crate::sweeps::print_firewall(false);
    section("5. RESPONSE ACTIONS — for the IR narrative");
    println!("  Run `mahoraga remediate --log` for the full reversible action timeline,");
    println!("  and `mahoraga export report` for the sealed incident report.");
    crate::EXIT_OK
}

#[cfg(target_os = "windows")]
fn sections() -> u8 {
    section("1. HOST POSTURE — what this box is, and what it is listening to");
    let _ = crate::sensors_win::print_win_overview(false);
    section("2. ACCOUNTS — local accounts, graded against the packet roster");
    let _ = crate::sensors_win::print_win_accounts(false);
    section("3. AUTOSTART / PERSISTENCE — tasks, services and Run keys");
    let _ = crate::sensors_win::print_win_persistence(false);
    section("4. RESPONSE ACTIONS — for the IR narrative");
    println!("  Run `mahoraga remediate --log` for the reversible action timeline,");
    println!("  and `mahoraga export report` for the sealed incident report.");
    crate::EXIT_OK
}

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
fn sections() -> u8 {
    println!("\n(no per-sweep sections on this OS)");
    crate::EXIT_OK
}

#[cfg(any(target_os = "linux", target_os = "windows"))]
fn section(title: &str) {
    println!("\n\n{}", "-".repeat(72));
    println!("## {title}");
    println!("{}", "-".repeat(72));
}
