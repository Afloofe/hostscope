#[cfg(target_os = "linux")]
use crate::render::{h, json_array, json_str};
#[cfg(target_os = "linux")]
use crate::{EXIT_OK, EXIT_PARTIAL, EXIT_USAGE};

#[cfg(target_os = "linux")]
pub(crate) fn print_sentinel(json: bool) {
    use hemostat_lifecycle::mechanism;

    let service = std::env::var("HEMOSTAT_UNIT").unwrap_or_default();
    let d = mechanism::probe(&service);

    let own = hemostat_lifecycle::image::Sealed::from_path(std::path::Path::new("/proc/self/exe"));

    if json {
        let rows: Vec<String> = d
            .mechanisms
            .iter()
            .map(|m| {
                format!(
                    "{{\"mechanism\":\"{}\",\"usable\":{},\"needs_live_sentinel\":{},\
                     \"survives_cgroup_kill\":{},\"reason\":{}}}",
                    m.mechanism.token(),
                    m.usable,
                    m.mechanism.needs_a_live_sentinel(),
                    m.mechanism.survives_agent_cgroup_kill(),
                    match &m.reason {
                        Some(r) => json_str(r),
                        None => "null".into(),
                    }
                )
            })
            .collect();
        jprintln!(
            "{{\"init\":{},\"usable\":{},\"resurrection_if_registered\":\"{}\",\
             \"survive_cgroup_kill\":{},\"autonomous\":{},\"image\":{},\"mechanisms\":[{}]}}",
            json_str(&d.init.token()),
            d.usable(),
            mechanism::Resurrection::of(d.usable()).token(),
            d.survive_cgroup_kill(),
            d.autonomous(),
            match &own {
                Ok(i) => format!("{{\"sealed\":{},\"digest\":\"{}\"}}", i.sealed(), i.digest()),
                Err(e) => format!("{{\"sealed\":false,\"error\":{}}}", json_str(e)),
            },
            rows.join(",")
        );
        return;
    }

    println!("sentinel — what would put this agent back");
    println!("\n  {}", h(&d.summary()));
    for m in &d.mechanisms {
        let mark = if m.usable { "ok  " } else { "NO  " };

        let cg = if m.mechanism.survives_agent_cgroup_kill() {
            "survives a cgroup kill"
        } else {
            "DIES with the agent's cgroup"
        };

        let w = match (m.mechanism.needs_a_live_sentinel(), m.mechanism) {
            (true, _) => "needs a live watcher",
            (false, mechanism::Mechanism::RunitService) => "runsv is the watcher",
            (false, _) => "systemd is the watcher",
        };
        println!("  {mark}{:<17} {cg:<28} {w}", m.mechanism.token());
        if let Some(r) = &m.reason {
            println!("        {}", h(r));
        }
    }

    match &own {
        Ok(i) if i.sealed() => println!(
            "\n  this image sealed for relaunch: yes ({} bytes, sha256:{})",
            i.len(),
            &i.digest()[..16.min(i.digest().len())]
        ),
        Ok(_) => println!(
            "\n  this image sealed for relaunch: NO — a copy was made but would not seal, so a \n  \
             relaunch could not be trusted to execute the image that was verified"
        ),
        Err(e) => println!("\n  this image sealed for relaunch: NO — {}", h(e)),
    }

    let grade = mechanism::Resurrection::of(d.usable());
    println!(
        "\n  N_effective if every usable mechanism registers: {} — resurrection {}",
        d.usable(),
        grade.token()
    );
    if let Some(p0) = grade.p0() {
        println!("  {p0}");
    }
    println!(
        "\n  NOTE: this is what is AVAILABLE, not what is running.\n  \
         `hemostat sentinel --register PID` starts one sentinel per usable mechanism."
    );
}

#[cfg(target_os = "linux")]
const CARRIED_ENV: &[&str] = &[
    "HEMOSTAT_PROFILE",
    "HEMOSTAT_ENGAGEMENT_ID",
    "HEMOSTAT_UNIT",
    "HEMOSTAT_POLICY",
    "HEMOSTAT_EPOCH_FLOOR",
    "HEMOSTAT_NONCE_LOG",
    "HEMOSTAT_ALLOWLIST",
    "HEMOSTAT_MANIFEST",
    "HEMOSTAT_CRASH_DIR",
    "HEMOSTAT_GOOFKIT_MAGIC",
    "HEMOSTAT_ENGAGEMENT_PUBKEY",
    "HEMOSTAT_RESPONDER_PUBKEY",
    "HEMOSTAT_RECOVERY_PUBKEY",
    "HEMOSTAT_SEAL_PUBKEY",
    "HEMOSTAT_SNAPSHOT_PUBKEY",
    "HEMOSTAT_MANIFEST_PUBKEY",
    "SUDO_USER",
    "SUDO_UID",
    "SSH_CONNECTION",
    "PATH",
];

#[cfg(target_os = "linux")]
fn carried(vars: impl IntoIterator<Item = (String, String)>) -> Vec<(String, String)> {
    vars.into_iter().filter(|(k, _)| CARRIED_ENV.contains(&k.as_str())).collect()
}

#[cfg(target_os = "linux")]
fn agent_env(pid: Option<u32>) -> Vec<(String, String)> {
    pid.and_then(hemostat_lifecycle::watch::environ_of).map(carried).unwrap_or_else(|| {
        carried(std::env::vars_os().filter_map(|(k, v)| Some((k.into_string().ok()?, v.into_string().ok()?))))
    })
}

#[cfg(target_os = "linux")]
pub(crate) fn registered_env() -> Vec<(String, String)> {
    agent_env(None)
}

#[cfg(target_os = "linux")]
fn parse_uids(status: &str) -> Option<(u32, u32)> {
    let mut ids = status.lines().find_map(|l| l.strip_prefix("Uid:"))?.split_whitespace();
    let real = ids.next()?.parse().ok()?;
    let effective = ids.next()?.parse().ok()?;
    Some((real, effective))
}

#[cfg(target_os = "linux")]
fn uids_of(pid: u32) -> Option<(u32, u32)> {

    let status = hemostat_sensor_linux::saferead::read_pid_text(format!("/proc/{pid}/status")).ok()?;
    parse_uids(&status)
}

#[cfg(target_os = "linux")]
pub(crate) fn owner_refusal(ours: Option<(u32, u32)>, theirs: Option<(u32, u32)>, pid: u32) -> Option<(u8, String)> {
    match (ours, theirs) {
        (Some(a), Some(b)) if a == b => None,
        (Some((r, e)), Some((tr, te))) => Some((
            EXIT_USAGE,
            format!(
                "pid {pid} runs this agent's image and arguments as uid {tr} (effective {te}), and this \
                 sentinel runs as uid {r} (effective {e}). Anyone can start the public binary with the \
                 agent's arguments: a process another user started is a decoy, and taking it for the \
                 agent would leave the agent dead and carry that user's environment into a relaunch"
            ),
        )),
        (None, _) => Some((
            EXIT_PARTIAL,
            "this sentinel cannot read its own uids from /proc/self/status, so it cannot tell the \
             agent from a decoy started by another user"
                .to_string(),
        )),
        (_, None) => Some((
            EXIT_PARTIAL,
            format!(
                "the uids of pid {pid} could not be read from /proc/{pid}/status, so there is no way to \
                 confirm it runs as this sentinel does — and a decoy started by another user is the \
                 thing the check is for"
            ),
        )),
    }
}

#[cfg(target_os = "linux")]
fn find_owned(
    digest: &str,
    argv: &[String],
    me: u32,
    ours: (u32, u32),
    decoy: &mut dyn FnMut(&str),
) -> Option<hemostat_lifecycle::watch::Target> {
    let mut found = None;
    for t in hemostat_lifecycle::watch::find_all_where(digest, me, |a| a == argv) {
        match owner_refusal(Some(ours), uids_of(t.pid), t.pid) {
            None => {
                found.get_or_insert(t);
            }
            Some((_, why)) => decoy(&format!("P0: not adopted — {why}")),
        }
    }
    found
}

#[cfg(target_os = "linux")]
fn owned_claim(
    claim: hemostat_lifecycle::watch::Claim,
    holds_claim: bool,
    refuse: impl Fn(&hemostat_lifecycle::watch::Target) -> Option<String>,
    rescan: impl FnOnce() -> Option<hemostat_lifecycle::watch::Target>,
    say: &mut dyn FnMut(&str),
) -> hemostat_lifecycle::watch::Claim {
    use hemostat_lifecycle::watch::Claim;
    match claim {
        Claim::Adopted(t) => match refuse(&t) {
            None => Claim::Adopted(t),
            Some(why) => {
                say(&format!("P0: not adopted — {why}"));
                match rescan() {
                    Some(owned) => Claim::Adopted(owned),
                    None if holds_claim => Claim::Mine,
                    None => Claim::Peer,
                }
            }
        },
        other => other,
    }
}

#[cfg(target_os = "linux")]
fn emit(json: bool, e: &str) {
    if json {
        jprintln!("{{\"event\":{}}}", json_str(e));
    } else {
        println!("  {}", h(e));
    }
}

#[cfg(target_os = "linux")]
fn carried_names(env: &[(String, String)]) -> Vec<String> {
    env.iter().map(|(k, _)| k.clone()).collect()
}

#[cfg(target_os = "linux")]
fn carried_line(env: &[(String, String)]) -> String {
    if env.is_empty() {
        "nothing".to_string()
    } else {
        h(&carried_names(env).join(", "))
    }
}

#[cfg(target_os = "linux")]
fn write_envdir(dir: &std::path::Path, env: &[(String, String)]) -> Result<(), String> {
    match std::fs::remove_dir_all(dir) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(format!("could not clear {}: {e}", dir.display())),
    }
    std::fs::create_dir_all(dir).map_err(|e| format!("could not create {}: {e}", dir.display()))?;
    for (k, v) in env {
        let f = dir.join(k);
        std::fs::write(&f, v).map_err(|e| format!("could not write {}: {e}", f.display()))?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub(crate) fn register_runit_sentinel(
    spec: &str,
    on_disk: &Option<String>,
    persist: bool,
    env: &[(String, String)],
) -> Result<String, String> {
    use hemostat_lifecycle::mechanism;

    let Some(binary) = on_disk else {
        return Err(
            "this agent is running from a sealed memory image with no path on disk, and a runit \
             service needs one. Writing the image to disk on an incident host is the operator's \
             call, not the sentinel's."
                .into(),
        );
    };
    let Some(svdir) = mechanism::runit_service_dir() else {
        return Err("runit's service scan directory could not be found".into());
    };
    if let Some(why) = boot_persistence_refusal(&svdir, persist) {
        return Err(why);
    }

    let name = "hemostat-sentinel";
    let dir = std::path::Path::new(&svdir).join(name);
    let run = dir.join("run");

    let script = format!(
        "#!/bin/sh\n\
         # Written by `hemostat sentinel --register`. Watches the HEMOSTAT agent\n\
         # and restarts it if it dies. Identity is the agent's image and argv,\n\
         # not a pid, so this survives being restarted itself. ./env holds the\n\
         # agent's configuration, one file per variable.\n\
         exec 2>&1\n\
         exec chpst -e ./env {binary} sentinel --watch {spec}\n"
    );

    std::fs::create_dir_all(&dir)
        .map_err(|e| format!("could not create {}: {e}", dir.display()))?;
    write_envdir(&dir.join("env"), env)?;
    std::fs::write(&run, script).map_err(|e| format!("could not write {}: {e}", run.display()))?;

    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(&run, std::fs::Permissions::from_mode(0o755))
        .map_err(|e| format!("could not make {} executable: {e}", run.display()))?;

    Ok(format!(
        "sentinel service written to {} — runsvdir starts it within ~5s{}",
        dir.display(),
        if volatile(&svdir) {
            "; it is on /run and goes at the next reboot"
        } else {
            "; it PERSISTS across reboots with no expiry (--persist) — `hemostat uninstall` \
             removes it"
        }
    ))
}

#[cfg(target_os = "linux")]
fn volatile(svdir: &str) -> bool {
    std::path::Path::new(svdir).starts_with("/run")
}

#[cfg(target_os = "linux")]
fn boot_persistence_refusal(svdir: &str, persist: bool) -> Option<String> {
    (!persist && !volatile(svdir)).then(|| {
        format!(
            "runit's service directory here is {svdir}, which is read at every boot, so a \
             sentinel written there would start the agent again after a reboot. That needs \
             --persist (design §18.9); without it this mechanism is not used"
        )
    })
}

#[cfg(target_os = "linux")]
fn transient_unit_argv(
    name: &str,
    on_disk: &Option<String>,
    spec: &str,
    env: &[(String, String)],
) -> Result<Vec<String>, String> {
    let Some(binary) = on_disk else {
        return Err(
            "this agent is running from a sealed memory image with no path on disk, and a \
             transient unit restarts its sentinel by executing a path after this registration \
             has exited. Writing the image to disk on an incident host is the operator's call, \
             not the sentinel's."
                .into(),
        );
    };
    let mut argv: Vec<String> =
        ["--unit", name, "--property=Restart=always", "--property=RestartSec=1", "--collect"]
            .map(String::from)
            .to_vec();
    argv.extend(env.iter().map(|(k, v)| format!("--setenv={k}={v}")));
    argv.extend([binary.as_str(), "sentinel", "--watch", spec].map(String::from));
    Ok(argv)
}

#[cfg(target_os = "linux")]
pub(crate) fn register_sentinels(pid: u32, json: bool, persist: bool) -> u8 {
    use hemostat_lifecycle::mechanism::{self, Mechanism};
    use hemostat_lifecycle::watch;

    let ours = watch::image_digest_of(std::process::id());
    let theirs = watch::image_digest_of(pid);
    if let Some((code, why)) = guard_refusal(ours.as_deref(), theirs.as_deref(), pid) {
        eprintln!("sentinel: pid {pid} {}", h(&why));
        return code;
    }

    if let Some((code, why)) = owner_refusal(uids_of(std::process::id()), uids_of(pid), pid) {
        eprintln!("sentinel: {}", h(&why));
        return code;
    }

    let argv = match watch::argv_of(pid) {
        Some(a) => a,
        None => {
            eprintln!(
                "sentinel: pid {pid} has no readable cmdline, so there is nothing to identify \
                 the agent by"
            );
            return EXIT_PARTIAL;
        }
    };
    let spec = watch::encode_argv(&argv);

    let env = agent_env(Some(pid));

    let service = std::env::var("HEMOSTAT_UNIT").unwrap_or_default();
    let d = mechanism::probe(&service);

    let on_disk = std::fs::read_link("/proc/self/exe")
        .ok()
        .filter(|p| p.is_absolute() && p.exists())
        .map(|p| p.display().to_string());
    let mut done: Vec<(Mechanism, Result<String, String>)> = Vec::new();

    for m in &d.mechanisms {
        if !m.usable {
            done.push((
                m.mechanism,
                Err(m.reason.clone().unwrap_or_else(|| "not available".into())),
            ));
            continue;
        }
        let r = match m.mechanism {

            Mechanism::ForkedChild => match hemostat_lifecycle::image::Sealed::from_path(
                std::path::Path::new("/proc/self/exe"),
            ) {
                Ok(img) => {
                    let sargv = vec![
                        "hemostat".to_string(),
                        "sentinel".to_string(),
                        "--watch".to_string(),
                        spec.clone(),
                    ];
                    watch::relaunch(&img, &sargv, &env).map(|p| format!("sentinel forked as pid {p}"))
                }
                Err(e) => Err(e),
            },

            Mechanism::TransientUnit => {

                let name = format!("{}{pid}", hemostat_sensor_linux::enablement::SENTINEL_UNIT_PREFIX);
                transient_unit_argv(&name, &on_disk, &spec, &env).and_then(|args| {
                    std::process::Command::new("systemd-run")
                        .args(&args)
                        .output()
                        .map_err(|e| format!("systemd-run could not be started: {e}"))
                        .and_then(|o| {
                            if o.status.success() {
                                Ok(format!("sentinel registered as transient unit {name}"))
                            } else {
                                Err(format!(
                                    "systemd-run refused: {}",
                                    String::from_utf8_lossy(&o.stderr).trim()
                                ))
                            }
                        })
                })
            }

            Mechanism::UnitRestart => {
                Ok(format!("already in effect: systemd restarts {service} on its own"))
            }

            Mechanism::RunitService => {
                Ok(format!("already in effect: runsv restarts {service} on its own"))
            }

            Mechanism::RunitSupervised => register_runit_sentinel(&spec, &on_disk, persist, &env),
        };
        done.push((m.mechanism, r));
    }

    let live = done.iter().filter(|(_, r)| r.is_ok()).count();
    let grade = mechanism::Resurrection::of(live);

    if json {
        let rows: Vec<String> = done
            .iter()
            .map(|(m, r)| {
                format!(
                    "{{\"mechanism\":\"{}\",\"registered\":{},\"detail\":{}}}",
                    m.token(),
                    r.is_ok(),
                    json_str(match r {
                        Ok(v) => v,
                        Err(e) => e,
                    })
                )
            })
            .collect();
        jprintln!(
            "{{\"guarding\":{pid},\"registered\":{live},\"of\":{},\"n_effective\":{live},\
             \"resurrection\":\"{}\",\"carried_env\":{},\"mechanisms\":[{}]}}",
            done.len(),
            grade.token(),
            json_array(&carried_names(&env)),
            rows.join(",")
        );
    } else {
        println!("sentinel: registering redundant watchers over pid {pid}");
        println!("  carrying from its environment: {}\n", carried_line(&env));
        for (m, r) in &done {
            match r {
                Ok(v) => println!("  ok  {:<15} {}", m.token(), h(v)),
                Err(e) => println!("  NO  {:<15} {}", m.token(), h(e)),
            }
        }
        println!(
            "\n  {live} of {} mechanism(s) registered: N_effective {live}, resurrection {}. {}",
            done.len(),
            grade.token(),
            if live == 0 {
                "Nothing will put this agent back if it is killed."
            } else {
                "Exactly one will relaunch on any given death; the others adopt."
            }
        );
        if let Some(p0) = grade.p0() {
            println!("  {p0}");
        }
    }

    if grade != mechanism::Resurrection::Normal {
        EXIT_PARTIAL
    } else {
        EXIT_OK
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn guard_refusal(ours: Option<&str>, theirs: Option<&str>, pid: u32) -> Option<(u8, String)> {
    match (ours, theirs) {
        (Some(a), Some(b)) if a == b => None,
        (_, Some(b)) => Some((
            EXIT_USAGE,
            format!(
                "is running a different image (sha256:{}, this one is sha256:{}). A sentinel \
                 relaunches the copy it sealed, so guarding another program would execute \
                 hemostat under that program's arguments rather than restarting it.",
                &b[..16.min(b.len())],
                ours.map_or("unknown", |a| &a[..16.min(a.len())]),
            ),
        )),

        (_, None) if !std::path::Path::new("/proc").join(pid.to_string()).exists() => Some((
            EXIT_PARTIAL,
            "is no longer running, so there is nothing to guard. It may have exited between the \
             pid being read and this sentinel starting."
                .to_string(),
        )),
        (_, None) => Some((
            EXIT_PARTIAL,
            "is running, but its image could not be read — so there is no way to confirm it is \
             this agent, and relaunching the wrong thing is worse than not relaunching. A \
             sentinel needs the privilege to read /proc/<pid>/exe of what it guards."
                .to_string(),
        )),
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn guard_pid(pid: u32, json: bool) -> u8 {
    use hemostat_lifecycle::watch;

    if watch::Target::of(pid).is_none() {
        eprintln!("sentinel: pid {pid} is not running, so there is nothing to guard");
        return EXIT_PARTIAL;
    }

    let ours = watch::image_digest_of(std::process::id());
    let theirs = watch::image_digest_of(pid);
    if let Some((code, why)) = guard_refusal(ours.as_deref(), theirs.as_deref(), pid) {
        eprintln!("sentinel: pid {pid} {}", h(&why));
        return code;
    }

    if let Some((code, why)) = owner_refusal(uids_of(std::process::id()), uids_of(pid), pid) {
        eprintln!("sentinel: {}", h(&why));
        return code;
    }

    let argv = match watch::argv_of(pid) {
        Some(a) => a,
        None => {
            eprintln!(
                "sentinel: pid {pid} has no readable cmdline, so a relaunch would have to guess \n\
                 what the agent was doing. It will not guess."
            );
            return EXIT_PARTIAL;
        }
    };

    watch_agent(&argv, agent_env(Some(pid)), json)
}

#[cfg(target_os = "linux")]
pub(crate) fn watch_agent(argv: &[String], env: Vec<(String, String)>, json: bool) -> u8 {
    use hemostat_lifecycle::{image::Sealed, restart::Policy, watch};

    let image = match Sealed::from_path(std::path::Path::new("/proc/self/exe")) {
        Ok(i) if i.sealed() => i,
        Ok(_) => {
            eprintln!(
                "sentinel: this image would not seal, so a relaunch could not be trusted to \
                 execute the image that was verified"
            );
            return EXIT_PARTIAL;
        }
        Err(e) => {
            eprintln!("sentinel: cannot seal this image: {e}");
            return EXIT_PARTIAL;
        }
    };

    let me = std::process::id();
    let our_digest = match watch::image_digest_of(me) {
        Some(d) => d,
        None => {
            eprintln!("sentinel: this process cannot read its own image, so it cannot identify \
                       the agent it is meant to guard");
            return EXIT_PARTIAL;
        }
    };

    let Some(ours) = uids_of(me) else {
        eprintln!(
            "sentinel: this process cannot read its own uids from /proc/self/status, so it cannot \
             tell the agent from a decoy started by another user"
        );
        return EXIT_PARTIAL;
    };
    let refuse = |t: &watch::Target| owner_refusal(Some(ours), uids_of(t.pid), t.pid).map(|(_, why)| why);

    let found = find_owned(&our_digest, argv, me, ours, &mut |e| emit(json, e));
    let target = match found {
        Some(t) => t,
        None => {

            let mut boot = hemostat_lifecycle::coordinate::Coordinator::new(&our_digest, me);
            let claim = boot.claim(argv);
            let claim = owned_claim(
                claim,
                boot.holds_claim(),
                refuse,
                || find_owned(&our_digest, argv, me, ours, &mut |_| {}),
                &mut |e| emit(json, e),
            );
            match claim {
                watch::Claim::Adopted(t) => t,
                watch::Claim::Peer => {
                    eprintln!(
                        "sentinel: no agent is running and a peer sentinel holds the claim to \
                         start one; standing by"
                    );
                    return EXIT_PARTIAL;
                }
                watch::Claim::Mine => match watch::relaunch(&image, argv, &env) {
                    Ok(pid) => {
                        println!("sentinel: no agent was running; started one as pid {pid}");
                        match watch::Target::of(pid) {
                            Some(t) => t,
                            None => {
                                eprintln!(
                                    "sentinel: the agent started as pid {pid} and did not survive \
                                     long enough to be watched"
                                );
                                return EXIT_PARTIAL;
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("sentinel: could not start the agent: {}", h(&e));
                        return EXIT_PARTIAL;
                    }
                },
            }
        }
    };

    if json {
        jprintln!(
            "{{\"guarding\":{},\"digest\":\"{}\",\"argv\":{},\"carried_env\":{}}}",
            target.pid,
            our_digest,
            json_array(argv),
            json_array(&carried_names(&env))
        );
    } else {
        println!(
            "sentinel: guarding pid {} (start_time {}), image sha256:{}",
            target.pid,
            target.start_time,
            &our_digest[..16.min(our_digest.len())]
        );
        println!("  it will be relaunched as: {}", h(&argv.join(" ")));
        println!("  carrying from its environment: {}", carried_line(&env));
    }

    let mut coord = hemostat_lifecycle::coordinate::Coordinator::new(&our_digest, me);

    if let Err(why) = crate::resources::apply_oom_score_adj(crate::authz::resource_profile("sentinel")) {
        eprintln!("sentinel: NOTE: {}", h(&why));
    }
    let policy = Policy::default();
    let mut peers = watch::PeerWatch::sentinels(&our_digest, &watch::encode_argv(argv), me);
    let mut polls = 0_u32;
    let mut peer_check = move || {
        polls = polls.wrapping_add(1);
        if polls % 5 == 0 {
            let mut events = Vec::new();
            for gone in peers.poll() {
                events.push(format!(
                    "P0: peer sentinel pid {} (start_time {}) is gone — a sentinel over this \
                     agent was removed or died; {} peer(s) remain",
                    gone.pid,
                    gone.start_time,
                    peers.peers()
                ));
            }

            for (held, how) in peers.held(watch::now_ms(), policy.held_ms) {
                events.push(format!(
                    "P0: peer sentinel pid {} (start_time {}) is alive but {} — a held \
                     sentinel relaunches nothing, so it is as good as removed until resumed",
                    held.pid,
                    held.start_time,
                    how.describe()
                ));
            }
            for e in events {
                if json {
                    jprintln!("{{\"event\":{}}}", json_str(&e));
                } else {
                    println!("  {e}");
                }
            }
        }
        true
    };

    let outcome = watch::supervise_with(
        target,
        &image,
        argv,
        &env,
        &policy,
        1_000,
        |dead_argv| {
            let c = coord.claim(dead_argv);
            if let Some(e) = coord.last_error() {
                eprintln!("sentinel: {}", h(e));
            }

            owned_claim(
                c,
                coord.holds_claim(),
                refuse,
                || find_owned(&our_digest, dead_argv, me, ours, &mut |_| {}),
                &mut |e| emit(json, e),
            )
        },
        &mut peer_check,
        |e| emit(json, e),
    );

    match outcome {
        watch::Stopped::Asked { .. } => EXIT_OK,

        watch::Stopped::GaveUp { attempts } => {
            eprintln!(
                "sentinel: gave up after {attempts} relaunches in the policy window — the agent \
                 will not stay up, and spinning on it would be the crash loop this is meant to end"
            );
            EXIT_PARTIAL
        }
        watch::Stopped::Failed { reason } => {
            eprintln!("sentinel: {}", h(&reason));
            EXIT_PARTIAL
        }
    }
}
