#[cfg(feature = "mod-tui")]
use crate::MANIFEST;

#[cfg(feature = "mod-tui")]
const SWEEP: &str = "freebsd";

#[cfg(feature = "mod-tui")]
const NOT_BUILT_YET: &str = "no FreeBSD sweep is built into this image yet, so nothing on this \
     host was examined. build-info, verify and read work here; the sweeps arrive with \
     sensor-freebsd (RFC-002 §6, S4 onward)";

#[cfg(feature = "mod-tui")]
pub(crate) fn console_model() -> hemostat_tui::ConsoleModel {

    let when = match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(d) => {
            let s = d.as_secs();
            format!("{:02}:{:02}:{:02} UTC", (s / 3600) % 24, (s / 60) % 60, s % 60)
        }
        Err(_) => String::new(),
    };

    hemostat_tui::ConsoleModel::new("unidentified host".into(), when, Vec::new())
        .with_gaps(vec![hemostat_tui::Gap::did_not_run(SWEEP, NOT_BUILT_YET)])
}

#[cfg(feature = "mod-tui")]
pub(crate) fn posture_model() -> hemostat_tui::PostureModel {
    use hemostat_tui::{Confidence, PostureModel, Row};
    PostureModel {
        variant: MANIFEST.variant.to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        tier: "NOT MEASURED".into(),
        tier_meaning: "no FreeBSD probe is in this image; what this host lets the agent do \
                       was not asked"
            .into(),
        rows: vec![Row {
            label: "sensor".into(),
            value: "none for FreeBSD".into(),

            confidence: Confidence::Measured,
            note: "from the build, not the host".into(),
        }],
        warnings: vec![NOT_BUILT_YET.to_string()],

        hooks: Vec::new(),
    }
}

#[cfg(feature = "mod-tui")]
pub(crate) fn apply_remedy(id: &str) -> Result<String, String> {
    Err(format!(
        "{}: no console remedy applies on FreeBSD in this image (variant {})",
        crate::render::h(id),
        MANIFEST.variant
    ))
}

use hemostat_sensor_freebsd::identity::{HostIdFile, HostIdentity};
use hemostat_sensor_freebsd::store::{Placement, QUOTA_BYTES};
use hemostat_sensor_freebsd::tools::Tool;

use crate::render::{h, hex32, jesc};
use crate::{EXIT_FAILED, EXIT_OK, EXIT_PARTIAL};

#[derive(Debug, Clone)]
pub(crate) struct ToolRow {
    pub(crate) tool: Tool,
    pub(crate) verdict: Result<ToolOk, String>,
}

#[derive(Debug, Clone)]
pub(crate) struct ToolOk {
    pub(crate) sha256: [u8; 32],
    pub(crate) libraries: usize,
    pub(crate) objects: usize,
    pub(crate) setid: bool,
    pub(crate) is_static: bool,
}

#[derive(Debug, Clone)]
pub(crate) struct ProbeReport {

    pub(crate) manifest: Result<Option<(String, usize)>, String>,

    pub(crate) sidecar: Result<Option<usize>, String>,
    pub(crate) tools: Vec<ToolRow>,
    pub(crate) host_id: [u8; 32],
    pub(crate) host: HostIdentity,
    pub(crate) store: Result<Placement, String>,
    pub(crate) reniced: Result<(), String>,
    pub(crate) hashed: u64,
}

impl ProbeReport {
    fn verified(&self) -> usize {
        self.tools.iter().filter(|t| t.verdict.is_ok()).count()
    }

    pub(crate) fn exit_code(&self) -> u8 {
        if self.manifest.is_err() {
            EXIT_FAILED
        } else if self.verified() < self.tools.len() || self.store.is_err() || self.sidecar.is_err() {
            EXIT_PARTIAL
        } else {
            EXIT_OK
        }
    }
}

#[cfg(unix)]
pub(crate) fn verify_tools(sys: &mut hemostat_sensor_freebsd::tools::System<'_>) -> Vec<ToolRow> {
    Tool::ALL
        .iter()
        .map(|&tool| ToolRow {
            tool,
            verdict: sys
                .verify(tool, &[])
                .map(|v| ToolOk {
                    sha256: v.digest().unwrap_or_default(),
                    libraries: v.libraries().count(),
                    objects: v.objects.len(),
                    setid: v.setid,
                    is_static: v.is_static,
                })
                .map_err(|e| e.to_string()),
        })
        .collect()
}

fn hostid_file(h: &HostIdentity) -> String {
    match &h.hostid_file {
        HostIdFile::Absent => "absent".into(),
        HostIdFile::Agrees => "agrees".into(),
        HostIdFile::Disagrees(u) => format!("DISAGREES ({u})"),
        HostIdFile::Only(u) => format!("the only source ({u})"),
        HostIdFile::Malformed => "present, not a UUID".into(),
        HostIdFile::Unreadable(why) => format!("unreadable ({why})"),
    }
}

pub(crate) fn render_probe(r: &ProbeReport) -> String {
    use std::fmt::Write as _;
    let mut o = String::new();
    let _ = writeln!(o, "probe — can this agent trust the tools it runs on this firewall (FreeBSD)");
    match &r.manifest {
        Ok(Some((rel, n))) => {
            let _ = writeln!(o, "  manifest  {} ({n} paths), signature checked against the pinned key", h(rel));
        }
        Ok(None) => {
            let _ = writeln!(
                o,
                "  manifest  NONE: pass --manifest PATH (PATH.sig beside it) or set $HEMOSTAT_MANIFEST, \
                 with the key in $HEMOSTAT_MANIFEST_PUBKEY. Without one no tool can be checked"
            );
        }
        Err(e) => {
            let _ = writeln!(o, "  manifest  REFUSED: {}", h(e));
        }
    }
    match &r.sidecar {
        Ok(Some(n)) => {
            let _ = writeln!(o, "  sidecar   {n} rows, signed and bound to the manifest: package links are followed where it records them");
        }
        Ok(None) => {}
        Err(e) => {
            let _ = writeln!(o, "  sidecar   NOT LOADED: {} — a tool that loads a library through a package's link (php) cannot be verified", h(e));
        }
    }
    let uuid = match &r.host.hostuuid {
        Ok(u) => h(u),
        Err(e) => format!("unread: {}", h(e)),
    };
    let _ = writeln!(
        o,
        "  host id   {} from {} (kern.hostuuid {uuid}; /etc/hostid {})",
        hex32(&r.host_id),
        r.host.source.label(),
        h(&hostid_file(&r.host))
    );
    if let Some((sev, what)) = r.host.finding() {
        let _ = writeln!(o, "            {}: {}", sev.tag(), h(&what));
    }
    match &r.store {
        Ok(p) => {
            let _ = writeln!(
                o,
                "  store     {} on {} ({}, {}){} · quota {} MiB",
                h(&p.dir),
                h(&p.mount.mountpoint),
                h(&p.mount.fstype),
                h(&p.mount.device),
                if p.exists { "" } else { ", not created yet" },
                QUOTA_BYTES / (1024 * 1024)
            );
        }
        Err(e) => {
            let _ = writeln!(o, "  store     REFUSED: {}", h(e));
        }
    }
    match &r.reniced {
        Ok(()) => {
            let _ = writeln!(o, "  priority  reniced to 10 with the verified renice");
        }
        Err(e) => {
            let _ = writeln!(o, "  priority  NOT reniced: {}", h(e));
        }
    }
    let _ = writeln!(o, "\n  {:<11} {:<11} DETAIL", "TOOL", "VERDICT");
    for t in &r.tools {
        match &t.verdict {
            Ok(v) => {
                let shape = if v.is_static {
                    "static".to_string()
                } else {
                    format!("{} {}", v.libraries, if v.libraries == 1 { "library" } else { "libraries" })
                };
                let setid = if v.setid { "; set-id, libraries found through ld-elf.so.hints" } else { "" };
                let _ = writeln!(
                    o,
                    "  {:<11} {:<11} {} {} · {shape}, {} files hashed{setid}",
                    t.tool.name(),
                    "verified",
                    t.tool.path(),
                    hex32(&v.sha256).get(..16).unwrap_or(""),
                    v.objects
                );
            }
            Err(e) => {
                let _ = writeln!(o, "  {:<11} {:<11} {}", t.tool.name(), "UNVERIFIED", h(e));
            }
        }
    }
    let _ = writeln!(
        o,
        "\n  {} of {} tools verified · {} KiB hashed",
        r.verified(),
        r.tools.len(),
        r.hashed / 1024
    );
    let _ = writeln!(
        o,
        "  Not seen by this check: a file swapped between the last re-check and execve(2), which \
         std cannot close without executing a descriptor; and a kernel that serves clean bytes \
         to read(2) and executes others (RFC-002 §4)."
    );
    o
}

pub(crate) fn render_probe_json(r: &ProbeReport) -> String {
    let opt = |s: Option<String>| s.map_or("null".to_string(), |v| format!("\"{}\"", jesc(&v)));
    let manifest = match &r.manifest {
        Ok(Some((rel, n))) => format!("{{\"release\":\"{}\",\"paths\":{n}}}", jesc(rel)),
        _ => "null".into(),
    };
    let tools: Vec<String> = r
        .tools
        .iter()
        .map(|t| match &t.verdict {
            Ok(v) => format!(
                "{{\"tool\":\"{}\",\"path\":\"{}\",\"verified\":true,\"sha256\":\"{}\",\
                 \"libraries\":{},\"files\":{},\"setid\":{},\"static\":{},\"why\":null}}",
                t.tool.name(),
                t.tool.path(),
                hex32(&v.sha256),
                v.libraries,
                v.objects,
                v.setid,
                v.is_static
            ),
            Err(e) => format!(
                "{{\"tool\":\"{}\",\"path\":\"{}\",\"verified\":false,\"why\":\"{}\"}}",
                t.tool.name(),
                t.tool.path(),
                jesc(e)
            ),
        })
        .collect();
    let store = match &r.store {
        Ok(p) => format!(
            "{{\"dir\":\"{}\",\"mountpoint\":\"{}\",\"fstype\":\"{}\",\"device\":\"{}\",\
             \"exists\":{},\"quota\":{QUOTA_BYTES},\"refused\":null}}",
            jesc(&p.dir),
            jesc(&p.mount.mountpoint),
            jesc(&p.mount.fstype),
            jesc(&p.mount.device),
            p.exists
        ),
        Err(e) => format!("{{\"refused\":\"{}\"}}", jesc(e)),
    };
    format!(
        "{{\"manifest\":{manifest},\"manifest_refused\":{},\"host_id\":\"{}\",\
         \"host_id_source\":\"{}\",\"hostuuid\":{},\"hostid_file\":\"{}\",\"identity_finding\":{},\
         \"sidecar_rows\":{},\"sidecar_refused\":{},\"store\":{store},\"reniced\":{},\"tools\":[{}],\"verified\":{},\"total\":{},\
         \"hashed_bytes\":{},\"complete\":{}}}",
        opt(r.manifest.as_ref().err().cloned()),
        hex32(&r.host_id),
        r.host.source.label(),
        opt(r.host.hostuuid.as_ref().ok().cloned()),
        jesc(&hostid_file(&r.host)),
        opt(r.host.finding().map(|(s, w)| format!("{}: {w}", s.tag()))),
        r.sidecar.as_ref().ok().copied().flatten().map_or("null".to_string(), |n| n.to_string()),
        opt(r.sidecar.as_ref().err().cloned()),
        r.reniced.is_ok(),
        tools.join(","),
        r.verified(),
        r.tools.len(),
        r.hashed,
        r.exit_code() == EXIT_OK
    )
}

#[cfg(target_os = "freebsd")]
pub(crate) fn print_probe(args: &[String], json: bool) -> u8 {
    use hemostat_sensor_freebsd::{store, tools};

    let path = args.iter().position(|a| a == "--manifest").and_then(|i| args.get(i + 1));
    let open = |p: &std::path::Path| {
        hemostat_sensor_freebsd::saferead::open_regular(p, hemostat_sensor_freebsd::saferead::NOT_REGULAR)
    };
    let loaded = crate::vendor_manifest::load_in_place(path.map(String::as_str), &open);
    let manifest = loaded.as_ref().ok().and_then(Option::as_ref);

    let sidecar = manifest.map(|m| {
        let env = std::env::var(crate::vendor_manifest::MANIFEST_ENV).ok();
        let mpath = path.cloned().or(env).unwrap_or_default();
        let given = args.iter().position(|a| a == "--meta").and_then(|i| args.get(i + 1)).map(String::as_str);
        let meta_path = crate::vendor_manifest::meta_path_for(&mpath, given);
        crate::vendor_manifest::load_meta_in_place(&meta_path, m, &open)
    });
    let meta = sidecar.as_ref().and_then(|r| r.as_ref().ok());
    let mut sys = tools::System::new(manifest).with_meta(meta);

    let reniced = tools::renice_self(&mut sys, 10).map_err(|e| e.to_string());
    let rows = verify_tools(&mut sys);
    let (host_id, host) = match crate::identity::gather_identity_with(&mut sys) {
        Ok((id, host)) => (id.host, host),
        Err(e) => {
            eprintln!("hemostat probe: cannot read entropy for the identity: {e}");
            return EXIT_FAILED;
        }
    };
    let store = store::place(&mut sys, std::path::Path::new("/"), store::STORE_DIR).map_err(|e| e.to_string());
    let report = ProbeReport {
        manifest: loaded.as_ref().map(|m| m.as_ref().map(|m| (m.release.clone(), m.paths()))).map_err(Clone::clone),
        sidecar: match &sidecar {
            None => Ok(None),
            Some(Ok(m)) => Ok(Some(m.rows())),
            Some(Err(e)) => Err(e.clone()),
        },
        tools: rows,
        host_id,
        host,
        store,
        reniced,
        hashed: sys.hashed(),
    };
    if json {
        jprintln!("{}", render_probe_json(&report));
    } else {
        print!("{}", render_probe(&report));
    }
    report.exit_code()
}

#[derive(Debug, Clone)]
pub(crate) struct SealedAt {
    pub(crate) dir: String,
    pub(crate) seal_pub: [u8; 32],
    pub(crate) records: usize,
    pub(crate) bytes: u64,
}

#[derive(Debug, Clone)]
pub(crate) struct PostureView {

    pub(crate) manifest: (String, usize),
    pub(crate) sealed: SealedAt,
    pub(crate) report: hemostat_sensor_freebsd::posture::Report,
    pub(crate) reniced: Result<(), String>,
    pub(crate) hashed: u64,
}

impl PostureView {

    pub(crate) fn exit_code(&self) -> u8 {
        if self.report.complete() {
            EXIT_OK
        } else {
            EXIT_PARTIAL
        }
    }
}

pub(crate) fn render_posture(v: &PostureView) -> String {
    use hs_core::severity::Severity;
    use std::fmt::Write as _;
    let r = &v.report;
    let mut o = String::new();
    let _ = writeln!(o, "posture — what runs, listens and is loaded on this firewall (FreeBSD)");
    let _ = writeln!(
        o,
        "  manifest   {} ({} paths), signature checked against the pinned key",
        h(&v.manifest.0),
        v.manifest.1
    );
    let _ = writeln!(
        o,
        "  sealed     {} · {} records, {} KiB, sealed before any verdict and judged from the store",
        h(&v.sealed.dir),
        v.sealed.records,
        v.sealed.bytes / 1024
    );
    let _ = writeln!(o, "             seal key {} — keep it off-host", hex32(&v.sealed.seal_pub));
    let _ = writeln!(
        o,
        "  processes  {} judged ({} kernel processes have no image) · {} images, {} vendor",
        r.processes, r.kernel_processes, r.images, r.vendor_images
    );
    let _ = writeln!(o, "  listeners  {} · {} owned by a pfSense service", r.listeners, r.owned.iter().map(|o| o.addresses.len()).sum::<usize>());
    let _ = writeln!(o, "  klds       {} judged", r.klds);
    for v in &r.views {
        let _ = writeln!(o, "  views      {}", h(v));
    }
    if let Some((pid, path)) = &r.agent {
        let _ = writeln!(o, "  agent      pid {pid} ({}) is this agent, and not judged", h(path.as_deref().unwrap_or("-")));
    }
    if let Err(e) = &v.reniced {
        let _ = writeln!(o, "  priority   NOT reniced: {}", h(e));
    }
    if !r.findings.is_empty() {
        let _ = writeln!(o);
    }
    for f in &r.findings {
        let pids = if f.pids.is_empty() {
            String::new()
        } else {
            let shown: Vec<String> = f.pids.iter().take(12).map(u32::to_string).collect();
            let more = f.pids.len().saturating_sub(12);
            format!(" [pid {}{}]", shown.join(" "), if more > 0 { format!(" +{more}") } else { String::new() })
        };
        let _ = writeln!(o, "  {:<8} {:<8} {}{pids}", f.severity.tag(), f.subject.label(), h(&f.what));
        let _ = writeln!(o, "           {}", h(&f.why));
    }
    let _ = writeln!(
        o,
        "\n  {} critical · {} warn · {} note",
        r.count(Severity::Critical),
        r.count(Severity::Warn),
        r.count(Severity::Note)
    );
    for g in &r.gaps {
        let _ = writeln!(o, "  NOT JUDGED: {}", h(g));
    }
    let _ = writeln!(
        o,
        "  Not seen by this check: a kernel file replaced on disk after it was loaded (kldstat \
         gives a path, not an inode); a pidfile root wrote for a vendor image of its own; and a \
         kernel that lies to procstat, fstat or read(2) (RFC-002 §4). The cross-views compare \
         tools that reach one kernel list each: a kernel module that unlinks a process, a socket \
         or itself from that list lies to every view alike."
    );
    o
}

pub(crate) fn render_posture_json(v: &PostureView) -> String {
    use hs_core::severity::Severity;
    let r = &v.report;
    let findings: Vec<String> = r
        .findings
        .iter()
        .map(|f| {
            format!(
                "{{\"severity\":\"{}\",\"subject\":\"{}\",\"what\":\"{}\",\"why\":\"{}\",\"pids\":[{}]}}",
                f.severity.tag(),
                f.subject.label(),
                jesc(&f.what),
                jesc(&f.why),
                f.pids.iter().map(u32::to_string).collect::<Vec<_>>().join(",")
            )
        })
        .collect();
    let owned: Vec<String> = r
        .owned
        .iter()
        .map(|o| {
            format!(
                "{{\"pid\":{},\"command\":\"{}\",\"pidfile\":\"{}\",\"addresses\":[{}]}}",
                o.pid,
                jesc(&o.command),
                jesc(&o.pidfile),
                o.addresses.iter().map(|a| format!("\"{}\"", jesc(a))).collect::<Vec<_>>().join(",")
            )
        })
        .collect();
    let tools: Vec<String> = r
        .tools
        .iter()
        .map(|(s, d)| {
            format!(
                "{{\"source\":\"{}\",\"sha256\":{}}}",
                s.label(),
                d.map_or("null".to_string(), |d| format!("\"{}\"", hex32(&d)))
            )
        })
        .collect();
    let gaps: Vec<String> = r.gaps.iter().map(|g| format!("\"{}\"", jesc(g))).collect();
    let views: Vec<String> = r.views.iter().map(|g| format!("\"{}\"", jesc(g))).collect();
    let itools: Vec<String> = r
        .integrity_tools
        .iter()
        .map(|(p, d)| format!("{{\"path\":\"{}\",\"sha256\":\"{}\"}}", jesc(p), jesc(d)))
        .collect();
    let agent = r.agent.as_ref().map_or("null".to_string(), |(pid, path)| {
        format!("{{\"pid\":{pid},\"path\":{}}}", path.as_ref().map_or("null".to_string(), |p| format!("\"{}\"", jesc(p))))
    });
    format!(
        "{{\"manifest\":{{\"release\":\"{}\",\"paths\":{}}},\"store\":{{\"dir\":\"{}\",\"seal_pub\":\"{}\",\
         \"records\":{},\"bytes\":{}}},\"processes\":{},\"kernel_processes\":{},\"images\":{},\
         \"vendor_images\":{},\"listeners\":{},\"klds\":{},\"agent\":{agent},\"critical\":{},\"warn\":{},\
         \"note\":{},\"findings\":[{}],\"owned\":[{}],\"tools\":[{}],\"views\":[{}],\"integrity_tools\":[{}],\
         \"gaps\":[{}],\"reniced\":{},\"hashed_bytes\":{},\"complete\":{}}}",
        jesc(&v.manifest.0),
        v.manifest.1,
        jesc(&v.sealed.dir),
        hex32(&v.sealed.seal_pub),
        v.sealed.records,
        v.sealed.bytes,
        r.processes,
        r.kernel_processes,
        r.images,
        r.vendor_images,
        r.listeners,
        r.klds,
        r.count(Severity::Critical),
        r.count(Severity::Warn),
        r.count(Severity::Note),
        findings.join(","),
        owned.join(","),
        tools.join(","),
        views.join(","),
        itools.join(","),
        gaps.join(","),
        v.reniced.is_ok(),
        v.hashed,
        r.complete()
    )
}

#[cfg(target_os = "freebsd")]
pub(crate) fn print_posture_sweep(args: &[String], json: bool) -> u8 {
    use hemostat_sensor_freebsd::{posture, saferead, store, tools};

    let path = args.iter().position(|a| a == "--manifest").and_then(|i| args.get(i + 1));
    let open = |p: &std::path::Path| saferead::open_regular(p, saferead::NOT_REGULAR);
    let manifest = match crate::vendor_manifest::load_in_place(path.map(String::as_str), &open) {
        Ok(Some(m)) => m,
        Ok(None) => {
            eprintln!(
                "hemostat posture: no manifest. Pass --manifest PATH (PATH.sig beside it) or set \
                 $HEMOSTAT_MANIFEST, with the key in $HEMOSTAT_MANIFEST_PUBKEY: without one no tool \
                 can be verified and no image judged"
            );
            return EXIT_PARTIAL;
        }
        Err(e) => {
            eprintln!("hemostat posture: manifest refused: {}", h(&e));
            return EXIT_FAILED;
        }
    };
    let mut sys = tools::System::new(Some(&manifest));
    let reniced = tools::renice_self(&mut sys, 10).map_err(|e| e.to_string());
    let (id, _) = match crate::identity::gather_identity_with(&mut sys) {
        Ok(x) => x,
        Err(e) => {
            eprintln!("hemostat posture: cannot read entropy for the identity: {e}");
            return EXIT_FAILED;
        }
    };
    let st = match store::Store::open(&mut sys, std::path::Path::new("/")) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("hemostat posture: nowhere to seal the evidence, so nothing is judged: {}", h(&e.to_string()));
            return EXIT_PARTIAL;
        }
    };
    let mut throttle = saferead::Throttle::new(saferead::HASH_BYTES_PER_SEC);
    let mut raw = posture::collect(&mut sys, std::path::Path::new("/"), &mut throttle, std::process::id());

    let held: u64 = raw.records().iter().map(|r| r.len() as u64).sum();
    let room = st.room().saturating_sub(held).saturating_sub(64 * 1024);
    raw.integrity = Some(hemostat_sensor_freebsd::integrity::collect_within(&mut sys, std::path::Path::new("/"), room));

    let total: u64 = raw.records().iter().map(|r| r.len() as u64).sum();
    let over = total.saturating_sub(st.room().saturating_sub(64 * 1024));
    if let Some(ev) = raw.integrity.as_mut().filter(|_| over > 0) {
        let own = u64::try_from(ev.size()).unwrap_or(u64::MAX);
        ev.shed_to(own.saturating_sub(over));
    }
    let records = raw.records();
    drop(raw);

    let secs = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs());
    let (tag, seed) = match (crate::identity::rand16(), crate::identity::rand32()) {
        (Ok(t), Ok(s)) => (t, s),
        (Err(e), _) | (_, Err(e)) => {
            eprintln!("hemostat posture: no entropy for the store: {e}");
            return EXIT_FAILED;
        }
    };
    let tag: String = tag.iter().take(4).map(|b| format!("{b:02x}")).collect();
    let dir = st.path().join(format!("posture-{secs}-{tag}")).display().to_string();
    let bytes: u64 = records.iter().map(|r| r.len() as u64).sum();
    if let Err(e) = st.admit(bytes + 64 * 1024) {
        eprintln!("hemostat posture: {}; nothing is judged", h(&e.to_string()));
        return EXIT_PARTIAL;
    }
    let ids = crate::freebsd_drift::Ids {
        engagement: id.engagement,
        host: id.host,
        agent: id.agent,
        instance: id.instance,
        run: id.run_id,
        boot: id.boot,
    };
    let sealed = match crate::freebsd_drift::seal(&dir, seed, &records, &ids) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("hemostat posture: could not seal the evidence, so nothing is judged: {}", h(&e));
            return EXIT_FAILED;
        }
    };
    let count = records.len();
    drop(records);

    let judged = crate::freebsd_drift::open(&dir, Some(sealed.seal_pub))
        .and_then(|o| posture::Raw::from_records(o.records.iter().map(Vec::as_slice)));
    let raw = match judged {
        Ok(r) => r,
        Err(e) => {
            eprintln!("hemostat posture: the store at {} did not read back ({}); nothing is judged", h(&dir), h(&e));
            return EXIT_FAILED;
        }
    };
    let view = PostureView {
        manifest: (manifest.release.clone(), manifest.paths()),
        sealed: SealedAt { dir, seal_pub: sealed.seal_pub, records: count, bytes },
        report: posture::judge(&raw, &manifest),
        reniced,
        hashed: sys.hashed() + throttle.bytes(),
    };
    if json {
        jprintln!("{}", render_posture_json(&view));
    } else {
        print!("{}", render_posture(&view));
    }
    view.exit_code()
}

pub(crate) struct VendorReport {
    pub(crate) release: String,
    pub(crate) paths: usize,
    pub(crate) provenance: Vec<(&'static str, usize)>,
    pub(crate) image: Option<String>,
    pub(crate) report: hemostat_sensor_freebsd::grade::Report,
    pub(crate) bytes: u64,
    pub(crate) seconds: u64,

    pub(crate) sealed: SealedAt,
}

impl VendorReport {

    pub(crate) fn exit_code(&self) -> u8 {
        if self.report.complete() {
            EXIT_OK
        } else {
            EXIT_PARTIAL
        }
    }
}

pub(crate) fn render_vendor(v: &VendorReport) -> String {
    use hs_core::severity::Severity;
    use std::fmt::Write as _;
    let r = &v.report;
    let mut o = String::new();
    let _ = writeln!(o, "vendor — this firewall's files against the {} manifest (FreeBSD)", h(&v.release));
    let _ = writeln!(o, "  manifest  {} ({} paths), signature checked against the pinned key", h(&v.release), v.paths);
    let prov = v.provenance.iter().map(|(k, n)| format!("{n} {k}")).collect::<Vec<_>>().join(" + ");
    let _ = writeln!(o, "  sidecar   bound to it; digests {prov}");
    if let Some(img) = &v.image {
        let _ = writeln!(o, "  image     {}", h(img));
    }
    let _ = writeln!(
        o,
        "  sealed    {} · {} records, {} KiB, seal key {} · sealed before any verdict and judged from the store",
        h(&v.sealed.dir),
        v.sealed.records,
        v.sealed.bytes / 1024,
        hex32(&v.sealed.seal_pub)
    );
    let _ = writeln!(
        o,
        "  walked    {} entries under {} · hashed {} files ({} MiB, paced to 32 MiB/s) in {} s",
        r.walked,
        hemostat_sensor_freebsd::walk::ROOTS.join(" "),
        r.hashed,
        v.bytes / (1024 * 1024),
        v.seconds
    );
    let m = |k: &str| r.matched.get(k).copied().unwrap_or(0);
    let _ = writeln!(
        o,
        "  matched   {} repo-signed, {} iso-pinned only · {} vendor files absent · {} unlisted files elsewhere · \
         {} with another mode or owner",
        m("repo-signed") + m("iso-signed"),
        m("iso-pinned"),
        r.absent,
        r.unlisted,
        r.metadata_differs
    );
    let _ = writeln!(o);
    if r.findings.is_empty() {
        let _ = writeln!(o, "  every file under the roots is one a vendor source shipped, and nothing else is there.");
    } else {
        let _ = writeln!(o, "  {:<9} {:<44} WHAT", "GRADE", "PATH");
        for f in &r.findings {
            let _ = writeln!(o, "  {:<9} {:<44} {}", f.severity.tag(), h(&f.path), h(&f.what));
            let _ = writeln!(o, "  {:<9} {:<44} {}", "", "", h(&f.detail));
        }
    }
    let _ = writeln!(
        o,
        "\n  {} critical · {} warn · {} note",
        r.count(Severity::Critical),
        r.count(Severity::Warn),
        r.count(Severity::Note)
    );
    for g in &r.gaps {
        let _ = writeln!(o, "  NOT SEEN  {}", h(g));
    }
    let _ = writeln!(
        o,
        "  Not seen by this check: a kernel that serves clean bytes to read(2) and executes others; and the \
         contents of files pfSense rewrites from config.xml, which the config sweeps judge (RFC-002 §2, §4)."
    );
    o
}

pub(crate) fn render_vendor_json(v: &VendorReport) -> String {
    let r = &v.report;
    let findings = r
        .findings
        .iter()
        .map(|f| {
            format!(
                "{{\"severity\":\"{}\",\"path\":\"{}\",\"what\":\"{}\",\"detail\":\"{}\"}}",
                f.severity.tag().to_ascii_lowercase(),
                jesc(&f.path),
                jesc(&f.what),
                jesc(&f.detail)
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    let iso = r
        .iso_only
        .iter()
        .map(|(p, f)| format!("[\"{}\",\"{}\"]", jesc(p), jesc(f)))
        .collect::<Vec<_>>()
        .join(",");
    let matched = r.matched.iter().map(|(k, n)| format!("\"{k}\":{n}")).collect::<Vec<_>>().join(",");
    let gaps = r.gaps.iter().map(|g| format!("\"{}\"", jesc(g))).collect::<Vec<_>>().join(",");
    format!(
        "{{\"release\":\"{}\",\"paths\":{},\"walked\":{},\"hashed\":{},\"bytes\":{},\"matched\":{{{matched}}},\
         \"absent\":{},\"unlisted\":{},\"metadata_differs\":{},\"findings\":[{findings}],\"iso_only\":[{iso}],\
         \"gaps\":[{gaps}],\"complete\":{},\"sealed\":{{\"dir\":\"{}\",\"seal_pub\":\"{}\",\"records\":{}}}}}",
        jesc(&v.release),
        v.paths,
        r.walked,
        r.hashed,
        v.bytes,
        r.absent,
        r.unlisted,
        r.metadata_differs,
        r.complete(),
        jesc(&v.sealed.dir),
        hex32(&v.sealed.seal_pub),
        v.sealed.records
    )
}

#[cfg(target_os = "freebsd")]
pub(crate) fn print_vendor(args: &[String], json: bool) -> u8 {
    use hemostat_sensor_freebsd::{grade, saferead, store, tools};

    let open = |p: &std::path::Path| saferead::open_regular(p, saferead::NOT_REGULAR);
    let flag = |f: &str| args.iter().position(|a| a == f).and_then(|i| args.get(i + 1)).map(String::as_str);
    let manifest = match crate::vendor_manifest::load_in_place(flag("--manifest"), &open) {
        Ok(Some(m)) => m,
        Ok(None) => {
            eprintln!(
                "hemostat vendor: no manifest. Pass --manifest PATH (PATH.sig and its sidecar beside it) or set \
                 ${}",
                crate::vendor_manifest::MANIFEST_ENV
            );
            return EXIT_FAILED;
        }
        Err(e) => {
            eprintln!("hemostat vendor: {}", h(&e));
            return EXIT_FAILED;
        }
    };
    let env = std::env::var(crate::vendor_manifest::MANIFEST_ENV).ok();
    let mpath = flag("--manifest").map(str::to_string).or(env).unwrap_or_default();
    let meta_path = crate::vendor_manifest::meta_path_for(&mpath, flag("--meta"));
    let meta = match crate::vendor_manifest::load_meta_in_place(&meta_path, &manifest, &open) {
        Ok(m) => m,
        Err(e) => {
            eprintln!(
                "hemostat vendor: {} — the sidecar says where each digest came from, and without it nothing \
                 here can be graded",
                h(&e)
            );
            return EXIT_FAILED;
        }
    };

    let mut sys = tools::System::new(Some(&manifest));
    if let Err(e) = tools::renice_self(&mut sys, 10) {
        eprintln!("hemostat vendor: NOTE: not reniced ({e}); hashing at the paced rate anyway");
    }
    let (id, _) = match crate::identity::gather_identity_with(&mut sys) {
        Ok(x) => x,
        Err(e) => {
            eprintln!("hemostat vendor: cannot read entropy for the identity: {e}");
            return EXIT_FAILED;
        }
    };
    let st = match store::Store::open(&mut sys, std::path::Path::new("/")) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("hemostat vendor: nowhere to seal the evidence, so nothing is judged: {}", h(&e.to_string()));
            return EXIT_PARTIAL;
        }
    };
    if let Err(e) = st.admit(grade::MAX_RECORD_BYTES + 64 * 1024) {
        eprintln!("hemostat vendor: {}; nothing is judged", h(&e.to_string()));
        return EXIT_PARTIAL;
    }
    let secs = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs());
    let (tag, seed) = match (crate::identity::rand16(), crate::identity::rand32()) {
        (Ok(t), Ok(s)) => (t, s),
        (Err(e), _) | (_, Err(e)) => {
            eprintln!("hemostat vendor: no entropy for the store: {e}");
            return EXIT_FAILED;
        }
    };
    let tag: String = tag.iter().take(4).map(|b| format!("{b:02x}")).collect();
    let dir = st.path().join(format!("vendor-{secs}-{tag}")).display().to_string();
    let ids = crate::freebsd_drift::Ids {
        engagement: id.engagement,
        host: id.host,
        agent: id.agent,
        instance: id.instance,
        run: id.run_id,
        boot: id.boot,
    };
    let started = std::time::Instant::now();
    let mut collector = grade::Collector::new(
        std::path::Path::new("/"),
        &manifest,
        &meta,
        saferead::Throttle::new(saferead::HASH_BYTES_PER_SEC),
        grade::MAX_RECORD_BYTES,
    );
    let mut count = 0usize;
    let sealed = match crate::freebsd_drift::seal(&dir, seed, collector.by_ref().inspect(|_| count += 1), &ids) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("hemostat vendor: could not seal the evidence, so nothing is judged: {}", h(&e));
            return EXIT_FAILED;
        }
    };
    let (bytes, record_bytes) = (collector.hashed_bytes(), collector.record_bytes());
    drop(collector);

    let report = crate::freebsd_drift::open(&dir, Some(sealed.seal_pub))
        .and_then(|o| grade::judge_records(o.records.iter().map(Vec::as_slice), &manifest, &meta));
    let report = match report {
        Ok(r) => r,
        Err(e) => {
            eprintln!("hemostat vendor: the store at {} did not read back ({}); nothing is judged", h(&dir), h(&e));
            return EXIT_FAILED;
        }
    };
    let v = VendorReport {
        release: manifest.release.clone(),
        paths: manifest.paths(),
        provenance: meta.provenance_counts().iter().map(|(p, n)| (p.label(), *n)).collect(),
        image: meta.isos.first().map(|i| format!("{} sha256 {} ({})", i.name, hex32(&i.sha256), i.how)),
        report,
        bytes,
        seconds: started.elapsed().as_secs(),
        sealed: SealedAt { dir, seal_pub: sealed.seal_pub, records: count, bytes: record_bytes },
    };
    if json {
        jprintln!("{}", render_vendor_json(&v));
    } else {
        print!("{}", render_vendor(&v));
    }
    v.exit_code()
}
