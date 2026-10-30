use std::path::Path;

use hemostat_sensor_linux::persist::{Category, Report as PersistReport, CATALOGUE};
use hemostat_sensor_linux::triage::{Finding, Severity};

use crate::{PersistKind, ProtectSet, RemovalAction};

const AUTH_ADVICE: &str = "authentication surface — removing it can lock you out as easily as the \
                           attacker, and a legitimate account looks identical. Review it by hand; \
                           to remove one line you have chosen, `hemostat remediate --lines <file>` \
                           lists them and `--strip-line <token> --auth` takes one out.";

const SHARED_FILE_ADVICE: &str = "a shared configuration file: the entry is a line inside it, so \
                                  removing the file would take the host's own configuration with \
                                  it. Read it and take the one line out: `hemostat remediate \
                                  --lines <file>` lists them, `--strip-line <token>` removes one.";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Disposition {

    Remove(RemovalAction),

    Advise(&'static str),

    Nothing,
}

impl Disposition {

    pub fn is_actionable(&self) -> bool {
        matches!(self, Disposition::Remove(_))
    }
}

#[derive(Debug, Clone)]
pub struct Candidate {

    pub mechanism: String,

    pub locus: String,

    pub severity: Severity,

    pub what: String,

    pub disposition: Disposition,
}

fn kind_for(mech_id: &str, category: &Category, name: &str) -> PersistKind {
    if mech_id.starts_with("systemd") {
        return PersistKind::SystemdUnit;
    }
    match category {
        Category::Scheduled => PersistKind::Cron,
        Category::Service => PersistKind::SystemdUnit,
        Category::Login => PersistKind::ShellInit,
        _ => PersistKind::Other(name.to_string()),
    }
}

const HOST_NETWORK_ADVICE: &str =
    "this belongs to a unit that brings the host's network up (networking, systemd-networkd, \
     NetworkManager, network, systemd-resolved, wicked, ifup@): its unit file, a file named for \
     it, or a drop-in of it. Stopping, disabling or masking that unit, or moving the file away, \
     takes the host off the network, and every scored service and remote session with it — so \
     nothing is offered here and every unit action refuses it. Read the file, and change it by \
     hand from a console that does not need the network.";

const ENABLEMENT_LINK_ADVICE: &str =
    "this is an enablement link, not the persistence itself: it only switches on the unit it \
     names, and the sweep judged it by reading through to that unit's text. Look at the unit \
     file — removing the link disables the unit at the next boot and changes nothing else.";

const UNIT_SUFFIXES: &[&str] = &[
    ".service", ".timer", ".socket", ".path", ".mount", ".automount", ".target",
];

fn unit_name(path: &Path) -> Option<String> {
    if !directly_in_unit_dir(path) {
        return None;
    }
    let name = path.file_name()?.to_str()?;
    UNIT_SUFFIXES
        .iter()
        .any(|s| name.ends_with(s))
        .then(|| name.to_string())
}

pub(crate) fn directly_in_unit_dir(path: &Path) -> bool {
    let Some(dir) = path.parent() else { return false };
    dir.file_name().is_some_and(|n| n == "system")
        && dir.parent().and_then(Path::file_name).is_some_and(|n| n == "systemd")
}

pub(crate) fn unit_file_refusal(unit: &str, path: &Path) -> Option<String> {
    if let Some(why) = unit_file_shape_refusal(unit, path) {
        return Some(why);
    }
    match fragment_path(unit) {
        Ok(fragment) => fragment_refusal(unit, path, fragment.as_deref()),
        Err(why) => Some(why),
    }
}

pub(crate) fn unit_file_shape_refusal(unit: &str, path: &Path) -> Option<String> {
    if !directly_in_unit_dir(path) {
        return Some(format!(
            "{} is not directly in a systemd unit directory — systemd loads no unit from a \
             drop-in (`*.d/`), an enablement directory (`*.wants/`, `*.requires/`) or any other \
             subdirectory, so it is not where `{unit}` is defined",
            path.display()
        ));
    }
    if path.file_name().and_then(|n| n.to_str()) != Some(unit) {
        return Some(format!("{} is not named `{unit}`, so it is not that unit's file", path.display()));
    }
    None
}

pub(crate) fn fragment_refusal(unit: &str, path: &Path, fragment: Option<&Path>) -> Option<String> {
    let Some(fragment) = fragment else {
        return Some(format!(
            "systemd reports no FragmentPath for `{unit}`: it has not loaded {} as that unit, so \
             stopping `{unit}` would act on something else, or on nothing. If the file is inert, \
             move it aside by hand",
            path.display()
        ));
    };
    let (Some(ours), Some(theirs)) =
        (crate::paths::canonical_parent(path), crate::paths::canonical_parent(fragment))
    else {
        return Some(format!(
            "{} and `{unit}`'s FragmentPath {} could not both be resolved to compare them",
            path.display(),
            fragment.display()
        ));
    };
    if ours != theirs {
        return Some(format!(
            "systemd loads `{unit}` from {}, not from {} — stopping it would stop the unit that \
             file defines, which this finding is not about",
            fragment.display(),
            path.display()
        ));
    }
    None
}

fn fragment_path(unit: &str) -> Result<Option<std::path::PathBuf>, String> {
    let Some(systemctl) = crate::resolve_tool(&["/usr/bin/systemctl", "/bin/systemctl"]) else {
        return Err(format!(
            "systemctl not found at /usr/bin or /bin, so which file systemd loaded `{unit}` from \
             cannot be asked"
        ));
    };
    let out = hemostat_sensor_linux::services::show_within(&systemctl, &["--property=FragmentPath", "--", unit])
        .map_err(|why| format!("{why}, so which file systemd loaded `{unit}` from is not known"))?;
    if !out.status.success() {
        return Err(format!(
            "`systemctl show --property=FragmentPath {unit}` failed ({}), so which file systemd \
             loaded it from is not known",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout)
        .lines()
        .find_map(|l| l.strip_prefix("FragmentPath="))
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .map(std::path::PathBuf::from))
}

const VENDOR_FILE_ADVICE: &str =
    "this file belongs to a distribution package, not to whoever administers this host — the \
     directories under /usr are the package manager's, and /etc is the administrator's. Two \
     things follow. Quarantining it does not remove the persistence durably, because the next \
     time that package is installed or verified the file comes back; and a stock rule that \
     merely looks like a command is exactly what lives here (NetworkManager's udev rules run \
     `sh -c` on every interface, and they are not an implant). Ask the package manager whether \
     the file still matches what it shipped — `pacman -Qkk`, `rpm -V`, `dpkg -V` — and if it \
     does not, reinstall the package rather than deleting the file.";

fn is_vendor_path(path: &Path) -> bool {
    let s = path.to_string_lossy();
    s.starts_with("/usr/") || s.starts_with("/lib/") || s.starts_with("/bin/") || s.starts_with("/sbin/")
}

fn is_vendor_unit(path: &Path) -> bool {
    let s = path.to_string_lossy();
    s.starts_with("/usr/lib/") || s.starts_with("/lib/")
}

fn in_system_unit_dir(path: &Path) -> bool {
    path.to_string_lossy().contains("/systemd/system/")
}

const RUNLEVEL_LINK_ADVICE: &str =
    "this is an OpenRC runlevel link, not the persistence itself: it only switches on the \
     service it names, and the sweep judged it by reading through to that service's script. \
     Look at the script — removing the link disables the service at the next boot and changes \
     nothing else.";

const SSH_SERVICE_ADVICE: &str =
    "this is the ssh service's own script or definition. Removing it does not stop sshd now, \
     so the run reports success — and sshd does not come back at its next restart or the next \
     boot, which cuts off the way you are reaching this host. Read it and edit the added line \
     out by hand.";

fn is_ssh_service_file(mech_id: &str, path: &Path) -> bool {
    matches!(mech_id, "init-d" | "openrc-services" | "runit-services" | "s6-services")
        && path
            .iter()
            .filter_map(|c| c.to_str())
            .any(crate::guards::unit_is_ssh)
}

const TABLE_ADVICE: &str =
    "one account's whole table: every job it schedules is a line in this one file, so removing \
     it stops all of them along with the attacker's. Take the one line out instead: `hemostat \
     remediate --lines <file>` lists them and `--strip-line <token>` removes one.";

fn is_per_user_table(mech_id: &str, path: &Path) -> bool {
    match mech_id {
        "cron-user" => path.starts_with("/var/spool/cron"),
        "incron" => path.starts_with("/var/spool/incron"),
        _ => false,
    }
}

const PACKAGED_FILE_ADVICE: &str =
    "a package installed this file: it is a stock script or config in a directory that also \
     takes drop-ins, so the finding is a line added to it rather than a file somebody dropped. \
     Removing it takes the stock behaviour with it — without /etc/grub.d/10_linux the next \
     `update-grub` writes a boot menu with no kernels, and a package does not put back a \
     configuration file it finds deleted. Compare it with what was shipped (`dpkg -V`, `rpm -V`, \
     `pacman -Qkk`), then take the added line out (`hemostat remediate --lines <file>`, \
     `--strip-line <token>`), or reinstall the package.";

fn package_owns(path: &Path) -> bool {
    hemostat_sensor_linux::pkg::manager().is_some_and(|m| m.owns(path))
}

fn is_enablement_link(path: &Path) -> bool {
    path.parent()
        .and_then(Path::file_name)
        .and_then(|n| n.to_str())
        .is_some_and(|n| n.ends_with(".wants") || n.ends_with(".requires"))
}

pub fn disposition_with(
    mech_id: &str,
    locus: &str,
    severity: Severity,
    exists: impl Fn(&Path) -> bool,
    packaged: impl Fn(&Path) -> bool,
) -> Disposition {

    if severity < Severity::Warn {
        return Disposition::Nothing;
    }
    let Some(mech) = CATALOGUE.iter().find(|m| m.id == mech_id) else {
        return Disposition::Nothing;
    };

    if matches!(mech.category, Category::Auth) {
        return Disposition::Advise(AUTH_ADVICE);
    }
    let path = Path::new(locus);

    if !path.is_absolute() || !exists(path) {
        return Disposition::Nothing;
    }

    if mech_id == "ld-preload" {
        return Disposition::Remove(RemovalAction::RemoveLdPreload {
            path: path.to_path_buf(),
            entry: None,
        });
    }

    if is_ssh_service_file(mech_id, path) {
        return Disposition::Advise(SSH_SERVICE_ADVICE);
    }
    if path.starts_with("/etc/runlevels") {
        return Disposition::Advise(RUNLEVEL_LINK_ADVICE);
    }

    if in_system_unit_dir(path) {
        if is_enablement_link(path) {
            return Disposition::Advise(ENABLEMENT_LINK_ADVICE);
        }

        if crate::guards::host_network_unit_of(path).is_some() {
            return Disposition::Advise(HOST_NETWORK_ADVICE);
        }
        if let Some(unit) = unit_name(path) {

            return Disposition::Remove(if is_vendor_unit(path) {
                RemovalAction::MaskService { unit }
            } else {
                RemovalAction::StopAndRemoveUnit { unit, path: path.to_path_buf() }
            });
        }
    }

    if !mech.entry_is_its_own_file(path) {
        return Disposition::Advise(SHARED_FILE_ADVICE);
    }
    if is_per_user_table(mech_id, path) {
        return Disposition::Advise(TABLE_ADVICE);
    }

    if is_vendor_path(path) {
        return Disposition::Advise(VENDOR_FILE_ADVICE);
    }

    if packaged(path) {
        return Disposition::Advise(PACKAGED_FILE_ADVICE);
    }
    Disposition::Remove(RemovalAction::DisablePersistence {
        path: path.to_path_buf(),
        kind: kind_for(mech_id, &mech.category, mech.name),
    })
}

pub fn disposition(finding: &Finding) -> Disposition {
    disposition_on_host(&finding.subject, &finding.locus, finding.severity)
}

pub fn disposition_on_host(mech_id: &str, locus: &str, severity: Severity) -> Disposition {
    disposition_with(mech_id, locus, severity, |p| p.exists(), package_owns)
}

fn weight(d: &Disposition) -> u8 {
    match d {
        Disposition::Remove(_) => 2,
        Disposition::Advise(_) => 1,
        Disposition::Nothing => 0,
    }
}

pub fn plan(report: &PersistReport) -> Vec<Candidate> {
    let mut out: Vec<Candidate> = Vec::with_capacity(report.findings.len());
    for f in &report.findings {
        let c = Candidate {
            mechanism: f.subject.clone(),
            locus: f.locus.clone(),
            severity: f.severity,
            what: f.what.clone(),
            disposition: disposition(f),
        };
        match out.iter_mut().find(|k| k.locus == c.locus) {

            Some(kept) if weight(&c.disposition) > weight(&kept.disposition) => *kept = c,
            Some(_) => {}
            None => out.push(c),
        }
    }
    out
}

pub const SCORED_UNIT_ADVICE: &str =
    "this belongs to a unit that runs the packet's scored service on this box (HEMOSTAT_GOLDEN): \
     its unit file, an alias of it, or a drop-in of it. Masking, stopping or disabling that unit, \
     or moving the file away, takes the service down, and while it is down nothing else protects \
     it — so nothing is offered here and every unit action refuses it. Fix it by hand and keep \
     the service up: restore a packaged unit from its package (`rpm -V` or `dpkg -V` names what \
     differs; `dnf reinstall` or `apt-get install --reinstall` of the package that owns it puts \
     the shipped file back), or take an added drop-in or line out with an editor; then \
     `systemctl daemon-reload`, and `services --restore --arm` brings the service back if it is \
     down.";

pub fn hold_scored(candidates: Vec<Candidate>, protect: &ProtectSet) -> Vec<Candidate> {
    candidates
        .into_iter()
        .map(|mut c| {
            if removes_held_scored(&c.disposition, &c.locus, protect) {
                c.disposition = Disposition::Advise(SCORED_UNIT_ADVICE);
            }
            c
        })
        .collect()
}

fn removes_held_scored(d: &Disposition, locus: &str, protect: &ProtectSet) -> bool {
    let Disposition::Remove(action) = d else { return false };
    let unit = match action {
        RemovalAction::MaskService { unit } | RemovalAction::StopAndRemoveUnit { unit, .. } => Some(unit.as_str()),
        _ => None,
    };
    unit.is_some_and(|u| protect.scored_service(u).is_some())
        || protect.scored_service_of_path(Path::new(locus)).is_some()
}
