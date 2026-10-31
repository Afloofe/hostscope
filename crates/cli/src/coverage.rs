#[cfg(any(target_os = "linux", target_os = "windows"))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Covered {

    Fully,

    NotAtAll(String),

    InPart(String),
}

#[cfg(any(target_os = "linux", target_os = "windows"))]
impl Covered {

    #[cfg(target_os = "linux")]
    pub(crate) fn gap(&self) -> Option<&str> {
        match self {
            Covered::Fully => None,
            Covered::NotAtAll(why) | Covered::InPart(why) => Some(why),
        }
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn ran(&self) -> bool {
        !matches!(self, Covered::NotAtAll(_))
    }

    pub(crate) fn exit_code(&self) -> u8 {
        match self {
            Covered::Fully => crate::EXIT_OK,
            Covered::NotAtAll(_) | Covered::InPart(_) => crate::EXIT_PARTIAL,
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "windows"))]
pub(crate) fn probe(unreadable: &[&str]) -> Covered {
    if unreadable.is_empty() {
        Covered::Fully
    } else {
        Covered::InPart(format!(
            "{} reading(s) could not be taken, so they are unchecked rather than off: {}",
            unreadable.len(),
            unreadable.join(", ")
        ))
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn linux_probe_unread(r: &hemostat_sensor_linux::probe::TierReport) -> Vec<&'static str> {
    if r.capabilities_known { Vec::new() } else { vec!["/proc/self/status (the process's capabilities)"] }
}

#[cfg(target_os = "linux")]
pub(crate) fn from_flag(available: bool, reason: &Option<String>) -> Covered {
    if available {
        Covered::Fully
    } else {
        Covered::NotAtAll(
            reason.clone().unwrap_or_else(|| "no reason given by the sensor".to_string()),
        )
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn trust(r: &hemostat_sensor_linux::trust::Report) -> Covered {
    if !r.available {
        return Covered::NotAtAll(r.reason.clone().unwrap_or_else(|| "no trust store was read".into()));
    }
    if r.unread.is_empty() {
        Covered::Fully
    } else {
        Covered::InPart(format!("{} part(s) of the trust store could not be read: {}", r.unread.len(), r.unread.join("; ")))
    }
}

#[cfg(all(target_os = "linux", feature = "mod-tui"))]
pub(crate) fn trust_against_arrival(r: &hemostat_sensor_linux::trust::Report, refused: Option<&str>) -> Covered {
    let Some(why) = refused else { return trust(r) };
    let arrival = format!(
        "{why}; no anchor was compared with arrival, so a CA added since that can sign for any name \
         may show as WARN, not the CRITICAL an added one is"
    );
    match trust(r) {
        Covered::Fully => Covered::InPart(arrival),
        Covered::InPart(part) => Covered::InPart(format!("{part}; {arrival}")),
        Covered::NotAtAll(none) => Covered::NotAtAll(format!("{none}; {arrival}")),
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn accounts(r: &hemostat_sensor_linux::AccountReport) -> Covered {
    match (r.available, r.unread.is_empty()) {
        (false, _) => Covered::NotAtAll(
            r.reason.clone().unwrap_or_else(|| "/etc/passwd would not read".into()),
        ),
        (true, false) => Covered::InPart(format!("could not read {}", r.unread.join(", "))),
        (true, true) => Covered::Fully,
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn overview(r: &hemostat_sensor_linux::OverviewReport) -> Covered {
    if r.unread_tables.is_empty() {
        Covered::Fully
    } else {
        Covered::InPart(format!(
            "{} of the /proc/net socket tables would not open: {}",
            r.unread_tables.len(),
            r.unread_tables.join(", ")
        ))
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn persistence(r: &hemostat_sensor_linux::PersistReport) -> Covered {
    if r.established == 0 {
        Covered::NotAtAll("not one mechanism in the catalogue could be established".into())
    } else if r.established < r.total {
        Covered::InPart(format!(
            "{} of {} mechanisms could not be read in full",
            r.total - r.established,
            r.total
        ))
    } else {
        Covered::Fully
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn enablement(r: &hemostat_sensor_linux::enablement::Report) -> Covered {
    if r.other_init.is_some() {
        return Covered::Fully;
    }
    match (r.available, &r.reason) {
        (false, _) => from_flag(false, &r.reason),
        (true, Some(why)) => Covered::InPart(why.clone()),
        (true, None) => Covered::Fully,
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn injected(r: &hemostat_sensor_linux::HookedReport) -> Covered {
    if r.examined == 0 {
        return Covered::NotAtAll(
            "no process could be examined, so nothing was checked for an injected mark".into(),
        );
    }
    let n = r.examined;
    let mut gaps = Vec::new();
    if r.unreadable > 0 {
        gaps.push(format!(
            "{} of {n} process(es) could not be read — an implant in one of those is not in \
             this report",
            r.unreadable
        ));
    }
    if r.maps_unreadable > 0 {
        gaps.push(format!(
            "{} of {n} memory map(s) refused, so the unexpected-library, anonymous-code and \
             memfd checks did not run on them",
            r.maps_unreadable
        ));
    }

    if r.maps_capped > 0 {
        gaps.push(format!(
            "{} of {n} memory map(s) were over the read cap and examined only in part, so a \
             library or memfd mapped past it is not in this report",
            r.maps_capped
        ));
    }
    if r.env_unreadable > 0 {
        gaps.push(format!(
            "{} of {n} environment(s) refused, so the LD_PRELOAD and LD_AUDIT checks did not \
             run on them",
            r.env_unreadable
        ));
    }

    if r.mounted_over > 0 {
        gaps.push(format!(
            "{} of {n} process(es) have something mounted over a file the kernel serves for them, \
             which was not read — the proc-mount finding names them",
            r.mounted_over
        ));
    }
    if gaps.is_empty() {
        Covered::Fully
    } else {
        Covered::InPart(gaps.join("; "))
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn kwalk(r: &hemostat_sensor_linux::KwalkReport) -> Covered {
    if !r.available {
        from_flag(false, &r.reason)
    } else if r.gaps.is_empty() {
        Covered::Fully
    } else {
        Covered::InPart(r.gaps.join("; "))
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn kground(r: &hemostat_sensor_linux::KgroundReport) -> Covered {
    use hemostat_sensor_linux::Coverage;
    match r.coverage {
        Coverage::Unreadable => Covered::NotAtAll(
            r.reason.clone().unwrap_or_else(|| "the kernel task iterator could not run".into()),
        ),
        Coverage::Partial => Covered::InPart(
            r.reason.clone().unwrap_or_else(|| "part of the cross-view did not run".into()),
        ),
        Coverage::Clean | Coverage::Populated | Coverage::NotPresent => Covered::Fully,
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn kernel_posture(r: &hemostat_sensor_linux::KernPostureReport) -> Covered {
    if r.privileged {
        Covered::Fully
    } else {
        Covered::InPart(
            "not run as root: whether a module can load and whether this agent is being \
             blinded were not judged"
                .into(),
        )
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn rootkit(r: &hemostat_sensor_linux::RootkitReport) -> Covered {
    if !r.cross_view_ran {
        Covered::NotAtAll(
            "the hidden-process cross-view could not list /proc, so no stat-vs-readdir \
             comparison was made"
                .into(),
        )
    } else if r.did_not_run.is_empty() {
        Covered::Fully
    } else {
        Covered::InPart(format!(
            "{} rootkit sub-scan(s) did not run in full: {}",
            r.did_not_run.len(),
            r.did_not_run.join("; ")
        ))
    }
}

#[cfg(all(target_os = "linux", feature = "mod-scan-yara"))]
pub(crate) fn scan(o: &hemostat_scan::Outcome, notes: &[String], targets: usize) -> Covered {
    match (&o.unavailable, notes.is_empty()) {
        (Some(why), _) => Covered::NotAtAll(why.clone()),
        (None, false) => Covered::InPart(format!(
            "{} of {} target(s) could not be read, so their content is unexamined",
            notes.len(),
            targets
        )),
        (None, true) => Covered::Fully,
    }
}
