use hs_core::mode::Profile;

pub(crate) const fn oom_score_adj(profile: Profile) -> i32 {
    match profile {
        Profile::It => -500,
        Profile::Ot => 0,
    }
}

pub(crate) fn apply_oom_score_adj(profile: Profile) -> Result<i32, String> {
    let v = oom_score_adj(profile);
    std::fs::write("/proc/self/oom_score_adj", v.to_string())
        .map(|()| v)
        .map_err(|e| format!("oom_score_adj could not be set to {v} ({e}); the agent runs at the kernel default"))
}

pub(crate) const DISK_CEILING: f64 = 0.85;

pub(crate) fn disk_refusal(dir: &std::path::Path) -> Option<String> {
    let Some(probe) = measured_at(dir) else {
        return Some(format!("no directory at or above {} exists to measure", dir.display()));
    };
    match hemostat_sensor_linux::volume::used_fraction(probe) {
        Ok(f) => judge(f),
        Err(e) => Some(format!("the volume under {} could not be measured ({e})", probe.display())),
    }
}

fn measured_at(dir: &std::path::Path) -> Option<&std::path::Path> {
    std::iter::successors(Some(dir), |p| p.parent())
        .map(|p| if p.as_os_str().is_empty() { std::path::Path::new(".") } else { p })
        .find(|p| p.exists())
}

fn judge(used: f64) -> Option<String> {
    (used >= DISK_CEILING).then(|| {
        format!(
            "the volume is {:.0}% full, at or past the {:.0}% ceiling the evidence writer keeps \
             (design §16.1.4); filling the host's disk is worse than a short store",
            used * 100.0,
            DISK_CEILING * 100.0
        )
    })
}
