pub const TICK: i64 = 10_000_000;

const UNIX_EPOCH: i64 = 116_444_736_000_000_000;

pub const AGREE: i64 = 2 * 3600 * TICK;

pub const SAME_WRITE: i64 = 5 * 60 * TICK;

pub const BOOT_SLACK: i64 = 2 * 60 * TICK;

pub const MAX_SETUP_BOOTS: usize = 3;

pub const KERNEL_GENERAL: u128 = 0xa68c_a8b7_004f_d7b6_a698_07e2_de0f_1f5d;

pub const SECURITY_AUDITING: u128 = 0x5484_9625_5478_4994_a5ba_3e3b_0328_c30d;

pub const EVENTLOG: u128 = 0xfc65_ddd8_d6ef_4962_83d5_6e5c_fe9c_e148;

pub const FAKEABLE: &str = "An administrator of this host can fake every one of these anchors: \
     clearing System and Security, rebooting, and rewriting InstallDate, InstallTime and \
     Panther's setupact.log makes later activity date this way. Treat it as image preparation \
     only if nobody untrusted had administrative control of this host or its image before it";

pub const fn filetime_from_unix(secs: i64) -> i64 {
    secs.saturating_mul(TICK).saturating_add(UNIX_EPOCH)
}

pub fn filetime_from_parts(y: i64, mo: i64, d: i64, h: i64, mi: i64, s: i64, ms: i64) -> Option<i64> {
    if !(1601..=30_827).contains(&y)
        || !(1..=12).contains(&mo)
        || !(1..=31).contains(&d)
        || !(0..24).contains(&h)
        || !(0..60).contains(&mi)
        || !(0..61).contains(&s)
        || !(0..1000).contains(&ms)
    {
        return None;
    }

    let y = if mo <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let mp = if mo > 2 { mo - 3 } else { mo + 9 };
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    let secs = days * 86_400 + h * 3600 + mi * 60 + s;
    Some(filetime_from_unix(secs) + ms * (TICK / 1000))
}

pub fn utc(ft: i64) -> String {
    let secs = ft.saturating_sub(UNIX_EPOCH).div_euclid(TICK);
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z", rem / 3600, (rem % 3600) / 60, rem % 60)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Mark {

    pub seq: u64,

    pub at: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Step {

    pub seq: u64,

    pub old: i64,

    pub new: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum Upgrade {

    Unread(String),

    Absent,

    Found(String),

    #[default]
    NotLooked,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Anchors {

    pub now: Option<i64>,

    pub boot: Option<i64>,

    pub install_date: Option<i64>,

    pub install_time: Option<i64>,

    pub setup_log: Option<i64>,

    pub upgrade: Upgrade,

    pub system_boots: Option<Vec<Mark>>,

    pub security_boots: Option<Vec<Mark>>,

    pub clock_steps: Option<Vec<Step>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Install {

    pub at: i64,

    pub boot: i64,

    pub first_boot: Mark,

    pub current_boot: Mark,

    pub security_first: Mark,

    pub security_current: Mark,

    pub boots: Vec<Mark>,

    pub basis: String,
}

fn in_order(marks: &[Mark], what: &str) -> Result<Vec<Mark>, String> {
    let mut sorted = marks.to_vec();
    sorted.sort_unstable_by_key(|m| m.seq);
    for w in sorted.windows(2) {
        if let [a, b] = w {
            if b.at <= a.at {
                return Err(format!(
                    "{what}: record {} says {} and comes after record {} at {}. A boot cannot \
                     start before the one it follows, so the clock was moved",
                    b.seq,
                    utc(b.at),
                    a.seq,
                    utc(a.at)
                ));
            }
        }
    }
    Ok(sorted)
}

pub fn install(a: &Anchors) -> Result<Install, String> {
    let (Some(_now), Some(boot)) = (a.now, a.boot) else {
        return Err("the clock or the boot time could not be read".into());
    };
    match &a.upgrade {
        Upgrade::Absent => {}
        Upgrade::Found(what) => {
            return Err(format!(
                "this installation was upgraded in place ({what}). An upgrade rewrites \
                 InstallDate, InstallTime and Panther together, so they date the upgrade, and \
                 everything before it would read as image preparation"
            ));
        }
        Upgrade::Unread(why) => {
            return Err(format!("whether this installation was upgraded in place could not be read: {why}"));
        }
        Upgrade::NotLooked => {
            return Err("whether this installation was upgraded in place was not looked for".into());
        }
    }

    let Some(sys) = &a.system_boots else {
        return Err(
            "the System log's boot records (Kernel-General 12) could not be read, which leaves \
             nothing to place the clone's first boot by"
                .into(),
        );
    };
    let sys = in_order(sys, "the System log's boots run backwards")?;
    let (Some(&first), Some(&current)) = (sys.first(), sys.last()) else {
        return Err("the System log holds no record of any boot (Kernel-General 12)".into());
    };
    if sys.len() < 2 {
        return Err(format!(
            "the System log holds one boot, this one at {}. Either this is the clone's first \
             boot, which setup has not finished, or the log began during it, and then it \
             does not reach back to setup",
            utc(current.at)
        ));
    }
    if (current.at - boot).abs() > BOOT_SLACK {
        return Err(format!(
            "the clock puts this boot at {} and the System log recorded it starting at {}. The \
             clock was moved after the boot (by hand, by w32time or by a domain controller), so \
             times stamped in this boot cannot be placed",
            utc(boot),
            utc(current.at)
        ));
    }

    let registry = match (a.install_date, a.install_time) {
        (Some(d), Some(t)) if (d - t).abs() > SAME_WRITE => {
            return Err(format!(
                "InstallDate says {} and InstallTime says {}. Windows writes them together, so \
                 one of them was edited",
                utc(d),
                utc(t)
            ));
        }
        (Some(d), Some(t)) => d.min(t),
        (Some(x), None) | (None, Some(x)) => x,
        (None, None) => return Err("the registry's install time could not be read".into()),
    };
    let Some(setup) = a.setup_log else {
        return Err(
            "Panther's setupact.log could not be read, which leaves the registry's install time \
             with nothing to check it against"
                .into(),
        );
    };
    if (registry - setup).abs() > AGREE {
        return Err(format!(
            "the registry dates the install at {} and Panther's setupact.log was last written at \
             {}. Those describe one event and are hours apart",
            utc(registry),
            utc(setup)
        ));
    }
    let setup_end = sys.get(MAX_SETUP_BOOTS).copied();
    for (name, t) in [
        ("InstallDate", a.install_date),
        ("InstallTime", a.install_time),
        ("Panther's setupact.log", Some(setup)),
    ] {
        let Some(t) = t else { continue };
        if t <= first.at {
            return Err(format!(
                "{name} ({}) is not after the oldest boot the System log holds ({}, record {}). \
                 Setup writes it while the clone first boots, so the log does not reach back to \
                 setup (it rolled over, or was cleared or recreated since), or the value was \
                 moved",
                utc(t),
                utc(first.at),
                first.seq
            ));
        }
        if let Some(end) = setup_end {
            if t >= end.at {
                return Err(format!(
                    "{name} ({}) is after the clone had already booted {MAX_SETUP_BOOTS} times \
                     (the next boot was at {}, record {}). Setup finishes in its first boots, so \
                     the value was moved later, or does not describe this installation",
                    utc(t),
                    utc(end.at),
                    end.seq
                ));
            }
        }
        if t >= current.at - BOOT_SLACK {
            return Err(format!(
                "{name} ({}) is not earlier than this boot ({}). Specialize reboots when it \
                 finishes, so the install must come first",
                utc(t),
                utc(current.at)
            ));
        }
    }

    let Some(sec) = &a.security_boots else {
        return Err(
            "the Security log's startup records (4608) could not be read, which leaves the System \
             log with nothing to check its history against"
                .into(),
        );
    };
    let sec = in_order(sec, "the Security log's startups run backwards")?;
    if sec.len() != sys.len() {
        return Err(format!(
            "the System log records {} boot(s) and the Security log {} startup(s). The two logs \
             disagree about this host's history, which is what one of them cleared or recreated \
             since setup looks like, whatever its clock said",
            sys.len(),
            sec.len()
        ));
    }
    for (k, s) in sys.iter().zip(&sec) {
        if (k.at - s.at).abs() > BOOT_SLACK {
            return Err(format!(
                "the System log records a boot at {} (record {}) and the Security log's startup \
                 beside it in order is at {} (record {}). The two logs disagree about this host's \
                 history",
                utc(k.at),
                k.seq,
                utc(s.at),
                s.seq
            ));
        }
    }
    let (Some(&security_first), Some(&security_current)) = (sec.first(), sec.last()) else {
        return Err("the Security log holds no startup records (4608)".into());
    };

    let Some(steps) = &a.clock_steps else {
        return Err(
            "the System log's clock-change records (Kernel-General 1) could not be read, so \
             whether the clock was set back since the clone first booted is unknown"
                .into(),
        );
    };
    let after: Vec<&Step> = steps.iter().filter(|s| s.seq > first.seq).collect();
    if let Some(s) = after.iter().find(|s| s.old.min(s.new) < first.at) {
        return Err(format!(
            "the System log records the clock changed from {} to {} (record {}), after the clone \
             first booted at {}. A clock that read earlier than that boot can stamp anything as \
             the image's",
            utc(s.old),
            utc(s.new),
            s.seq,
            utc(first.at)
        ));
    }

    let at = first.at.min(security_first.at);
    if current.at - BOOT_SLACK <= at {
        return Err("this boot began too close to the clone's first boot to tell them apart".into());
    }
    let setup_boots = sys.iter().filter(|b| b.at <= registry.max(setup)).count();
    Ok(Install {
        at,
        boot,
        first_boot: first,
        current_boot: current,
        security_first,
        security_current,
        boots: sys.clone(),
        basis: format!(
            "the clone first booted at {} (System Kernel-General 12, record {}; Security 4608, \
             record {}); InstallDate {}, InstallTime {} and Panther setupact.log {} all land in \
             its first {setup_boots} boot(s); System and Security agree on all {} boots since; \
             this boot began at {} by the tick count and {} by the System log (record {}); {} \
             recorded clock change(s) since the first boot, none earlier than it; no upgrade \
             marker.",
            utc(first.at),
            first.seq,
            security_first.seq,
            a.install_date.map_or_else(|| "unread".into(), utc),
            a.install_time.map_or_else(|| "unread".into(), utc),
            utc(setup),
            sys.len(),
            utc(boot),
            utc(current.at),
            current.seq,
            after.len()
        ),
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Log {

    System,

    Security,

    Journal,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Chronology {

    pub install: Install,

    pub boundary: Mark,

    pub current: u64,

    pub earliest: Mark,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Dating {

    Dated(Chronology),

    Undated(String),
}

impl Default for Dating {
    fn default() -> Self {
        Self::Undated("nothing was read to date it by".into())
    }
}

pub fn chronology(
    marks: &[Mark],
    install: &Result<Install, String>,
    log: Log,
    whole: Result<(), String>,
) -> Dating {
    if let Err(why) = whole {
        return Dating::Undated(why);
    }
    let install = match install {
        Ok(i) => i.clone(),
        Err(why) => return Dating::Undated(why.clone()),
    };
    let mut sorted = marks.to_vec();
    sorted.sort_unstable_by_key(|m| m.seq);
    let Some(&earliest) = sorted.first() else {
        return Dating::Undated("the log held no records to place the install in".into());
    };

    let found = |want: Mark| sorted.contains(&want);
    let (boundary, current) = match log {
        Log::System | Log::Security => {
            let (b, c) = if log == Log::System {
                (install.first_boot, install.current_boot)
            } else {
                (install.security_first, install.security_current)
            };
            if !found(b) || !found(c) {
                return Dating::Undated(format!(
                    "this log's records do not include the boot records the install was placed \
                     by (records {} and {}), so the log changed between the two reads",
                    b.seq, c.seq
                ));
            }
            (b, c.seq)
        }
        Log::Journal => {
            let Some(&b) = sorted.iter().find(|m| m.at >= install.at) else {
                return Dating::Undated(format!(
                    "the journal holds nothing from the clone's first boot at {} onward, so it has \
                     not been here since then",
                    utc(install.at)
                ));
            };
            let this_boot = install.current_boot.at.min(install.boot) - BOOT_SLACK;
            let Some(c) = sorted.iter().find(|m| m.at >= this_boot) else {
                return Dating::Undated(format!(
                    "the journal holds nothing from this boot at {}, so it has not been here since \
                     the machine started",
                    utc(install.boot)
                ));
            };

            for k in install.boots.iter().filter(|k| k.at >= earliest.at) {
                if !sorted.iter().any(|m| (m.at - k.at).abs() <= BOOT_SLACK) {
                    return Dating::Undated(format!(
                        "the System log records a boot at {} (record {}) and the journal, which \
                         reaches back to {}, holds nothing from within two minutes of it. A \
                         volume is written to as it boots, so the journal was not here then: it \
                         was recreated since, whatever its clock said",
                        utc(k.at),
                        k.seq,
                        utc(earliest.at)
                    ));
                }
            }
            (b, c.seq)
        }
    };

    if let Some(m) = sorted.iter().find(|m| m.seq > boundary.seq && m.at < install.at) {
        return Dating::Undated(format!(
            "record {} is numbered after the clone's first boot (record {}) and stamped {}, \
             before it. The clock was set back since this installation began, so times in this \
             log date nothing",
            m.seq,
            boundary.seq,
            utc(m.at)
        ));
    }
    Dating::Dated(Chronology { install, boundary, current, earliest })
}

impl Chronology {

    pub fn evidence(&self) -> String {
        format!(
            "In this log's own numbering the clone's first boot is {} at {}, and the oldest \
             surviving record is {} at {}. Anchors that agreed: {}",
            self.boundary.seq,
            utc(self.boundary.at),
            self.earliest.seq,
            utc(self.earliest.at),
            self.install.basis
        )
    }

    pub fn predates(&self, seq: u64, at: i64) -> Result<(), String> {
        if seq >= self.current {
            return Err(format!(
                "it is in this boot (numbered {seq}, and this boot begins at {} in this log), and \
                 nothing in the current boot is dated as the image's, whatever its time says",
                self.current
            ));
        }
        if at >= self.install.at {
            return Err(format!(
                "it is dated {}, not before this clone first booted at {}",
                utc(at),
                utc(self.install.at)
            ));
        }
        if seq >= self.boundary.seq {
            return Err(format!(
                "it is dated {} but this log numbers it after the clone's first boot ({} at {}), \
                 which is what a clock wound back looks like",
                utc(at),
                self.boundary.seq,
                utc(self.boundary.at)
            ));
        }
        Ok(())
    }
}

impl Dating {

    pub fn predates(&self, seq: u64, at: i64) -> Result<&Chronology, String> {
        match self {
            Self::Dated(c) => c.predates(seq, at).map(|()| c),
            Self::Undated(why) => Err(format!(
                "whether it predates this installation could not be established: {why}"
            )),
        }
    }
}

#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
const CURRENT_VERSION: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion";

#[cfg(target_os = "windows")]
fn upgrade_markers() -> Upgrade {
    let keys = match crate::reg::subkeys_read(crate::reg::Hive::Machine, r"SYSTEM\Setup") {
        Ok(k) => k,
        Err(rc) => return Upgrade::Unread(format!(r"HKLM\SYSTEM\Setup could not be read (error {rc})")),
    };
    let mut found: Vec<String> = keys
        .iter()
        .filter(|k| k.starts_with("Source OS"))
        .map(|k| format!(r"HKLM\SYSTEM\Setup\{k}"))
        .collect();
    for p in [r"C:\Windows.old", r"C:\$WINDOWS.~BT", r"C:\Windows\Panther\NewOs"] {
        if std::path::Path::new(p).exists() {
            found.push(p.to_string());
        }
    }
    if found.is_empty() {
        Upgrade::Absent
    } else {
        Upgrade::Found(found.join(", "))
    }
}

#[cfg(target_os = "windows")]
pub fn anchors() -> Anchors {
    use windows_sys::Win32::Foundation::FILETIME;
    use windows_sys::Win32::System::SystemInformation::{GetSystemTimeAsFileTime, GetTickCount64};

    let mut ft = FILETIME { dwLowDateTime: 0, dwHighDateTime: 0 };

    unsafe { GetSystemTimeAsFileTime(std::ptr::addr_of_mut!(ft)) };
    let now = (i64::from(ft.dwHighDateTime) << 32) | i64::from(ft.dwLowDateTime);

    let up_ms = unsafe { GetTickCount64() };
    let boot = i64::try_from(up_ms).ok().map(|ms| now - ms.saturating_mul(TICK / 1000));

    let setup_log = std::fs::metadata(r"C:\Windows\Panther\setupact.log")
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .and_then(|d| i64::try_from(d.as_nanos() / 100).ok())
        .map(|ticks| ticks + UNIX_EPOCH);

    Anchors {
        now: (now > 0).then_some(now),
        boot,
        install_date: crate::reg::hklm_dword(CURRENT_VERSION, "InstallDate")
            .map(|s| filetime_from_unix(i64::from(s))),
        install_time: crate::reg::hklm_qword(CURRENT_VERSION, "InstallTime")
            .and_then(|t| i64::try_from(t).ok()),
        setup_log,
        upgrade: upgrade_markers(),
        system_boots: crate::evtlog::boot_records(),
        security_boots: crate::evtlog::security_startups(),
        clock_steps: crate::evtlog::clock_changes(),
    }
}

#[cfg(not(target_os = "windows"))]
pub fn anchors() -> Anchors {
    Anchors::default()
}
