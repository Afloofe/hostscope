#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Guid(pub &'static str);

impl Guid {

    pub fn to_fields(self) -> Option<(u32, u16, u16, [u8; 8])> {
        let s = self.0;
        if s.len() != 36 {
            return None;
        }
        let parts: Vec<&str> = s.split('-').collect();
        if parts.len() != 5 || [8, 4, 4, 4, 12] != [
            parts[0].len(),
            parts[1].len(),
            parts[2].len(),
            parts[3].len(),
            parts[4].len(),
        ] {
            return None;
        }
        let d1 = u32::from_str_radix(parts[0], 16).ok()?;
        let d2 = u16::from_str_radix(parts[1], 16).ok()?;
        let d3 = u16::from_str_radix(parts[2], 16).ok()?;
        let mut d4 = [0u8; 8];
        let tail: String = format!("{}{}", parts[3], parts[4]);
        for (i, slot) in d4.iter_mut().enumerate() {
            *slot = u8::from_str_radix(tail.get(i * 2..i * 2 + 2)?, 16).ok()?;
        }
        Some((d1, d2, d3, d4))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lane {

    P0,

    P1,

    P2,

    EventLog,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {

    Full,

    Partial,

    NotInV1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Consumption {

    PrivateSession,

    EventLogOnly,

    Unavailable(&'static str),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Registration {

    KernelMode,

    UserMode,
}

#[derive(Debug, Clone, Copy)]
pub struct Provider {

    pub id: &'static str,

    pub name: &'static str,

    pub guid: Guid,

    pub keywords: u64,

    pub level: u8,

    pub lane: Lane,

    pub consumption: Consumption,

    pub registration: Registration,

    pub status: Status,

    pub buys: &'static str,
}

pub const KW_PROCESS: u64 = 0x10;

pub const KW_THREAD: u64 = 0x20;

pub const KW_IMAGE: u64 = 0x40;

pub const CATALOGUE: &[Provider] = &[
    Provider {
        id: "kernel-process",
        name: "Microsoft-Windows-Kernel-Process",
        guid: Guid("22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716"),

        keywords: KW_PROCESS | KW_IMAGE,
        level: 4,
        lane: Lane::P0,
        consumption: Consumption::PrivateSession,
        registration: Registration::KernelMode,
        status: Status::Partial,
        buys: "process lineage and image loads. NO command line in any version \
               (§6.2.6) — that is why this is Partial and not Full",
    },
    Provider {
        id: "kernel-audit-api",
        name: "Microsoft-Windows-Kernel-Audit-API-Calls",
        guid: Guid("E02A841C-75A3-4FA7-AFC8-AE09CF9B7F23"),
        keywords: 0,
        level: 4,
        lane: Lane::P0,
        consumption: Consumption::PrivateSession,
        registration: Registration::KernelMode,
        status: Status::Partial,
        buys: "the no-Sysmon answer to \"who killed the agent\" and \"who opened \
               LSASS\": cross-process terminate, OpenProcess with the access mask",
    },
    Provider {
        id: "kernel-network",
        name: "Microsoft-Windows-Kernel-Network",
        guid: Guid("7DD42A49-5329-4832-8DFD-43D979153A88"),
        keywords: 0,
        level: 4,
        lane: Lane::P2,
        consumption: Consumption::PrivateSession,
        registration: Registration::KernelMode,
        status: Status::Full,
        buys: "TCP connect/accept/disconnect and UDP with PID and 5-tuple. \
               Telemetry only — blocking is WFP",
    },
    Provider {
        id: "kernel-file",
        name: "Microsoft-Windows-Kernel-File",
        guid: Guid("EDD08927-9CC4-4E65-B970-C2560FB5C289"),
        keywords: 0,
        level: 4,
        lane: Lane::P2,
        consumption: Consumption::PrivateSession,
        registration: Registration::KernelMode,
        status: Status::Full,
        buys: "create, delete, rename and setinfo with PID. Very high volume, \
               and fires AFTER the I/O — it cannot pre-block",
    },
    Provider {
        id: "kernel-registry",
        name: "Microsoft-Windows-Kernel-Registry",
        guid: Guid("70EB4F03-C1DE-4F73-A051-33D13D5413BD"),
        keywords: 0,
        level: 4,
        lane: Lane::P2,
        consumption: Consumption::PrivateSession,
        registration: Registration::KernelMode,
        status: Status::Full,
        buys: "key and value writes, for the persistence sweep. Query and \
               enumerate keywords stay off — they are pure volume",
    },
    Provider {
        id: "dns-client",
        name: "Microsoft-Windows-DNS-Client",
        guid: Guid("1C95126E-7EEA-49A9-A3FE-A378B03DDB4D"),
        keywords: 0,
        level: 4,
        lane: Lane::P1,
        consumption: Consumption::PrivateSession,
        registration: Registration::UserMode,
        status: Status::Full,
        buys: "queries and responses with PID and name. Preferred over the \
               DNS-Client/Operational log, which is usually disabled",
    },
    Provider {
        id: "powershell",
        name: "Microsoft-Windows-PowerShell",
        guid: Guid("A0C1853B-5C40-4B15-8766-3CF1C58F985A"),
        keywords: 0,
        level: 4,
        lane: Lane::P1,
        consumption: Consumption::PrivateSession,
        registration: Registration::UserMode,
        status: Status::Partial,
        buys: "script block (4104) and module logging (4103) — but only once \
               script block logging is enabled, which is a hardening action",
    },
    Provider {
        id: "wmi-activity",
        name: "Microsoft-Windows-WMI-Activity",
        guid: Guid("1418EF04-B0B4-4623-BF7E-D74AB47BBDAA"),
        keywords: 0,
        level: 4,
        lane: Lane::P1,
        consumption: Consumption::PrivateSession,
        registration: Registration::UserMode,
        status: Status::Partial,
        buys: "WMI event-subscription persistence",
    },
    Provider {
        id: "dotnet-runtime",
        name: "Microsoft-Windows-DotNETRuntime",
        guid: Guid("E13C0D23-CCBC-4E12-931B-D9CC2EEE27E4"),
        keywords: 0x8,
        level: 4,
        lane: Lane::P1,
        consumption: Consumption::PrivateSession,
        registration: Registration::UserMode,
        status: Status::Full,
        buys: "assembly and module loads, catching reflectively loaded .NET that \
               leaves no image-load record. Per-process blinding via \
               DOTNET_ETWEnabled=0 makes this raise-cost, not a guarantee",
    },
    Provider {
        id: "amsi",
        name: "Microsoft-Antimalware-Scan-Interface",
        guid: Guid("2A576B87-09A7-520E-C21A-4942F0271D67"),
        keywords: 0,
        level: 4,
        lane: Lane::P1,
        consumption: Consumption::PrivateSession,
        registration: Registration::UserMode,
        status: Status::Partial,
        buys: "the scanned buffer for script, macro and in-memory .NET content. \
               An in-process amsi.dll patch suppresses the scan, so absence is \
               a tell rather than a guarantee",
    },
    Provider {
        id: "sysmon",
        name: "Microsoft-Windows-Sysmon",
        guid: Guid("5770385F-C22A-43E0-BF4C-06F5698FFBD9"),
        keywords: 0,
        level: 4,
        lane: Lane::P0,
        consumption: Consumption::PrivateSession,
        registration: Registration::UserMode,
        status: Status::Partial,
        buys: "process access, image load and process tampering — the W-A \
               telemetry mode. Operator-dependent: absent unless installed",
    },
    Provider {
        id: "security-auditing",
        name: "Microsoft-Windows-Security-Auditing",
        guid: Guid("54849625-5478-4994-A5BA-3E3B0328C30D"),
        keywords: 0,
        level: 4,
        lane: Lane::EventLog,

        consumption: Consumption::EventLogOnly,
        registration: Registration::KernelMode,
        status: Status::Full,
        buys: "4624/4625 logon, 4688 process create WITH command line, 4697 \
               service install, 1102 log clear — via EvtSubscribe, never a \
               private session",
    },
    Provider {
        id: "threat-intelligence",
        name: "Microsoft-Windows-Threat-Intelligence",
        guid: Guid("F4E1897C-BB5D-5668-F1D8-040F4D8DD344"),
        keywords: 0,
        level: 4,
        lane: Lane::P0,
        consumption: Consumption::Unavailable(
            "the kernel refuses this provider to a controller that is not an \
             anti-malware Protected Process Light, which needs a signed driver \
             this project cannot obtain (§6.1)",
        ),
        registration: Registration::KernelMode,
        status: Status::NotInV1,
        buys: "nothing here — listed so its absence is a stated limit rather \
               than an apparent oversight",
    },
];

pub fn providers_for(lane: Lane) -> Vec<&'static Provider> {
    CATALOGUE
        .iter()
        .filter(|p| p.lane == lane && matches!(p.consumption, Consumption::PrivateSession))
        .collect()
}

pub fn pid_filter_refusal(p: &Provider) -> Option<String> {
    match p.registration {
        Registration::UserMode => None,
        Registration::KernelMode => Some(format!(
            "{} is registered by a kernel-mode component, so a PID filter does not narrow it — \
             it leaves the provider DISABLED in the kernel and no events arrive at all. Use \
             keyword masks or an event-ID filter instead (§6.2.4).",
            p.name
        )),
    }
}

pub const MAX_EVENT_ID_FILTER: usize = 64;

pub const MAX_PID_FILTER: usize = 8;

pub fn event_id_filter_fits(ids: &[u16]) -> Result<(), String> {
    if ids.len() > MAX_EVENT_ID_FILTER {
        return Err(format!(
            "an EVENT_FILTER_TYPE_EVENT_ID filter holds at most {MAX_EVENT_ID_FILTER} ids and \
             {} were given; the excess would be silently dropped, so the filter would admit \
             events nobody asked for",
            ids.len()
        ));
    }
    Ok(())
}

pub fn by_id(id: &str) -> Option<&'static Provider> {
    CATALOGUE.iter().find(|p| p.id == id)
}
