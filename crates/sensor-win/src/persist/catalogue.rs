use super::{Category, Mechanism, Probe};

pub const CATALOGUE: &[Mechanism] = &[
    Mechanism {
        id: "hklm-run",
        name: "machine Run key",
        category: Category::Logon,
        probe: Probe::KeyValues(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
    },
    Mechanism {
        id: "hklm-runonce",
        name: "machine RunOnce key",
        category: Category::Logon,
        probe: Probe::KeyValues(r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
    },
    Mechanism {
        id: "hklm-run-wow",
        name: "machine Run key (32-bit view)",
        category: Category::Logon,

        probe: Probe::KeyValues(r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"),
    },
    Mechanism {
        id: "winlogon",
        name: "Winlogon shell and userinit",
        category: Category::Logon,

        probe: Probe::NamedValues(
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
            &["Userinit", "Shell", "Taskman", "AppSetup", "GinaDLL", "VMApplet", "System"],
        ),
    },
    Mechanism {
        id: "appinit-dlls",
        name: "AppInit_DLLs",
        category: Category::Injection,

        probe: Probe::NamedValues(
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows",
            &["AppInit_DLLs", "LoadAppInit_DLLs"],
        ),
    },
    Mechanism {
        id: "ifeo-debugger",
        name: "Image File Execution Options debuggers",
        category: Category::Injection,
        probe: Probe::SubkeyValue(
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
            "Debugger",
        ),
    },
    Mechanism {
        id: "services",
        name: "services configured to start themselves",
        category: Category::Service,
        probe: Probe::SubkeyValue(r"SYSTEM\CurrentControlSet\Services", "ImagePath"),
    },
    Mechanism {
        id: "scheduled-tasks",
        name: "scheduled tasks",
        category: Category::Scheduled,
        probe: Probe::TaskFiles(r"C:\Windows\System32\Tasks"),
    },
    Mechanism {
        id: "startup-folder",
        name: "all-users Startup folder",
        category: Category::Logon,
        probe: Probe::Directory(
            r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp",
        ),
    },

    Mechanism {
        id: "hklm-runonce-wow",
        name: "machine RunOnce key (32-bit view)",
        category: Category::Logon,
        probe: Probe::KeyValues(r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce"),
    },
    Mechanism {
        id: "policies-explorer-run",
        name: "Explorer policy Run key",
        category: Category::Logon,

        probe: Probe::KeyValues(
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
        ),
    },
    Mechanism {
        id: "active-setup",
        name: "Active Setup installed components",
        category: Category::Logon,

        probe: Probe::SubkeyValue(r"SOFTWARE\Microsoft\Active Setup\Installed Components", "StubPath"),
    },
    Mechanism {
        id: "winlogon-notify",
        name: "Winlogon notification packages",
        category: Category::Injection,

        probe: Probe::SubkeyValue(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify", "DllName"),
    },
    Mechanism {
        id: "logon-scripts",
        name: "user logon scripts (UserInitMprLogonScript), in every loaded profile",
        category: Category::Logon,

        probe: Probe::UserValues(r"Environment", &["UserInitMprLogonScript"]),
    },
    Mechanism {
        id: "gpo-scripts",
        name: "Group Policy startup and shutdown scripts",
        category: Category::Boot,
        probe: Probe::Directory(r"C:\Windows\System32\GroupPolicy\Machine\Scripts"),
    },
    Mechanism {
        id: "terminal-server-initial",
        name: "Terminal Services initial program",
        category: Category::Logon,
        probe: Probe::NamedValues(
            r"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp",
            &["InitialProgram", "WorkDirectory"],
        ),
    },

    Mechanism {
        id: "appcert-dlls",
        name: "AppCertDlls",
        category: Category::Injection,

        probe: Probe::KeyValues(r"SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls"),
    },
    Mechanism {
        id: "lsa-packages",
        name: "LSA authentication and notification packages",
        category: Category::Injection,

        probe: Probe::NamedValues(
            r"SYSTEM\CurrentControlSet\Control\Lsa",
            &["Authentication Packages", "Security Packages", "Notification Packages"],
        ),
    },
    Mechanism {
        id: "lsa-osconfig",
        name: "LSA security packages (OSConfig)",
        category: Category::Injection,

        probe: Probe::NamedValues(
            r"SYSTEM\CurrentControlSet\Control\Lsa\OSConfig",
            &["Security Packages"],
        ),
    },
    Mechanism {
        id: "lsa-extensions",
        name: "LSA extension packages",
        category: Category::Injection,
        probe: Probe::NamedValues(
            r"SYSTEM\CurrentControlSet\Control\LsaExtensionConfig\LsaSrv",
            &["Extensions"],
        ),
    },
    Mechanism {
        id: "known-dlls",
        name: "KnownDLLs",
        category: Category::Injection,

        probe: Probe::KeyValues(r"SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs"),
    },
    Mechanism {
        id: "boot-execute",
        name: "Session Manager BootExecute",
        category: Category::Boot,

        probe: Probe::NamedValues(
            r"SYSTEM\CurrentControlSet\Control\Session Manager",
            &["BootExecute", "SetupExecute", "Execute", "S0InitialCommand"],
        ),
    },

    Mechanism {
        id: "ssodl",
        name: "ShellServiceObjectDelayLoad",
        category: Category::Injection,
        probe: Probe::KeyValues(
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad",
        ),
    },
    Mechanism {
        id: "shared-task-scheduler",
        name: "SharedTaskScheduler",
        category: Category::Injection,
        probe: Probe::KeyValues(
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\SharedTaskScheduler",
        ),
    },
    Mechanism {
        id: "shell-execute-hooks",
        name: "ShellExecuteHooks",
        category: Category::Injection,
        probe: Probe::KeyValues(
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellExecuteHooks",
        ),
    },

    Mechanism {
        id: "browser-helper-objects",
        name: "Browser Helper Objects",
        category: Category::Injection,
        probe: Probe::SubkeyValue(
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects",
            "",
        ),
    },
    Mechanism {
        id: "icon-overlay-handlers",
        name: "shell icon overlay handlers",
        category: Category::Injection,
        probe: Probe::SubkeyValue(
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellIconOverlayIdentifiers",
            "",
        ),
    },
    Mechanism {
        id: "shell-extension-approved",
        name: "approved shell extensions",
        category: Category::Injection,
        probe: Probe::KeyValues(
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved",
        ),
    },

    Mechanism {
        id: "print-monitors",
        name: "print monitors",
        category: Category::Service,

        probe: Probe::SubkeyValue(r"SYSTEM\CurrentControlSet\Control\Print\Monitors", "Driver"),
    },
    Mechanism {
        id: "print-providers",
        name: "print providers",
        category: Category::Service,
        probe: Probe::SubkeyValue(r"SYSTEM\CurrentControlSet\Control\Print\Providers", "Name"),
    },
    Mechanism {
        id: "time-providers",
        name: "W32Time time providers",
        category: Category::Service,
        probe: Probe::SubkeyValue(r"SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders", "DllName"),
    },
    Mechanism {
        id: "netsh-helpers",
        name: "netsh helper DLLs",
        category: Category::Injection,

        probe: Probe::KeyValues(r"SOFTWARE\Microsoft\Netsh"),
    },
    Mechanism {
        id: "winsock-autodial",
        name: "Winsock AutodialDLL",
        category: Category::Injection,
        probe: Probe::NamedValues(
            r"SYSTEM\CurrentControlSet\Services\WinSock2\Parameters",
            &["AutodialDLL"],
        ),
    },

    Mechanism {
        id: "winrm-plugins",
        name: "WinRM / PowerShell session configurations",
        category: Category::Service,

        probe: Probe::SubkeyValue(
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN\Plugin",
            "FileName",
        ),
    },
    Mechanism {
        id: "winrm-listener",
        name: "WinRM listeners",
        category: Category::Service,
        probe: Probe::SubkeyValue(
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN\Listener",
            "Address",
        ),
    },
    Mechanism {
        id: "winrm-client",
        name: "WinRM client trust settings",
        category: Category::Service,

        probe: Probe::NamedValues(
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN\Client",
            &["TrustedHosts", "AllowUnencrypted", "Basic"],
        ),
    },
    Mechanism {
        id: "winrm-service",
        name: "WinRM service settings",
        category: Category::Service,
        probe: Probe::NamedValues(
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN\Service",
            &["AllowUnencrypted", "Basic", "CbtHardeningLevel", "EnableCompatibilityHttpListener"],
        ),
    },

    Mechanism {
        id: "task-cache",
        name: "scheduled task cache (registry side)",
        category: Category::Scheduled,

        probe: Probe::SubkeyValue(
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks",
            "Path",
        ),
    },

    Mechanism {
        id: "powershell-profiles",
        name: "PowerShell profiles",
        category: Category::Logon,

        probe: Probe::Directory(r"C:\Windows\System32\WindowsPowerShell\v1.0"),
    },
    Mechanism {
        id: "office-startup",
        name: "Office startup and template folders",
        category: Category::Logon,
        probe: Probe::Directory(r"C:\Program Files\Microsoft Office\root\Office16\STARTUP"),
    },
];
