use super::{Category, Mechanism, Probe};

pub const CATALOGUE: &[Mechanism] = &[

    Mechanism {
        id: "rc-local",
        name: "rc.local and SysV init scripts",
        category: Category::Boot,
        why: "the oldest run-at-boot hook, still honoured by a compatibility unit on \
              most distributions and rarely looked at",
        probe: Probe::Files(&["/etc/rc.local", "/etc/rc.d/rc.local", "/etc/inittab"]),
    },
    Mechanism {
        id: "init-d",
        name: "/etc/init.d scripts",
        category: Category::Boot,
        why: "SysV service scripts, still executed through systemd's generator on \
              hosts that carry them",
        probe: Probe::FilesIn(&["/etc/init.d"]),
    },
    Mechanism {
        id: "tmpfiles-d",
        name: "systemd-tmpfiles rules",
        category: Category::Boot,
        why: "a `C`, `w` or `L` line copies, writes or links a file into place on every \
              boot, so a payload deleted during remediation is simply recreated the next \
              time the host starts — persistence that survives being cleaned up",
        probe: Probe::FilesIn(&["/etc/tmpfiles.d", "/usr/lib/tmpfiles.d", "/run/tmpfiles.d"]),
    },
    Mechanism {
        id: "sysusers-d",
        name: "systemd-sysusers rules",
        category: Category::Boot,
        why: "creates accounts at boot, so a user deleted during response reappears on \
              the next start with the uid the file asks for",
        probe: Probe::FilesIn(&["/etc/sysusers.d", "/usr/lib/sysusers.d"]),
    },
    Mechanism {
        id: "initramfs-hooks",
        name: "initramfs hooks and scripts",
        category: Category::Boot,
        why: "code baked into the initial ramdisk runs before the root filesystem is \
              mounted, so it precedes every other mechanism in this table",
        probe: Probe::TreeUnder(&[
            "/etc/initramfs-tools/hooks",
            "/etc/initramfs-tools/scripts",
            "/etc/initcpio/hooks",
            "/etc/initcpio/install",
        ]),
    },

    Mechanism {
        id: "bootloader",
        name: "bootloader configuration and generator scripts",
        category: Category::Boot,
        why: "a kernel command line runs before the init system, before every LSM policy is \
              loaded and before anything in this catalogue; the generator scripts under \
              /etc/grub.d execute as root every time the config is rebuilt",
        probe: Probe::TreeUnder(&["/etc/grub.d", "/etc/default/grub.d"]),
    },
    Mechanism {
        id: "bootloader-config",
        name: "bootloader config files",
        category: Category::Boot,
        why: "an `init=` or `rdinit=` on the kernel line replaces pid 1 itself, which is the \
              earliest persistence a host can hold short of firmware",
        probe: Probe::Files(&[
            "/etc/default/grub",
            "/boot/grub/grub.cfg",
            "/boot/grub2/grub.cfg",
            "/boot/loader/loader.conf",
        ]),
    },
    Mechanism {
        id: "systemd-linger",
        name: "systemd user lingering",
        category: Category::Service,
        why: "a user marked as lingering has their user units started at boot and kept running \
              with nobody logged in — a per-user service that survives logout and that a sweep \
              of system units never sees",
        probe: Probe::FilesIn(&["/var/lib/systemd/linger"]),
    },
    Mechanism {
        id: "incron",
        name: "incron filesystem triggers",
        category: Category::Scheduled,
        why: "runs a command when a path is touched rather than on a clock, so it fires on the \
              responder's own investigation and leaves no cron line to find",
        probe: Probe::TreeUnder(&["/etc/incron.d", "/var/spool/incron"]),
    },
    Mechanism {
        id: "xsession",
        name: "X session and display-manager scripts",
        category: Category::Login,
        why: "every graphical login sources these, as the user logging in, before their shell \
              profile runs",
        probe: Probe::TreeUnder(&[
            "/etc/X11/Xsession.d",
            "/etc/X11/xinit/xinitrc.d",
            "/etc/gdm3",
            "/etc/gdm",
            "/etc/lightdm",
            "/etc/sddm.conf.d",
        ]),
    },
    Mechanism {
        id: "ssh-ca",
        name: "SSH certificate authority keys",
        category: Category::Auth,
        why: "a trusted CA key lets its holder mint a certificate for any principal on this \
              host — access that needs no authorized_keys entry and that removing one user's \
              key does not revoke",
        probe: Probe::Files(&[
            "/etc/ssh/trusted_user_ca_keys",
            "/etc/ssh/ca.pub",
            "/etc/ssh/authorized_principals",
        ]),
    },

    Mechanism {
        id: "runit-services",
        name: "runit / daemontools service directories",
        category: Category::Service,
        why: "a directory with an executable `run` script in the supervisor's scan path is started within seconds and restarted every time it exits — persistence that re-establishes itself without a restart policy anyone has to set, on hosts where nobody thinks to look because they are looking for units",

        probe: Probe::TreeUnder(&[
            "/etc/service",
            "/run/runit/service",
            "/var/service",
            "/service",
            "/etc/sv",
            "/etc/runit/sv",
            "/etc/runit/runsvdir",
        ]),
    },
    Mechanism {
        id: "runit-boot",
        name: "runit stage scripts",
        category: Category::Boot,
        why: "runit's three boot stages are plain shell scripts; a line added to stage 1 or 2 runs before any service does, and they are not files anybody diffs",
        probe: Probe::Files(&[
            "/etc/runit/1",
            "/etc/runit/2",
            "/etc/runit/3",
            "/etc/rc.local.d",
        ]),
    },
    Mechanism {
        id: "s6-services",
        name: "s6 service directories",
        category: Category::Service,
        why: "the same shape as runit — an executable `run` under a supervised scan directory — on hosts that chose s6 instead",
        probe: Probe::TreeUnder(&["/etc/s6", "/run/service", "/etc/s6-rc", "/var/lib/s6"]),
    },
    Mechanism {
        id: "openrc-services",
        name: "OpenRC runlevels and service config",
        category: Category::Service,
        why: "OpenRC's runlevel symlinks and per-service config decide what starts at boot \
              with no systemd anywhere near it; the scripts themselves are covered by init-d",

        probe: Probe::TreeUnder(&["/etc/runlevels", "/etc/conf.d"]),
    },
    Mechanism {
        id: "systemd-system",
        name: "systemd system units",
        category: Category::Service,
        why: "the primary persistence surface on a modern host; a unit with a \
              plausible name and description is the standard shape (the red team's \
              Go implant installs exactly this way)",
        probe: Probe::FilesIn(&[
            "/etc/systemd/system",
            "/usr/lib/systemd/system",
            "/lib/systemd/system",
            "/run/systemd/system",
        ]),
    },
    Mechanism {
        id: "systemd-dropins",
        name: "systemd drop-in overrides",
        category: Category::Service,
        why: "a `.d/*.conf` fragment can add an ExecStartPre to a legitimate unit \
              without altering the unit file anybody would inspect",
        probe: Probe::TreeUnder(&[
            "/etc/systemd/system",
            "/run/systemd/system",
            "/usr/lib/systemd/system",
        ]),
    },
    Mechanism {
        id: "systemd-user",
        name: "systemd user units",
        category: Category::Service,
        why: "runs as the user at login and is out of the way of anyone looking only \
              at system units",

        probe: Probe::PerUser(&[
            ".config/systemd/user",
            ".config/systemd/user.control",
            ".config/systemd/user.attached",
            ".local/share/systemd/user",
        ]),
    },
    Mechanism {
        id: "systemd-user-system",
        name: "system-wide systemd user units",
        category: Category::Service,
        why: "a unit dropped in /etc/systemd/user starts in *every* user's session \
              manager, so one file outside any home directory buys execution as each \
              person who logs in — and a sweep that only reads ~/.config/systemd/user \
              never sees it",
        probe: Probe::FilesIn(&[
            "/etc/systemd/user",
            "/usr/lib/systemd/user",
            "/run/systemd/user",
        ]),
    },
    Mechanism {
        id: "nsswitch",
        name: "NSS modules (/etc/nsswitch.conf)",
        category: Category::Linker,
        why: "a name listed in nsswitch.conf makes every process that resolves a user, \
              group or host dlopen `libnss_<name>.so` — which is most processes on the \
              box, including ones running as root. It is the loader-level cousin of \
              LD_PRELOAD, it needs no environment variable to survive, and nothing in \
              this catalogue was reading the file",
        probe: Probe::Files(&["/etc/nsswitch.conf"]),
    },
    Mechanism {
        id: "inetd",
        name: "inetd and xinetd super-servers",
        category: Category::Service,
        why: "a super-server entry runs a program on every connection to its port, so \
              the listener belongs to inetd and the process table never shows the \
              implant waiting for it",
        probe: Probe::Files(&["/etc/inetd.conf", "/etc/xinetd.conf"]),
    },
    Mechanism {
        id: "xinetd-d",
        name: "xinetd service drop-ins",
        category: Category::Service,
        why: "one file per service, each naming a program to run on connection — the \
              drop-in form of the same network-triggered execution",
        probe: Probe::FilesIn(&["/etc/xinetd.d"]),
    },
    Mechanism {
        id: "systemd-generators",
        name: "systemd generators",
        category: Category::Service,
        why: "executables run by systemd very early, on every boot and every reload, \
              to synthesise units — an under-inspected execution point",
        probe: Probe::FilesIn(&[
            "/etc/systemd/system-generators",
            "/usr/lib/systemd/system-generators",
            "/etc/systemd/user-generators",
            "/usr/lib/systemd/user-generators",
        ]),
    },

    Mechanism {
        id: "cron-system",
        name: "system crontab and /etc/cron.d",
        category: Category::Scheduled,
        why: "runs on a clock as any user it names, and a single line is enough",
        probe: Probe::Files(&["/etc/crontab", "/etc/anacrontab"]),
    },
    Mechanism {
        id: "cron-d",
        name: "/etc/cron.d fragments",
        category: Category::Scheduled,
        why: "a drop-in directory where one new file is easy to miss among the \
              package-supplied ones",
        probe: Probe::FilesIn(&["/etc/cron.d"]),
    },
    Mechanism {
        id: "cron-periodic",
        name: "cron.hourly / daily / weekly / monthly",
        category: Category::Scheduled,
        why: "run-parts directories where any executable file is run on schedule, \
              with no crontab line to review",
        probe: Probe::FilesIn(&[
            "/etc/cron.hourly",
            "/etc/cron.daily",
            "/etc/cron.weekly",
            "/etc/cron.monthly",
        ]),
    },
    Mechanism {
        id: "cron-user",
        name: "per-user crontabs",
        category: Category::Scheduled,
        why: "a user's own schedule, stored outside /etc where a review of system \
              configuration will not see it",
        probe: Probe::FilesIn(&[
            "/var/spool/cron/crontabs",
            "/var/spool/cron",
        ]),
    },
    Mechanism {
        id: "at-jobs",
        name: "at and batch jobs",
        category: Category::Scheduled,
        why: "a one-shot scheduled job that can re-queue itself, leaving no crontab \
              entry at all",
        probe: Probe::FilesIn(&["/var/spool/cron/atjobs", "/var/spool/at"]),
    },
    Mechanism {
        id: "systemd-timers",
        name: "systemd timers",
        category: Category::Scheduled,
        why: "the modern replacement for cron; a timer plus a service is two \
              innocuous-looking files",
        probe: Probe::FilesIn(&[
            "/etc/systemd/system",
            "/usr/lib/systemd/system",
            "/run/systemd/system",
        ]),
    },

    Mechanism {
        id: "shell-system",
        name: "system-wide shell startup files",
        category: Category::Login,
        why: "runs for every user who opens a shell, including the responder \
              investigating the host",
        probe: Probe::Files(&[
            "/etc/profile",
            "/etc/bash.bashrc",
            "/etc/bashrc",
            "/etc/zsh/zshrc",
            "/etc/zsh/zprofile",
            "/etc/environment",
        ]),
    },
    Mechanism {
        id: "shell-profile-d",
        name: "/etc/profile.d",
        category: Category::Login,
        why: "a drop-in directory sourced by every login shell; one file is enough \
              and package-supplied ones make it crowded",
        probe: Probe::FilesIn(&["/etc/profile.d"]),
    },
    Mechanism {
        id: "environment-d",
        name: "systemd environment.d",
        category: Category::Login,
        why: "systemd folds these into every user session's environment, so a single \
              LD_PRELOAD line injects a library into everything that user runs — and it \
              is nowhere near the shell startup files anyone thinks to check",
        probe: Probe::FilesIn(&[
            "/etc/environment.d",
            "/usr/lib/environment.d",
            "/run/environment.d",
        ]),
    },
    Mechanism {
        id: "environment-d-user",
        name: "per-user environment.d",
        category: Category::Login,
        why: "the same session-wide injection, owned by the user and needing no \
              privilege to plant",
        probe: Probe::PerUser(&[".config/environment.d"]),
    },
    Mechanism {
        id: "pam-env",
        name: "pam_env environment",
        category: Category::Login,
        why: "pam_env sets these variables at every authentication, so an LD_PRELOAD \
              here reaches every login session — and it sits outside /etc/pam.d, where \
              a PAM review usually stops",
        probe: Probe::Files(&["/etc/security/pam_env.conf"]),
    },
    Mechanism {
        id: "pam-env-user",
        name: "per-user pam_env file",
        category: Category::Login,
        why: "the per-user half of pam_env, still honoured on several distributions and \
              writable by the user it runs for",
        probe: Probe::PerUser(&[".pam_environment"]),
    },
    Mechanism {
        id: "ssh-rc",
        name: "sshd login script (sshrc)",
        category: Category::Login,
        why: "sshd executes /etc/ssh/sshrc on every successful login, before the shell \
              starts. It is execution on authentication without touching authorized_keys \
              or sshd_config, which is exactly where everyone looks instead",
        probe: Probe::Files(&["/etc/ssh/sshrc"]),
    },
    Mechanism {
        id: "ssh-rc-user",
        name: "per-user sshd login script",
        category: Category::Login,
        why: "the same hook owned by the user: ~/.ssh/rc runs at their every ssh login \
              and needs no privilege to plant",
        probe: Probe::PerUser(&[".ssh/rc"]),
    },
    Mechanism {
        id: "shell-user",
        name: "per-user shell startup files",
        category: Category::Login,
        why: "runs as that user at every shell or login, and is owned by them so it \
              needs no privilege to plant",
        probe: Probe::PerUser(&[
            ".bashrc",
            ".bash_profile",
            ".bash_login",
            ".bash_logout",
            ".profile",
            ".zshrc",
            ".zshenv",
            ".zprofile",
            ".zlogin",
            ".config/fish/config.fish",
        ]),
    },
    Mechanism {
        id: "motd-update",
        name: "dynamic MOTD scripts",
        category: Category::Login,
        why: "executables run as root on every SSH login to build the message of the \
              day — an execution point most reviews never open",
        probe: Probe::FilesIn(&["/etc/update-motd.d"]),
    },
    Mechanism {
        id: "xdg-autostart",
        name: "desktop autostart entries",
        category: Category::Login,
        why: "runs when a graphical session begins, for the user who logs in",
        probe: Probe::FilesIn(&["/etc/xdg/autostart"]),
    },
    Mechanism {
        id: "xdg-autostart-user",
        name: "per-user desktop autostart",
        category: Category::Login,
        why: "the same, owned by the user and needing no privilege",
        probe: Probe::PerUser(&[".config/autostart"]),
    },

    Mechanism {
        id: "ld-preload",
        name: "/etc/ld.so.preload",
        category: Category::Linker,
        why: "forces a library into every dynamically-linked process on the host — \
              the install point for a userland rootkit, and normally absent, so any \
              content at all is worth explaining",
        probe: Probe::Files(&["/etc/ld.so.preload"]),
    },
    Mechanism {
        id: "ld-so-conf",
        name: "dynamic linker search path",
        category: Category::Linker,
        why: "a directory prepended to the library search path lets an attacker \
              shadow a legitimate library without touching it",
        probe: Probe::Files(&["/etc/ld.so.conf"]),
    },
    Mechanism {
        id: "ld-so-conf-d",
        name: "/etc/ld.so.conf.d",
        category: Category::Linker,
        why: "the drop-in form of the same thing",
        probe: Probe::FilesIn(&["/etc/ld.so.conf.d"]),
    },

    Mechanism {
        id: "modules-load",
        name: "modules loaded at boot",
        category: Category::Kernel,
        why: "names a kernel module to load on every boot, which is how a malicious \
              module survives a reboot",
        probe: Probe::Files(&["/etc/modules"]),
    },
    Mechanism {
        id: "modules-load-d",
        name: "/etc/modules-load.d",
        category: Category::Kernel,
        why: "the drop-in form of the same thing",
        probe: Probe::FilesIn(&["/etc/modules-load.d", "/usr/lib/modules-load.d"]),
    },
    Mechanism {
        id: "modprobe-d",
        name: "/etc/modprobe.d",
        category: Category::Kernel,
        why: "an `install` directive runs an arbitrary command instead of loading a \
              module, so this is an execution point and not merely configuration",
        probe: Probe::FilesIn(&["/etc/modprobe.d", "/usr/lib/modprobe.d"]),
    },
    Mechanism {
        id: "sysctl-d",
        name: "sysctl drop-ins",
        category: Category::Kernel,
        why: "not execution, but where `kptr_restrict`, `dmesg_restrict` and \
              `yama.ptrace_scope` get weakened to prepare for something else",
        probe: Probe::FilesIn(&["/etc/sysctl.d", "/usr/lib/sysctl.d"]),
    },
    Mechanism {
        id: "binfmt",
        name: "binfmt_misc interpreters",
        category: Category::Kernel,
        why: "registers an interpreter the kernel invokes for files matching a magic \
              value — execution triggered by opening an ordinary-looking file",
        probe: Probe::FilesIn(&["/etc/binfmt.d", "/usr/lib/binfmt.d"]),
    },

    Mechanism {
        id: "ssh-authorized-keys",
        name: "SSH authorized_keys",
        category: Category::Auth,
        why: "the single most common Linux persistence: one line grants a login that \
              survives every password rotation",
        probe: Probe::PerUser(&[
            ".ssh/authorized_keys",
            ".ssh/authorized_keys2",
        ]),
    },
    Mechanism {
        id: "sshd-config",
        name: "sshd configuration",
        category: Category::Auth,
        why: "`AuthorizedKeysCommand`, `ForceCommand` and a permissive \
              `PermitRootLogin` each turn the SSH daemon itself into the backdoor",
        probe: Probe::Files(&["/etc/ssh/sshd_config"]),
    },
    Mechanism {
        id: "sshd-config-d",
        name: "sshd drop-in configuration",
        category: Category::Auth,
        why: "the same directives, in a fragment that an inspection of the main file \
              will not show",
        probe: Probe::FilesIn(&["/etc/ssh/sshd_config.d"]),
    },
    Mechanism {
        id: "pam",
        name: "PAM stacks",
        category: Category::Auth,
        why: "a `pam_exec` line runs a command on every authentication, and a swapped \
              module authenticates anybody",
        probe: Probe::FilesIn(&["/etc/pam.d"]),
    },
    Mechanism {
        id: "sudoers",
        name: "sudoers and sudoers.d",
        category: Category::Auth,
        why: "a NOPASSWD rule is a privilege-escalation path that looks like \
              administration",
        probe: Probe::Files(&["/etc/sudoers"]),
    },
    Mechanism {
        id: "sudoers-d",
        name: "/etc/sudoers.d",
        category: Category::Auth,
        why: "the drop-in form, and the one an audit of /etc/sudoers misses",
        probe: Probe::FilesIn(&["/etc/sudoers.d"]),
    },

    Mechanism {
        id: "mail-aliases",
        name: "mail aliases",
        category: Category::Event,
        why: "an alias whose target begins with a pipe runs a command every time mail \
              arrives for that address, which hands execution to anyone who can send \
              the host an email",
        probe: Probe::Files(&["/etc/aliases", "/etc/mail/aliases", "/etc/postfix/aliases"]),
    },
    Mechanism {
        id: "mail-forward",
        name: "per-user mail forwarding",
        category: Category::Event,
        why: "a ~/.forward containing a pipe runs a command on every delivery to that \
              user, and the file is theirs to write",
        probe: Probe::PerUser(&[".forward"]),
    },
    Mechanism {
        id: "rsyslog",
        name: "rsyslog configuration",
        category: Category::Event,
        why: "an omprog action, or a legacy ^program action, executes a binary for \
              matching log lines — persistence that fires whenever the attacker can \
              make something log",
        probe: Probe::Files(&["/etc/rsyslog.conf"]),
    },
    Mechanism {
        id: "rsyslog-d",
        name: "rsyslog drop-ins",
        category: Category::Event,
        why: "the drop-in form of the same thing, and the place a new rule is least \
              likely to be noticed",
        probe: Probe::FilesIn(&["/etc/rsyslog.d"]),
    },
    Mechanism {
        id: "systemd-sleep",
        name: "systemd suspend/resume hooks",
        category: Category::Event,
        why: "every script here runs on suspend and again on resume — a laptop or \
              workstation reaches it routinely, and almost nobody audits it",
        probe: Probe::FilesIn(&[
            "/usr/lib/systemd/system-sleep",
            "/lib/systemd/system-sleep",
            "/etc/systemd/system-sleep",
        ]),
    },
    Mechanism {
        id: "systemd-shutdown",
        name: "systemd shutdown hooks",
        category: Category::Event,
        why: "runs as the host goes down, which is the last code to execute and a good \
              place to re-plant whatever was removed while it was up",
        probe: Probe::FilesIn(&[
            "/usr/lib/systemd/system-shutdown",
            "/lib/systemd/system-shutdown",
            "/etc/systemd/system-shutdown",
        ]),
    },
    Mechanism {
        id: "networkd-dispatcher",
        name: "networkd-dispatcher hooks",
        category: Category::Event,
        why: "the systemd-networkd counterpart of the NetworkManager dispatcher: a \
              script per link state, run every time an interface comes up",
        probe: Probe::TreeUnder(&["/etc/networkd-dispatcher"]),
    },
    Mechanism {
        id: "udev-rules",
        name: "udev rules",
        category: Category::Event,
        why: "a `RUN+=` rule executes as root when a device event fires, which an \
              attacker can trigger on demand",
        probe: Probe::FilesIn(&["/etc/udev/rules.d", "/usr/lib/udev/rules.d", "/run/udev/rules.d"]),
    },
    Mechanism {
        id: "networkmanager-dispatcher",
        name: "NetworkManager dispatcher scripts",
        category: Category::Event,
        why: "runs as root on every interface up or down — a reliable trigger that \
              fires on reboot and on reconnect",
        probe: Probe::FilesIn(&["/etc/NetworkManager/dispatcher.d"]),
    },
    Mechanism {
        id: "dbus-services",
        name: "D-Bus activatable services",
        category: Category::Event,
        why: "names a binary the bus will start on demand when a message arrives, so \
              nothing is running until the attacker asks for it",
        probe: Probe::FilesIn(&[
            "/usr/share/dbus-1/system-services",
            "/usr/share/dbus-1/services",
            "/etc/dbus-1/system.d",
        ]),
    },
    Mechanism {
        id: "polkit-rules",
        name: "polkit rules",
        category: Category::Event,
        why: "a rule granting an action to an unprivileged user is a quiet \
              escalation path",
        probe: Probe::FilesIn(&["/etc/polkit-1/rules.d", "/usr/share/polkit-1/rules.d"]),
    },
    Mechanism {
        id: "logrotate",
        name: "logrotate configuration",
        category: Category::Event,
        why: "a `postrotate` block runs as root on a schedule, inside a file nobody \
              reads as an execution point",
        probe: Probe::FilesIn(&["/etc/logrotate.d"]),
    },

    Mechanism {
        id: "pkg-hooks",
        name: "package-manager hooks",
        category: Category::Package,
        why: "runs as root every time software is installed or updated, including \
              during remediation",
        probe: Probe::FilesIn(&[
            "/etc/apt/apt.conf.d",
            "/etc/dpkg/dpkg.cfg.d",
            "/etc/pacman.d/hooks",
            "/usr/share/libalpm/hooks",
            "/etc/yum/pluginconf.d",
            "/etc/dnf/plugins",
        ]),
    },
];
