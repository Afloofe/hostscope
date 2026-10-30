use super::Choices::{Fixed, Live, None as Typed};
use super::Platform::{Collector as C, FreeBsd as F, Linux as L, Portable as P, Windows as W};
use super::{opt, opt_many, pos, pos_many, pos_opt, req, switch, Arm, Commit, Field, Kind, VerbSpec};

const fn v(
    name: &'static str,
    argv: &'static [&'static str],
    platforms: &'static [super::Platform],
    kind: Kind,
    needs: &'static [&'static str],
    fields: &'static [Field],
) -> VerbSpec {
    VerbSpec { name, argv, platforms, kind, needs, fields, arm: None, commit: None, warn: "" }
}

const fn act(
    name: &'static str,
    argv: &'static [&'static str],
    platforms: &'static [super::Platform],
    needs: &'static [&'static str],
    fields: &'static [Field],
    warn: &'static str,
) -> VerbSpec {
    VerbSpec { name, argv, platforms, kind: Kind::Act, needs, fields, arm: Some(Arm::Flag("--arm")), commit: None, warn }
}

const fn change(
    name: &'static str,
    argv: &'static [&'static str],
    platforms: &'static [super::Platform],
    needs: &'static [&'static str],
    fields: &'static [Field],
    warn: &'static str,
) -> VerbSpec {
    VerbSpec { name, argv, platforms, kind: Kind::Change, needs, fields, arm: None, commit: None, warn }
}

use Kind::{Read as R, Watch as Wa, Write as Wr};

const SECS: Choices = Fixed(&["30", "60", "120", "300", "600"]);
type Choices = super::Choices;

const MANIFEST: Field = opt("--manifest", "PATH", Live("manifest"), "the signed vendor manifest to hold the box to");
const META: Field = opt("--meta", "PATH", Live("manifest"), "the signed sidecar (default: beside the manifest)");
const STORE: Field = opt("--store", "DIR", Live("store"), "the sealed store to read or write");
const ROOT: Field = opt("--root", "DIR", Live("store"), "the collector's root (default hemostat-collector)");
const ENGAGEMENT: Field = opt("--engagement", "HEX", Typed, "the engagement id (or $HEMOSTAT_ENGAGEMENT_ID)");
const OPERATOR_KEY: Field =
    opt_many("--operator-key", "SHA256:FP", Typed, "your own key's fingerprint (or $HEMOSTAT_OPERATOR_KEY)");
const ALIAS: Field = req("--alias", "NAME", Fixed(&["HEMOSTAT_OUT", "HEMOSTAT_IN"]), "outbound (HEMOSTAT_OUT) or inbound (HEMOSTAT_IN)");
const PROTECT_CIDR: Field = opt_many("--protect", "CIDR", Typed, "a range that must never be blocked (repeatable)");

pub const REGISTRY: &[VerbSpec] = &[

    v("build-info", &["build-info"], &[P], R, &[], &[]),
    v("probe", &["probe"], &[L, W], R, &[], &[]),
    v("probe", &["probe"], &[F], R, &[], &[MANIFEST, META]),
    v("posture", &["posture"], &[L, W], R, &["mod-tui"], &[]),
    v("posture", &["posture"], &[F], R, &[], &[MANIFEST]),
    v("console --once", &["console", "--once"], &[L, W, F], R, &["mod-tui"], &[]),
    v("hooks", &["hooks"], &[L], R, &[], &[]),

    v("accounts", &["accounts"], &[L, W], R, &[], &[]),
    v("accounts", &["accounts"], &[F], R, &[], &[MANIFEST, STORE, OPERATOR_KEY]),
    v("overview", &["overview"], &[L, W], R, &[], &[]),
    v("overview --export", &["overview", "--export"], &[L], Wr, &[], &[pos("DIR", Live("store"), "the new sealed store for `correlate`'s host half")]),
    v("injected", &["injected"], &[L], R, &[], &[]),
    v("persistence", &["persistence"], &[L, W], R, &[], &[switch("--all", "every catalogued mechanism, the clean ones too")]),
    v("persistence", &["persistence"], &[F], R, &[], &[MANIFEST, STORE]),
    v("rootkit", &["rootkit"], &[L], R, &[], &[]),
    v("syscall-hooks", &["syscall-hooks"], &[L], R, &[], &[]),
    v("ftrace-hooks", &["ftrace-hooks"], &[L], R, &[], &[]),
    v("kernel-posture", &["kernel-posture"], &[L], R, &[], &[]),
    v("kwalk", &["kwalk"], &[L], R, &[], &[]),
    v("kground", &["kground"], &[L], R, &[], &[]),
    v("kmod", &["kmod"], &[L], R, &[], &[]),
    v("bpf-progs", &["bpf-progs"], &[L], R, &[], &[]),
    v("sysmap", &["sysmap"], &[L], R, &[], &[]),
    v("kptr-hooks", &["kptr-hooks"], &[L], R, &[], &[]),
    v("crossview", &["crossview"], &[L], R, &[], &[]),
    v("ps", &["ps"], &[L], R, &[], &[]),
    v("firewall", &["firewall"], &[L], R, &[], &[]),
    act("firewall --allow", &["firewall", "--allow"], &[L], &["mod-enf-net-ingress"], &[
        pos("PORT", Typed, "the scored TCP port to open (additive accept at the top of the input chain)"),
    ], "Opens a port the firewall is blocking so a listening scored service becomes reachable. Additive — it cannot lock anyone out; nftables only; `hemostat undo` removes the rule, matched by its mahoraga comment."),
    v("sysctl", &["sysctl"], &[L], R, &[], &[]),
    v("sshd", &["sshd"], &[L], R, &[], &[]),
    v("trust", &["trust"], &[L], R, &[], &[switch("--all", "every CA, the vendor-shipped ones too"), STORE]),
    v("trust", &["trust"], &[W], R, &[], &[switch("--all", "every CA, the vendor-shipped ones too")]),
    v("trust", &["trust"], &[F], R, &[], &[MANIFEST, STORE]),
    v("suid", &["suid"], &[L], R, &[], &[]),
    v("inventory", &["inventory"], &[L], R, &[], &[]),
    v("ad", &["ad"], &[L], R, &[], &[]),
    v("audit", &["audit"], &[L], R, &["mod-sensor-audit"], &[]),
    v("watchdog", &["watchdog"], &[L], R, &[], &[]),
    v("services", &["services"], &[L], R, &[], &[
        opt_many("--service", "NAME", Live("unit"), "a declared critical service to check (repeatable)"),
        STORE,
    ]),
    act("services --start", &["services", "--start"], &[L], &["mod-enf-persistence"], &[
        pos("UNIT", Live("unit"), "a declared service to enable and start"),
    ], "Only a service you declared (in /etc/hemostat/critical or with --service) can be started; `hemostat undo` restores its prior enabled/active state."),
    act("services --restore", &["services", "--restore"], &[L], &["mod-enf-persistence"], &[
        opt("--every", "SECS", SECS, "run as a watchdog: repeat the restore every SECS, keeping scored services up (dry without --arm)"),
    ],
        "Brings up every DOWN scored service this box owns per the IRSeC packet (needs HEMOSTAT_GOLDEN), each resolved to its installed unit — the uptime auto-recovery path. Names no unit: the roster is the packet's, not yours. A start counts only once the scored port answers; a unit already running with its port shut is left to you; a box it cannot check is NOT CHECKED (exit 7) — HEMOSTAT_ROLE=<role> names the role when the hostname does not. `hemostat undo` restores prior state."),
    act("services --compose-up", &["services", "--compose-up"], &[L], &["mod-enf-persistence"], &[
        pos_many("PROJECT", false, Typed, "the Compose projects to bring up, by the name `docker compose ls` gives them, or a compose file's path (none: list what is down and change nothing)"),
    ],
        "Brings up only the Docker Compose projects named here (grandstand's IRC after a `compose down`), each journaled; a project nobody named is never started, and the run is refused whole if any named one cannot be. A project comes back with every compose file it was started with, each its own -f in order, and is refused if any of them is not a file here. `services --restore` restarts the daemon and restart-policy containers; this brings back a project removed from the daemon. Reversible with `compose down`."),
    act("services --install-watchdog", &["services", "--install-watchdog"], &[L], &["mod-enf-persistence"], &[
        opt("--every", "SECS", SECS, "the watchdog interval (default 30s)"),
    ],
        "Installs the uptime watchdog as a systemd service (mahoraga-watchdog.service, HEMOSTAT_GOLDEN=1 and the policy environment this view runs under, Restart=always) so it survives a reboot or a dropped console. Installing it IS the decision to auto-fix. Refuses a link or a different unit at the path; journaled. Remove with `services --uninstall-watchdog`."),
    act("services --uninstall-watchdog", &["services", "--uninstall-watchdog"], &[L], &[], &[],
        "Stops, disables and removes the uptime watchdog service; the scored services it kept up are left as they are. It is the way out of the auto-fix, so it is in every image, and it is reported done only once nothing of it is left."),
    v("vendor", &["vendor"], &[L, F], R, &[], &[MANIFEST, META]),
    v("allowlist", &["allowlist"], &[L], R, &[], &[opt("--check", "TARGET", Typed, "whether anything suppresses this target")]),
    v("query", &["query"], &[L], R, &["mod-query"], &[pos("SQL", Fixed(&[
        "SELECT pid, exe FROM processes WHERE uid = 0",
        "SELECT * FROM listeners",
    ]), "the query (`--tables` lists what there is)")]),
    v("query --tables", &["query", "--tables"], &[L], R, &["mod-query"], &[]),
    v("correlate", &["correlate"], &[L], R, &["mod-correlation"], &[]),
    v("detect", &["detect"], &[L, W], R, &["mod-detect-sigma"], &[opt("--rules", "DIR", Live("rules"), "a Sigma rule repository; none is compiled in")]),
    v("scan", &["scan"], &[L], R, &["mod-scan-yara"], &[
        pos_many("PATH", false, Live("path"), "files to match (none: every running executable and ld.so.preload)"),
        opt("--rules", "DIR", Live("rules"), "a YARA feed you trust"),
    ]),
    v("export", &["export"], &[L], R, &[], &[pos_opt("FORMAT", Fixed(&["report", "jsonl", "stix", "misp"]), "the handover format (default report)")]),
    v("brief", &["brief"], &[L, W], R, &[], &[]),
    v("drift", &["drift"], &[L, W, F], R, &[], &[STORE]),

    v("watch", &["watch"], &[L], Wa, &[], &[]),
    v("fswatch", &["fswatch"], &[L], Wa, &["mod-sensor-fanotify"], &[
        opt("--seconds", "N", SECS, "how long to watch (default 60)"),
        switch("--all", "every write, not only under the persistence directories"),
    ]),
    v("watchdog --watch", &["watchdog"], &[L], Wa, &[], &[req("--watch", "SECS", SECS, "wait this long and report what respawned")]),
    v("detect --watch", &["detect"], &[W], Wa, &["mod-detect-sigma"], &[
        req("--watch", "SECS", SECS, "the process starts written during the next SECS seconds"),
        opt("--rules", "DIR", Live("rules"), "a Sigma rule repository"),
    ]),
    v("remote", &["remote"], &[L], Wa, &["mod-remote"], &[
        req("--beacon", "HOST:PORT", Typed, "where the heartbeat goes (outbound only)"),
        req("--console-key", "HEX", Typed, "the console's pinned key"),
        opt("--seconds", "N", SECS, "how long to beacon (default 300)"),
    ]),

    act("remediate", &["remediate"], &[L], &["mod-enf-persistence"], &[
        opt_many("--protect", "UNIT", Live("unit"), "a unit that must not be touched (repeatable)"),
        opt_many("--allow-listener", "UNIT", Live("unit"), "a listener that is meant to be there (repeatable)"),
        OPERATOR_KEY,
        switch("--session-key-unknown", "say you cannot name the key your session came in on"),
        switch("--last-admin-key", "allow removing what may be the last admin key"),
    ], "Each removal is moved into the vault and journalled; `hemostat undo <journal>` puts it back. The authentication surface is never removed by this run, and a unit that brings the network up (networking, systemd-networkd, NetworkManager, network, systemd-resolved, wicked, ifup@), its unit file and its drop-ins are never stopped, masked or moved. With HEMOSTAT_GOLDEN set the same holds for the units this box's role runs its scored services in (MariaDB on scrutineering: mariadb, mysqld, mysql), while the service is down too: a finding in one is left to you, to restore the unit from its package by hand."),
    v("remediate --lines", &["remediate", "--lines"], &[L], R, &["mod-enf-persistence"], &[pos("FILE", Live("path"), "a shared file whose lines to list, each with its token")]),
    v("remediate --anchors", &["remediate", "--anchors"], &[L], R, &["mod-enf-persistence"], &[]),
    act("remediate --remove-anchor", &["remediate", "--remove-anchor"], &[L], &["mod-enf-persistence"], &[
        pos("TOKEN", Typed, "the CA's token, from `remediate --anchors`"),
    ], "One CA comes out of the trust store: its file goes into the vault and the store is rebuilt. `hemostat undo <journal>` puts it back and rebuilds again."),
    act("remediate --strip-line", &["remediate", "--strip-line"], &[L], &["mod-enf-persistence"], &[
        pos("TOKEN", Typed, "the line's token, from `remediate --lines`"),
        switch("--auth", "the file is sudoers, PAM, sshd or authorized_keys: needed for those"),
        OPERATOR_KEY,
        switch("--session-key-unknown", "say you cannot name the key your session came in on"),
        switch("--last-admin-key", "allow removing what may be the last admin key"),
    ], "One line comes out of a shared file; the journal holds it, and `hemostat undo <journal>` (with --auth for a login file) puts it back. A sudoers line naming whiteteam or a DataDog account, or someone that cannot be resolved, is refused, and so is every key in the authorized_keys of whiteteam or a DataDog account (one of them owns it, or it is in one's home) or of an account that cannot be told. With HEMOSTAT_GOLDEN set, a line of a unit file or drop-in of this box's scored services is refused too."),
    v("remediate --pam", &["remediate", "--pam"], &[L], R, &["mod-enf-persistence"], &[]),
    v("remediate --log", &["remediate", "--log"], &[L], R, &["mod-enf-persistence"], &[]),
    act("remediate --restore-pam", &["remediate", "--restore-pam"], &[L], &["mod-enf-persistence"], &[
        pos("PATH", Live("path"), "the module path, from `remediate --pam`"),
    ], "The distribution's stock module is written back atomically (owner, mode and SELinux label kept): the build baked for the installed package version, and if none is baked it is refused, naming the baked builds. The current file goes to the vault and `hemostat undo <journal>` restores it. Armed, a throwaway login is tried from an unprivileged account before and after the swap, with the right password and a wrong one; if it got in before and not after, or a wrong password is taken after but was refused before, the swap is rolled back."),

    VerbSpec {
        name: "remediate --seal-binaries",
        argv: &["remediate", "--seal-binaries"],
        platforms: &[L],
        kind: Kind::Write,
        needs: &["mod-enf-persistence"],
        fields: &[switch("--replace", "re-seal over an existing vault (only if the binaries are still known-clean)")],
        arm: None,
        commit: None,
        warn: "Copies this host's critical binaries (scored daemons + su/sudo/sshd/passwd) into /var/lib/hemostat/arrival-bin at arrival — the reliable offline source for a later restore, since the snapshot keeps only hashes and the package cache is usually empty. There is no dry run: Run seals at once, and with --replace overwrites the arrival copies. Read-only on the system; writes only the vault, and refuses a vault that is a link or not root's alone. One that is there and could not be sealed (not a regular file, over the size cap) is listed [skipped] and the run exits 7. A name that is a link (Rocky's /usr/sbin/mariadbd) is sealed once, as the real file it leads to, and listed [link].",
    },
    act("remediate --restore-binary", &["remediate", "--restore-binary"], &[L], &["mod-enf-persistence"], &[
        pos("PATH", Live("path"), "the absolute path of the tampered binary to restore"),
    ], "Writes the arrival copy back over a tampered binary, atomically and attribute-preserving, after sha-verifying the sealed copy against its manifest (a tampered vault is refused). Given a link's name, it writes the real file the link led to when sealed, never through the link, and refuses (exit 4) if the link no longer leads there. The current file goes to the vault and `hemostat undo <journal>` restores it."),
    VerbSpec {
        name: "network",
        argv: &["network"],
        platforms: &[L],
        kind: Kind::Act,
        needs: &["mod-enf-net-ingress"],
        fields: &[
            switch("--egress", "default-deny outbound too, keeping DNS, DHCP, syslog, Wazuh, DataDog and what network-allow declares"),
            opt("--block-pid", "N", Live("pid"), "narrow instead: refuse NEW connections from this process (refused for whiteteam, DataDog, log shippers)"),
            opt("--block-dest", "ADDR", Typed, "narrow instead: refuse NEW connections to this address"),
        ],
        arm: Some(Arm::Window { flag: "--arm", choices: &["60", "120", "300", "600"], default: "120" }),
        commit: Some(Commit::Window {
            what: "the network ruleset",
            keep: &["network", "--confirm"],
            revert: &["network", "--revert"],
            fixed: &["--block-pid", "--block-dest"],
            fixed_secs: 120,
        }),
        warn: "The ruleset rolls itself back at the end of the window unless kept. Open a SECOND connection and check it works before [Keep]. Refused, with nothing applied, if /var/lib/hemostat is a link or anyone but root can write it. A plan that keeps tcp/21 also loads the kernel's FTP conntrack helper, so passive FTP keeps working; a kernel that cannot load it fails the arm, with nothing applied. --block-pid is refused (exit 4) when its cgroup holds a process that belongs to whiteteam or a DataDog account, or whose account cannot be named, or a log shipper.",
    },
    change("network --confirm", &["network", "--confirm"], &[L], &[], &[], "Keeps an armed ruleset: its scheduled rollback will not fire."),
    change("network --revert", &["network", "--revert"], &[L], &[], &[], "Deletes the table the arm added (inet hemostat, or inet hemostat_narrow for a narrowing) and nothing else: firewalld's, ufw's and Docker's tables are left as they are. The run exits 6, naming the `nft delete table` command to run by hand, if the table is still loaded afterwards."),
    act("exec-block", &["exec-block"], &[L], &["mod-enf-exec"], &[
        pos_opt("PATH", Live("path"), "the binary to stop starting again"),
        opt("--pid", "N", Live("pid"), "the binary this process runs"),
        switch("--lift", "remove a block instead"),
    ], "The file is left byte-identical (a bind mount of /dev/null over it); the journal undoes it. Refused for sshd, a listening process's binary, anything a declared service starts, anything a unit of this box's scored services starts with HEMOSTAT_GOLDEN set, or the systemd-networkd and systemd-resolved binaries."),
    act("account", &["account"], &[L], &["mod-enf-account"], &[
        pos("USER", Live("user"), "the account"),
        switch("--end-sessions", "end its sessions"),
        switch("--purge-tickets", "purge its Kerberos tickets"),
        switch("--expire-password", "expire its password"),
        opt("--drop-group", "GROUP", Live("group"), "take it out of this group"),
        switch("--lock", "lock it: disable password and key auth, shell to nologin (reversible)"),
    ], "Account changes are only ever made by you, here or at the CLI: no rule fires them. Name one of the five flags. whiteteam and the DataDog accounts (dd-agent, ddagentuser, datadog) are always refused."),
    act("account --disable", &["account", "--disable"], &[W], &["mod-enf-account"], &[
        pos("USER", Live("user"), "the rogue local user to disable (reversible: net user /active:yes)"),
    ], "Windows only: disables a rogue local user (net user /active:no). Refuses a protected (whiteteam/datadog) or built-in Windows account, the account this session runs as (by SID), and the last enabled administrator."),
    act("kill", &["kill"], &[W], &["mod-enf-proc"], &[
        opt("--pid", "N", Typed, "the PID to terminate"),
        switch("--allow-listener", "it listens and it is the red team's (a bind shell); every other refusal still holds"),
    ], "Windows: terminates a process. Refuses System/Idle, the critical Windows processes, a shared svchost, a scored service's image, DataDog, this session's own processes, one whose image cannot be read, and a listener unless --allow-listener. Irreversible — acquire it first if it is wanted as evidence."),
    act("quarantine", &["quarantine"], &[W], &["mod-enf-file"], &[
        pos("PATH", Live("path"), "the malicious file to move into the vault"),
    ], "Windows: moves a file into the vault, reversible (it prints the command to move it back). Refuses a file under a system or program directory or DataDog's, judged where it really is, and anything but one regular file."),
    act("remediate --remove-task", &["remediate", "--remove-task"], &[W], &["mod-enf-persistence"], &[
        pos("NAME", Typed, "the rogue scheduled task to delete"),
    ], "Windows: deletes a rogue scheduled task after exporting its XML to the vault (reversible: schtasks /create /xml). Refuses Microsoft/system tasks."),
    act("remediate --remove-run", &["remediate", "--remove-run"], &[W], &["mod-enf-persistence"], &[
        pos("NAME", Typed, "the rogue autostart Run value to delete (from `drift`)"),
    ], "Windows: deletes a rogue HKLM/HKCU Run autostart value (reversible: its type and exact data are kept first in an admin-only .reg file, and `reg import` of that file is the undo; a value that cannot be kept exactly is not removed). Refuses a DataDog value."),
    act("remediate --remove-wmi", &["remediate", "--remove-wmi"], &[W], &["mod-enf-persistence"], &[
        pos("NAME", Typed, "the WMI event consumer to remove (from `wmi`)"),
    ], "Windows: removes a permanent-WMI subscription from root\\subscription: the __EventConsumer named exactly NAME, the __FilterToConsumerBinding instances that reference it, and each bound __EventFilter no other binding uses. Killing the payload does not stop it re-firing; this does. Every property and the MOF of each object is written to the fix log first, and nothing is removed if that fails (WMI has no one-command undo). Refuses a NAME with a quote, backtick, $ or control character, and any object that mentions DataDog."),

    VerbSpec {
        name: "remediate --seal-binaries",
        argv: &["remediate", "--seal-binaries"],
        platforms: &[W],
        kind: Kind::Write,
        needs: &["mod-enf-persistence"],
        fields: &[
            pos_many("PATH", false, Live("path"), "extra binaries to seal beyond the present standalone scored-service exes"),
            switch("--replace", "re-seal over an existing vault (only if the binaries are still known-clean)"),
        ],
        arm: None,
        commit: None,
        warn: "Windows: copies this host's present standalone scored-service binaries (DNS, Telnet, IIS, OpenSSH) and any extra PATHs into the admin-only %ProgramData%\\hemostat\\arrival-bin vault at arrival — the offline source for a later restore. There is no dry run: Run seals at once, and with --replace overwrites the arrival copies. Read-only on the system; writes only the vault, and refuses a vault directory it did not make admin-only.",
    },
    act("remediate --restore-binary", &["remediate", "--restore-binary"], &[W], &["mod-enf-persistence"], &[
        pos("PATH", Live("path"), "the absolute path of the tampered binary to restore"),
    ], "Windows: writes the arrival copy back over a tampered binary after sha-verifying the sealed copy against its manifest, and checking again that the vault is admin-only (a tampered or user-owned vault is refused). The tampered binary is renamed aside (kept, not deleted); restart the service to run the clean bytes."),
    v("harden-boot", &["harden-boot"], &[L], R, &[], &[]),
    act("harden-boot --set", &["harden-boot", "--set"], &[L], &["mod-harden-reboot"], &[
        pos("PARAM", Live("boot-param"), "a kernel parameter from the listing"),
    ], "Edits the bootloader config and regenerates it; it takes effect at the next boot."),
    act("kmod --unload", &["kmod", "--unload"], &[L], &["mod-enf-persistence"], &[
        pos("NAME", Live("kmod"), "the hiding module to remove"),
    ], "There is NO journal for this: unloading a module may not be reversible."),
    act("sidecar", &["sidecar"], &[L], &["mod-sidecar"], &[
        req("--install", "NAME", Typed, "the tool"),
        req("--from", "DIR", Live("path"), "where you brought it"),
        req("--sha256", "HEX", Typed, "the digest you declared before you arrived"),
    ], ""),
    act("deceive", &["deceive"], &[L], &["mod-deceive"], &[], "Plants inert honeytokens in home directories, one journal record each."),
    act("deceive --remove", &["deceive", "--remove"], &[L], &["mod-deceive"], &[], "Takes the planted honeytokens away again."),
    v("deceive --list", &["deceive", "--list"], &[L], R, &["mod-deceive"], &[]),
    v("deceive --watch", &["deceive"], &[L], Wa, &["mod-deceive"], &[req("--watch", "SECS", SECS, "hold the tripwire on the planted canaries")]),
    act("acquire", &["acquire"], &[L], &["mod-acquire"], &[
        req("--pid", "N", Live("pid"), "the process"),
        opt("--into", "DIR", Live("store"), "where the artefacts go (default /var/lib/hemostat/acquired)"),
    ], "Writes artefacts into DIR only; the process is not touched."),
    act("uninstall", &["uninstall"], &[L], &[], &[], "Removes the agent's binary and service; LEAVES the evidence store, the undo journals and their snapshots."),
    change("undo", &["undo"], &[L], &[], &[
        pos("JOURNAL", Live("journal"), "the undo journal an armed run printed"),
        switch("--auth", "a stripped line goes back into a login or privilege file"),
    ], "Replays the journal: what it removed goes back. It has no dry run."),
    v("selfprotect", &["selfprotect"], &[L], R, &[], &[]),
    v("sentinel", &["sentinel"], &[L], R, &[], &[]),
    change("sentinel --register", &["sentinel"], &[L], &[], &[
        req("--register", "PID", Live("pid"), "the agent to put back if it is killed"),
        switch("--persist", "also a supervisor that survives a reboot"),
    ], "Starts one sentinel per usable mechanism (transient units, runit); --persist makes one boot-persistent."),

    v("fw rules", &["fw", "rules"], &[F], R, &[], &[MANIFEST, STORE]),
    v("fw flows", &["fw", "flows"], &[F], R, &[], &[
        MANIFEST,
        opt("--dst", "ADDR", Typed, "only flows to this address"),
        opt("--limit", "N", Fixed(&["40", "200", "1000"]), "how many (default 40)"),
    ]),
    v("fw verdict", &["fw", "verdict"], &[F], R, &[], &[
        pos("ADDR[:PORT][/PROTO]", Typed, "the destination"),
        MANIFEST,
        opt("--src", "ADDR", Typed, "only flows from this address"),
    ]),
    v("fw status", &["fw", "status"], &[F], R, &[], &[MANIFEST, META]),
    VerbSpec {
        name: "fw block",
        argv: &["fw", "block"],
        platforms: &[F],
        kind: Kind::Act,
        needs: &["mod-enf-perimeter"],
        fields: &[
            pos("CIDR", Typed, "the range to block"),
            ALIAS,
            req("--tracker", "N", Typed, "the rule's tracker"),
            PROTECT_CIDR,
            MANIFEST,
            META,
            opt("--deadline", "SECS", Fixed(&["60", "120", "300", "600"]), "when the watcher lifts it unless confirmed (default 120)"),
        ],
        arm: Some(Arm::Flag("--arm")),
        commit: Some(Commit::Block {
            what: "the pf block",
            marker: "hemostat fw confirm ",
            deadline: "--deadline",
            default_secs: 120,
            keep: &["fw", "confirm", "--arm"],
            revert: &["undo"],
            carry: &["--manifest", "--meta"],
        }),
        warn: "The block goes live in pf's table and a watcher lifts it at the deadline unless kept. It needs a v2 ticket bound to this alias and range.",
    },
    act("fw confirm", &["fw", "confirm"], &[F], &["mod-enf-perimeter"], &[
        pos("ID", Live("block-id"), "the block `fw block` printed"),
        MANIFEST,
        META,
    ], "Makes a live block persistent: one config.xml revision through pfSense's own PHP, and a filter reload. The deadline no longer lifts it; `undo` with its id does."),
    VerbSpec {
        name: "fw statekill",
        argv: &["fw", "statekill"],
        platforms: &[F],
        kind: Kind::Act,
        needs: &["mod-enf-perimeter-kill"],
        fields: &[pos("CIDR", Typed, "the range whose states to kill"), ALIAS, PROTECT_CIDR, MANIFEST, META],
        arm: Some(Arm::Flag("--arm")),
        commit: None,
        warn: "This CANNOT be undone: every matching pf state is killed (they are sealed first).",
    },
    change("undo", &["undo"], &[F], &[], &[
        pos_opt("ID", Live("block-id"), "one block (none: every one the journal and the box show)"),
        MANIFEST,
        META,
    ], "Lifts what `fw block` applied, now. It has no dry run."),

    v("etw", &["etw"], &[W], R, &[], &[]),
    v("etw --watch", &["etw"], &[W], Wa, &[], &[req("--watch", "SECS", SECS, "open a session and count what arrives")]),
    v("streams", &["streams"], &[W], R, &[], &[pos_many("PATH", false, Live("path"), "where to look")]),
    v("dll-hijack", &["dll-hijack"], &[W], R, &[], &[]),
    v("signature", &["signature"], &[W], R, &[], &[pos_many("PATH", true, Live("path"), "the files, on a local drive (a share is not opened)")]),
    v("com", &["com"], &[W], R, &[], &[]),
    v("usn", &["usn"], &[W], R, &["mod-sensor-usn"], &[opt("--volume", "DRIVE", Fixed(&["C:", "D:", "E:"]), "the volume (default C:)")]),
    v("sysmon", &["sysmon"], &[W], R, &["mod-sensor-sysmon"], &[]),
    v("evtlog", &["evtlog"], &[W], R, &["mod-sensor-evtlog"], &[switch("--quick", "skip the record count")]),
    v("wmi", &["wmi"], &[W], R, &[], &[]),
    v("modules", &["modules"], &[W], R, &[], &[]),

    v("snapshot", &["snapshot"], &[L, W, F], Wr, &[], &[STORE, switch("--replace", "keep the old store renamed and record a new one")]),
    v("collect", &["collect"], &[L], Wr, &["mod-collect"], &[pos_opt("DIR", Live("store"), "the new store (default ./hemostat-evidence)")]),
    v("verify", &["verify"], &[P], R, &[], &[pos("DIR", Live("store"), "the store")]),
    v("read", &["read"], &[P], R, &[], &[pos("DIR", Live("store"), "the store; the key comes from $HEMOSTAT_RECOVERY_KEY as the view started")]),
    v("ship --to", &["ship"], &[L, W], Wr, &["mod-remote"], &[
        pos_many("STORE", true, Live("store"), "the sealed stores"),
        req("--to", "HOST:PORT", Typed, "the pinned collector"),
        req("--collector-key", "HEX", Typed, "its key"),
        req("--receipt-key", "HEX", Typed, "its receipt key"),
        opt("--link-key", "PATH", Live("path"), "this agent's link key"),
        opt("--checkpoints", "DIR", Live("store"), "where receipts are kept"),
    ]),
    v("ship --identity", &["ship", "--identity"], &[L, W], Wr, &["mod-remote"], &[opt("--link-key", "PATH", Live("path"), "this agent's link key")]),

    v("ticket", &["ticket"], &[L, C], Wr, &[], &[
        opt("--op", "OP", Fixed(&["action", "lift", "uninstall", "undo", "export"]), "what it authorizes (default action)"),
        opt("--class", "CLASS", Live("class"), "the action class (needed for --op action)"),
        req("--engagement", "HEX", Typed, "the engagement id"),
        req("--host", "HEX", Typed, "the host id"),
        opt("--ttl", "SECS", Fixed(&["300", "600", "1800", "3600"]), "how long it lasts (default 300)"),
        opt("--out", "FILE", Live("ticket"), "where it goes (default ./hemostat-ticket.bin)"),
        opt("--alias", "NAME", Fixed(&["HEMOSTAT_OUT", "HEMOSTAT_IN"]), "a perimeter class only"),
        opt("--cidr", "NET/LEN", Typed, "a perimeter class only: the one range it may block"),
    ]),
    v("policy", &["policy"], &[L, C], Wr, &[], &[
        req("--engagement", "HEX", Typed, "the engagement id"),
        req("--epoch", "N", Typed, "the policy epoch"),
        req("--allow", "CLASS[,CLASS]", Live("class"), "the classes it permits"),
        opt("--scope", "HOST[,HOST]", Typed, "the host ids"),
        opt("--profile", "it|ot", Fixed(&["it", "ot"]), "the profile (default it)"),
        opt("--bulk", "N", Typed, "the bulk limit (default 10)"),
        opt("--ttl", "SECS", Fixed(&["3600", "14400", "86400"]), "how long it lasts (default 3600)"),
        opt("--out", "FILE", Typed, "where it goes (default hemostat-policy.bin)"),
    ]),
    v("manifest-sign", &["manifest-sign"], &[L, C], Wr, &[], &[
        opt("--in", "PATH", Live("manifest"), "the manifest to sign"),
        opt("--new-key", "PATH", Typed, "create the signing key instead"),
        opt("--manifest", "PATH", Live("manifest"), "the manifest a meta sidecar is bound to"),
    ]),

    v("correlate", &["correlate"], &[C], R, &["mod-collector"], &[
        opt("--fw", "DIR", Live("store"), "the firewall's sealed fw store"),
        opt("--fw-pin", "HEX", Typed, "its seal key"),
        opt("--host", "DIR", Live("store"), "the host's overview --export"),
        opt("--host-pin", "HEX", Typed, "its seal key"),
        MANIFEST,
        opt("--offset", "SECS", Typed, "the host's clock offset"),
        opt("--skew", "SECS", Typed, "the clock skew allowed"),
    ]),
    v("collector ingest", &["collector", "ingest"], &[C], Wr, &["mod-collector"], &[
        pos("DIR", Live("store"), "the media"),
        opt_many("--seal-key", "HEX", Typed, "a seal key to accept (repeatable)"),
        ROOT,
        ENGAGEMENT,
    ]),
    v("collector ingest --spool", &["collector", "ingest", "--spool"], &[C], Wr, &["mod-collector"], &[ROOT, ENGAGEMENT]),
    v("collector ingest --follow", &["collector", "ingest", "--spool", "--follow"], &[C], Wr, &["mod-collector"], &[
        req("--seconds", "N", SECS, "how long to follow the spool"),
        ROOT,
        ENGAGEMENT,
    ]),
    v("collector ledger", &["collector", "ledger"], &[C], R, &["mod-collector"], &[ROOT, ENGAGEMENT]),
    v("collector read-key", &["collector", "read-key"], &[C], Wr, &["mod-collector"], &[ROOT, ENGAGEMENT]),
    v("collector keys", &["collector", "keys"], &[C], Wr, &["mod-collector"], &[ROOT, ENGAGEMENT]),
    v("collector listen", &["collector", "listen"], &[C], Wa, &["mod-collector"], &[
        pos("ADDR:PORT", Fixed(&["0.0.0.0:7443"]), "where to listen"),
        opt("--seconds", "N", SECS, "how long (none: until stopped)"),
        ROOT,
        ENGAGEMENT,
    ]),
    v("enroll", &["enroll"], &[C], Wr, &["mod-collector"], &[
        req("--label", "NAME", Typed, "the host's label"),
        req("--host-id", "HEX", Typed, "its host id"),
        req("--digest", "HEX", Typed, "its binary's digest"),
        opt("--link-key", "HEX", Typed, "its agent link key"),
        ROOT,
        ENGAGEMENT,
    ]),
    v("queue --once", &["queue", "--once"], &[C], R, &["mod-collector"], &[ROOT, ENGAGEMENT, MANIFEST, OPERATOR_KEY]),
    v("queue list", &["queue", "list"], &[C], R, &["mod-collector"], &[ROOT, ENGAGEMENT, MANIFEST, OPERATOR_KEY]),
    v("queue show", &["queue", "show"], &[C], R, &["mod-collector"], &[pos("ID", Typed, "the alert"), ROOT, ENGAGEMENT, MANIFEST, OPERATOR_KEY]),
    v("queue --export", &["queue"], &[C], Wr, &["mod-collector"], &[
        req("--export", "FORMAT", Fixed(&["report", "jsonl"]), "a static HTML page or JSON lines"),
        opt("--out", "FILE", Typed, "a new file (none: printed here)"),
        ROOT,
        ENGAGEMENT,
        MANIFEST,
        OPERATOR_KEY,
    ]),
];

pub const NOT_OFFERED: &[(&str, &str)] = &[
    ("tui", "it is the Posture view itself; its print-once form is the `posture` entry"),
    ("console", "it is the Findings console itself; its print-once form is `console --once`"),
    ("queue", "it is the collector's queue view itself; ack, investigating, resolve and note are its Alerts tab, and `queue --once` prints it"),
    ("console --rules", "a flag of the Windows console when it is launched: the view in front of you already read its rules"),
    ("fw watch", "the watcher `fw block` starts under daemon(8); never run by hand"),
    ("fw --manifest-pubkey", "the watcher's own flag"),
    ("fw block --dry-run", "every run from here is a dry run until [a Arm]; the flag would only say so twice"),
    ("fw statekill --dry-run", "every run from here is a dry run until [a Arm]; the flag would only say so twice"),
    ("fw confirm --dry-run", "every run from here is a dry run until [a Arm]; the flag would only say so twice"),
    ("--allow-subnet", "a block of more than one address is typed at a terminal, on purpose: the view blocks one address at a time"),
    ("network --plan", "the view carries the digest its own dry run printed to the armed run; there is nothing to type"),
    ("selfprotect --arm", "it holds a deny over the process that runs it; run from here that is a child that does nothing else. Run it at a terminal"),
    ("sentinel --guard", "the process that runs it becomes the supervisor; `sentinel --register` from here starts proper ones"),
    ("sentinel --watch", "what a registered supervisor runs, written by `--register`: an agent identity, not an operator flag"),
    ("remote --listen", "removed by RFC-003: an agent never listens"),
    ("services --baseline", "retired"),
    ("queue --as", "the resolution, chosen on the queue's Alerts tab when an alert is resolved there"),
    ("queue --reason", "the reason, typed or chosen on the queue's Alerts tab when an alert is resolved or noted there"),
    ("--json", "the output pane shows the human rendering; scripts use the CLI"),
];
