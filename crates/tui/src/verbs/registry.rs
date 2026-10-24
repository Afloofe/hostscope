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
    v("kmod", &["kmod"], &[L], R, &[], &[]),
    v("bpf-progs", &["bpf-progs"], &[L], R, &[], &[]),
    v("sysmap", &["sysmap"], &[L], R, &[], &[]),
    v("kptr-hooks", &["kptr-hooks"], &[L], R, &[], &[]),
    v("crossview", &["crossview"], &[L], R, &[], &[]),
    v("ps", &["ps"], &[L], R, &[], &[]),
    v("firewall", &["firewall"], &[L], R, &[], &[]),
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
    ], "Each removal is moved into the vault and journalled; `hemostat undo <journal>` puts it back. The authentication surface is never removed by this run."),
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
    ], "One line comes out of a shared file; the journal holds it, and `hemostat undo <journal>` (with --auth for a login file) puts it back."),
    VerbSpec {
        name: "network",
        argv: &["network"],
        platforms: &[L],
        kind: Kind::Act,
        needs: &["mod-enf-net-ingress"],
        fields: &[
            switch("--egress", "default-deny outbound too, keeping what network-allow declares"),
            opt("--block-pid", "N", Live("pid"), "narrow instead: refuse NEW connections from this process"),
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
        warn: "The ruleset rolls itself back at the end of the window unless kept. Open a SECOND connection and check it works before [Keep].",
    },
    change("network --confirm", &["network", "--confirm"], &[L], &[], &[], "Keeps an armed ruleset: its scheduled rollback will not fire."),
    change("network --revert", &["network", "--revert"], &[L], &[], &[], "Puts the ruleset saved before the arm back now."),
    act("exec-block", &["exec-block"], &[L], &["mod-enf-exec"], &[
        pos_opt("PATH", Live("path"), "the binary to stop starting again"),
        opt("--pid", "N", Live("pid"), "the binary this process runs"),
        switch("--lift", "remove a block instead"),
    ], "The file is left byte-identical (a bind mount of /dev/null over it); the journal undoes it."),
    act("account", &["account"], &[L], &["mod-enf-account"], &[
        pos("USER", Live("user"), "the account"),
        switch("--end-sessions", "end its sessions"),
        switch("--purge-tickets", "purge its Kerberos tickets"),
        switch("--expire-password", "expire its password"),
        opt("--drop-group", "GROUP", Live("group"), "take it out of this group"),
    ], "Account changes are only ever made by you, here or at the CLI: no rule fires them. Name one of the four flags."),
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

    v("fw rules", &["fw", "rules"], &[F], R, &[], &[STORE]),
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
            keep: &["fw", "confirm"],
            revert: &["undo"],
        }),
        warn: "The block goes live in pf's table and a watcher lifts it at the deadline unless kept. It needs a v2 ticket bound to this alias and range.",
    },
    change("fw confirm", &["fw", "confirm"], &[F], &["mod-enf-perimeter"], &[
        pos("ID", Live("block-id"), "the block `fw block` printed"),
        MANIFEST,
        META,
    ], "Makes a live block persistent: one config.xml revision through pfSense's own PHP, and a filter reload."),
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
    v("signature", &["signature"], &[W], R, &[], &[pos_many("PATH", true, Live("path"), "the files")]),
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
    ("selfprotect --arm", "it holds a deny over the process that runs it; run from here that is a child that does nothing else. Run it at a terminal"),
    ("sentinel --guard", "the process that runs it becomes the supervisor; `sentinel --register` from here starts proper ones"),
    ("sentinel --watch", "what a registered supervisor runs, written by `--register`: an agent identity, not an operator flag"),
    ("remote --listen", "removed by RFC-003: an agent never listens"),
    ("services --baseline", "retired"),
    ("queue --as", "the resolution, chosen on the queue's Alerts tab when an alert is resolved there"),
    ("queue --reason", "the reason, typed or chosen on the queue's Alerts tab when an alert is resolved or noted there"),
    ("--json", "the output pane shows the human rendering; scripts use the CLI"),
];
