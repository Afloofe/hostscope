# Verbs a responder needs

`hemostat help` (or --help) prints the full list, with every flag and the exit codes. These are the ones an incident usually needs. Every one of them is also on the Verbs tab of every view, so none of this needs a shell.

## Looking

- `hemostat console`: every sweep in this view. --once prints one frame and exits 7 if a sweep did not run in full.
- `hemostat tui`: the posture view, live. `hemostat probe` and `hemostat build-info` print what the host and the image can do.
- `hemostat persistence`, `hemostat accounts`, `hemostat rootkit`, `hemostat suid`, `hemostat watchdog`, `hemostat overview`: single sweeps, printed.
- `hemostat snapshot` on arrival, then `hemostat drift`: every change since, graded.
- `hemostat trust`: the TLS trust store — every CA the host believes, where it came from, and whether its vendor ships it; a CA added since the snapshot that can sign for any name is CRITICAL. --all lists the distribution's own too.

## Acting (dry run until --arm)

- `hemostat remediate`: a reversible removal for every catalogued persistence finding; --arm applies and writes an undo journal. `remediate --anchors` lists the trust anchors you could remove, and `--remove-anchor <TOKEN>` takes one out and rebuilds the store (Linux).
- `hemostat exec-block <PATH>` or --pid N: stop one binary starting again; --arm applies, --lift removes.
- `hemostat account`: --end-sessions, --purge-tickets, --expire-password, --drop-group G; --arm applies.
- `hemostat network`: the default-deny plan; --arm N applies it with an automatic rollback in N seconds unless you --confirm. --block-pid N and --block-dest ADDR narrow egress instead.
- `hemostat undo <JOURNAL>`: reverse an armed remediation.
- `hemostat ticket --op <OP> --ttl <SECS> --out <FILE>`: mint an authorization ticket; point $HEMOSTAT_TICKET at it.

## Evidence and the collector

- `hemostat collect [DIR]`: the sweeps into a sealed, hash-chained store. `hemostat verify <DIR>` checks it with no key; `hemostat read <DIR>` decrypts it with $HEMOSTAT_RECOVERY_KEY.
- `hemostat ship --to <HOST:PORT> --collector-key <HEX> --receipt-key <HEX> <STORE>...`: push sealed stores to a collector. On the collector, `hemostat collector ingest <DIR>`, then `hemostat queue`.
- `hemostat queue list`, `queue show <ID>`, `queue ack <ID>`, `queue resolve <ID> --as true-positive|false-positive|benign --reason <TEXT>`, `queue note <ID> --reason <TEXT>`: the same triage without the terminal view.

## Exit codes

0 ran · 1 failed · 2 usage · 3 authorization denied · 4 policy refusal · 5 dry run, nothing applied · 6 the enforcer failed (NOT success) · 7 a sweep could not run (partial, not clean) · 8 NOT-BUILT in this variant.
