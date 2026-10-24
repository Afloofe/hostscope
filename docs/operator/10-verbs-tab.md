# The Verbs tab

Every view has a Verbs tab (v, or click it): every verb this platform has, so nothing needs a shell. A run is the CLI itself, started by the view with the flags you set: the same code, the same Response Broker, the same ticket, policy, journal and undo, and the same exit code, shown in words at the top of the output.

## The list

- Each row is a verb and what running it does: read, watch, writes, ACTS (changes the host, dry run first) or CHANGES (changes the host and has no dry run of its own).
- A verb this image does not have is dimmed with the reason (NOT-BUILT, and the module). It can be opened and read, and it runs nothing.
- Enter, or a click on the selected row, opens its flags. [t Ticket] chooses the ticket a run presents as $HEMOSTAT_TICKET: as the view started, none, or a file.

## Setting flags

- Up and Down select a field; Enter, e, or a click on the selected field sets it. A switch toggles. A value opens its choices: F2 to F7 (or a click) fill one in, PgUp and PgDn page through more, and the typing keys or the on-screen keyboard edit it. Enter sets it, Esc leaves it as it was, x clears it.
- A value can never start with a dash: it would be read as a flag. Flags are set one field each.
- The line under the fields is exactly what will run.

## Running

- read and watch: [r Run]. A watch prints until it ends or you press [s Stop]. A read can be stopped too.
- writes: [r Run] asks first, then runs. It writes evidence, a ledger record, a key or a ticket; it changes no setting of the host.
- ACTS: [d Dry run] runs the verb without arming it. Its plan is the output. [a Arm] is offered only once that dry run ended as a plan (exit 0 or 5), and only for exactly those flags: change one and you have to dry-run again. [a Arm] asks APPLY? and only y, or a click on [Apply], runs it armed. [Apply] is never where the button you pressed was, and a click on it in the first 400 ms is ignored.
- CHANGES (undo, fw confirm, sentinel --register, network --confirm and --revert): [r Run] shows the exact command and asks APPLY?.
- An armed run, or one that writes, is never stopped halfway and the view will not quit under it.
- Nothing is chained. A run ending never starts another one.

## Rollback windows

- An armed network ruleset rolls itself back at the end of its window unless kept; a pf block is lifted at its deadline unless confirmed. While one is open its countdown is on the tab bar of every tab and on top of the Verbs tab.
- [p Keep] keeps it (network --confirm, or fw confirm with the block's id) and [u Revert] puts it back now (network --revert, or undo with the id). Each asks APPLY? first. Check a second way in works before you keep a ruleset.
- When the window runs out the view says so and runs nothing: the host's own rollback is what acts then. Quitting while one is open asks twice, and leaving does not keep the change.

## What is not here

- selfprotect --arm holds a deny over the process that runs it, so it is run at a terminal. sentinel --guard and --watch make the process that runs them a supervisor; sentinel --register starts proper ones from here.
- The views themselves: the Findings console, the Posture view and the collector's queue. Each has a print-once entry (console --once, posture, queue --once).
- The Alerts tab of the queue is where ack, investigating, resolve and note are.
