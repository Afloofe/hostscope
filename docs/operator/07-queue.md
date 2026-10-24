# The collector queue

`hemostat queue` on the collector: one alert per problem per host, folded from the ledger and every store it holds. It is refused as root, because every triage record names your login.

## Tabs

- Alerts: worst first, then oldest. Enter, or a click on the selected row, or [Enter Open], opens one alert's detail. Esc goes back.
- Hosts: what was heard from each host, and when.
- Clusters: alerts that are about the same thing on different hosts.
- A line in red starting with ! is something the fold could not reconcile in the ledger. It is on every tab until it is resolved; `hemostat queue list` prints them all.

## Triage

- a ack: you have seen it.
- i investigating: you own it now.
- r resolve: choose true-positive (t), false-positive (f) or benign (b), then give a reason. The reason is required: it is what the ledger keeps of the judgement.
- n note: add a note without changing the state.
- g re-reads the ledger and the stores.

Typing a reason: every key is text, Enter records it, Esc cancels and records nothing. With the mouse: click a ready-made reason to fill it in (F2 to F7 do the same from the keyboard), edit it with the on-screen keyboard ([Aa] or Tab switches case, ⌫ erases), then [Enter Submit]. A reason is at most 500 characters.

Nothing here closes, lowers or deletes an alert, and nothing is sent to any host. An alert marked "absent" was not in the latest store; it is shown and never acted on.
