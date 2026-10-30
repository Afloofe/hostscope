# The findings console

`hemostat` with no verb, on a terminal, and `hemostat console` open this view. Every detection sweep runs once and the findings are listed worst first. Nothing is swept again until you ask (r): a sweep reads a lot of the host, and doing it on a timer is noise on a machine you are meant to observe quietly.

## Findings tab

- The header counts CRITICAL, WARN and note findings and says when the sweep ran.
- The list title names any sweep that DID NOT RUN or was NOT FULLY SEARCHED. A host where a sweep could not run has not been examined, whatever the count says.
- The DETAIL pane below shows what the selected finding is, why it was raised, and its remedy if it has one: "f fix [risk]: what it does".

## Evidence tab

Everything known about the selected finding, untruncated: the subject, what and why in full, the paths and PIDs to go and look at, the remedy, and the coverage gaps. Up and down (k and j) move to the previous and next finding; the wheel, J and K, and the scrollbar scroll the text.

On Linux every sweep the console shows (the first, each r, and the re-sweep after a fix) is sealed into its own store under /var/lib/hemostat/evidence, one at a time, in the background. The evidence rows say which recovery key the stores are wrapped to and what each seal came to; a seal that failed is a WARN for the rest of the session. With no $HEMOSTAT_RECOVERY_PUBKEY set and none built in, a key is minted: it is in the evidence row and the footer, and printed again when the console closes. Write it down and take it off the host: it is the only key that reads those stores. Quitting waits up to 10 seconds for a seal in progress and begins no other; a seal still being written then is cut off, and the console names the store it left incomplete.

## Fixing a finding

Most findings have no remedy, and that is correct: a rootkit is not a setting to flip. Where there is one:

- f (or [f Fix]) opens the APPLY? screen. It shows the risk first, then what will be done, what it costs, and how to undo it. Nothing has changed yet.
- y applies. Any other key cancels, including q and Esc: the reflex that closes a dialog must never be the one that changes the host.
- With the mouse: only [y Apply] applies. A click anywhere else cancels. [Apply] is never placed where [Fix] was, and clicks in the first moment after the dialog opens are ignored, so a double-click on [Fix] cannot apply anything.
- After applying, the console sweeps again and the verdict comes from that sweep, not from the write. "STILL PRESENT" means the change was made and the problem is still there. "CANNOT be confirmed" means the sweep that would have seen it did not run. "NOT YET IN EFFECT" means a reboot or a service restart is still needed.
