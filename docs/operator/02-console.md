# The findings console

`hemostat` with no verb, on a terminal, and `hemostat console` open this view. Every detection sweep runs once and the findings are listed worst first. Nothing is swept again until you ask (r): a sweep reads a lot of the host, and doing it on a timer is noise on a machine you are meant to observe quietly.

`hemostat gui` opens this same console drawn by the tool itself, with real buttons, for when a terminal over a web console mangles the keys or the mouse. Mouse and keyboard both work with nothing to turn on. Ctrl and + or - zoom, Ctrl and 0 resets (Alt with them on a Linux console). Everything else is this console: the same sweeps and seals, dry run, [a Arm], APPLY?, journal and undo; q or [q Quit] leaves it.

- On Windows it is a window of its own, on the logged-in desktop or in an RDP session. Leave the console window it was started from open: closing it, or Ctrl+Break in it, ends the GUI and any run it has going. Ctrl+C there stops the first sweep and is ignored once the view is up. A click that only brings the window to the front does nothing else.
- On Linux it takes the machine's own screen: start it as root from the host's text console (Compsole, noVNC, a local screen). Over SSH it refuses and changes nothing. Under sudo, which hides the console behind a pseudo-terminal, give it a console of its own: `sudo openvt -s -w -- /full/path/to/hemostat gui`, which switches back when the GUI ends.
- On Linux every sweep runs on the text console: the first, each r, the one after a fix, each --every. There Ctrl+C ends the GUI at once, without waiting for a seal in progress, and Alt+Fn switches away; the view comes back when the sweep is done, and waits for you if you switched away. While the Verbs tab has a run going or a commit window open, a sweep keeps the view instead, so that no Ctrl+C can reach the run. While the view is up, Alt+Fn does not switch consoles: leave the GUI first.
- If the GUI is killed and its picture stays on the screen, see Recovery.

## Findings tab

- The header counts CRITICAL, WARN and note findings and says when the sweep ran.
- The list title names any sweep that DID NOT RUN or was NOT FULLY SEARCHED. A host where a sweep could not run has not been examined, whatever the count says.
- trust is NOT FULLY SEARCHED when the arrival snapshot is there and was refused (tampered, cut short, over the size cap, or not the one $HEMOSTAT_SNAPSHOT_PUBKEY pins). No CA could then be called added since arrival, so a planted one may show as WARN, not CRITICAL; the gap says why, and `console --once` exits 7. Take a new snapshot only once you know what changed it.
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
