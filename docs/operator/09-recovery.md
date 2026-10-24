# Recovery

HEMOSTAT puts the terminal back when it exits or panics: raw mode off, mouse reporting off, the normal screen and cursor back. If the session was killed instead (a dropped SSH link, a kill -9), the terminal can be left not echoing, not scrolling, or printing junk when the mouse moves.

- Type `reset` and press Enter, even if you cannot see it. Or `stty sane`, then `tput rmcup`.
- If mouse movement prints characters, turn mouse reporting off: `printf '\e[?1000l\e[?1002l\e[?1003l\e[?1006l'`.
- On Windows, close the console window and open a new one.
- Then run the view again: nothing it shows is lost by quitting, and the console re-sweeps when it opens.

If an applied remedy turns out to be wrong, its undo is on the APPLY? screen and in its journal. `hemostat undo <JOURNAL>` replays it.
