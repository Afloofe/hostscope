# Recovery

HEMOSTAT puts the terminal back when it exits or panics: raw mode off, mouse reporting off, the normal screen and cursor back. If the session was killed instead (a dropped SSH link, a kill -9), the terminal can be left not echoing, not scrolling, or printing junk when the mouse moves.

- Type `reset` and press Enter, even if you cannot see it. Or `stty sane`, then `tput rmcup`.
- If mouse movement prints characters, turn mouse reporting off: `printf '\e[?1000l\e[?1002l\e[?1003l\e[?1006l'`.
- On Windows, close the console window and open a new one.
- Then run the view again: nothing it shows is lost by quitting, and the console re-sweeps when it opens.

`hemostat gui` on a Linux console puts the console back the same way, from every signal that can be caught as well. A kill -9 cannot be caught, and leaves the GUI's last picture on the screen with the keyboard going nowhere you can see:

- Press Alt+F2, then Alt+F1. While the GUI held the console it held every switch; once it is gone the kernel lets the switch through and gives the console back in text mode.
- If the picture is still there after that, type the command that started the GUI again, even though you cannot see it, and quit it with q once it is up: giving the console back redraws it.
- If it is stuck but not dead (stopped, or in a sweep a hostile host never answers), end it from another session first: `kill -KILL <PID>`. From SSH, `chvt 2` then `chvt 1` do what Alt+F2 and Alt+F1 do.
- On Windows, end it with Task Manager; closing the console window it was started from ends it too.

If an applied remedy turns out to be wrong, its undo is on the APPLY? screen and in its journal. `hemostat undo <JOURNAL>` replays it.
