# Getting around

Every HEMOSTAT terminal view works with the keyboard alone and with the mouse alone. A red team that takes one away has not taken the console. The mouse needs one step first: start the console with `HEMOSTAT_MOUSE=1` (see When the mouse does nothing).

- The top row is the tab bar. Click a tab, press its number, or use Tab and Shift-Tab. F1 or ? opens these docs from anywhere.
- Every view has a Verbs tab (v): every verb the CLI has, with its flags set from choices or the on-screen keyboard, dry run first for anything that changes the host.
- The bottom rows are buttons. Each one shows its key first: [r Rescan] is the r key or a click.
- Click a row to select it. The wheel scrolls. Panes that run long have a scrollbar on their right edge: click its arrows to move a line, or the track above or below the thumb to move a page.
- q quits from every view except while you are typing text, where every key is text.

## Docs tab

- Contents is on the left (t hides or shows it). Click a heading to jump to it, or use [ and ] for the previous and next section.
- / searches (Enter to search, Esc to stop), n and N go to the next and previous match. With the mouse, [/ Find] opens the same search with an on-screen keyboard.

## When the mouse does nothing

Mouse capture is off unless the console was started with HEMOSTAT_MOUSE=1 in its environment, for example `sudo HEMOSTAT_MOUSE=1 ./hemostat`. Over a VNC or SPICE console (a Proxmox noVNC window) the terminal reports every mouse movement and the view redraws on each one, so with capture on it churns or looks stuck; that is why it is off by default. It cannot be turned on from inside a running console, so if the keyboard may be taken away, start the console with it before you need the mouse.

A bare Linux virtual console (the text console on the machine's own screen, with no mouse daemon such as gpm running) delivers no mouse events to programs at all. Use the keyboard there. SSH sessions in an xterm-compatible terminal, tmux and screen with mouse support on, and the Windows Console all deliver clicks and the wheel.

Some terminals send no wheel events, or keep the wheel for their own scrollback. The scrollbar arrows and the track do the same thing as the wheel.
