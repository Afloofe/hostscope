# Severities

- CRITICAL: a rootkit or backdoor is almost certainly present. Treat the host as compromised until you have explained it.
- WARN: a lead. Explain it before you trust the host; many have a legitimate cause, and the finding says what to check.
- note: context, or a check that ran clean. Read them when a CRITICAL needs explaining.

A severity is about the evidence, not about urgency to act: a CRITICAL with no remedy is still CRITICAL. In the collector queue an alert is ranked by the highest grade it ever had; a * beside it means the latest sighting was graded lower, and the detail view says why.

A note can be a stock thing that looks like an implant, lowered by evidence the row names: a persistence line in a file the package manager vouches for as shipped, or the transient unit dbus-broker starts for a packaged bus service (setroubleshoot's, after an SELinux denial) once its program, files and running image check out. The same shape without that evidence keeps its severity. A link to a directory among the files a persistence mechanism reads is named in a note, or a WARN where what reads that directory follows a link by that name (a unit's .d or .wants), and is never counted as a place the sweep could not read.

A missing answer is never shown as a clean one. "unknown", "DID NOT RUN" and "NOT-BUILT" each mean nobody looked, not that nothing was there.

A lead is graded down only on evidence the red team cannot fake cheaply, and it stays on the list as a note that says what vouched for it: the kernel's own bpfilter helper (deleted-executable, Ubuntu 22.04) only when its parent is a kernel thread and its map is the one image the module embeds, with at most the host's C library beside it, and libffi's closure trampolines (memfd-execution, Rocky 9 under SELinux) only when the package manager verifies the program, its script and its libffi unmodified, and a Python program only as a daemon run from /usr/sbin or /usr/libexec with nothing on its command line or in its environment that could load other code. Anything else by the same name keeps its grade.

A named pipe, device, socket or file from another filesystem mounted over a process's file under /proc is refused, never read or waited on: injected names those processes (proc-mount, WARN) and counts the files as not checked, so the sweep exits 7. Another process's own /proc files mounted there are procfs's and are read as they are.

A command a finding suggests names an attacker-chosen file only as a quoted literal (PowerShell's -LiteralPath), after the stream it acts on, so no line of a wrapped command acts on the file alone. One that reads a stream shows its bytes as hex (Format-Hex, in Windows PowerShell 5.1), never as text, so the escape character an attacker's text needs to drive your terminal is shown as a dot. When a name cannot be carried that way (a quote-like or invisible character, a wildcard in a stream name, two spaces in a row, a path that does not start at a drive letter), the finding shows the names as data and suggests no command.
