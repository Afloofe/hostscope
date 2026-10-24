# Remedies and their undo

What the console can offer, and how each one is reversed. The APPLY? screen shows the exact undo for the finding in front of you.

## Linux

- /etc/ld.so.preload (safe): the file is moved into the vault. New processes stop loading the library; running ones keep it until they restart. Undo: `hemostat undo <JOURNAL>`, or move the file back out of /var/lib/hemostat/quarantine.
- Kernel tunable (may break something): one key is written at a time to /proc/sys and read back, and recorded in /etc/sysctl.d; if any key in a set fails, the ones already changed are put back. Undo: `hemostat undo <JOURNAL>`, or write the previous value back and delete its line from the drop-in.
- sshd setting (staged; needs a service restart): written to a 00- drop-in and checked with `sshd -T`. The running daemon is NOT restarted; restart it yourself with a second way in open. Undo: delete the drop-in file named on the screen.
- Respawning group (may break something): every member is frozen first, then killed; all of them or none. Undo: a killed process cannot be restarted. A group frozen but not yet killed is resumed by `hemostat undo <JOURNAL>`.
- Empty-password or extra uid-0 account (may break something): locked with usermod -L and the shell set to nologin; nothing it owns is touched. Undo: `usermod -U <user> -s <the shell printed when it was applied>`.
- System account in a privileged group (may break something): removed from that group. Undo: `gpasswd -a <user> <group>`.
- SUID-root binary (may break something): the setuid bit is cleared; the file stays where it is. Undo: `chmod u+s <path>`.
- Catalogued persistence (may break something): removed exactly as `hemostat remediate --arm` would, protect-set included. Undo: `hemostat undo <JOURNAL>`.
- TLS trust anchor nothing vendor-shipped explains (may break something): the one certificate is taken out — its file into the vault, or its PEM block out of a bundle — matched by its SHA-256 and refused if the file changed since the row was drawn; a store source is followed by the distribution's own rebuild (update-ca-certificates, update-ca-trust), refused if the rebuild would change any other certificate. Whatever relied on that CA stops validating. Undo: `hemostat undo <JOURNAL>` puts the file back and rebuilds again.
- A setting that points TLS elsewhere (SSL_CERT_FILE and the like): that one line is taken out of the file that sets it. Undo: `hemostat undo <JOURNAL>`.

## Windows

- WDigest UseLogonCredential (safe): set to 0. Undo: set it back to 1.
- Vulnerable driver blocklist (needs reboot): set to 1; not in force until the host restarts. Undo: set it to 0 and reboot.
- LSA protection (RunAsPPL) is shown but set by hand, not from the console: on a Secure Boot host it cannot be undone locally.

## Risk words

- safe: restores a documented default, takes effect now, no plausible way to take a service down.
- needs reboot: correct and reversible, and does nothing until the host restarts.
- staged; needs a service restart: written and verified, but the running service still uses the old value.
- may break something: real hardening with a real failure mode. Worth doing, not worth doing blind.
