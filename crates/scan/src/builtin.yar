rule hemostat_bash_dev_tcp_shell {
  meta:
    description = "a script that opens a socket through bash's /dev/tcp and wires a shell to it"
  strings:
    $tcp = "/dev/tcp/"
    $sh1 = "0>&1"
    $sh2 = "0<&196"
    $sh3 = "exec 196<>"
  condition:
    $tcp and any of ($sh*)
}

rule hemostat_nc_exec_shell {
  meta:
    description = "netcat or ncat invoked with -e, which hands a shell to whoever connects"
  strings:
    $a = /\bnc(at)?\s+(-[a-zA-Z]*\s+)*-e\s+\/bin\/(ba)?sh/
  condition:
    $a
}

// There is no LD_PRELOAD readdir-hider shape here, on purpose. The one that
// was keyed on the strings dlsym, readdir and RTLD_NEXT, and RTLD_NEXT is a
// macro: a compiled hook never contains its name, so the range's
// /lib/libpreload.so matched nothing. glibc's libc.so.6 carries all three (the
// third in an error message), so it matched libc instead. Telling a hook from
// libc needs the dynamic symbol table — defines readdir, imports dlsym — which
// this engine cannot read without yara-x's elf module, and that rule has to be
// calibrated on the range against the implant and against libc, libasan and
// libtsan before it ships. `rootkit` flags /etc/ld.so.preload itself.

rule hemostat_python_inline_reverse_shell {
  meta:
    description = "the copy-pasted python reverse shell: socket, connect, then dup2 onto the standard descriptors"
  strings:
    $s = "socket.socket"
    $c = "connect(("
    $d = "dup2"
    $e = /pty\.spawn|\/bin\/sh|\/bin\/bash/
  condition:
    all of ($s, $c, $d) and $e
}
