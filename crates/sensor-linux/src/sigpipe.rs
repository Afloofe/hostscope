pub fn restore_default() {

    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }
}
