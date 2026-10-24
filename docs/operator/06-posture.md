# The posture view

`hemostat tui` opens it live; `hemostat posture` prints it once. It answers what this binary is (version and variant), what this host lets it do (the enforcement tier and each capability, marked measured, inferred or unknown), which LSM hooks a denial could be written against, and what you should act on.

r probes again. It is not done on a timer: probing attaches and detaches a BPF program, which is a strange thing to do on a heartbeat to a host you are observing.
