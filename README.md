# hostscope

A single, dependency-free static binary for Linux host inventory and posture
reporting. FreeBSD and Windows builds are in `dist/`. Reads system state and
reports what stands out; read-only by default — any change is previewed and must
be explicitly armed.

## Run

    ./dist/hemostat posture          # overview
    sudo ./dist/hemostat posture     # full detail
    ./dist/hemostat --help

## Build

    cargo build --release -p hemostat-cli --features variant-it-full
