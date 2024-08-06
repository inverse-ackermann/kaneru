# kaneru

## *the masscan we have at home* 

## Prerequisites

1. Install bpf-linker: `cargo install bpf-linker`

## Build eBPF

```bash
# from ./kaneru-ebpf
cargo build --target=bpfel-unknown-none -Z build-std=core
```

To perform a release build you can use the `--release` flag.
You may also change the target architecture with the `--target` flag.

## Build Userspace

```bash
cargo build
```
