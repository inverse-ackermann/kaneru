# kaneru

## *the masscan we have at home* 

This tool is an attempt to build a high-performance TCP SYN port scanner "for cheap" without relying on bespoke drivers and trying to monopolize an entire NIC all to yourself. 
This is made possible thanks to the introduction of the AF_XDP socket family in recent Linux kernel versions. 
What it allows us to do is to roll your own (zero-copy) userspace networking without having to write driver code or messing with other things your OS might want to with the NIC.
It will also work on any new-ish mainline kernel, provided that the driver for your NIC implements the required functionality (which is often true for, say, Intel network cards). 

For general rationale behind XDP sockets, see [the following presentation by Intel](https://archive.fosdem.org/2018/schedule/event/af_xdp/attachments/slides/2221/export/events/attachments/af_xdp/slides/2221/fosdem_2018_v3.pdf).

For now this tool is a crude prototype, the code quality is not great, and I haven't gotten to benchmarking it on proper hardware yet.

## Usage

```bash
kaneru -i <name of the interface, i.e. eth0> -l <ranges of ip/subnet:ports 45.33.32.156/24:22,80,100-10000> # this will scan scanme.nmap.org
```

## Prerequisites

1. Install bpf-linker: `cargo install bpf-linker`

## Building eBPF

```bash
# from ./kaneru-ebpf
cargo build --target=bpfel-unknown-none -Z build-std=core
```


## Building Userspace

This will also rebuild the eBPF code.

```bash
# from ./kaneru
cargo build
```
