# OStealth - eBPF-based OS Fingerprint Spoofer
A high-performance Linux kernel-space tool that modifies outgoing TCP SYN packets to evade passive OS fingerprinting by tools like p0f.

## Overview
OStealth uses eBPF (extended Berkeley Packet Filter) attached to the TC (Traffic Control) egress hook to rewrite packet characteristics in real-time, achieving line-rate performance without userspace context switches.

## Installation (Kali Linux)

```
# Install dependencies
sudo apt update
sudo apt install -y clang llvm libbpf-dev iproute2 tcpdump

# Fix ARM64 header symlink issue (if using Mac ARM)
sudo ln -sf /usr/include/aarch64-linux-gnu/asm /usr/include/asm
```

## Compilation
```
# Compile eBPF program to bytecode
clang -O2 -g -target bpf -c ospoof_ebpf.c -o ospoof_ebpf.o

# Verify compilation
llvm-objdump -h ospoof_ebpf.o | grep tc_egress
```

The -O2 optimization is required for the eBPF verifier to accept the program.

## Usage

### 1. Load the eBPF Program
```
# Replace eth0 with your network interface
sudo tc qdisc add dev eth0 clsact

sudo tc filter add dev eth0 egress bpf direct-action \
     obj ospoof_ebpf.o sec tc_egress verbose

# Verify it loaded
sudo tc filter show dev eth0 egress

```

### 2. Configure Spoofing Parameters
```
sudo python3 ostealth.py eth0
```

### 3. Test it

Check using Tcpdump or Wireshark that outbound packets are modified.

### 4. Unload
```
sudo tc filter del dev eth0 egress
sudo tc qdisc del dev eth0 clsact
```

## License
GPL (required for eBPF helper functions)

