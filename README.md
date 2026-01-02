# OStealth - eBPF-based OS Fingerprint Spoofer
A high-performance Linux kernel-space tool that modifies outgoing TCP SYN packets to evade passive OS fingerprinting by tools like p0f.

## Overview
OStealth uses eBPF (extended Berkeley Packet Filter) attached to the TC (Traffic Control) egress hook to rewrite packet characteristics in real-time, achieving line-rate performance without userspace context switches.

## Installation (Kali Linux)

```
# Install dependencies
sudo apt update
sudo apt install -y clang llvm libbpf-dev iproute2 tcpdump bpftool

# Fix ARM64 header symlink issue (if using Mac ARM)
sudo ln -sf /usr/include/aarch64-linux-gnu/asm /usr/include/asm
```

## Compilation
```
# Compile eBPF program to bytecode
clang -O2 -g -target bpf -c ostealth.c -o ostealth.o

# Verify compilation
llvm-objdump -h ostealth.o | grep tc_egress
```

The -O2 optimization is required for the eBPF verifier to accept the program.

## Usage

### 1. Load the eBPF Program
```
# Replace eth0 with your network interface
sudo tc qdisc add dev eth0 clsact

sudo tc filter add dev eth0 egress bpf direct-action \
     obj ostealth.o sec tc_egress verbose

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

## AI

In order to run all the modules for the AI part, the user needs to install all the requirements with the following commanda.

```
pip install -r requirements.txt
```

For the modules it is a easy command. First go to the folder modeling/ in your computer and run:

```
python3 train.py
```
For the training part.

```
python3 validation.py
```

For the validation part.

```
sudo python3 predict.py iface
```
In the iface replaced with interface you want to listen to eth0 in Linex and Windows or en0 for MACOS.
 sudo ./generate_traffic_realistic_scapy_no_nmap.sh 192.168.1.1 eth0 60


sudo nmap -O --osscan-guess -Pn -n -F 192.168.0.1


[[1 0]] equal fingerprint
[[0 1]] equal no fingerprint
