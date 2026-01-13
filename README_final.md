# 🛡️ OStealth + AI Fingerprinting Detection

**OS Fingerprinting Evasion and Detection Framework**

This project is composed of three independent but complementary components, designed to demonstrate OS fingerprinting evasion and detection techniques:

1. **OStealth (eBPF)** – Passive OS fingerprint spoofing (p0f only)
2. **AI Module** – Active fingerprinting detection using nmap
3. **Application & Demonstrations** – Dashboard and practical traffic tests

---

## 🖥️ System Requirements

⚠️ **This project is specifically designed for Kali Linux and is not portable to other systems.**

### Why Kali Linux Only?

The project has deep dependencies on Kali's kernel and tooling:

- **eBPF kernel module**: Requires Linux kernel ≥4.18 with BPF support, clang with BPF backend, and specific kernel headers.
- **OStealth dependencies**: Traffic Control (tc), clsact qdisc, bpftool, libbpf-dev.
- **Security tools**: p0f, nmap, tcpdump (pre-installed and pre-configured in Kali).
- **Root privileges**: Required for packet manipulation, eBPF loading, and network monitoring.
- **Network stack configuration**: Specific tc filter and qdisc setup.

### Required Installation Path

**The project MUST be installed in:** `/home/kali/OStealth/`

This path is hardcoded in the dashboard application (`app.py`) because:
- The project is already 100% dependent on Kali Linux environment.
- eBPF and network tools operate with absolute paths and root context.
- Hardcoded paths ensure consistency and reproducibility.
- It simplifies setup for evaluation and demonstration purposes.

Attempting to run this on other distributions (Ubuntu, Fedora, macOS, Windows) would require:
- Recompiling eBPF modules for different kernels.
- Installing and configuring p0f, nmap, and network tools manually.
- Resolving sudo/root permission handling differences.
- Significant code refactoring.

**This is not supported and outside the scope of this academic project.**

---

## 📌 Recommended Deployment Flow

1. Clone repository to `/home/kali/OStealth/`
2. Setup Python virtual environment in `/home/kali/OStealth/dashboard/final/`
3. Install and run OStealth (eBPF module)
4. Train and execute the AI module
5. Deploy the application (dashboard)
6. Run practical demonstrations (curl, nmap, traffic generation)
   
---

## 1️⃣ Virtual Environment Setup (Required before AI Module)

⚠️ **Critical:** The virtual environment **must** be created inside `/home/kali/OStealth/dashboard/final/` because:
- The Streamlit application (`app.py`) contains hardcoded absolute paths to this location.
- The dashboard references: `/home/kali/OStealth/dashboard/final/venv/bin/python3`.
- The AI module and dashboard share dependencies and need to access the same models.
- This path consistency is required due to the complex interaction between eBPF, sudo, venv, and Streamlit.

```bash
# Navigate to dashboard directory
cd /home/kali/OStealth/dashboard/final/

# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate

# Install all dependencies (dashboard + AI module)
pip install -r requirements.txt
```
---
**Note:** Keep this virtual environment activated for all subsequent Python operations (AI training and dashboard execution).

## 2️⃣ OStealth Installation (Mandatory First Step)

OStealth is a kernel-space eBPF tool that modifies outgoing TCP SYN packets in real time to evade passive OS fingerprinting performed by p0f.

⚠️ **Important:** OStealth only affects p0f. It does not spoof active fingerprinting tools such as nmap.

### Install dependencies and compile (Kali Linux)
```bash
# Install required packages
sudo apt update
sudo apt install -y clang llvm libbpf-dev iproute2 tcpdump bpftool p0f

# ARM64 Fix (Mac M1/M2 virtual machines only)
sudo ln -sf /usr/include/aarch64-linux-gnu/asm /usr/include/asm

# Navigate to project directory
cd /home/kali/OStealth/

# Compile eBPF program (-O2 optimization required for eBPF verifier)
clang -O2 -g -target bpf -c ostealth.c -o ostealth.o

# Verify tc_egress section exists
llvm-objdump -h ostealth.o | grep tc_egress
```

### Load OStealth
```bash
# Configure network interface (replace eth0 with your interface: en0, wlan0, etc.)
sudo tc qdisc add dev eth0 clsact

# Attach eBPF filter
sudo tc filter add dev eth0 egress bpf direct-action \
     obj ostealth.o sec tc_egress verbose

# Verify installation
sudo tc filter show dev eth0 egress
```

### Configure Runtime Spoofing
Once the eBPF program is loaded, use the Python script to update the configuration map with the desired OS signature.

```bash
# Syntax: sudo python3 ostealth.py <OS_NAME>
# Supported OS: WindowsXP, Windows7, FreeBSD, OpenBSD, Solaris, Linux

sudo python3 ostealth.py WindowsXP
```

### Unload OStealth
```bash
sudo tc filter del dev eth0 egress
sudo tc qdisc del dev eth0 clsact
```
---

## 3️⃣ AI Module – Active Fingerprinting Detection

This module is independent from OStealth. Its purpose is to detect active OS fingerprinting attempts performed with nmap, using a trained machine learning model.

⚠️ **Note:** Ensure the virtual environment from step 2 is activated before proceeding.

### Train and validate model
```bash
# Ensure venv is activated
source /home/kali/OStealth/dashboard/final/venv/bin/activate

# Train model (from modeling/ directory)
cd /home/kali/OStealth/modeling/
python3 train.py

# Validate model
python3 validation.py

# Run real-time prediction (replace eth0 with your interface if needed)
sudo python3 predict.py eth0
```

**Output interpretation:**
- `[[1 0]]` → Fingerprinting detected (Nmap scan)
- `[[0 1]]` → No fingerprinting detected (Normal traffic)

---

## 4️⃣ Application Deployment (Dashboard)

The application provides a Streamlit-based dashboard to visualize and interact with the system.

⚠️ **Note:** Ensure the virtual environment from step 2 is activated before running the dashboard.

```bash
# Navigate to dashboard directory (if not already there)
cd /home/kali/OStealth/dashboard/final/

# Activate virtual environment
source venv/bin/activate

# Run application
streamlit run app.py
```

The dashboard will be accessible at `http://localhost:8501`

### Dashboard Features

- **Defense Layer**: Activate OStealth with different OS profiles (Windows XP/7, Linux, FreeBSD, OpenBSD, Solaris).
- **Inspection Layer**: Run p0f passive fingerprinting tests with automated curl traffic generation.
- **Live Detection**: Real-time AI-powered detection of active nmap fingerprinting attempts.

---

## 5️⃣ Practical Demonstrations

### TCP Traffic Generation (Netcat)
```bash
# On OStealth machine
nc -lvp 1234

# On remote machine
nc <OSTEALTH_MACHINE_IP> 1234
```

### CURL Demonstration (Recommended)

Due to forced TCP SYN packet manipulation, curl is more reliable than netcat for observing OS fingerprinting behavior.
```bash
# On remote machine - setup web server
mkdir -p ~/web
echo "WEB de B OK" > ~/web/index.html
cd ~/web
python3 -m http.server 11080 --bind 0.0.0.0

# On OStealth machine - test connection
curl http://localhost:11080/
```

### Traffic Generation and Fingerprinting Tests
```bash
# Generate realistic traffic
sudo ./generate_traffic_realistic_scapy_no_nmap.sh 192.168.1.1 eth0 60

# Test active fingerprinting with nmap
sudo nmap -O --osscan-guess -Pn -n -F 192.168.0.1
```

---

## 📂 Project Structure
```
OStealth/
├── ostealth.c              # eBPF program source
├── ostealth.o              # Compiled eBPF object
├── ostealth.py             # OStealth configuration script (updates BPF map)
├── modeling/               # AI Module
│   ├── train.py           # Model training
│   ├── validation.py      # Model validation
│   └── predict.py         # Real-time prediction
└── dashboard/
    └── final/             # Dashboard application
        ├── venv/          # Python virtual environment (MUST BE HERE)
        ├── app.py         # Streamlit dashboard
        ├── requirements.txt
        └── inspection.log # Live detection logs (generated at runtime)
```

---

## ⚠️ Known Limitations & Design Decisions

### Absolute Paths
The dashboard (`app.py`) uses hardcoded absolute paths:
- `/home/kali/OStealth/dashboard/final/venv/bin/python3`
- `/home/kali/OStealth/modeling`
- `/home/kali/OStealth/dashboard/final/inspection.log`
- `/home/kali/OStealth/ostealth.log`

**Rationale:**
- The project is already 100% dependent on Kali Linux due to eBPF and network tooling requirements.
- Hardcoded paths provide consistency with the Kali environment where kernel modules and root operations execute.
- The complex interaction between eBPF (kernel space), sudo (elevated privileges), Python venv, and Streamlit (web context) makes relative paths unreliable.
- This design choice prioritizes reproducibility and ease of setup for academic demonstration.

**Impact:** The project requires Kali Linux with exact directory structure `/home/kali/OStealth/`. This is acceptable for a proof-of-concept security research project.

**Future improvement:** For production deployment, this would require containerization (Docker with privileged mode for eBPF) or a proper installer with environment detection and configuration management.

### OStealth Scope
OStealth only affects **passive fingerprinting** (p0f). It does not evade **active fingerprinting** tools like nmap, which send probe packets and analyze responses. The AI module addresses active fingerprinting detection as a complementary defense layer.

---

## 🔧 Troubleshooting

### eBPF Compilation Issues
```bash
# Verify clang BPF support
clang --version | grep -i bpf

# Check kernel headers
ls /usr/src/linux-headers-$(uname -r)/

# Verify bpftool installation
which bpftool
```

### TC Filter Not Loading
```bash
# Remove existing qdiscs
sudo tc qdisc del dev eth0 clsact

# Recreate and reload
sudo tc qdisc add dev eth0 clsact
sudo tc filter add dev eth0 egress bpf direct-action obj ostealth.o sec tc_egress
```

### Virtual Environment Issues
```bash
# Recreate venv if corrupted
cd /home/kali/OStealth/dashboard/final/
rm -rf venv
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Dashboard Not Starting
```bash
# Check if port 8501 is already in use
sudo lsof -i :8501

# Kill existing Streamlit processes
pkill -f streamlit

# Restart dashboard
streamlit run app.py
```

---

## 📜 License

GPL – required for the use of eBPF helper functions and kernel interaction.

---

## 👥 Authors

Academic project for OS Fingerprinting research and demonstration.

---

## 📚 References

- [eBPF Documentation](https://ebpf.io/)
- [p0f - Passive OS Fingerprinting](https://lcamtuf.coredump.cx/p0f3/)
- [nmap OS Detection](https://nmap.org/book/man-os-detection.html)
- [Traffic Control (tc) Man Page](https://man7.org/linux/man-pages/man8/tc.8.html)
