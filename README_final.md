# 🛡️ OStealth + AI Fingerprinting Detection

**OS Fingerprinting Evasion and Detection Framework**

This project is composed of three independent but complementary components, designed to demonstrate OS fingerprinting evasion and detection techniques:

1. **OStealth (eBPF)** – Passive OS fingerprint spoofing (p0f only)
2. **AI Module** – Active fingerprinting detection using nmap
3. **Application & Demonstrations** – Dashboard and practical traffic tests

---

## 📌 Recommended Deployment Flow

1. Install and run OStealth
2. Setup virtual environment: `cd ~/OStealth/dashboard/final/ && python3 -m venv venv && source venv/bin/activate && pip install -r requirements.txt`
3. Train and execute the AI module
4. Deploy the application (dashboard)
5. Run practical demonstrations (curl, nmap, traffic generation)

---

## 1️⃣ OStealth Installation (Mandatory First Step)

OStealth is a kernel-space eBPF tool that modifies outgoing TCP SYN packets in real time to evade passive OS fingerprinting performed by p0f.

⚠️ **Important:** OStealth only affects p0f. It does not spoof active fingerprinting tools such as nmap.

### Install dependencies and compile (Kali Linux)
```bash
# Install required packages
sudo apt update
sudo apt install -y clang llvm libbpf-dev iproute2 tcpdump bpftool

# ARM64 Fix (Mac M1/M2 virtual machines only)
sudo ln -sf /usr/include/aarch64-linux-gnu/asm /usr/include/asm

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

# Configure runtime spoofing
sudo python3 ostealth.py eth0
```

### Unload OStealth
```bash
sudo tc filter del dev eth0 egress
sudo tc qdisc del dev eth0 clsact
```

---

## 2️⃣ Virtual Environment Setup (Required before AI Module)

⚠️ **Critical:** The virtual environment **must** be created inside `~/OStealth/dashboard/final/` because:
- The Streamlit application (`app.py`) contains hardcoded absolute paths to this location
- The dashboard references: `/home/kali/OStealth/dashboard/final/venv/bin/python3`
- The AI module and dashboard share dependencies and need to access the same models
- Changing this location will break the application's functionality
```bash
# Navigate to dashboard directory
cd ~/OStealth/dashboard/final/

# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate

# Install all dependencies (dashboard + AI module)
pip install -r requirements.txt
```

---

## 3️⃣ AI Module – Active Fingerprinting Detection

This module is independent from OStealth. Its purpose is to detect active OS fingerprinting attempts performed with nmap, using a trained machine learning model.

⚠️ **Note:** Ensure the virtual environment from step 2 is activated before proceeding.

### Train and validate model
```bash
# Ensure venv is activated
source ~/OStealth/dashboard/final/venv/bin/activate

# Train model (from modeling/ directory)
cd ~/OStealth/modeling/
python3 train.py

# Validate model
python3 validation.py

# Run real-time prediction (replace iface with eth0, en0, etc.)
sudo python3 predict.py iface
```

**Output interpretation:**
- `[[1 0]]` → Fingerprinting detected
- `[[0 1]]` → No fingerprinting detected

---

## 4️⃣ Application Deployment (Dashboard)

The application provides a Streamlit-based dashboard to visualize and interact with the system.

⚠️ **Note:** Ensure the virtual environment from step 2 is activated before running the dashboard.
```bash
# Navigate to dashboard directory (if not already there)
cd ~/OStealth/dashboard/final/

# Activate virtual environment
source venv/bin/activate

# Run application
streamlit run app.py
```

The dashboard will be accessible at `http://localhost:8501`

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

## 📜 License

GPL – required for the use of eBPF helper functions.
