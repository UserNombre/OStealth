# 🛡️ OStealth + AI Fingerprinting Detection

**OS Fingerprinting Evasion and Detection Framework**

This project is composed of three independent but complementary components, designed to demonstrate OS fingerprinting evasion and detection techniques:

1. **OStealth (eBPF)** – Passive OS fingerprint spoofing (p0f only)
2. **AI Module** – Active fingerprinting detection using nmap
3. **Application & Demonstrations** – Dashboard and practical traffic tests

---

## 📌 Recommended Deployment Flow

1. Install and run OStealth
2. Train and execute the AI module
3. Deploy the application (dashboard)
4. Run practical demonstrations (curl, nmap, traffic generation)

---

## 1️⃣ OStealth Installation (Mandatory First Step)

OStealth is a kernel-space eBPF tool that modifies outgoing TCP SYN packets in real time to evade passive OS fingerprinting performed by p0f.

⚠️ **Important:** OStealth only affects p0f. It does not spoof active fingerprinting tools such as nmap.

### 🔧 Requirements (Kali Linux)
```bash
sudo apt update
sudo apt install -y clang llvm libbpf-dev iproute2 tcpdump bpftool
```

### ARM64 Fix (Mac M1/M2 virtual machines)
```bash
sudo ln -sf /usr/include/aarch64-linux-gnu/asm /usr/include/asm
```

### ⚙️ eBPF Program Compilation
```bash
clang -O2 -g -target bpf -c ostealth.c -o ostealth.o
```

Verify the `tc_egress` section exists:
```bash
llvm-objdump -h ostealth.o | grep tc_egress
```

The `-O2` optimization flag is required for the eBPF verifier.

### 🚀 Loading OStealth

**1. Configure the network interface**
```bash
sudo tc qdisc add dev eth0 clsact
```

Replace `eth0` with the appropriate interface (`en0`, `wlan0`, etc.).

**2. Attach the eBPF filter**
```bash
sudo tc filter add dev eth0 egress bpf direct-action \
     obj ostealth.o sec tc_egress verbose
```

**3. Verify installation**
```bash
sudo tc filter show dev eth0 egress
```

### ⚙️ Runtime Spoofing Configuration
```bash
sudo python3 ostealth.py eth0
```

### 🧹 Unloading OStealth
```bash
sudo tc filter del dev eth0 egress
sudo tc qdisc del dev eth0 clsact
```

---

## 2️⃣ AI Module – Active Fingerprinting Detection (Independent)

This module is independent from OStealth. Its purpose is to detect active OS fingerprinting attempts performed with nmap, using a trained machine learning model.

### 📦 Install Dependencies
```bash
pip install -r requirements.txt
```

### 🧠 Model Training

From the `modeling/` directory:
```bash
python3 train.py
```

### ✅ Model Validation
```bash
python3 validation.py
```

### 🔍 Real-Time Prediction
```bash
sudo python3 predict.py iface
```

Interface examples:
- Linux: `eth0`
- macOS: `en0`

### 📊 Output Interpretation
```
[[1 0]] → Fingerprinting detected
[[0 1]] → No fingerprinting detected
```

---

## 3️⃣ Application Deployment (Dashboard)

The application provides a Streamlit-based dashboard to visualize and interact with the system.

### 🐍 Python Virtual Environment
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 🚀 Run the Application
```bash
streamlit run app.py
```

---

## 4️⃣ Practical Demonstrations

### 📡 TCP Traffic Generation (Netcat)

**On the OStealth machine:**
```bash
nc -lvp 1234
```

**On the remote machine:**
```bash
nc <OSTEALTH_MACHINE_IP> 1234
```

### 🌐 CURL Demonstration (Recommended)

Due to forced TCP SYN packet manipulation, curl is more reliable than netcat for observing OS fingerprinting behavior.

**Remote machine:**
```bash
mkdir -p ~/web
echo "WEB de B OK" > ~/web/index.html
cd ~/web
python3 -m http.server 11080 --bind 0.0.0.0
```

**OStealth machine:**
```bash
curl http://localhost:11080/
```

### 🔬 Realistic Traffic Generation
```bash
sudo ./generate_traffic_realistic_scapy_no_nmap.sh 192.168.1.1 eth0 60
```

### 🧪 Active Fingerprinting Test (nmap)
```bash
sudo nmap -O --osscan-guess -Pn -n -F 192.168.0.1
```

---

## 📜 License

GPL – required for the use of eBPF helper functions.
