# 🛡️ OStealth

1. **eBPF Implementation** - Packet modification engine
2. **Streamlit Dashboard** - Interactive control interface
3. **Remote Machine Demo** - TCP traffic generation and analysis
---

## 1️⃣ eBPF Implementation

### 📥 Load eBPF Program

Configure the queueing discipline:
```bash
sudo tc qdisc add dev eth0 clsact
```

> ⚠️ **Note:** Replace `eth0` with your network interface.

Attach the eBPF filter to egress traffic:
```bash
sudo tc filter add dev eth0 egress bpf direct-action \
     obj ostealth.o sec tc_egress verbose
```

### 🔍 Verification

Verify the eBPF program loaded correctly:
```bash
sudo tc filter show dev eth0 egress
```

### 🧹 Unload OStealth

Stop OStealth and clean up:
```bash
sudo tc filter del dev eth0 egress
sudo tc qdisc del dev eth0 clsact
```

---

## 2️⃣ Streamlit Dashboard

### 🐍 Python Environment Setup

From the dashboard directory:
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 🚀 Run Dashboard

With the virtual environment activated:
```bash
streamlit run app.py
```

---

## 3️⃣ Remote Machine Demo

### 📡 TCP Traffic Generation (Netcat)

**On the OStealth machine:**
```bash
nc -lvp 1234
```

**On the remote machine:**
```bash
nc <OSTEALTH_MACHINE_IP> 1234
```
## 4. CURL TCP for other SO
**Remote machine**
mkdir -p ~/web && echo "WEB de B OK" > ~/web/index.html 
cd ~/web 
python3 -m http.server 11080 --bind 0.0.0.0
**On Stealth machine**
curl http://localhost:11080/
url http://localhost:11080/
Inspect traffic using **p0f** to verify OS fingerprint modification.

---
