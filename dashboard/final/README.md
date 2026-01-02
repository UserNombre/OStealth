🛡️ OStealth – README

OStealth is a network fingerprint obfuscation and evasion system based on eBPF, complemented by a Streamlit dashboard that allows interactive control and verification of network behavior.

The project is composed of three main components:

OStealth eBPF implementation

Streamlit control dashboard

Remote machine demonstration using TCP traffic

1️⃣ OStealth Implementation (eBPF)

OStealth uses an eBPF program attached to the Linux Traffic Control (tc) subsystem to intercept and modify outbound (egress) network packets.
This allows the system to hide or alter operating system network signatures.

📥 Loading the eBPF Program

⚠️ Replace eth0 with the correct network interface for your system.

sudo tc qdisc add dev eth0 clsact


Attach the eBPF filter to outbound traffic:

sudo tc filter add dev eth0 egress bpf direct-action \
     obj ostealth.o sec tc_egress verbose

🔍 Verification

To verify that the eBPF program was loaded correctly:

sudo tc filter show dev eth0 egress

🧹 Unloading OStealth

To stop OStealth and clean up the system configuration:

sudo tc filter del dev eth0 egress
sudo tc qdisc del dev eth0 clsact


This removes the eBPF filter and the associated queue discipline from the interface.

2️⃣ Streamlit Control Dashboard

The project includes an interactive Streamlit dashboard that allows users to:

Launch OStealth with different OS fingerprints

Run traffic inspections using p0f

Visually confirm OS detection results in real time

🐍 Python Environment Setup

From the dashboard directory:

python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt


This creates an isolated Python environment with all required dependencies.

🚀 Running the Dashboard (Streamlit)

With the virtual environment activated:

streamlit run app.py


Once started, the dashboard will be available in the browser and can be used to control OStealth through a graphical interface.

3️⃣ Remote Machine Demonstration

To demonstrate OStealth in action, real TCP traffic can be generated from a remote machine and analyzed to observe how OS fingerprinting is altered.

📡 TCP Traffic Generation (Netcat Example)
On the machine running OStealth

Start a TCP listener on a chosen port:

nc <OSTEALTH_MACHINE_IP> 1234

On the remote machine

Connect to the OStealth machine:

sudo nc -lvp 1234

This TCP traffic can be inspected using tools such as p0f to verify how OStealth modifies network signatures and misleads operating system detection.
