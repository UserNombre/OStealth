# Dashboard

Streamlit dashboard for p0f.
# OStealth Streamlit Dashboard

This directory contains a **Streamlit-based dashboard** used to visualize and monitor
the behavior of p0f.

⚠️ **Important**:  
This dashboard is **only a frontend / visualization layer**.  
The actual fingerprinting, packet inspection, and spoofing logic happens **outside**
of Streamlit (kernel module, eBPF, system tools).

## System requirements

This project is intended to run on **Kali Linux**.

```bash
sudo apt update
sudo apt install -y p0f nmap git python3 python3-venv python3-pip
