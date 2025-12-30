import os
import csv
import sys
import time
import pickle
import sklearn

import numpy as np

from scapy.all import sniff, TCP

import warnings
warnings.filterwarnings("ignore", category=UserWarning, message=".*feature names.*")


# =========================
# AUXILIARY FUNCTIONS
# =========================
def flags_hex_to_string(flags_int):
    s = ""
    if flags_int & 0x01: s += "F"
    if flags_int & 0x02: s += "S"
    if flags_int & 0x04: s += "R"
    if flags_int & 0x08: s += "P"
    if flags_int & 0x10: s += "A"
    if flags_int & 0x20: s += "U"
    if flags_int & 0x40: s += "E"
    if flags_int & 0x80: s += "C"
    return s

# =========================
# CONSTANTS
# =========================
flags_map = {
    "":0,"S":1,"A":2,"SA":3,"F":4,"FA":5,
    "R":6,"RA":7,"P":8,"PA":9,"FPU":10,
    "FSPU":11,"SEC":12
}

model_path = './models/model.pkl'
with open(model_path, 'rb') as file:
    model = pickle.load(file)

# =========================
# CALLBACK PER PACKET
# =========================
instance_id = 1
def handle_packet(pkt):
    global instance_id
    global model 

    if not pkt.haslayer(TCP):
        return

    tcp = pkt[TCP]

    srcp = tcp.sport
    dstp = tcp.dport
    window = tcp.window or 0
    flags_int = int(tcp.flags)

    flags_str = flags_hex_to_string(flags_int)
    flags_num = flags_map.get(flags_str, 99)

    X_new = np.array([srcp, dstp, flags_int, flags_num,window]).reshape(1, -1)

    predictions = model.predict(X_new)
    print(predictions)

    instance_id += 1

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('Usage: sudo python3 predict.py iface')
        exit(1)
    
    IFACE = sys.argv[1]

    print(f"[*] Capturing in {IFACE}")
        
    # =========================
    # START SNIFFING
    # =========================
    try:
        sniff(
            iface=IFACE,
            prn=handle_packet,
            filter="tcp",
            store=False
        )
    except KeyboardInterrupt:
        print("\n[*] Captura detenida por usuario")
    finally:
        print("\n[*] DONE \n")