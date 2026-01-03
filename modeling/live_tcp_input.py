#!/usr/bin/env python3

from scapy.all import sniff, TCP, IP, get_if_addr
import csv
import time
import sys
import os

# =========================
# CONFIGURACIÓN
# =========================
IFACE = sys.argv[1] if len(sys.argv) > 1 else None
MAX_PACKETS = int(sys.argv[2]) if len(sys.argv) > 2 else None

OUTDIR = "./processed_traffic"
TS = time.strftime("%Y%m%d_%H%M%S")
CSV_FILE = f"{OUTDIR}/live_tcp_{TS}.csv"

if not IFACE or not MAX_PACKETS:
    print(f"Uso: sudo {sys.argv[0]} <interfaz> <num_paquetes>")
    sys.exit(1)

# Obtener IP de la interfaz
IFACE_IP = get_if_addr(IFACE)

os.makedirs(OUTDIR, exist_ok=True)

# =========================
# CSV INIT
# =========================
csv_file = open(CSV_FILE, "w", newline="")
writer = csv.writer(csv_file)

writer.writerow([
    "tcp.srcport",
    "tcp.dstport",
    "tcp.flags",
    "tcp.flags_numeric",
    "tcp.window_size_value",
    "type_f",
    "type_n",
    "series_id",
    "instance_id"
])

instance_id = 1
packet_count = 0

print(f"[*] Capturando TCP entrante en {IFACE}")
print(f"[*] IP local interfaz: {IFACE_IP}")
print(f"[*] Máximo paquetes: {MAX_PACKETS}")
print(f"[*] CSV: {CSV_FILE}")
print("[*] Ctrl+C para parar")

# =========================
# FUNCIONES AUXILIARES
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

flags_map = {
    "":0,"S":1,"A":2,"SA":3,"F":4,"FA":5,
    "R":6,"RA":7,"P":8,"PA":9,"FPU":10,
    "FSPU":11,"SEC":12
}

def is_nmap_fingerprint(flags, window):
    return (
        (flags=="S" and window in (1,4,16,63,512,31337)) or
        (flags=="" and window==128) or
        (flags=="FSPU" and window==256) or
        (flags=="FPU" and window==65535) or
        (flags=="A" and window in (1024,32768)) or
        (flags=="SEC" and window==3)
    )

# =========================
# CALLBACK POR PAQUETE
# =========================
def handle_packet(pkt):
    global instance_id, packet_count

    if not pkt.haslayer(TCP) or not pkt.haslayer(IP):
        return

    # DESCARTAR paquetes salientes
    if pkt[IP].src == IFACE_IP:
        return

    tcp = pkt[TCP]

    srcp = tcp.sport
    dstp = tcp.dport
    window = tcp.window or 0
    flags_int = int(tcp.flags)

    flags_str = flags_hex_to_string(flags_int)
    flags_num = flags_map.get(flags_str, 99)

    fingerprint = is_nmap_fingerprint(flags_str, window)

    writer.writerow([
        srcp,
        dstp,
        flags_int,
        flags_num,
        window,
        1 if fingerprint else 0,
        0 if fingerprint else 1,
        1,
        instance_id
    ])

    instance_id += 1
    packet_count += 1

# =========================
# START SNIFFING
# =========================
try:
    sniff(
        iface=IFACE,
        prn=handle_packet,
        filter="tcp",
        store=False,
        stop_filter=lambda pkt: packet_count >= MAX_PACKETS
    )
except KeyboardInterrupt:
    print("\n[*] Captura detenida por usuario")
finally:
    csv_file.close()
    print(f"[*] CSV guardado: {CSV_FILE}")
    print(f"[*] Paquetes capturados: {packet_count}")
