#!/bin/bash

# =====================================================================
#  PROCESADOR TCP PARA DETECTAR FINGERPRINTING (versión corregida)
# =====================================================================
#  - Extrae paquetes TCP desde un PCAP
#  - Filtra opcionalmente por IP atacante
#  - Detecta fingerprinting usando SOLO patrones T1–T7/ECN de Nmap
#  - Elimina heurística SYN+window=1024 que inflaba falsos positivos
# =====================================================================

ATTACKER="${2:-}"              # Opcional: IP atacante
OUTDIR="./processed_traffic"

if [ $# -lt 1 ]; then
    cat << 'EOF'
USO:
  ./process_tcp_only.sh <archivo.pcap> [ip_atacante]

EJEMPLOS:
  ./process_tcp_only.sh traffic.pcap
  ./process_tcp_only.sh traffic.pcap 192.168.1.2
EOF
    exit 1
fi

PCAP_FILE="$1"

if [ ! -f "$PCAP_FILE" ]; then
    echo "❌ Error: Archivo '$PCAP_FILE' no existe"
    exit 1
fi

if ! command -v tshark >/dev/null 2>&1; then
    echo "❌ Error: tshark no está instalado"
    exit 1
fi

mkdir -p "$OUTDIR"

BASENAME=$(basename "$PCAP_FILE" .pcap)
TS=$(date +"%Y%m%d_%H%M%S")
CSV_FILE="${OUTDIR}/${BASENAME}_processed_${TS}.csv"
TMP_CSV="${OUTDIR}/tmp_${BASENAME}_${TS}.csv"

echo "══════ Extrayendo tráfico TCP del PCAP ══════"

tshark -r "$PCAP_FILE" -Y "tcp" \
    -T fields \
    -e frame.number \
    -e ip.src \
    -e ip.dst \
    -e tcp.srcport \
    -e tcp.dstport \
    -e tcp.flags \
    -e tcp.window_size_value \
    -E header=y -E separator=, -E quote=d -E occurrence=f \
    > "$TMP_CSV" 2>/dev/null

if [ ! -s "$TMP_CSV" ]; then
    echo "❌ No se pudieron extraer datos TCP"
    rm -f "$TMP_CSV"
    exit 1
fi

echo "══════ Procesando paquetes con Python ══════"

python3 - "$TMP_CSV" "$CSV_FILE" "$ATTACKER" << 'PYTHON_EOF'
import csv
import sys

in_path = sys.argv[1]
out_path = sys.argv[2]
attacker_ip = sys.argv[3] if len(sys.argv) > 3 else ""

def to_int(v, default=0):
    try:
        return int(float(v)) if v else default
    except:
        return default

# -----------------------------
# CONVERSIÓN DE FLAGS HEX → TEXTO
# (solo para la lógica interna, NO se guarda en el CSV)
# -----------------------------
def flags_hex_to_string(flags_hex):
    if not flags_hex:
        return ""
    try:
        f = str(flags_hex).lower().replace("0x", "")
        flags_int = int(f, 16)
    except:
        return ""
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

# -----------------------------
# CONVERSIÓN FLAGS STRING → CÓDIGO NUMÉRICO
# -----------------------------
flags_map = {
    "": 0, "S": 1, "A": 2, "SA": 3, "F": 4, "FA": 5,
    "R": 6, "RA": 7, "P": 8, "PA": 9, "FPU": 10,
    "FSPU": 11, "SEC": 12
}
def flags_str_to_numeric(s):
    return flags_map.get(s, 99)

# -----------------------------
# CONVERSIÓN FLAGS HEX → ENTERO (para el CSV, solo números)
# -----------------------------
def flags_hex_to_int(flags_hex):
    if not flags_hex:
        return 0
    try:
        f = str(flags_hex).strip().lower()
        if f.startswith("0x"):
            f = f[2:]
        return int(f, 16)
    except:
        return 0

# =====================================================================
# DETECTOR DE FINGERPRINTING (Versión corregida: SOLO patrones Nmap)
# =====================================================================
def is_nmap_fingerprint(flags_str, window, port):

    # T1/T2/T3/T4/T6/T7 window patterns
    if flags_str == "S" and window in (1, 4, 16, 63, 512, 31337):
        return True

    # Test T2
    if flags_str == "" and window == 128:
        return True

    # Test T7 (FSPU, FPU)
    if flags_str == "FSPU" and window == 256:
        return True
    if flags_str == "FPU" and window == 65535:
        return True

    # ACK probes
    if flags_str == "A" and window == 1024:
        return True
    if flags_str == "A" and window == 32768:
        return True

    # ECN probes
    if flags_str == "SEC" and window == 3:
        return True

    # *** IMPORTANTE: ELIMINADO ***
    # Ya NO existe la regla:
    #    flags="S" and window=1024 on non-legit port
    # para evitar falsos positivos masivos.

    return False

# =====================================================================

with open(in_path, 'r') as f:
    rows = list(csv.reader(f))

header = rows[0]
idx = {col: i for i, col in enumerate(header)}

instance_id = 1

with open(out_path, 'w', newline='') as fo:
    w = csv.writer(fo)
    w.writerow([
        "tcp.srcport", "tcp.dstport", "tcp.flags", "tcp.flags_numeric",
        "tcp.window_size_value", "type_f", "type_n", "series_id", "instance_id"
    ])

    for row in rows[1:]:
        if len(row) < len(header): 
            continue

        ip_src = row[idx["ip.src"]]

        # Si se especificó la IP atacante, filtramos
        if attacker_ip and ip_src != attacker_ip:
            continue

        srcp = to_int(row[idx["tcp.srcport"]])
        dstp = to_int(row[idx["tcp.dstport"]])
        flags_hex = row[idx["tcp.flags"]]
        window = to_int(row[idx["tcp.window_size_value"]])

        # Interno: string para la lógica de fingerprinting
        flags_str = flags_hex_to_string(flags_hex)
        flags_num = flags_str_to_numeric(flags_str)

        # CSV: tcp.flags como entero (bitmask) sin letras
        flags_int = flags_hex_to_int(flags_hex)

        # Clasificación real
        fingerprint = is_nmap_fingerprint(flags_str, window, dstp)
        type_f = 1 if fingerprint else 0
        type_n = 0 if fingerprint else 1

        w.writerow([
            srcp,
            dstp,
            flags_int,   # <- ahora es solo número
            flags_num,
            window,
            type_f,
            type_n,
            1,              # series_id fijo
            instance_id
        ])

        instance_id += 1

print("Procesamiento completo.")
PYTHON_EOF

rm -f "$TMP_CSV"

echo ""
echo "Archivo generado:"
echo "  $CSV_FILE"
echo ""
echo "Hecho."
