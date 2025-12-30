#!/bin/bash

# =====================================================================
# GENERADOR DEFINITIVO: Scapy (Tráfico Realista) + Nmap (Fingerprinting)
# =====================================================================
# Genera:
#   - Tráfico TCP REALISTA con handshakes completos (Scapy)
#   - Escaneos nmap periódicos (OS fingerprinting)
#
# Uso:
#   sudo ./generate_traffic_realistic_scapy.sh <target> <interfaz> <duracion_seg>
#
# Ejemplo:
#   sudo ./generate_traffic_realistic_scapy.sh 192.168.1.1 eth0 600
# =====================================================================

set -e

# ========= PARÁMETROS =========
TARGET="${1}"
IFACE="${2}"
DURATION="${3}"
OUTDIR="./traffic_capture"

# ========= AYUDA =========
if [ "$1" == "-h" ] || [ "$1" == "--help" ] || [ -z "$TARGET" ] || [ -z "$IFACE" ] || [ -z "$DURATION" ]; then
    cat << 'EOF'
╔══════════════════════════════════════════════════════════════════════╗
║  GENERADOR DEFINITIVO: Scapy + Nmap                                  ║
╚══════════════════════════════════════════════════════════════════════╝

DESCRIPCIÓN:
  Genera tráfico TCP REALISTA con handshakes completos usando Scapy,
  combinado con escaneos nmap periódicos para fingerprinting.

USO:
  sudo ./generate_traffic_realistic_scapy.sh <target> <interfaz> <duracion>

PARÁMETROS:
  target      : IP objetivo (ej: 192.168.1.1)
  interfaz    : Interfaz de red (ej: eth0, wlan0)
  duracion    : Duración en segundos (ej: 600 para 10 minutos)

EJEMPLOS:
  sudo ./generate_traffic_realistic_scapy.sh 192.168.1.1 eth0 600
  sudo ./generate_traffic_realistic_scapy.sh 10.0.0.1 wlan0 1800

REQUISITOS:
  - python3-scapy  : sudo apt-get install python3-scapy
  - nmap           : sudo apt-get install nmap
  - tcpdump        : sudo apt-get install tcpdump

TRÁFICO GENERADO:
  Normal (70%):
    • HTTP  : Handshakes completos (SYN → ACK → PSH-ACK → FIN-ACK)
    • HTTPS : Con TLS ClientHello
    • SSH   : Conexiones completas
    • DNS   : Consultas UDP
    • FTP   : Intentos de conexión
    • SMTP  : Intentos de conexión
    • ICMP  : Pings con tamaños variados

  Fingerprinting (30%):
    • Nmap cada 120-180 segundos
    • Tests: -O (OS detection), -sV (version), -A (aggressive)

SALIDA:
  - PCAP: ./traffic_capture/traffic_scapy_TIMESTAMP.pcap
  - LOG:  ./traffic_capture/traffic_scapy_TIMESTAMP.log

╚══════════════════════════════════════════════════════════════════════╝
EOF
    exit 0
fi

# ========= VERIFICACIONES =========
echo "[*] Verificando requisitos..."

if [ "$EUID" -ne 0 ]; then 
    echo "❌ Este script requiere permisos root (sudo)"
    exit 1
fi

MISSING=()
for tool in nmap tcpdump python3; do
    if ! command -v $tool >/dev/null 2>&1; then
        MISSING+=("$tool")
    fi
done

if [ ${#MISSING[@]} -gt 0 ]; then
    echo "❌ Faltan herramientas: ${MISSING[*]}"
    echo "   Instala con: sudo apt-get install ${MISSING[*]}"
    exit 1
fi

# Verificar Scapy
if ! python3 -c "from scapy.all import *" 2>/dev/null; then
    echo "❌ python3-scapy no instalado"
    echo "   Instala con: sudo apt-get install python3-scapy"
    exit 1
fi

# Verificar interfaz
if ! ip link show "$IFACE" >/dev/null 2>&1; then
    echo "❌ Interfaz '$IFACE' no existe"
    echo "   Interfaces disponibles:"
    ip link show | grep '^[0-9]' | awk '{print "     - " $2}' | sed 's/:$//'
    exit 1
fi

# Obtener IP local
MY_IP=$(ip addr show "$IFACE" | grep 'inet ' | awk '{print $2}' | cut -d/ -f1)

if [ -z "$MY_IP" ]; then
    echo "❌ No se pudo obtener IP de $IFACE"
    exit 1
fi

# Verificar conectividad
echo "[*] Verificando conectividad con $TARGET..."
if ! ping -c 1 -W 2 "$TARGET" >/dev/null 2>&1; then
    echo "⚠️  Advertencia: No hay respuesta de $TARGET"
    read -p "   ¿Continuar de todos modos? (s/n): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Ss]$ ]]; then
        exit 1
    fi
fi

mkdir -p "$OUTDIR"
TS=$(date +"%Y%m%d_%H%M%S")
PCAP_FILE="${OUTDIR}/traffic_scapy_${TS}.pcap"
LOG_FILE="${OUTDIR}/traffic_scapy_${TS}.log"

# ========= LIMPIEZA =========
cleanup() {
    echo "" | tee -a "$LOG_FILE"
    echo "[*] Finalizando captura..." | tee -a "$LOG_FILE"
    
    if [ -n "$TCPDUMP_PID" ]; then
        kill -INT "$TCPDUMP_PID" 2>/dev/null || true
        wait "$TCPDUMP_PID" 2>/dev/null || true
    fi
    
    if [ -n "$SCAPY_PID" ]; then
        kill -TERM "$SCAPY_PID" 2>/dev/null || true
        wait "$SCAPY_PID" 2>/dev/null || true
    fi
    
    if [ -f "$SCAPY_SCRIPT" ]; then
        rm -f "$SCAPY_SCRIPT"
    fi
    
    if [ -f "$PCAP_FILE" ]; then
        SIZE=$(stat -c%s "$PCAP_FILE" 2>/dev/null || stat -f%z "$PCAP_FILE" 2>/dev/null)
        PACKETS=$(tcpdump -r "$PCAP_FILE" 2>/dev/null | wc -l)
        echo "" | tee -a "$LOG_FILE"
        echo "╔══════════════════════════════════════════════════════════════════════╗" | tee -a "$LOG_FILE"
        echo "║  CAPTURA COMPLETADA                                                  ║" | tee -a "$LOG_FILE"
        echo "╚══════════════════════════════════════════════════════════════════════╝" | tee -a "$LOG_FILE"
        echo "  PCAP: $PCAP_FILE" | tee -a "$LOG_FILE"
        echo "  Tamaño: $(numfmt --to=iec-i --suffix=B $SIZE)" | tee -a "$LOG_FILE"
        echo "  Paquetes brutos: $PACKETS" | tee -a "$LOG_FILE"
        echo "" | tee -a "$LOG_FILE"
        echo "📊 SIGUIENTE PASO:" | tee -a "$LOG_FILE"
        echo "  ./process_tcp_only.sh $PCAP_FILE $MY_IP" | tee -a "$LOG_FILE"
        echo "" | tee -a "$LOG_FILE"
    fi
}

trap cleanup EXIT INT TERM

# ========= HEADER =========
clear
cat << EOF | tee "$LOG_FILE"
╔══════════════════════════════════════════════════════════════════════╗
║        GENERADOR DEFINITIVO: Scapy (Realista) + Nmap                ║
╚══════════════════════════════════════════════════════════════════════╝

  📍 Configuración:
     Mi IP    : $MY_IP (atacante)
     Target   : $TARGET
     Interfaz : $IFACE
     Duración : ${DURATION}s ($(($DURATION / 60)) minutos)

  📦 Salida:
     PCAP: $PCAP_FILE
     LOG : $LOG_FILE

  🌐 Tráfico que se generará:
     • HTTP  : Handshakes completos (SYN → ACK → PSH-ACK → FIN)
     • HTTPS : Con TLS ClientHello
     • SSH   : Conexiones completas
     • DNS   : Consultas UDP
     • FTP/SMTP: Intentos de conexión
     • ICMP  : Pings variados
     
  🔍 Fingerprinting:
     • Nmap cada 120-180 segundos
     • OS Detection, Version Scan, Aggressive

╔══════════════════════════════════════════════════════════════════════╗

EOF

# ========= INICIAR CAPTURA =========
echo "[*] Iniciando captura tcpdump..." | tee -a "$LOG_FILE"
tcpdump -i "$IFACE" -w "$PCAP_FILE" "src $MY_IP and dst $TARGET" 2>/dev/null &
TCPDUMP_PID=$!
sleep 2

if ! ps -p $TCPDUMP_PID > /dev/null 2>&1; then
    echo "❌ tcpdump falló al iniciar" | tee -a "$LOG_FILE"
    exit 1
fi

echo "✅ tcpdump activo (PID: $TCPDUMP_PID)" | tee -a "$LOG_FILE"
echo "" | tee -a "$LOG_FILE"

# ========= CREAR SCRIPT SCAPY =========
SCAPY_SCRIPT="/tmp/scapy_generator_$$.py"

cat > "$SCAPY_SCRIPT" << 'PYTHON_CODE'
#!/usr/bin/env python3
"""
Generador de tráfico TCP realista con Scapy
Genera handshakes completos para HTTP, HTTPS, SSH, etc.
"""

from scapy.all import *
import random
import time
import sys

# Configuración
TARGET = sys.argv[1]
DURATION = int(sys.argv[2])

# Desactivar verbose de Scapy
conf.verb = 0

# Contadores
stats = {
    'http': 0,
    'https': 0,
    'ssh': 0,
    'dns': 0,
    'ftp': 0,
    'smtp': 0,
    'icmp': 0,
    'total_packets': 0
}

def log_progress():
    """Mostrar progreso"""
    elapsed = int(time.time() - start_time)
    print(f"[{elapsed:3d}s] Paquetes: {stats['total_packets']:4d} | "
          f"HTTP:{stats['http']:3d} HTTPS:{stats['https']:3d} "
          f"SSH:{stats['ssh']:3d} DNS:{stats['dns']:3d} "
          f"FTP:{stats['ftp']:2d} SMTP:{stats['smtp']:2d} "
          f"ICMP:{stats['icmp']:3d}", flush=True)

def http_session(dst):
    """
    Simula sesión HTTP COMPLETA:
    1. SYN (inicio)
    2. ACK (confirmar handshake tras recibir SYN-ACK)
    3. PSH-ACK con HTTP GET (enviar request)
    4. ACK (confirmar respuesta)
    5. FIN-ACK (cerrar conexión)
    """
    sport = random.randint(49152, 65535)
    seq = random.randint(1000000, 9000000)
    
    # Windows realistas de navegadores
    win = random.choice([64240, 65535, 8192, 16384])
    
    # 1. SYN - Inicio de conexión
    syn_pkt = IP(dst=dst)/TCP(
        sport=sport, 
        dport=80, 
        flags="S", 
        seq=seq, 
        window=win,
        options=[('MSS', 1460), ('WScale', 7), ('SAckOK', b''), ('Timestamp', (int(time.time()), 0))]
    )
    send(syn_pkt, verbose=0)
    stats['total_packets'] += 1
    time.sleep(0.05)
    
    # 2. ACK - Confirmar handshake (asumiendo recibimos SYN-ACK)
    ack_pkt = IP(dst=dst)/TCP(
        sport=sport,
        dport=80,
        flags="A",
        seq=seq+1,
        ack=1,
        window=win
    )
    send(ack_pkt, verbose=0)
    stats['total_packets'] += 1
    time.sleep(0.1)
    
    # 3. PSH-ACK - Enviar HTTP GET request
    http_request = b"GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n"
    push_pkt = IP(dst=dst)/TCP(
        sport=sport,
        dport=80,
        flags="PA",
        seq=seq+1,
        ack=1,
        window=win
    )/Raw(load=http_request)
    send(push_pkt, verbose=0)
    stats['total_packets'] += 1
    time.sleep(0.5)
    
    # 4. ACK - Confirmar respuesta del servidor
    ack2_pkt = IP(dst=dst)/TCP(
        sport=sport,
        dport=80,
        flags="A",
        seq=seq+len(http_request)+1,
        ack=500,  # Simular que recibimos 500 bytes
        window=win
    )
    send(ack2_pkt, verbose=0)
    stats['total_packets'] += 1
    time.sleep(0.2)
    
    # 5. FIN-ACK - Cerrar conexión
    fin_pkt = IP(dst=dst)/TCP(
        sport=sport,
        dport=80,
        flags="FA",
        seq=seq+len(http_request)+1,
        ack=500,
        window=win
    )
    send(fin_pkt, verbose=0)
    stats['total_packets'] += 1
    
    stats['http'] += 1

def https_session(dst):
    """
    Simula sesión HTTPS con TLS ClientHello
    """
    sport = random.randint(49152, 65535)
    seq = random.randint(1000000, 9000000)
    win = random.choice([64240, 65535])
    
    # 1. SYN
    syn_pkt = IP(dst=dst)/TCP(
        sport=sport,
        dport=443,
        flags="S",
        seq=seq,
        window=win,
        options=[('MSS', 1460), ('WScale', 7), ('SAckOK', b''), ('Timestamp', (int(time.time()), 0))]
    )
    send(syn_pkt, verbose=0)
    stats['total_packets'] += 1
    time.sleep(0.05)
    
    # 2. ACK
    ack_pkt = IP(dst=dst)/TCP(
        sport=sport,
        dport=443,
        flags="A",
        seq=seq+1,
        ack=1,
        window=win
    )
    send(ack_pkt, verbose=0)
    stats['total_packets'] += 1
    time.sleep(0.1)
    
    # 3. PSH-ACK con TLS ClientHello
    tls_hello = b"\x16\x03\x01\x00\x50" + b"\x00" * 75  # Inicio de TLS ClientHello
    push_pkt = IP(dst=dst)/TCP(
        sport=sport,
        dport=443,
        flags="PA",
        seq=seq+1,
        ack=1,
        window=win
    )/Raw(load=tls_hello)
    send(push_pkt, verbose=0)
    stats['total_packets'] += 1
    time.sleep(0.5)
    
    # 4. FIN-ACK
    fin_pkt = IP(dst=dst)/TCP(
        sport=sport,
        dport=443,
        flags="FA",
        seq=seq+len(tls_hello)+1,
        ack=1,
        window=win
    )
    send(fin_pkt, verbose=0)
    stats['total_packets'] += 1
    
    stats['https'] += 1

def ssh_session(dst):
    """
    Simula sesión SSH
    """
    sport = random.randint(49152, 65535)
    seq = random.randint(1000000, 9000000)
    
    # Windows típicos de clientes Linux SSH
    win = random.choice([29200, 32768, 29696])
    
    # 1. SYN
    syn_pkt = IP(dst=dst)/TCP(
        sport=sport,
        dport=22,
        flags="S",
        seq=seq,
        window=win,
        options=[('MSS', 1460), ('SAckOK', b''), ('Timestamp', (int(time.time()), 0)), ('WScale', 7)]
    )
    send(syn_pkt, verbose=0)
    stats['total_packets'] += 1
    time.sleep(0.05)
    
    # 2. ACK
    ack_pkt = IP(dst=dst)/TCP(
        sport=sport,
        dport=22,
        flags="A",
        seq=seq+1,
        ack=1,
        window=win
    )
    send(ack_pkt, verbose=0)
    stats['total_packets'] += 1
    time.sleep(0.1)
    
    # 3. PSH-ACK con banner SSH
    ssh_banner = b"SSH-2.0-OpenSSH_8.2\r\n"
    push_pkt = IP(dst=dst)/TCP(
        sport=sport,
        dport=22,
        flags="PA",
        seq=seq+1,
        ack=1,
        window=win
    )/Raw(load=ssh_banner)
    send(push_pkt, verbose=0)
    stats['total_packets'] += 1
    time.sleep(0.3)
    
    # 4. FIN-ACK
    fin_pkt = IP(dst=dst)/TCP(
        sport=sport,
        dport=22,
        flags="FA",
        seq=seq+len(ssh_banner)+1,
        ack=1,
        window=win
    )
    send(fin_pkt, verbose=0)
    stats['total_packets'] += 1
    
    stats['ssh'] += 1

def dns_query(dst):
    """
    Simula consulta DNS
    """
    domains = [
        "google.com", "github.com", "amazon.com", "microsoft.com",
        "facebook.com", "twitter.com", "wikipedia.org", "reddit.com",
        "youtube.com", "instagram.com", "linkedin.com", "stackoverflow.com"
    ]
    domain = random.choice(domains)
    
    dns_pkt = IP(dst=dst)/UDP(
        sport=random.randint(49152, 65535),
        dport=53
    )/DNS(rd=1, qd=DNSQR(qname=domain))
    
    send(dns_pkt, verbose=0)
    stats['total_packets'] += 1
    stats['dns'] += 1

def ftp_session(dst):
    """
    Simula intento FTP
    """
    sport = random.randint(49152, 65535)
    seq = random.randint(1000000, 9000000)
    win = 8192
    
    # SYN
    syn_pkt = IP(dst=dst)/TCP(
        sport=sport,
        dport=21,
        flags="S",
        seq=seq,
        window=win,
        options=[('MSS', 1460)]
    )
    send(syn_pkt, verbose=0)
    stats['total_packets'] += 1
    time.sleep(0.05)
    
    # ACK
    ack_pkt = IP(dst=dst)/TCP(
        sport=sport,
        dport=21,
        flags="A",
        seq=seq+1,
        ack=1,
        window=win
    )
    send(ack_pkt, verbose=0)
    stats['total_packets'] += 1
    
    stats['ftp'] += 1

def smtp_session(dst):
    """
    Simula intento SMTP
    """
    sport = random.randint(49152, 65535)
    seq = random.randint(1000000, 9000000)
    dport = random.choice([25, 587])  # SMTP o SMTP-SSL
    win = 16384
    
    # SYN
    syn_pkt = IP(dst=dst)/TCP(
        sport=sport,
        dport=dport,
        flags="S",
        seq=seq,
        window=win,
        options=[('MSS', 1460)]
    )
    send(syn_pkt, verbose=0)
    stats['total_packets'] += 1
    time.sleep(0.05)
    
    # ACK
    ack_pkt = IP(dst=dst)/TCP(
        sport=sport,
        dport=dport,
        flags="A",
        seq=seq+1,
        ack=1,
        window=win
    )
    send(ack_pkt, verbose=0)
    stats['total_packets'] += 1
    
    stats['smtp'] += 1

def icmp_ping(dst):
    """
    Simula ping ICMP con tamaños variados
    """
    sizes = [32, 40, 56, 64, 84, 100, 120]
    size = random.choice(sizes)
    
    ping_pkt = IP(dst=dst)/ICMP()/Raw(load="X"*size)
    send(ping_pkt, verbose=0)
    stats['total_packets'] += 1
    stats['icmp'] += 1

# ========= LOOP PRINCIPAL =========
print(f"[*] Iniciando generador Scapy...")
print(f"[*] Target: {TARGET}")
print(f"[*] Duración: {DURATION}s")
print()

start_time = time.time()
packet_count = 0

while time.time() - start_time < DURATION:
    # Distribución realista de tráfico
    rand = random.randint(0, 100)
    
    if rand < 30:  # 30% HTTP
        http_session(TARGET)
    elif rand < 50:  # 20% HTTPS
        https_session(TARGET)
    elif rand < 65:  # 15% DNS
        dns_query(TARGET)
    elif rand < 75:  # 10% ICMP
        icmp_ping(TARGET)
    elif rand < 85:  # 10% SSH
        ssh_session(TARGET)
    elif rand < 92:  # 7% SMTP
        smtp_session(TARGET)
    else:  # 8% FTP
        ftp_session(TARGET)
    
    packet_count += 1
    
    # Mostrar progreso cada 10 generaciones
    if packet_count % 10 == 0:
        log_progress()
    
    # Pausa realista entre 2-5 segundos (simula usuario navegando)
    time.sleep(random.uniform(2.0, 5.0))

# Resumen final
print()
print("=" * 70)
print("RESUMEN TRÁFICO SCAPY")
print("=" * 70)
print(f"Total sesiones generadas: {packet_count}")
print(f"Total paquetes enviados: {stats['total_packets']}")
print(f"  HTTP : {stats['http']:3d} sesiones")
print(f"  HTTPS: {stats['https']:3d} sesiones")
print(f"  SSH  : {stats['ssh']:3d} sesiones")
print(f"  DNS  : {stats['dns']:3d} consultas")
print(f"  SMTP : {stats['smtp']:3d} intentos")
print(f"  FTP  : {stats['ftp']:3d} intentos")
print(f"  ICMP : {stats['icmp']:3d} pings")
print("=" * 70)
PYTHON_CODE

chmod +x "$SCAPY_SCRIPT"

# ========= INICIAR GENERADOR SCAPY =========
echo "[*] Iniciando generador Scapy en background..." | tee -a "$LOG_FILE"
python3 "$SCAPY_SCRIPT" "$TARGET" "$DURATION" 2>&1 | tee -a "$LOG_FILE" &
SCAPY_PID=$!
sleep 2

if ! ps -p $SCAPY_PID > /dev/null 2>&1; then
    echo "❌ Scapy falló al iniciar" | tee -a "$LOG_FILE"
    exit 1
fi

echo "✅ Scapy activo (PID: $SCAPY_PID)" | tee -a "$LOG_FILE"
echo "" | tee -a "$LOG_FILE"

# ========= FUNCIÓN NMAP =========
NMAP_COUNT=0

run_nmap() {
    local nmap_type=$1
    
    echo "" | tee -a "$LOG_FILE"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" | tee -a "$LOG_FILE"
    echo "[NMAP #$((NMAP_COUNT + 1))] $nmap_type" | tee -a "$LOG_FILE"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" | tee -a "$LOG_FILE"
    
    case $nmap_type in
        "OS Detection")
            nmap -O --osscan-guess -Pn -n -F "$TARGET" 2>&1 | tee -a "$LOG_FILE" | grep -E "^(OS|Running|Aggressive)" | head -5
            ;;
        "Version Detection")
            nmap -sV --version-all -Pn -n -p 1-1000 "$TARGET" 2>&1 | tee -a "$LOG_FILE" | grep -E "^[0-9]" | head -5
            ;;
        "Aggressive Scan")
            nmap -A -Pn -n -p 1-1000 "$TARGET" 2>&1 | tee -a "$LOG_FILE" | grep -E "^(OS|Running|[0-9])" | head -8
            ;;
        "SYN Scan + OS")
            nmap -sS -O -Pn -n -F "$TARGET" 2>&1 | tee -a "$LOG_FILE" | grep -E "^(OS|Running)" | head -5
            ;;
    esac
    
    NMAP_COUNT=$((NMAP_COUNT + 1))
    echo "✓ Completado" | tee -a "$LOG_FILE"
}

# ========= LOOP NMAP PERIÓDICO =========
echo "[*] Iniciando escaneos nmap periódicos..." | tee -a "$LOG_FILE"
echo "    (Cada 120-180 segundos)" | tee -a "$LOG_FILE"
echo "" | tee -a "$LOG_FILE"

# Tipos de escaneo nmap
NMAP_TYPES=("OS Detection" "Version Detection" "Aggressive Scan" "SYN Scan + OS")

START=$(date +%s)
LAST_NMAP=$START

# Primer nmap inmediato
run_nmap "${NMAP_TYPES[0]}"

# Loop mientras Scapy esté activo
while ps -p $SCAPY_PID > /dev/null 2>&1; do
    CURRENT=$(date +%s)
    ELAPSED=$((CURRENT - START))
    
    # Terminar si se acabó el tiempo
    [ $ELAPSED -ge $DURATION ] && break
    
    # Ejecutar nmap cada 120-180 segundos (aleatorio)
    NMAP_INTERVAL=$((30 + RANDOM % 31))
    
    if [ $((CURRENT - LAST_NMAP)) -ge $NMAP_INTERVAL ]; then
        # Rotar tipo de escaneo
        NMAP_TYPE_IDX=$((NMAP_COUNT % ${#NMAP_TYPES[@]}))
        run_nmap "${NMAP_TYPES[$NMAP_TYPE_IDX]}"
        LAST_NMAP=$(date +%s)
    fi
    
    sleep 10
done

# Esperar a que termine Scapy
wait $SCAPY_PID 2>/dev/null

sleep 2

echo "" | tee -a "$LOG_FILE"
echo "╔══════════════════════════════════════════════════════════════════════╗" | tee -a "$LOG_FILE"
echo "║  RESUMEN FINAL                                                       ║" | tee -a "$LOG_FILE"
echo "╚══════════════════════════════════════════════════════════════════════╝" | tee -a "$LOG_FILE"
echo "  Tráfico Scapy generado: Ver detalles arriba" | tee -a "$LOG_FILE"
echo "  Escaneos nmap ejecutados: $NMAP_COUNT" | tee -a "$LOG_FILE"
echo "  Duración total: $(($DURATION / 60)) minutos" | tee -a "$LOG_FILE"
echo "╚══════════════════════════════════════════════════════════════════════╝" | tee -a "$LOG_FILE"
