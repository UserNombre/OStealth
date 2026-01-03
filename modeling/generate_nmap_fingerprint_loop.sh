#!/bin/bash

# ============================================
# GENERADOR CONTINUO DE FINGERPRINTING NMAP
# ============================================
# Ejecuta Nmap en bucle infinito hasta Ctrl+C
#
# Uso:
#   sudo ./generate_nmap_fingerprint_loop.sh <target> [sleep_seconds]
#
# Ejemplos:
#   sudo ./generate_nmap_fingerprint_loop.sh 192.168.1.1
#   sudo ./generate_nmap_fingerprint_loop.sh 192.168.1.1 0
#   sudo ./generate_nmap_fingerprint_loop.sh 192.168.1.1 5
# ============================================

TARGET="$1"
SLEEP_TIME="${2:-0}"

if [ -z "$TARGET" ]; then
    echo "Uso: sudo $0 <target> [sleep_seconds]"
    exit 1
fi

echo "[*] Iniciando fingerprinting continuo contra $TARGET"
echo "[*] Modo sleep: $SLEEP_TIME (0 = inmediato)"
echo "[*] Ctrl+C para detener"

while true; do
    sudo nmap -O --osscan-guess -Pn -n -F "$TARGET"

    if [ "$SLEEP_TIME" -gt 0 ]; then
        sleep "$SLEEP_TIME"
    fi
done
