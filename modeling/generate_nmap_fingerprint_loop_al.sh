#!/bin/bash

# Use:
#   sudo ./generate_nmap_fingerprint_loop.sh <target> [max_sleep_seconds]
#
#   sudo ./generate_nmap_fingerprint_loop.sh 192.168.1.1 10
# ============================================

TARGET="$1"
MAX_SLEEP="${2:-0}"

if [ -z "$TARGET" ]; then
    echo "Uso: sudo $0 <target> [max_sleep_seconds]"
    exit 1
fi

echo "[*] Iniciando fingerprinting continuo contra $TARGET"
echo "[*] Sleep aleatorio entre 0 y ${MAX_SLEEP}s"
echo "[*] Ctrl+C para detener"

while true; do
    sudo nmap -O --osscan-guess -Pn -n -F "$TARGET"

    if [ "$MAX_SLEEP" -gt 0 ]; then
        # Generar sleep aleatorio (entero) entre 0 y MAX_SLEEP
        RAND_SLEEP=$(( RANDOM % (MAX_SLEEP + 1) ))
        sleep "$RAND_SLEEP"
    fi
done
