# ============================================================================
# OStealth Python Control Plane
# ============================================================================

'''
eBPF OS Fingerprint Spoofer - Control Plane
Loads and configures the eBPF TC egress program to modify outgoing SYN packets
'''

import sys
import time
import ctypes
import struct
import subprocess


class TCPRequestConfig(ctypes.Structure):
    _fields_ = [
        ("window_size", ctypes.c_uint16),
        ("ttl_value", ctypes.c_uint8),
        ("df_flag", ctypes.c_uint8),
        ("options_size", ctypes.c_uint8),
        ("options", ctypes.c_uint8 * 40),
    ]

selectable_fingerprints = {
    'windowsXP':[
        TCPRequestConfig(
            window_size=65535,
            ttl_value=128,
            df_flag=1,
            options_size=4 + 1 + 1 + 2, # MSS + NOP + NOP + SOK
            options=(ctypes.c_uint8 * 40)(2, 4, 1460 >> 8, 1460 & 0xFF, 1, 1, 4, 2)
        )
    ]
}

def find_map_id(map_name="config_map"):
    """Find the map ID by name"""
    result = subprocess.run(['bpftool', 'map', 'list'], 
                          capture_output=True, text=True)
    for line in result.stdout.split('\n'):
        if map_name in line:
            # Extract ID from line like "12: array  name config_map..."
            map_id = line.split(':')[0]
            return int(map_id)
    return None

def configure_spoofer(enabled=True, mss=1460, ttl=128, df=1, window=65535):
    """Configure OS spoofing parameters"""
    map_id = find_map_id()
    if not map_id:
        print("[-] Error: config_map not found. Is the eBPF program loaded?")
        return False
    
    # Update map using bpftool
    config = bytes(selectable_fingerprints['windowsXP'][0])
    key = struct.pack('<I', 0)  # Key = 0
    
    cmd = ['bpftool', 'map', 'update', 'id', str(map_id),
           'key', 'hex'] + [f'{b:02x}' for b in key] + \
          ['value', 'hex'] + [f'{b:02x}' for b in config]
    
    result = subprocess.run(cmd, capture_output=True)
    
    if result.returncode == 0:
        print(f"[+] Configuration applied to map ID {map_id}:")
        print(f"    MSS: {mss}")
        print(f"    TTL: {ttl}")
        print(f"    DF: {df}")
        print(f"    Window: {window}")
        return True
    else:
        print(f"[-] Error updating map: {result.stderr.decode()}")
        return False

if __name__ == "__main__":
    
    # Example: Spoof as Windows (TTL=128, Window=65535)
    configure_spoofer(enabled=True, mss=1460, ttl=128, df=1, window=65535)
    
    print("\n[*] Press Ctrl+C to disable...")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Disabling spoofer...")
        configure_spoofer(enabled=False)
        print("[*] Done!")

