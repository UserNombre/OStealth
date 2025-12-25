# ============================================================================
# OStealth Python Control Plane
# ============================================================================

#!/usr/bin/env python3
'''
eBPF OS Fingerprint Spoofer - Control Plane
Loads and configures the eBPF TC egress program to modify outgoing SYN packets
'''

#!/usr/bin/env python3
import subprocess
import struct

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
    
    # Pack the struct (little-endian)
    # struct os_config: u32 enabled, u16 mss, u16 window, u8 ttl, u8 df, padding[2]
    config = struct.pack('<I H H B B x x', 
                        1 if enabled else 0,
                        mss,
                        window,
                        ttl,
                        df)
    
    # Update map using bpftool
    key = struct.pack('<I', 0)  # Key = 0
    
    cmd = ['bpftool', 'map', 'update', 'id', str(map_id),
           'key', 'hex'] + [f'{b:02x}' for b in key] + \
          ['value', 'hex'] + [f'{b:02x}' for b in config]
    
    result = subprocess.run(cmd, capture_output=True)
    
    if result.returncode == 0:
        print(f"[+] Configuration applied to map ID {map_id}:")
        print(f"    Enabled: {enabled}")
        print(f"    MSS: {mss}")
        print(f"    TTL: {ttl}")
        print(f"    DF: {df}")
        print(f"    Window: {window}")
        return True
    else:
        print(f"[-] Error updating map: {result.stderr.decode()}")
        return False

if __name__ == "__main__":
    import sys
    
    # Example: Spoof as Windows (TTL=128, Window=65535)
    configure_spoofer(enabled=True, mss=1460, ttl=128, df=1, window=65535)
    
    print("\n[*] Press Ctrl+C to disable...")
    try:
        import time
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Disabling spoofer...")
        configure_spoofer(enabled=False)
        print("[*] Done!")

