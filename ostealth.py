# ============================================================================
# OStealth Python Control Plane
# ============================================================================

'''
eBPF OS Fingerprint Spoofer - Control Plane
Loads and configures the eBPF TC egress program to modify outgoing SYN packets
'''


import sys
import time
import random
import ctypes
import struct
import subprocess

from dataclasses import dataclass
from enum import Enum

temporary_signature = '*:128:0:*:16384,*:mss,nop,nop,sok:df,id+:0'
default_mss = {"windowsXP": 1460}

@dataclass
class TCPOption():
    option_kind: int
    option_length: int | None
    option_data: list[int] | None

class TCPRequestConfig(ctypes.Structure):
    _fields_ = [
        ("window_size", ctypes.c_uint16),
        ("ttl_value", ctypes.c_uint8),
        ("df_flag", ctypes.c_uint8),
        ("options_size", ctypes.c_uint8),
        ("options", ctypes.c_uint8 * 40),
    ]

class TCPOptionP0FFactory():
    tcp_opts = {
        'nop': 1,
        'mss': 2,
        'ws': 3,
        'sok': 4,
        'ts': 8
    }

    tcp_lens = {
        'nop': None,
        'mss': 4,
        'ws': 3,
        'sok': 2,
        'ts': 10
    }

    def str_to_option(self, option_type: str, input1: int | None, input2: int | None) -> TCPOption:
        option_value = None 
        if option_type == 'ts':
            option_value = [(input1 >> (i * 8)) & 0xFF for i in range(4)] + [(input2 >> (i * 8)) & 0xFF for i in range(4)]
        elif option_type == 'mss':
            option_value = [(input1 >> (i * 8)) & 0xFF for i in range(2)]
        elif option_type == 'ws':
            option_value = [input1 & 0xFF]

        return TCPOption(
            self.tcp_opts[option_type],
            self.tcp_lens[option_type],
            option_value
        )

class TCPRequestConfigFactory():

    def __init__(self):
        self.tcpfactory = TCPOptionP0FFactory()

    def signature_to_tcpr(self, fooling_as: str, signature: str) -> TCPRequestConfig:
        splits = signature.split(':')

        ttl = int(splits[1])
        window_size = int(splits[4].split(',')[0])

        signature_options = splits[5].split(',')
        selected_options = []
        total_size = 0
        for s in signature_options:
            if s == 'mss':
                selected_options.append(self.tcpfactory.str_to_option(s, default_mss[fooling_as], None))
            elif s == 'ts':
                selected_options.append(self.tcpfactory.str_to_option(s, random.randint(0, 2147483647), 0))
            else:
                selected_options.append(self.tcpfactory.str_to_option(s, None, None))
            total_size += selected_options[-1].option_length if selected_options[-1].option_length is not None else 1

        df_flag_present = splits[6].split(',')[0] == 'df'

        result = TCPRequestConfig(
            window_size=window_size,
            ttl_value=ttl,
            df_flag=df_flag_present,
            options_size=total_size,
            options=(ctypes.c_uint8 * 40)()
        )

        index = 0
        for obj in selected_options:
            result.options[index] = obj.option_kind
            if obj.option_length is not None:
                result.options[index + 1] = obj.option_length
            if obj.option_data is not None:
                for j in range(len(obj.option_data)):
                    result.options[index + 2 + j] = obj.option_data[j]
            
            index += obj.option_length if obj.option_length is not None else 1

        return result


class TCPRequestConfig(ctypes.Structure):
    _fields_ = [
        ("window_size", ctypes.c_uint16),
        ("ttl_value", ctypes.c_uint8),
        ("df_flag", ctypes.c_uint8),
        ("options_size", ctypes.c_uint8),
        ("options", ctypes.c_uint8 * 40),
    ]

# selectable_fingerprints = {
#     'windowsXP':[
#         TCPRequestConfig(
#             window_size=65535,
#             ttl_value=128,
#             df_flag=1,
#             options_size=4 + 1 + 1 + 2, # MSS + NOP + NOP + SOK
#             options=(ctypes.c_uint8 * 40)(2, 4, 1460 >> 8, 1460 & 0xFF, 1, 1, 4, 2)
#         )
#     ],
#     'MacOS_X_10.x':[
#         TCPRequestConfig(
#             window_size=65535,
#             ttl_value=64,
#             df_flag=1,
#             options_size=4 + 1 + 1 + 2, # MSS + NOP + NOP + SOK
#             options=(ctypes.c_uint8 * 40)(2, 4, 1500 >> 8, 1500 & 0xFF, 1, 1, 4, 2)
#         )
#     ]
# }

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
    config = bytes(TCPRequestConfigFactory().signature_to_tcpr('windowsXP', temporary_signature))
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

