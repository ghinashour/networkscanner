#!/usr/bin/env python3
"""
Advanced Network Scanner - using Nmap for host discovery and Scapy for MAC/TTL.
No ping sweeps or ARP table dumps – just nmap + scapy.
"""

import sys
import os
import platform
import subprocess
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import json
import sqlite3
import socket
import re
import xml.etree.ElementTree as ET
import urllib.request
import time
import hashlib
from datetime import datetime
from typing import List, Dict, Any, Optional, Tuple
import logging
from collections import defaultdict
import ipaddress
import concurrent.futures
import struct

# ============================================================================
# Scapy imports (Mandatory for MAC & TTL)
# ============================================================================
try:
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.l2 import ARP, Ether
    from scapy.sendrecv import srp, sr1, send
    from scapy.config import conf
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("⚠️ Scapy not installed. Install with: pip install scapy")
    print("   MAC/TTL retrieval will fall back to system ARP cache (no TTL).")

# ============================================================================
# Nmap imports (Required for host discovery)
# ============================================================================
try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False
    print("⚠️ python-nmap not installed. Install with: pip install python-nmap")
    print("   Host discovery will fall back to Scapy ARP scanning.")

# ============================================================================
# Optional imports
# ============================================================================
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

# Try netifaces for better gateway detection
try:
    import netifaces
    NETIFACES_AVAILABLE = True
except ImportError:
    NETIFACES_AVAILABLE = False

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)


# ============================================================================
# MAC VENDOR DATABASE (expanded with common brands)
# ============================================================================
MAC_VENDORS = {
    # Apple
    '00:03:93': 'Apple', '00:0A:27': 'Apple', '00:0D:93': 'Apple',
    '00:11:24': 'Apple', '00:17:F2': 'Apple', '00:19:E3': 'Apple',
    '00:1B:63': 'Apple', '00:1C:B3': 'Apple', '00:1D:4F': 'Apple',
    '00:1E:52': 'Apple', '00:1F:F3': 'Apple', '00:23:32': 'Apple',
    '00:24:36': 'Apple', '00:25:00': 'Apple', '00:25:BC': 'Apple',
    '00:26:08': 'Apple', '00:26:4A': 'Apple', '00:26:BB': 'Apple',
    '00:27:0C': 'Apple', '00:27:64': 'Apple', '00:29:95': 'Apple',
    '10:9A:DD': 'Apple', '14:7D:DA': 'Apple', '18:69:74': 'Apple',
    '1C:36:BB': 'Apple', '1C:E6:2B': 'Apple', '20:07:CA': 'Apple',
    '24:AB:81': 'Apple', '28:6A:BA': 'Apple', '2C:29:39': 'Apple',
    '30:9C:23': 'Apple', '34:12:98': 'Apple', '38:0F:4A': 'Apple',
    '3C:15:C2': 'Apple', '40:6C:8F': 'Apple', '44:2A:60': 'Apple',
    '48:59:29': 'Apple', '4C:57:CA': 'Apple', '50:E0:85': 'Apple',
    '54:AE:27': 'Apple', '5C:96:9D': 'Apple', '60:33:4B': 'Apple',
    '64:20:0C': 'Apple', '68:A8:6D': 'Apple', '6C:40:08': 'Apple',
    '70:56:81': 'Apple', '70:CD:60': 'Apple', '74:E1:4A': 'Apple',
    '78:CA:04': 'Apple', '7C:6D:62': 'Apple', '7C:DF:A1': 'Apple',
    '80:BE:05': 'Apple', '84:38:35': 'Apple', '88:53:2E': 'Apple',
    '88:66:5A': 'Apple', '8C:29:37': 'Apple', '8C:85:80': 'Apple',
    '90:72:40': 'Apple', '90:9C:4A': 'Apple', '94:94:26': 'Apple',
    '98:01:A7': 'Apple', '98:5A:EB': 'Apple', '98:FE:94': 'Apple',
    '9C:F3:87': 'Apple', 'A0:99:9B': 'Apple', 'A4:D1:D2': 'Apple',
    'A8:66:7F': 'Apple', 'AC:29:3A': 'Apple', 'B0:34:95': 'Apple',
    'B4:89:95': 'Apple', 'B8:09:8A': 'Apple', 'B8:53:AC': 'Apple',
    'BC:92:6B': 'Apple', 'C0:2C:05': 'Apple', 'C4:2C:03': 'Apple',
    'C8:69:CD': 'Apple', 'CC:08:E0': 'Apple', 'CC:9C:52': 'Apple',
    'D0:23:DB': 'Apple', 'D4:9A:20': 'Apple', 'DC:2B:61': 'Apple',
    'DC:41:04': 'Apple', 'E0:AC:CB': 'Apple', 'E4:CE:8F': 'Apple',
    'E8:06:88': 'Apple', 'EC:35:86': 'Apple', 'F0:18:98': 'Apple',
    'F4:5C:89': 'Apple', 'F8:1E:DF': 'Apple', 'FC:35:47': 'Apple',
    # Samsung (expanded)
    '00:1C:F0': 'Samsung', '00:22:FA': 'Samsung', '00:23:C6': 'Samsung',
    '00:24:4B': 'Samsung', '00:24:C6': 'Samsung', '00:25:CE': 'Samsung',
    '00:26:9E': 'Samsung', '00:26:C6': 'Samsung', '00:27:13': 'Samsung',
    '00:27:5C': 'Samsung', '00:27:6F': 'Samsung', '00:27:E4': 'Samsung',
    '00:28:55': 'Samsung', '00:29:16': 'Samsung', '00:29:6A': 'Samsung',
    '00:29:79': 'Samsung', '00:2A:6A': 'Samsung', '00:2B:67': 'Samsung',
    '00:2B:D9': 'Samsung', '00:2C:44': 'Samsung', '00:2D:55': 'Samsung',
    '00:2F:2F': 'Samsung', '00:2F:9E': 'Samsung', '00:30:2E': 'Samsung',
    '00:30:3A': 'Samsung', '00:30:6C': 'Samsung', '00:31:65': 'Samsung',
    '00:31:B1': 'Samsung', '00:32:A4': 'Samsung', '00:33:33': 'Samsung',
    '80:CE:B9': 'Samsung', '10:8E:E0': 'Samsung', 'B8:03:60': 'Samsung',
    'C8:BF:FA': 'Samsung', 'DC:24:73': 'Samsung', 'F4:10:EA': 'Samsung',
    'F8:36:61': 'Samsung', 'F8:CF:C5': 'Samsung', 'D8:24:BD': 'Samsung',
    'E8:46:85': 'Samsung', '3C:5A:37': 'Samsung', '5C:E5:0C': 'Samsung',
    '78:45:C4': 'Samsung', '98:62:B4': 'Samsung',
    # Huawei
    '00:1E:10': 'Huawei', '00:22:93': 'Huawei', '00:23:68': 'Huawei',
    '00:24:3E': 'Huawei', '00:25:B5': 'Huawei', '00:26:2F': 'Huawei',
    '00:27:78': 'Huawei', '00:28:18': 'Huawei', '00:29:9B': 'Huawei',
    '00:2A:10': 'Huawei', '00:2B:16': 'Huawei', '00:2C:FE': 'Huawei',
    # Xiaomi
    '00:1A:7D': 'Xiaomi', '00:23:8E': 'Xiaomi', '00:24:D4': 'Xiaomi',
    '00:26:3C': 'Xiaomi', '00:27:9B': 'Xiaomi', '00:28:9A': 'Xiaomi',
    '00:29:35': 'Xiaomi', '00:2A:7D': 'Xiaomi', '00:2B:5E': 'Xiaomi',
    # Google
    '00:18:0B': 'Google', '00:1C:0C': 'Google', '00:20:0D': 'Google',
    '00:22:0E': 'Google', '00:24:0F': 'Google', '00:26:10': 'Google',
    # Cisco
    '00:00:0C': 'Cisco', '00:01:42': 'Cisco', '00:01:97': 'Cisco',
    '00:01:DE': 'Cisco', '00:02:16': 'Cisco', '00:02:2D': 'Cisco',
    # HP
    '00:01:03': 'HP', '00:01:04': 'HP', '00:01:06': 'HP',
    '00:01:0A': 'HP', '00:01:0C': 'HP', '00:01:0E': 'HP',
    # Dell
    '00:01:0B': 'Dell', '00:01:0D': 'Dell', '00:01:0F': 'Dell',
    '00:01:10': 'Dell', '00:01:11': 'Dell', '00:01:12': 'Dell',
    # Lenovo
    '00:01:13': 'Lenovo', '00:01:14': 'Lenovo', '00:01:15': 'Lenovo',
    '00:01:16': 'Lenovo', '00:01:17': 'Lenovo', '00:01:18': 'Lenovo',
    # Asus
    '00:01:19': 'Asus', '00:01:1A': 'Asus', '00:01:1B': 'Asus',
    '00:01:1C': 'Asus', '00:01:1D': 'Asus', '00:01:1E': 'Asus',
    # Raspberry Pi
    'B8:27:EB': 'Raspberry Pi', 'DC:A6:32': 'Raspberry Pi', 'E4:5F:01': 'Raspberry Pi',
    '2C:CF:67': 'Raspberry Pi', '28:CD:C1': 'Raspberry Pi',
    # Netis
    '04:5E:A4': 'Netis Technologies',
    # Espressif
    '18:FE:34': 'Espressif', '24:0A:C4': 'Espressif', '5C:CF:7F': 'Espressif',
    'A0:20:A6': 'Espressif', 'B4:E6:2D': 'Espressif', 'DC:4F:22': 'Espressif',
    'E0:5A:1B': 'Espressif', 'F0:08:D1': 'Espressif',
    # TP-Link
    '00:1A:2A': 'TP-Link', '00:1D:0F': 'TP-Link', '00:23:CD': 'TP-Link',
    '00:25:86': 'TP-Link', '10:FE:ED': 'TP-Link', '14:CC:20': 'TP-Link',
    '50:91:E3': 'TP-Link', '54:AF:97': 'TP-Link', '8C:21:0A': 'TP-Link',
    '9C:53:22': 'TP-Link',
    # Netgear
    '00:09:5B': 'Netgear', '00:0F:B5': 'Netgear', '00:14:6C': 'Netgear',
    '00:1B:2F': 'Netgear', '00:1F:33': 'Netgear', '00:22:3F': 'Netgear',
    '00:24:B2': 'Netgear', '00:26:F2': 'Netgear', '08:36:C9': 'Netgear',
    '0C:81:91': 'Netgear', '14:0C:76': 'Netgear', '20:4E:7F': 'Netgear',
    '34:98:B5': 'Netgear', '4C:60:DE': 'Netgear', 'A0:21:B7': 'Netgear',
    'B0:39:56': 'Netgear', 'D8:50:E6': 'Netgear', 'DC:EF:09': 'Netgear',
    'E0:46:9A': 'Netgear', 'E8:9A:8F': 'Netgear', 'F0:9C:E2': 'Netgear',
    # D-Link
    '00:05:5D': 'D-Link', '00:0D:88': 'D-Link', '00:11:95': 'D-Link',
    '00:13:46': 'D-Link', '00:15:E9': 'D-Link', '00:17:9A': 'D-Link',
    '00:19:5B': 'D-Link', '00:1B:11': 'D-Link', '00:1C:F0': 'D-Link',
    '00:1E:58': 'D-Link', '00:21:91': 'D-Link', '00:22:B0': 'D-Link',
    '00:24:01': 'D-Link', '00:26:5A': 'D-Link', '00:27:E4': 'D-Link',
    # Qualcomm / Atheros
    '00:13:49': 'Qualcomm', '00:16:32': 'Qualcomm', '00:17:C4': 'Qualcomm',
    '00:19:25': 'Qualcomm', '00:1B:06': 'Qualcomm', '00:1D:4D': 'Qualcomm',
    '00:1F:2E': 'Qualcomm', '00:21:2C': 'Qualcomm', '00:23:1D': 'Qualcomm',
    '00:24:06': 'Qualcomm', '00:25:2C': 'Qualcomm', '00:26:37': 'Qualcomm',
    # MediaTek
    '00:1F:7B': 'MediaTek', '00:22:F6': 'MediaTek', '00:24:1C': 'MediaTek',
    # Realtek
    '00:04:76': 'Realtek', '00:07:95': 'Realtek', '00:0A:E6': 'Realtek',
    '00:0E:2E': 'Realtek', '00:11:09': 'Realtek', '00:13:D4': 'Realtek',
    '00:15:F2': 'Realtek', '00:16:D9': 'Realtek', '00:18:4D': 'Realtek',
    '00:1A:4D': 'Realtek', '00:1D:72': 'Realtek', '00:1F:1F': 'Realtek',
    '00:22:68': 'Realtek', '00:24:8C': 'Realtek', '00:26:18': 'Realtek',
    # Intel
    '00:07:E9': 'Intel', '00:09:5B': 'Intel', '00:15:17': 'Intel',
    '00:16:76': 'Intel', '00:19:23': 'Intel', '00:1A:6A': 'Intel',
    '00:1B:3E': 'Intel', '00:1C:BF': 'Intel', '00:1E:65': 'Intel',
    '00:21:5C': 'Intel', '00:22:FB': 'Intel', '00:24:D7': 'Intel',
    '00:26:C7': 'Intel', '00:27:10': 'Intel', '00:27:15': 'Intel',
    '00:28:F8': 'Intel', '00:2A:37': 'Intel', '00:2B:48': 'Intel',
    '00:2C:C7': 'Intel', '00:2D:68': 'Intel', '00:2E:4F': 'Intel',
    # Microsoft
    '00:15:5D': 'Microsoft', '00:50:56': 'VMware', '08:00:27': 'VirtualBox',
    # Oneplus
    '3C:C8:FB': 'OnePlus', '50:91:E3': 'OnePlus', '9C:B6:D0': 'OnePlus',
    # LG
    '00:1B:69': 'LG', '00:1C:62': 'LG', '00:1E:75': 'LG',
    '00:22:13': 'LG', '00:24:D9': 'LG', '00:26:5E': 'LG',
    '00:28:F8': 'LG', '00:2A:37': 'LG',
    # Sony
    '00:07:7D': 'Sony', '00:0E:46': 'Sony', '00:12:3F': 'Sony',
    '00:16:6D': 'Sony', '00:19:D1': 'Sony', '00:1D:BA': 'Sony',
    '00:22:48': 'Sony', '00:24:33': 'Sony', '00:26:43': 'Sony',
    # Motorola
    '00:04:1E': 'Motorola', '00:11:22': 'Motorola', '00:12:D1': 'Motorola',
    '00:13:20': 'Motorola', '00:14:38': 'Motorola', '00:15:05': 'Motorola',
    '00:16:CB': 'Motorola', '00:18:66': 'Motorola', '00:19:63': 'Motorola',
}


class EnhancedNetworkScanner:
    """
    Network Scanner – uses nmap for host discovery, Scapy for MAC and TTL.
    """

    def __init__(self, db_path: str = "data/network_scanner.db"):
        self.db_path = db_path
        self.scapy_available = SCAPY_AVAILABLE
        self.nmap_available = NMAP_AVAILABLE
        self.psutil_available = PSUTIL_AVAILABLE
        self.interface = self._get_wifi_interface()
        self.permissions_ok = self._check_permissions()
        self.mac_cache = {}
        self._load_mac_cache()

        self.oui_cache = {}
        self._load_oui_cache()

        self.nmap_scanner = nmap.PortScanner() if NMAP_AVAILABLE else None

        os.makedirs(os.path.dirname(db_path) if os.path.dirname(db_path) else ".", exist_ok=True)
        self._init_database()

        self.OS_CONFIDENCE_THRESHOLD = 40

        logger.info(f"✅ Scanner initialized on interface: {self.interface}")
        logger.info(f"   Scapy: {'✅' if self.scapy_available else '❌'}")
        logger.info(f"   Nmap: {'✅' if self.nmap_available else '❌'}")
        logger.info(f"   Permissions: {'✅' if self.permissions_ok else '⚠️  (Scapy may fail without admin/root)'}")

    # ============================================================================
    # PERMISSION CHECK
    # ============================================================================
    def _check_permissions(self) -> bool:
        if sys.platform.startswith('win'):
            return True
        try:
            return os.geteuid() == 0
        except AttributeError:
            return False

    # ============================================================================
    # INTERFACE DETECTION (unchanged)
    # ============================================================================
    def _get_wifi_interface(self) -> str:
        if self.psutil_available:
            try:
                import psutil
                for iface, addrs in psutil.net_if_addrs().items():
                    iface_lower = iface.lower()
                    if ('wi-fi' in iface_lower or 'wireless' in iface_lower or
                        'wlan' in iface_lower or 'wifi' in iface_lower):
                        for addr in addrs:
                            if addr.family == socket.AF_INET and addr.address != '127.0.0.1':
                                if not addr.address.startswith('169.254'):
                                    return iface
            except:
                pass
        if sys.platform.startswith('win'):
            try:
                result = subprocess.run(
                    ['netsh', 'interface', 'show', 'interface'],
                    capture_output=True,
                    text=True,
                    timeout=2
                )
                for line in result.stdout.split('\n'):
                    if 'Wi-Fi' in line or 'Wireless' in line or 'WLAN' in line:
                        parts = line.split()
                        if len(parts) >= 4:
                            return parts[-1]
            except:
                pass
        wifi_names = ['Wi-Fi', 'WiFi', 'Wireless', 'WLAN', 'wlan0']
        for iface in wifi_names:
            try:
                if sys.platform.startswith('win'):
                    subprocess.run(['ipconfig', iface], capture_output=True, timeout=2)
                else:
                    subprocess.run(['ip', 'link', 'show', iface], capture_output=True, timeout=2)
                return iface
            except:
                continue
        return self._get_default_interface()

    def _get_default_interface(self) -> str:
        if self.psutil_available:
            try:
                import psutil
                for iface, addrs in psutil.net_if_addrs().items():
                    for addr in addrs:
                        if addr.family == socket.AF_INET and addr.address != '127.0.0.1':
                            if not addr.address.startswith('169.254'):
                                return iface
            except:
                pass
        if sys.platform.startswith('win'):
            try:
                result = subprocess.run(['ipconfig'], capture_output=True, text=True, timeout=2)
                lines = result.stdout.split('\n')
                current_iface = None
                for line in lines:
                    if 'adapter' in line.lower():
                        match = re.search(r'adapter\s+([^:]+):', line, re.IGNORECASE)
                        if match:
                            current_iface = match.group(1).strip()
                    elif 'ipv4' in line.lower() and current_iface:
                        match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                        if match:
                            ip = match.group(1)
                            if not ip.startswith('127.') and not ip.startswith('169.254'):
                                return current_iface
            except:
                pass
        return 'eth0'

    def _get_local_ip(self) -> str:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "192.168.1.1"

    def _get_network_range(self, target: str = None) -> str:
        if target and '/' in target:
            return target
        local_ip = self._get_local_ip()
        parts = local_ip.split('.')
        return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"

    # ============================================================================
    # MAC UTILITIES - FIXED
    # ============================================================================
    def _normalize_mac(self, mac: str) -> str:
        if not mac:
            return ''
        # Remove any separators (colons, dashes, dots, spaces)
        mac = re.sub(r'[^0-9A-Fa-f]', '', mac)
        if len(mac) != 12:
            return mac  # fallback, unlikely
        # Insert colon every two characters
        mac = ':'.join(mac[i:i+2] for i in range(0, 12, 2))
        return mac.upper()

    def _get_oui_from_mac(self, mac: str) -> str:
        mac = self._normalize_mac(mac)
        if len(mac) >= 17:  # 'XX:XX:XX:...'
            return mac[:8]  # first 3 octets
        return ''

    def _get_mac_from_arp_cache(self, ip: str) -> str:
        mac = ''
        try:
            if sys.platform.startswith('win'):
                result = subprocess.run(['arp', '-a', ip], capture_output=True, text=True, timeout=1)
                if result.returncode == 0:
                    match = re.search(r'([0-9a-fA-F]{2}-[0-9a-fA-F]{2}-[0-9a-fA-F]{2}-[0-9a-fA-F]{2}-[0-9a-fA-F]{2}-[0-9a-fA-F]{2})', result.stdout)
                    if match:
                        mac = self._normalize_mac(match.group(1))
            else:
                result = subprocess.run(['arp', '-n', ip], capture_output=True, text=True, timeout=1)
                if result.returncode == 0:
                    match = re.search(r'([0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2})', result.stdout)
                    if match:
                        mac = self._normalize_mac(match.group(1))
                if not mac and sys.platform.startswith('linux'):
                    result = subprocess.run(['ip', 'neigh', 'show', ip], capture_output=True, text=True, timeout=1)
                    if result.returncode == 0:
                        match = re.search(r'([0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2})', result.stdout)
                        if match:
                            mac = self._normalize_mac(match.group(1))
        except Exception as e:
            logger.debug(f"Failed to get MAC from ARP cache for {ip}: {e}")
        return mac

    def _is_randomized_mac(self, mac: str) -> bool:
        if not mac:
            return False
        try:
            first_byte = int(mac[0:2], 16)
            is_local = (first_byte & 0x02) != 0
            second_nibble = int(mac[1], 16)
            is_random_pattern = second_nibble in [2, 6, 10, 14]
            return is_local and is_random_pattern
        except:
            return False

    # ============================================================================
    # OUI LOOKUP (unchanged)
    # ============================================================================
    def _lookup_oui_online(self, oui: str) -> Optional[str]:
        if not oui:
            return None
        oui_clean = oui.upper().replace(':', '')
        if oui in self.oui_cache:
            return self.oui_cache[oui]
        for vendor in self._try_online_oui_lookup(oui_clean):
            if vendor:
                self.oui_cache[oui] = vendor
                self._save_oui_cache()
                return vendor
        return None

    def _try_online_oui_lookup(self, oui_hex: str) -> List[Optional[str]]:
        vendors = []
        try:
            url = f"https://api.macvendors.com/{oui_hex}"
            req = urllib.request.Request(url, headers={'User-Agent': 'NetworkScanner/1.0'})
            with urllib.request.urlopen(req, timeout=3) as resp:
                vendor = resp.read().decode('utf-8').strip()
                if vendor and vendor != 'Not Found' and '<' not in vendor:
                    vendors.append(vendor)
        except:
            pass
        try:
            url = f"https://api.maclookup.app/v2/macs/{oui_hex}"
            req = urllib.request.Request(url, headers={'User-Agent': 'NetworkScanner/1.0'})
            with urllib.request.urlopen(req, timeout=3) as resp:
                data = json.loads(resp.read().decode('utf-8'))
                if data and data.get('company'):
                    vendors.append(data['company'])
        except:
            pass
        return vendors

    def _get_vendor_from_mac(self, mac: str) -> str:
        if not mac:
            return 'Unknown'
        if self._is_randomized_mac(mac):
            return 'Unknown (Randomized MAC)'
        mac_prefix = self._get_oui_from_mac(mac)
        vendor = MAC_VENDORS.get(mac_prefix, '')
        if vendor:
            return vendor
        vendor = self._lookup_oui_online(mac_prefix)
        if vendor:
            return vendor
        return 'Unknown'

    def _lookup_oui_cache_file(self) -> str:
        cache_dir = os.path.join(os.environ.get('TEMP', '/tmp'), 'network_scanner')
        os.makedirs(cache_dir, exist_ok=True)
        return os.path.join(cache_dir, 'oui_cache.json')

    def _load_oui_cache(self):
        cache_file = self._lookup_oui_cache_file()
        if os.path.exists(cache_file):
            try:
                with open(cache_file, 'r') as f:
                    self.oui_cache = json.load(f)
            except Exception as e:
                logger.debug(f"Failed to load OUI cache: {e}")

    def _save_oui_cache(self):
        cache_file = self._lookup_oui_cache_file()
        try:
            with open(cache_file, 'w') as f:
                json.dump(self.oui_cache, f)
        except Exception as e:
            logger.debug(f"Failed to save OUI cache: {e}")

    # ============================================================================
    # DATABASE (unchanged)
    # ============================================================================
    def _init_database(self):
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS devices (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip_address TEXT UNIQUE,
                    mac_address TEXT,
                    hostname TEXT,
                    device_type TEXT,
                    brand TEXT,
                    os TEXT,
                    os_family TEXT,
                    os_confidence REAL,
                    open_ports TEXT,
                    services TEXT,
                    discovery_source TEXT,
                    confidence REAL,
                    confidence_level TEXT,
                    ttl INTEGER,
                    first_seen TEXT,
                    last_seen TEXT,
                    scan_count INTEGER DEFAULT 1,
                    upnp_model_name TEXT,
                    upnp_model_number TEXT,
                    upnp_manufacturer TEXT,
                    mac_randomized INTEGER DEFAULT 0,
                    mac_is_local INTEGER DEFAULT 0,
                    is_gateway INTEGER DEFAULT 0
                )
            ''')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_ip ON devices(ip_address)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_mac ON devices(mac_address)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_last_seen ON devices(last_seen)')
            conn.commit()
            conn.close()
            logger.info("✅ Database initialized")
        except Exception as e:
            logger.error(f"Database init error: {e}")

    def _load_mac_cache(self):
        cache_file = os.path.join(os.environ.get('TEMP', '/tmp'), 'mac_cache.json')
        if os.path.exists(cache_file):
            try:
                with open(cache_file, 'r') as f:
                    self.mac_cache = json.load(f)
            except Exception as e:
                logger.warning(f"Failed to load MAC cache: {e}")

    def _save_mac_cache(self):
        cache_file = os.path.join(os.environ.get('TEMP', '/tmp'), 'mac_cache.json')
        try:
            with open(cache_file, 'w') as f:
                json.dump(self.mac_cache, f)
        except Exception as e:
            logger.warning(f"Failed to save MAC cache: {e}")

    # ============================================================================
    # OS DETECTION - IMPROVED
    # ============================================================================
    def _detect_os(self, ip: str, ttl: Optional[int], open_ports: List[int],
                   hostname: str, mac: str = '') -> Dict[str, Any]:
        os_name = 'Unknown'
        confidence = 0
        os_family = 'Unknown'
        hints = []

        nmap_os = self._detect_os_with_nmap(ip)
        if nmap_os != 'Unknown':
            os_name = nmap_os
            confidence += 50
            hints.append('nmap')

        hostname_os = self._detect_os_from_hostname(hostname)
        if hostname_os != 'Unknown':
            os_name = hostname_os
            confidence += 25
            hints.append('hostname')

        if ttl:
            ttl_os = self._detect_os_from_ttl(ttl)
            if ttl_os != 'Unknown':
                if os_name == 'Unknown' or confidence < 30:
                    os_name = ttl_os['os']
                    os_family = ttl_os['family']
                    confidence += 30
                    hints.append(f'ttl={ttl}')
                elif os_name == ttl_os['os']:
                    confidence += 10
                    hints.append(f'ttl={ttl}_confirmed')

        port_os = self._detect_os_from_ports(open_ports)
        if port_os != 'Unknown':
            if os_name == 'Unknown' or (os_name != port_os and confidence < 40):
                os_name = port_os
                confidence += 25
                hints.append('ports')
            elif os_name == port_os:
                confidence += 10

        if self._is_randomized_mac(mac):
            if os_name == 'Unknown':
                os_name = 'Mobile (Randomized MAC)'
                os_family = 'Mobile'
                confidence += 15
                hints.append('randomized_mac')

        if os_name == 'Unknown' or confidence < self.OS_CONFIDENCE_THRESHOLD:
            fallback_os = self._fallback_os_detection(ip)
            if fallback_os != 'Unknown':
                os_name = fallback_os
                confidence += 15
                hints.append('fallback')

        if ttl and ttl > 200:
            vendor = self._get_vendor_from_mac(mac)
            if any(v in vendor.lower() for v in ['netis', 'tp-link', 'netgear', 'd-link',
                                                   'cisco', 'asus', 'linksys', 'huawei', 'zte']):
                os_name = 'Router Firmware'
                os_family = 'Network'
                confidence = max(confidence, 50)
                hints.append('router_vendor')

        if mac:
            vendor = self._get_vendor_from_mac(mac)
            router_vendors = ['netis', 'cisco', 'netgear', 'tp-link', 'd-link', 'linksys',
                              'asus', 'mikrotik', 'ubiquiti', 'juniper', 'huawei', 'zte']
            if any(v in vendor.lower() for v in router_vendors):
                if confidence < 70:
                    os_name = 'Router Firmware'
                    os_family = 'Network'
                    confidence = max(confidence, 70)
                    hints.append('router_vendor_override')

        if 'Linux' in os_name or 'Android' in os_name or 'Unix' in os_name:
            os_family = 'Unix'
        elif 'Windows' in os_name:
            os_family = 'Windows'
        elif 'macOS' in os_name or 'iOS' in os_name or 'Apple' in os_name:
            os_family = 'Apple'
        elif 'Router' in os_name or 'Network' in os_name or 'Network_Device' in os_name:
            os_family = 'Network'
        elif 'Mobile' in os_name:
            os_family = 'Mobile'

        return {
            'os_name': os_name,
            'os_family': os_family,
            'confidence': min(confidence, 100),
            'hints': hints
        }

    def _detect_os_from_ttl(self, ttl: int) -> Dict[str, str]:
        if ttl <= 32:
            return {'os': 'Linux', 'family': 'Unix'}
        elif ttl <= 64:
            return {'os': 'Linux/Android', 'family': 'Unix'}
        elif ttl <= 65:
            return {'os': 'Linux/Android', 'family': 'Unix'}
        elif ttl <= 100:
            return {'os': 'Windows', 'family': 'Windows'}
        elif ttl <= 128:
            return {'os': 'Windows', 'family': 'Windows'}
        elif ttl <= 130:
            return {'os': 'Windows', 'family': 'Windows'}
        elif ttl <= 180:
            return {'os': 'Linux', 'family': 'Unix'}
        elif ttl <= 200:
            return {'os': 'Linux', 'family': 'Unix'}
        elif ttl <= 255:
            return {'os': 'macOS/iOS/Network_Device', 'family': 'Network'}
        else:
            return {'os': 'Unknown', 'family': 'Unknown'}

    def _detect_os_from_ports(self, ports: List[int]) -> str:
        if not ports:
            return 'Unknown'
        port_set = set(ports)
        windows_ports = {135, 137, 139, 445, 3389}
        linux_ports = {22, 111, 2049, 6000}
        macos_ports = {548, 631, 3689, 5353}
        network_ports = {23, 161, 162, 514, 69}
        windows_match = len(port_set & windows_ports)
        linux_match = len(port_set & linux_ports)
        macos_match = len(port_set & macos_ports)
        network_match = len(port_set & network_ports)
        if windows_match >= 2:
            return 'Windows'
        elif linux_match >= 2:
            return 'Linux'
        elif macos_match >= 2:
            return 'macOS'
        elif network_match >= 2:
            return 'Network_Device'
        if 22 in ports and 80 in ports:
            return 'Linux'
        if 80 in ports and 443 in ports:
            return 'Linux'
        if 445 in ports and 139 in ports:
            return 'Windows'
        if 548 in ports:
            return 'macOS'
        if 23 in ports:
            return 'Network_Device'
        return 'Unknown'

    def _detect_os_from_hostname(self, hostname: str) -> str:
        if not hostname:
            return 'Unknown'
        hostname_lower = hostname.lower()
        if any(x in hostname_lower for x in ['android', 'galaxy', 'pixel', 'oneplus',
                                               'moto', 'huawei', 'xiaomi', 'redmi', 'poco']):
            return 'Android'
        if any(x in hostname_lower for x in ['iphone', 'ipad', 'ipod', 'darwin',
                                               'ios-', 'ios_', 'ios.local']):
            return 'iOS'
        if any(x in hostname_lower for x in ['macbook', 'macbook-pro', 'imac',
                                               'mac mini', 'macpro', 'air']):
            return 'macOS'
        if 'windows' in hostname_lower:
            return 'Windows'
        elif any(x in hostname_lower for x in ['linux', 'ubuntu', 'debian', 'centos',
                                                 'fedora', 'arch', 'raspberry']):
            return 'Linux'
        elif any(x in hostname_lower for x in ['mac', 'osx']):
            return 'macOS'
        elif 'android' in hostname_lower:
            return 'Android'
        elif any(x in hostname_lower for x in ['router', 'gateway', 'ap', 'switch']):
            return 'Network_Device'
        return 'Unknown'

    def _detect_os_with_nmap(self, ip: str) -> str:
        if not self.nmap_available or not self.nmap_scanner or not self.permissions_ok:
            return 'Unknown'
        try:
            self.nmap_scanner.scan(ip, arguments='-O --osscan-guess -T4 --host-timeout 30s')
            if ip in self.nmap_scanner.all_hosts():
                host = self.nmap_scanner[ip]
                os_matches = host.get('osmatch', [])
                if os_matches:
                    best_match = os_matches[0]
                    accuracy = int(best_match.get('accuracy', 0))
                    if accuracy > 70:
                        return best_match.get('name', 'Unknown')
        except Exception as e:
            logger.debug(f"Nmap OS detection failed: {e}")
        return 'Unknown'

    def _fallback_os_detection(self, ip: str) -> str:
        try:
            hostname = socket.gethostbyaddr(ip)[0].lower()
            if 'win' in hostname:
                return 'Windows'
            elif 'linux' in hostname or 'ubuntu' in hostname:
                return 'Linux'
            elif 'mac' in hostname or 'apple' in hostname:
                return 'macOS'
            elif 'android' in hostname:
                return 'Android'
            elif 'iphone' in hostname or 'ipad' in hostname:
                return 'iOS'
        except:
            pass
        ttl = self._get_ttl(ip)   # system ping fallback
        if ttl:
            ttl_info = self._detect_os_from_ttl(ttl)
            return ttl_info['os']
        try:
            if sys.platform.startswith('win'):
                cmd = ['ping', '-n', '1', '-l', '64', ip]
            else:
                cmd = ['ping', '-c', '1', '-s', '64', ip]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=3)
            if result.returncode == 0:
                if 'TTL' in result.stdout:
                    return 'Windows' if 'TTL=128' in result.stdout else 'Linux'
        except:
            pass
        return 'Unknown'

    def _get_ttl(self, ip: str) -> Optional[int]:
        try:
            if sys.platform.startswith('win'):
                cmd = ['ping', '-n', '1', ip]
            else:
                cmd = ['ping', '-c', '1', ip]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=3)
            if result.returncode == 0:
                if sys.platform.startswith('win'):
                    match = re.search(r'TTL=(\d+)', result.stdout, re.IGNORECASE)
                else:
                    match = re.search(r'ttl=(\d+)', result.stdout.lower())
                if match:
                    return int(match.group(1))
        except:
            pass
        return None

    # ============================================================================
    # DEFAULT GATEWAY - IMPROVED
    # ============================================================================
    def _get_default_gateway(self) -> Optional[str]:
        try:
            if NETIFACES_AVAILABLE:
                gateways = netifaces.gateways()
                default = gateways.get('default', {})
                if default and netifaces.AF_INET in default:
                    return default[netifaces.AF_INET][0]
        except:
            pass

        if sys.platform.startswith('win'):
            try:
                result = subprocess.run(['ipconfig'], capture_output=True, text=True, timeout=2)
                for line in result.stdout.split('\n'):
                    if 'Default Gateway' in line:
                        parts = line.split(':')
                        if len(parts) > 1:
                            gateway = parts[1].strip()
                            if gateway and not gateway.startswith('::'):
                                return gateway
            except:
                pass
        else:
            try:
                result = subprocess.run(['ip', 'route', 'show', 'default'], capture_output=True, text=True, timeout=2)
                for line in result.stdout.split('\n'):
                    if 'default' in line:
                        parts = line.split()
                        for i, part in enumerate(parts):
                            if part == 'via' and i + 1 < len(parts):
                                return parts[i+1]
            except:
                pass

        # Fallback: guess from local IP
        local_ip = self._get_local_ip()
        parts = local_ip.split('.')
        return f"{parts[0]}.{parts[1]}.{parts[2]}.1"

    # ============================================================================
    # UPNP DISCOVERY (unchanged)
    # ============================================================================
    def _discover_upnp_devices(self, timeout: int = 3) -> Dict[str, Dict[str, str]]:
        upnp_info = {}
        msg = (
            'M-SEARCH * HTTP/1.1\r\n'
            'HOST: 239.255.255.250:1900\r\n'
            'MAN: "ssdp:discover"\r\n'
            'MX: 2\r\n'
            'ST: ssdp:all\r\n'
            '\r\n'
        )
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            sock.settimeout(timeout)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.sendto(msg.encode('utf-8'), ('239.255.255.250', 1900))
            logger.info("📡 Sending UPnP discovery request...")
            start_time = time.time()
            while time.time() - start_time < timeout:
                try:
                    data, addr = sock.recvfrom(65536)
                    ip = addr[0]
                    response = data.decode('utf-8', errors='ignore')
                    location_match = re.search(r'(?i)Location:\s*(https?://[^\r\n]+)', response)
                    if location_match:
                        location_url = location_match.group(1).strip()
                        if ip not in upnp_info:
                            device_details = self._fetch_upnp_xml(location_url)
                            if device_details:
                                upnp_info[ip] = device_details
                except socket.timeout:
                    break
                except Exception as e:
                    logger.debug(f"Error receiving UPnP response: {e}")
        except Exception as e:
            logger.error(f"UPnP discovery failed: {e}")
        finally:
            sock.close()
        return upnp_info

    def _fetch_upnp_xml(self, url: str) -> Dict[str, str]:
        details = {}
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=2) as response:
                xml_data = response.read()
            xml_str = xml_data.decode('utf-8', errors='ignore')
            xml_str = re.sub(r'\sxmlns="[^"]+"', '', xml_str, count=1)
            root = ET.fromstring(xml_str)
            device = root.find('.//device')
            if device is not None:
                friendly_name = device.findtext('friendlyName')
                model_name = device.findtext('modelName')
                model_number = device.findtext('modelNumber')
                manufacturer = device.findtext('manufacturer')
                if friendly_name: details['friendlyName'] = friendly_name
                if model_name: details['modelName'] = model_name
                if model_number: details['modelNumber'] = model_number
                if manufacturer: details['manufacturer'] = manufacturer
        except Exception as e:
            logger.debug(f"Failed to fetch/parse UPnP XML from {url}: {e}")
        return details

    # ============================================================================
    # NEW DISCOVERY: nmap + scapy only
    # ============================================================================
    def _discover_devices(self, ip_range: str) -> List[Dict[str, Any]]:
        """
        Primary: use nmap -sn to get live IPs.
        Then for each IP, use Scapy to get MAC and TTL.
        If nmap not available, use Scapy ARP scan.
        If both fail, return empty.
        """
        live_ips = []

        # 1. Try nmap if available
        if self.nmap_available and self.nmap_scanner:
            logger.info("🔎 Using nmap -sn for host discovery...")
            try:
                self.nmap_scanner.scan(hosts=ip_range, arguments='-sn -T4 --host-timeout 10s')
                live_ips = self.nmap_scanner.all_hosts()
                logger.info(f"✅ Nmap found {len(live_ips)} live hosts.")
            except Exception as e:
                logger.error(f"Nmap scan failed: {e}")
                live_ips = []

        # 2. Fallback to Scapy ARP scan if nmap gave nothing or not available
        if not live_ips and self.scapy_available and self.permissions_ok:
            logger.info("🔎 Nmap not available/empty – falling back to Scapy ARP scan...")
            arp_devices = self._arp_scan_scapy(ip_range)
            if arp_devices:
                logger.info(f"✅ Scapy ARP found {len(arp_devices)} devices.")
                return arp_devices
            else:
                logger.warning("Scapy ARP scan returned no devices.")

        # If we have nmap results, enrich them with MAC & TTL using Scapy (or ARP cache)
        if live_ips:
            devices = []
            for ip in live_ips:
                # Exclude self and invalid
                if not self._should_include_device(ip):
                    continue
                # Get MAC via Scapy ARP request (if possible) else ARP cache
                mac = ''
                if self.scapy_available and self.permissions_ok:
                    mac = self._get_mac_with_scapy(ip)
                if not mac:
                    mac = self._get_mac_from_arp_cache(ip)

                # Get TTL via Scapy ICMP echo, fallback to TCP SYN, then system ping
                ttl = None
                if self.scapy_available and self.permissions_ok:
                    ttl = self._get_ttl_with_scapy(ip)
                    if ttl is None:
                        ttl = self._get_ttl_with_tcp(ip)  # try TCP SYN
                if ttl is None and not (self.scapy_available and self.permissions_ok):
                    ttl = self._get_ttl(ip)  # system ping (last resort)

                hostname = self._get_hostname(ip)

                devices.append({
                    'ip_address': ip,
                    'mac_address': mac,
                    'hostname': hostname,
                    'ttl': ttl,
                    'status': 'up',
                    'discovery_source': ['nmap_sn']
                })
            logger.info(f"✅ Enriched {len(devices)} devices with MAC/TTL.")
            return devices

        # If we reach here, no devices found.
        logger.warning("No devices discovered by nmap or scapy.")
        return []

    # -------------------------------------------------------------------------
    # Scapy helpers
    # -------------------------------------------------------------------------
    def _get_mac_with_scapy(self, ip: str) -> str:
        """Send ARP request to a single IP and return MAC."""
        if not self.scapy_available or not self.permissions_ok:
            return ''
        try:
            arp = ARP(pdst=ip)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether / arp
            ans, _ = srp(packet, timeout=2, verbose=False, iface=self.interface)
            for sent, received in ans:
                if received.psrc == ip:
                    return self._normalize_mac(received.hwsrc)
        except Exception as e:
            logger.debug(f"Scapy MAC request for {ip} failed: {e}")
        return ''

    def _get_ttl_with_scapy(self, ip: str) -> Optional[int]:
        """Send ICMP echo request and extract TTL from reply."""
        if not self.scapy_available or not self.permissions_ok:
            return None
        try:
            packet = IP(dst=ip) / ICMP()
            reply = sr1(packet, timeout=2, verbose=False)
            if reply:
                return reply.ttl
        except Exception as e:
            logger.debug(f"Scapy ICMP request for {ip} failed: {e}")
        return None

    def _get_ttl_with_tcp(self, ip: str, port: int = 80) -> Optional[int]:
        """Send TCP SYN to a common port and extract TTL from SYN-ACK."""
        if not self.scapy_available or not self.permissions_ok:
            return None
        try:
            pkt = IP(dst=ip) / TCP(dport=port, flags='S')
            reply = sr1(pkt, timeout=2, verbose=False)
            if reply and reply.haslayer(TCP):
                return reply.ttl
        except Exception:
            pass
        return None

    def _arp_scan_scapy(self, ip_range: str) -> List[Dict[str, Any]]:
        """Full ARP scan over the whole subnet – used as fallback."""
        if not self.scapy_available or not self.permissions_ok:
            return []
        try:
            network = ipaddress.ip_network(ip_range, strict=False)
        except ValueError:
            return []
        ip_list = [str(ip) for ip in network.hosts()]
        logger.info(f"   Sending ARP requests to {len(ip_list)} IPs...")
        arp = ARP(pdst=ip_range)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp
        try:
            answered, _ = srp(packet, timeout=3, verbose=False, iface=self.interface)
        except Exception as e:
            logger.error(f"Scapy ARP scan failed: {e}")
            return []
        devices = []
        for sent, received in answered:
            ip = received.psrc
            mac = received.hwsrc
            hostname = self._get_hostname(ip)
            ttl = self._get_ttl_with_scapy(ip) or self._get_ttl_with_tcp(ip) or self._get_ttl(ip)
            devices.append({
                'ip_address': ip,
                'mac_address': self._normalize_mac(mac),
                'hostname': hostname,
                'ttl': ttl,
                'status': 'up',
                'discovery_source': ['arp_scan']
            })
        return devices

    # -------------------------------------------------------------------------
    # Helper methods (unchanged)
    # -------------------------------------------------------------------------
    def _get_hostname(self, ip: str) -> str:
        try:
            return socket.gethostbyaddr(ip)[0]
        except:
            return ''

    def _should_include_device(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
            if addr.is_multicast or addr.is_link_local:
                return False
            if str(addr).endswith('.255'):
                return False
        except ValueError:
            return False
        virtual_subnets = ['192.168.121.', '192.168.154.', '192.168.56.', '10.0.2.', '10.0.3.']
        for subnet in virtual_subnets:
            if ip.startswith(subnet):
                return False
        return True

    # ============================================================================
    # PORT SCANNING (unchanged)
    # ============================================================================
    def tcp_port_scan(self, target: str, ports: List[int] = None) -> List[int]:
        if not ports:
            ports = [22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995,
                     1723, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 27017]
        open_ports = []
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                result = sock.connect_ex((target, port))
                sock.close()
                if result == 0:
                    open_ports.append(port)
            except:
                continue
        return open_ports

    def _get_service_name(self, port: int) -> str:
        services = {
            22: 'ssh', 23: 'telnet', 25: 'smtp', 53: 'dns',
            80: 'http', 110: 'pop3', 135: 'msrpc', 139: 'netbios',
            143: 'imap', 443: 'https', 445: 'smb', 993: 'imaps',
            995: 'pop3s', 1723: 'pptp', 3306: 'mysql', 3389: 'rdp',
            5432: 'postgresql', 5900: 'vnc', 6379: 'redis',
            8080: 'http-alt', 8443: 'https-alt', 27017: 'mongodb'
        }
        return services.get(port, f'port_{port}')

    # ============================================================================
    # DEVICE INTELLIGENCE - FIXED
    # ============================================================================
    def _detect_device_type(self, hostname: str, os_name: str, open_ports: List[int],
                            mac: str, ip: str, ttl: Optional[int] = None) -> str:
        # 1. Gateway check (highest priority)
        gateway = self._get_default_gateway()
        if gateway and ip == gateway:
            return 'Router'

        # 2. If IP ends with .1 and has typical router infrastructure ports
        if ip.endswith('.1') and any(p in open_ports for p in [53, 67, 68]):
            return 'Router'

        # 3. Vendor-based router detection (but only if not obviously Windows)
        vendor = self._get_vendor_from_mac(mac)
        router_vendors = ['cisco', 'netgear', 'tp-link', 'd-link', 'linksys', 'asus',
                          'netis', 'mikrotik', 'ubiquiti', 'juniper', 'huawei', 'zte']
        if any(v in vendor.lower() for v in router_vendors):
            # If the OS is already detected as Windows, override vendor guess
            if 'windows' not in os_name.lower():
                return 'Router'

        # 4. Hostname-based router keywords
        if hostname:
            host_lower = hostname.lower()
            router_keywords = ['router', 'gateway', 'ap', 'wifi', 'wlan', 'netis', 'cisco', 'tp-link']
            if any(kw in host_lower for kw in router_keywords) and 'windows' not in os_name.lower():
                return 'Router'

        # 5. OS detection: if Windows, classify as PC
        if 'windows' in os_name.lower():
            return 'Windows_PC'

        # 6. Mobile device detection (randomized MAC, hostname keywords, or TTL heuristics)
        is_mobile = False
        if self._is_randomized_mac(mac):
            is_mobile = True
        if hostname:
            mobile_keywords = ['android', 'galaxy', 'pixel', 'oneplus', 'iphone', 'ipad',
                               'ipod', 'samsung', 'huawei', 'xiaomi', 'redmi', 'poco',
                               'moto', 'motorola', 'oppo', 'vivo', 'realme']
            if any(kw in hostname.lower() for kw in mobile_keywords):
                is_mobile = True
        if ttl and ttl in [64, 128] and not open_ports:
            is_mobile = True
        if is_mobile:
            if hostname and any(kw in hostname.lower() for kw in ['iphone', 'ipad', 'ipod', 'ios']):
                return 'iPhone/iPad'
            elif ttl == 128 and not open_ports:
                return 'iOS Device'
            else:
                return 'Mobile'

        # 7. Windows-specific open ports (SMB + RDP)
        if 445 in open_ports and 3389 in open_ports:
            return 'Windows_PC'

        # 8. Mac-specific port (AFP)
        if 548 in open_ports:
            return 'Mac'

        # 9. Linux server (SSH + HTTP)
        if 22 in open_ports and 80 in open_ports:
            return 'Linux_Server'

        # 10. Web server (HTTP + HTTPS) – but only if not already classified as router
        if 80 in open_ports and 443 in open_ports:
            return 'WebServer'

        # 11. Router-specific ports (exclude 80, 443, 8080 to avoid false positives)
        router_ports = {53, 67, 68, 69, 161, 162, 23}
        if len(set(open_ports) & router_ports) >= 2:
            return 'Router'

        # 12. TTL > 200 often indicates network devices
        if ttl and ttl > 200:
            return 'Network_Device'

        # 13. Fallback based on OS name
        if 'android' in os_name.lower():
            return 'Mobile'
        if 'ios' in os_name.lower():
            return 'iPhone/iPad'
        if 'linux' in os_name.lower():
            return 'Linux_PC'
        if 'macos' in os_name.lower():
            return 'Mac'

        # 14. Last resort: randomized MAC with no ports → likely mobile
        if not open_ports and self._is_randomized_mac(mac):
            return 'Mobile'

        # 15. Original fallback (kept for completeness)
        return self._detect_device_type_original(hostname, os_name, open_ports, mac)

    def _detect_device_type_original(self, hostname: str, os_name: str, open_ports: List[int], mac: str) -> str:
        vendor = self._get_vendor_from_mac(mac)
        if 'router' in vendor.lower() or 'network' in vendor.lower():
            return 'Router'
        if 'phone' in vendor.lower() or 'mobile' in vendor.lower():
            return 'Mobile'
        if 'printer' in vendor.lower():
            return 'Printer'
        if hostname:
            hostname_lower = hostname.lower()
            if any(x in hostname_lower for x in ['phone', 'mobile', 'android', 'iphone', 'ipad']):
                return 'Mobile'
            if any(x in hostname_lower for x in ['router', 'gateway', 'ap', 'wifi']):
                return 'Router'
            if any(x in hostname_lower for x in ['server', 'db', 'database', 'web']):
                return 'Server'
            if any(x in hostname_lower for x in ['printer', 'print']):
                return 'Printer'
            if any(x in hostname_lower for x in ['tv', 'smarttv', 'roku']):
                return 'SmartTV'
        if 23 in open_ports and 80 in open_ports:
            return 'Router'
        if 445 in open_ports and 3389 in open_ports:
            return 'Windows_PC'
        if 548 in open_ports:
            return 'Mac'
        if 80 in open_ports and 443 in open_ports:
            return 'WebServer'
        if 'android' in os_name.lower():
            return 'Mobile'
        if 'windows' in os_name.lower():
            return 'PC'
        if 'linux' in os_name.lower():
            return 'Linux_PC'
        if 'macos' in os_name.lower() or 'ios' in os_name.lower():
            return 'Mac'
        return 'Unknown'

    def _detect_brand(self, mac: str, hostname: str) -> str:
        brand = self._get_vendor_from_mac(mac)
        # If vendor not recognized, try to infer from hostname
        if brand.startswith('Unknown') or brand == '':
            if hostname:
                host_lower = hostname.lower()
                if 'apple' in host_lower or 'mac' in host_lower or 'iphone' in host_lower or 'ipad' in host_lower:
                    return 'Apple'
                if 'samsung' in host_lower:
                    return 'Samsung'
                if 'huawei' in host_lower:
                    return 'Huawei'
                if 'xiaomi' in host_lower or 'redmi' in host_lower or 'poco' in host_lower:
                    return 'Xiaomi'
                if 'google' in host_lower or 'pixel' in host_lower:
                    return 'Google'
                if 'cisco' in host_lower:
                    return 'Cisco'
                if 'hp' in host_lower:
                    return 'HP'
                if 'dell' in host_lower:
                    return 'Dell'
                if 'lenovo' in host_lower:
                    return 'Lenovo'
                if 'asus' in host_lower:
                    return 'Asus'
                if 'raspberry' in host_lower:
                    return 'Raspberry Pi'
                if 'netis' in host_lower:
                    return 'Netis Technologies'
                if 'espressif' in host_lower:
                    return 'Espressif'
                if 'oneplus' in host_lower:
                    return 'OnePlus'
                if 'oppo' in host_lower:
                    return 'OPPO'
                if 'vivo' in host_lower:
                    return 'Vivo'
                if 'realme' in host_lower:
                    return 'Realme'
            return 'Unknown'
        return brand

    def _calculate_confidence(self, mac: str, os_info: Dict, open_ports: List[int],
                              hostname: str, upnp_details: Dict, device_type: str,
                              brand: str, ttl: Optional[int]) -> Tuple[int, str]:
        confidence = 0
        if mac:
            if self._is_randomized_mac(mac):
                confidence += 10
            else:
                confidence += 25
        if os_info['os_name'] != 'Unknown':
            confidence += 20
        if open_ports:
            confidence += 15
        if hostname:
            confidence += 20
        if ttl:
            confidence += 10
        if upnp_details:
            confidence += 15
        if brand != 'Unknown':
            confidence += 10
        if device_type != 'Unknown':
            confidence += 5
        if self._is_randomized_mac(mac) and device_type in ['Mobile', 'iPhone/iPad', 'iOS Device']:
            confidence += 10
        confidence = min(confidence, 100)
        level = 'HIGH' if confidence >= 70 else 'MEDIUM' if confidence >= 40 else 'LOW'
        return confidence, level

    # ============================================================================
    # MAIN SCAN
    # ============================================================================
    def scan_network(self, target: str) -> Dict[str, Any]:
        start_time = time.time()
        results: Dict[str, Any] = {
            'timestamp': datetime.now().isoformat(),
            'target': target,
            'interface': self.interface,
            'permissions_ok': self.permissions_ok,
            'devices': [],
            'stats': {
                'total_devices': 0,
                'devices_with_os': 0,
                'devices_with_mac': 0,
                'devices_with_brand': 0,
                'devices_with_randomized_mac': 0,
                'scan_duration': 0
            }
        }

        # Use the new discovery (nmap + scapy)
        logger.info("📡 Discovering devices using nmap + scapy...")
        discovered_devices = self._discover_devices(target)

        if not discovered_devices:
            logger.warning("No devices found at all!")
            results['stats']['scan_duration'] = time.time() - start_time
            return results

        logger.info(f"🔍 Analyzing {len(discovered_devices)} devices...")

        # UPnP discovery (optional enhancement)
        upnp_devices_info = self._discover_upnp_devices(timeout=3)

        for device_data in discovered_devices:
            ip = device_data['ip_address']
            mac = device_data.get('mac_address', '')
            hostname = device_data.get('hostname', '')
            ttl = device_data.get('ttl')

            # Port scan
            open_ports = self.tcp_port_scan(ip)
            services = [{'port': p, 'service': self._get_service_name(p)} for p in open_ports]

            # OS detection
            os_info = self._detect_os(ip, ttl, open_ports, hostname, mac)

            # Device type
            device_type = self._detect_device_type(hostname, os_info['os_name'],
                                                    open_ports, mac, ip, ttl)

            # Brand
            brand = self._detect_brand(mac, hostname)

            # Confidence
            upnp_details = upnp_devices_info.get(ip, {})
            confidence, confidence_level = self._calculate_confidence(
                mac, os_info, open_ports, hostname, upnp_details, device_type, brand, ttl
            )

            device_info = {
                'ip_address': ip,
                'mac_address': mac,
                'hostname': hostname or '',
                'device_type': device_type,
                'brand': brand,
                'os': os_info['os_name'],
                'os_family': os_info['os_family'],
                'os_confidence': os_info['confidence'],
                'ttl': ttl,
                'open_ports': open_ports,
                'services': services,
                'discovery_source': device_data.get('discovery_source', ['unknown']),
                'confidence': confidence,
                'confidence_level': confidence_level,
                'mac_randomized': self._is_randomized_mac(mac),
                'mac_is_local': self._is_local_mac(mac),
                'is_gateway': ip == self._get_default_gateway(),
                'upnp_friendly_name': upnp_details.get('friendlyName', ''),
                'upnp_model_name': upnp_details.get('modelName', ''),
                'upnp_model_number': upnp_details.get('modelNumber', ''),
                'upnp_manufacturer': upnp_details.get('manufacturer', ''),
                'os_detection_hints': os_info.get('hints', [])
            }

            if upnp_details:
                device_info['discovery_source'].append('upnp')

            results['devices'].append(device_info)

            # Log
            mac_status = " [RANDOMIZED]" if self._is_randomized_mac(mac) else ""
            logger.info(f"   {ip} | MAC: {mac[:17] if mac else 'N/A'}{mac_status}")
            logger.info(f"   OS: {os_info['os_name']} ({os_info['confidence']}%) | Hints: {os_info.get('hints', [])}")
            logger.info(f"   Brand: {brand} | Type: {device_type} | TTL: {ttl}")
            logger.info(f"   Ports: {open_ports} | Confidence: {confidence_level} ({confidence}%)")
            if upnp_details.get('modelName'):
                logger.info(f"   UPnP Model: {upnp_details['modelName']}")
            logger.info("-" * 60)

        # Save caches
        self._save_mac_cache()
        self._save_oui_cache()

        # Stats
        results['stats']['total_devices'] = len(results['devices'])
        results['stats']['devices_with_os'] = sum(1 for d in results['devices'] if d['os'] != 'Unknown')
        results['stats']['devices_with_mac'] = sum(1 for d in results['devices'] if d['mac_address'])
        results['stats']['devices_with_brand'] = sum(1 for d in results['devices'] if d['brand'] != 'Unknown' and 'Randomized' not in d['brand'])
        results['stats']['devices_with_randomized_mac'] = sum(1 for d in results['devices'] if d['mac_randomized'])
        results['stats']['scan_duration'] = time.time() - start_time

        self._save_to_database(results['devices'])

        logger.info("=" * 60)
        logger.info("✅ SCAN COMPLETE")
        logger.info("=" * 60)
        logger.info(f"   Total devices: {results['stats']['total_devices']}")
        logger.info(f"   Devices with OS: {results['stats']['devices_with_os']}")
        logger.info(f"   Devices with MAC: {results['stats']['devices_with_mac']}")
        logger.info(f"   Devices with Brand: {results['stats']['devices_with_brand']}")
        logger.info(f"   Devices with Randomized MAC: {results['stats']['devices_with_randomized_mac']}")
        logger.info(f"   Duration: {results['stats']['scan_duration']:.2f} seconds")
        logger.info("=" * 60)

        return results

    def _is_local_mac(self, mac: str) -> bool:
        if not mac:
            return False
        try:
            first_byte = int(mac[0:2], 16)
            return (first_byte & 0x02) != 0
        except:
            return False

    def _save_to_database(self, devices: List[Dict[str, Any]]):
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            for device in devices:
                ip = device.get('ip_address')
                if not ip:
                    continue
                cursor.execute('SELECT id FROM devices WHERE ip_address = ?', (ip,))
                existing = cursor.fetchone()
                open_ports = json.dumps(device.get('open_ports', []))
                services = json.dumps(device.get('services', []))
                discovery_source = ','.join(device.get('discovery_source', []))
                if existing:
                    cursor.execute('''
                        UPDATE devices SET
                            mac_address = ?,
                            hostname = ?,
                            device_type = ?,
                            brand = ?,
                            os = ?,
                            os_family = ?,
                            os_confidence = ?,
                            open_ports = ?,
                            services = ?,
                            discovery_source = ?,
                            confidence = ?,
                            confidence_level = ?,
                            ttl = ?,
                            last_seen = ?,
                            scan_count = scan_count + 1,
                            upnp_model_name = ?,
                            upnp_model_number = ?,
                            upnp_manufacturer = ?,
                            mac_randomized = ?,
                            mac_is_local = ?,
                            is_gateway = ?
                        WHERE ip_address = ?
                    ''', (
                        device.get('mac_address', ''),
                        device.get('hostname', ''),
                        device.get('device_type', 'Unknown'),
                        device.get('brand', 'Unknown'),
                        device.get('os', 'Unknown'),
                        device.get('os_family', 'Unknown'),
                        device.get('os_confidence', 0),
                        open_ports,
                        services,
                        discovery_source,
                        device.get('confidence', 0),
                        device.get('confidence_level', 'LOW'),
                        device.get('ttl'),
                        datetime.now().isoformat(),
                        device.get('upnp_model_name', ''),
                        device.get('upnp_model_number', ''),
                        device.get('upnp_manufacturer', ''),
                        int(device.get('mac_randomized', False)),
                        int(device.get('mac_is_local', False)),
                        int(device.get('is_gateway', False)),
                        ip
                    ))
                else:
                    cursor.execute('''
                        INSERT INTO devices
                        (ip_address, mac_address, hostname, device_type, brand, os,
                         os_family, os_confidence, open_ports, services, discovery_source,
                         confidence, confidence_level, ttl, first_seen, last_seen,
                         upnp_model_name, upnp_model_number, upnp_manufacturer,
                         mac_randomized, mac_is_local, is_gateway)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        ip,
                        device.get('mac_address', ''),
                        device.get('hostname', ''),
                        device.get('device_type', 'Unknown'),
                        device.get('brand', 'Unknown'),
                        device.get('os', 'Unknown'),
                        device.get('os_family', 'Unknown'),
                        device.get('os_confidence', 0),
                        open_ports,
                        services,
                        discovery_source,
                        device.get('confidence', 0),
                        device.get('confidence_level', 'LOW'),
                        device.get('ttl'),
                        datetime.now().isoformat(),
                        datetime.now().isoformat(),
                        device.get('upnp_model_name', ''),
                        device.get('upnp_model_number', ''),
                        device.get('upnp_manufacturer', ''),
                        int(device.get('mac_randomized', False)),
                        int(device.get('mac_is_local', False)),
                        int(device.get('is_gateway', False))
                    ))
            conn.commit()
            conn.close()
        except Exception as e:
            logger.error(f"Database save error: {e}")

    def generate_report(self, results: Dict[str, Any]) -> str:
        report = []
        report.append("=" * 80)
        report.append("NETWORK SCAN REPORT")
        report.append("=" * 80)
        report.append(f"Scan Time: {results['timestamp']}")
        report.append(f"Target: {results['target']}")
        report.append(f"Interface: {results.get('interface', 'Unknown')}")
        report.append(f"Permissions: {'OK' if results.get('permissions_ok') else 'Limited'}")
        report.append("=" * 80)
        report.append("")

        stats = results.get('stats', {})
        report.append("STATISTICS:")
        report.append(f"   Total Devices: {stats.get('total_devices', 0)}")
        report.append(f"   Devices with OS: {stats.get('devices_with_os', 0)}")
        report.append(f"   Devices with MAC: {stats.get('devices_with_mac', 0)}")
        report.append(f"   Devices with Brand: {stats.get('devices_with_brand', 0)}")
        report.append(f"   Devices with Randomized MAC: {stats.get('devices_with_randomized_mac', 0)}")
        report.append(f"   Scan Duration: {stats.get('scan_duration', 0):.2f}s")
        report.append("")

        report.append("DISCOVERED DEVICES:")
        report.append("-" * 100)
        report.append(f"{'IP':<15} {'MAC':<18} {'OS':<22} {'Brand':<14} {'Type':<14} {'TTL':<5} {'Confidence':<12}")
        report.append("-" * 100)

        for device in sorted(results.get('devices', []), key=lambda x: x.get('ip_address', '')):
            ip = device.get('ip_address', '')
            mac = device.get('mac_address', '')[:17]
            os_info = device.get('os', 'Unknown')[:21]
            brand = device.get('brand', 'Unknown')[:13]
            device_type = device.get('device_type', 'Unknown')[:13]
            ttl = str(device.get('ttl', 'N/A'))[:4]
            confidence = f"{device.get('confidence_level', 'LOW')} ({device.get('confidence', 0)}%)"[:11]

            report.append(f"{ip:<15} {mac:<18} {os_info:<22} {brand:<14} {device_type:<14} {ttl:<5} {confidence:<12}")
            if device.get('mac_randomized'):
                report.append(f"    NOTE: MAC address is randomized (privacy feature enabled)")
            if device.get('is_gateway'):
                report.append(f"    NOTE: This is the network gateway/router")
            if device.get('hostname'):
                report.append(f"    Hostname: {device['hostname']}")

        report.append("-" * 100)
        report.append("")

        report.append("DEVICE SUMMARY:")
        report.append("-" * 40)
        device_types = {}
        for device in results.get('devices', []):
            dt = device.get('device_type', 'Unknown')
            device_types[dt] = device_types.get(dt, 0) + 1

        for dtype, count in sorted(device_types.items()):
            report.append(f"   {dtype}: {count}")

        report.append("-" * 40)
        report.append("")
        report.append("=" * 80)

        return '\n'.join(report)


# ============================================================================
# MAIN ENTRY POINT
# ============================================================================
def main():
    import argparse
    parser = argparse.ArgumentParser(description='Advanced Network Scanner – using nmap + scapy only')
    parser.add_argument('-t', '--target', help='Target network (e.g., 192.168.1.0/24)')
    parser.add_argument('--db', default='data/network_scanner.db', help='Database path')
    parser.add_argument('--interface', help='Network interface to use')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')

    args = parser.parse_args()

    if args.verbose:
        logger.setLevel(logging.DEBUG)

    scanner = EnhancedNetworkScanner(db_path=args.db)

    if args.interface:
        scanner.interface = args.interface
        logger.info(f"Using specified interface: {scanner.interface}")

    target = args.target or scanner._get_network_range()
    logger.info(f"Scanning network: {target}")

    results = scanner.scan_network(target=target)

    report_content = scanner.generate_report(results)
    print(report_content)

    report_filename = f"network_scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    with open(report_filename, 'w') as f:
        f.write(report_content)
    logger.info(f"Report saved to {report_filename}")


if __name__ == "__main__":
    main()