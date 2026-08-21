#!/usr/bin/env python3
"""
Advanced Device Intelligence - Multiple discovery methods
"""

import socket
import struct
import json
import requests
import subprocess
import re
from datetime import datetime
from typing import Dict, List, Optional, Any
import logging
import time

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class DeviceIntelligence:
    """
    Advanced device discovery and fingerprinting using multiple methods
    """
    
    def __init__(self):
        self.cache = {}
    
    # ============================================================
    # 1. MAC VENDOR LOOKUP
    # ============================================================
    
    def get_vendor_from_mac(self, mac: str) -> Dict[str, str]:
        """Get vendor from MAC address"""
        if not mac or len(mac) < 8:
            return {'vendor': 'Unknown', 'brand': 'Unknown'}
        
        # Check cache first
        if mac in self.cache:
            return self.cache[mac]
        
        # Try online MAC lookup first (more accurate)
        try:
            response = requests.get(
                f'https://api.macvendors.com/{mac}',
                timeout=5
            )
            if response.status_code == 200:
                vendor = response.text.strip()
                result = {'vendor': vendor, 'brand': vendor}
                self.cache[mac] = result
                return result
        except:
            pass
        
        # Fallback: Use local MAC vendor database
        try:
            from scripts.device_fingerprinter import MAC_VENDORS
            mac_upper = mac.upper()
            for prefix, vendor in MAC_VENDORS.items():
                if mac_upper.startswith(prefix):
                    result = {'vendor': vendor, 'brand': vendor}
                    self.cache[mac] = result
                    return result
        except:
            pass
        
        result = {'vendor': 'Unknown', 'brand': 'Unknown'}
        self.cache[mac] = result
        return result
    
    # ============================================================
    # 2. HTTP USER-AGENT SNIFFING
    # ============================================================
    
    def http_user_agent_scan(self, ip: str, port: int = 80) -> Dict[str, Any]:
        """Connect to HTTP server and get User-Agent to detect device"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((ip, port))
            
            request = b"GET / HTTP/1.1\r\nHost: " + ip.encode() + b"\r\nConnection: close\r\n\r\n"
            sock.send(request)
            
            response = sock.recv(4096).decode('utf-8', errors='ignore')
            sock.close()
            
            headers = {}
            for line in response.split('\n'):
                if ': ' in line:
                    key, value = line.split(': ', 1)
                    headers[key.lower()] = value.strip()
            
            server = headers.get('server', '')
            device_info = self._parse_http_server(server)
            
            return {
                'server': server,
                'device_type': device_info.get('type'),
                'os': device_info.get('os'),
                'brand': device_info.get('brand'),
                'source': 'http'
            }
            
        except Exception as e:
            logger.debug(f"HTTP scan failed for {ip}:{port} - {e}")
            return {}
    
    def _parse_http_server(self, server: str) -> Dict[str, str]:
        """Parse HTTP server header to detect device"""
        server_lower = server.lower()
        
        if any(x in server_lower for x in ['router', 'gateway', 'apache', 'nginx', 'lighttpd']):
            if 'router' in server_lower:
                return {'type': 'Router', 'os': 'Linux', 'brand': 'Unknown'}
            return {'type': 'WebServer', 'os': 'Linux', 'brand': 'Unknown'}
        
        if any(x in server_lower for x in ['hp', 'printer', 'epson', 'brother', 'canon']):
            return {'type': 'Printer', 'os': 'Embedded', 'brand': 'Printer'}
        
        if any(x in server_lower for x in ['samsung', 'lg', 'sony', 'panasonic', 'vizio', 'roku']):
            return {'type': 'SmartTV', 'os': 'Linux', 'brand': 'TV'}
        
        if 'apple' in server_lower or 'darwin' in server_lower:
            return {'type': 'Apple', 'os': 'macOS', 'brand': 'Apple'}
        
        if 'microsoft' in server_lower or 'iis' in server_lower:
            return {'type': 'Windows_PC', 'os': 'Windows', 'brand': 'Microsoft'}
        
        return {}
    
    # ============================================================
    # 3. UPnP/SSDP DISCOVERY
    # ============================================================
    
    def upnp_discovery(self, timeout: int = 3) -> List[Dict[str, Any]]:
        """Discover UPnP devices"""
        logger.info("🔍 UPnP Discovery...")
        
        devices = []
        
        try:
            ssdp_addr = ('239.255.255.250', 1900)
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.settimeout(timeout)
            
            mreq = struct.pack("4sl", socket.inet_aton('239.255.255.250'), socket.INADDR_ANY)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
            
            message = (
                "M-SEARCH * HTTP/1.1\r\n"
                "HOST: 239.255.255.250:1900\r\n"
                "MAN: ssdp:discover\r\n"
                "MX: 3\r\n"
                "ST: upnp:rootdevice\r\n"
                "\r\n"
            )
            
            sock.sendto(message.encode(), ssdp_addr)
            
            start_time = time.time()
            seen_ips = set()
            
            while time.time() - start_time < timeout:
                try:
                    data, addr = sock.recvfrom(4096)
                    ip = addr[0]
                    
                    if ip in seen_ips:
                        continue
                    
                    seen_ips.add(ip)
                    response = data.decode('utf-8', errors='ignore')
                    device_info = self._parse_upnp_response(response, ip)
                    if device_info:
                        devices.append(device_info)
                        
                except socket.timeout:
                    continue
            
            sock.close()
            
        except Exception as e:
            logger.error(f"UPnP discovery error: {e}")
        
        return devices
    
    def _parse_upnp_response(self, response: str, ip: str) -> Dict[str, Any]:
        """Parse UPnP response"""
        lines = response.split('\n')
        
        device_info = {
            'ip': ip,
            'source': 'upnp',
            'device_type': 'Unknown',
            'brand': 'Unknown',
            'hostname': '',
            'services': []
        }
        
        for line in lines:
            if 'LOCATION:' in line:
                location = line.split(':', 1)[1].strip()
                device_info['location'] = location
                if 'upnp' in location.lower() or 'rootdesc' in location.lower():
                    device_info['device_type'] = 'UPnP_Device'
            
            elif 'SERVER:' in line:
                server = line.split(':', 1)[1].strip()
                if 'linux' in server.lower():
                    device_info['os'] = 'Linux'
                elif 'windows' in server.lower():
                    device_info['os'] = 'Windows'
                
                if 'samsung' in server.lower():
                    device_info['brand'] = 'Samsung'
                    device_info['device_type'] = 'SmartTV'
                elif 'lg' in server.lower():
                    device_info['brand'] = 'LG'
                    device_info['device_type'] = 'SmartTV'
                elif 'sony' in server.lower():
                    device_info['brand'] = 'Sony'
                    device_info['device_type'] = 'SmartTV'
                elif 'apple' in server.lower():
                    device_info['brand'] = 'Apple'
                elif 'hp' in server.lower():
                    device_info['brand'] = 'HP'
                    device_info['device_type'] = 'Printer'
            
            elif 'USN:' in line:
                usn = line.split(':', 1)[1].strip()
                if 'printer' in usn.lower():
                    device_info['device_type'] = 'Printer'
                elif 'media' in usn.lower():
                    device_info['device_type'] = 'MediaServer'
                elif 'camera' in usn.lower():
                    device_info['device_type'] = 'IPCamera'
        
        return device_info
    
    # ============================================================
    # 4. COMPLETE DEVICE FINGERPRINTING
    # ============================================================
    
    def fingerprint_device(self, ip: str, mac: str = '', hostname: str = '') -> Dict[str, Any]:
        """Combine all methods to get complete device fingerprint"""
        device_info = {
            'ip': ip,
            'mac': mac,
            'hostname': hostname,
            'brand': 'Unknown',
            'device_type': 'Unknown',
            'os': 'Unknown',
            'confidence': 0,
            'confidence_level': 'LOW',
            'sources': []
        }
        
        # 1. MAC Vendor lookup
        if mac:
            vendor = self.get_vendor_from_mac(mac)
            if vendor.get('brand') != 'Unknown':
                device_info['brand'] = vendor.get('brand')
                device_info['sources'].append('mac')
                device_info['confidence'] += 25
        
        # 2. HTTP User-Agent scan
        try:
            http_info = self.http_user_agent_scan(ip)
            if http_info:
                if http_info.get('brand'):
                    device_info['brand'] = http_info.get('brand')
                if http_info.get('device_type'):
                    device_info['device_type'] = http_info.get('device_type')
                if http_info.get('os'):
                    device_info['os'] = http_info.get('os')
                device_info['sources'].append('http')
                device_info['confidence'] += 20
        except:
            pass
        
        # 3. Hostname analysis
        if hostname:
            hostname_lower = hostname.lower()
            # Brand detection
            if 'galaxy' in hostname_lower or 'samsung' in hostname_lower:
                device_info['brand'] = 'Samsung'
                device_info['device_type'] = 'Mobile'
                device_info['os'] = 'Android'
                device_info['sources'].append('hostname')
                device_info['confidence'] += 20
            elif 'iphone' in hostname_lower or 'ipad' in hostname_lower:
                device_info['brand'] = 'Apple'
                device_info['device_type'] = 'Mobile'
                device_info['os'] = 'iOS'
                device_info['sources'].append('hostname')
                device_info['confidence'] += 20
            elif 'infinix' in hostname_lower:
                device_info['brand'] = 'Infinix'
                device_info['device_type'] = 'Mobile'
                device_info['os'] = 'Android'
                device_info['sources'].append('hostname')
                device_info['confidence'] += 20
            elif 'huawei' in hostname_lower:
                device_info['brand'] = 'Huawei'
                device_info['device_type'] = 'Mobile'
                device_info['os'] = 'Android'
                device_info['sources'].append('hostname')
                device_info['confidence'] += 20
            elif 'xiaomi' in hostname_lower:
                device_info['brand'] = 'Xiaomi'
                device_info['device_type'] = 'Mobile'
                device_info['os'] = 'Android'
                device_info['sources'].append('hostname')
                device_info['confidence'] += 20
            
            # Device type from hostname
            if any(x in hostname_lower for x in ['router', 'gateway', 'ap', 'wifi']):
                device_info['device_type'] = 'Router'
                device_info['sources'].append('hostname')
                device_info['confidence'] += 10
            elif any(x in hostname_lower for x in ['server', 'db', 'web', 'mail']):
                device_info['device_type'] = 'Server'
                device_info['sources'].append('hostname')
                device_info['confidence'] += 10
            elif any(x in hostname_lower for x in ['desktop', 'pc', 'laptop', 'workstation']):
                device_info['device_type'] = 'PC'
                device_info['sources'].append('hostname')
                device_info['confidence'] += 10
        
        # 4. Determine confidence level
        confidence = device_info['confidence']
        if confidence >= 70:
            device_info['confidence_level'] = 'HIGH'
        elif confidence >= 40:
            device_info['confidence_level'] = 'MEDIUM'
        else:
            device_info['confidence_level'] = 'LOW'
        
        return device_info


# ============================================================
# QUICK TEST
# ============================================================

if __name__ == "__main__":
    print("=" * 60)
    print("📱 Advanced Device Intelligence Test")
    print("=" * 60)
    
    intel = DeviceIntelligence()
    
    # Test with sample data
    test_cases = [
        {"ip": "192.168.1.1", "mac": "00:11:22:33:44:55", "hostname": "router.local"},
        {"ip": "192.168.1.5", "mac": "14:D4:24:86:0B:11", "hostname": "GHINASHOUR"},
        {"ip": "192.168.1.10", "mac": "00:1C:F0:12:34:56", "hostname": "Galaxy-S23"},
        {"ip": "192.168.1.20", "mac": "C8:69:CD:4A:2B:1F", "hostname": "iPhone-14"},
    ]
    
    for test in test_cases:
        print(f"\n🔍 Device: {test['ip']}")
        print("-" * 40)
        result = intel.fingerprint_device(test['ip'], test['mac'], test['hostname'])
        print(f"   Brand: {result['brand']}")
        print(f"   Type: {result['device_type']}")
        print(f"   OS: {result['os']}")
        print(f"   Confidence: {result['confidence_level']}")
        print(f"   Sources: {', '.join(result['sources'])}")
    
    print("\n" + "=" * 60)