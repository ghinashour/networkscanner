#!/usr/bin/env python3
"""
Windows Discovery - LLMNR and NetBIOS discovery for Windows devices
"""

import socket
import struct
import time
import threading
from typing import List, Dict
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class WindowsDiscovery:
    """
    Discover Windows devices using LLMNR and NetBIOS
    """
    
    def __init__(self, timeout: int = 3):
        self.timeout = timeout
        self.discovered = {}
    
    def discover_netbios(self, subnet: str = "192.168.1.0/24") -> List[Dict]:
        """
        Discover devices using NetBIOS name resolution
        """
        logger.info("🔍 Discovering Windows devices via NetBIOS...")
        devices = []
        
        # Parse subnet
        base_ip = subnet.replace('/24', '')
        base = '.'.join(base_ip.split('.')[:3]) + '.'
        
        # Common NetBIOS queries
        netbios_names = ['*', 'WORKGROUP', 'MSHOME']
        
        for i in range(1, 255):
            ip = f"{base}{i}"
            try:
                # Try NetBIOS name lookup
                name = socket.gethostbyaddr(ip)[0]
                if name and '.' not in name:  # NetBIOS names don't have dots
                    devices.append({
                        'ip': ip,
                        'hostname': name,
                        'source': 'netbios',
                        'device_type': 'Windows_PC'  # Likely Windows
                    })
                    logger.info(f"   ✅ Found Windows device: {ip} ({name})")
            except:
                pass
        
        return devices
    
    def discover_llmnr(self, subnet: str = "192.168.1.0/24") -> List[Dict]:
        """
        Discover devices using LLMNR (Link-Local Multicast Name Resolution)
        """
        logger.info("🔍 Discovering devices via LLMNR...")
        devices = []
        
        # LLMNR multicast address
        llmnr_addr = '224.0.0.252'
        llmnr_port = 5355
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.settimeout(2)
            
            # Join multicast
            mreq = struct.pack("4sl", socket.inet_aton(llmnr_addr), socket.INADDR_ANY)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
            sock.bind(('', llmnr_port))
            
            # Send LLMNR query
            # Simple LLMNR query for hostname resolution
            query = self._build_llmnr_query()
            sock.sendto(query, (llmnr_addr, llmnr_port))
            
            # Listen for responses
            start_time = time.time()
            while time.time() - start_time < self.timeout:
                try:
                    data, addr = sock.recvfrom(1024)
                    if addr[0] not in [d['ip'] for d in devices]:
                        devices.append({
                            'ip': addr[0],
                            'hostname': f"LLMNR-{addr[0]}",
                            'source': 'llmnr',
                            'device_type': 'Unknown'
                        })
                        logger.info(f"   ✅ Found device via LLMNR: {addr[0]}")
                except socket.timeout:
                    continue
                
        except Exception as e:
            logger.debug(f"LLMNR error: {e}")
        
        return devices
    
    def _build_llmnr_query(self) -> bytes:
        """Build LLMNR query packet"""
        # Simple LLMNR query for ANY type
        header = struct.pack('!HHHHHH', 0x0000, 0x0100, 0x0001, 0x0000, 0x0000, 0x0000)
        qname = b'\x01*\x00\x00\x01\x00\x01'  # Query for *
        return header + qname
    
    def discover_all(self, subnet: str = "192.168.1.0/24") -> List[Dict]:
        """Discover devices using all Windows protocols"""
        devices = []
        
        # NetBIOS discovery
        netbios_devices = self.discover_netbios(subnet)
        devices.extend(netbios_devices)
        
        # LLMNR discovery
        llmnr_devices = self.discover_llmnr(subnet)
        devices.extend(llmnr_devices)
        
        # Deduplicate
        seen = set()
        unique_devices = []
        for device in devices:
            if device['ip'] not in seen:
                seen.add(device['ip'])
                unique_devices.append(device)
        
        logger.info(f"✅ Found {len(unique_devices)} Windows devices")
        return unique_devices


if __name__ == "__main__":
    print("=" * 60)
    print("🪟 Windows Device Discovery")
    print("=" * 60)
    
    discovery = WindowsDiscovery()
    devices = discovery.discover_all()
    
    if devices:
        print(f"\n📊 Found {len(devices)} Windows devices:")
        for device in devices:
            print(f"   {device['ip']:<15} {device['hostname']:<20} ({device['source']})")
    else:
        print("\nℹ️ No Windows devices found. This is normal if:")
        print("   - There are no Windows devices on the network")
        print("   - Windows devices have NetBIOS/LLMNR disabled")
        print("   - Firewall is blocking the discovery")
    
    print("\n" + "=" * 60)