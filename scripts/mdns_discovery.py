#!/usr/bin/env python3
"""
mDNS/Bonjour Discovery Module
Discovers devices that advertise services via mDNS (Apple Bonjour, ZeroConf)
"""

import socket
import struct
import time
import json
import threading
from typing import List, Dict, Any
import logging
from datetime import datetime

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class MDNSDiscovery:
    """
    Discover devices using mDNS (Multicast DNS)
    Finds Apple devices, printers, smart TVs, IoT devices
    """
    
    # mDNS multicast address and port
    MDNS_ADDR = '224.0.0.251'
    MDNS_PORT = 5353
    MDNS_QUERY = {
        '_services._dns-sd._udp.local': 'Service Discovery',
        '_http._tcp.local': 'Web Servers',
        '_ssh._tcp.local': 'SSH Servers',
        '_airplay._tcp.local': 'AirPlay Devices',
        '_airport._tcp.local': 'AirPort Devices',
        '_printer._tcp.local': 'Printers',
        '_ipp._tcp.local': 'IP Printers',
        '_ipp._udp.local': 'IP Printers (UDP)',
        '_scanner._tcp.local': 'Scanners',
        '_smb._tcp.local': 'SMB/CIFS Servers',
        '_afpovertcp._tcp.local': 'AFP Servers (Mac)',
        '_apple-mobdev2._tcp.local': 'Apple Mobile Devices',
        '_homekit._tcp.local': 'HomeKit Devices',
        '_hue._tcp.local': 'Philips Hue',
        '_sonos._tcp.local': 'Sonos Speakers',
        '_spotify-connect._tcp.local': 'Spotify Connect',
        '_googlecast._tcp.local': 'Google Cast/Chromecast',
        '_roku._tcp.local': 'Roku Devices',
        '_hap._tcp.local': 'HomeKit Accessory Protocol',
        '_mqtt._tcp.local': 'MQTT Brokers',
        '_xbmc-jsonrpc._tcp.local': 'Kodi/XBMC',
        '_plexmediaserver._tcp.local': 'Plex Media Server',
        '_daap._tcp.local': 'iTunes DAAP',
        '_raop._tcp.local': 'AirPlay Audio'
    }
    
    def __init__(self, timeout: int = 5):
        self.timeout = timeout
        self.discovered_devices = {}
        self.lock = threading.Lock()
        self.running = True
    
    def discover(self, services: List[str] = None) -> Dict[str, Any]: # type: ignore
        """
        Discover devices via mDNS
        
        Args:
            services: List of service types to query (default: all)
        
        Returns:
            Dictionary of discovered devices
        """
        if services is None:
            services = list(self.MDNS_QUERY.keys())
        
        logger.info(f"🔍 Discovering mDNS services ({len(services)} queries)...")
        
        # Create socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.settimeout(self.timeout)
        
        # Join multicast group
        mreq = struct.pack("4sl", socket.inet_aton(self.MDNS_ADDR), socket.INADDR_ANY)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        sock.bind(('', self.MDNS_PORT))
        
        # Send queries
        for service in services:
            query = self._build_query(service)
            sock.sendto(query, (self.MDNS_ADDR, self.MDNS_PORT))
            logger.debug(f"   Query sent: {service}")
        
        # Collect responses
        start_time = time.time()
        responses = []
        
        while time.time() - start_time < self.timeout and self.running:
            try:
                data, addr = sock.recvfrom(4096)
                # Parse response
                response = self._parse_response(data, addr)
                if response:
                    responses.append(response)
                    self._add_device(response)
            except socket.timeout:
                continue
            except Exception as e:
                logger.debug(f"Error receiving mDNS response: {e}")
                continue
        
        sock.close()
        
        logger.info(f"   Found {len(self.discovered_devices)} unique devices")
        return self.discovered_devices
    
    def _build_query(self, service_type: str) -> bytes:
        """Build mDNS query packet"""
        # Simple DNS query for PTR record
        # Format: DNS header + Question
        # Transaction ID: 0x0000, Flags: 0x0100 (Standard query)
        header = struct.pack('!HHHHHH', 0x0000, 0x0100, 0x0001, 0x0000, 0x0000, 0x0000)
        
        # QNAME (service type)
        qname = self._encode_dns_name(service_type)
        
        # QTYPE: PTR (12), QCLASS: IN (1)
        question = qname + struct.pack('!HH', 12, 1)
        
        return header + question
    
    def _encode_dns_name(self, name: str) -> bytes:
        """Encode DNS name for query"""
        parts = name.split('.')
        result = b''
        for part in parts:
            result += bytes([len(part)]) + part.encode('utf-8')
        result += b'\x00'
        return result
    
    def _parse_response(self, data: bytes, addr: tuple) -> Dict[str, Any]:
        """Parse mDNS response"""
        try:
            # Skip header (12 bytes)
            offset = 12
            
            # Parse questions
            qdcount = struct.unpack('!H', data[4:6])[0]
            for _ in range(qdcount):
                name, offset = self._parse_dns_name(data, offset)
                # Skip QTYPE and QCLASS (4 bytes)
                offset += 4
            
            # Parse answers
            ancount = struct.unpack('!H', data[6:8])[0]
            for _ in range(ancount):
                name, offset = self._parse_dns_name(data, offset)
                rtype, rclass, ttl, rdlength = struct.unpack('!HHIH', data[offset:offset+10])
                offset += 10
                rdata = data[offset:offset+rdlength]
                offset += rdlength
                
                if rtype == 12:  # PTR
                    # Service name
                    ptr_name, _ = self._parse_dns_name(rdata, 0)
                    return {
                        'type': 'service',
                        'service_name': ptr_name,
                        'ip': addr[0],
                        'port': 0,
                        'ttl': ttl,
                        'timestamp': datetime.now().isoformat()
                    }
                
                elif rtype == 1:  # A (IPv4)
                    ip = socket.inet_ntoa(rdata)
                    return {
                        'type': 'a_record',
                        'name': name,
                        'ip': ip,
                        'ttl': ttl,
                        'timestamp': datetime.now().isoformat()
                    }
                
                elif rtype == 28:  # AAAA (IPv6)
                    ip = socket.inet_ntop(socket.AF_INET6, rdata)
                    return {
                        'type': 'aaaa_record',
                        'name': name,
                        'ip': ip,
                        'ttl': ttl,
                        'timestamp': datetime.now().isoformat()
                    }
                
                elif rtype == 33:  # SRV
                    priority, weight, port = struct.unpack('!HHH', rdata[:6])
                    target, _ = self._parse_dns_name(rdata, 6)
                    return {
                        'type': 'srv_record',
                        'name': name,
                        'target': target,
                        'port': port,
                        'priority': priority,
                        'weight': weight,
                        'ttl': ttl,
                        'timestamp': datetime.now().isoformat()
                    }
                
                elif rtype == 16:  # TXT
                    txt_data = self._parse_txt_record(rdata)
                    return {
                        'type': 'txt_record',
                        'name': name,
                        'data': txt_data,
                        'ttl': ttl,
                        'timestamp': datetime.now().isoformat()
                    }
            
        except Exception as e:
            logger.debug(f"Error parsing mDNS response: {e}")
        
        return None # type: ignore
    
    def _parse_dns_name(self, data: bytes, offset: int) -> tuple:
        """Parse DNS name (supports compression)"""
        name_parts = []
        jumped = False
        original_offset = offset
        
        while True:
            if offset >= len(data):
                break
                
            length = data[offset]
            offset += 1
            
            if length == 0:
                break
            
            if length & 0xC0:  # Compression pointer
                if not jumped:
                    original_offset = offset + 1
                pointer = ((length & 0x3F) << 8) | data[offset]
                offset = pointer
                jumped = True
                continue
            
            name_parts.append(data[offset:offset+length].decode('utf-8'))
            offset += length
        
        if jumped:
            offset = original_offset
        else:
            offset += 1
        
        return '.'.join(name_parts), offset
    
    def _parse_txt_record(self, data: bytes) -> dict:
        """Parse TXT record data"""
        txt_data = {}
        offset = 0
        
        while offset < len(data):
            length = data[offset]
            offset += 1
            if length > 0:
                entry = data[offset:offset+length].decode('utf-8')
                offset += length
                if '=' in entry:
                    key, value = entry.split('=', 1)
                    txt_data[key] = value
                else:
                    txt_data[entry] = ''
        
        return txt_data
    
    def _add_device(self, response: Dict[str, Any]):
        """Add discovered device to collection"""
        with self.lock:
            ip = response.get('ip')
            if not ip:
                return
            
            if ip not in self.discovered_devices:
                self.discovered_devices[ip] = {
                    'ip': ip,
                    'services': {},
                    'first_seen': datetime.now().isoformat(),
                    'last_seen': datetime.now().isoformat()
                }
            
            # Add service info
            if response.get('type') == 'service':
                service_name = response.get('service_name', '')
                self.discovered_devices[ip]['services'][service_name] = {
                    'service': service_name,
                    'timestamp': response.get('timestamp'),
                    'ttl': response.get('ttl')
                }
                self.discovered_devices[ip]['last_seen'] = datetime.now().isoformat()
    
    def get_device_info(self) -> List[Dict[str, Any]]:
        """Get device information from discovered devices"""
        devices = []
        for ip, data in self.discovered_devices.items():
            device_info = {
                'ip': ip,
                'source': 'mdns',
                'services': list(data['services'].keys()),
                'first_seen': data.get('first_seen'),
                'last_seen': data.get('last_seen'),
                'device_type': self._guess_device_type(data['services'])
            }
            devices.append(device_info)
        return devices
    
    def _guess_device_type(self, services: dict) -> str:
        """Guess device type from mDNS services"""
        service_names = [s.lower() for s in services.keys()]
        
        if any('airport' in s for s in service_names):
            return 'Router'
        elif any('apple-tv' in s or 'airplay' in s for s in service_names):
            return 'TV'
        elif any('printer' in s or 'ipp' in s for s in service_names):
            return 'Printer'
        elif any('scanner' in s for s in service_names):
            return 'Scanner'
        elif any('homekit' in s or 'hap' in s for s in service_names):
            return 'IoT'
        elif any('sonos' in s for s in service_names):
            return 'Speaker'
        elif any('googlecast' in s for s in service_names):
            return 'Chromecast'
        elif any('hue' in s for s in service_names):
            return 'SmartLight'
        elif any('plex' in s for s in service_names):
            return 'MediaServer'
        elif any('smb' in s for s in service_names):
            return 'FileServer'
        elif any('ssh' in s for s in service_names):
            return 'Server'
        elif any('http' in s for s in service_names):
            return 'WebServer'
        else:
            return 'Unknown'


# ============================================================================
# QUICK TEST
# ============================================================================

if __name__ == "__main__":
    print("=" * 60)
    print("📡 mDNS/Bonjour Discovery Test")
    print("=" * 60)
    
    # Initialize discovery
    mdns = MDNSDiscovery(timeout=5)
    
    # Discover devices
    devices = mdns.discover()
    
    print(f"\n📊 Found {len(devices)} devices:")
    print("-" * 60)
    
    for ip, data in devices.items():
        services = list(data['services'].keys())
        device_type = mdns._guess_device_type(data['services'])
        print(f"   {ip:<15} {device_type:<15} Services: {len(services)}")
        if len(services) <= 3:
            print(f"      {', '.join(services[:3])}")
        else:
            print(f"      {', '.join(services[:3])} ... (+{len(services)-3} more)")
    
    print("\n" + "=" * 60)