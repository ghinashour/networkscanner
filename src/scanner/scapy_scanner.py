"""
Scapy scanner module for low-level network operations.
Provides ARP scanning, packet crafting, and custom probes.
"""

import scapy.all as scapy
from scapy.layers.l2 import ARP, Ether
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.all import srp, sr1, sniff, send
from typing import List, Dict, Any, Optional
from datetime import datetime
import socket
import subprocess
import re
import logging

# Setup logger
logger = logging.getLogger(__name__)

class ScapyScanner:
    """Handles Scapy-based network scanning operations."""
    
    def __init__(self, interface: Optional[str] = None):
        """Initialize Scapy scanner."""
        self.interface = interface or self._get_default_interface()
        logger.info(f"Scapy scanner initialized on interface: {self.interface}")
    
    def _get_default_interface(self) -> str:
        """Get the default network interface using socket and system commands."""
        try:
            # Method 1: Try to get default interface from routing table
            # This works on most Unix-like systems
            try:
                import fcntl
                import struct
                
                # Get default interface by checking the route
                with open('/proc/net/route', 'r') as f:
                    for line in f.readlines():
                        fields = line.strip().split()
                        if fields[1] == '00000000':  # Default route
                            return fields[0]
            except:
                pass
            
            # Method 2: Use socket to get hostname and IP
            try:
                hostname = socket.gethostname()
                ip_address = socket.gethostbyname(hostname)
                
                # Find interface with this IP
                import psutil
                for iface, addrs in psutil.net_if_addrs().items():
                    for addr in addrs:
                        if addr.address == ip_address and addr.family == socket.AF_INET:
                            return iface
            except:
                pass
            
            # Method 3: Try common interfaces
            common_interfaces = ['eth0', 'en0', 'wlan0', 'enp0s3', 'ens33', 'wlp2s0']
            for iface in common_interfaces:
                try:
                    # Check if interface exists
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    sock.bind((iface, 0))
                    sock.close()
                    return iface
                except:
                    continue
            
            # Method 4: Use ip command (Linux)
            try:
                result = subprocess.run(['ip', 'route', 'show', 'default'], 
                                      capture_output=True, text=True)
                if result.stdout:
                    parts = result.stdout.strip().split()
                    if 'dev' in parts:
                        return parts[parts.index('dev') + 1]
            except:
                pass
            
            # Method 5: Use ifconfig (older systems)
            try:
                result = subprocess.run(['ifconfig'], capture_output=True, text=True)
                if result.stdout:
                    # Look for active interfaces
                    interfaces = re.findall(r'^(\w+):', result.stdout, re.MULTILINE)
                    for iface in interfaces:
                        if 'lo' not in iface and 'docker' not in iface:
                            # Check if it has an IP
                            if re.search(r'inet\s+\d+\.\d+\.\d+\.\d+', result.stdout):
                                return iface
            except:
                pass
            
            raise RuntimeError("No network interface found")
            
        except Exception as e:
            logger.warning(f"Could not detect default interface: {e}")
            # Final fallback
            return 'eth0'  # Common default
    
    def _get_local_ip(self) -> Optional[str]:
        """Get local IP address without netifaces."""
        try:
            # Create a socket to get local IP
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                # Connect to a public DNS server
                s.connect(('8.8.8.8', 80))
                ip = s.getsockname()[0]
            except:
                # Fallback: get hostname
                ip = socket.gethostbyname(socket.gethostname())
            finally:
                s.close()
            return ip
        except:
            return None
    
    def arp_scan(self, ip_range: str, timeout: int = 2) -> List[Dict[str, Any]]:
        """
        Perform ARP scan to discover devices on the network.
        
        Args:
            ip_range: IP range to scan (e.g., '192.168.1.0/24')
            timeout: Response timeout in seconds
        
        Returns:
            List of discovered devices with IP and MAC addresses
        """
        logger.info(f"Starting ARP scan on {ip_range}")
        
        try:
            # Create and send ARP request
            arp_request = ARP(pdst=ip_range)
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
            answered = srp(
                broadcast / arp_request,
                timeout=timeout,
                verbose=False,
                iface=self.interface
            )[0]
            
            devices = []
            for _, response in answered:
                devices.append({
                    'ip_address': response.psrc,
                    'mac_address': response.hwsrc,
                    'status': 'up'
                })
            
            logger.info(f"Found {len(devices)} devices")
            return devices
            
        except Exception as e:
            logger.error(f"ARP scan failed: {str(e)}")
            return []
    
    def tcp_port_scan(self, target: str, ports: List[int], timeout: int = 2) -> Dict[str, Any]:
        """
        Perform TCP port scanning using Scapy.
        
        Args:
            target: Target IP address
            ports: List of ports to scan
            timeout: Response timeout in seconds
        
        Returns:
            Dictionary with port scan results
        """
        logger.info(f"Starting TCP port scan on {target} ({len(ports)} ports)")
        
        open_ports = []
        
        for port in ports:
            try:
                # Send SYN packet
                packet = IP(dst=target) / TCP(dport=port, flags='S')
                reply = sr1(packet, timeout=timeout, verbose=False, iface=self.interface)
                
                # Check if we got a reply and it has TCP layer
                if reply and reply.haslayer(TCP):
                    tcp_layer = reply.getlayer(TCP)
                    if tcp_layer:
                        flags = tcp_layer.flags
                        if flags & 0x12:  # SYN-ACK
                            open_ports.append(port)
                            # Send RST to close connection
                            send(IP(dst=target) / TCP(dport=port, flags='R'), verbose=False)
                            
            except Exception as e:
                logger.debug(f"Port {port} scan failed: {str(e)}")
        
        logger.info(f"Found {len(open_ports)} open ports")
        
        return {
            'target': target,
            'open_ports': open_ports,
            'total_scanned': len(ports)
    }
    def banner_grab(self, target: str, port: int, timeout: int = 3) -> Optional[str]:
        """
        Attempt to grab banner from a service.
        
        Args:
            target: Target IP address
            port: Port number
            timeout: Connection timeout in seconds
        
        Returns:
            Banner string or None if not available
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((target, port))
            
            # Try common probes
            probes = [b"\n", b"HEAD / HTTP/1.0\r\n\r\n", b"EHLO\r\n"]
            
            for probe in probes:
                try:
                    sock.send(probe)
                    banner = sock.recv(1024).decode('utf-8', errors='ignore')
                    if banner:
                        sock.close()
                        return banner.strip()
                except:
                    continue
            
            sock.close()
            return None
            
        except Exception:
            return None
    
    def packet_capture(self, count: int = 10, timeout: int = 10) -> List[Dict[str, Any]]:
        """
        Capture network packets for analysis.
        
        Args:
            count: Number of packets to capture
            timeout: Capture timeout in seconds
        
        Returns:
            List of captured packet summaries
        """
        logger.info(f"Starting packet capture (count: {count}, timeout: {timeout}s)")
        
        captured = []
        
        def packet_handler(packet):
            if packet.haslayer(IP):
                captured.append({
                    'src': packet[IP].src,
                    'dst': packet[IP].dst,
                    'protocol': packet[IP].proto,
                    'length': len(packet),
                    'summary': packet.summary()
                })
            
            return len(captured) >= count
        
        try:
            sniff(
                iface=self.interface,
                prn=packet_handler,
                timeout=timeout,
                count=count,
                store=False
            )
            return captured
            
        except Exception as e:
            logger.error(f"Packet capture failed: {str(e)}")
            return []
    
    def ping_sweep(self, ip_range: str, timeout: int = 1) -> List[str]:
        """
        Perform ICMP ping sweep to discover active hosts.
        
        Args:
            ip_range: IP range to scan
            timeout: Response timeout in seconds
        
        Returns:
            List of active IP addresses
        """
        logger.info(f"Starting ping sweep on {ip_range}")
        
        active_hosts = []
        
        # Parse IP range
        try:
            from ipaddress import ip_network
            network = ip_network(ip_range, strict=False)
            targets = [str(ip) for ip in network.hosts()]
            
            # Limit targets for demo
            targets = targets[:10]
            
            for target in targets:
                try:
                    packet = IP(dst=target) / ICMP()
                    reply = sr1(packet, timeout=timeout, verbose=False, iface=self.interface)
                    if reply:
                        active_hosts.append(target)
                        logger.debug(f"Host {target} is up")
                except:
                    continue
            
            logger.info(f"Found {len(active_hosts)} active hosts")
            
        except Exception as e:
            logger.error(f"Ping sweep failed: {str(e)}")
        
        return active_hosts
    
    def get_network_info(self) -> Dict[str, Any]:
        """Get local network information without netifaces."""
        info = {
            'interface': self.interface,
            'ip_address': self._get_local_ip(),
            'mac_address': None,
            'gateway': None
        }
        
        # Try to get MAC address using system commands
        try:
            # Linux
            if self.interface:
                result = subprocess.run(
                    ['ip', 'link', 'show', self.interface],
                    capture_output=True, text=True
                )
                if result.stdout:
                    mac_match = re.search(r'link/ether\s+([0-9a-fA-F:]{17})', result.stdout)
                    if mac_match:
                        info['mac_address'] = mac_match.group(1)
        except:
            pass
        
        # Try to get gateway
        try:
            # Linux
            result = subprocess.run(
                ['ip', 'route', 'show', 'default'],
                capture_output=True, text=True
            )
            if result.stdout:
                parts = result.stdout.strip().split()
                if 'via' in parts:
                    info['gateway'] = parts[parts.index('via') + 1]
        except:
            pass
        
        return info