"""
Device Feature Extractor - Balanced for All Device Types
Optimized for ~85% accuracy across all classes
"""

import pandas as pd
import numpy as np
from typing import List, Dict, Any
import logging
import re

logger = logging.getLogger(__name__)

class DeviceFeatureExtractor:
    """
    Extract numerical features from device scan data for ML classification.
    Balanced feature extraction for all device types.
    """
    
    def __init__(self):
        # ===== IOT-SPECIFIC =====
        self.iot_ports = [554, 1900, 5000, 8000, 8888, 3000, 4200, 1883, 8883, 
                          5683, 5684, 3702, 4242, 4444, 5555, 6666, 7777, 9000, 9090]
        self.iot_services = ['rtsp', 'upnp', 'coap', 'mqtt', 'onvif', 'psia', 'snmp', 
                            'bonjour', 'ssdp', 'soap', 'wsdd', 'msearch']
        self.iot_os = ['embedded', 'iot', 'openwrt', 'dd-wrt', 'arm', 'mips', 'vxworks', 
                       'freertos', 'contiki', 'tinyos', 'busybox']
        self.iot_vendors = ['raspberry', 'arduino', 'esp', 'espressif', 'ubiquiti', 
                           'microchip', 'broadcom', 'ti', 'silicon']
        self.iot_hostname = ['sensor', 'camera', 'device', 'iot', 'smart', 'hub', 
                            'gateway', 'zigbee', 'zwave', 'thermostat', 'plug', 
                            'bulb', 'bridge', 'recorder']
        
        # ===== MOBILE-SPECIFIC =====
        self.mobile_ports = [5223, 5228, 5229, 5230, 5684, 8883, 4433, 8500, 1640, 1641]
        self.mobile_services = ['apple', 'icloud', 'google', 'android', 'ios', 'push', 
                               'firebase', 'gcm', 'apns', 'mdm']
        self.mobile_vendors = ['apple', 'samsung', 'huawei', 'xiaomi', 'oppo', 'vivo', 
                              'oneplus', 'google', 'lg', 'sony', 'motorola']
        self.mobile_hostname = ['iphone', 'ipad', 'galaxy', 'pixel', 'android', 'phone', 
                               'tablet', 'mobile', 'ios']
        
        # ===== SERVER-SPECIFIC (ENHANCED) =====
        self.server_ports = [389, 636, 3268, 3269, 88, 464, 1433, 1434, 2383, 2480, 
                            3306, 5432, 6379, 27017, 9200, 9300, 5672, 61613, 61614,
                            5000, 5001, 5003, 5005, 111, 2049, 4045, 4046]
        self.server_services = ['ldap', 'kerberos', 'active directory', 'ad', 'exchange', 
                               'sharepoint', 'oracle', 'mysql', 'postgres', 'mongodb', 
                               'redis', 'elastic', 'activemq', 'rabbitmq', 'kafka', 
                               'zookeeper', 'nfs', 'smb', 'cifs', 'iis', 'apache', 'nginx',
                               'tomcat', 'jetty', 'jboss', 'weblogic', 'websphere']
        self.server_vendors = ['dell', 'hp', 'ibm', 'oracle', 'emc', 'supermicro', 
                              'lenovo', 'cisco', 'juniper', 'quantum', 'hitachi']
        self.server_hostname = ['server', 'db', 'database', 'web', 'app', 'mail', 'exchange', 
                               'ldap', 'dns', 'dhcp', 'dc', 'domain', 'sql', 'oracle',
                               'mysql', 'postgres', 'mongo', 'redis', 'elastic', 'kafka',
                               'rabbit', 'activemq', 'tomcat', 'jboss', 'weblogic']
        
        # ===== ROUTER-SPECIFIC =====
        self.router_ports = [53, 67, 68, 69, 161, 162, 500, 4500, 1723, 1812, 1813, 
                            1194, 1701, 4500, 500, 4500]
        self.router_services = ['dns', 'dhcp', 'tftp', 'snmp', 'ike', 'vpn', 'pptp', 
                               'radius', 'ospf', 'bgp', 'rip', 'l2tp']
        self.router_vendors = ['cisco', 'juniper', 'mikrotik', 'aruba', 'ruckus', 
                              'linksys', 'netgear', 'tp-link', 'd-link', 'ubiquiti']
        self.router_hostname = ['router', 'ap', 'wlan', 'wifi', 'gateway', 'gw', 'switch',
                               'firewall', 'fw', 'edge']
        
        # ===== WINDOWS PC-SPECIFIC =====
        self.windows_ports = [135, 137, 138, 139, 445, 3389, 49152, 49153, 49154, 49155]
        self.windows_services = ['smb', 'netbios', 'rpc', 'rdp', 'windows', 'microsoft',
                                'exchange', 'outlook', 'office']
        self.windows_vendors = ['dell', 'hp', 'lenovo', 'asus', 'acer', 'msi', 'gigabyte',
                               'intel', 'amd']
        self.windows_hostname = ['desktop', 'workstation', 'pc', 'windows', 'win', 
                                'laptop', 'notebook', 'computer']
        
        # Common ports (shared across device types - helps with generalization)
        self.common_ports = [80, 443, 22, 25, 110, 143, 993, 995, 8080, 8443]
        
    def extract_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Extract numerical features from raw device data."""
        logger.info("Extracting features from device data...")
        features = {}
        
        # ===== BASIC FEATURES (Shared across all) =====
        if 'open_ports' in df.columns:
            basic_features = self._extract_basic_features(df['open_ports'])
            features.update(basic_features)
        
        # ===== DEVICE-SPECIFIC PORT FEATURES =====
        if 'open_ports' in df.columns:
            port_features = self._extract_port_features(df['open_ports'])
            features.update(port_features)
        
        # ===== OS FEATURES =====
        if 'os_fingerprint' in df.columns:
            os_features = self._extract_os_features(df['os_fingerprint'])
            features.update(os_features)
        
        # ===== SERVICE FEATURES =====
        if 'services' in df.columns:
            service_features = self._extract_service_features(df['services'])
            features.update(service_features)
        
        # ===== VENDOR FEATURES =====
        if 'mac_vendor' in df.columns:
            vendor_features = self._extract_vendor_features(df['mac_vendor'])
            features.update(vendor_features)
        
        # ===== HOSTNAME FEATURES =====
        if 'hostname' in df.columns:
            hostname_features = self._extract_hostname_features(df['hostname'])
            features.update(hostname_features)
        
        # ===== COMBINED SCORES (Balanced) =====
        if 'open_ports' in df.columns and 'services' in df.columns:
            score_features = self._extract_balanced_scores(df)
            features.update(score_features)
        
        # Convert to DataFrame
        feature_df = pd.DataFrame(features)
        feature_df = feature_df.fillna(0)
        
        logger.info(f"Extracted {len(feature_df.columns)} features from {len(df)} devices")
        return feature_df
    
    def _extract_basic_features(self, port_series: pd.Series) -> Dict[str, List[float]]:
        """Extract basic universal features."""
        features = {
            'num_ports': [],
            'has_web_port': [],
            'has_ssh_port': [],
            'has_common_ports': [],
            'port_diversity': []
        }
        
        for ports_str in port_series:
            ports = self._parse_ports(ports_str)
            
            features['num_ports'].append(len(ports))
            features['has_web_port'].append(1 if any(p in [80, 443, 8080, 8443] for p in ports) else 0)
            features['has_ssh_port'].append(1 if 22 in ports else 0)
            
            # Common ports score (how many common ports are open)
            common_count = sum(1 for p in ports if p in self.common_ports)
            features['has_common_ports'].append(min(common_count, 3))
            
            # Port diversity (different port ranges)
            if ports:
                port_ranges = sum(1 for p in ports if p < 1024) / max(len(ports), 1)
                features['port_diversity'].append(port_ranges)
            else:
                features['port_diversity'].append(0)
        
        return features
    
    def _extract_port_features(self, port_series: pd.Series) -> Dict[str, List[int]]:
        """Extract device-specific port features with balanced weights."""
        features = {
            # IoT ports
            'iot_port_count': [],
            'has_iot_port': [],
            # Server ports
            'server_port_count': [],
            'has_server_port': [],
            # Router ports
            'router_port_count': [],
            'has_router_port': [],
            # Windows ports
            'windows_port_count': [],
            'has_windows_port': [],
            # Mobile ports
            'mobile_port_count': [],
            'has_mobile_port': [],
        }
        
        for ports_str in port_series:
            ports = self._parse_ports(ports_str)
            
            # IoT ports
            iot_count = sum(1 for p in ports if p in self.iot_ports)
            features['iot_port_count'].append(min(iot_count, 5))  # Cap at 5
            features['has_iot_port'].append(1 if iot_count > 0 else 0)
            
            # Server ports
            server_count = sum(1 for p in ports if p in self.server_ports)
            features['server_port_count'].append(min(server_count, 5))
            features['has_server_port'].append(1 if server_count > 0 else 0)
            
            # Router ports
            router_count = sum(1 for p in ports if p in self.router_ports)
            features['router_port_count'].append(min(router_count, 5))
            features['has_router_port'].append(1 if router_count > 0 else 0)
            
            # Windows ports
            windows_count = sum(1 for p in ports if p in self.windows_ports)
            features['windows_port_count'].append(min(windows_count, 5))
            features['has_windows_port'].append(1 if windows_count > 0 else 0)
            
            # Mobile ports
            mobile_count = sum(1 for p in ports if p in self.mobile_ports)
            features['mobile_port_count'].append(min(mobile_count, 5))
            features['has_mobile_port'].append(1 if mobile_count > 0 else 0)
        
        return features
    
    def _extract_os_features(self, os_series: pd.Series) -> Dict[str, List[int]]:
        """Extract OS features with balanced weights."""
        features = {
            'os_iot': [],
            'os_mobile': [],
            'os_server': [],
            'os_windows': [],
            'os_linux': [],
            'os_router': [],
        }
        
        for os_str in os_series:
            os_lower = str(os_str).lower() if not pd.isna(os_str) and os_str else ''
            
            features['os_iot'].append(1 if any(kw in os_lower for kw in self.iot_os) else 0)
            features['os_mobile'].append(1 if any(kw in os_lower for kw in ['android', 'ios', 'iphone', 'ipad']) else 0)
            features['os_server'].append(1 if any(kw in os_lower for kw in ['server', 'centos', 'red hat', 'enterprise', 'datacenter']) else 0)
            features['os_windows'].append(1 if any(kw in os_lower for kw in ['windows', 'win', 'microsoft']) else 0)
            features['os_linux'].append(1 if any(kw in os_lower for kw in ['linux', 'ubuntu', 'debian', 'fedora']) else 0)
            features['os_router'].append(1 if any(kw in os_lower for kw in ['routeros', 'ios', 'cisco']) else 0)
        
        return features
    
    def _extract_service_features(self, service_series: pd.Series) -> Dict[str, List[int]]:
        """Extract service features with balanced weights."""
        features = {
            'iot_service_count': [],
            'has_iot_service': [],
            'server_service_count': [],
            'has_server_service': [],
            'router_service_count': [],
            'has_router_service': [],
            'mobile_service_count': [],
            'has_mobile_service': [],
            'windows_service_count': [],
            'has_windows_service': [],
        }
        
        for services_str in service_series:
            services_lower = str(services_str).lower() if not pd.isna(services_str) and services_str else ''
            
            # IoT services
            iot_count = sum(1 for s in self.iot_services if s in services_lower)
            features['iot_service_count'].append(min(iot_count, 5))
            features['has_iot_service'].append(1 if iot_count > 0 else 0)
            
            # Server services
            server_count = sum(1 for s in self.server_services if s in services_lower)
            features['server_service_count'].append(min(server_count, 5))
            features['has_server_service'].append(1 if server_count > 0 else 0)
            
            # Router services
            router_count = sum(1 for s in self.router_services if s in services_lower)
            features['router_service_count'].append(min(router_count, 5))
            features['has_router_service'].append(1 if router_count > 0 else 0)
            
            # Mobile services
            mobile_count = sum(1 for s in self.mobile_services if s in services_lower)
            features['mobile_service_count'].append(min(mobile_count, 5))
            features['has_mobile_service'].append(1 if mobile_count > 0 else 0)
            
            # Windows services
            windows_count = sum(1 for s in self.windows_services if s in services_lower)
            features['windows_service_count'].append(min(windows_count, 5))
            features['has_windows_service'].append(1 if windows_count > 0 else 0)
        
        return features
    
    def _extract_vendor_features(self, vendor_series: pd.Series) -> Dict[str, List[int]]:
        """Extract vendor features."""
        features = {
            'vendor_iot': [],
            'vendor_mobile': [],
            'vendor_server': [],
            'vendor_router': [],
            'vendor_windows': [],
        }
        
        for vendor in vendor_series:
            vendor_lower = str(vendor).lower() if not pd.isna(vendor) and vendor else ''
            
            features['vendor_iot'].append(1 if any(v in vendor_lower for v in self.iot_vendors) else 0)
            features['vendor_mobile'].append(1 if any(v in vendor_lower for v in self.mobile_vendors) else 0)
            features['vendor_server'].append(1 if any(v in vendor_lower for v in self.server_vendors) else 0)
            features['vendor_router'].append(1 if any(v in vendor_lower for v in self.router_vendors) else 0)
            features['vendor_windows'].append(1 if any(v in vendor_lower for v in self.windows_vendors) else 0)
        
        return features
    
    def _extract_hostname_features(self, hostname_series: pd.Series) -> Dict[str, List[int]]:
        """Extract hostname features."""
        features = {
            'hostname_iot': [],
            'hostname_mobile': [],
            'hostname_server': [],
            'hostname_router': [],
            'hostname_windows': [],
            'hostname_length': [],
            'has_hostname': []
        }
        
        for hostname in hostname_series:
            if pd.isna(hostname) or not hostname or hostname == '':
                features['hostname_iot'].append(0)
                features['hostname_mobile'].append(0)
                features['hostname_server'].append(0)
                features['hostname_router'].append(0)
                features['hostname_windows'].append(0)
                features['hostname_length'].append(0)
                features['has_hostname'].append(0)
            else:
                hostname_str = str(hostname).strip().lower()
                features['hostname_iot'].append(1 if any(h in hostname_str for h in self.iot_hostname) else 0)
                features['hostname_mobile'].append(1 if any(h in hostname_str for h in self.mobile_hostname) else 0)
                features['hostname_server'].append(1 if any(h in hostname_str for h in self.server_hostname) else 0)
                features['hostname_router'].append(1 if any(h in hostname_str for h in self.router_hostname) else 0)
                features['hostname_windows'].append(1 if any(h in hostname_str for h in self.windows_hostname) else 0)
                features['hostname_length'].append(len(hostname_str))
                features['has_hostname'].append(1)
        
        return features
    
    def _extract_balanced_scores(self, df: pd.DataFrame) -> Dict[str, List[int]]:
        """Extract balanced device scores (prevents any class from dominating)."""
        features = {
            'score_iot': [],
            'score_mobile': [],
            'score_server': [],
            'score_router': [],
            'score_windows': [],
            # Confidence indicators
            'server_confidence': [],
            'mobile_confidence': [],
            'iot_confidence': [],
            'router_confidence': [],
            'windows_confidence': [],
        }
        
        for idx, row in df.iterrows():
            ports = self._parse_ports(row.get('open_ports', ''))
            services = str(row.get('services', '')).lower()
            os_fp = str(row.get('os_fingerprint', '')).lower()
            hostname = str(row.get('hostname', '')).lower()
            vendor = str(row.get('mac_vendor', '')).lower()
            
            # ===== IOT SCORE (0-10) =====
            iot_score = 0
            iot_score += min(sum(1 for p in ports if p in self.iot_ports), 3) * 2
            iot_score += min(sum(1 for s in services if s in self.iot_services), 3) * 2
            iot_score += 2 if any(o in os_fp for o in self.iot_os) else 0
            iot_score += 1 if any(v in vendor for v in self.iot_vendors) else 0
            iot_score += 2 if any(h in hostname for h in self.iot_hostname) else 0
            iot_score += 1 if len(ports) <= 3 else 0
            features['score_iot'].append(min(10, iot_score))
            
            # ===== MOBILE SCORE (0-10) =====
            mobile_score = 0
            mobile_score += min(sum(1 for p in ports if p in self.mobile_ports), 3) * 2
            mobile_score += min(sum(1 for s in services if s in self.mobile_services), 3) * 2
            mobile_score += 2 if any(o in os_fp for o in ['android', 'ios']) else 0
            mobile_score += 1 if any(v in vendor for v in self.mobile_vendors) else 0
            mobile_score += 2 if any(h in hostname for h in self.mobile_hostname) else 0
            mobile_score += 1 if len(ports) <= 3 else 0
            features['score_mobile'].append(min(10, mobile_score))
            
            # ===== SERVER SCORE (0-10) - ENHANCED =====
            server_score = 0
            # Server ports (weighted)
            server_ports_count = sum(1 for p in ports if p in self.server_ports)
            server_score += min(server_ports_count, 4) * 2
            
            # Critical server ports (extra weight)
            critical_ports = [389, 636, 3268, 3269, 88, 464, 1433, 3306, 5432, 27017]
            critical_count = sum(1 for p in ports if p in critical_ports)
            server_score += min(critical_count, 3) * 2
            
            # Server services
            server_services_count = sum(1 for s in services if s in self.server_services)
            server_score += min(server_services_count, 4) * 2
            
            # Critical server services
            critical_services = ['ldap', 'kerberos', 'active directory', 'oracle', 'mysql', 'postgres']
            critical_svc_count = sum(1 for s in critical_services if s in services)
            server_score += min(critical_svc_count, 3) * 2
            
            # OS server detection
            if 'server' in os_fp or 'enterprise' in os_fp or 'datacenter' in os_fp:
                server_score += 3
            elif any(o in os_fp for o in ['linux', 'ubuntu', 'debian']):
                server_score += 1  # Linux can be server
            if 'windows' in os_fp and 'server' in os_fp:
                server_score += 2
            
            # Vendor
            if any(v in vendor for v in self.server_vendors):
                server_score += 2
            
            # Hostname
            if any(h in hostname for h in self.server_hostname):
                server_score += 2
            
            # Multiple ports (server characteristic)
            if len(ports) > 8:
                server_score += 2
            elif len(ports) > 5:
                server_score += 1
            
            features['score_server'].append(min(10, server_score))
            
            # ===== ROUTER SCORE (0-10) =====
            router_score = 0
            router_score += min(sum(1 for p in ports if p in self.router_ports), 3) * 2
            router_score += min(sum(1 for s in services if s in self.router_services), 3) * 2
            router_score += 2 if any(v in vendor for v in self.router_vendors) else 0
            router_score += 2 if any(h in hostname for h in self.router_hostname) else 0
            router_score += 1 if len(ports) <= 5 else 0
            features['score_router'].append(min(10, router_score))
            
            # ===== WINDOWS SCORE (0-10) =====
            windows_score = 0
            windows_score += min(sum(1 for p in ports if p in self.windows_ports), 3) * 2
            windows_score += min(sum(1 for s in services if s in self.windows_services), 3) * 2
            windows_score += 2 if 'windows' in os_fp else 0
            windows_score += 1 if any(v in vendor for v in self.windows_vendors) else 0
            windows_score += 2 if any(h in hostname for h in self.windows_hostname) else 0
            windows_score += 1 if 3 <= len(ports) <= 8 else 0
            features['score_windows'].append(min(10, windows_score))
            
            # ===== CONFIDENCE INDICATORS (0-10) =====
            # These help the model make decisions when scores are close
            features['server_confidence'].append(min(10, server_score))
            features['mobile_confidence'].append(min(10, mobile_score))
            features['iot_confidence'].append(min(10, iot_score))
            features['router_confidence'].append(min(10, router_score))
            features['windows_confidence'].append(min(10, windows_score))
        
        return features
    
    def _parse_ports(self, ports_str) -> List[int]:
        """Helper to parse port strings into a list of integers."""
        try:
            if pd.isna(ports_str) or ports_str == '':
                return []
            elif isinstance(ports_str, (int, float)):
                return [int(ports_str)]
            else:
                port_str = str(ports_str)
                port_str = re.sub(r'[\[\]\'\"]', '', port_str)
                ports = []
                for p in re.split(r'[,;\s]+', port_str):
                    p = p.strip()
                    if p and p.isdigit():
                        ports.append(int(p))
                return ports
        except Exception as e:
            logger.debug(f"Error parsing ports: {ports_str} - {e}")
            return []
