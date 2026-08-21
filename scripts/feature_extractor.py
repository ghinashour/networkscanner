"""
Device Feature Extractor - Converts network data to ML features
Enhanced with advanced features for better classification
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
    """
    
    def __init__(self):
        self.common_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 
                            443, 445, 993, 995, 1723, 3306, 3389, 5432, 
                            5900, 6379, 8080, 8443, 27017]
        
        self.os_keywords = {
            'windows': ['windows', 'win', 'microsoft', 'nt'],
            'linux': ['linux', 'ubuntu', 'centos', 'debian', 'fedora'],
            'ios': ['ios', 'apple', 'mac', 'darwin'],
            'android': ['android'],
            'embedded': ['embedded', 'iot', 'routeros', 'vxworks', 'openwrt', 'dd-wrt']
        }
        
        # IoT-specific ports
        self.iot_ports = [554, 1900, 5000, 8080, 8000, 8888, 3000, 4200, 1883, 8883]
        self.enterprise_ports = [389, 636, 3268, 3269, 88, 464, 135, 445]
        self.media_ports = [554, 7070, 1935, 5004, 5005]
        
        # Service patterns
        self.iot_services = ['rtsp', 'upnp', 'coap', 'mqtt', 'onvif', 'psia', 'snmp']
        self.enterprise_services = ['ldap', 'kerberos', 'ad', 'exchange', 'sharepoint']
        self.cloud_services = ['aws', 'azure', 'gcp', 'cloud', 'saas']
    
    def extract_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Extract numerical features from raw device data.
        
        Args:
            df: DataFrame with device scan data
        
        Returns:
            DataFrame with numerical features
        """
        logger.info("Extracting features from device data...")
        features = {}
        
        # 1. Port-based features
        if 'open_ports' in df.columns:
            port_features = self._extract_port_features(df['open_ports'])
            features.update(port_features)
        
        # 2. OS fingerprint features
        if 'os_fingerprint' in df.columns:
            os_features = self._extract_os_features(df['os_fingerprint'])
            features.update(os_features)
        
        # 3. Service features
        if 'services' in df.columns:
            service_features = self._extract_service_features(df['services'])
            features.update(service_features)
        
        # 4. IP-based features
        if 'ip' in df.columns:
            ip_features = self._extract_ip_features(df['ip'])
            features.update(ip_features)
        
        # 5. MAC vendor features
        if 'mac_vendor' in df.columns:
            vendor_features = self._extract_vendor_features(df['mac_vendor'])
            features.update(vendor_features)
        
        # 6. Hostname features
        if 'hostname' in df.columns:
            hostname_features = self._extract_hostname_features(df['hostname'])
            features.update(hostname_features)
        
        # 7. Advanced port features
        if 'open_ports' in df.columns:
            advanced_port_features = self._extract_advanced_port_features(df['open_ports'])
            features.update(advanced_port_features)
        
        # 8. Advanced service features (combinations)
        if 'services' in df.columns:
            advanced_service_features = self._extract_advanced_service_features(df['services'])
            features.update(advanced_service_features)
        
        # 9. Advanced OS features (combinations)
        if 'os_fingerprint' in df.columns:
            advanced_os_features = self._extract_advanced_os_features(df['os_fingerprint'])
            features.update(advanced_os_features)
        
        # 10. Device behavior patterns
        if 'open_ports' in df.columns and 'services' in df.columns:
            behavior_features = self._extract_behavior_features(df)
            features.update(behavior_features)
        
        # Convert to DataFrame
        feature_df = pd.DataFrame(features)
        
        # Handle missing values
        feature_df = feature_df.fillna(0)
        
        logger.info(f"Extracted {len(feature_df.columns)} features from {len(df)} devices")
        return feature_df
    
    def _extract_port_features(self, port_series: pd.Series) -> Dict[str, List[float]]:
        """Extract basic features from port data."""
        features = {
            'num_ports': [],
            'has_web_port': [],
            'has_ssh_port': [],
            'has_smb_port': [],
            'has_rdp_port': [],
            'has_database_port': [],
            'has_mail_port': [],
            'has_dns_port': []
        }
        
        for ports_str in port_series:
            ports = self._parse_ports(ports_str)
            
            features['num_ports'].append(len(ports))
            features['has_web_port'].append(1 if any(p in [80, 443, 8080, 8443] for p in ports) else 0)
            features['has_ssh_port'].append(1 if 22 in ports else 0)
            features['has_smb_port'].append(1 if 445 in ports or 139 in ports else 0)
            features['has_rdp_port'].append(1 if 3389 in ports else 0)
            features['has_database_port'].append(1 if any(p in [3306, 5432, 27017, 1433, 1521] for p in ports) else 0)
            features['has_mail_port'].append(1 if any(p in [25, 110, 143, 993, 995] for p in ports) else 0)
            features['has_dns_port'].append(1 if 53 in ports else 0)
        
        return features
    
    def _extract_advanced_port_features(self, port_series: pd.Series) -> Dict[str, List[float]]:
        """Extract advanced features from port data for better classification."""
        features = {
            'has_iot_ports': [],
            'has_enterprise_ports': [],
            'has_media_ports': [],
            'port_diversity': [],
            'is_high_port_count': [],
            'is_low_port_count': [],
            'port_range_span': []
        }
        
        for ports_str in port_series:
            ports = self._parse_ports(ports_str)
            
            if not ports:
                features['has_iot_ports'].append(0)
                features['has_enterprise_ports'].append(0)
                features['has_media_ports'].append(0)
                features['port_diversity'].append(0)
                features['is_high_port_count'].append(0)
                features['is_low_port_count'].append(1)
                features['port_range_span'].append(0)
                continue
            
            # Check for IoT-specific ports
            features['has_iot_ports'].append(1 if any(p in self.iot_ports for p in ports) else 0)
            
            # Check for enterprise-specific ports
            features['has_enterprise_ports'].append(1 if any(p in self.enterprise_ports for p in ports) else 0)
            
            # Check for media ports
            features['has_media_ports'].append(1 if any(p in self.media_ports for p in ports) else 0)
            
            # Port diversity (how many different first digits)
            first_digits = len(set(str(p)[0] for p in ports if p > 0))
            features['port_diversity'].append(first_digits / 10)  # Normalize to 0-1
            
            # Port count categories
            features['is_high_port_count'].append(1 if len(ports) > 10 else 0)
            features['is_low_port_count'].append(1 if len(ports) < 3 else 0)
            
            # Port range span (max - min)
            if len(ports) > 1:
                features['port_range_span'].append((max(ports) - min(ports)) / 65535)  # Normalize
            else:
                features['port_range_span'].append(0)
        
        return features
    
    def _extract_os_features(self, os_series: pd.Series) -> Dict[str, List[int]]:
        """Extract basic OS features."""
        features = {
            'os_windows': [],
            'os_linux': [],
            'os_ios': [],
            'os_android': [],
            'os_embedded': []
        }
        
        for os_str in os_series:
            os_lower = str(os_str).lower() if not pd.isna(os_str) and os_str else ''
            
            features['os_windows'].append(1 if any(kw in os_lower for kw in self.os_keywords['windows']) else 0)
            features['os_linux'].append(1 if any(kw in os_lower for kw in self.os_keywords['linux']) else 0)
            features['os_ios'].append(1 if any(kw in os_lower for kw in self.os_keywords['ios']) else 0)
            features['os_android'].append(1 if any(kw in os_lower for kw in self.os_keywords['android']) else 0)
            features['os_embedded'].append(1 if any(kw in os_lower for kw in self.os_keywords['embedded']) else 0)
        
        return features
    
    def _extract_advanced_os_features(self, os_series: pd.Series) -> Dict[str, List[int]]:
        """Extract advanced OS features."""
        features = {
            'is_server_like': [],
            'is_embedded_like': [],
            'is_mobile_like': [],
            'os_uncertainty': []
        }
        
        server_indicators = ['server', 'datacenter', 'enterprise', 'x86_64', '64-bit']
        embedded_indicators = ['embedded', 'arm', 'mips', 'openwrt', 'dd-wrt', 'busybox']
        mobile_indicators = ['android', 'ios', 'phone', 'tablet', 'mobile']
        
        for os_str in os_series:
            os_lower = str(os_str).lower() if not pd.isna(os_str) and os_str else ''
            
            # Server-like
            features['is_server_like'].append(
                1 if any(ind in os_lower for ind in server_indicators) else 0
            )
            
            # Embedded-like
            features['is_embedded_like'].append(
                1 if any(ind in os_lower for ind in embedded_indicators) else 0
            )
            
            # Mobile-like
            features['is_mobile_like'].append(
                1 if any(ind in os_lower for ind in mobile_indicators) else 0
            )
            
            # OS uncertainty (if OS fingerprint is generic)
            generic_os = ['linux', 'windows', 'unix', 'unknown', 'generic']
            features['os_uncertainty'].append(
                1 if any(g in os_lower for g in generic_os) and len(os_lower) < 10 else 0
            )
        
        return features
    
    def _extract_service_features(self, service_series: pd.Series) -> Dict[str, List[int]]:
        """Extract basic service features."""
        features = {
            'has_http': [],
            'has_https': [],
            'has_ssh': [],
            'has_smtp': [],
            'has_ftp': [],
            'has_sql': [],
            'has_rdp': [],
            'has_snmp': []
        }
        
        for services_str in service_series:
            services_lower = str(services_str).lower() if not pd.isna(services_str) and services_str else ''
            
            features['has_http'].append(1 if 'http' in services_lower else 0)
            features['has_https'].append(1 if 'https' in services_lower or 'ssl' in services_lower else 0)
            features['has_ssh'].append(1 if 'ssh' in services_lower else 0)
            features['has_smtp'].append(1 if 'smtp' in services_lower or 'mail' in services_lower else 0)
            features['has_ftp'].append(1 if 'ftp' in services_lower else 0)
            features['has_sql'].append(1 if any(x in services_lower for x in ['sql', 'mysql', 'postgres', 'mongodb']) else 0)
            features['has_rdp'].append(1 if 'rdp' in services_lower or 'terminal' in services_lower else 0)
            features['has_snmp'].append(1 if 'snmp' in services_lower else 0)
        
        return features
    
    def _extract_advanced_service_features(self, service_series: pd.Series) -> Dict[str, List[int]]:
        """Extract advanced service features and combinations."""
        features = {
            'has_iot_services': [],
            'has_enterprise_services': [],
            'has_cloud_services': [],
            'has_web_and_db': [],
            'has_smb_and_rdp': [],
            'has_multimedia_services': [],
            'service_diversity': []
        }
        
        for services_str in service_series:
            services_lower = str(services_str).lower() if not pd.isna(services_str) and services_str else ''
            service_list = [s.strip() for s in services_lower.split(',') if s.strip()]
            
            # IoT services
            features['has_iot_services'].append(
                1 if any(s in services_lower for s in self.iot_services) else 0
            )
            
            # Enterprise services
            features['has_enterprise_services'].append(
                1 if any(s in services_lower for s in self.enterprise_services) else 0
            )
            
            # Cloud services
            features['has_cloud_services'].append(
                1 if any(s in services_lower for s in self.cloud_services) else 0
            )
            
            # Web + Database combination
            has_web = 'http' in services_lower or 'https' in services_lower
            has_db = any(s in services_lower for s in ['sql', 'mysql', 'postgres', 'mongodb'])
            features['has_web_and_db'].append(1 if has_web and has_db else 0)
            
            # SMB + RDP combination (Windows server)
            has_smb = 'smb' in services_lower or 'cifs' in services_lower
            has_rdp = 'rdp' in services_lower
            features['has_smb_and_rdp'].append(1 if has_smb and has_rdp else 0)
            
            # Multimedia services
            multimedia = ['rtsp', 'rtmp', 'rtp', 'hls', 'dash', 'stream']
            features['has_multimedia_services'].append(
                1 if any(s in services_lower for s in multimedia) else 0
            )
            
            # Service diversity (different types of services)
            service_types = set()
            for s in service_list:
                if any(core in s for core in ['http', 'https', 'ssl']):
                    service_types.add('web')
                elif any(core in s for core in ['sql', 'db', 'mongo']):
                    service_types.add('db')
                elif any(core in s for core in ['ssh', 'telnet', 'rlogin']):
                    service_types.add('remote')
                elif any(core in s for core in ['smtp', 'imap', 'pop', 'mail']):
                    service_types.add('mail')
            
            features['service_diversity'].append(len(service_types) / 5)  # Normalize
        
        return features
    
    def _extract_behavior_features(self, df: pd.DataFrame) -> Dict[str, List[int]]:
        """Extract features based on device behavior patterns."""
        features = {
            'is_iot_pattern': [],
            'is_server_pattern': [],
            'is_workstation_pattern': []
        }
        
        for idx, row in df.iterrows():
            ports = self._parse_ports(row.get('open_ports', ''))
            services = str(row.get('services', '')).lower()
            os_fp = str(row.get('os_fingerprint', '')).lower()
            
            # IoT pattern: few ports, IoT-specific services, embedded OS
            iot_score = 0
            iot_score += 1 if any(p in self.iot_ports for p in ports) else 0
            iot_score += 1 if any(s in services for s in self.iot_services) else 0
            iot_score += 1 if 'embedded' in os_fp or 'arm' in os_fp else 0
            iot_score += 1 if len(ports) <= 3 else 0
            features['is_iot_pattern'].append(1 if iot_score >= 3 else 0)
            
            # Server pattern: many services, enterprise services, server OS
            server_score = 0
            server_score += 1 if len(ports) > 5 else 0
            server_score += 1 if any(p in self.enterprise_ports for p in ports) else 0
            server_score += 1 if any(s in services for s in self.enterprise_services) else 0
            server_score += 1 if 'server' in os_fp else 0
            features['is_server_pattern'].append(1 if server_score >= 3 else 0)
            
            # Workstation pattern: specific ports, specific services
            workstation_score = 0
            workstation_score += 1 if any(p in [3389, 445, 135] for p in ports) else 0
            workstation_score += 1 if any(s in services for s in ['smb', 'rdp', 'rpc']) else 0
            workstation_score += 1 if 'windows' in os_fp else 0
            workstation_score += 1 if 3 <= len(ports) <= 8 else 0
            features['is_workstation_pattern'].append(1 if workstation_score >= 3 else 0)
        
        return features
    
    def _extract_vendor_features(self, vendor_series: pd.Series) -> Dict[str, List[int]]:
        """Extract features from MAC vendor data."""
        features = {
            'vendor_cisco': [],
            'vendor_hp': [],
            'vendor_dell': [],
            'vendor_apple': [],
            'vendor_linux': [],
            'vendor_embedded': [],
            'vendor_iot': [],
            'vendor_enterprise': [],
            'vendor_consumer': []
        }
        
        cisco_keywords = ['cisco', 'meraki', 'linksys']
        hp_keywords = ['hp', 'hewlett', 'packard']
        dell_keywords = ['dell', 'emc']
        apple_keywords = ['apple', 'mac']
        linux_keywords = ['linux', 'canonical', 'ubuntu']
        embedded_keywords = ['raspberry', 'arduino', 'esp', 'microchip', 'silicon', 'arm']
        iot_vendors = ['raspberry', 'arduino', 'esp', 'espressif', 'ubiquiti', 'microchip']
        enterprise_vendors = ['cisco', 'juniper', 'hp', 'dell', 'emc', 'ibm', 'oracle', 'brocade']
        consumer_vendors = ['apple', 'samsung', 'lg', 'sony', 'google', 'asus', 'acer']
        
        for vendor in vendor_series:
            vendor_lower = str(vendor).lower() if not pd.isna(vendor) and vendor else ''
            
            features['vendor_cisco'].append(1 if any(kw in vendor_lower for kw in cisco_keywords) else 0)
            features['vendor_hp'].append(1 if any(kw in vendor_lower for kw in hp_keywords) else 0)
            features['vendor_dell'].append(1 if any(kw in vendor_lower for kw in dell_keywords) else 0)
            features['vendor_apple'].append(1 if any(kw in vendor_lower for kw in apple_keywords) else 0)
            features['vendor_linux'].append(1 if any(kw in vendor_lower for kw in linux_keywords) else 0)
            features['vendor_embedded'].append(1 if any(kw in vendor_lower for kw in embedded_keywords) else 0)
            features['vendor_iot'].append(1 if any(v in vendor_lower for v in iot_vendors) else 0)
            features['vendor_enterprise'].append(1 if any(v in vendor_lower for v in enterprise_vendors) else 0)
            features['vendor_consumer'].append(1 if any(v in vendor_lower for v in consumer_vendors) else 0)
        
        return features
    
    def _extract_ip_features(self, ip_series: pd.Series) -> Dict[str, List[int]]:
        """Extract features from IP addresses."""
        features = {
            'is_private': [],
            'is_multicast': [],
            'is_public': [],
            'is_link_local': []
        }
        
        for ip_str in ip_series:
            try:
                if pd.isna(ip_str) or not ip_str:
                    features['is_private'].append(0)
                    features['is_multicast'].append(0)
                    features['is_public'].append(0)
                    features['is_link_local'].append(0)
                    continue
                
                ip = str(ip_str).strip()
                
                # Private IP ranges
                if ip.startswith(('10.', '172.16.', '172.17.', '172.18.', '172.19.', '172.20.', 
                                 '172.21.', '172.22.', '172.23.', '172.24.', '172.25.', '172.26.',
                                 '172.27.', '172.28.', '172.29.', '172.30.', '172.31.', '192.168.')):
                    features['is_private'].append(1)
                    features['is_public'].append(0)
                    features['is_multicast'].append(0)
                    features['is_link_local'].append(0)
                elif ip.startswith('224.'):
                    features['is_private'].append(0)
                    features['is_public'].append(0)
                    features['is_multicast'].append(1)
                    features['is_link_local'].append(0)
                elif ip.startswith('169.254.'):
                    features['is_private'].append(0)
                    features['is_public'].append(0)
                    features['is_multicast'].append(0)
                    features['is_link_local'].append(1)
                else:
                    features['is_private'].append(0)
                    features['is_public'].append(1)
                    features['is_multicast'].append(0)
                    features['is_link_local'].append(0)
            except:
                features['is_private'].append(0)
                features['is_multicast'].append(0)
                features['is_public'].append(0)
                features['is_link_local'].append(0)
        
        return features
    
    def _extract_hostname_features(self, hostname_series: pd.Series) -> Dict[str, List[int]]:
        """Extract features from hostname data."""
        features = {
            'has_hostname': [],
            'is_domain': [],
            'hostname_length': [],
            'has_iot_hostname': [],
            'has_server_hostname': []
        }
        
        iot_patterns = ['sensor', 'camera', 'device', 'iot', 'smart', 'hub', 'gateway']
        server_patterns = ['server', 'db', 'database', 'web', 'app', 'mail', 'exchange']
        
        for hostname in hostname_series:
            if pd.isna(hostname) or not hostname or hostname == '':
                features['has_hostname'].append(0)
                features['is_domain'].append(0)
                features['hostname_length'].append(0)
                features['has_iot_hostname'].append(0)
                features['has_server_hostname'].append(0)
            else:
                hostname_str = str(hostname).strip().lower()
                features['has_hostname'].append(1)
                features['is_domain'].append(1 if '.' in hostname_str else 0)
                features['hostname_length'].append(len(hostname_str))
                features['has_iot_hostname'].append(1 if any(p in hostname_str for p in iot_patterns) else 0)
                features['has_server_hostname'].append(1 if any(p in hostname_str for p in server_patterns) else 0)
        
        return features
    
    def _parse_ports(self, ports_str) -> List[int]:
        """Helper to parse port strings into a list of integers."""
        try:
            if pd.isna(ports_str) or ports_str == '':
                return []
            elif isinstance(ports_str, (int, float)):
                return [int(ports_str)]
            else:
                # Handle different formats
                port_str = str(ports_str)
                # Remove brackets, quotes, etc.
                port_str = re.sub(r'[\[\]\'"]', '', port_str)
                # Split by comma or space
                ports = []
                for p in re.split(r'[,;\s]+', port_str):
                    p = p.strip()
                    if p and p.isdigit():
                        ports.append(int(p))
                return ports
        except Exception as e:
            logger.debug(f"Error parsing ports: {ports_str} - {e}")
            return []