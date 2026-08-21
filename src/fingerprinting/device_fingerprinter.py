"""
Device fingerprinting module for collecting and extracting device signatures.
Generates comprehensive fingerprints from network scan data.
"""

import hashlib
import json
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime
from collections import Counter
import logging

# Setup logger
logger = logging.getLogger(__name__)

class DeviceFingerprinter:
    """Extracts and generates device fingerprints from scan data."""
    
    def __init__(self):
        """Initialize the device fingerprinter."""
        self.device_patterns = self._get_device_patterns()
        logger.info("Device fingerprinter initialized")
    
    def _get_device_patterns(self) -> Dict[str, Dict]:
        """Get known device patterns for fingerprinting."""
        return {
            'router': {
                'ports': [22, 23, 80, 443, 8080, 8443, 53],
                'services': ['ssh', 'telnet', 'http', 'https', 'dns'],
                'keywords': ['router', 'gateway', 'cisco', 'huawei', 'mikrotik']
            },
            'server': {
                'ports': [80, 443, 21, 22, 25, 53, 110, 143, 3306, 5432, 27017, 8080],
                'services': ['http', 'https', 'ftp', 'ssh', 'smtp', 'dns', 'mysql', 'postgresql'],
                'keywords': ['apache', 'nginx', 'iis', 'tomcat', 'postgres', 'mysql', 'server']
            },
            'workstation': {
                'ports': [22, 80, 443, 3389, 5900, 445, 139],
                'services': ['ssh', 'http', 'https', 'rdp', 'vnc', 'smb'],
                'keywords': ['windows', 'microsoft', 'workstation', 'desktop']
            },
            'iot': {
                'ports': [80, 443, 23, 22, 8080, 1883, 8883],
                'services': ['http', 'https', 'telnet', 'ssh', 'mqtt'],
                'keywords': ['esp', 'arduino', 'raspberry', 'pi', 'sensor', 'camera']
            },
            'printer': {
                'ports': [515, 631, 9100, 80, 443, 161],
                'services': ['ipp', 'http', 'snmp', 'printer'],
                'keywords': ['hp', 'brother', 'epson', 'canon', 'printer']
            },
            'camera': {
                'ports': [80, 443, 554, 8554, 8080, 8443],
                'services': ['http', 'https', 'rtsp'],
                'keywords': ['camera', 'hikvision', 'dahua', 'h264']
            },
            'nas': {
                'ports': [80, 443, 21, 22, 139, 445, 2049, 548, 8080],
                'services': ['http', 'https', 'ftp', 'ssh', 'smb', 'nfs'],
                'keywords': ['synology', 'qnap', 'netapp', 'nas', 'storage']
            }
        }
    
    def fingerprint_device(self, host_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate a comprehensive fingerprint for a device.
        
        Args:
            host_data: Host data from scan results
        
        Returns:
            Dictionary with device fingerprint
        """
        logger.debug(f"Fingerprinting device: {host_data.get('ip_address', 'unknown')}")
        
        # Extract features
        features = self._extract_features(host_data)
        
        # Classify device
        classifications = self._classify_device(features)
        
        # Get best guess
        best_type, confidence = self._get_best_guess(classifications)
        
        fingerprint = {
            'ip_address': host_data.get('ip_address'),
            'mac_address': host_data.get('mac_address'),
            'hostname': host_data.get('hostname'),
            'timestamp': datetime.utcnow().isoformat(),
            'fingerprint_id': self._generate_id(host_data),
            'features': features,
            'device_type': best_type,
            'confidence': confidence,
            'all_classifications': classifications,
            'os': host_data.get('os_name') or host_data.get('os_family', 'unknown')
        }
        
        return fingerprint
    
    def _extract_features(self, host_data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract features from host data."""
        features = {
            'ports': [],
            'services': [],
            'banners': [],
            'open_port_count': 0,
            'service_count': 0
        }
        
        # Process services
        for service in host_data.get('services', []):
            port = service.get('port')
            if port:
                features['ports'].append(port)
                features['open_port_count'] += 1
            
            service_name = service.get('service_name', '').lower()
            if service_name and service_name != 'unknown':
                features['services'].append(service_name)
                features['service_count'] += 1
            
            banner = service.get('banner', '')
            if banner:
                features['banners'].append(banner.lower())
        
        return features
    
    def _classify_device(self, features: Dict[str, Any]) -> Dict[str, float]:
        """Classify device type based on features."""
        scores = {}
        
        for device_type, pattern in self.device_patterns.items():
            score = 0
            max_score = 0
            
            # Check ports (weight: 1)
            port_matches = sum(1 for p in features['ports'] if p in pattern['ports'])
            score += port_matches
            max_score += len(pattern['ports'])
            
            # Check services (weight: 2)
            service_matches = sum(1 for s in features['services'] if s in pattern['services'])
            score += service_matches * 2
            max_score += len(pattern['services']) * 2
            
            # Check keywords in banners (weight: 3)
            keyword_matches = 0
            for banner in features['banners']:
                for keyword in pattern['keywords']:
                    if keyword in banner:
                        keyword_matches += 1
                        break
            score += keyword_matches * 3
            max_score += len(pattern['keywords']) * 3
            
            # Normalize score
            scores[device_type] = score / max_score if max_score > 0 else 0
        
        return scores
    
    def _get_best_guess(self, classifications: Dict[str, float]) -> Tuple[str, float]:
        """Get the best guess from classifications."""
        if not classifications:
            return ('unknown', 0.0)
        
        # Sort by score descending
        sorted_types = sorted(classifications.items(), key=lambda x: x[1], reverse=True)
        
        if len(sorted_types) == 1:
            return sorted_types[0]
        
        best_type, best_score = sorted_types[0]
        second_score = sorted_types[1][1] if len(sorted_types) > 1 else 0
        
        # Calculate confidence based on gap between first and second
        if best_score == 0:
            confidence = 0.0
        elif second_score == 0:
            confidence = best_score
        else:
            confidence = (best_score - second_score) / best_score if best_score > 0 else 0
        
        # Cap confidence at 1.0
        confidence = min(confidence, 1.0)
        
        return (best_type, confidence)
    
    def _generate_id(self, host_data: Dict[str, Any]) -> str:
        """Generate a unique fingerprint ID."""
        # Create a hash based on key features
        data = {
            'ip': host_data.get('ip_address', ''),
            'mac': host_data.get('mac_address', ''),
            'ports': sorted([s.get('port') for s in host_data.get('services', []) if s.get('port')])
        }
        
        fingerprint_string = json.dumps(data, sort_keys=True)
        return hashlib.md5(fingerprint_string.encode()).hexdigest()[:12]
    
    def compare_fingerprints(self, fp1: Dict[str, Any], fp2: Dict[str, Any]) -> float:
        """
        Compare two device fingerprints and return similarity score.
        
        Args:
            fp1: First fingerprint
            fp2: Second fingerprint
        
        Returns:
            Similarity score between 0 and 1
        """
        # Get ports
        ports1 = set(fp1.get('features', {}).get('ports', []))
        ports2 = set(fp2.get('features', {}).get('ports', []))
        
        # Port similarity
        if not ports1 and not ports2:
            port_sim = 1.0
        elif not ports1 or not ports2:
            port_sim = 0.0
        else:
            intersection = len(ports1 & ports2)
            union = len(ports1 | ports2)
            port_sim = intersection / union if union > 0 else 0
        
        # Get services
        services1 = set(fp1.get('features', {}).get('services', []))
        services2 = set(fp2.get('features', {}).get('services', []))
        
        # Service similarity
        if not services1 and not services2:
            service_sim = 1.0
        elif not services1 or not services2:
            service_sim = 0.0
        else:
            intersection = len(services1 & services2)
            union = len(services1 | services2)
            service_sim = intersection / union if union > 0 else 0
        
        # Weighted average (ports 60%, services 40%)
        similarity = (port_sim * 0.6) + (service_sim * 0.4)
        return similarity
    
    def get_device_summary(self, fingerprint: Dict[str, Any]) -> Dict[str, Any]:
        """
        Get a human-readable summary of the fingerprint.
        
        Args:
            fingerprint: Device fingerprint
        
        Returns:
            Summary dictionary
        """
        features = fingerprint.get('features', {})
        
        # Get unique services safely
        services = features.get('services', [])
        if not isinstance(services, list):
            services = []
        
        unique_services = list(set(services))
        
        summary = {
            'ip_address': fingerprint.get('ip_address', 'unknown'),
            'mac_address': fingerprint.get('mac_address', 'unknown'),
            'hostname': fingerprint.get('hostname', 'unknown'),
            'device_type': fingerprint.get('device_type', 'unknown'),
            'confidence': f"{fingerprint.get('confidence', 0) * 100:.1f}%",
            'os': fingerprint.get('os', 'unknown'),
            'open_ports': features.get('open_port_count', 0),
            'service_count': features.get('service_count', 0),
            'detected_services': ', '.join(unique_services[:5]) if unique_services else 'none'
        }
        
        return summary
    
    def batch_fingerprint(self, hosts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Fingerprint multiple hosts.
        
        Args:
            hosts: List of host data
        
        Returns:
            List of fingerprints
        """
        fingerprints = []
        
        for host in hosts:
            try:
                fingerprint = self.fingerprint_device(host)
                fingerprints.append(fingerprint)
            except Exception as e:
                logger.error(f"Failed to fingerprint {host.get('ip_address', 'unknown')}: {str(e)}")
                continue
        
        logger.info(f"Fingerprinted {len(fingerprints)} devices")
        return fingerprints
    
    def export_fingerprint(self, fingerprint: Dict[str, Any], format_type: str = 'json') -> str:
        """
        Export fingerprint in different formats.
        
        Args:
            fingerprint: Device fingerprint
            format_type: Export format ('json', 'summary')
        
        Returns:
            Formatted string
        """
        if format_type == 'summary':
            summary = self.get_device_summary(fingerprint)
            return json.dumps(summary, indent=2)
        else:
            return json.dumps(fingerprint, indent=2, default=str)