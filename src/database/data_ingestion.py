"""
Data ingestion pipeline for processing scan results.
Handles data normalization, validation, and storage.
"""

from typing import Dict, Any, List, Optional
from datetime import datetime
import re
import logging

# Setup logger
logger = logging.getLogger(__name__)

class DataIngestionPipeline:
    """Processes and ingests scan data."""
    
    def __init__(self):
        """Initialize the data ingestion pipeline."""
        self.validated_data = []
        self.errors = []
        logger.info("Data ingestion pipeline initialized")
    
    def process_scan_results(self, scan_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process and normalize scan results.
        
        Args:
            scan_data: Raw scan results
        
        Returns:
            Normalized data ready for storage
        """
        normalized = {
            'scan_id': scan_data.get('scan_id', self._generate_scan_id()),
            'timestamp': scan_data.get('timestamp', datetime.utcnow().isoformat()),
            'target': scan_data.get('target', 'unknown'),
            'type': scan_data.get('type', 'scan'),
            'hosts': []
        }
        
        # Process hosts
        for host in scan_data.get('hosts', []):
            normalized_host = {
                'ip_address': host.get('ip_address'),
                'mac_address': host.get('mac_address'),
                'hostname': host.get('hostname'),
                'os_name': host.get('os_name'),
                'os_family': self._extract_os_family(host.get('os_name')),
                'os_accuracy': host.get('os_accuracy'),
                'status': host.get('status', 'up'),
                'services': []
            }
            
            # Process services
            for service in host.get('services', []):
                normalized_service = {
                    'port': service.get('port'),
                    'protocol': service.get('protocol', 'tcp'),
                    'service_name': service.get('service_name', 'unknown'),
                    'service_version': service.get('service_version'),
                    'banner': service.get('banner'),
                    'state': service.get('state', 'open')
                }
                normalized_host['services'].append(normalized_service)
            
            normalized['hosts'].append(normalized_host)
        
        return normalized
    
    def _generate_scan_id(self) -> str:
        """Generate a unique scan ID."""
        return f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    
    def _extract_os_family(self, os_name: Optional[str]) -> str:
        """Extract OS family from OS name."""
        if not os_name:
            return 'Unknown'
        
        os_lower = os_name.lower()
        
        os_families = {
            'windows': 'Windows',
            'linux': 'Linux',
            'mac': 'macOS',
            'darwin': 'macOS',
            'cisco': 'Cisco IOS',
            'android': 'Android',
            'ios': 'iOS',
            'ubuntu': 'Linux',
            'debian': 'Linux',
            'centos': 'Linux',
            'red hat': 'Linux',
            'fedora': 'Linux'
        }
        
        for key, family in os_families.items():
            if key in os_lower:
                return family
        
        return 'Unknown'
    
    def validate_data(self, data: Dict[str, Any]) -> bool:
        """
        Validate normalized data.
        
        Args:
            data: Normalized data to validate
        
        Returns:
            True if valid, False otherwise
        """
        self.errors = []
        
        # Check required fields
        if 'scan_id' not in data:
            self.errors.append("Missing scan_id")
            return False
        
        if 'hosts' not in data or not data['hosts']:
            self.errors.append("No hosts found in data")
            return False
        
        # Validate hosts
        for idx, host in enumerate(data.get('hosts', [])):
            if 'ip_address' not in host or not host['ip_address']:
                self.errors.append(f"Host {idx}: Missing ip_address")
                return False
            
            if not self._validate_ip(host['ip_address']):
                self.errors.append(f"Host {idx}: Invalid IP address: {host['ip_address']}")
                return False
            
            # Validate services
            for service in host.get('services', []):
                if 'port' not in service:
                    self.errors.append(f"Host {idx}: Service missing port")
                    return False
                
                port = service['port']
                if not isinstance(port, int) or port < 1 or port > 65535:
                    self.errors.append(f"Host {idx}: Invalid port: {port}")
                    return False
        
        return True
    
    def _validate_ip(self, ip: str) -> bool:
        """Validate IP address format."""
        if not ip:
            return False
        
        # Basic IP validation
        parts = ip.split('.')
        if len(parts) != 4:
            return False
        
        for part in parts:
            try:
                num = int(part)
                if num < 0 or num > 255:
                    return False
            except ValueError:
                return False
        
        return True
    
    def store_data(self, data: Dict[str, Any]) -> bool:
        """
        Store validated data (in-memory storage).
        
        Args:
            data: Normalized data
        
        Returns:
            True if successful, False otherwise
        """
        try:
            # Validate first
            if not self.validate_data(data):
                logger.error(f"Validation failed: {self.errors}")
                return False
            
            # Store in memory
            self.validated_data.append({
                'data': data,
                'stored_at': datetime.utcnow().isoformat()
            })
            
            # Log success
            host_count = len(data.get('hosts', []))
            service_count = sum(len(h.get('services', [])) for h in data.get('hosts', []))
            
            logger.info(f"Stored scan {data['scan_id']}: {host_count} hosts, {service_count} services")
            return True
            
        except Exception as e:
            logger.error(f"Failed to store data: {str(e)}")
            self.errors.append(str(e))
            return False
    
    def get_data(self, scan_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Retrieve stored data.
        
        Args:
            scan_id: Optional scan ID to filter by
        
        Returns:
            List of stored data entries
        """
        if scan_id:
            return [entry for entry in self.validated_data 
                   if entry['data'].get('scan_id') == scan_id]
        return self.validated_data
    
    def get_hosts(self) -> List[Dict[str, Any]]:
        """Get all hosts from stored data."""
        hosts = []
        for entry in self.validated_data:
            hosts.extend(entry['data'].get('hosts', []))
        return hosts
    
    def get_host_by_ip(self, ip_address: str) -> Optional[Dict[str, Any]]:
        """Get a specific host by IP address."""
        for entry in self.validated_data:
            for host in entry['data'].get('hosts', []):
                if host.get('ip_address') == ip_address:
                    return host
        return None
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get statistics about stored data."""
        total_hosts = len(self.get_hosts())
        total_scans = len(self.validated_data)
        
        # Count unique hosts
        unique_ips = set()
        services_count = 0
        
        for entry in self.validated_data:
            for host in entry['data'].get('hosts', []):
                if host.get('ip_address'):
                    unique_ips.add(host['ip_address'])
                services_count += len(host.get('services', []))
        
        return {
            'total_scans': total_scans,
            'total_hosts': total_hosts,
            'unique_hosts': len(unique_ips),
            'total_services': services_count,
            'total_errors': len(self.errors),
            'last_error': self.errors[-1] if self.errors else None
        }
    
    def clear_data(self) -> None:
        """Clear all stored data."""
        self.validated_data = []
        self.errors = []
        logger.info("Cleared all stored data")
    
    def export_data(self, format_type: str = 'json') -> Dict[str, Any]:
        """
        Export stored data in different formats.
        
        Args:
            format_type: Export format ('json', 'summary')
        
        Returns:
            Exported data
        """
        if format_type == 'summary':
            return {
                'statistics': self.get_statistics(),
                'scans': [
                    {
                        'scan_id': entry['data'].get('scan_id'),
                        'timestamp': entry['stored_at'],
                        'host_count': len(entry['data'].get('hosts', []))
                    }
                    for entry in self.validated_data
                ]
            }
        
        # Default: return full data
        return {
            'scans': self.validated_data,
            'statistics': self.get_statistics()
        }