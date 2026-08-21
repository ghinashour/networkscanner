"""
Scan orchestrator for managing and scheduling network scans.
Coordinates Nmap and Scapy scans, handles results, and manages scanning jobs.
"""

import threading
import queue
import time
import uuid
from datetime import datetime
from typing import Dict, List, Any, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
from src.scanner.scapy_scanner import ScapyScanner
import logging

# Setup logger
logger = logging.getLogger(__name__)

class ScanOrchestrator:
    """Orchestrates network scanning operations."""
    
    def __init__(self, max_workers: int = 3):
        """Initialize scan orchestrator."""
        self.scapy_scanner = ScapyScanner()
        self.max_workers = max_workers
        self.scan_queue = queue.Queue()
        self.scan_history = []
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
        self._worker_running = False
        self._worker_thread = None
        
        logger.info(f"Scan orchestrator initialized with {max_workers} workers")
    
    def scan_network(self, target: str, scan_profile: str = 'default') -> Dict[str, Any]:
        """
        Perform a complete network scan.
        
        Args:
            target: Target network range or IP
            scan_profile: Scan profile ('quick', 'default', 'deep')
        
        Returns:
            Dictionary with scan results
        """
        scan_id = f"scan_{uuid.uuid4().hex[:8]}"
        logger.info(f"Starting scan {scan_id} on {target} with {scan_profile} profile")
        
        results = {
            'scan_id': scan_id,
            'target': target,
            'profile': scan_profile,
            'timestamp': datetime.utcnow().isoformat(),
            'status': 'running',
            'hosts': [],
            'statistics': {}
        }
        
        try:
            # Step 1: Host Discovery
            logger.info("Discovering hosts...")
            devices = self.scapy_scanner.arp_scan(target)
            results['hosts'] = devices
            results['statistics']['total_hosts'] = len(devices)
            
            if not devices:
                logger.warning("No hosts found")
                results['status'] = 'completed'
                results['statistics']['scanned_hosts'] = 0
                return results
            
            # Step 2: Port scanning
            logger.info("Scanning ports...")
            ports = self._get_ports_for_profile(scan_profile)
            
            scan_results = []
            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                futures = {
                    executor.submit(self._scan_single_host, device['ip_address'], ports): device['ip_address']
                    for device in devices[:10]  # Limit to 10 hosts
                }
                
                for future in as_completed(futures):
                    try:
                        result = future.result(timeout=120)
                        scan_results.append(result)
                    except Exception as e:
                        logger.error(f"Scan failed: {str(e)}")
            
            # Step 3: Update results
            for host_result in results['hosts']:
                matched = next(
                    (r for r in scan_results if r['target'] == host_result['ip_address']),
                    None
                )
                if matched:
                    host_result['open_ports'] = matched.get('open_ports', [])
                    host_result['services'] = matched.get('services', [])
            
            results['status'] = 'completed'
            results['statistics']['scanned_hosts'] = len(scan_results)
            
            # Step 4: Save to database (optional)
            self._save_results(results)
            
            logger.info(f"Scan {scan_id} completed")
            return results
            
        except Exception as e:
            logger.error(f"Scan failed: {str(e)}")
            results['status'] = 'failed'
            results['error'] = str(e)
            return results
    
    def _get_ports_for_profile(self, profile: str) -> List[int]:
        """Get ports based on scan profile."""
        ports = {
            'quick': [22, 80, 443, 3389],
            'default': [22, 80, 443, 3306, 3389, 8080],
            'deep': [22, 25, 53, 80, 110, 143, 443, 993, 995, 3306, 3389, 5432, 8080, 8443]
        }
        return ports.get(profile, ports['default'])
    
    def _scan_single_host(self, host_ip: str, ports: List[int]) -> Dict[str, Any]:
        """Scan a single host."""
        result = {
            'target': host_ip,
            'open_ports': [],
            'services': []
        }
        
        try:
            # TCP port scan
            port_results = self.scapy_scanner.tcp_port_scan(host_ip, ports)
            result['open_ports'] = port_results.get('open_ports', [])
            
            # Banner grabbing for open ports
            for port in result['open_ports'][:3]:  # Limit to 3 ports
                banner = self.scapy_scanner.banner_grab(host_ip, port)
                if banner:
                    result['services'].append({
                        'port': port,
                        'protocol': 'tcp',
                        'banner': banner[:200],  # Truncate banner
                        'service_name': self._guess_service(port, banner)
                    })
            
            return result
            
        except Exception as e:
            logger.error(f"Failed to scan {host_ip}: {str(e)}")
            return result
    
    def _guess_service(self, port: int, banner: str) -> str:
        """Guess service name from port and banner."""
        common = {
            22: 'ssh', 23: 'telnet', 25: 'smtp', 53: 'dns',
            80: 'http', 110: 'pop3', 143: 'imap', 443: 'https',
            3306: 'mysql', 3389: 'rdp', 5432: 'postgresql',
            8080: 'http-alt', 8443: 'https-alt'
        }
        
        if port in common:
            return common[port]
        
        # Try to detect from banner
        if banner:
            banner_lower = banner.lower()
            if 'ssh' in banner_lower:
                return 'ssh'
            elif 'http' in banner_lower or 'html' in banner_lower:
                return 'http'
            elif 'mysql' in banner_lower:
                return 'mysql'
            elif 'ftp' in banner_lower:
                return 'ftp'
        
        return 'unknown'
    
    def _save_results(self, results: Dict[str, Any]) -> None:
        """Save results (stub for database integration)."""
        try:
            # This is a placeholder - implement actual database saving
            logger.debug(f"Would save scan {results['scan_id']} to database")
        except Exception as e:
            logger.error(f"Failed to save results: {str(e)}")
    
    def get_scan_history(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get recent scan history."""
        return self.scan_history[-limit:]
    
    def get_host_details(self, ip_address: str) -> Optional[Dict[str, Any]]:
        """Get details about a specific host from history."""
        for scan in self.scan_history:
            for host in scan.get('hosts', []):
                if host.get('ip_address') == ip_address:
                    return host
        return None
    
    def schedule_scan(self, target: str, scan_profile: str = 'default', 
                     delay_seconds: int = 0) -> str:
        """Schedule a scan for later execution."""
        scan_id = f"scheduled_{uuid.uuid4().hex[:8]}"
        
        self.scan_queue.put({
            'scan_id': scan_id,
            'target': target,
            'profile': scan_profile,
            'delay': delay_seconds
        })
        
        # Start background worker
        self._start_worker()
        
        return scan_id
    
    def _start_worker(self):
        """Start background worker for scheduled scans."""
        if not self._worker_running:
            self._worker_running = True
            self._worker_thread = threading.Thread(target=self._process_queue)
            self._worker_thread.daemon = True
            self._worker_thread.start()
            logger.info("Background worker started")
    
    def _process_queue(self):
        """Process scheduled scans."""
        while self._worker_running:
            try:
                job = self.scan_queue.get(timeout=1)
                if job:
                    delay = job.get('delay', 0)
                    if delay > 0:
                        time.sleep(delay)
                    
                    logger.info(f"Executing scheduled scan: {job['scan_id']}")
                    result = self.scan_network(job['target'], job['profile'])
                    self.scan_history.append(result)
                    
            except queue.Empty:
                continue
            except Exception as e:
                logger.error(f"Worker error: {str(e)}")
                time.sleep(5)
    
    def cleanup(self):
        """Clean up resources."""
        self._worker_running = False
        if self._worker_thread:
            self._worker_thread.join(timeout=2)
        self.executor.shutdown(wait=True)
        logger.info("Orchestrator cleaned up")