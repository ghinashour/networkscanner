#!/usr/bin/env python3
"""
Integration Scanner - Complete Network Scan + CVE Lookup + Risk Assessment
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import sqlite3
import json
import logging
from datetime import datetime
from typing import List, Dict, Any

from real_scanner import RealNetworkScanner
from cve_integration import CVEService
from risk_engine import RiskEngine
from threat_intelligence import ThreatIntelligence
from adversary_risk_engine import AdversaryRiskEngine

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class IntegrationScanner:
    """
    Complete integration of all scanner components:
    - Network discovery with ML classification
    - CVE lookup via NVD API
    - Risk scoring (CVSS-based)
    - Threat intelligence prioritization
    """
    
    def __init__(self, db_path="data/network_scanner.db"):
        self.db_path = db_path
        self.nmap_scanner = RealNetworkScanner(db_path)
        self.cve_service = CVEService(db_path)
        self.risk_engine = RiskEngine(db_path)
        self.threat_intel = ThreatIntelligence(db_path)
        self.adversary_engine = AdversaryRiskEngine(db_path)
        
        # Ensure all tables exist
        self._init_database()
    
    def _init_database(self):
        """Initialize all database tables"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Create devices table if not exists
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS devices (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip_address TEXT UNIQUE,
                    mac_address TEXT,
                    hostname TEXT,
                    device_type TEXT,
                    os TEXT,
                    open_ports TEXT,
                    services TEXT,
                    first_seen TEXT,
                    last_seen TEXT
                )
            ''')
            
            # Create services table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS services (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    device_id INTEGER,
                    port INTEGER,
                    service_name TEXT,
                    version TEXT,
                    detected_date TEXT,
                    FOREIGN KEY (device_id) REFERENCES devices (id)
                )
            ''')
            
            conn.commit()
            conn.close()
            logger.info("✅ Database initialized with required tables")
            
        except Exception as e:
            logger.error(f"Database initialization error: {e}")
    
    def run_complete_scan(self, target_subnet: str = None) -> Dict: # type: ignore
        """
        Run complete scan workflow:
        1. Discover devices with ML classification
        2. Look up CVEs for each device
        3. Calculate risk scores
        4. Apply threat intelligence prioritization
        """
        logger.info("=" * 60)
        logger.info("🚀 Starting Complete Integration Scan")
        logger.info("=" * 60)
        
        results = {
            'timestamp': datetime.now().isoformat(),
            'devices_found': 0,
            'devices_with_cves': 0,
            'total_cves': 0,
            'critical_cves': 0,
            'high_cves': 0,
            'device_details': [],
            'priority_summary': {}
        }
        
        # Step 1: Scan network with ML classification
        logger.info("\n📡 Step 1: Network Discovery with ML Classification")
        logger.info("-" * 40)
        
        devices = self.nmap_scanner.scan_network(target_subnet)
        
        if not devices:
            logger.warning("❌ No devices found. Check your network connection.")
            return results
        
        # Save devices to database
        self.nmap_scanner.save_to_database(devices)
        results['devices_found'] = len(devices)
        
        logger.info(f"   ✅ Found {len(devices)} devices")
        
        # Step 2: Look up CVEs for each device
        logger.info("\n🔍 Step 2: CVE Lookup for Each Device")
        logger.info("-" * 40)
        
        for device in devices:
            device_id = self._get_device_id(device['ip'])
            if not device_id:
                continue
            
            # Get open ports and services
            open_ports = device.get('open_ports', [])
            services = device.get('services', [])
            
            if not open_ports and not services:
                logger.info(f"   ℹ️ No open ports on {device['ip']}, skipping CVE scan")
                continue
            
            # Build service list for CVE lookup
            service_list = []
            
            # If we have service objects
            if services and isinstance(services, list):
                for service in services:
                    if isinstance(service, dict):
                        service_list.append(service)
                    elif isinstance(service, str):
                        parts = service.split(':')
                        if len(parts) >= 2:
                            try:
                                service_list.append({
                                    'service': parts[0].strip(),
                                    'port': int(parts[1].strip())
                                })
                            except:
                                pass
            
            # If we only have ports
            if not service_list and open_ports:
                common_services = {
                    22: 'openssh', 23: 'telnet', 25: 'smtp', 53: 'dns',
                    80: 'http', 110: 'pop3', 135: 'msrpc', 139: 'netbios',
                    143: 'imap', 443: 'https', 445: 'smb', 3389: 'rdp',
                    3306: 'mysql', 5432: 'postgresql', 8080: 'http-proxy'
                }
                for port in open_ports:
                    service_name = common_services.get(port, f'service_{port}')
                    service_list.append({'service': service_name, 'port': port})
            
            # Scan each service for CVEs
            if service_list:
                logger.info(f"   🔍 Scanning {device['ip']} ({len(service_list)} services)")
                cves = self.cve_service.scan_device_services(device_id, service_list)
                
                if cves:
                    # Calculate risk score for this device
                    risk = self.risk_engine.calculate_risk_score(device_id)
                    results['devices_with_cves'] += 1
                    results['total_cves'] += len(cves)
                    
                    # Count critical and high CVEs
                    for cve in cves:
                        if cve.get('severity') == 'CRITICAL':
                            results['critical_cves'] += 1
                        elif cve.get('severity') == 'HIGH':
                            results['high_cves'] += 1
                    
                    logger.info(f"      Found {len(cves)} CVEs, Risk Score: {risk.get('risk_score', 0)}")
                else:
                    logger.info(f"      No CVEs found for {device['ip']}")
        
        # Step 3: Apply threat intelligence prioritization
        logger.info("\n🎯 Step 3: Threat Intelligence Prioritization")
        logger.info("-" * 40)
        
        if results['devices_with_cves'] > 0:
            priority_report = self.adversary_engine.generate_priority_report()
            results['priority_summary'] = priority_report
            
            logger.info(f"   📊 Priority Report:")
            stats = priority_report.get('statistics', {})
            logger.info(f"      Total Devices: {stats.get('total_devices', 0)}")
            logger.info(f"      Vulnerable Devices: {stats.get('vulnerable_devices', 0)}")
            logger.info(f"      KEV Devices: {stats.get('kev_devices', 0)}")
            
            logger.info("      Priority Distribution:")
            for priority in priority_report.get('priority_distribution', []):
                logger.info(f"         {priority['priority']}: {priority.get('device_count', 0)} devices, {priority.get('cve_count', 0)} CVEs")
        else:
            logger.info("   ℹ️ No CVEs found to prioritize")
        
        # Step 4: Generate summary report
        logger.info("\n📊 Step 4: Scan Complete - Summary")
        logger.info("=" * 60)
        logger.info(f"   Devices Found: {results['devices_found']}")
        logger.info(f"   Devices with CVEs: {results['devices_with_cves']}")
        logger.info(f"   Total CVEs Found: {results['total_cves']}")
        logger.info(f"   Critical CVEs: {results['critical_cves']}")
        logger.info(f"   High CVEs: {results['high_cves']}")
        
        if results['critical_cves'] > 0:
            logger.info("   ⚠️ CRITICAL: You have vulnerabilities that are being exploited in the wild!")
            logger.info("   🚨 IMMEDIATE ACTION REQUIRED: Patch or isolate affected devices.")
        elif results['high_cves'] > 0:
            logger.info("   ⚠️ HIGH: Vulnerabilities with high risk of exploitation.")
            logger.info("   📋 Schedule remediation in your next maintenance window.")
        else:
            logger.info("   ✅ No critical or high vulnerabilities detected.")
        
        logger.info("=" * 60)
        
        return results
    
    def _get_device_id(self, ip_address: str) -> int:
        """Get device ID from IP address"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('SELECT id FROM devices WHERE ip_address = ?', (ip_address,))
            row = cursor.fetchone()
            conn.close()
            return row[0] if row else None # type: ignore
        except:
            return None # type: ignore
    
    def get_devices_with_priorities(self) -> List[Dict]:
        """Get all devices with their adversary-driven priorities"""
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT 
                    d.id,
                    d.ip_address,
                    d.hostname,
                    d.device_type,
                    d.os,
                    COUNT(dv.id) as vuln_count,
                    SUM(CASE WHEN ti.kev_status = 1 THEN 1 ELSE 0 END) as kev_count,
                    AVG(ti.risk_score) as avg_threat_score,
                    MAX(ti.risk_level) as highest_priority
                FROM devices d
                LEFT JOIN device_vulnerabilities dv ON d.id = dv.device_id
                LEFT JOIN threat_intel ti ON dv.cve_id = ti.cve_id
                GROUP BY d.id
                ORDER BY avg_threat_score DESC NULLS LAST
            ''')
            
            devices = [dict(row) for row in cursor.fetchall()]
            conn.close()
            return devices
            
        except Exception as e:
            logger.error(f"Error getting devices with priorities: {e}")
            return []


# ============================================================================
# QUICK TEST
# ============================================================================

if __name__ == "__main__":
    print("=" * 60)
    print("🚀 INTEGRATION SCANNER TEST")
    print("=" * 60)
    
    # Initialize scanner
    scanner = IntegrationScanner()
    
    # Run complete scan
    results = scanner.run_complete_scan()
    
    # Show devices with priorities
    print("\n📋 Devices with Priorities:")
    print("-" * 60)
    devices = scanner.get_devices_with_priorities()
    
    for device in devices:
        priority = device.get('highest_priority', 'LOW')
        priority_emoji = {
            'CRITICAL': '🔴',
            'HIGH': '🟠', 
            'MEDIUM': '🟡',
            'LOW': '🟢'
        }.get(priority, '⚪')
        
        vuln_count = device.get('vuln_count', 0)
        kev_count = device.get('kev_count', 0)
        
        print(f"   {priority_emoji} {device['ip_address']:<15} "
              f"{device['device_type']:<12} "
              f"Vulns: {vuln_count}  "
              f"KEV: {kev_count}  "
              f"Priority: {priority}")
    
    print("\n" + "=" * 60)