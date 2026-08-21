"""
CVE Lookup Service - Query NVD API for vulnerabilities
"""

import requests
import json
import sqlite3
import time
from datetime import datetime
from typing import List, Dict, Any
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class CVEService:
    def __init__(self, db_path="data/network_scanner.db"):
        self.db_path = db_path
        self.nvd_api_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.init_db()
    
    def init_db(self):
        """Initialize CVE database tables"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Create cves table - using 'references_text' instead of 'references'
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS cves (
                    cve_id TEXT PRIMARY KEY,
                    description TEXT,
                    cvss_score REAL,
                    severity TEXT,
                    published_date TEXT,
                    last_modified TEXT,
                    references_text TEXT,
                    cvss_vector TEXT
                )
            ''')
            
            # Create device_vulnerabilities table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS device_vulnerabilities (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    device_id INTEGER,
                    cve_id TEXT,
                    service TEXT,
                    detected_date TEXT,
                    FOREIGN KEY (device_id) REFERENCES devices (id),
                    FOREIGN KEY (cve_id) REFERENCES cves (cve_id)
                )
            ''')
            
            # Create devices table if it doesn't exist (for foreign key)
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS devices (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip_address TEXT,
                    mac_address TEXT,
                    hostname TEXT,
                    device_type TEXT,
                    os TEXT,
                    first_seen TEXT,
                    last_seen TEXT
                )
            ''')
            
            conn.commit()
            conn.close()
            logger.info("✅ CVE database initialized successfully")
            
        except Exception as e:
            logger.error(f"❌ Database initialization error: {e}")
            raise
    
    def get_cves_for_service(self, service_name: str, port: int) -> List[Dict]:
        """Query NVD API for CVEs related to a service"""
        try:
            # Build query - search for service name
            query = f"{service_name}"
            params = {
                'keywordSearch': query,
                'resultsPerPage': 10
            }
            
            logger.info(f"🔍 Querying NVD for: {service_name} (port {port})")
            
            response = requests.get(self.nvd_api_url, params=params, timeout=15)
            
            if response.status_code == 200:
                data = response.json()
                cves = []
                
                for vuln in data.get('vulnerabilities', []):
                    cve_data = vuln.get('cve', {})
                    metrics = cve_data.get('metrics', {})
                    
                    # Extract CVSS score (try V31 first, then V30, then V2)
                    cvss_info = {}
                    if 'cvssMetricV31' in metrics and metrics['cvssMetricV31']:
                        cvss_info = metrics['cvssMetricV31'][0].get('cvssData', {})
                    elif 'cvssMetricV30' in metrics and metrics['cvssMetricV30']:
                        cvss_info = metrics['cvssMetricV30'][0].get('cvssData', {})
                    elif 'cvssMetricV2' in metrics and metrics['cvssMetricV2']:
                        cvss_info = metrics['cvssMetricV2'][0].get('cvssData', {})
                    
                    cvss_score = cvss_info.get('baseScore', 0)
                    
                    # Get description
                    descriptions = cve_data.get('descriptions', [])
                    description = ""
                    for desc in descriptions:
                        if desc.get('lang') == 'en':
                            description = desc.get('value', '')
                            break
                    
                    # Get references
                    refs = cve_data.get('references', [])
                    ref_list = []
                    for ref in refs:
                        ref_list.append(ref.get('url', ''))
                    
                    cve = {
                        'cve_id': cve_data.get('id', ''),
                        'description': description[:500],  # Truncate for DB
                        'cvss_score': cvss_score,
                        'severity': self._get_severity(cvss_score),
                        'published_date': cve_data.get('published', ''),
                        'references_text': json.dumps(ref_list[:5]),  # Limit references
                        'cvss_vector': cvss_info.get('vectorString', '')
                    }
                    
                    cves.append(cve)
                
                # Save to database
                for cve in cves:
                    self._save_cve(cve)
                
                logger.info(f"   Found {len(cves)} CVEs for {service_name}")
                
                # Rate limiting - be nice to NVD API
                time.sleep(1)
                
                return cves
            else:
                logger.warning(f"⚠️ NVD API error: {response.status_code} - {response.text[:100]}")
                return []
                
        except requests.exceptions.Timeout:
            logger.error(f"⏰ Timeout fetching CVEs for {service_name}")
            return []
        except requests.exceptions.ConnectionError:
            logger.error(f"🔌 Connection error fetching CVEs for {service_name}")
            return []
        except Exception as e:
            logger.error(f"❌ Error fetching CVEs: {e}")
            return []
    
    def _save_cve(self, cve_data: Dict):
        """Save CVE to database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT OR REPLACE INTO cves 
                (cve_id, description, cvss_score, severity, 
                 published_date, references_text, cvss_vector)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                cve_data['cve_id'],
                cve_data['description'],
                cve_data['cvss_score'],
                cve_data['severity'],
                cve_data['published_date'],
                cve_data['references_text'],
                cve_data['cvss_vector']
            ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"Error saving CVE {cve_data.get('cve_id')}: {e}")
    
    def save_device_vulnerability(self, device_id: int, cve_id: str, service: str):
        """Associate a CVE with a device"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO device_vulnerabilities 
                (device_id, cve_id, service, detected_date)
                VALUES (?, ?, ?, ?)
            ''', (
                device_id,
                cve_id,
                service,
                datetime.now().isoformat()
            ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"Error saving device vulnerability: {e}")
    
    def _get_severity(self, score: float) -> str:
        """Convert CVSS score to severity level"""
        if score >= 9.0:
            return "CRITICAL"
        elif score >= 7.0:
            return "HIGH"
        elif score >= 4.0:
            return "MEDIUM"
        elif score > 0:
            return "LOW"
        else:
            return "UNKNOWN"
    
    def get_device_vulnerabilities(self, device_id: int) -> List[Dict]:
        """Get all vulnerabilities for a device"""
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT c.cve_id, c.description, c.cvss_score, 
                       c.severity, c.published_date, dv.service
                FROM device_vulnerabilities dv
                JOIN cves c ON dv.cve_id = c.cve_id
                WHERE dv.device_id = ?
                ORDER BY c.cvss_score DESC
            ''', (device_id,))
            
            results = [dict(row) for row in cursor.fetchall()]
            conn.close()
            return results
            
        except Exception as e:
            logger.error(f"Error getting device vulnerabilities: {e}")
            return []
    
    def get_vulnerability_summary(self) -> Dict:
        """Get summary statistics of vulnerabilities"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Total CVEs
            cursor.execute('SELECT COUNT(*) FROM cves')
            total_cves = cursor.fetchone()[0]
            
            # By severity
            cursor.execute('''
                SELECT severity, COUNT(*) 
                FROM cves 
                GROUP BY severity
            ''')
            severity_counts = dict(cursor.fetchall())
            
            # Devices with vulnerabilities
            cursor.execute('''
                SELECT COUNT(DISTINCT device_id) 
                FROM device_vulnerabilities
            ''')
            affected_devices = cursor.fetchone()[0]
            
            conn.close()
            
            return {
                'total_cves': total_cves,
                'severity_counts': severity_counts,
                'affected_devices': affected_devices,
                'last_updated': datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error getting vulnerability summary: {e}")
            return {}
    
    def scan_device_services(self, device_id: int, services: List[Dict]):
        """
        Scan a device's services for vulnerabilities
        
        Args:
            device_id: Device ID in database
            services: List of {'service': 'http', 'port': 80} dicts
        """
        logger.info(f"🔍 Scanning device {device_id} services for CVEs...")
        
        all_cves = []
        for service_info in services:
            service_name = service_info.get('service', '')
            port = service_info.get('port', 0)
            
            if service_name and port:
                cves = self.get_cves_for_service(service_name, port)
                for cve in cves:
                    self.save_device_vulnerability(device_id, cve['cve_id'], f"{service_name}:{port}")
                    all_cves.append(cve)
        
        logger.info(f"✅ Found {len(all_cves)} total CVEs for device {device_id}")
        return all_cves


# ============================================================================
# QUICK TEST
# ============================================================================

if __name__ == "__main__":
    print("=" * 60)
    print("CVE INTEGRATION TEST")
    print("=" * 60)
    
    # Initialize service
    cve_service = CVEService()
    
    # Test query for common services
    test_services = [
        ('nginx', 80),
        ('openssh', 22),
        ('mysql', 3306),
        ('apache', 443),
    ]
    
    print("\n🔍 Testing CVE queries:")
    for service, port in test_services:
        print(f"\n--- {service}:{port} ---")
        cves = cve_service.get_cves_for_service(service, port)
        for cve in cves[:3]:  # Show top 3
            print(f"  - {cve['cve_id']}: CVSS {cve['cvss_score']} ({cve['severity']})")
    
    # Show summary
    print("\n" + "=" * 60)
    summary = cve_service.get_vulnerability_summary()
    print("📊 SUMMARY:")
    print(f"   Total CVEs in DB: {summary.get('total_cves', 0)}")
    print(f"   Severity distribution: {summary.get('severity_counts', {})}")
    print(f"   Affected devices: {summary.get('affected_devices', 0)}")
    print("=" * 60)