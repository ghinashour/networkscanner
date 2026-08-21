"""
Risk Engine - Calculate and prioritize device risks
"""

import sqlite3
import json
from datetime import datetime
from typing import Dict, List, Any, Optional
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class RiskEngine:
    def __init__(self, db_path="data/network_scanner.db"):
        self.db_path = db_path
        self.init_db()
    
    def init_db(self):
        """Initialize risk tables"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS device_risks (
                    device_id INTEGER PRIMARY KEY,
                    risk_score REAL,
                    risk_level TEXT,
                    total_cves INTEGER,
                    critical_cves INTEGER,
                    high_cves INTEGER,
                    medium_cves INTEGER,
                    low_cves INTEGER,
                    last_scanned TEXT,
                    recommendations TEXT,
                    FOREIGN KEY (device_id) REFERENCES devices (id)
                )
            ''')
            
            conn.commit()
            conn.close()
            logger.info("✅ Risk engine database initialized")
            
        except Exception as e:
            logger.error(f"❌ Risk engine initialization error: {e}")
            raise
    
    def calculate_risk_score(self, device_id: int) -> Dict:
        """
        Calculate comprehensive risk score for a device
        
        Returns:
            Dictionary with risk metrics
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Get device info
            cursor.execute('SELECT ip_address, device_type FROM devices WHERE id = ?', (device_id,))
            device = cursor.fetchone()
            
            if not device:
                logger.warning(f"Device {device_id} not found")
                return {'error': 'Device not found'}
            
            # Get CVEs for this device
            cursor.execute('''
                SELECT c.cvss_score, c.severity, c.cve_id
                FROM device_vulnerabilities dv
                JOIN cves c ON dv.cve_id = c.cve_id
                WHERE dv.device_id = ?
            ''', (device_id,))
            
            cves = cursor.fetchall()
            conn.close()
            
            if not cves:
                result = {
                    'device_id': device_id,
                    'ip_address': device[0],
                    'device_type': device[1],
                    'risk_score': 0,
                    'risk_level': 'LOW',
                    'total_cves': 0,
                    'critical_cves': 0,
                    'high_cves': 0,
                    'medium_cves': 0,
                    'low_cves': 0,
                    'recommendations': 'No vulnerabilities found',
                    'last_scanned': datetime.now().isoformat()
                }
                self._save_risk_score(device_id, result)
                return result
            
            # Count by severity
            severity_counts = {
                'CRITICAL': 0,
                'HIGH': 0,
                'MEDIUM': 0,
                'LOW': 0
            }
            
            total_score = 0
            critical_cves_list = []
            
            for cvss_score, severity, cve_id in cves:
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
                total_score += cvss_score
                if severity in ['CRITICAL', 'HIGH']:
                    critical_cves_list.append(cve_id)
            
            # Calculate risk score (0-10)
            avg_score = total_score / len(cves) if cves else 0
            
            # Weighted multiplier based on severity
            severity_multiplier = 1.0
            if severity_counts['CRITICAL'] > 2:
                severity_multiplier = 2.0
            elif severity_counts['CRITICAL'] > 0:
                severity_multiplier = 1.7
            elif severity_counts['HIGH'] > 3:
                severity_multiplier = 1.4
            elif severity_counts['HIGH'] > 0:
                severity_multiplier = 1.1
            
            risk_score = min(10, (avg_score * severity_multiplier) * 0.8 + 
                                   min(3, (len(cves) * 0.1)))
            
            # Determine risk level
            if risk_score >= 8.0:
                risk_level = 'CRITICAL'
                recommendation = 'Immediate action required! Patch or isolate this device.'
            elif risk_score >= 6.0:
                risk_level = 'HIGH'
                recommendation = 'High risk - prioritize patching and monitoring.'
            elif risk_score >= 3.0:
                risk_level = 'MEDIUM'
                recommendation = 'Medium risk - schedule remediation in next maintenance window.'
            else:
                risk_level = 'LOW'
                recommendation = 'Low risk - continue normal monitoring.'
            
            # Device-specific recommendations
            if device[1] == 'Server':
                recommendation += ' Server devices require stricter security controls.'
            elif device[1] == 'IoT':
                recommendation += ' IoT devices often have limited update capabilities. Consider network segmentation.'
            
            result = {
                'device_id': device_id,
                'ip_address': device[0],
                'device_type': device[1],
                'risk_score': round(risk_score, 2),
                'risk_level': risk_level,
                'total_cves': len(cves),
                'critical_cves': severity_counts['CRITICAL'],
                'high_cves': severity_counts['HIGH'],
                'medium_cves': severity_counts['MEDIUM'],
                'low_cves': severity_counts['LOW'],
                'recommendations': recommendation,
                'last_scanned': datetime.now().isoformat()
            }
            
            # Save to database
            self._save_risk_score(device_id, result)
            
            return result
            
        except Exception as e:
            logger.error(f"Error calculating risk score: {e}")
            return {'error': str(e)}
    
    def _save_risk_score(self, device_id: int, risk_data: Dict):
        """Save risk score to database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT OR REPLACE INTO device_risks 
                (device_id, risk_score, risk_level, total_cves, 
                 critical_cves, high_cves, medium_cves, low_cves, 
                 last_scanned, recommendations)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                device_id,
                risk_data['risk_score'],
                risk_data['risk_level'],
                risk_data['total_cves'],
                risk_data['critical_cves'],
                risk_data['high_cves'],
                risk_data['medium_cves'],
                risk_data['low_cves'],
                risk_data['last_scanned'],
                risk_data.get('recommendations', '')
            ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"Error saving risk score: {e}")
    
    def get_device_risk(self, device_id: int) -> Optional[Dict]:
        """Get risk score for a specific device"""
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT * FROM device_risks WHERE device_id = ?
            ''', (device_id,))
            
            result = cursor.fetchone()
            conn.close()
            
            return dict(result) if result else None
            
        except Exception as e:
            logger.error(f"Error getting device risk: {e}")
            return None
    
    def get_risk_summary(self) -> Dict:
        """Get risk summary statistics"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Total devices
            cursor.execute('SELECT COUNT(*) FROM devices')
            total_devices = cursor.fetchone()[0]
            
            # Devices with risks
            cursor.execute('SELECT COUNT(*) FROM device_risks')
            assessed_devices = cursor.fetchone()[0]
            
            # Risk level distribution
            cursor.execute('''
                SELECT risk_level, COUNT(*) 
                FROM device_risks 
                GROUP BY risk_level
            ''')
            
            risk_counts = dict(cursor.fetchall())
            
            # Average risk score
            cursor.execute('SELECT AVG(risk_score) FROM device_risks')
            avg_risk = cursor.fetchone()[0] or 0
            
            # Critical vulnerabilities
            cursor.execute('''
                SELECT SUM(critical_cves) FROM device_risks
            ''')
            critical_vulns = cursor.fetchone()[0] or 0
            
            conn.close()
            
            return {
                'total_devices': total_devices,
                'assessed_devices': assessed_devices,
                'risk_counts': risk_counts,
                'average_risk_score': round(avg_risk, 2),
                'critical_vulnerabilities': critical_vulns,
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error getting risk summary: {e}")
            return {}
    
    def get_high_risk_devices(self, limit: int = 10) -> List[Dict]:
        """Get devices with highest risk scores"""
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT d.ip_address, d.device_type, 
                       r.risk_score, r.risk_level, r.total_cves,
                       r.critical_cves, r.high_cves, r.recommendations
                FROM devices d
                JOIN device_risks r ON d.id = r.device_id
                WHERE r.risk_score > 0
                ORDER BY r.risk_score DESC
                LIMIT ?
            ''', (limit,))
            
            results = [dict(row) for row in cursor.fetchall()]
            conn.close()
            return results
            
        except Exception as e:
            logger.error(f"Error getting high risk devices: {e}")
            return []


# ============================================================================
# QUICK TEST
# ============================================================================

if __name__ == "__main__":
    print("=" * 60)
    print("RISK ENGINE TEST")
    print("=" * 60)
    
    # Initialize risk engine
    risk_engine = RiskEngine()
    
    # Get summary
    print("\n📊 Risk Summary:")
    summary = risk_engine.get_risk_summary()
    print(f"   Total devices: {summary.get('total_devices', 0)}")
    print(f"   Assessed devices: {summary.get('assessed_devices', 0)}")
    print(f"   Average risk score: {summary.get('average_risk_score', 0)}")
    print(f"   Risk distribution: {summary.get('risk_counts', {})}")
    
    # Get high risk devices
    print("\n🔴 High Risk Devices:")
    high_risk = risk_engine.get_high_risk_devices(5)
    if high_risk:
        for device in high_risk:
            print(f"   {device['ip_address']} ({device['device_type']})")
            print(f"      Risk: {device['risk_score']} ({device['risk_level']})")
            print(f"      CVEs: {device['total_cves']} (Critical: {device['critical_cves']})")
            print(f"      Recommendation: {device['recommendations'][:100]}...")
    else:
        print("   No devices with risks found")
    
    print("\n" + "=" * 60)