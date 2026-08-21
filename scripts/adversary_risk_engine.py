#!/usr/bin/env python3
"""
Adversary-Driven Risk Engine
Prioritizes vulnerabilities based on real-world threat intelligence
"""

import sqlite3
import json
from datetime import datetime
from typing import Dict, List, Any
import logging
from threat_intelligence import ThreatIntelligence

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class AdversaryRiskEngine:
    """
    Risk engine that prioritizes based on adversary behavior
    """
    
    def __init__(self, db_path="data/network_scanner.db"):
        self.db_path = db_path
        self.threat_intel = ThreatIntelligence(db_path)
    
    def assess_device_risk(self, device_id: int) -> Dict:
        """Assess device risk with adversary-driven prioritization"""
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute('SELECT * FROM devices WHERE id = ?', (device_id,))
            device = cursor.fetchone()
            
            if not device:
                return {'error': 'Device not found'}
            
            # Get vulnerabilities with threat intel and CVSS
            cursor.execute('''
                SELECT 
                    c.cve_id,
                    c.cvss_score,
                    c.severity,
                    c.description,
                    ti.kev_status,
                    ti.exploit_count,
                    ti.epss_score,
                    ti.epss_percentile,
                    COALESCE(ti.risk_score, 0) as threat_score,
                    COALESCE(ti.risk_level, 'LOW') as threat_level,
                    ti.priority
                FROM device_vulnerabilities dv
                JOIN cves c ON dv.cve_id = c.cve_id
                LEFT JOIN threat_intel ti ON c.cve_id = ti.cve_id
                WHERE dv.device_id = ?
                ORDER BY c.cvss_score DESC
            ''', (device_id,))
            
            vulns = [dict(row) for row in cursor.fetchall()]
            conn.close()
            
            # Calculate combined risk
            total_cvss = sum(v.get('cvss_score', 0) or 0 for v in vulns)
            avg_cvss = total_cvss / len(vulns) if vulns else 0
            
            total_threat_score = sum(v.get('threat_score', 0) or 0 for v in vulns)
            avg_threat_score = total_threat_score / len(vulns) if vulns else 0
            
            # Combined score (CVSS + Threat Intelligence)
            combined_score = (avg_cvss * 0.5) + (avg_threat_score / 10 * 0.5)
            
            # Count critical threats
            critical_threats = sum(1 for v in vulns if v.get('threat_level') == 'CRITICAL')
            high_threats = sum(1 for v in vulns if v.get('threat_level') == 'HIGH')
            critical_cvss = sum(1 for v in vulns if v.get('severity') == 'CRITICAL')
            high_cvss = sum(1 for v in vulns if v.get('severity') == 'HIGH')
            
            # Determine overall priority
            if critical_threats > 0 or critical_cvss > 0:
                priority = 'CRITICAL'
            elif high_threats > 2 or high_cvss > 2:
                priority = 'HIGH'
            elif high_threats > 0 or high_cvss > 0:
                priority = 'MEDIUM'
            else:
                priority = 'LOW'
            
            return {
                'device_id': device_id,
                'vulnerabilities': vulns,
                'total_vulns': len(vulns),
                'critical_threats': critical_threats,
                'high_threats': high_threats,
                'critical_cvss': critical_cvss,
                'high_cvss': high_cvss,
                'avg_cvss': avg_cvss,
                'avg_threat_score': avg_threat_score,
                'combined_score': combined_score,
                'priority': priority,
                'has_kev': any(v.get('kev_status') for v in vulns),
                'has_exploits': any(v.get('exploit_count', 0) > 0 for v in vulns)
            }
            
        except Exception as e:
            logger.error(f"Error assessing device risk: {e}")
            return {'error': str(e)}
    
    def get_priority_devices(self, limit: int = 10) -> List[Dict]:
        """Get devices ordered by adversary-driven risk priority using combined CVSS + Threat Intel"""
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            # Query combining CVSS and Threat Intelligence
            query = '''
                SELECT 
                    d.id,
                    d.ip_address,
                    d.hostname,
                    d.device_type,
                    COUNT(dv.id) as vuln_count,
                    SUM(CASE WHEN ti.kev_status = 1 THEN 1 ELSE 0 END) as kev_count,
                    SUM(CASE WHEN ti.exploit_count > 0 THEN 1 ELSE 0 END) as exploit_count,
                    AVG(c.cvss_score) as avg_cvss,
                    COALESCE(AVG(ti.risk_score), 0) as avg_threat_score,
                    MAX(CASE 
                        WHEN ti.risk_level = 'CRITICAL' OR c.severity = 'CRITICAL' THEN 'CRITICAL'
                        WHEN ti.risk_level = 'HIGH' OR c.severity = 'HIGH' THEN 'HIGH'
                        WHEN ti.risk_level = 'MEDIUM' OR c.severity = 'MEDIUM' THEN 'MEDIUM'
                        ELSE 'LOW'
                    END) as highest_priority
                FROM devices d
                LEFT JOIN device_vulnerabilities dv ON d.id = dv.device_id
                LEFT JOIN cves c ON dv.cve_id = c.cve_id
                LEFT JOIN threat_intel ti ON dv.cve_id = ti.cve_id
                GROUP BY d.id
                HAVING vuln_count > 0
                ORDER BY 
                    CASE MAX(CASE 
                        WHEN ti.risk_level = 'CRITICAL' OR c.severity = 'CRITICAL' THEN 'CRITICAL'
                        WHEN ti.risk_level = 'HIGH' OR c.severity = 'HIGH' THEN 'HIGH'
                        WHEN ti.risk_level = 'MEDIUM' OR c.severity = 'MEDIUM' THEN 'MEDIUM'
                        ELSE 'LOW'
                    END)
                        WHEN 'CRITICAL' THEN 1
                        WHEN 'HIGH' THEN 2
                        WHEN 'MEDIUM' THEN 3
                        WHEN 'LOW' THEN 4
                    END,
                    AVG(c.cvss_score) DESC NULLS LAST
                LIMIT ?
            '''
            
            cursor.execute(query, (limit,))
            devices = [dict(row) for row in cursor.fetchall()]
            conn.close()
            return devices
            
        except Exception as e:
            logger.error(f"Error getting priority devices: {e}")
            return []
    
    def generate_priority_report(self) -> Dict:
        """Generate a report of adversary-driven priorities"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Get all devices with their vulnerabilities and threat intel
            cursor.execute('''
                SELECT 
                    d.id,
                    d.ip_address,
                    COUNT(dv.id) as vuln_count,
                    SUM(CASE WHEN ti.kev_status = 1 THEN 1 ELSE 0 END) as kev_count,
                    SUM(CASE WHEN ti.exploit_count > 0 THEN 1 ELSE 0 END) as exploit_count,
                    COUNT(DISTINCT CASE 
                        WHEN ti.risk_level = 'CRITICAL' OR c.severity = 'CRITICAL' 
                        THEN dv.cve_id END) as critical_threats,
                    COUNT(DISTINCT CASE 
                        WHEN ti.risk_level = 'HIGH' OR c.severity = 'HIGH' 
                        THEN dv.cve_id END) as high_threats,
                    COUNT(DISTINCT CASE 
                        WHEN ti.risk_level = 'MEDIUM' OR c.severity = 'MEDIUM' 
                        THEN dv.cve_id END) as medium_threats
                FROM devices d
                LEFT JOIN device_vulnerabilities dv ON d.id = dv.device_id
                LEFT JOIN cves c ON dv.cve_id = c.cve_id
                LEFT JOIN threat_intel ti ON dv.cve_id = ti.cve_id
                GROUP BY d.id
            ''')
            
            device_risks = cursor.fetchall()
            
            # Statistics
            total_devices = len(device_risks)
            vulnerable_devices = sum(1 for d in device_risks if d[2] > 0)
            kev_devices = sum(1 for d in device_risks if d[3] > 0)
            kev_cves = sum(d[3] for d in device_risks)
            
            # Priority distribution
            critical_devices = sum(1 for d in device_risks if d[5] > 0)  # critical_threats
            high_devices = sum(1 for d in device_risks if d[6] > 0)      # high_threats
            medium_devices = sum(1 for d in device_risks if d[7] > 0)    # medium_threats
            
            # Build priority distribution
            priority_dist = []
            if critical_devices > 0:
                priority_dist.append({
                    'priority': 'CRITICAL',
                    'device_count': critical_devices,
                    'cve_count': sum(d[5] for d in device_risks)
                })
            if high_devices > 0:
                priority_dist.append({
                    'priority': 'HIGH',
                    'device_count': high_devices,
                    'cve_count': sum(d[6] for d in device_risks)
                })
            if medium_devices > 0:
                priority_dist.append({
                    'priority': 'MEDIUM',
                    'device_count': medium_devices,
                    'cve_count': sum(d[7] for d in device_risks)
                })
            
            # Add LOW if there are vulnerable devices not in higher categories
            low_devices = vulnerable_devices - critical_devices - high_devices - medium_devices
            if low_devices > 0:
                priority_dist.append({
                    'priority': 'LOW',
                    'device_count': low_devices,
                    'cve_count': 0
                })
            
            conn.close()
            
            return {
                'statistics': {
                    'total_devices': total_devices,
                    'vulnerable_devices': vulnerable_devices,
                    'kev_devices': kev_devices,
                    'kev_cves': kev_cves
                },
                'priority_distribution': priority_dist,
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error generating priority report: {e}")
            return {'error': str(e)}
    
    def get_attack_chain_risk(self, device_id: int) -> Dict:
        """Analyze attack chain risk - how this device can be used to compromise others"""
        result = {
            'device_id': device_id,
            'lateral_movement_risk': 'MEDIUM',
            'potential_targets': [],
            'blast_radius': 0,
            'recommendations': []
        }
        
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Check for vulnerabilities that enable lateral movement
            cursor.execute('''
                SELECT c.cve_id, c.description
                FROM device_vulnerabilities dv
                JOIN cves c ON dv.cve_id = c.cve_id
                WHERE dv.device_id = ?
                AND (
                    c.description LIKE '%lateral%' OR
                    c.description LIKE '%movement%' OR
                    c.description LIKE '%remote code%' OR
                    c.description LIKE '%RCE%' OR
                    c.description LIKE '%privilege%'
                )
            ''', (device_id,))
            
            lateral_vulns = cursor.fetchall()
            
            if lateral_vulns:
                result['lateral_movement_risk'] = 'HIGH'
                result['recommendations'] = [
                    'Isolate this device from critical systems',
                    'Apply patches for lateral movement vulnerabilities',
                    'Monitor network traffic for suspicious connections'
                ]
                result['blast_radius'] = len(lateral_vulns)
            
            conn.close()
            
        except Exception as e:
            logger.error(f"Error analyzing attack chain: {e}")
        
        return result


# ============================================================================
# QUICK TEST
# ============================================================================

if __name__ == "__main__":
    print("=" * 60)
    print("🎯 Adversary-Driven Risk Engine Test")
    print("=" * 60)
    
    engine = AdversaryRiskEngine()
    
    # Get priority devices
    print("\n📊 Priority Devices:")
    print("-" * 60)
    
    devices = engine.get_priority_devices(10)
    
    if devices:
        for device in devices:
            vuln_count = device.get('vuln_count', 0)
            kev_count = device.get('kev_count', 0)
            priority = device.get('highest_priority', 'LOW')
            avg_cvss = device.get('avg_cvss', 0) or 0
            threat_score = device.get('avg_threat_score', 0) or 0
            
            priority_emoji = {
                'CRITICAL': '🔴',
                'HIGH': '🟠',
                'MEDIUM': '🟡',
                'LOW': '🟢',
                'UNKNOWN': '⚪'
            }.get(priority, '⚪')
            
            print(f"   {priority_emoji} {device.get('ip_address', ''):<15} "
                  f"{device.get('device_type', 'Unknown'):<12} "
                  f"Vulns: {vuln_count:<3} "
                  f"KEV: {kev_count}  "
                  f"CVSS: {avg_cvss:.1f}  "
                  f"Score: {threat_score:.1f}  "
                  f"Priority: {priority}")
    else:
        print("   No devices with vulnerabilities found")
    
    # Generate report
    print("\n📊 Priority Report:")
    print("-" * 60)
    report = engine.generate_priority_report()
    
    if 'error' not in report:
        stats = report.get('statistics', {})
        print(f"   Total devices: {stats.get('total_devices', 0)}")
        print(f"   Vulnerable devices: {stats.get('vulnerable_devices', 0)}")
        print(f"   Devices with KEV vulnerabilities: {stats.get('kev_devices', 0)}")
        print(f"   Priority distribution:")
        
        priority_dist = report.get('priority_distribution', [])
        if priority_dist:
            for priority in priority_dist:
                print(f"      {priority['priority']}: {priority.get('device_count', 0)} devices, {priority.get('cve_count', 0)} CVEs")
        else:
            print("      No vulnerabilities found")
    
    print("\n" + "=" * 60)