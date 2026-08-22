"""
AI Recommendations Engine - Intelligent Security Recommendations
Uses ML model and vulnerability data to provide actionable insights
"""

import sqlite3
import json
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
import logging
import joblib
from pathlib import Path

logger = logging.getLogger(__name__)

class AIRecommendations:
    """Generate intelligent security recommendations using ML and data analysis"""
    
    def __init__(self, db_path="data/network_scanner.db", model_path=None):
        self.db_path = db_path
        self.model = None
        self.scaler = None
        self.label_encoder = None
        
        # Load ML model if available
        if model_path:
            self.load_model(model_path)
        else:
            # Try to find latest model
            self._find_latest_model()
        
        self.init_db()
    
    def _find_latest_model(self):
        """Find the latest trained model"""
        model_dir = Path("data/models")
        if model_dir.exists():
            models = sorted(model_dir.glob("device_classifier_*.pkl"))
            if models:
                self.load_model(str(models[-1]))
                logger.info(f"Loaded latest model: {models[-1].name}")
    
    def load_model(self, model_path: str):
        """Load the ML model"""
        try:
            data = joblib.load(model_path)
            self.model = data.get('model')
            self.scaler = data.get('scaler')
            self.label_encoder = data.get('label_encoder')
            self.feature_names = data.get('feature_names', [])
            logger.info(f"✅ ML model loaded from {model_path}")
        except Exception as e:
            logger.error(f"Error loading model: {e}")
    
    def init_db(self):
        """Initialize recommendations table"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS recommendations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    device_id INTEGER,
                    recommendation_type TEXT,
                    priority TEXT,
                    title TEXT,
                    description TEXT,
                    action TEXT,
                    created_date TEXT,
                    status TEXT DEFAULT 'pending',
                    FOREIGN KEY (device_id) REFERENCES devices (id)
                )
            ''')
            
            conn.commit()
            conn.close()
            logger.info("✅ Recommendations database initialized")
            
        except Exception as e:
            logger.error(f"Error initializing recommendations DB: {e}")
    
    def generate_all_recommendations(self) -> Dict:
        """Generate comprehensive recommendations for all devices"""
        logger.info("Generating AI recommendations for all devices...")
        
        results = {
            'critical': [],
            'high': [],
            'medium': [],
            'low': [],
            'summary': {}
        }
        
        # Get all devices
        devices = self._get_devices()
        
        if not devices:
            return {'error': 'No devices found'}
        
        for device in devices:
            device_id = device['id']
            
            # Get device vulnerabilities
            vulns = self._get_device_vulnerabilities(device_id)
            
            # Generate recommendations based on device data
            recs = self._generate_device_recommendations(device, vulns)
            
            # Categorize recommendations
            for rec in recs:
                if rec['priority'] == 'critical':
                    results['critical'].append(rec)
                elif rec['priority'] == 'high':
                    results['high'].append(rec)
                elif rec['priority'] == 'medium':
                    results['medium'].append(rec)
                else:
                    results['low'].append(rec)
                
                # Save to database
                self._save_recommendation(device_id, rec)
        
        # Generate summary
        results['summary'] = {
            'total_recommendations': len(results['critical']) + len(results['high']) + 
                                     len(results['medium']) + len(results['low']),
            'critical_count': len(results['critical']),
            'high_count': len(results['high']),
            'medium_count': len(results['medium']),
            'low_count': len(results['low']),
            'devices_analyzed': len(devices),
            'timestamp': datetime.now().isoformat()
        }
        
        logger.info(f"✅ Generated {results['summary']['total_recommendations']} recommendations")
        return results
    
    def _get_devices(self) -> List[Dict]:
        """Get all devices with their data"""
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT d.*, 
                       r.risk_score, r.risk_level, r.total_cves,
                       r.critical_cves, r.high_cves, r.recommendations as existing_rec
                FROM devices d
                LEFT JOIN device_risks r ON d.id = r.device_id
                ORDER BY r.risk_score DESC
            ''')
            
            devices = [dict(row) for row in cursor.fetchall()]
            conn.close()
            return devices
            
        except Exception as e:
            logger.error(f"Error getting devices: {e}")
            return []
    
    def _get_device_vulnerabilities(self, device_id: int) -> List[Dict]:
        """Get vulnerabilities for a specific device"""
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
            
            vulns = [dict(row) for row in cursor.fetchall()]
            conn.close()
            return vulns
            
        except Exception as e:
            logger.error(f"Error getting vulnerabilities for device {device_id}: {e}")
            return []
    
    def _safe_int(self, value, default=0):
        """Convert value to int, return default if None or non-convertible"""
        if value is None:
            return default
        try:
            return int(value)
        except (ValueError, TypeError):
            return default
    
    def _safe_float(self, value, default=0.0):
        """Convert value to float, return default if None or non-convertible"""
        if value is None:
            return default
        try:
            return float(value)
        except (ValueError, TypeError):
            return default
    
    def _generate_device_recommendations(self, device: Dict, vulns: List[Dict]) -> List[Dict]:
        """Generate real-world, actionable recommendations for a single device"""
        recommendations = []
        
        # Safely extract numeric values
        risk_score = self._safe_float(device.get('risk_score'), 0.0)
        total_cves = self._safe_int(device.get('total_cves'), 0)
        critical_cves = self._safe_int(device.get('critical_cves'), 0)
        high_cves = self._safe_int(device.get('high_cves'), 0)
        risk_level = device.get('risk_level', 'NONE')
        device_type = device.get('device_type', 'Unknown')
        os_name = device.get('os', '').lower()
        ip = device.get('ip_address', '')
        hostname = device.get('hostname', '')
        
        # Parse open ports and services
        open_ports = []
        services_list = []
        try:
            ports_json = device.get('open_ports', '[]')
            if ports_json:
                open_ports = json.loads(ports_json) if isinstance(ports_json, str) else ports_json
            services_json = device.get('services', '[]')
            if services_json:
                services_list = json.loads(services_json) if isinstance(services_json, str) else services_json
        except:
            pass
        
        # Ensure we have lists
        open_ports = list(set(open_ports))  # unique
        service_names = [s.get('service', '').lower() for s in services_list if isinstance(s, dict)]
        
        # ====================================================================
        # CRITICAL RECOMMENDATIONS
        # ====================================================================
        
        # 1. Critical CVEs
        if critical_cves > 0:
            cve_ids = [v['cve_id'] for v in vulns if v.get('severity') == 'CRITICAL'][:5]
            cve_str = ', '.join(cve_ids[:3])
            recommendations.append({
                'priority': 'critical',
                'title': f'🔴 {critical_cves} Critical Vulnerabilities on {hostname or ip}',
                'description': f'Device has {critical_cves} critical CVEs (e.g., {cve_str}). These require immediate patching or isolation.',
                'action': f'Apply vendor patches for {cve_str}. If no patch is available, consider network isolation or additional security controls.',
                'type': 'vulnerability'
            })
        
        # 2. Very high risk score
        if risk_score >= 9.0:
            recommendations.append({
                'priority': 'critical',
                'title': f'🚨 Extremely High Risk (Score {risk_score:.1f}/10)',
                'description': f'Device {hostname or ip} has a risk score of {risk_score:.1f} - this is in the highest risk band.',
                'action': 'Immediate incident response: isolate device, conduct forensic analysis, and implement emergency patching.',
                'type': 'risk'
            })
        
        # 3. Specific dangerous services exposed
        dangerous_services = {
            'smb': 'SMB (port 445) is often targeted by ransomware (e.g., EternalBlue).',
            'rdp': 'RDP (port 3389) is a common attack vector for brute-force and credential theft.',
            'telnet': 'Telnet transmits credentials in plaintext; extremely insecure.',
            'ftp': 'FTP is unencrypted; use SFTP or FTPS instead.',
            'snmp': 'SNMP can leak device information and is often misconfigured with default credentials.',
            'nfs': 'NFS may expose sensitive file shares without proper authentication.'
        }
        for service_name in dangerous_services:
            if service_name in service_names or any(p == port for port in open_ports if port in [445, 3389, 23, 21, 161, 2049]):
                if service_name == 'smb' and 445 in open_ports:
                    recommendations.append({
                        'priority': 'critical',
                        'title': f'⚠️ SMB Service Exposed (Port 445)',
                        'description': f'SMB is exposed on {hostname or ip}. This service is frequently used in ransomware attacks.',
                        'action': 'Disable SMBv1, apply MS17-010 patch, restrict SMB access to trusted subnets, and enforce SMB signing.',
                        'type': 'hardening'
                    })
                elif service_name == 'rdp' and 3389 in open_ports:
                    recommendations.append({
                        'priority': 'critical',
                        'title': f'🔑 RDP Service Exposed (Port 3389)',
                        'description': f'RDP is open on {hostname or ip}. RDP attacks (brute-force, BlueKeep) are common.',
                        'action': 'Use a VPN/RDG gateway, enable Network Level Authentication (NLA), enforce strong passwords, and enable account lockout.',
                        'type': 'hardening'
                    })
                elif service_name == 'telnet':
                    recommendations.append({
                        'priority': 'critical',
                        'title': f'🚫 Telnet Enabled (Insecure)',
                        'description': 'Telnet transmits credentials in plaintext and is vulnerable to interception.',
                        'action': 'Immediately disable Telnet and replace with SSH. Use SSH with key-based authentication.',
                        'type': 'hardening'
                    })
                break  # only one critical service recommendation
        
        # ====================================================================
        # HIGH RECOMMENDATIONS
        # ====================================================================
        
        # 4. High CVEs
        if high_cves > 0:
            high_cve_ids = [v['cve_id'] for v in vulns if v.get('severity') == 'HIGH'][:3]
            rec = {
                'priority': 'high',
                'title': f'🟠 {high_cves} High-Severity Vulnerabilities',
                'description': f'Device has {high_cves} high CVEs (e.g., {", ".join(high_cve_ids)}). These should be patched soon.',
                'action': f'Apply patches for {", ".join(high_cve_ids)}. Test in staging before production.',
                'type': 'vulnerability'
            }
            recommendations.append(rec)
        
        # 5. Outdated OS / EOL
        eol_indicators = ['windows 7', 'windows 8', 'ubuntu 16', 'centos 6', 'debian 8', 'rhel 6']
        if any(indicator in os_name for indicator in eol_indicators):
            recommendations.append({
                'priority': 'high',
                'title': '🔄 End-of-Life Operating System Detected',
                'description': f'{hostname or ip} is running {device["os"]}, which is no longer supported with security updates.',
                'action': f'Plan migration to a supported OS (e.g., Windows Server 2022, Ubuntu 22.04, RHEL 9). Schedule within 60 days.',
                'type': 'os'
            })
        
        # 6. Server with many vulnerabilities
        if device_type == 'Server' and total_cves > 8:
            recommendations.append({
                'priority': 'high',
                'title': '🖥️ Server Security Hardening Needed',
                'description': f'Server {hostname or ip} has {total_cves} vulnerabilities. Servers are prime targets.',
                'action': 'Implement server hardening benchmarks (CIS, DISA STIG). Review firewall rules, disable unused services, and enforce least privilege.',
                'type': 'hardening'
            })
        
        # 7. Excessive open ports (high attack surface)
        if len(open_ports) > 15:
            recommendations.append({
                'priority': 'high',
                'title': '🔌 Excessive Open Ports (Attack Surface)',
                'description': f'Device has {len(open_ports)} open ports, increasing potential entry points.',
                'action': f'Review and close unnecessary ports. Use firewall to restrict access to only required services. Current open ports: {", ".join(map(str, open_ports[:10]))}...',
                'type': 'network'
            })
        
        # 8. Weak or no hostname (asset management issue)
        if not hostname or hostname == '':
            recommendations.append({
                'priority': 'high',
                'title': '🏷️ Missing Hostname',
                'description': f'Device {ip} lacks a proper hostname, making management and incident response difficult.',
                'action': 'Assign a descriptive hostname (e.g., SRV-DB01, USR-LAPTOP-01) in DNS and local host file.',
                'type': 'best_practice'
            })
        
        # ====================================================================
        # MEDIUM RECOMMENDATIONS
        # ====================================================================
        
        # 9. Medium/low vulnerabilities (if no critical/high)
        if total_cves > 0 and critical_cves == 0 and high_cves == 0:
            rec = {
                'priority': 'medium',
                'title': f'📋 {total_cves} Medium/Low Vulnerabilities',
                'description': 'Device has manageable vulnerabilities that should be addressed in routine maintenance.',
                'action': 'Apply available security patches. Review risk acceptance policy for low severity issues.',
                'type': 'vulnerability'
            }
            recommendations.append(rec)
        
        # 10. IoT device
        if device_type == 'IoT':
            recommendations.append({
                'priority': 'medium',
                'title': '📡 IoT Device Security Review',
                'description': f'IoT device {hostname or ip} may have limited security capabilities and firmware update challenges.',
                'action': 'Check for firmware updates. Isolate IoT devices in a separate VLAN. Disable UPnP, Telnet, and default credentials.',
                'type': 'iot'
            })
        
        # 11. Open SSH with weak configuration
        if 22 in open_ports and 'ssh' in service_names:
            recommendations.append({
                'priority': 'medium',
                'title': '🔑 SSH Server Configuration',
                'description': f'SSH is open on {hostname or ip}. Ensure secure configuration.',
                'action': 'Disable root login, enforce key-based authentication, change default port (optional), and set LoginGraceTime to 30s.',
                'type': 'hardening'
            })
        
        # 12. Web services (HTTP/HTTPS) open
        web_ports = [80, 443, 8080, 8443]
        if any(p in open_ports for p in web_ports):
            recommendations.append({
                'priority': 'medium',
                'title': '🌐 Web Service Exposure',
                'description': f'Web services are running on {hostname or ip}. Ensure they are up-to-date and secure.',
                'action': 'Apply web server patches, enable HTTPS with strong TLS, configure security headers (HSTS, CSP), and use WAF if applicable.',
                'type': 'network'
            })
        
        # 13. No recent scan (stale data)
        last_seen = device.get('last_seen')
        if last_seen:
            try:
                last_seen_dt = datetime.fromisoformat(last_seen.replace('Z', '+00:00'))
                if (datetime.now() - last_seen_dt).days > 30:
                    recommendations.append({
                        'priority': 'medium',
                        'title': '🕒 Device Not Scanned Recently',
                        'description': f'Last scan for {hostname or ip} was more than 30 days ago.',
                        'action': 'Schedule a new network scan to refresh vulnerability data and device inventory.',
                        'type': 'monitoring'
                    })
            except:
                pass
        
        # ====================================================================
        # LOW RECOMMENDATIONS (Best Practices)
        # ====================================================================
        
        # 14. Best practice: regular scanning
        if total_cves == 0:
            recommendations.append({
                'priority': 'low',
                'title': '✅ Device Appears Secure - Continue Monitoring',
                'description': f'No vulnerabilities found on {hostname or ip}. Keep monitoring.',
                'action': 'Maintain regular scanning schedule (e.g., weekly). Review security policies quarterly.',
                'type': 'monitoring'
            })
        
        # 15. Windows Workstation specific
        if 'windows' in os_name and device_type != 'Server':
            recommendations.append({
                'priority': 'low',
                'title': '💻 Windows Workstation Best Practices',
                'description': f'Ensure Windows workstation {hostname or ip} is properly configured.',
                'action': 'Verify Windows Update settings, enable Windows Defender, enable BitLocker, and enforce LAPS for local admin passwords.',
                'type': 'best_practice'
            })
        
        # 16. Router/Switch
        if device_type == 'Router':
            recommendations.append({
                'priority': 'low',
                'title': '🌐 Network Device Security',
                'description': f'Router {hostname or ip} should have secure management and up-to-date firmware.',
                'action': 'Disable telnet, enable SSH, enforce ACLs, update firmware, and use SNMPv3 with strong community strings.',
                'type': 'network'
            })
        
        # 17. Printer / Multi-function device
        if 'printer' in device_type.lower():
            recommendations.append({
                'priority': 'low',
                'title': '🖨️ Printer Security',
                'description': 'Printers can be entry points. Ensure secure configuration.',
                'action': 'Disable unnecessary protocols (FTP, Telnet). Enable secure printing (IPSec). Keep firmware updated.',
                'type': 'hardening'
            })
        
        # 18. No firewall recommendation if not detected
        # (We can't detect firewall, but we can recommend enabling it)
        recommendations.append({
            'priority': 'low',
            'title': '🛡️ Enable Host Firewall',
            'description': f'Ensure host-based firewall is enabled on {hostname or ip} to limit inbound traffic.',
            'action': 'Enable Windows Firewall or iptables/nftables. Configure default deny inbound, allow outbound.',
            'type': 'best_practice'
        })
        
        # Remove duplicates based on title (keep first occurrence)
        seen_titles = set()
        unique_recs = []
        for rec in recommendations:
            if rec['title'] not in seen_titles:
                seen_titles.add(rec['title'])
                unique_recs.append(rec)
        
        # Limit to max 8 recommendations per device to avoid spam
        return unique_recs[:8]
    
    def _save_recommendation(self, device_id: int, rec: Dict):
        """Save recommendation to database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO recommendations 
                (device_id, recommendation_type, priority, title, description, action, created_date, status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                device_id,
                rec.get('type', 'general'),
                rec['priority'],
                rec['title'],
                rec['description'],
                rec['action'],
                datetime.now().isoformat(),
                'pending'
            ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"Error saving recommendation: {e}")
    
    def get_device_recommendations(self, device_id: int) -> List[Dict]:
        """Get recommendations for a specific device"""
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT * FROM recommendations
                WHERE device_id = ?
                ORDER BY 
                    CASE priority 
                        WHEN 'critical' THEN 1 
                        WHEN 'high' THEN 2 
                        WHEN 'medium' THEN 3 
                        WHEN 'low' THEN 4 
                    END
            ''', (device_id,))
            
            recs = [dict(row) for row in cursor.fetchall()]
            conn.close()
            return recs
            
        except Exception as e:
            logger.error(f"Error getting recommendations: {e}")
            return []
    
    def get_all_recommendations(self) -> List[Dict]:
        """Get all recommendations"""
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT r.*, d.ip_address, d.device_type
                FROM recommendations r
                JOIN devices d ON r.device_id = d.id
                ORDER BY 
                    CASE priority 
                        WHEN 'critical' THEN 1 
                        WHEN 'high' THEN 2 
                        WHEN 'medium' THEN 3 
                        WHEN 'low' THEN 4 
                    END,
                    r.created_date DESC
            ''')
            
            recs = [dict(row) for row in cursor.fetchall()]
            conn.close()
            return recs
            
        except Exception as e:
            logger.error(f"Error getting all recommendations: {e}")
            return []
    
    def update_recommendation_status(self, rec_id: int, status: str):
        """Update recommendation status (pending, in_progress, done, dismissed)"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                UPDATE recommendations 
                SET status = ? 
                WHERE id = ?
            ''', (status, rec_id))
            
            conn.commit()
            conn.close()
            return {'success': True}
            
        except Exception as e:
            logger.error(f"Error updating recommendation status: {e}")
            return {'success': False, 'error': str(e)}
    
    def get_recommendation_summary(self) -> Dict:
        """Get summary statistics for recommendations"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Total recommendations by priority
            cursor.execute('''
                SELECT priority, COUNT(*) as count
                FROM recommendations
                GROUP BY priority
            ''')
            priority_counts = dict(cursor.fetchall())
            
            # Total recommendations by status
            cursor.execute('''
                SELECT status, COUNT(*) as count
                FROM recommendations
                GROUP BY status
            ''')
            status_counts = dict(cursor.fetchall())
            
            # Most common recommendation types
            cursor.execute('''
                SELECT recommendation_type, COUNT(*) as count
                FROM recommendations
                GROUP BY recommendation_type
                ORDER BY count DESC
                LIMIT 5
            ''')
            type_counts = dict(cursor.fetchall())
            
            conn.close()
            
            return {
                'priority_counts': priority_counts,
                'status_counts': status_counts,
                'type_counts': type_counts,
                'total': sum(priority_counts.values()),
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error getting recommendation summary: {e}")
            return {}


# ============================================================================
# QUICK TEST
# ============================================================================

if __name__ == "__main__":
    print("=" * 60)
    print("🤖 AI RECOMMENDATIONS ENGINE TEST")
    print("=" * 60)
    
    # Initialize
    ai = AIRecommendations()
    
    # Generate recommendations
    results = ai.generate_all_recommendations()
    
    if 'error' in results:
        print(f"❌ Error: {results['error']}")
    else:
        print("\n📊 Summary:")
        summary = results['summary']
        print(f"   Devices Analyzed: {summary['devices_analyzed']}")
        print(f"   Total Recommendations: {summary['total_recommendations']}")
        print(f"   Critical: {summary['critical_count']}")
        print(f"   High: {summary['high_count']}")
        print(f"   Medium: {summary['medium_count']}")
        print(f"   Low: {summary['low_count']}")
        
        print("\n🔴 Top Critical Recommendations:")
        for rec in results['critical'][:3]:
            print(f"   - {rec['title']}")
            print(f"     {rec['description'][:100]}...")
            print(f"     Action: {rec['action'][:100]}...")
            print()
    
    print("\n" + "=" * 60)