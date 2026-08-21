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
    
    def _generate_device_recommendations(self, device: Dict, vulns: List[Dict]) -> List[Dict]:
        """Generate recommendations for a single device"""
        recommendations = []
        
        # Get device attributes
        device_type = device.get('device_type', 'Unknown')
        risk_level = device.get('risk_level', 'NONE')
        risk_score = device.get('risk_score', 0)
        total_cves = device.get('total_cves', 0)
        critical_cves = device.get('critical_cves', 0)
        high_cves = device.get('high_cves', 0)
        
        # ===== CRITICAL RECOMMENDATIONS =====
        
        # 1. Critical vulnerabilities
        if critical_cves > 0:
            recommendations.append({
                'priority': 'critical',
                'title': f'🔴 {critical_cves} Critical Vulnerabilities Detected',
                'description': f'Device {device["ip_address"]} has {critical_cves} critical vulnerabilities that require immediate attention.',
                'action': 'Patch or isolate this device immediately. Apply security updates and restart services.',
                'type': 'vulnerability'
            })
        
        # 2. High risk score
        if risk_score >= 8.0:
            recommendations.append({
                'priority': 'critical',
                'title': '🚨 Critical Risk Level Detected',
                'description': f'Device has a risk score of {risk_score}/10, indicating severe security risk.',
                'action': 'Perform immediate security assessment. Consider network isolation until remediation.',
                'type': 'risk'
            })
        
        # ===== HIGH RECOMMENDATIONS =====
        
        # 3. High vulnerabilities
        if high_cves > 0:
            recommendations.append({
                'priority': 'high',
                'title': f'🟠 {high_cves} High Vulnerabilities Detected',
                'description': f'Device has {high_cves} high-severity vulnerabilities that need attention.',
                'action': 'Schedule patching within the next maintenance window. Review security configuration.',
                'type': 'vulnerability'
            })
        
        # 4. Old OS version
        os_name = device.get('os', '').lower()
        if any(term in os_name for term in ['windows 7', 'windows 8', 'ubuntu 16', 'centos 6', 'debian 8']):
            recommendations.append({
                'priority': 'high',
                'title': '⚠️ Outdated Operating System',
                'description': f'Device running {device["os"]}, which is end-of-life or outdated.',
                'action': 'Plan upgrade to a supported OS version. Consider migration plan.',
                'type': 'os'
            })
        
        # 5. Device type specific recommendations
        if device_type == 'Server' and total_cves > 5:
            recommendations.append({
                'priority': 'high',
                'title': '🖥️ Server Requires Security Hardening',
                'description': f'Server device has {total_cves} vulnerabilities that could be exploited.',
                'action': 'Implement server hardening guidelines. Review firewall rules and access controls.',
                'type': 'hardening'
            })
        
        # ===== MEDIUM RECOMMENDATIONS =====
        
        # 6. Moderate vulnerabilities
        if total_cves > 0 and critical_cves == 0 and high_cves == 0:
            recommendations.append({
                'priority': 'medium',
                'title': f'📋 {total_cves} Medium/Low Vulnerabilities Found',
                'description': 'Device has manageable vulnerabilities that should be addressed.',
                'action': 'Apply available security patches. Review security best practices.',
                'type': 'vulnerability'
            })
        
        # 7. IoT device recommendations
        if device_type == 'IoT':
            recommendations.append({
                'priority': 'medium',
                'title': '📡 IoT Device Security Check',
                'description': 'IoT devices often have limited security features and update capabilities.',
                'action': 'Check for firmware updates. Review network segmentation. Disable unnecessary services.',
                'type': 'iot'
            })
        
        # 8. Multiple open ports
        open_ports = json.loads(device.get('open_ports', '[]')) if device.get('open_ports') else []
        if len(open_ports) > 10:
            recommendations.append({
                'priority': 'medium',
                'title': '🔌 Excessive Open Ports',
                'description': f'Device has {len(open_ports)} open ports, increasing attack surface.',
                'action': 'Review and close unnecessary ports. Implement firewall rules to restrict access.',
                'type': 'network'
            })
        
        # ===== LOW RECOMMENDATIONS =====
        
        # 9. Missing hostname (best practice)
        if not device.get('hostname') or device.get('hostname') == '':
            recommendations.append({
                'priority': 'low',
                'title': '🏷️ Missing Device Hostname',
                'description': 'Device lacks a proper hostname for identification.',
                'action': 'Assign a descriptive hostname to improve asset management.',
                'type': 'best_practice'
            })
        
        # 10. Regular scanning recommendation
        if total_cves == 0:
            recommendations.append({
                'priority': 'low',
                'title': '✅ Device Appears Secure - Continue Monitoring',
                'description': 'No vulnerabilities found on this device.',
                'action': 'Maintain regular scanning schedule. Review security policies quarterly.',
                'type': 'monitoring'
            })
        
        # 11. Windows-specific recommendations
        if 'windows' in os_name and device_type != 'Server':
            recommendations.append({
                'priority': 'low',
                'title': '💻 Windows Workstation Security',
                'description': 'Ensure Windows workstations are properly configured.',
                'action': 'Verify Windows Update settings. Check antivirus status. Review user permissions.',
                'type': 'best_practice'
            })
        
        # 12. Router/Switch recommendations
        if device_type == 'Router':
            recommendations.append({
                'priority': 'low',
                'title': '🌐 Network Device Security',
                'description': 'Network infrastructure devices require special attention.',
                'action': 'Review router security settings. Disable remote management if not needed.',
                'type': 'network'
            })
        
        return recommendations
    
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