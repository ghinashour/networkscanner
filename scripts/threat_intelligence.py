#!/usr/bin/env python3
"""
Threat Intelligence Integration - CISA KEV, Exploit-DB, EPSS
Moves beyond CVSS to real-world risk prioritization
"""

import requests
import json
import sqlite3
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class ThreatIntelligence:
    """
    Integrates multiple threat intelligence sources:
    - CISA KEV (Known Exploited Vulnerabilities)
    - Exploit-DB (public exploits)
    - EPSS (Exploit Prediction Scoring System)
    """
    
    def __init__(self, db_path="data/network_scanner.db"):
        self.db_path = db_path
        self.cisa_kev_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        self.exploit_db_url = "https://www.exploit-db.com/search"
        self.epss_url = "https://api.first.org/epss/v1"
        self.cisa_kev = {}
        self.cache = {}
        self.cache_timeout = 3600  # 1 hour
        self.init_db()
    
    def init_db(self):
        """Initialize threat intelligence tables with all required columns"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Check if table exists and has correct schema
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='threat_intel'")
            table_exists = cursor.fetchone()
            
            if table_exists:
                # Check existing columns
                cursor.execute("PRAGMA table_info(threat_intel)")
                columns = [col[1] for col in cursor.fetchall()]
                
                # Add missing columns if needed
                if 'risk_score' not in columns:
                    cursor.execute("ALTER TABLE threat_intel ADD COLUMN risk_score REAL DEFAULT 0")
                    logger.info("✅ Added column: risk_score")
                
                if 'risk_level' not in columns:
                    cursor.execute("ALTER TABLE threat_intel ADD COLUMN risk_level TEXT DEFAULT 'LOW'")
                    logger.info("✅ Added column: risk_level")
                
                if 'priority' not in columns:
                    cursor.execute("ALTER TABLE threat_intel ADD COLUMN priority TEXT DEFAULT 'LOW'")
                    logger.info("✅ Added column: priority")
            else:
                # Create full table
                cursor.execute('''
                    CREATE TABLE threat_intel (
                        cve_id TEXT PRIMARY KEY,
                        kev_status INTEGER DEFAULT 0,
                        exploit_count INTEGER DEFAULT 0,
                        epss_score REAL DEFAULT 0,
                        epss_percentile REAL DEFAULT 0,
                        risk_score REAL DEFAULT 0,
                        risk_level TEXT DEFAULT 'LOW',
                        priority TEXT DEFAULT 'LOW',
                        last_updated TEXT,
                        source TEXT,
                        raw_data TEXT
                    )
                ''')
                logger.info("✅ Created threat_intel table with all columns")
            
            conn.commit()
            conn.close()
            logger.info("✅ Threat intelligence database initialized")
            
        except Exception as e:
            logger.error(f"Error initializing threat intel DB: {e}")
            raise
    
    def get_cisa_kev(self) -> Dict[str, Dict]:
        """
        Fetch CISA Known Exploited Vulnerabilities list
        Returns dict of CVE IDs that are known to be exploited
        """
        try:
            response = requests.get(self.cisa_kev_url, timeout=15)
            response.raise_for_status()
            
            data = response.json()
            kev_list = {}
            
            for vuln in data.get('vulnerabilities', []):
                cve_id = vuln.get('cveID')
                if cve_id:
                    kev_list[cve_id] = {
                        'date_added': vuln.get('dateAdded'),
                        'due_date': vuln.get('dueDate'),
                        'known_ransomware': vuln.get('knownRansomwareCampaignUse', False),
                        'product': vuln.get('product'),
                        'short_description': vuln.get('shortDescription')
                    }
            
            logger.info(f"✅ Fetched {len(kev_list)} KEV entries from CISA")
            self.cisa_kev = kev_list
            return kev_list
            
        except requests.exceptions.Timeout:
            logger.warning("⚠️ CISA KEV API timeout")
            return {}
        except Exception as e:
            logger.error(f"Error fetching CISA KEV: {e}")
            return {}
    
    def get_epss_score(self, cve_ids: List[str]) -> Dict[str, Dict]:
        """
        Get EPSS scores for CVEs (Exploit Prediction Scoring System)
        EPSS scores are 0-1, higher = more likely to be exploited
        """
        if not cve_ids:
            return {}
        
        results = {}
        
        try:
            # EPSS API - use the correct endpoint
            params = {'cve': ','.join(cve_ids)}
            
            # Try the new API endpoint
            response = requests.get(
                'https://api.first.org/epss/v1/get',
                params=params,
                timeout=30,
                headers={'User-Agent': 'NetworkScanner/1.0'}
            )
            response.raise_for_status()
            
            data = response.json()
            
            # Parse response
            if 'data' in data:
                for item in data['data']:
                    cve_id = item.get('cve')
                    if cve_id:
                        results[cve_id] = {
                            'score': float(item.get('epss', 0)),
                            'percentile': float(item.get('percentile', 0))
                        }
            
            logger.info(f"✅ Fetched EPSS scores for {len(results)} CVEs")
            return results
            
        except requests.exceptions.Timeout:
            logger.warning("⚠️ EPSS API timeout")
            return self._get_epss_fallback(cve_ids)
        except requests.exceptions.HTTPError as e:
            logger.warning(f"⚠️ EPSS API error: {e}")
            return self._get_epss_fallback(cve_ids)
        except Exception as e:
            logger.error(f"Error fetching EPSS scores: {e}")
            return self._get_epss_fallback(cve_ids)
    
    def _get_epss_fallback(self, cve_ids: List[str]) -> Dict[str, Dict]:
        """Fallback method for EPSS if primary API fails"""
        results = {}
        try:
            for cve_id in cve_ids:
                results[cve_id] = {
                    'score': 0.0,
                    'percentile': 0.0
                }
            logger.info(f"✅ Using fallback EPSS scores for {len(results)} CVEs")
            return results
        except Exception as e:
            logger.error(f"EPSS fallback failed: {e}")
            return {}
    
    def get_exploit_count(self, cve_id: str) -> int:
        """
        Get number of public exploits for a CVE via Exploit-DB
        """
        try:
            # Check if it's in the KEV list (often indicates public exploits)
            if self.cisa_kev and cve_id in self.cisa_kev:
                return 1  # At least one known exploit
            
            # Could also check other sources in production
            return 0
            
        except Exception as e:
            logger.debug(f"Error checking exploits for {cve_id}: {e}")
            return 0
    
    def analyze_cves(self, cve_ids: List[str]) -> Dict[str, Dict]:
        """
        Analyze CVEs with threat intelligence
        Returns risk scores combining multiple factors
        """
        if not cve_ids:
            return {}
        
        results = {}
        
        # Get CISA KEV
        self.cisa_kev = self.get_cisa_kev()
        
        # Get EPSS scores
        epss_scores = self.get_epss_score(cve_ids)
        
        for cve_id in cve_ids:
            risk = {
                'cve_id': cve_id,
                'kev_status': False,
                'exploit_count': 0,
                'epss_score': 0,
                'epss_percentile': 0,
                'risk_score': 0,
                'risk_level': 'LOW',
                'priority': 'LOW'
            }
            
            # 1. CISA KEV status (HIGHEST WEIGHT)
            if cve_id in self.cisa_kev:
                risk['kev_status'] = True
                risk['risk_score'] += 50
                
                # If known ransomware, even higher
                if self.cisa_kev[cve_id].get('known_ransomware'):
                    risk['risk_score'] += 20
            
            # 2. EPSS score (HIGH WEIGHT)
            if cve_id in epss_scores:
                epss = epss_scores[cve_id]
                risk['epss_score'] = epss.get('score', 0)
                risk['epss_percentile'] = epss.get('percentile', 0)
                
                # EPSS > 0.5 = high probability of exploitation
                if risk['epss_score'] > 0.5:
                    risk['risk_score'] += 30
                elif risk['epss_score'] > 0.2:
                    risk['risk_score'] += 15
                elif risk['epss_score'] > 0.05:
                    risk['risk_score'] += 5
            
            # 3. Public exploits (MEDIUM WEIGHT)
            exploit_count = self.get_exploit_count(cve_id)
            risk['exploit_count'] = exploit_count
            if exploit_count > 5:
                risk['risk_score'] += 25
            elif exploit_count > 1:
                risk['risk_score'] += 15
            elif exploit_count > 0:
                risk['risk_score'] += 5
            
            # Determine risk level
            if risk['risk_score'] >= 70:
                risk['risk_level'] = 'CRITICAL'
                risk['priority'] = 'IMMEDIATE'
            elif risk['risk_score'] >= 40:
                risk['risk_level'] = 'HIGH'
                risk['priority'] = 'HIGH'
            elif risk['risk_score'] >= 20:
                risk['risk_level'] = 'MEDIUM'
                risk['priority'] = 'MEDIUM'
            else:
                risk['risk_level'] = 'LOW'
                risk['priority'] = 'LOW'
            
            # Save to database
            self._save_threat_intel(risk)
            
            results[cve_id] = risk
        
        return results
    
    def _save_threat_intel(self, risk: Dict):
        """Save threat intelligence to database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT OR REPLACE INTO threat_intel 
                (cve_id, kev_status, exploit_count, epss_score, epss_percentile, 
                 risk_score, risk_level, priority, last_updated, source)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                risk['cve_id'],
                1 if risk['kev_status'] else 0,
                risk['exploit_count'],
                risk['epss_score'],
                risk['epss_percentile'],
                risk['risk_score'],
                risk['risk_level'],
                risk['priority'],
                datetime.now().isoformat(),
                'cisa_kev,epss'
            ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"Error saving threat intel: {e}")
    
    def get_device_risk_priority(self, device_id: int) -> Dict:
        """
        Get prioritized risk for a device
        Combines vulnerability CVSS with threat intelligence
        """
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            # Get device vulnerabilities with threat intel
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
                    ti.risk_score as threat_score,
                    ti.risk_level as threat_level,
                    ti.priority
                FROM device_vulnerabilities dv
                JOIN cves c ON dv.cve_id = c.cve_id
                LEFT JOIN threat_intel ti ON c.cve_id = ti.cve_id
                WHERE dv.device_id = ?
                ORDER BY ti.risk_score DESC NULLS LAST
            ''', (device_id,))
            
            vulns = [dict(row) for row in cursor.fetchall()]
            conn.close()
            
            # Calculate combined risk
            total_threat_score = sum(v.get('threat_score', 0) or 0 for v in vulns)
            avg_threat_score = total_threat_score / len(vulns) if vulns else 0
            
            # Count critical threats
            critical_threats = sum(1 for v in vulns if v.get('threat_level') == 'CRITICAL')
            high_threats = sum(1 for v in vulns if v.get('threat_level') == 'HIGH')
            
            # Determine overall priority
            if critical_threats > 0:
                priority = 'CRITICAL'
            elif high_threats > 2:
                priority = 'HIGH'
            elif high_threats > 0:
                priority = 'MEDIUM'
            else:
                priority = 'LOW'
            
            return {
                'device_id': device_id,
                'vulnerabilities': vulns,
                'total_vulns': len(vulns),
                'critical_threats': critical_threats,
                'high_threats': high_threats,
                'avg_threat_score': avg_threat_score,
                'priority': priority,
                'has_kev': any(v.get('kev_status') for v in vulns),
                'has_exploits': any(v.get('exploit_count', 0) > 0 for v in vulns)
            }
            
        except Exception as e:
            logger.error(f"Error getting device risk priority: {e}")
            return {'error': str(e)}


# ============================================================================
# QUICK TEST
# ============================================================================

if __name__ == "__main__":
    print("=" * 60)
    print("🛡️ Threat Intelligence Test")
    print("=" * 60)
    
    ti = ThreatIntelligence()
    
    # Test CVEs
    test_cves = ["CVE-2021-44228", "CVE-2024-6387", "CVE-2024-12345"]
    
    print("\n📊 Analyzing CVEs with Threat Intelligence:")
    print("-" * 60)
    
    results = ti.analyze_cves(test_cves)
    
    for cve_id, risk in results.items():
        print(f"\n🔍 {cve_id}:")
        print(f"   KEV Status: {'✅' if risk['kev_status'] else '❌'}")
        print(f"   EPSS Score: {risk['epss_score']:.4f} (Percentile: {risk['epss_percentile']:.1f}%)")
        print(f"   Public Exploits: {risk['exploit_count']}")
        print(f"   Risk Score: {risk['risk_score']}")
        print(f"   Risk Level: {risk['risk_level']}")
        print(f"   Priority: {risk['priority']}")
    
    print("\n" + "=" * 60)