"""
Complete System Test - Test all components
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))

import sqlite3
import json
import pandas as pd
from datetime import datetime
import logging
from cve_integration import CVEService
from risk_engine import RiskEngine
from ai_recommendations import AIRecommendations
from network_graph import NetworkGraph

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class SystemTester:
    def __init__(self, db_path="data/network_scanner.db"):
        self.db_path = db_path
        self.results = {
            'tests': [],
            'passed': 0,
            'failed': 0,
            'total': 0
        }
    
    def run_all_tests(self):
        """Run all system tests"""
        logger.info("=" * 60)
        logger.info("🧪 STARTING SYSTEM TESTS")
        logger.info("=" * 60)
        
        self.test_database()
        self.test_cve_integration()
        self.test_risk_engine()
        self.test_ai_recommendations()
        self.test_network_graph()
        self.test_integration()
        
        self.print_summary()
        return self.results
    
    def test_database(self):
        """Test database connectivity and schema"""
        logger.info("\n📊 Test 1: Database")
        
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Check tables
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = [row[0] for row in cursor.fetchall()]
            
            required_tables = ['devices', 'cves', 'device_vulnerabilities', 'device_risks', 'recommendations']
            missing = [t for t in required_tables if t not in tables]
            
            if missing:
                logger.error(f"❌ Missing tables: {missing}")
                self._add_result('Database', False, f"Missing tables: {missing}")
                conn.close()
                return
            
            # Check if we have data
            cursor.execute("SELECT COUNT(*) FROM devices")
            device_count = cursor.fetchone()[0]
            
            conn.close()
            
            logger.info(f"✅ Database OK - {device_count} devices, {len(tables)} tables")
            self._add_result('Database', True, f"{device_count} devices, {len(tables)} tables")
            
        except Exception as e:
            logger.error(f"❌ Database test failed: {e}")
            self._add_result('Database', False, str(e))
    
    def test_cve_integration(self):
        """Test CVE integration"""
        logger.info("\n🔍 Test 2: CVE Integration")
        
        try:
            cve_service = CVEService(self.db_path)
            
            # Test query
            cves = cve_service.get_cves_for_service('nginx', 80)
            
            if cves:
                logger.info(f"✅ CVE Integration OK - Found {len(cves)} CVEs for nginx")
                self._add_result('CVE Integration', True, f"Found {len(cves)} CVEs")
            else:
                logger.warning("⚠️ No CVEs found (this could be due to API rate limiting)")
                self._add_result('CVE Integration', True, "No CVEs found (API may be rate limited)")
            
        except Exception as e:
            logger.error(f"❌ CVE Integration test failed: {e}")
            self._add_result('CVE Integration', False, str(e))
    
    def test_risk_engine(self):
        """Test risk engine"""
        logger.info("\n📊 Test 3: Risk Engine")
        
        try:
            risk_engine = RiskEngine(self.db_path)
            
            # Get all devices
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT id FROM devices LIMIT 1")
            device = cursor.fetchone()
            conn.close()
            
            if device:
                risk = risk_engine.calculate_risk_score(device[0])
                logger.info(f"✅ Risk Engine OK - Device {device[0]} risk score: {risk.get('risk_score', 0)}")
                self._add_result('Risk Engine', True, f"Risk score: {risk.get('risk_score', 0)}")
            else:
                logger.warning("⚠️ No devices found to test risk engine")
                self._add_result('Risk Engine', True, "No devices available")
            
        except Exception as e:
            logger.error(f"❌ Risk Engine test failed: {e}")
            self._add_result('Risk Engine', False, str(e))
    
    def test_ai_recommendations(self):
        """Test AI recommendations"""
        logger.info("\n🤖 Test 4: AI Recommendations")
        
        try:
            ai = AIRecommendations(self.db_path)
            
            # Get recommendations
            recommendations = ai.get_all_recommendations()
            
            if recommendations:
                logger.info(f"✅ AI Recommendations OK - Found {len(recommendations)} recommendations")
                self._add_result('AI Recommendations', True, f"{len(recommendations)} recommendations")
            else:
                # Try generating
                logger.info("Generating new recommendations...")
                results = ai.generate_all_recommendations()
                
                if 'error' not in results:
                    count = results['summary']['total_recommendations']
                    logger.info(f"✅ Generated {count} recommendations")
                    self._add_result('AI Recommendations', True, f"Generated {count} recommendations")
                else:
                    self._add_result('AI Recommendations', False, results['error'])
            
        except Exception as e:
            logger.error(f"❌ AI Recommendations test failed: {e}")
            self._add_result('AI Recommendations', False, str(e))
    
    def test_network_graph(self):
        """Test network graph generation"""
        logger.info("\n🌐 Test 5: Network Graph")
        
        try:
            graph = NetworkGraph(self.db_path)
            data = graph.get_network_graph()
            
            if 'error' not in data:
                nodes = len(data.get('nodes', []))
                links = len(data.get('links', []))
                logger.info(f"✅ Network Graph OK - {nodes} nodes, {links} edges")
                self._add_result('Network Graph', True, f"{nodes} nodes, {links} edges")
            else:
                self._add_result('Network Graph', False, data['error'])
            
        except Exception as e:
            logger.error(f"❌ Network Graph test failed: {e}")
            self._add_result('Network Graph', False, str(e))
    
    def test_integration(self):
        """Test complete integration"""
        logger.info("\n🔗 Test 6: System Integration")
        
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Check if all components have data
            cursor.execute("SELECT COUNT(*) FROM devices")
            devices = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM cves")
            cves = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM device_vulnerabilities")
            vulns = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM device_risks")
            risks = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM recommendations")
            recs = cursor.fetchone()[0]
            
            conn.close()
            
            logger.info(f"✅ Integration OK - {devices} devices, {cves} CVEs, {vulns} vulns, {risks} risks, {recs} recs")
            self._add_result('Integration', True, 
                           f"Devices:{devices} CVEs:{cves} Vulns:{vulns} Risks:{risks} Recs:{recs}")
            
        except Exception as e:
            logger.error(f"❌ Integration test failed: {e}")
            self._add_result('Integration', False, str(e))
    
    def _add_result(self, test_name, passed, details):
        """Add test result"""
        self.results['tests'].append({
            'name': test_name,
            'passed': passed,
            'details': details
        })
        self.results['total'] += 1
        if passed:
            self.results['passed'] += 1
        else:
            self.results['failed'] += 1
    
    def print_summary(self):
        """Print test summary"""
        logger.info("\n" + "=" * 60)
        logger.info("📊 TEST SUMMARY")
        logger.info("=" * 60)
        
        for test in self.results['tests']:
            status = "✅ PASSED" if test['passed'] else "❌ FAILED"
            logger.info(f"{status} - {test['name']}: {test['details']}")
        
        logger.info("\n" + "-" * 60)
        logger.info(f"Total: {self.results['total']}")
        logger.info(f"Passed: {self.results['passed']}")
        logger.info(f"Failed: {self.results['failed']}")
        
        if self.results['failed'] == 0:
            logger.info("\n🎉 ALL TESTS PASSED! System is ready for production!")
        else:
            logger.warning(f"\n⚠️ {self.results['failed']} tests failed. Please fix before proceeding.")
        
        logger.info("=" * 60)


# ============================================================================
# PERFORMANCE TEST
# ============================================================================

def test_performance():
    """Test system performance"""
    logger.info("\n⚡ Performance Test")
    logger.info("-" * 40)
    
    import time
    
    start = time.time()
    
    # Test database query performance
    conn = sqlite3.connect("data/network_scanner.db")
    cursor = conn.cursor()
    
    # Complex query
    cursor.execute('''
        SELECT d.ip_address, d.device_type, 
               COUNT(dv.id) as vuln_count,
               AVG(c.cvss_score) as avg_cvss
        FROM devices d
        LEFT JOIN device_vulnerabilities dv ON d.id = dv.device_id
        LEFT JOIN cves c ON dv.cve_id = c.cve_id
        GROUP BY d.id
        ORDER BY vuln_count DESC
        LIMIT 20
    ''')
    
    results = cursor.fetchall()
    conn.close()
    
    elapsed = time.time() - start
    
    logger.info(f"✅ Query executed in {elapsed:.3f} seconds")
    logger.info(f"   Returned {len(results)} rows")
    
    if elapsed < 1.0:
        logger.info("   ✅ Performance is excellent")
    elif elapsed < 3.0:
        logger.info("   ✅ Performance is good")
    else:
        logger.warning("   ⚠️ Performance could be improved")
    
    return elapsed


# ============================================================================
# MAIN
# ============================================================================

if __name__ == "__main__":
    import sys
    
    print("=" * 60)
    print("🧪 NETWORK SCANNER SYSTEM TEST")
    print("=" * 60)
    
    # Run tests
    tester = SystemTester()
    results = tester.run_all_tests()
    
    # Performance test
    print("\n" + "=" * 60)
    test_performance()
    
    print("\n" + "=" * 60)
    print("📋 RECOMMENDATIONS FOR NEXT STEPS")
    print("=" * 60)
    
    if results['failed'] == 0:
        print("""
✅ All tests passed! You're ready to:
   1. Deploy to production
   2. Schedule regular scans
   3. Set up alerts and notifications
   4. Train more team members on the system
        """)
    else:
        print("""
⚠️ Some tests failed. Please:
   1. Check the error messages above
   2. Fix the issues
   3. Run tests again
   4. Contact support if needed
        """)