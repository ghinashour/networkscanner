#!/usr/bin/env python3
"""
Complete Threat Intelligence Fix
- Fetches CISA KEV
- Fetches EPSS scores
- Calculates risk scores for all CVEs
- Updates threat_intel table
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import sqlite3
import json
import time
import logging
from datetime import datetime
from threat_intelligence import ThreatIntelligence

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def fix_all_threats():
    """Complete threat intelligence fix"""
    
    print("=" * 60)
    print("🔧 COMPLETE THREAT INTELLIGENCE FIX")
    print("=" * 60)
    
    # 1. Check if CVEs exist
    conn = sqlite3.connect('data/network_scanner.db')
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='cves'")
    if not cursor.fetchone():
        print("❌ No CVEs table found!")
        print("   Run: python scripts/integrate_scanner.py first")
        conn.close()
        return
    
    cursor.execute('SELECT COUNT(*) FROM cves')
    cve_count = cursor.fetchone()[0]
    conn.close()
    
    if cve_count == 0:
        print("❌ No CVEs found in database!")
        print("   Run: python scripts/integrate_scanner.py first")
        return
    
    print(f"\n📊 Found {cve_count} CVEs in database")
    
    # 2. Initialize threat intelligence
    ti = ThreatIntelligence()
    
    # 3. Fetch CISA KEV
    print("\n📡 Fetching CISA KEV...")
    kev = ti.get_cisa_kev()
    print(f"   ✅ Found {len(kev)} KEV entries")
    
    # 4. Get all CVE IDs
    conn = sqlite3.connect('data/network_scanner.db')
    cursor = conn.cursor()
    cursor.execute('SELECT DISTINCT cve_id FROM cves')
    cves = [row[0] for row in cursor.fetchall()]
    conn.close()
    
    # 5. Analyze CVEs in batches
    print(f"\n📊 Analyzing {len(cves)} CVEs with threat intelligence...")
    
    batch_size = 50
    total_analyzed = 0
    
    for i in range(0, len(cves), batch_size):
        batch = cves[i:i+batch_size]
        print(f"   Batch {i//batch_size + 1}/{(len(cves)-1)//batch_size + 1}...")
        
        results = ti.analyze_cves(batch)
        total_analyzed += len(results)
        time.sleep(0.5)
    
    print(f"   ✅ Analyzed {total_analyzed} CVEs")
    
    # 6. Verify results
    conn = sqlite3.connect('data/network_scanner.db')
    cursor = conn.cursor()
    
    # Check threat_intel table
    cursor.execute("SELECT COUNT(*) FROM threat_intel")
    threat_count = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM threat_intel WHERE risk_score > 0")
    scored_count = cursor.fetchone()[0]
    
    cursor.execute("SELECT AVG(risk_score) FROM threat_intel WHERE risk_score > 0")
    avg_score = cursor.fetchone()[0]
    
    # Get KEV count
    cursor.execute("SELECT COUNT(*) FROM threat_intel WHERE kev_status = 1")
    kev_count = cursor.fetchone()[0]
    
    # Get priority distribution
    cursor.execute("""
        SELECT risk_level, COUNT(*) 
        FROM threat_intel 
        WHERE risk_level IS NOT NULL
        GROUP BY risk_level
    """)
    priority_dist = cursor.fetchall()
    
    conn.close()
    
    # 7. Show results
    print("\n" + "=" * 60)
    print("📊 RESULTS")
    print("=" * 60)
    print(f"   Total CVEs analyzed: {threat_count}")
    print(f"   CVEs with risk scores: {scored_count}")
    print(f"   Average risk score: {avg_score:.1f}" if avg_score else "   Average risk score: N/A")
    print(f"   CVEs in CISA KEV: {kev_count}")
    
    print("\n   Priority Distribution:")
    if priority_dist:
        for level, count in priority_dist:
            emoji = {
                'CRITICAL': '🔴',
                'HIGH': '🟠',
                'MEDIUM': '🟡',
                'LOW': '🟢'
            }.get(level, '⚪')
            print(f"      {emoji} {level}: {count} CVEs")
    else:
        print("      No priorities assigned yet")
    
    # 8. Show top 10 highest risk CVEs
    conn = sqlite3.connect('data/network_scanner.db')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("""
        SELECT cve_id, risk_score, risk_level, kev_status, exploit_count, epss_score
        FROM threat_intel
        WHERE risk_score > 0
        ORDER BY risk_score DESC
        LIMIT 10
    """)
    top_cves = cursor.fetchall()
    conn.close()
    
    if top_cves:
        print("\n🔍 Top 10 Highest Risk CVEs:")
        print("-" * 60)
        for cve in top_cves:
            kev = "✅" if cve['kev_status'] else "❌"
            print(f"   {cve['cve_id']:<15} Score: {cve['risk_score']:>3}  "
                  f"Level: {cve['risk_level']:<8} KEV: {kev}  "
                  f"EPSS: {cve['epss_score']:.2f}")
    
    print("\n" + "=" * 60)
    print("✅ Fix complete!")
    print("   Run: python scripts/adversary_risk_engine.py")
    print("=" * 60)

if __name__ == "__main__":
    fix_all_threats()