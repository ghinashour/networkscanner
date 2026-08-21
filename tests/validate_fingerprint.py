import sqlite3
import json

def validate_device_fingerprints(db_path="data/network_scanner.db"):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT ip_address, hostname, device_type, brand, os, confidence_level
        FROM devices
        WHERE device_type != 'Unknown' AND confidence_level != 'LOW'
    """)
    
    devices = cursor.fetchall()
    
    print(f"📊 Validating {len(devices)} devices...")
    print("\nSample results:")
    for device in devices[:10]:
        print(f"  {device[0]} → {device[2]} ({device[3]}) | Confidence: {device[5]} | OS: {device[4]}")
    
    conn.close()

if __name__ == "__main__":
    validate_device_fingerprints()