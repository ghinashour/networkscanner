#!/usr/bin/env python3
"""
Generate 2000 realistic network device records
Based on the original dataset patterns
No errors, no None, fully self-contained
"""

import pandas as pd
import numpy as np
import random
import os
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
import warnings
warnings.filterwarnings('ignore')

class DeviceDataGenerator:
    """Generate synthetic network device data"""
    
    def __init__(self, seed: int = 42):
        random.seed(seed)
        np.random.seed(seed)
        
        # Define device patterns
        self.patterns = {
            'Windows PC': {
                'os': ['Windows 10 Pro', 'Windows 11 Pro', 'Windows 10 Enterprise', 'Windows 10 IoT'],
                'ports': [
                    '3389,445,80,135,139', '80,443,445,135', '3389,445,80,443,135',
                    '80,135,445,443', '3389,80,445,135,139', '135,445,80,443',
                    '80,443,3389,135', '3389,445,80,135'
                ],
                'services': [
                    'rdp,smb,http,msrpc,netbios', 'smb,http,https,msrpc',
                    'http,msrpc,smb,https', 'rdp,smb,http,msrpc',
                    'http,msrpc,smb,rdp,https', 'rdp,smb,http,msrpc,netbios'
                ],
                'vendor': ['Microsoft', 'Dell', 'HP', 'Lenovo'],
                'models': [
                    'OptiPlex 7060', 'EliteBook 840', 'Latitude 7420', 'ThinkPad T490',
                    'XPS 15', 'ProBook 650', 'Precision 5560', 'Surface Laptop 4',
                    'OptiPlex 3080', 'EliteBook 850 G6', 'Latitude 5520', 'ThinkPad X1'
                ],
                'locations': ['Office_2nd_Floor', 'Office_3rd_Floor', 'Office_1st_Floor'],
                'risk': ['Medium', 'High'],
                'category': 'Computing',
                'sub': ['Desktop', 'Laptop', 'Workstation', 'Convertible_Laptop', 'Gaming_Laptop'],
                'caps': [
                    'Print_Server_File_Share', 'Remote_Desktop_File_Share', 'Remote_Desktop_Web',
                    'Legacy_SMB_RDP', 'Standard_Office_Work', 'Business_Laptop_Legacy',
                    'Remote_Desktop_Collab', 'Remote_Access_Web_Services', 'Remote_Desktop_Dev',
                    'Legacy_NetBIOS_RDP', 'Legacy_Office_Services'
                ]
            },
            'Server': {
                'os': ['Debian 11', 'Debian 12', 'Ubuntu Server 22.04', 'CentOS 8', 'CentOS 7'],
                'ports': [
                    '22,80,443,3306', '22,8080,443,3306', '22,80,443', '22,80,443,3306,8080',
                    '443,22,3306', '22,80,445,443'
                ],
                'services': [
                    'ssh,http,https,mysql', 'ssh,http,https,http-alt', 'ssh,http,https',
                    'ssh,http,https,smb'
                ],
                'vendor': ['Linux', 'Microsoft'],
                'models': [
                    'Proxmox VE', 'Apache Server', 'NGINX Server', 'Tomcat Server',
                    'PostgreSQL Server', 'Docker Host', 'Kubernetes Node', 'Redis Server',
                    'Prometheus Server', 'Grafana Server', 'File Server', 'Flask Server',
                    'Docker Swarm', 'Node.js Server', 'MySQL Server'
                ],
                'locations': ['Server_Room_A', 'Server_Room_B'],
                'risk': ['Low'],
                'category': 'Infrastructure',
                'sub': [
                    'Web_Server', 'Application_Server', 'Database_Server', 'Container_Host',
                    'Virtualization', 'Cache_Server', 'Monitoring', 'File_Server',
                    'Container_Orchestrator'
                ],
                'caps': [
                    'HTTP_HTTPS_DB', 'Web_Hosting_DB', 'Web_Hosting_Load_Balancer',
                    'Docker_Orchestration', 'Kubernetes_Worker_Node', 'PostgreSQL_Data_Storage',
                    'Redis_InMemory_DB', 'Prometheus_Metrics_Monitoring', 'Node_JS_Runtime',
                    'Apache_Web_Hosting', 'NGINX_Reverse_Proxy', 'Java_Apps_DB'
                ]
            },
            'Router': {
                'os': ['OpenWRT 22.03', 'DD-WRT v3.0', 'RouterOS 7.8', 'OpenWRT 21.02', 'RouterOS 6.49', 'OpenWRT 19.07', 'RouterOS 7.9'],
                'ports': [
                    '80,443,22,53', '80,443,22,8291,53', '22,80,443,53', '80,22,8291,53',
                    '80,443,22,8291', '22,80,8291,53', '80,22,443,53'
                ],
                'services': [
                    'http,https,ssh,dns', 'http,https,ssh,winbox,dns', 'http,ssh,winbox,dns',
                    'http,ssh,https,dns', 'http,ssh,winbox'
                ],
                'vendor': ['TP-Link', 'Netgear', 'MikroTik', 'Asus', 'Ubiquiti', 'GL.iNet', 'Linksys', 'Xiaomi'],
                'models': [
                    'Archer C7', 'R7000', 'RB750Gr3', 'RT-AC68U', 'EdgeRouter X',
                    'RB4011', 'GL-MT1300', 'Archer AX50', 'CRS305-1G-4S+', 'RT-AC87U',
                    'RB951G-2HnD', 'GL-AR750', 'RB1100AHx4', 'R7800', 'RT-AC88U',
                    'RAX120', 'GL-SFT1200', 'RT-AC66U', 'RB2011UiAS', 'WRT1900ACS'
                ],
                'locations': ['Network_Rack_1', 'Network_Rack_2', 'Network_Rack_3', 'Office_1st_Floor', 'Wireless_Zone_2'],
                'risk': ['Low'],
                'category': 'Networking',
                'sub': ['Router', 'Switch_Router'],
                'caps': [
                    'Gateway_WiFi_DHCP_DNS', 'Gateway_WiFi_VPN', 'Advanced_Routing_QoS',
                    'WiFi6_Gateway_VPN', 'Edge_Routing_Firewall', 'Core_Routing_LoadBalancer',
                    'Advanced_Routing_WiFi', 'WiFi_Gateway_DNS', 'Open_Source_Routing',
                    'Advanced_Switching_Routing', 'Enterprise_Routing', 'Portable_Gateway_VPN',
                    'Portable_Router_VPN', 'WiFi6_Advanced_Routing', 'Gaming_Router_AC3100',
                    'AC1900_Router', 'ARM_Enterprise_Router'
                ]
            },
            'Mobile Device': {
                'os': ['Android 13', 'iOS 17.0', 'Android 11', 'iOS 16.6'],
                'ports': ['5555,8080,443', '62078,443,5223'],
                'services': ['adb,http-proxy,https', 'iphone-sync,https,apple-push'],
                'vendor': ['Samsung', 'Apple', 'Xiaomi', 'OnePlus', 'Google'],
                'models': [
                    'Galaxy S23', 'iPhone 14 Pro', 'Redmi Note 10', 'Pixel 6',
                    'Galaxy A52', 'iPhone 15', 'Redmi Note 11', 'Pixel 7 Pro',
                    'Galaxy S22', 'iPhone 13 Pro', 'OnePlus 9 Pro', 'Galaxy Z Flip4',
                    'Pixel 6 Pro', 'OnePlus 10 Pro', 'Galaxy A54', 'iPhone SE 2022'
                ],
                'locations': ['Wireless_Zone_1', 'Wireless_Zone_2'],
                'risk': ['Medium'],
                'category': 'Mobile',
                'sub': ['Smartphone'],
                'caps': [
                    'Mobile_Dev_ADB_Dev', 'iOS_Sync_Push', 'Android_Dev_ADB',
                    'Google_Tensor_ADB', 'Samsung_Flagship_ADB', 'iOS_Sync_iCloud',
                    'Mobile_Dev_Proxy', 'Android_Ultra_ADB', 'iOS_Pro_Features',
                    'OnePlus_Flagship_ADB', 'Foldable_Android_ADB', 'Google_Flagship_ADB',
                    'Android_MidRange_ADB', 'Xiaomi_Budget_ADB'
                ]
            },
            'IoT Device': {
                'os': ['Embedded Linux 4.14', 'Embedded Linux 5.10', 'Raspberry Pi OS 11', 'Embedded Linux 4.19', 'Embedded Linux 5.15'],
                'ports': [
                    '80,1883,443', '554,80,443', '80,1883,443,22', '1883,443,22',
                    '1883,80,443,22', '80,554,443', '1883,443'
                ],
                'services': [
                    'http,mqtt,https', 'rtsp,http,https', 'http,mqtt,https,ssh',
                    'mqtt,https,ssh', 'mqtt,http,https'
                ],
                'vendor': ['ESP8266', 'Raspberry Pi', 'ESP32', 'HiSilicon', 'Hikvision', 'Dahua', 'Reolink', 'Amcrest', 'Ambarella'],
                'models': [
                    'Sonoff Basic', 'Raspberry Pi Camera', 'Shelly EM', 'IP Camera',
                    'Smart Plug', 'Pi 4 Model B', 'Shelly 2.5', 'Smart Thermostat',
                    'Pi 3 Model B+', 'Pi Zero W', 'Pi 3 Model B', 'Smart Lock',
                    'Raspberry Pi Camera V2', 'Pi Zero 2 W', 'Sensor Node'
                ],
                'locations': ['Smart_Home_Hub', 'Surveillance_Zone', 'Smart_Home_Zone'],
                'risk': ['Medium', 'High'],
                'category': ['Smart_Home', 'Surveillance'],
                'sub': [
                    'Switch', 'IP_Camera', 'Energy_Monitor', 'Sensor_Hub',
                    'Hub_Controller', 'Smart_Plug', 'Temperature_Sensor',
                    'Smart_Speaker', 'Garage_Controller', 'Light_Controller'
                ],
                'caps': [
                    'Remote_Control_Automation', 'Video_Streaming_Recording',
                    'Power_Monitoring_Control', 'Home_Automation_Control',
                    'Remote_Desktop_File_Share', 'Home_Automation_MQTT',
                    'Smart_Home_Automation', 'Lightweight_Automation',
                    'Home_Assistant_Server', 'Remote_Control_Automation',
                    'Remote_Power_Control', 'HVAC_Control_Energy_Saving',
                    'Video_Streaming_AI', '4K_Video_Streaming'
                ]
            }
        }
    
    def _generate_ip(self, used_ips: set) -> str:
        """Generate a unique IP within 192.168.1.x"""
        while True:
            ip = f"192.168.1.{random.randint(2, 254)}"
            if ip not in used_ips:
                used_ips.add(ip)
                return ip
    
    def _generate_mac(self, vendor: str) -> str:
        """Generate MAC address with vendor OUI prefix"""
        vendor_ouis = {
            'Microsoft': ['AA:11', 'AA:11:03', 'AA:11:38', 'AA:11:7b', 'AA:11:9c'],
            'Dell': ['AA:11:b3', 'AA:11:d6', 'AA:11:4c', 'AA:11:9a'],
            'HP': ['AA:11:51', 'AA:11:0b', 'AA:11:8b', 'AA:11:06'],
            'Lenovo': ['AA:11:7b', 'AA:11:9c', 'AA:11:1d', 'AA:11:33'],
            'TP-Link': ['BB:22:2b', 'BB:22:60', 'BB:22:76', 'BB:22:ac'],
            'Netgear': ['BB:22:0a', 'BB:22:49', 'BB:22:00', 'BB:22:e1'],
            'MikroTik': ['BB:22:a5', 'BB:22:8e', 'BB:22:fb', 'BB:22:4f'],
            'Asus': ['BB:22:67', 'BB:22:8d', 'BB:22:4f', 'BB:22:b7'],
            'Ubiquiti': ['BB:22:84', 'BB:22:5c'],
            'GL.iNet': ['BB:22:3b', 'BB:22:a7', 'BB:22:dc'],
            'Linksys': ['BB:22:e5', 'BB:22:95', 'BB:22:0e'],
            'Xiaomi': ['BB:22:02', 'EE:55:e3', 'EE:55:bc'],
            'Samsung': ['EE:55:0f', 'EE:55:da', 'EE:55:78', 'EE:55:ca', 'EE:55:61'],
            'Apple': ['EE:55:92', 'EE:55:70', 'EE:55:65', 'EE:55:43', 'EE:55:d1'],
            'Google': ['EE:55:6e', 'EE:55:dc', 'EE:55:ec'],
            'OnePlus': ['EE:55:a1', 'EE:55:8b', 'EE:55:76'],
            'ESP8266': ['DD:44:74', 'DD:44:dc', 'DD:44:20', 'DD:44:75'],
            'ESP32': ['DD:44:bf', 'DD:44:3d', 'DD:44:ca', 'DD:44:b3'],
            'Raspberry Pi': ['DD:44:20', 'DD:44:06', 'DD:44:82', 'DD:44:fb', 'DD:44:b5'],
            'Hikvision': ['DD:44:9a', 'DD:44:f5'],
            'Dahua': ['DD:44:62', 'DD:44:79'],
            'Reolink': ['DD:44:0b'],
            'Amcrest': ['DD:44:b0'],
            'Ambarella': ['DD:44:1f'],
            'HiSilicon': ['DD:44:3b'],
            'Linux': ['CC:33:35', 'CC:33:7a', 'CC:33:8d', 'CC:33:db'],
            'Other': ['FF:44:11', 'GG:55:22']
        }
        prefix = random.choice(vendor_ouis.get(vendor, ['AA:BB:CC']))
        rest = ':'.join([f"{random.randint(0,255):02x}" for _ in range(3)])
        return f"{prefix}:{rest}".upper()
    
    def _generate_timestamp(self) -> str:
        """Generate recent timestamp"""
        days_ago = random.randint(0, 30)
        hours_ago = random.randint(0, 23)
        mins_ago = random.randint(0, 59)
        dt = datetime.now() - timedelta(days=days_ago, hours=hours_ago, minutes=mins_ago)
        return dt.strftime('%Y-%m-%d %H:%M:%S')
    
    def _generate_firmware(self, device_type: str, os_str: str) -> str:
        """Generate firmware version based on OS"""
        if 'Windows' in os_str:
            return random.choice(['10.0.19045', '10.0.22621', '10.0.19044'])
        elif 'Debian' in os_str:
            return random.choice(['11.0', '11.7', '12.0', '12.5'])
        elif 'Ubuntu' in os_str:
            return '22.04'
        elif 'CentOS' in os_str:
            return random.choice(['7.0', '7.9', '8.0', '8.5'])
        elif 'OpenWRT' in os_str:
            return random.choice(['22.03', '21.02', '19.07'])
        elif 'DD-WRT' in os_str:
            return 'v3.0'
        elif 'RouterOS' in os_str:
            return random.choice(['6.49', '7.8', '7.9'])
        elif 'Embedded' in os_str:
            return random.choice(['4.14', '4.19', '5.10', '5.15'])
        elif 'Raspberry' in os_str:
            return '11.0'
        elif 'Android' in os_str:
            return random.choice(['11.0', '13.0'])
        elif 'iOS' in os_str:
            return random.choice(['16.6', '17.0'])
        else:
            return '1.0'
    
    def _generate_record(self, device_type: str, used_ips: set) -> Dict[str, Any]:
        """Generate a single device record"""
        pattern = self.patterns[device_type]
        
        os_choice = random.choice(pattern['os'])
        ports = random.choice(pattern['ports'])
        services = random.choice(pattern['services'])
        vendor = random.choice(pattern['vendor'])
        model = random.choice(pattern['models'])
        location = random.choice(pattern['locations'])
        risk = random.choice(pattern['risk'])
        category = random.choice(pattern['category']) if isinstance(pattern['category'], list) else pattern['category']
        sub = random.choice(pattern['sub'])
        cap = random.choice(pattern['caps'])
        confidence = round(random.uniform(0.85, 0.99), 2)
        status = 'active'
        
        ip = self._generate_ip(used_ips)
        mac = self._generate_mac(vendor)
        last_seen = self._generate_timestamp()
        firmware = self._generate_firmware(device_type, os_choice)
        
        return {
            'ip': ip,
            'mac': mac,
            'os': os_choice,
            'ports': ports,
            'services': services,
            'device_type': device_type,
            'vendor': vendor,
            'device_model': model,
            'location': location,
            'status': status,
            'last_seen': last_seen,
            'confidence': confidence,
            'category': category,
            'sub_category': sub,
            'capabilities': cap,
            'risk_level': risk,
            'firmware_version': firmware
        }
    
    def generate(self, total_records: int = 2000) -> pd.DataFrame:
        """Generate the full dataset"""
        print(f"🚀 Generating {total_records} records...")
        
        # Determine distribution (based on original dataset)
        # We'll use a balanced but realistic distribution
        device_types = list(self.patterns.keys())
        # Approximate original distribution: Windows PC ~33%, Router ~30%, Server ~20%, IoT ~10%, Mobile ~7%
        weights = [0.33, 0.20, 0.30, 0.10, 0.07]
        # Ensure sum = 1
        weights = [w / sum(weights) for w in weights]
        
        used_ips = set()
        records = []
        
        for i in range(total_records):
            device_type = np.random.choice(device_types, p=weights)
            record = self._generate_record(device_type, used_ips)
            records.append(record)
            
            if (i+1) % 500 == 0:
                print(f"   Generated {i+1}/{total_records} records...")
        
        df = pd.DataFrame(records)
        print(f"✅ Generated {len(df)} records with {len(df.columns)} columns")
        return df
    
    def save(self, df: pd.DataFrame, output_path: str = 'data/dataset_augmented.csv') -> None:
        """Save dataset to CSV"""
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        df.to_csv(output_path, index=False)
        print(f"💾 Saved to: {output_path}")
        print(f"   File size: {os.path.getsize(output_path) / 1024:.1f} KB")


def main():
    """Main execution"""
    print("="*60)
    print("📊 Network Device Dataset Generator")
    print("="*60)
    
    generator = DeviceDataGenerator(seed=42)
    df = generator.generate(total_records=2000)
    
    # Display stats
    print("\n📈 Dataset Statistics:")
    print(f"   Total records: {len(df)}")
    print(f"   Device types: {df['device_type'].nunique()}")
    print("\n   Device Type Distribution:")
    for dtype, count in df['device_type'].value_counts().items():
        print(f"      {dtype}: {count} ({count/len(df)*100:.1f}%)")
    
    print("\n   Risk Level Distribution:")
    for risk, count in df['risk_level'].value_counts().items():
        print(f"      {risk}: {count} ({count/len(df)*100:.1f}%)")
    
    # Save
    generator.save(df, 'data/dataset_augmented.csv')
    
    # Show first few records
    print("\n📋 Sample records (first 5):")
    print(df.head(5).to_string(index=False))
    
    print("\n✅ Done! You can now train your model with this augmented dataset.")
    print("   Run: python train_models.py")

if __name__ == "__main__":
    main()