#!/usr/bin/env python3
"""
Real Network Scanner with ML Prediction
- Scans your actual network
- Uses trained ML model to classify devices
- Evaluates prediction accuracy
"""

import subprocess
import socket
import re
import json
import sqlite3
import sys
import os
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any, Optional
import logging
import joblib
import pandas as pd
import numpy as np

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# Import your feature extractor
try:
    from scripts.feature_extractor import DeviceFeatureExtractor
except ImportError:
    from feature_extractor import DeviceFeatureExtractor

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class RealNetworkScanner:
    """Real network scanner with ML prediction"""
    
    def __init__(self, db_path="data/network_scanner.db", model_path=None):
        self.db_path = db_path
        self.model = None
        self.scaler = None
        self.label_encoder = None
        self.feature_extractor = DeviceFeatureExtractor()
        self.feature_names = []
        
        # Load ML model if available
        self._load_model(model_path)
        
        # Get local network
        self.local_ip = self._get_local_ip()
        self.subnet = self._get_subnet()
    
    def _load_model(self, model_path=None):
        """Load the trained ML model"""
        try:
            if not model_path:
                # Find latest model
                model_dir = Path("data/models")
                if model_dir.exists():
                    models = sorted(model_dir.glob("device_classifier_*.pkl"))
                    if models:
                        model_path = str(models[-1])
            
            if model_path and Path(model_path).exists():
                data = joblib.load(model_path)
                self.model = data.get('model')
                self.scaler = data.get('scaler')
                self.label_encoder = data.get('label_encoder')
                self.feature_names = data.get('feature_names', [])
                logger.info(f"✅ ML model loaded from {model_path}")
                logger.info(f"   Model type: {type(self.model).__name__}")
                logger.info(f"   Features: {len(self.feature_names)}")
                return True
            else:
                logger.warning("⚠️ No ML model found. Device types will be 'Unknown'.")
                return False
                
        except Exception as e:
            logger.error(f"Error loading model: {e}")
            return False
    
    def _get_local_ip(self) -> str:
        """Get local IP address"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception as e:
            logger.error(f"Error getting local IP: {e}")
            return "192.168.1.100"
    
    def _get_subnet(self) -> str:
        """Get network subnet"""
        ip_parts = self.local_ip.split('.')
        return f"{'.'.join(ip_parts[:3])}.0/24"
    
    def scan_network(self, target_subnet=None) -> List[Dict]:
        """Scan network and return devices with ML predictions"""
        if target_subnet:
            self.subnet = target_subnet
        
        logger.info(f"🔍 Scanning network: {self.subnet}")
        
        # Try nmap first
        devices = self._scan_with_nmap()
        
        if not devices:
            logger.info("Nmap scan failed, falling back to ping scan...")
            devices = self._scan_with_ping()
        
        # Add ML predictions
        if devices:
            devices = self._predict_device_types(devices)
        
        return devices
    
    def _scan_with_nmap(self) -> List[Dict]:
        """Scan network using nmap"""
        try:
            # Check if nmap is available
            result = subprocess.run(['nmap', '--version'], capture_output=True, text=True)
            if result.returncode != 0:
                raise FileNotFoundError("nmap not found")
            
            logger.info("📡 Using nmap for device discovery...")
            
            # Run nmap ping scan
            result = subprocess.run(
                ['nmap', '-sn', self.subnet, '--host-timeout', '5s'],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            devices = []
            current_ip = None
            
            for line in result.stdout.split('\n'):
                line = line.strip()
                
                # Find IP
                if 'Nmap scan report for' in line:
                    ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                    if ip_match:
                        current_ip = ip_match.group(1)
                        
                        # Try to get hostname
                        hostname = ''
                        try:
                            hostname = socket.gethostbyaddr(current_ip)[0]
                        except:
                            pass
                        
                        devices.append({
                            'ip': current_ip,
                            'hostname': hostname,
                            'status': 'online'
                        })
            
            # Now do port scan for open ports (for better ML prediction)
            if devices:
                logger.info(f"   Found {len(devices)} devices. Scanning ports for ML features...")
                devices = self._scan_ports(devices)
            
            return devices
            
        except FileNotFoundError:
            logger.warning("Nmap not found. Install nmap for better results.")
            return []
        except subprocess.TimeoutExpired:
            logger.warning("Nmap scan timeout.")
            return []
        except Exception as e:
            logger.error(f"Error scanning with nmap: {e}")
            return []
    
    def _scan_with_ping(self) -> List[Dict]:
        """Fallback: Scan network using ping"""
        logger.info("📡 Using ping for device discovery...")
        
        devices = []
        base_ip = self.subnet.replace('/24', '')
        base = '.'.join(base_ip.split('.')[:3]) + '.'
        
        for i in range(1, 255):
            ip = f"{base}{i}"
            
            # Ping with timeout
            if sys.platform.startswith('win'):
                cmd = ['ping', '-n', '1', '-w', '1000', ip]
            else:
                cmd = ['ping', '-c', '1', '-W', '1', ip]
            
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=2)
                if result.returncode == 0:
                    hostname = ''
                    try:
                        hostname = socket.gethostbyaddr(ip)[0]
                    except:
                        pass
                    
                    devices.append({
                        'ip': ip,
                        'hostname': hostname,
                        'status': 'online'
                    })
                    
                    logger.info(f"   ✅ Found: {ip}")
            except:
                pass
        
        # Scan ports for discovered devices
        if devices:
            devices = self._scan_ports(devices)
        
        return devices
    
    def _scan_ports(self, devices: List[Dict]) -> List[Dict]:
        """Scan common ports on each device for ML features"""
        common_ports = [22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 3389, 3306, 5432, 8080]
        
        for device in devices:
            open_ports = []
            services = []
            
            for port in common_ports:
                if self._is_port_open(device['ip'], port):
                    open_ports.append(port)
                    service_name = self._get_service_name(port)
                    services.append({'service': service_name, 'port': port})
            
            device['open_ports'] = open_ports
            device['services'] = services
        
        return devices
    
    def _is_port_open(self, ip: str, port: int) -> bool:
        """Check if a port is open"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((ip, port))
            sock.close()
            return result == 0
        except:
            return False
    
    def _get_service_name(self, port: int) -> str:
        """Get service name from port number"""
        services = {
            22: 'openssh',
            23: 'telnet',
            25: 'smtp',
            53: 'dns',
            80: 'http',
            110: 'pop3',
            135: 'msrpc',
            139: 'netbios',
            143: 'imap',
            443: 'https',
            445: 'smb',
            3389: 'rdp',
            3306: 'mysql',
            5432: 'postgresql',
            8080: 'http-proxy'
        }
        return services.get(port, f'port_{port}')
    
    def _predict_device_types(self, devices: List[Dict]) -> List[Dict]:
        """Use ML model to predict device types"""
        
        if not self.model or not self.scaler:
            logger.warning("⚠️ No ML model available. Device types set to 'Unknown'.")
            for device in devices:
                device['predicted_type'] = 'Unknown'
                device['confidence'] = 0
                device['matched'] = False
            return devices
        
        try:
            # Prepare data for ML model
            df_data = []
            for device in devices:
                row = {
                    'ip': device.get('ip', ''),
                    'hostname': device.get('hostname', ''),
                    'open_ports': ','.join(str(p) for p in device.get('open_ports', [])),
                    'services': ','.join(s.get('service', '') for s in device.get('services', []))
                }
                df_data.append(row)
            
            if not df_data:
                return devices
            
            df = pd.DataFrame(df_data)
            
            # Extract ALL features
            feature_df = self.feature_extractor.extract_features(df)
            logger.info(f"   Extracted {len(feature_df.columns)} features")
            
            # ===== CRITICAL FIX: Only use features the model was trained on =====
            # Get the feature names from the model
            if self.feature_names:
                # Filter to only features the model knows
                available_features = [f for f in self.feature_names if f in feature_df.columns]
                
                if available_features:
                    feature_df = feature_df[available_features]
                    logger.info(f"   Using {len(available_features)} features that match the model")
                else:
                    # Fallback: use the first N features the model expects
                    expected_count = self.model.n_features_in_
                    logger.warning(f"   No matching features found, using first {expected_count} columns")
                    # Use first N columns
                    if len(feature_df.columns) >= expected_count:
                        feature_df = feature_df.iloc[:, :expected_count]
                    else:
                        # Pad with zeros
                        for i in range(expected_count - len(feature_df.columns)):
                            feature_df[f'padding_{i}'] = 0
            else:
                # If no feature names stored, use first N columns
                expected_count = self.model.n_features_in_
                logger.warning(f"   No feature names in model, using first {expected_count} columns")
                if len(feature_df.columns) >= expected_count:
                    feature_df = feature_df.iloc[:, :expected_count]
                else:
                    for i in range(expected_count - len(feature_df.columns)):
                        feature_df[f'padding_{i}'] = 0
            
            # Fill missing values
            feature_df = feature_df.fillna(0)
            
            # Ensure we have exactly the right number of features
            expected_features = self.model.n_features_in_
            if feature_df.shape[1] != expected_features:
                logger.warning(f"   Feature count mismatch: got {feature_df.shape[1]}, expected {expected_features}")
                # Pad or truncate to match
                if feature_df.shape[1] < expected_features:
                    for i in range(expected_features - feature_df.shape[1]):
                        feature_df[f'padding_{i}'] = 0
                else:
                    feature_df = feature_df.iloc[:, :expected_features]
            
            # Scale features
            X = feature_df.values
            X = np.nan_to_num(X, nan=0.0)
            
            # Predict
            predictions = self.model.predict(X)
            
            # Get probabilities if available
            if hasattr(self.model, 'predict_proba'):
                probabilities = self.model.predict_proba(X)
            else:
                probabilities = None
            
            # Map predictions to device types
            for i, device in enumerate(devices):
                if i < len(predictions):
                    pred_idx = predictions[i]
                    if self.label_encoder:
                        device['predicted_type'] = self.label_encoder.inverse_transform([pred_idx])[0]
                    else:
                        device['predicted_type'] = str(pred_idx)
                    
                    # Get confidence
                    if probabilities is not None:
                        device['confidence'] = float(max(probabilities[i])) * 100
                    else:
                        device['confidence'] = 0
                    
                    device['matched'] = True
                else:
                    device['predicted_type'] = 'Unknown'
                    device['confidence'] = 0
                    device['matched'] = False
            
            logger.info(f"✅ ML predictions added for {len(devices)} devices")
            
        except Exception as e:
            logger.error(f"Error predicting device types: {e}")
            import traceback
            traceback.print_exc()
            for device in devices:
                device['predicted_type'] = 'Unknown'
                device['confidence'] = 0
                device['matched'] = False
        
        return devices
    
    def evaluate_predictions(self, devices: List[Dict]) -> Dict:
        """Evaluate prediction accuracy"""
        results = {
            'total': len(devices),
            'correct': 0,
            'incorrect': 0,
            'unknown': 0,
            'confidence': []
        }
        
        for device in devices:
            if device.get('device_type') and device.get('predicted_type'):
                if device['device_type'] == device['predicted_type']:
                    results['correct'] += 1
                else:
                    results['incorrect'] += 1
            else:
                results['unknown'] += 1
            
            if device.get('confidence'):
                results['confidence'].append(device['confidence'])
        
        if results['confidence']:
            results['avg_confidence'] = sum(results['confidence']) / len(results['confidence'])
        else:
            results['avg_confidence'] = 0
        
        results['accuracy'] = (results['correct'] / results['total'] * 100) if results['total'] > 0 else 0
        
        return results
    
    def save_to_database(self, devices: List[Dict]):
        """Save scanned devices to database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            saved_count = 0
            for device in devices:
                try:
                    # Check if exists
                    cursor.execute('SELECT id FROM devices WHERE ip_address = ?', (device['ip'],))
                    existing = cursor.fetchone()
                    
                    # Determine device type
                    device_type = device.get('device_type') or device.get('predicted_type', 'Unknown')
                    
                    if existing:
                        # Update
                        cursor.execute('''
                            UPDATE devices SET 
                                hostname = ?,
                                device_type = ?,
                                os = ?,
                                mac_address = ?,
                                open_ports = ?,
                                services = ?,
                                last_seen = ?
                            WHERE ip_address = ?
                        ''', (
                            device.get('hostname', ''),
                            device_type,
                            device.get('os', 'Unknown'),
                            device.get('mac', ''),
                            json.dumps(device.get('open_ports', [])),
                            json.dumps(device.get('services', [])),
                            datetime.now().isoformat(),
                            device['ip']
                        ))
                    else:
                        # Insert
                        cursor.execute('''
                            INSERT INTO devices 
                            (ip_address, hostname, device_type, os, mac_address, 
                             open_ports, services, first_seen, last_seen)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                        ''', (
                            device['ip'],
                            device.get('hostname', ''),
                            device_type,
                            device.get('os', 'Unknown'),
                            device.get('mac', ''),
                            json.dumps(device.get('open_ports', [])),
                            json.dumps(device.get('services', [])),
                            datetime.now().isoformat(),
                            datetime.now().isoformat()
                        ))
                    
                    saved_count += 1
                    
                except Exception as e:
                    logger.error(f"Error saving device {device.get('ip')}: {e}")
                    continue
            
            conn.commit()
            conn.close()
            logger.info(f"✅ Saved {saved_count} devices to database")
            
        except Exception as e:
            logger.error(f"Database error: {e}")


# ============================================================================
# QUICK TEST
# ============================================================================

if __name__ == "__main__":
    print("=" * 60)
    print("🔍 REAL NETWORK SCANNER WITH ML PREDICTION")
    print("=" * 60)
    
    # Initialize scanner
    scanner = RealNetworkScanner()
    
    if not scanner.model:
        print("\n⚠️ No ML model found. Please train the model first:")
        print("   python scripts/train_with_features.py device_dataset.csv")
    
    print(f"\n📡 Your IP: {scanner.local_ip}")
    print(f"📡 Scanning subnet: {scanner.subnet}")
    print("\n" + "-" * 60)
    
    # Scan network
    devices = scanner.scan_network()
    
    if not devices:
        print("\n❌ No devices found. Check your network connection.")
        sys.exit(0)
    
    print(f"\n📊 Found {len(devices)} devices:")
    print("-" * 60)
    print(f"{'IP Address':<15} {'Predicted Type':<20} {'Confidence':<12} {'Hostname'}")
    print("-" * 60)
    
    for device in devices:
        ip = device.get('ip', '')
        dev_type = device.get('predicted_type', 'Unknown')
        confidence = f"{device.get('confidence', 0):.1f}%"
        hostname = device.get('hostname', '')[:20]
        print(f"{ip:<15} {dev_type:<20} {confidence:<12} {hostname}")
    
    # Ask user to verify/correct predictions
    print("\n" + "-" * 60)
    print("📝 Verify and correct predictions (helps improve the model):")
    print("   Press Enter to keep prediction, or type the correct type")
    
    for i, device in enumerate(devices):
        print(f"\n{i+1}. {device['ip']} - Predicted: {device.get('predicted_type', 'Unknown')}")
        correction = input(f"   Correct type: ").strip()
        if correction:
            device['device_type'] = correction
            device['verified'] = True
        else:
            device['device_type'] = device.get('predicted_type', 'Unknown')
            device['verified'] = False
    
    # Save to database
    print("\n💾 Saving devices to database...")
    scanner.save_to_database(devices)
    
    # Evaluate predictions
    verified_devices = [d for d in devices if d.get('verified')]
    if verified_devices:
        print("\n📊 Prediction Evaluation:")
        eval_results = scanner.evaluate_predictions(verified_devices)
        print(f"   Total Verified: {eval_results['total']}")
        print(f"   Correct: {eval_results['correct']}")
        print(f"   Incorrect: {eval_results['incorrect']}")
        print(f"   Accuracy: {eval_results['accuracy']:.1f}%")
        print(f"   Avg Confidence: {eval_results['avg_confidence']:.1f}%")
    print("\n" + "=" * 60)  
    print("✅ Done! Check the dashboard at http://localhost:5000/devices")
    print("=" * 60)