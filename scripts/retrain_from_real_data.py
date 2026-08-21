#!/usr/bin/env python3
"""
Retrain ML model using real device data from the database
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import sqlite3
import pandas as pd
import numpy as np
import json
from datetime import datetime
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler
import joblib

from scripts.feature_extractor import DeviceFeatureExtractor

def retrain_model(db_path="data/network_scanner.db"):
    """Retrain model using real device data from database"""
    
    print("=" * 60)
    print("🔄 RETRAINING MODEL WITH REAL DEVICE DATA")
    print("=" * 60)
    
    # Connect to database
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Get devices with verified types
    cursor.execute('''
        SELECT ip_address, hostname, device_type, open_ports, services
        FROM devices
        WHERE device_type IS NOT NULL AND device_type != 'Unknown'
    ''')
    
    rows = cursor.fetchall()
    
    if len(rows) < 10:
        print(f"⚠️ Only {len(rows)} devices found. Need at least 10 for training.")
        print("   Scan more devices or add more data first!")
        conn.close()
        return
    
    print(f"📊 Found {len(rows)} devices with verified types")
    
    # Create DataFrame
    data = []
    for row in rows:
        try:
            open_ports = json.loads(row[3]) if row[3] else []
            services = json.loads(row[4]) if row[4] else []
            service_names = [s.get('service', '') for s in services] if services else []
            
            data.append({
                'ip': row[0],
                'hostname': row[1] or '',
                'device_type': row[2],
                'open_ports': ','.join(str(p) for p in open_ports),
                'services': ','.join(service_names)
            })
        except:
            continue
    
    if len(data) < 10:
        print(f"⚠️ Only {len(data)} devices after cleaning. Need at least 10.")
        conn.close()
        return
    
    df = pd.DataFrame(data)
    
    # Extract features
    extractor = DeviceFeatureExtractor()
    feature_df = extractor.extract_features(df)
    
    # Prepare labels
    y = df['device_type'].values
    le = LabelEncoder()
    y_encoded = le.fit_transform(y)
    
    # Select features (use all)
    X = feature_df.values
    X = np.nan_to_num(X, nan=0.0)
    
    # Remove constant features
    constant_cols = []
    for i in range(X.shape[1]):
        if len(np.unique(X[:, i])) <= 1:
            constant_cols.append(i)
    
    if constant_cols:
        print(f"   Removing {len(constant_cols)} constant features")
        X = np.delete(X, constant_cols, axis=1)
    
    print(f"📊 Training with {X.shape[1]} features, {len(le.classes_)} classes")
    print(f"   Classes: {list(le.classes_)}")
    
    # Split and train
    X_train, X_test, y_train, y_test = train_test_split(
        X, y_encoded, test_size=0.2, random_state=42
    )
    
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    
    # Train Random Forest
    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=10,
        random_state=42,
        class_weight='balanced'
    )
    model.fit(X_train_scaled, y_train)
    
    # Evaluate
    accuracy = model.score(X_test_scaled, y_test)
    print(f"📊 Accuracy: {accuracy:.2%}")
    
    # Save model
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    model_dir = Path("data/models")
    model_dir.mkdir(parents=True, exist_ok=True)
    
    model_data = {
        'model': model,
        'scaler': scaler,
        'label_encoder': le,
        'feature_names': feature_df.columns.tolist(),
        'metadata': {
            'trained_at': datetime.now().isoformat(),
            'accuracy': float(accuracy),
            'n_samples': len(df),
            'n_features': X.shape[1],
            'classes': list(le.classes_),
            'data_source': 'real_network_scan',
            'n_devices': len(df)
        }
    }
    
    model_path = model_dir / f"device_classifier_real_{timestamp}.pkl"
    joblib.dump(model_data, model_path)
    print(f"💾 Model saved to: {model_path}")
    
    # Show feature importance
    if hasattr(model, 'feature_importances_'):
        importances = model.feature_importances_
        feature_importance = pd.DataFrame({
            'feature': feature_df.columns,
            'importance': importances
        }).sort_values('importance', ascending=False)
        
        print("\n🔍 Top 10 Most Important Features:")
        for _, row in feature_importance.head(10).iterrows():
            print(f"   {row['feature']}: {row['importance']:.4f}")
    
    conn.close()
    print("\n✅ Retraining complete!")
    print(f"   New model: {model_path.name}")
    print(f"   Accuracy: {accuracy:.2%}")
    
    return model_path

if __name__ == "__main__":
    retrain_model()