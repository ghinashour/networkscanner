
#!/usr/bin/env python3
"""
Train ML model with proper feature extraction, hyperparameter tuning, and cross-validation.
"""

import sys
import os
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.svm import SVC
from sklearn.neighbors import KNeighborsClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split, cross_val_score, GridSearchCV, StratifiedKFold
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix
from sklearn.pipeline import Pipeline
import joblib
import json
from datetime import datetime
import logging
import warnings

warnings.filterwarnings("ignore")

# Initialize logger FIRST before using it
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# Import the actual feature extractor
try:
    from src.ml.feature_extractor import DeviceFeatureExtractor
    logger.info("✅ Successfully imported DeviceFeatureExtractor from src.ml.feature_extractor")
except ImportError:
    logger.error("❌ Failed to import DeviceFeatureExtractor. Ensure src/ml/feature_extractor.py exists and is correct.")
    sys.exit(1)

def create_sample_data():
    """Create sample data for testing if no CSV exists. Expanded for better diversity."""
    logger.info("📝 Creating an expanded sample dataset for testing...")
    
    sample_data = {
        'device_type': [
            'Router', 'Router', 'Router', 'Router', 'Router',
            'Windows_PC', 'Windows_PC', 'Windows_PC', 'Windows_PC',
            'Server', 'Server', 'Server', 'Server',
            'IoT', 'IoT', 'IoT', 'IoT', 'IoT', 'IoT',
            'Printer', 'Printer',
            'Mobile', 'Mobile', 'Mobile', 'Mobile'
        ],
        'ip': [
            '192.168.1.1', '192.168.1.2', '192.168.1.3', '192.168.1.4', '192.168.1.5',
            '192.168.1.10', '192.168.1.11', '192.168.1.12', '192.168.1.13',
            '192.168.1.100', '192.168.1.101', '192.168.1.102', '192.168.1.103',
            '192.168.1.50', '192.168.1.51', '192.168.1.52', '192.168.1.53', '192.168.1.54', '192.168.1.55',
            '192.168.1.60', '192.168.1.61',
            '192.168.1.80', '192.168.1.81', '192.168.1.82', '192.168.1.83'
        ],
        'open_ports': [
            '22,80,443,53,67,68', '22,80,443,53,69', '80,443,161,162', '23,80,443', '53,67,68,1723',
            '135,445,3389', '135,445,3389,80', '135,445,8080', '445,5900',
            '22,80,443,3306', '22,80,443,5432', '22,80,443,27017', '80,443,9200,9300',
            '80,554,1900', '80,554,22,1883', '80,554,443,8883', '80,554,5683', '80,554,3702', '80,554,4242',
            '515,9100', '515,9100,80',
            '80,443,5223', '80,443,5228', '80,443,8883', '80,443,5684'
        ],
        'os_fingerprint': [
            'Linux', 'Linux', 'Linux', 'Embedded', 'Linux',
            'Windows 10', 'Windows 10', 'Windows Server', 'Windows 7',
            'Linux', 'Linux', 'Linux', 'Linux',
            'Embedded Linux', 'Embedded Linux', 'Embedded Linux', 'FreeRTOS', 'BusyBox', 'OpenWrt',
            'Embedded', 'Embedded',
            'Android', 'iOS', 'Android', 'iOS'
        ],
        'services': [
            'ssh,http,https,dns,dhcp', 'ssh,http,https,dns,tftp', 'http,https,snmp', 'telnet,http,https', 'dns,dhcp,pptp',
            'smb,rpc,rdp', 'smb,rpc,rdp,http', 'smb,rpc,http-alt', 'smb,vnc',
            'ssh,http,https,mysql', 'ssh,http,https,postgresql', 'ssh,http,https,mongodb', 'http,https,elastic',
            'http,rtsp,upnp', 'http,rtsp,ssh,mqtt', 'http,rtsp,https,mqtts', 'http,rtsp,coap', 'http,rtsp,onvif', 'http,rtsp,psia',
            'lpd,ipp', 'lpd,ipp,http',
            'http,https,apple-push', 'http,https,google-push', 'http,https,mqtts', 'http,https,coap'
        ],
        'mac_vendor': [
            'Cisco', 'Cisco', 'Netgear', 'TP-Link', 'Ubiquiti',
            'Dell', 'HP', 'Lenovo', 'Microsoft',
            'Dell', 'HP', 'IBM', 'Oracle',
            'Raspberry', 'Arduino', 'Espressif', 'Ubiquiti', 'Microchip', 'Broadcom',
            'HP', 'Canon',
            'Samsung', 'Apple', 'Google', 'Apple'
        ],
        'hostname': [
            'router.local', 'gateway.local', 'ap-01', 'wifi-router', 'firewall',
            'desktop-win10', 'laptop-hp', 'server-win', 'workstation-pc',
            'db-server', 'web-server', 'app-server', 'elastic-node',
            'sensor-temp', 'camera-front', 'iot-hub', 'smart-plug', 'recorder-nvr', 'home-gateway',
            'printer-hp', 'printer-canon',
            'iphone-user', 'galaxy-phone', 'pixel-tablet', 'ipad-pro'
        ],
        'ttl': [
            64, 64, 64, 64, 64,
            128, 128, 128, 128,
            64, 64, 64, 64,
            64, 64, 64, 64, 64, 64,
            64, 64,
            64, 64, 64, 64
        ]
    }
    
    df = pd.DataFrame(sample_data)
    df.to_csv('device_dataset.csv', index=False)
    logger.info(f"✅ Created expanded sample dataset with {len(df)} devices")
    return df

def train_device_classifier(csv_path: str = "device_dataset.csv"):
    """
    Train ML model with proper feature extraction, hyperparameter tuning, and cross-validation.
    """
    logger.info("=" * 60)
    logger.info("TRAINING DEVICE CLASSIFIER WITH ENHANCED FEATURES")
    logger.info("=" * 60)
    
    # Check if CSV exists, create sample if not
    if not Path(csv_path).exists():
        logger.warning(f"⚠️  {csv_path} not found. Creating sample data...")
        df = create_sample_data()
    else:
        # Load data
        logger.info(f"\n📊 Loading dataset from: {csv_path}")
        df = pd.read_csv(csv_path)
        logger.info(f"✅ Loaded {len(df)} devices")
    
    # Check if we have enough data
    if len(df) < 20: # Increased threshold for better training
        logger.warning(f"⚠️  Only {len(df)} devices found. Creating more sample data...")
        df = create_sample_data()
    
    # Initialize feature extractor
    extractor = DeviceFeatureExtractor()
    
    # Extract features
    logger.info("\n🔧 Extracting features...")
    feature_df = extractor.extract_features(df)
    
    # Add TTL feature (numerical)
    if 'ttl' in df.columns:
        feature_df['ttl'] = df['ttl'].fillna(0) # Fill NaN TTLs with 0
        logger.info("Added 'ttl' as a feature.")
    
    # Combine with label
    if 'device_type' in df.columns:
        y_raw = df['device_type'].values
    elif 'category' in df.columns:
        y_raw = df['category'].values
    else:
        logger.error("❌ No label column found! Looking for device_type or category...")
        sys.exit(1)
    
    # Clean labels (normalize names)
    label_mapping = {
        'Router': 'Router',
        'Windows PC': 'Windows_PC',
        'Windows_PC': 'Windows_PC',
        'Server': 'Server',
        'Mobile Device': 'Mobile',
        'IoT Device': 'IoT',
        'IoT': 'IoT',
        'Printer': 'Printer',
        'Camera': 'Camera',
        'Mobile': 'Mobile',
        'Phone': 'Mobile',
        'Tablet': 'Mobile',
        'Embedded Linux': 'IoT',
        'Embedded': 'IoT',
        'FreeRTOS': 'IoT',
        'BusyBox': 'IoT',
        'OpenWrt': 'IoT',
        'Windows 7': 'Windows_PC',
        'Windows Server': 'Server'
    }
    
    y = np.array([label_mapping.get(str(label), str(label)) for label in y_raw])
    
    # Show distribution
    logger.info("\n📊 Label distribution:")
    label_counts = pd.Series(y).value_counts()
    for label, count in label_counts.items():
        percentage = (count / len(y)) * 100
        logger.info(f"  {label}: {count} ({percentage:.1f}%)")
    
    # Prepare features
    X = feature_df.values
    X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)
    
    # Remove constant features (all zeros or all same value)
    initial_feature_names = feature_df.columns.tolist()
    constant_cols_indices = []
    for i in range(X.shape[1]):
        if len(np.unique(X[:, i])) <= 1:
            constant_cols_indices.append(i)
    
    if constant_cols_indices:
        logger.info(f"   Removing {len(constant_cols_indices)} constant features")
        X = np.delete(X, constant_cols_indices, axis=1)
        feature_names = [name for i, name in enumerate(initial_feature_names) if i not in constant_cols_indices]
    else:
        feature_names = initial_feature_names

    # Encode labels
    le = LabelEncoder()
    y_encoded = le.fit_transform(y)
    
    logger.info(f"   Features: {X.shape[1]}")
    logger.info(f"   Classes: {list(le.classes_)}")
    
    # Check if we have enough data for training after feature extraction
    if X.shape[0] < 10 or X.shape[1] == 0:
        logger.error("❌ Not enough data or features for proper training after extraction.")
        sys.exit(1)
    
    # Split data
    logger.info("\n📊 Splitting data (80% train, 20% test) with stratification...")
    try:
        X_train, X_test, y_train, y_test = train_test_split(
            X, y_encoded, test_size=0.2, random_state=42, stratify=y_encoded
        )
    except ValueError as e:
        logger.warning(f"⚠️ Stratification failed: {e}. Using random split.")
        X_train, X_test, y_train, y_test = train_test_split(
            X, y_encoded, test_size=0.2, random_state=42
        )
    
    # Define models and their parameter grids for GridSearchCV
    pipelines = {
        'Random Forest': Pipeline([
            ('scaler', StandardScaler()),
            ('classifier', RandomForestClassifier(random_state=42, class_weight='balanced'))
        ]),
        'Gradient Boosting': Pipeline([
            ('scaler', StandardScaler()),
            ('classifier', GradientBoostingClassifier(random_state=42))
        ]),
        'SVM': Pipeline([
            ('scaler', StandardScaler()),
            ('classifier', SVC(random_state=42, class_weight='balanced', probability=True))
        ]),
        'Logistic Regression': Pipeline([
            ('scaler', StandardScaler()),
            ('classifier', LogisticRegression(random_state=42, class_weight='balanced', max_iter=1000))
        ])
    }

    param_grids = {
        'Random Forest': {
            'classifier__n_estimators': [50, 100, 200],
            'classifier__max_depth': [5, 10, 15, None]
        },
        'Gradient Boosting': {
            'classifier__n_estimators': [50, 100, 200],
            'classifier__learning_rate': [0.01, 0.1, 0.2]
        },
        'SVM': {
            'classifier__C': [0.1, 1, 10],
            'classifier__gamma': ['scale', 'auto']
        },
        'Logistic Regression': {
            'classifier__C': [0.1, 1, 10],
            'classifier__solver': ['liblinear', 'lbfgs']
        }
    }
    
    results = {}
    best_accuracy = 0
    best_pipeline = None
    best_name = None
    
    logger.info("\n🤖 Training and tuning models with GridSearchCV...")
    
    for name, pipeline in pipelines.items():
        logger.info(f"  Tuning {name}...")
        try:
            # Use StratifiedKFold for cross-validation to handle potential class imbalance
            cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
            grid_search = GridSearchCV(pipeline, param_grids[name], cv=cv, scoring='accuracy', n_jobs=-1, verbose=0)
            grid_search.fit(X_train, y_train)
            
            y_pred = grid_search.predict(X_test)
            accuracy = accuracy_score(y_test, y_pred)
            
            results[name] = {
                'accuracy': accuracy,
                'best_params': grid_search.best_params_,
                'best_score': grid_search.best_score_,
                'model': grid_search.best_estimator_,
                'predictions': y_pred
            }
            
            logger.info(f"  {name} - Best CV Score: {grid_search.best_score_:.3f}, Test Accuracy: {accuracy:.3f}")
            
            if accuracy > best_accuracy:
                best_accuracy = accuracy
                best_pipeline = grid_search.best_estimator_
                best_name = name
                
        except Exception as e:
            logger.warning(f"  {name}: Failed - {str(e)}")
    
    # If all models failed, use a simple fallback (should not happen with proper data)
    if best_pipeline is None:
        logger.warning("⚠️  All models failed or no best model found. Using a default Random Forest as fallback...")
        fallback_pipeline = Pipeline([
            ('scaler', StandardScaler()),
            ('classifier', RandomForestClassifier(n_estimators=100, random_state=42, class_weight='balanced'))
        ])
        fallback_pipeline.fit(X_train, y_train)
        best_pipeline = fallback_pipeline
        best_name = "Random Forest (Fallback)"
        best_accuracy = best_pipeline.score(X_test, y_test)
        logger.info(f"  Fallback Random Forest Test Accuracy: {best_accuracy:.3f}")
    
    # Save best model pipeline
    logger.info(f"\n🏆 Best model: {best_name} (Test Accuracy: {best_accuracy:.3f})")
    
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    model_dir = Path("data/models")
    model_dir.mkdir(parents=True, exist_ok=True)
    
    model_path = model_dir / f"device_classifier_pipeline_{timestamp}.pkl"
    joblib.dump({
        'pipeline': best_pipeline,
        'label_encoder': le,
        'feature_names': feature_names,
        'metadata': {
            'trained_at': datetime.now().isoformat(),
            'best_model': best_name,
            'test_accuracy': float(best_accuracy),
            'n_samples': len(df),
            'n_features': X.shape[1],
            'classes': list(le.classes_),
            'dataset': str(csv_path),
            'best_params': results.get(best_name, {}).get('best_params', {})
        }
    }, model_path)
    logger.info(f"💾 Model pipeline saved to: {model_path}")
    
    # Generate report
    try:
        y_pred = best_pipeline.predict(X_test)
        
        logger.info("\n" + "=" * 60)
        logger.info("📊 CLASSIFICATION REPORT")
        logger.info("=" * 60)
        print(classification_report(y_test, y_pred, target_names=le.classes_, zero_division=0))
        
        # Confusion Matrix
        cm = confusion_matrix(y_test, y_pred)
        logger.info("\n📊 Confusion Matrix:")
        print(pd.DataFrame(cm, index=le.classes_, columns=le.classes_))
        
        # Feature importance (if applicable)
        if hasattr(best_pipeline.named_steps['classifier'], 'feature_importances_'):
            logger.info("\n📊 Feature Importance (Top 15):")
            importances = best_pipeline.named_steps['classifier'].feature_importances_
            feature_importance = pd.DataFrame({
                'feature': feature_names,
                'importance': importances
            }).sort_values('importance', ascending=False)
            print(feature_importance.head(15).to_string(index=False))
        elif hasattr(best_pipeline.named_steps['classifier'], 'coef_'):
            logger.info("\n📊 Feature Coefficients (Top 15 for first class):")
            coefs = best_pipeline.named_steps['classifier'].coef_[0] # For multi-class, inspect one class
            feature_coef = pd.DataFrame({
                'feature': feature_names,
                'coefficient': coefs
            }).sort_values('coefficient', ascending=False)
            print(feature_coef.head(15).to_string(index=False))
            
    except Exception as e:
        logger.warning(f"Could not generate full report: {e}")
    
    logger.info("\n🎉 Training successful!")
    logger.info(f"   📁 Model pipeline: {model_path}")
    logger.info(f"   📊 Best Test Accuracy: {best_accuracy:.3f}")
    
    return model_path

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description='Train ML model for device classification.')
    parser.add_argument('--csv', default='device_dataset.csv', help='Path to the dataset CSV file.')
    args = parser.parse_args()
    
    try:
        train_device_classifier(args.csv)
    except Exception as e:
        logger.error(f"❌ Training failed: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
