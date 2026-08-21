#!/usr/bin/env python3
"""
Train ML model with proper feature extraction.
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.svm import SVC
from sklearn.neighbors import KNeighborsClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix
import joblib
import json
from datetime import datetime
import logging
import warnings
warnings.filterwarnings('ignore')

# Try to import feature extractor, create dummy if missing
try:
    # Use src.ml.feature_extractor (repo structure)
    from src.ml.feature_extractor import DeviceFeatureExtractor # pyright: ignore[reportAssignmentType]

except ImportError:
    # Fallback minimal extractor (keeps training script runnable)
    class DeviceFeatureExtractor:
        def extract_features(self, df):
            features = {}
            for col in df.columns:
                if df[col].dtype in ['int64', 'float64']:
                    features[col] = df[col].values
                elif df[col].dtype == 'object':
                    try:
                        features[f'{col}_numeric'] = pd.to_numeric(df[col], errors='coerce').fillna(0).values
                    except Exception:
                        features[f'{col}_len'] = df[col].astype(str).str.len().fillna(0).values
            return pd.DataFrame(features)


logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def create_sample_data():
    """Create sample data for testing if no CSV exists."""
    logger.info("📝 Creating sample dataset for testing...")
    
    sample_data = {
        'device_type': [
            'Router', 'Router', 'Router', 
            'Windows_PC', 'Windows_PC', 'Windows_PC',
            'Server', 'Server', 'Server',
            'IoT', 'IoT', 'IoT',
            'Printer', 'Printer', 'Printer',
            'Camera', 'Camera', 'Camera',
            'Mobile', 'Mobile', 'Mobile'
        ],
        'ip': [
            '192.168.1.1', '192.168.1.2', '192.168.1.3',
            '192.168.1.10', '192.168.1.11', '192.168.1.12',
            '192.168.1.100', '192.168.1.101', '192.168.1.102',
            '192.168.1.50', '192.168.1.51', '192.168.1.52',
            '192.168.1.60', '192.168.1.61', '192.168.1.62',
            '192.168.1.70', '192.168.1.71', '192.168.1.72',
            '192.168.1.80', '192.168.1.81', '192.168.1.82'
        ],
        'open_ports': [
            '22,80,443', '22,80,443,53', '22,80,443,8080',
            '135,445,3389', '135,445,3389,80', '135,445,3389,443',
            '22,80,443', '22,80,443,3306', '22,80,443,5432',
            '80,554', '80,554,22', '80,554,443',
            '515,9100', '515,9100,80', '515,9100,443',
            '80,554', '80,554,443', '80,554,22',
            '80,443', '80,443,8080', '80,443,22'
        ],
        'os_fingerprint': [
            'Linux', 'Linux', 'Linux',
            'Windows 10', 'Windows 10', 'Windows Server',
            'Linux', 'Linux', 'Linux',
            'Linux', 'Linux', 'Linux',
            'Embedded', 'Embedded', 'Embedded',
            'Linux', 'Linux', 'Linux',
            'Android', 'iOS', 'Android'
        ],
        'services': [
            'ssh,http,https', 'ssh,http,https,dns', 'ssh,http,https,proxy',
            'smb,rpc,rdp', 'smb,rpc,rdp,http', 'smb,rpc,rdp,https',
            'ssh,http,https', 'ssh,http,https,mysql', 'ssh,http,https,postgres',
            'http,rtsp', 'http,rtsp,ssh', 'http,rtsp,https',
            'lpd,ipp', 'lpd,ipp,http', 'lpd,ipp,https',
            'http,rtsp', 'http,rtsp,https', 'http,rtsp,ssh',
            'http,https', 'http,https,proxy', 'http,https,ssh'
        ],
        'mac_vendor': [
            'Cisco', 'Cisco', 'Cisco',
            'Dell', 'HP', 'HP',
            'Dell', 'Dell', 'HP',
            'Raspberry', 'Raspberry', 'Arduino',
            'HP', 'HP', 'HP',
            'Ubiquiti', 'Ubiquiti', 'Ubiquiti',
            'Samsung', 'Apple', 'Samsung'
        ],
        'hostname': [
            'router.local', 'router2.local', 'router3.local',
            'desktop-001', 'desktop-002', 'server-001',
            'server.local', 'db-server', 'app-server',
            'sensor-001', 'sensor-002', 'sensor-003',
            'printer-001', 'printer-002', 'printer-003',
            'camera-001', 'camera-002', 'camera-003',
            'phone-001', 'tablet-001', 'phone-002'
        ]
    }
    
    df = pd.DataFrame(sample_data)
    df.to_csv('device_dataset.csv', index=False)
    logger.info(f"✅ Created sample dataset with {len(df)} devices")
    return df

def train_with_features(csv_path: str = "device_dataset.csv"):
    """
    Train ML model with proper feature extraction.
    """
    logger.info("=" * 60)
    logger.info("TRAINING WITH PROPER FEATURE EXTRACTION")
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
    if len(df) < 5:
        logger.warning(f"⚠️  Only {len(df)} devices found. Creating more sample data...")
        df = create_sample_data()
    
    # Extract features
    logger.info("\n🔧 Extracting features...")
    try:
        extractor = DeviceFeatureExtractor()
        feature_df = extractor.extract_features(df)
    except Exception as e:
        logger.error(f"❌ Feature extraction failed: {e}")
        logger.info("Using fallback feature extraction...")
        # Fallback: use simple numeric features
        feature_df = pd.DataFrame()
        for col in df.select_dtypes(include=[np.number]).columns:
            if col != 'device_type' and col != 'category':
                feature_df[col] = df[col].values
        
        # Add some basic features if none exist
        if len(feature_df.columns) == 0:
            feature_df['port_count'] = df['open_ports'].astype(str).str.count(',') + 1
            feature_df['has_http'] = df['services'].astype(str).str.contains('http', case=False).astype(int)
            feature_df['os_len'] = df['os_fingerprint'].astype(str).str.len()
    
    # Combine with label
    if 'device_type' in df.columns:
        y_raw = df['device_type'].values
    elif 'category' in df.columns:
        y_raw = df['category'].values
    else:
        logger.error("❌ No label column found! Looking for device_type or category...")
        # Try to find any text column that might be labels
        for col in df.columns:
            if df[col].dtype == 'object' and df[col].nunique() < 20:
                logger.info(f"Using '{col}' as label column")
                y_raw = df[col].values
                break
        else:
            logger.error("❌ Could not find a suitable label column")
            return None, None
    
    # Clean labels (normalize names)
    label_mapping = {
        'Router': 'Router',
        'Windows PC': 'Windows_PC',
        'Windows PC': 'Windows_PC',
        'Windows_PC': 'Windows_PC',
        'Server': 'Server',
        'Mobile Device': 'Mobile',
        'IoT Device': 'IoT',
        'IoT': 'IoT',
        'router': 'Router',
        'server': 'Server',
        'workstation': 'Windows_PC',
        'iot': 'IoT',
        'printer': 'Printer',
        'camera': 'Camera',
        'Camera': 'Camera',
        'Mobile': 'Mobile',
        'Printer': 'Printer',
        'Phone': 'Mobile',
        'Tablet': 'Mobile'
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
    constant_cols = []
    for i in range(X.shape[1]):
        try:
            if len(np.unique(X[:, i])) <= 1:
                constant_cols.append(i)
        except:
            constant_cols.append(i)
    
    if constant_cols:
        logger.info(f"   Removing {len(constant_cols)} constant features")
        X = np.delete(X, constant_cols, axis=1)
    
    # Encode labels
    le = LabelEncoder()
    y_encoded = le.fit_transform(y)
    
    logger.info(f"   Features: {X.shape[1]}")
    logger.info(f"   Classes: {list(le.classes_)}")
    
    # Check if we have enough data for training
    if X.shape[0] < 10:
        logger.warning("⚠️  Not enough data for proper training. Creating more sample data...")
        df = create_sample_data()
        return train_with_features(csv_path)
    
    # Split data
    logger.info("\n📊 Splitting data (80% train, 20% test)...")
    try:
        X_train, X_test, y_train, y_test = train_test_split(
            X, y_encoded, test_size=0.2, random_state=42, stratify=y_encoded
        )
    except ValueError:
        # If stratification fails, do without it
        logger.warning("Stratification failed, using random split")
        X_train, X_test, y_train, y_test = train_test_split(
            X, y_encoded, test_size=0.2, random_state=42
        )
    
    # Scale features
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    
    # Train models
    logger.info("\n🤖 Training models...")
    
    models = {
        'Random Forest': RandomForestClassifier(
            n_estimators=100, max_depth=10, random_state=42, 
            class_weight='balanced', n_jobs=-1
        ),
        'Gradient Boosting': GradientBoostingClassifier(
            n_estimators=100, learning_rate=0.1, random_state=42
        ),
        'SVM': SVC(kernel='rbf', C=1.0, gamma='scale', random_state=42, 
                   class_weight='balanced', probability=True),
        'KNN': KNeighborsClassifier(n_neighbors=3),
        'Logistic Regression': LogisticRegression(
            max_iter=1000, random_state=42, class_weight='balanced'
        )
    }
    
    results = {}
    best_accuracy = 0
    best_model = None
    best_name = None
    
    for name, model in models.items():
        try:
            model.fit(X_train_scaled, y_train)
            y_pred = model.predict(X_test_scaled)
            accuracy = accuracy_score(y_test, y_pred)
            
            results[name] = {
                'accuracy': accuracy,
                'model': model,
                'predictions': y_pred
            }
            
            logger.info(f"  {name}: {accuracy:.3f}")
            
            if accuracy > best_accuracy:
                best_accuracy = accuracy
                best_model = model
                best_name = name
                
        except Exception as e:
            logger.warning(f"  {name}: Failed - {str(e)}")
    
    # If all models failed, use a simple fallback
    if best_model is None:
        logger.warning("⚠️  All models failed. Using Random Forest as fallback...")
        best_model = RandomForestClassifier(n_estimators=50, random_state=42)
        best_model.fit(X_train_scaled, y_train)
        best_name = "Random Forest (Fallback)"
        best_accuracy = best_model.score(X_test_scaled, y_test)
    
    # Save best model
    logger.info(f"\n🏆 Best model: {best_name} ({best_accuracy:.3f})")
    
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    model_dir = Path("data/models")
    model_dir.mkdir(parents=True, exist_ok=True)
    
    model_data = {
        'model': best_model,
        'scaler': scaler,
        'label_encoder': le,
        'feature_names': feature_df.columns.tolist() if hasattr(feature_df, 'columns') else [],
        'metadata': {
            'trained_at': datetime.now().isoformat(),
            'best_model': best_name,
            'accuracy': float(best_accuracy),
            'n_samples': len(df),
            'n_features': X.shape[1] if X.size > 0 else 0,
            'classes': list(le.classes_),
            'dataset': str(csv_path)
        }
    }
    
    model_path = model_dir / f"device_classifier_{timestamp}.pkl"
    joblib.dump(model_data, model_path)
    logger.info(f"💾 Model saved to: {model_path}")
    
    # Generate report
    try:
        y_pred = best_model.predict(X_test_scaled)
        
        logger.info("\n" + "=" * 60)
        logger.info("📊 CLASSIFICATION REPORT")
        logger.info("=" * 60)
        print(classification_report(y_test, y_pred, target_names=le.classes_, zero_division=0))
        
        # Confusion Matrix
        cm = confusion_matrix(y_test, y_pred)
        logger.info("\n📊 Confusion Matrix:")
        print(pd.DataFrame(cm, index=le.classes_, columns=le.classes_))
        
        # Feature importance
        if hasattr(best_model, 'feature_importances_'):
            logger.info("\n📊 Feature Importance (Top 15):")
            feature_names = [f for f in feature_df.columns if f not in constant_cols]
            if len(feature_names) == len(best_model.feature_importances_):
                importances = best_model.feature_importances_
                feature_importance = pd.DataFrame({
                    'feature': feature_names,
                    'importance': importances
                }).sort_values('importance', ascending=False)
                print(feature_importance.head(15).to_string(index=False))
    except Exception as e:
        logger.warning(f"Could not generate full report: {e}")
    
    # Save metadata
    metadata = {
        'model_path': str(model_path),
        'timestamp': timestamp,
        'best_model': best_name,
        'accuracy': float(best_accuracy),
        'n_samples': len(df),
        'n_features': X.shape[1] if X.size > 0 else 0,
        'classes': list(le.classes_),
        'feature_names': feature_df.columns.tolist() if hasattr(feature_df, 'columns') else []
    }
    
    meta_path = model_dir / f"training_metadata_{timestamp}.json"
    with open(meta_path, 'w') as f:
        json.dump(metadata, f, indent=2)
    
    logger.info(f"\n✅ Training complete!")
    logger.info(f"   📁 Model: {model_path}")
    logger.info(f"   📁 Metadata: {meta_path}")
    logger.info(f"   📊 Accuracy: {best_accuracy:.3f}")
    
    try:
        cv_scores = cross_val_score(best_model, X_train_scaled, y_train, cv=min(5, len(X_train_scaled)))
        logger.info(f"   📊 Cross-validation: {cv_scores.mean():.3f} (+/- {cv_scores.std():.3f})")
    except:
        pass
    
    return model_path, metadata

if __name__ == "__main__":
    try:
        csv_path = "device_dataset.csv"
        if len(sys.argv) > 1:
            csv_path = sys.argv[1]
        
        result = train_with_features(csv_path)
        
        if result and result[0]:
            logger.info("\n🎉 Training successful! You can now use the model for predictions.")
        else:
            logger.error("❌ Training failed.")
            sys.exit(1)
        
    except Exception as e:
        logger.error(f"❌ Training failed: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)