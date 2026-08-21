"""
Feature Aligner - Match extracted features to model expectations
"""

import pandas as pd
import numpy as np
import joblib
from pathlib import Path
import logging

logger = logging.getLogger(__name__)

class FeatureAligner:
    """Align features from extractor to model expectations"""
    
    def __init__(self, model_path=None):
        self.model_data = None
        self.model = None
        self.scaler = None
        self.label_encoder = None
        self.expected_features = []
        
        # Load model
        if not model_path:
            model_dir = Path("data/models")
            if model_dir.exists():
                models = sorted(model_dir.glob("device_classifier_*.pkl"))
                if models:
                    model_path = str(models[-1])
        
        if model_path:
            self.load_model(model_path)
    
    def load_model(self, model_path):
        """Load model and extract feature info"""
        try:
            self.model_data = joblib.load(model_path)
            self.model = self.model_data.get('model')
            self.scaler = self.model_data.get('scaler')
            self.label_encoder = self.model_data.get('label_encoder')
            self.expected_features = self.model_data.get('feature_names', [])
            
            # If no feature names stored, try to infer from model
            if not self.expected_features and hasattr(self.model, 'feature_importances_'):
                # Use generic feature names
                n_features = self.model.n_features_in_
                self.expected_features = [f'feature_{i}' for i in range(n_features)]
            
            logger.info(f"Model expects {len(self.expected_features)} features")
            return True
        except Exception as e:
            logger.error(f"Error loading model: {e}")
            return False
    
    def align_features(self, feature_df):
        """Align extracted features to model expectations"""
        if not self.expected_features:
            logger.warning("No expected features defined, returning original")
            return feature_df
        
        # Create aligned dataframe
        aligned_df = pd.DataFrame()
        
        # Try to match by name
        for feat in self.expected_features:
            if feat in feature_df.columns:
                aligned_df[feat] = feature_df[feat]
            else:
                # Feature not found, use 0
                aligned_df[feat] = 0
        
        # Ensure correct number of features
        if len(aligned_df.columns) != len(self.expected_features):
            logger.warning(f"Feature count mismatch: {len(aligned_df.columns)} vs {len(self.expected_features)}")
            # Pad or truncate
            if len(aligned_df.columns) < len(self.expected_features):
                for i in range(len(self.expected_features) - len(aligned_df.columns)):
                    aligned_df[f'padding_{i}'] = 0
            else:
                aligned_df = aligned_df.iloc[:, :len(self.expected_features)]
        
        return aligned_df
    
    def predict(self, feature_df):
        """Predict using aligned features"""
        if not self.model:
            logger.error("No model loaded")
            return None, None
        
        # Align features
        aligned_df = self.align_features(feature_df)
        
        # Fill missing values
        aligned_df = aligned_df.fillna(0)
        
        # Scale
        X = aligned_df.values
        X = np.nan_to_num(X, nan=0.0)
        
        if self.scaler:
            X = self.scaler.transform(X)
        
        # Predict
        predictions = self.model.predict(X)
        
        # Get probabilities
        if hasattr(self.model, 'predict_proba'):
            probabilities = self.model.predict_proba(X)
        else:
            probabilities = None
        
        return predictions, probabilities


# Test
if __name__ == "__main__":
    from feature_extractor import DeviceFeatureExtractor
    
    # Load aligner
    aligner = FeatureAligner()
    
    # Test with sample data
    df = pd.DataFrame({
        'open_ports': ['22,80,443,3306'],
        'services': ['ssh,http,https,mysql'],
        'os_fingerprint': ['Linux'],
        'ip': ['192.168.1.1'],
        'hostname': ['server.local']
    })
    
    # Extract features
    extractor = DeviceFeatureExtractor()
    features = extractor.extract_features(df)
    
    print(f"Extracted {len(features.columns)} features")
    print(f"Model expects {len(aligner.expected_features)} features")
    
    # Align
    aligned = aligner.align_features(features)
    print(f"Aligned to {len(aligned.columns)} features")
    
    if aligner.model:
        preds, probs = aligner.predict(features)
        if preds is not None:
            print(f"Prediction: {aligner.label_encoder.inverse_transform(preds)[0]}") # type: ignore