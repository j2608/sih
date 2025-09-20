#!/usr/bin/env python3
"""
Machine Learning Threat Detector for VNC Security
Implements Isolation Forest and feature engineering for anomaly detection
"""

import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import RobustScaler
from sklearn.metrics import classification_report, confusion_matrix
import joblib
import json
from datetime import datetime
import warnings
warnings.filterwarnings('ignore')

class VNCMLDetector:
    def __init__(self):
        self.model = None
        self.scaler = None
        self.feature_columns = None
        self.feature_importance = {}
        
    def engineer_features(self, sessions_df):
        """Engineer features from session data based on threat matrix"""
        df = sessions_df.copy()
        
        # Ratio features
        df['ratio_bytes_out_in'] = df['total_bytes_out'] / (df['total_bytes_in'] + 1)
        df['bytes_per_minute'] = df['total_bytes_out'] / (df['duration_seconds']/60 + 1)
        df['clipboard_bytes_ratio'] = df['total_clipboard_bytes'] / (df['total_bytes_out'] + 1)
        df['clip_events_per_min'] = df['num_clipboard_events'] / (df['duration_seconds']/60 + 1)
        df['screenshot_rate'] = df['num_screenshot_events'] / (df['duration_seconds']/60 + 1)
        df['file_transfer_rate'] = df['num_file_transfer_events'] / (df['duration_seconds']/60 + 1)
        df['avg_file_size'] = df['total_files_size_bytes'] / (df['total_files_transferred'] + 1)
        
        # Time-based features
        df['start_hour'] = pd.to_datetime(df['start_ts']).dt.hour
        df['unusual_time_flag'] = ((df['start_hour'] < 6) | (df['start_hour'] > 22)).astype(int)
        df['weekend_flag'] = pd.to_datetime(df['start_ts']).dt.weekday.isin([5, 6]).astype(int)
        
        # Security features
        df['low_trust_device'] = (df['device_trust_score'] < 0.5).astype(int)
        df['weak_auth'] = (df['auth_method'] == 'password').astype(int)
        df['unencrypted'] = (~df['is_encrypted']).astype(int)
        
        # Behavioral anomaly features
        df['high_clipboard_activity'] = (df['num_clipboard_events'] > 10).astype(int)
        df['high_screenshot_activity'] = (df['num_screenshot_events'] > 20).astype(int)
        df['large_file_transfer'] = (df['total_files_size_bytes'] > 10**7).astype(int)  # 10MB
        df['high_frame_rate'] = (df['avg_frame_rate'] > 12).astype(int)
        df['many_processes'] = (df['processes_spawned_count'] > 10).astype(int)
        
        # Statistical features
        df['bytes_out_zscore'] = (df['total_bytes_out'] - df['total_bytes_out'].mean()) / df['total_bytes_out'].std()
        df['duration_zscore'] = (df['duration_seconds'] - df['duration_seconds'].mean()) / df['duration_seconds'].std()
        
        return df
    
    def select_features(self, df):
        """Select relevant features for ML model"""
        feature_cols = [
            # Core metrics
            'duration_seconds', 'total_bytes_out', 'avg_bytes_per_sec_out',
            'num_clipboard_events', 'total_clipboard_bytes', 'num_screenshot_events',
            'num_file_transfer_events', 'total_files_size_bytes', 'avg_frame_rate',
            'processes_spawned_count', 'device_trust_score',
            
            # Engineered features
            'ratio_bytes_out_in', 'bytes_per_minute', 'clipboard_bytes_ratio',
            'clip_events_per_min', 'screenshot_rate', 'file_transfer_rate',
            'avg_file_size', 'unusual_time_flag', 'weekend_flag',
            'low_trust_device', 'weak_auth', 'unencrypted',
            'high_clipboard_activity', 'high_screenshot_activity',
            'large_file_transfer', 'high_frame_rate', 'many_processes',
            'bytes_out_zscore', 'duration_zscore'
        ]
        
        return df[feature_cols].fillna(0)
    
    def train(self, sessions_df, contamination=0.15):
        """Train the anomaly detection model"""
        print("🔄 Engineering features...")
        df_features = self.engineer_features(sessions_df)
        
        print("🔄 Selecting features...")
        X = self.select_features(df_features)
        self.feature_columns = X.columns.tolist()
        
        print("🔄 Scaling features...")
        self.scaler = RobustScaler()
        X_scaled = self.scaler.fit_transform(X)
        
        print("🔄 Training Isolation Forest...")
        self.model = IsolationForest(
            contamination=contamination,
            random_state=42,
            n_estimators=200,
            max_samples='auto',
            max_features=1.0
        )
        
        self.model.fit(X_scaled)
        
        # Calculate feature importance (approximation)
        self._calculate_feature_importance(X_scaled)
        
        print("✅ Model training completed!")
        return self
    
    def _calculate_feature_importance(self, X_scaled):
        """Calculate approximate feature importance for Isolation Forest"""
        # Use decision path lengths as proxy for importance
        scores = self.model.decision_function(X_scaled)
        
        importance_scores = {}
        for i, feature in enumerate(self.feature_columns):
            # Calculate correlation between feature and anomaly score
            feature_values = X_scaled[:, i]
            correlation = np.corrcoef(feature_values, scores)[0, 1]
            importance_scores[feature] = abs(correlation)
        
        # Normalize to sum to 1
        total = sum(importance_scores.values())
        self.feature_importance = {k: v/total for k, v in importance_scores.items()}
    
    def predict(self, sessions_df):
        """Predict anomalies in new session data"""
        if self.model is None:
            raise ValueError("Model not trained. Call train() first.")
        
        df_features = self.engineer_features(sessions_df)
        X = self.select_features(df_features)
        X_scaled = self.scaler.transform(X)
        
        # Get predictions and scores
        predictions = self.model.predict(X_scaled)  # 1 for normal, -1 for anomaly
        scores = self.model.decision_function(X_scaled)  # Higher = more normal
        
        # Convert to binary (1 for anomaly, 0 for normal)
        anomaly_predictions = (predictions == -1).astype(int)
        
        # Convert scores to risk scores (0-1, higher = more risky)
        risk_scores = 1 - ((scores - scores.min()) / (scores.max() - scores.min()))
        
        return anomaly_predictions, risk_scores
    
    def explain_prediction(self, session_data, top_n=5):
        """Explain why a session was flagged as anomalous"""
        if isinstance(session_data, pd.Series):
            session_df = pd.DataFrame([session_data])
        else:
            session_df = session_data.copy()
        
        df_features = self.engineer_features(session_df)
        X = self.select_features(df_features)
        
        # Get top contributing features
        feature_values = X.iloc[0].to_dict()
        
        # Sort features by importance and value
        explanations = []
        for feature, importance in sorted(self.feature_importance.items(), 
                                        key=lambda x: x[1], reverse=True)[:top_n]:
            value = feature_values.get(feature, 0)
            explanations.append({
                'feature': feature,
                'value': value,
                'importance': importance,
                'description': self._get_feature_description(feature, value)
            })
        
        return explanations
    
    def _get_feature_description(self, feature, value):
        """Get human-readable description of feature"""
        descriptions = {
            'bytes_per_minute': f'Data transfer rate: {value:.0f} bytes/min',
            'clipboard_bytes_ratio': f'Clipboard data ratio: {value:.2%}',
            'clip_events_per_min': f'Clipboard events: {value:.1f}/min',
            'screenshot_rate': f'Screenshot rate: {value:.1f}/min',
            'unusual_time_flag': 'Session during unusual hours' if value else 'Normal hours',
            'high_clipboard_activity': 'High clipboard activity' if value else 'Normal clipboard',
            'large_file_transfer': 'Large file transfer detected' if value else 'Normal file sizes',
            'low_trust_device': 'Low trust device' if value else 'Trusted device',
            'weak_auth': 'Weak authentication' if value else 'Strong authentication',
            'total_bytes_out': f'Total data out: {value/1024/1024:.1f} MB',
            'num_file_transfer_events': f'File transfers: {value:.0f}',
            'device_trust_score': f'Device trust: {value:.2f}'
        }
        
        return descriptions.get(feature, f'{feature}: {value:.2f}')
    
    def evaluate(self, sessions_df):
        """Evaluate model performance on labeled data"""
        if 'label' not in sessions_df.columns:
            print("⚠️  No labels available for evaluation")
            return None
        
        predictions, scores = self.predict(sessions_df)
        true_labels = (sessions_df['label'] == 'anomalous').astype(int)
        
        print("\n📊 Model Evaluation Results:")
        print("=" * 50)
        print(classification_report(true_labels, predictions, 
                                  target_names=['Normal', 'Anomalous']))
        
        print("\nConfusion Matrix:")
        cm = confusion_matrix(true_labels, predictions)
        print(f"True Negatives: {cm[0,0]}, False Positives: {cm[0,1]}")
        print(f"False Negatives: {cm[1,0]}, True Positives: {cm[1,1]}")
        
        # Calculate additional metrics
        precision = cm[1,1] / (cm[1,1] + cm[0,1]) if (cm[1,1] + cm[0,1]) > 0 else 0
        recall = cm[1,1] / (cm[1,1] + cm[1,0]) if (cm[1,1] + cm[1,0]) > 0 else 0
        
        print(f"\nPrecision: {precision:.3f}")
        print(f"Recall: {recall:.3f}")
        
        return {
            'precision': precision,
            'recall': recall,
            'confusion_matrix': cm.tolist(),
            'predictions': predictions,
            'scores': scores
        }
    
    def save_model(self, filepath='models/vnc_detector.joblib'):
        """Save trained model"""
        import os
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        
        model_data = {
            'model': self.model,
            'scaler': self.scaler,
            'feature_columns': self.feature_columns,
            'feature_importance': self.feature_importance
        }
        
        joblib.dump(model_data, filepath)
        print(f"✅ Model saved to {filepath}")
    
    def load_model(self, filepath='models/vnc_detector.joblib'):
        """Load trained model"""
        model_data = joblib.load(filepath)
        
        self.model = model_data['model']
        self.scaler = model_data['scaler']
        self.feature_columns = model_data['feature_columns']
        self.feature_importance = model_data['feature_importance']
        
        print(f"✅ Model loaded from {filepath}")
        return self

if __name__ == "__main__":
    # Demo training and evaluation
    from data_generator import VNCDataGenerator
    
    print("🚀 VNC ML Detector Demo")
    
    # Generate synthetic data
    generator = VNCDataGenerator()
    sessions_df, _, _ = generator.save_datasets()
    
    # Train model
    detector = VNCMLDetector()
    detector.train(sessions_df)
    
    # Evaluate
    results = detector.evaluate(sessions_df)
    
    # Save model
    detector.save_model()
    
    print("\n🎯 Top 5 Most Important Features:")
    for i, (feature, importance) in enumerate(
        sorted(detector.feature_importance.items(), key=lambda x: x[1], reverse=True)[:5]
    ):
        print(f"{i+1}. {feature}: {importance:.3f}")