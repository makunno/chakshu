"""
ML Attack Classifier & Anomaly Detector
Uses trained models for attack detection and unsupervised learning for anomaly detection
"""

import os
import pickle
import numpy as np
import pandas as pd
from typing import List, Dict, Any, Optional
from datetime import datetime
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.feature_extraction.text import TfidfVectorizer

# Load the trained models
MODELS_DIR = os.path.join(os.path.dirname(__file__), '..', 'models')

# Global model state
model = None
vectorizer = None
label_encoder = None
anomaly_detector = None
scaler = None
feature_extractor = None
_models_loaded = False


class FeatureExtractor:
    """Extract numerical and semantic features from parsed log entries for anomaly detection"""
    
    def __init__(self, tfidf_max_features: int = 100):
        self.label_encoders = {}
        self.categorical_fields = ['logType', 'severity', 'action', 'outcome']
        self.numerical_fields = ['status', 'bytes', 'port', 'src_port', 'dst_port', 'duration_ms']
        self.tfidf_vectorizer = TfidfVectorizer(max_features=tfidf_max_features, stop_words='english')
        self._tfidf_fitted = False
        
    def extract(self, entries: List[Dict[str, Any]], fit: bool = False) -> pd.DataFrame:
        if not entries:
            return pd.DataFrame()
            
        data = []
        messages = []
        for entry in entries:
            features = {}
            
            # 1. Temporal features
            ts_str = entry.get('timestamp', '')
            try:
                ts = datetime.fromisoformat(ts_str) if ts_str else datetime.now()
                features['hour'] = ts.hour
                features['day_of_week'] = ts.weekday()
            except:
                features['hour'] = 0
                features['day_of_week'] = 0
                
            # 2. Categorical features
            for field in self.categorical_fields:
                val = entry.get(field, 'unknown')
                if isinstance(val, list):
                    val = val[0] if val else 'unknown'
                features[field] = str(val).lower()
                
            # 3. Numerical features
            fields_data = entry.get('fields', {})
            for field in self.numerical_fields:
                val = fields_data.get(field) or entry.get(field)
                try:
                    features[field] = float(val) if val is not None and str(val).replace('.', '', 1).isdigit() else 0.0
                except:
                    features[field] = 0.0
                    
            # 4. Content features (Length/Entropy)
            msg = entry.get('message', '') or entry.get('rawLine', '')
            messages.append(msg)
            features['msg_len'] = len(msg)
            features['msg_entropy'] = self._calculate_entropy(msg)
            
            data.append(features)
            
        df = pd.DataFrame(data)
        
        # Encode categorical features
        for field in self.categorical_fields:
            if field in df.columns:
                le = LabelEncoder()
                df[field] = le.fit_transform(df[field].astype(str))
        
        # 5. NLP: TF-IDF Vectorization
        try:
            if fit:
                tfidf_matrix = self.tfidf_vectorizer.fit_transform(messages)
                self._tfidf_fitted = True
            elif self._tfidf_fitted:
                tfidf_matrix = self.tfidf_vectorizer.transform(messages)
            else:
                # Fallback if not fitted
                tfidf_matrix = None
                
            if tfidf_matrix is not None:
                tfidf_df = pd.DataFrame(
                    tfidf_matrix.toarray(), 
                    columns=[f'tfidf_{i}' for i in range(tfidf_matrix.shape[1])]
                )
                df = pd.concat([df, tfidf_df], axis=1)
        except Exception as e:
            print(f"TF-IDF extraction failed: {e}")
                
        return df

    def _calculate_entropy(self, text: str) -> float:
        if not text:
            return 0.0
        probs = [text.count(c) / len(text) for c in set(text)]
        return -sum(p * np.log2(p) for p in probs)


def _load_models():
    """Load trained models"""
    global model, vectorizer, label_encoder, anomaly_detector, scaler, feature_extractor, _models_loaded
    
    if _models_loaded:
        return
    
    model_path = os.path.join(MODELS_DIR, 'unified_model.pkl')
    vectorizer_path = os.path.join(MODELS_DIR, 'vectorizer.pkl')
    label_encoder_path = os.path.join(MODELS_DIR, 'label_encoder.pkl')
    anomaly_model_path = os.path.join(MODELS_DIR, 'anomaly_detector.pkl')
    scaler_path = os.path.join(MODELS_DIR, 'scaler.pkl')
    extractor_path = os.path.join(MODELS_DIR, 'feature_extractor.pkl')
    
    try:
        if os.path.exists(model_path):
            with open(model_path, 'rb') as f:
                model = pickle.load(f)
        
        if os.path.exists(vectorizer_path):
            with open(vectorizer_path, 'rb') as f:
                vectorizer = pickle.load(f)
        
        if os.path.exists(label_encoder_path):
            with open(label_encoder_path, 'rb') as f:
                label_encoder = pickle.load(f)
        
        if os.path.exists(anomaly_model_path):
            with open(anomaly_model_path, 'rb') as f:
                anomaly_detector = pickle.load(f)
        
        if os.path.exists(scaler_path):
            with open(scaler_path, 'rb') as f:
                scaler = pickle.load(f)
                
        if os.path.exists(extractor_path):
            with open(extractor_path, 'rb') as f:
                feature_extractor = pickle.load(f)
        
        _models_loaded = True
        print("ML models loaded successfully!")
    except Exception as e:
        print(f"Error loading models: {e}")
        _models_loaded = False


def train_anomaly_detector(entries: List[Dict[str, Any]]):
    """Train unsupervised anomaly detector on provided entries (baseline)"""
    global anomaly_detector, scaler, feature_extractor
    
    if len(entries) < 10:
        return
        
    feature_extractor = FeatureExtractor(tfidf_max_features=50)
    df = feature_extractor.extract(entries, fit=True)
    
    scaler = StandardScaler()
    X = scaler.fit_transform(df)
    
    # Contamination parameter: expected proportion of outliers
    anomaly_detector = IsolationForest(contamination=0.05, random_state=42)
    anomaly_detector.fit(X)
    
    # Save models
    os.makedirs(MODELS_DIR, exist_ok=True)
    with open(os.path.join(MODELS_DIR, 'anomaly_detector.pkl'), 'wb') as f:
        pickle.dump(anomaly_detector, f)
    with open(os.path.join(MODELS_DIR, 'scaler.pkl'), 'wb') as f:
        pickle.dump(scaler, f)
    with open(os.path.join(MODELS_DIR, 'feature_extractor.pkl'), 'wb') as f:
        pickle.dump(feature_extractor, f)
        
    print(f"Anomaly detector trained on {len(entries)} entries with NLP.")


def detect_ml_attacks(entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Detect attacks using ML models and return results aligned with entries"""
    if not entries:
        return []
    
    _load_models()
    
    # Initialize empty predictions for all entries
    all_predictions = [None] * len(entries)
    
    # 1. Supervised Classification (known attack patterns)
    if _models_loaded and model and vectorizer and label_encoder:
        messages = [e.get('message', '') or e.get('rawLine', '') for e in entries]
        try:
            X = vectorizer.transform(messages)
            preds = model.predict(X)
            probas = model.predict_proba(X)
            
            for i, (pred, proba) in enumerate(zip(preds, probas)):
                attack_type = label_encoder.inverse_transform([pred])[0]
                confidence = float(proba[pred])
                
                if attack_type not in ['safe', 'normal'] and confidence >= 0.3:
                    all_predictions[i] = {
                        'attackType': attack_type,
                        'confidence': confidence,
                        'explanation': [f"Classified as {attack_type} (conf: {confidence:.1%})"],
                        'isAnomaly': False
                    }
        except Exception as e:
            print(f"Supervised ML error: {e}")

    # 2. Unsupervised Anomaly Detection (behavioral outliers)
    if _models_loaded and anomaly_detector and scaler and feature_extractor:
        try:
            df = feature_extractor.extract(entries)
            X = scaler.transform(df)
            
            # Scores: higher is more normal, lower is more anomalous
            scores = anomaly_detector.decision_function(X)
            is_anomaly = anomaly_detector.predict(X) # -1 for anomaly, 1 for normal
            
            for i, (score, pred) in enumerate(zip(scores, is_anomaly)):
                if pred == -1: # It's an anomaly
                    # If we already have a classification, just add anomaly flag
                    anomaly_score = float((1 - score) / 2) # Normalize to 0-1
                    if all_predictions[i]:
                        all_predictions[i]['isAnomaly'] = True
                        all_predictions[i]['anomalyScore'] = anomaly_score
                        all_predictions[i]['explanation'].append(f"Content anomaly detected (score: {anomaly_score:.2f})")
                    else:
                        all_predictions[i] = {
                            'attackType': 'anomaly',
                            'confidence': anomaly_score,
                            'explanation': [f"Content anomaly detected (score: {anomaly_score:.2f})"],
                            'isAnomaly': True,
                            'anomalyScore': anomaly_score
                        }
        except Exception as e:
            print(f"Unsupervised anomaly error: {e}")
            
    return all_predictions


def enrich_entries_with_attacks(entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Enrich entries with attack detection results"""
    results = detect_ml_attacks(entries)
    for i, res in enumerate(results):
        if res:
            entries[i].update({
                'attackType': res['attackType'],
                'attackConfidence': res['confidence'],
                'isAnomaly': res.get('isAnomaly', False),
                'anomalyScore': res.get('anomalyScore', 0),
                'explanation': res['explanation']
            })
            # Also update overall severity if it's a high-confidence attack
            if res['confidence'] > 0.7:
                entries[i]['severity'] = 'high' if entries[i]['severity'] != 'critical' else 'critical'
    return entries
