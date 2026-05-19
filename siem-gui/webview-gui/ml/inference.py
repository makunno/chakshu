"""
ML Inference Engine for SIEM
Lightweight inference using trained models with confidence scores
"""

import os
import json
import pickle
import numpy as np
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from datetime import datetime

MODELS_DIR = os.path.join(os.path.dirname(__file__), 'models')

@dataclass
class AttackPrediction:
    attack_type: str
    confidence: float
    probability: float
    is_attack: bool
    category: str
    explanation: str

class MLInferenceEngine:
    def __init__(self, models_dir: str = MODELS_DIR):
        self.models_dir = models_dir
        self.model = None
        self.vectorizer = None
        self.label_encoder = None
        self.use_category_models = False
        self.models_loaded = False
        
        self._load_models()
    
    def _load_models(self):
        """Load trained models"""
        print("Loading ML models...")
        
        # Load the new trained model
        model_path = os.path.join(self.models_dir, 'unified_model.pkl')
        vectorizer_path = os.path.join(self.models_dir, 'vectorizer.pkl')
        label_encoder_path = os.path.join(self.models_dir, 'label_encoder.pkl')
        
        if os.path.exists(model_path):
            try:
                with open(model_path, 'rb') as f:
                    self.model = pickle.load(f)
                print(f"  Loaded model from {model_path}")
            except Exception as e:
                print(f"  Error loading model: {e}")
                self.model = None
        
        if os.path.exists(vectorizer_path):
            try:
                with open(vectorizer_path, 'rb') as f:
                    self.vectorizer = pickle.load(f)
                print(f"  Loaded vectorizer")
            except Exception as e:
                print(f"  Error loading vectorizer: {e}")
                self.vectorizer = None
        
        if os.path.exists(label_encoder_path):
            try:
                with open(label_encoder_path, 'rb') as f:
                    self.label_encoder = pickle.load(f)
                print(f"  Loaded label encoder: {self.label_encoder.classes_}")
            except Exception as e:
                print(f"  Error loading label encoder: {e}")
                self.label_encoder = None
        
        if self.model and self.vectorizer and self.label_encoder:
            self.models_loaded = True
            print("ML models loaded successfully!")
        else:
            print("Warning: Not all models loaded, inference may not work properly")
    
    def predict(self, log_message: str, log_type: str = 'unknown') -> AttackPrediction:
        """Predict attack type for a log message"""
        
        if not self.models_loaded:
            return AttackPrediction(
                attack_type='unknown',
                confidence=0.0,
                probability=0.0,
                is_attack=False,
                category='unknown',
                explanation='ML model not loaded'
            )
        
        try:
            # Transform the log message
            X = self.vectorizer.transform([log_message])
            
            # Get prediction
            prediction = self.model.predict(X)[0]
            probabilities = self.model.predict_proba(X)[0]
            
            # Get the predicted class
            attack_type = self.label_encoder.inverse_transform([prediction])[0]
            confidence = float(probabilities[prediction])
            
            # Determine if it's an attack
            is_attack = attack_type not in ['safe', 'normal']
            
            # Generate explanation
            explanation = self._generate_explanation(attack_type, confidence, log_message)
            
            return AttackPrediction(
                attack_type=attack_type,
                confidence=confidence,
                probability=confidence,
                is_attack=is_attack,
                category=log_type,
                explanation=explanation
            )
            
        except Exception as e:
            print(f"Prediction error: {e}")
            return AttackPrediction(
                attack_type='unknown',
                confidence=0.0,
                probability=0.0,
                is_attack=False,
                category=log_type,
                explanation=f'Prediction error: {str(e)}'
            )
    
    def _generate_explanation(self, attack_type: str, confidence: float, log_message: str = '') -> str:
        """Generate human-readable explanation"""
        
        if attack_type in ['safe', 'normal']:
            return f"Normal activity detected (confidence: {confidence:.1%})"
        
        explanations = {
            'bruteforce': f"Multiple failed login attempts detected from same source (confidence: {confidence:.1%})",
            'password_spray': f"Multiple users targeted from single IP (confidence: {confidence:.1%})",
            'credential_stuffing': f"Using leaked credentials for authentication (confidence: {confidence:.1%})",
            'mfa_fatigue': f"Multiple MFA requests detected (confidence: {confidence:.1%})",
            'ddos': f"High volume of requests from multiple sources (confidence: {confidence:.1%})",
            'port_scan': f"Multiple ports accessed from single source (confidence: {confidence:.1%})",
            'sql_injection': f"SQL injection pattern detected in request (confidence: {confidence:.1%})",
            'xss_attack': f"Cross-site scripting pattern detected (confidence: {confidence:.1%})",
            'command_injection': f"Command injection pattern detected (confidence: {confidence:.1%})",
            'privilege_escalation': f"Privilege escalation attempt detected (confidence: {confidence:.1%})",
        }
        
        return explanations.get(attack_type, f"{attack_type} detected (confidence: {confidence:.1%})")

# Global instance
_inference_engine = None

def get_inference_engine() -> MLInferenceEngine:
    """Get or create the global inference engine"""
    global _inference_engine
    if _inference_engine is None:
        _inference_engine = MLInferenceEngine()
    return _inference_engine

def predict_attack(log_message: str, log_type: str = 'unknown') -> Dict[str, Any]:
    """Simple function to predict attack type"""
    engine = get_inference_engine()
    prediction = engine.predict(log_message, log_type)
    
    return {
        'attackType': prediction.attack_type,
        'confidence': prediction.confidence,
        'probability': prediction.probability,
        'isAttack': prediction.is_attack,
        'category': prediction.category,
        'explanation': prediction.explanation
    }

# Test if models are loaded
if __name__ == '__main__':
    engine = get_inference_engine()
    print(f"\nModels loaded: {engine.models_loaded}")
    
    if engine.models_loaded:
        # Test predictions
        test_logs = [
            ('Failed password for admin from 192.168.1.100 port 22 ssh2', 'ssh_auth'),
            ('Oct 10 10:15:33 server sudo: admin : TTY=pts/0 ; PWD=/home', 'auth'),
            ('GET /login?user=admin\' OR \'1\'=\'1 HTTP/1.1', 'apache'),
            ('Kernel: [IPTABLES DROP] IN=eth0 SRC=10.0.0.1 DST=10.0.0.2 PROTO=TCP DPT=22', 'firewall'),
            ('Accepted password for root from 10.0.0.1 port 22 ssh2', 'ssh_auth'),
        ]
        
        print("\nTesting predictions:")
        for log, log_type in test_logs:
            result = predict_attack(log, log_type)
            print(f"  {log[:50]}...")
            print(f"    -> {result['attackType']} ({result['confidence']:.2f})")
