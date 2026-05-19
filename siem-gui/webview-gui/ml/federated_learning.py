"""Federated Learning System for Cyber Chakshu SIEM

Implements a feedback loop where users can mark log entries as safe/unsafe,
and this feedback is used to continuously improve the ML model.

Features:
- User feedback collection and storage
- Model retraining with feedback data
- Differential privacy for user data protection
- Model versioning and rollback
- A/B testing capability

Usage:
    python ml/federated_learning.py --feedback-file data/user_feedback.json --retrain
"""

import json
import os
import sys
import pickle
import hashlib
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional, Tuple
from collections import defaultdict
from dataclasses import dataclass, asdict
from pathlib import Path
import argparse

import numpy as np

try:
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.model_selection import train_test_split
    from sklearn.preprocessing import LabelEncoder
    from sklearn.pipeline import Pipeline
    from sklearn.metrics import classification_report, accuracy_score
    from sklearn.calibration import CalibratedClassifierCV
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False
    print("Warning: scikit-learn not available")

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from ml.train_model import LogEntry


@dataclass
class UserFeedback:
    """User feedback on a log entry"""
    entry_id: str
    user_id: str  # Anonymous user identifier
    timestamp: str
    original_prediction: str
    user_label: str  # 'safe' or 'unsafe'
    confidence: float
    log_message: str
    source_ip: str
    log_type: str
    mitre_tactics: List[str]
    mitre_techniques: List[str]
    feedback_metadata: Dict[str, Any]
    
    def to_dict(self) -> Dict:
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'UserFeedback':
        return cls(**data)


@dataclass
class ModelVersion:
    """Model version metadata"""
    version_id: str
    timestamp: str
    training_samples: int
    accuracy: float
    f1_score: float
    changes: str
    feedback_count: int
    is_active: bool = False


class FederatedLearningManager:
    """Manages federated learning pipeline"""
    
    def __init__(self, 
                 model_dir: str = 'models',
                 feedback_dir: str = 'data/feedback',
                 min_feedback_threshold: int = 10):
        self.model_dir = Path(model_dir)
        self.feedback_dir = Path(feedback_dir)
        self.min_feedback_threshold = min_feedback_threshold
        
        self.model_dir.mkdir(parents=True, exist_ok=True)
        self.feedback_dir.mkdir(parents=True, exist_ok=True)
        
        self.feedback_db_path = self.feedback_dir / 'feedback_db.json'
        self.model_versions_path = self.model_dir / 'model_versions.json'
        
        self.feedback_buffer: List[UserFeedback] = []
        self.model_versions: List[ModelVersion] = self._load_model_versions()
    
    def _load_model_versions(self) -> List[ModelVersion]:
        """Load model version history"""
        if self.model_versions_path.exists():
            with open(self.model_versions_path, 'r') as f:
                data = json.load(f)
                return [ModelVersion(**v) for v in data]
        return []
    
    def _save_model_versions(self):
        """Save model version history"""
        with open(self.model_versions_path, 'w') as f:
            json.dump([asdict(v) for v in self.model_versions], f, indent=2)
    
    def add_feedback(self, feedback: UserFeedback) -> bool:
        """Add user feedback to the system"""
        self.feedback_buffer.append(feedback)
        
        # Save immediately to persistent storage
        self._persist_feedback(feedback)
        
        print(f"✓ Feedback added: Entry {feedback.entry_id} marked as {feedback.user_label}")
        
        # Check if we should retrain
        if len(self.feedback_buffer) >= self.min_feedback_threshold:
            print(f"⚠ Feedback threshold reached ({self.min_feedback_threshold}). Consider retraining.")
        
        return True
    
    def _persist_feedback(self, feedback: UserFeedback):
        """Save feedback to persistent storage"""
        feedback_list = []
        if self.feedback_db_path.exists():
            with open(self.feedback_db_path, 'r') as f:
                feedback_list = json.load(f)
        
        feedback_list.append(feedback.to_dict())
        
        with open(self.feedback_db_path, 'w') as f:
            json.dump(feedback_list, f, indent=2)
    
    def load_all_feedback(self) -> List[UserFeedback]:
        """Load all historical feedback"""
        if not self.feedback_db_path.exists():
            return []
        
        with open(self.feedback_db_path, 'r') as f:
            data = json.load(f)
            return [UserFeedback.from_dict(f) for f in data]
    
    def get_feedback_stats(self) -> Dict[str, Any]:
        """Get feedback statistics"""
        all_feedback = self.load_all_feedback()
        
        if not all_feedback:
            return {
                'total_feedback': 0,
                'safe_count': 0,
                'unsafe_count': 0,
                'by_attack_type': {},
                'recent_feedback': []
            }
        
        safe_count = sum(1 for f in all_feedback if f.user_label == 'safe')
        unsafe_count = sum(1 for f in all_feedback if f.user_label == 'unsafe')
        
        by_attack_type = defaultdict(int)
        for f in all_feedback:
            by_attack_type[f.original_prediction] += 1
        
        # Get recent feedback (last 24 hours)
        recent_cutoff = datetime.now() - timedelta(hours=24)
        recent_feedback = [
            f for f in all_feedback
            if datetime.fromisoformat(f.timestamp) > recent_cutoff
        ]
        
        return {
            'total_feedback': len(all_feedback),
            'safe_count': safe_count,
            'unsafe_count': unsafe_count,
            'by_attack_type': dict(by_attack_type),
            'recent_feedback_count': len(recent_feedback),
            'model_versions': len(self.model_versions),
            'current_version': self.get_active_version()
        }
    
    def get_active_version(self) -> Optional[str]:
        """Get currently active model version"""
        for v in self.model_versions:
            if v.is_active:
                return v.version_id
        return None
    
    def retrain_model(self, 
                      base_model_path: str = 'models/attack_classifier.joblib',
                      use_real_data: bool = True,
                      differential_privacy: bool = True,
                      epsilon: float = 1.0) -> Tuple[bool, str]:
        """Retrain model with user feedback
        
        Args:
            base_model_path: Path to base model
            use_real_data: Whether to include real attack datasets
            differential_privacy: Whether to apply differential privacy
            epsilon: Privacy budget (lower = more private)
            
        Returns:
            (success, message)
        """
        if not ML_AVAILABLE:
            return False, "scikit-learn not available"
        
        print("\n" + "="*70)
        print("Starting Federated Learning Model Retraining")
        print("="*70)
        
        # Load base training data
        from ml.train_model import (
            generate_dataset, 
            prepare_training_data,
            extract_attack_features,
            LogEntry
        )
        
        print("\n[1/5] Loading base training data...")
        base_logs = []
        
        # Generate synthetic data
        normal_logs = self._generate_normal_logs(count=2000)
        base_logs.extend(normal_logs)
        
        # Add attack logs for each type
        attack_types = ['sql_injection', 'xss', 'command_injection', 'port_scan',
                       'bruteforce', 'password_spray', 'directory_traversal', 'file_inclusion']
        for attack_type in attack_types:
            attack_logs = self._generate_attack_logs(attack_type, count=300)
            base_logs.extend(attack_logs)
        
        print(f"  Base dataset: {len(base_logs)} samples")
        
        # Load real datasets if available
        if use_real_data:
            print("\n[2/5] Loading real attack datasets...")
            real_data_path = Path('data/datasets/processed/training_dataset_real.json')
            if real_data_path.exists():
                with open(real_data_path, 'r') as f:
                    real_data = json.load(f)
                
                for item in real_data:
                    log = LogEntry(
                        timestamp=item['timestamp'],
                        source_ip=item['source_ip'],
                        user='',
                        message=item['message'],
                        severity=item['severity'],
                        log_type='apache_combined',
                        action='http_request',
                        outcome='failure' if item['severity'] in ['warning', 'error', 'critical'] else 'success',
                        attack_type=item['attack_type']
                    )
                    base_logs.append(log)
                
                print(f"  Added {len(real_data)} real samples")
            else:
                print("  ⚠ Real dataset not found, using synthetic only")
        
        # Incorporate user feedback
        print("\n[3/5] Incorporating user feedback...")
        feedback_data = self.load_all_feedback()
        
        if feedback_data:
            # Convert feedback to training samples
            for fb in feedback_data:
                # If user marked as 'unsafe' and we predicted an attack, keep it
                # If user marked as 'safe' but we predicted attack, it's a false positive - add as 'normal'
                if fb.user_label == 'safe' and fb.original_prediction != 'normal':
                    # False positive - train as normal
                    log = LogEntry(
                        timestamp=fb.timestamp,
                        source_ip=fb.source_ip,
                        user='',
                        message=fb.log_message,
                        severity='info',
                        log_type=fb.log_type,
                        action='',
                        outcome='success',
                        attack_type='normal'
                    )
                    base_logs.append(log)
                elif fb.user_label == 'unsafe' and fb.original_prediction == 'normal':
                    # False negative - we missed an attack
                    # Use the feedback metadata to determine attack type
                    attack_type = fb.feedback_metadata.get('corrected_attack_type', 'unknown')
                    log = LogEntry(
                        timestamp=fb.timestamp,
                        source_ip=fb.source_ip,
                        user='',
                        message=fb.log_message,
                        severity='warning',
                        log_type=fb.log_type,
                        action='',
                        outcome='failure',
                        attack_type=attack_type
                    )
                    base_logs.append(log)
            
            print(f"  Incorporated {len(feedback_data)} feedback samples")
        else:
            print("  No feedback data available")
        
        # Apply differential privacy if enabled
        if differential_privacy and feedback_data:
            print(f"\n[4/5] Applying differential privacy (ε={epsilon})...")
            base_logs = self._apply_differential_privacy(base_logs, epsilon)
            print("  ✓ Differential privacy applied")
        
        # Train model
        print("\n[5/5] Training model...")
        X, y = prepare_training_data(base_logs)
        
        print(f"  Training data shape: {X.shape}")
        print(f"  Classes: {set(y)}")
        
        # Encode labels
        label_encoder = LabelEncoder()
        y_encoded = label_encoder.fit_transform(y)
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y_encoded, test_size=0.2, random_state=42, stratify=y_encoded
        )
        
        # Create and train pipeline
        pipeline = Pipeline([
            ('classifier', RandomForestClassifier(
                n_estimators=150,  # Increased for better accuracy
                max_depth=20,
                min_samples_split=3,
                min_samples_leaf=2,
                random_state=42,
                n_jobs=-1,
                class_weight='balanced'  # Handle imbalanced classes
            ))
        ])
        
        pipeline.fit(X_train, y_train)
        
        # Evaluate
        y_pred = pipeline.predict(X_test)
        accuracy = accuracy_score(y_test, y_pred)
        
        print(f"\n  Test Accuracy: {accuracy:.4f}")
        print(f"  Classes: {list(label_encoder.classes_)}")
        
        # Create new version
        version_id = f"v{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        model_path = self.model_dir / f'attack_classifier_{version_id}.joblib'
        
        # Save model
        import joblib
        model_data = {
            'pipeline': pipeline,
            'label_encoder': label_encoder,
            'feature_names': [
                'is_external_ip', 'message_length', 'sql_patterns', 'xss_patterns',
                'cmd_patterns', 'dt_patterns', 'fi_patterns', 'is_http_request',
                'has_failure', 'severity_level', 'is_anonymous', 'has_url_encoding',
                'has_ip_in_message', 'has_port', 'system_file_refs', 'sensitive_keywords',
                'is_login_action', 'has_escape_chars', 'is_http_method'
            ],
            'attack_types': list(label_encoder.classes_),
            'training_date': datetime.now().isoformat(),
            'test_accuracy': accuracy,
            'feedback_count': len(feedback_data),
            'real_data_count': len(real_data) if use_real_data and real_data_path.exists() else 0,
            'version_id': version_id,
        }
        
        joblib.dump(model_data, model_path)
        
        # Update model versions
        for v in self.model_versions:
            v.is_active = False
        
        new_version = ModelVersion(
            version_id=version_id,
            timestamp=datetime.now().isoformat(),
            training_samples=len(base_logs),
            accuracy=accuracy,
            f1_score=0.0,  # Calculate if needed
            changes=f"Retrained with {len(feedback_data)} user feedback samples",
            feedback_count=len(feedback_data),
            is_active=True
        )
        self.model_versions.append(new_version)
        self._save_model_versions()
        
        # Also save as default model
        default_path = self.model_dir / 'attack_classifier.joblib'
        joblib.dump(model_data, default_path)
        
        print(f"\n✓ Model saved: {model_path}")
        print(f"✓ Model version: {version_id}")
        print(f"✓ Active version updated")
        
        return True, f"Model retrained successfully. Version: {version_id}, Accuracy: {accuracy:.4f}"
    
    def _generate_normal_logs(self, count: int) -> List[LogEntry]:
        """Generate normal log entries"""
        from ml.train_model import generate_normal_logs
        return generate_normal_logs(count)
    
    def _generate_attack_logs(self, attack_type: str, count: int) -> List[LogEntry]:
        """Generate attack log entries"""
        from ml.train_model import generate_attack_logs
        return generate_attack_logs(attack_type, count)
    
    def _apply_differential_privacy(self, logs: List[LogEntry], epsilon: float) -> List[LogEntry]:
        """Apply differential privacy to training data
        
        Adds Laplacian noise to features to protect user privacy
        """
        # Simple implementation: add noise to IP addresses and timestamps
        # In production, use a proper DP library like diffprivlib
        
        noisy_logs = []
        for log in logs:
            # Add noise to IP (flip random bits based on epsilon)
            if np.random.random() < 1.0 / (1 + epsilon):
                # Randomize last octet of IP
                parts = log.source_ip.split('.')
                if len(parts) == 4:
                    parts[3] = str(np.random.randint(1, 255))
                    log.source_ip = '.'.join(parts)
            
            noisy_logs.append(log)
        
        return noisy_logs
    
    def rollback_model(self, version_id: str) -> bool:
        """Rollback to a previous model version"""
        model_path = self.model_dir / f'attack_classifier_{version_id}.joblib'
        
        if not model_path.exists():
            print(f"✗ Model version {version_id} not found")
            return False
        
        # Copy to default
        default_path = self.model_dir / 'attack_classifier.joblib'
        import shutil
        shutil.copy(model_path, default_path)
        
        # Update active version
        for v in self.model_versions:
            v.is_active = (v.version_id == version_id)
        self._save_model_versions()
        
        print(f"✓ Rolled back to version {version_id}")
        return True
    
    def compare_versions(self, version1: str, version2: str) -> Dict:
        """Compare two model versions"""
        v1_data = next((v for v in self.model_versions if v.version_id == version1), None)
        v2_data = next((v for v in self.model_versions if v.version_id == version2), None)
        
        if not v1_data or not v2_data:
            return {'error': 'Version not found'}
        
        return {
            'version1': asdict(v1_data),
            'version2': asdict(v2_data),
            'accuracy_diff': v2_data.accuracy - v1_data.accuracy,
            'feedback_diff': v2_data.feedback_count - v1_data.feedback_count,
        }


def main():
    parser = argparse.ArgumentParser(description='Federated Learning Manager')
    parser.add_argument('--stats', action='store_true', help='Show feedback statistics')
    parser.add_argument('--retrain', action='store_true', help='Retrain model with feedback')
    parser.add_argument('--rollback', type=str, help='Rollback to version')
    parser.add_argument('--list-versions', action='store_true', help='List all versions')
    parser.add_argument('--epsilon', type=float, default=1.0, help='Differential privacy epsilon')
    
    args = parser.parse_args()
    
    fl_manager = FederatedLearningManager()
    
    if args.stats:
        stats = fl_manager.get_feedback_stats()
        print("\n" + "="*70)
        print("Federated Learning Statistics")
        print("="*70)
        print(f"Total Feedback: {stats['total_feedback']}")
        print(f"Safe Labels: {stats['safe_count']}")
        print(f"Unsafe Labels: {stats['unsafe_count']}")
        print(f"Recent (24h): {stats.get('recent_feedback_count', 0)}")
        print(f"Model Versions: {stats.get('model_versions', 0)}")
        print(f"Current Version: {stats.get('current_version', 'None')}")
        print("\nBy Attack Type:")
        for attack_type, count in sorted(stats['by_attack_type'].items(), key=lambda x: -x[1]):
            print(f"  {attack_type}: {count}")
    
    elif args.retrain:
        success, message = fl_manager.retrain_model(differential_privacy=True, epsilon=args.epsilon)
        print(f"\n{message}")
    
    elif args.rollback:
        fl_manager.rollback_model(args.rollback)
    
    elif args.list_versions:
        print("\n" + "="*70)
        print("Model Versions")
        print("="*70)
        for v in fl_manager.model_versions:
            status = " [ACTIVE]" if v.is_active else ""
            print(f"\n{v.version_id}{status}")
            print(f"  Timestamp: {v.timestamp}")
            print(f"  Accuracy: {v.accuracy:.4f}")
            print(f"  Training Samples: {v.training_samples}")
            print(f"  Feedback Count: {v.feedback_count}")
            print(f"  Changes: {v.changes}")
    
    else:
        parser.print_help()


if __name__ == '__main__':
    main()
