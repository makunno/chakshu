"""
Feedback-based Retraining Script
Uses user feedback to improve ML models
"""

import os
import json
import pickle
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score
import shutil

DATA_DIR = os.path.join(os.path.dirname(__file__), 'data')
MODELS_DIR = os.path.join(os.path.dirname(__file__), 'models')
FEEDBACK_FILE = os.path.join(DATA_DIR, 'feedback.json')

def load_feedback():
    """Load user feedback data"""
    if not os.path.exists(FEEDBACK_FILE):
        print("No feedback data found")
        return []
    
    with open(FEEDBACK_FILE, 'r') as f:
        return json.load(f)

def retrain_with_feedback():
    """Retrain models with user feedback"""
    feedback = load_feedback()
    
    if len(feedback) < 10:
        print(f"Not enough feedback to retrain ({len(feedback)} samples, need 10)")
        return False
    
    print(f"Retraining with {len(feedback)} feedback samples...")
    
    # Create training data from feedback
    messages = []
    labels = []
    
    for item in feedback:
        messages.append(item['log_message'])
        
        if item['user_correct']:
            # Use the actual attack type provided by user
            labels.append(item['actual_attack'])
        else:
            # If user said prediction was wrong, use their correction
            labels.append(item['actual_attack'])
    
    # Load original training data
    original_data = []
    for category in ['webserver', 'database', 'auth', 'firewall', 'mail', 'network', 'system', 'cloud']:
        filepath = os.path.join(DATA_DIR, f'{category}_dataset.json')
        if os.path.exists(filepath):
            with open(filepath, 'r') as f:
                original_data.extend(json.load(f))
    
    # Add original data
    for item in original_data[:5000]:  # Limit to prevent overfitting
        messages.append(item['message'])
        labels.append(item['attack_type'])
    
    # Extract features
    vectorizer = TfidfVectorizer(max_features=500, ngram_range=(1, 2))
    X = vectorizer.fit_transform(messages).toarray()
    
    # Encode labels
    label_encoder = LabelEncoder()
    y = label_encoder.fit_transform(labels)
    
    # Split
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    # Train
    model = LogisticRegression(max_iter=1000, class_weight='balanced', C=0.5)
    model.fit(X_train, y_train)
    
    # Evaluate
    accuracy = accuracy_score(y_test, model.predict(X_test))
    print(f"Retrained model accuracy: {accuracy:.4f}")
    
    # Backup old model
    backup_path = os.path.join(MODELS_DIR, 'base_model_backup.pkl')
    if os.path.exists(os.path.join(MODELS_DIR, 'base_model.pkl')):
        shutil.copy(os.path.join(MODELS_DIR, 'base_model.pkl'), backup_path)
    
    # Save new model
    model_artifacts = {
        'model': model,
        'vectorizer': vectorizer,
        'label_encoder': label_encoder,
        'model_type': 'retrained_with_feedback',
        'accuracy': accuracy,
        'retrained_from_feedback': True
    }
    
    with open(os.path.join(MODELS_DIR, 'base_model.pkl'), 'wb') as f:
        pickle.dump(model_artifacts, f)
    
    print(f"Model retrained and saved!")
    
    # Clear feedback after successful retrain
    with open(FEEDBACK_FILE, 'w') as f:
        json.dump([], f)
    
    return True

def main():
    import sys
    if '--retrain' in sys.argv:
        retrain_with_feedback()
    else:
        feedback = load_feedback()
        print(f"Current feedback count: {len(feedback)}")
        print("Run with --retrain to retrain models")

if __name__ == '__main__':
    main()
