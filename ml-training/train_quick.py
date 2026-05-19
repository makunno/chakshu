"""
Quick Training Script for Enhanced SIEM ML Model
Uses the new enhanced dataset to train a better classifier
"""

import os
import json
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score
import pickle
import warnings
warnings.filterwarnings('ignore')

DATA_DIR = './data'
OUTPUT_DIR = './models'

def load_combined_data():
    """Load the enhanced combined training dataset"""
    filepath = os.path.join(DATA_DIR, 'combined_training.json')
    if os.path.exists(filepath):
        with open(filepath, 'r') as f:
            data = json.load(f)
        return pd.DataFrame(data)
    else:
        print("Combined dataset not found, loading individual datasets...")
        all_data = []
        for cat in ['auth', 'firewall', 'webserver', 'database']:
            filepath = os.path.join(DATA_DIR, f'{cat}_dataset_v2.json')
            if os.path.exists(filepath):
                with open(filepath, 'r') as f:
                    all_data.extend(json.load(f))
        return pd.DataFrame(all_data)

def extract_features(texts, vectorizer=None, fit=True):
    """Extract features using TF-IDF"""
    if fit:
        vectorizer = TfidfVectorizer(
            max_features=1000,
            ngram_range=(1, 3),
            min_df=2,
            max_df=0.95,
            sublinear_tf=True
        )
        features = vectorizer.fit_transform(texts)
    else:
        features = vectorizer.transform(texts)
    
    return features, vectorizer

def train_model():
    print("Loading enhanced dataset...")
    df = load_combined_data()
    
    print(f"Total samples: {len(df)}")
    print(f"Attack type distribution:")
    print(df['attack_type'].value_counts())
    
    # Handle class imbalance - we'll use balanced class weights
    X_text = df['message'].values
    y = df['attack_type'].values
    
    # Encode labels
    label_encoder = LabelEncoder()
    y_encoded = label_encoder.fit_transform(y)
    
    print(f"\nClasses: {label_encoder.classes_}")
    
    # Split data
    X_train_text, X_test_text, y_train, y_test = train_test_split(
        X_text, y_encoded, test_size=0.2, random_state=42, stratify=y_encoded
    )
    
    # Extract features
    print("\nExtracting features...")
    X_train, vectorizer = extract_features(X_train_text, fit=True)
    X_test, _ = extract_features(X_test_text, vectorizer=vectorizer, fit=False)
    
    print(f"Feature shape: {X_train.shape}")
    
    # Train model
    print("\nTraining model...")
    model = LogisticRegression(
        max_iter=1000,
        class_weight='balanced',
        C=1.0,
        solver='lbfgs',
        multi_class='multinomial',
        random_state=42,
        n_jobs=-1
    )
    model.fit(X_train, y_train)
    
    # Evaluate
    print("\nEvaluating model...")
    y_pred = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    print(f"\nAccuracy: {accuracy:.4f}")
    
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=label_encoder.classes_))
    
    # Save model
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    
    model_path = os.path.join(OUTPUT_DIR, 'unified_model.pkl')
    vectorizer_path = os.path.join(OUTPUT_DIR, 'vectorizer.pkl')
    label_encoder_path = os.path.join(OUTPUT_DIR, 'label_encoder.pkl')
    
    with open(model_path, 'wb') as f:
        pickle.dump(model, f)
    with open(vectorizer_path, 'wb') as f:
        pickle.dump(vectorizer, f)
    with open(label_encoder_path, 'wb') as f:
        pickle.dump(label_encoder, f)
    
    print(f"\nModel saved to {model_path}")
    print(f"Vectorizer saved to {vectorizer_path}")
    print(f"Label encoder saved to {label_encoder_path}")
    
    return model, vectorizer, label_encoder

if __name__ == '__main__':
    train_model()
