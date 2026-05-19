"""
SIEM ML Training Pipeline
Trains a base model and fine-tunes for each log category
"""

import os
import json
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.metrics import classification_report, accuracy_score, f1_score
import pickle
import warnings
warnings.filterwarnings('ignore')

# Try to import transformers for advanced embeddings
try:
    from transformers import AutoTokenizer, AutoModel
    import torch
    TRANSFORMERS_AVAILABLE = True
    print("Transformers available - will use BERT embeddings")
except ImportError:
    TRANSFORMERS_AVAILABLE = False
    print("Transformers not available - will use TF-IDF")

DATA_DIR = './data'
OUTPUT_DIR = './models'

# Attack type mapping
ATTACK_TYPES = [
    'normal', 'bruteforce', 'password_spray', 'credential_stuffing',
    'mfa_bypass', 'mfa_fatigue', 'session_hijacking', 'account_takeover',
    'sql_injection', 'xss_attack', 'path_traversal', 'command_injection',
    'privilege_escalation', 'lateral_movement', 'data_exfiltration',
    'port_scan', 'ddos', 'reconnaissance', 'dns_tunneling',
    'malware_activity', 'c2_communication', 'insider_threat',
    'phishing', 'spam', 'cryptomining', 'ransomware'
]

LOG_CATEGORIES = ['webserver', 'database', 'auth', 'firewall', 'mail', 'network', 'system', 'cloud']

def load_data(category: str = None):
    """Load dataset for a category or all categories"""
    all_data = []
    
    if category:
        files = [f'{category}_dataset.json']
    else:
        files = [f'{cat}_dataset.json' for cat in LOG_CATEGORIES]
    
    for file in files:
        filepath = os.path.join(DATA_DIR, file)
        if os.path.exists(filepath):
            with open(filepath, 'r') as f:
                data = json.load(f)
                all_data.extend(data)
    
    return pd.DataFrame(all_data)

def extract_features_tfidf(texts, vectorizer=None, fit=True):
    """Extract features using TF-IDF"""
    if fit:
        vectorizer = TfidfVectorizer(
            max_features=500,
            ngram_range=(1, 2),
            min_df=2,
            max_df=0.95
        )
        features = vectorizer.fit_transform(texts)
    else:
        features = vectorizer.transform(texts)
    
    return features, vectorizer

def extract_features_bert(texts, model_name='distilbert-base-uncased'):
    """Extract features using BERT embeddings"""
    tokenizer = AutoTokenizer.from_pretrained(model_name)
    model = AutoModel.from_pretrained(model_name)
    model.eval()
    
    embeddings = []
    batch_size = 32
    
    with torch.no_grad():
        for i in range(0, len(texts), batch_size):
            batch = texts[i:i+batch_size]
            inputs = tokenizer(batch, padding=True, truncation=True, max_length=128, return_tensors='pt')
            outputs = model(**inputs)
            # Use [CLS] token embedding
            batch_embeddings = outputs.last_hidden_state[:, 0, :].numpy()
            embeddings.extend(batch_embeddings)
    
    return np.array(embeddings)

def prepare_features(df, vectorizer=None, use_bert=False, fit=True):
    """Prepare features from dataframe"""
    texts = df['message'].tolist()
    
    if use_bert and TRANSFORMERS_AVAILABLE:
        features = extract_features_bert(texts)
        return features, None
    else:
        features, vec = extract_features_tfidf(texts, vectorizer, fit)
        return features.toarray() if hasattr(features, 'toarray') else features, vec

def train_base_model(X_train, y_train, model_type='logistic'):
    """Train base classification model"""
    print(f"Training base model with {model_type}...")
    
    if model_type == 'logistic':
        model = LogisticRegression(
            max_iter=1000,
            class_weight='balanced',
            C=1.0,
            random_state=42
        )
    elif model_type == 'random_forest':
        model = RandomForestClassifier(
            n_estimators=100,
            max_depth=20,
            class_weight='balanced',
            random_state=42,
            n_jobs=-1
        )
    elif model_type == 'gradient_boosting':
        model = GradientBoostingClassifier(
            n_estimators=100,
            max_depth=5,
            random_state=42
        )
    else:
        model = LogisticRegression(max_iter=1000, class_weight='balanced', random_state=42)
    
    model.fit(X_train, y_train)
    return model

def evaluate_model(model, X_test, y_test, category='base'):
    """Evaluate model performance"""
    y_pred = model.predict(X_test)
    
    accuracy = accuracy_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred, average='weighted')
    
    print(f"\n{category.upper()} Model Results:")
    print(f"  Accuracy: {accuracy:.4f}")
    print(f"  F1-Score (weighted): {f1:.4f}")
    
    return accuracy, f1

def train_base_model_all_categories():
    """Train a base model on all categories combined"""
    print("=" * 60)
    print("STEP 1: Training BASE model on ALL categories")
    print("=" * 60)
    
    # Load all data
    df = load_data()
    print(f"Total samples: {len(df)}")
    print(f"Attack types: {df['attack_type'].nunique()}")
    print(f"Distribution:\n{df['attack_type'].value_counts()}")
    
    # Prepare features
    print("\nExtracting features...")
    X, vectorizer = prepare_features(df, fit=True)
    
    # Encode labels
    label_encoder = LabelEncoder()
    y = label_encoder.fit_transform(df['attack_type'])
    
    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    print(f"Training set: {len(X_train)}, Test set: {len(X_test)}")
    
    # Train model
    model = train_base_model(X_train, y_train, 'logistic')
    
    # Evaluate
    accuracy, f1 = evaluate_model(model, X_test, y_test, 'BASE')
    
    # Save model and artifacts
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    
    model_artifacts = {
        'model': model,
        'vectorizer': vectorizer,
        'label_encoder': label_encoder,
        'model_type': 'base',
        'accuracy': accuracy,
        'f1_score': f1,
        'categories': LOG_CATEGORIES
    }
    
    with open(os.path.join(OUTPUT_DIR, 'base_model.pkl'), 'wb') as f:
        pickle.dump(model_artifacts, f)
    
    print(f"\nBase model saved to {OUTPUT_DIR}/base_model.pkl")
    
    return model_artifacts

def train_category_models(base_artifacts):
    """Fine-tune models for each log category"""
    print("\n" + "=" * 60)
    print("STEP 2: Training FINE-TUNED models for each category")
    print("=" * 60)
    
    category_models = {}
    
    for category in LOG_CATEGORIES:
        print(f"\n--- Training model for: {category.upper()} ---")
        
        df = load_data(category)
        if len(df) == 0:
            print(f"No data for {category}, skipping...")
            continue
        
        print(f"Samples: {len(df)}")
        
        # For category-specific models, use the same vectorizer
        # but train on category data only
        X, vectorizer = prepare_features(df, base_artifacts['vectorizer'], fit=False)
        
        label_encoder = LabelEncoder()
        y = label_encoder.fit_transform(df['attack_type'])
        
        # Split
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        
        # Train with more regularization for smaller datasets
        model = LogisticRegression(
            max_iter=1000,
            class_weight='balanced',
            C=0.5,  # More regularization
            random_state=42
        )
        model.fit(X_train, y_train)
        
        accuracy, f1 = evaluate_model(model, X_test, y_test, category)
        
        category_models[category] = {
            'model': model,
            'label_encoder': label_encoder,
            'accuracy': accuracy,
            'f1_score': f1,
            'vectorizer': vectorizer
        }
    
    # Save category models
    with open(os.path.join(OUTPUT_DIR, 'category_models.pkl'), 'wb') as f:
        pickle.dump(category_models, f)
    
    print(f"\nCategory models saved to {OUTPUT_DIR}/category_models.pkl")
    
    return category_models

def create_unified_model():
    """Create a unified model that includes log category as a feature"""
    print("\n" + "=" * 60)
    print("STEP 3: Creating UNIFIED model with category embedding")
    print("=" * 60)
    
    # Load all data
    df = load_data()
    
    # Add category as a feature
    category_encoder = LabelEncoder()
    df['category_encoded'] = category_encoder.fit_transform(df['log_type'].apply(
        lambda x: next((c for c, types in {
            'webserver': LOG_CATEGORIES[:1],
            'database': LOG_CATEGORIES[1:2],
            'auth': LOG_CATEGORIES[2:3],
            'firewall': LOG_CATEGORIES[3:4],
            'mail': LOG_CATEGORIES[4:5],
            'network': LOG_CATEGORIES[5:6],
            'system': LOG_CATEGORIES[6:7],
            'cloud': LOG_CATEGORIES[7:8]
        }.items() if x in types), 'system')
    ))
    
    # Extract text features
    X_text, vectorizer = prepare_features(df, fit=True)
    
    # Add category as numeric feature
    category_features = df['category_encoded'].values.reshape(-1, 1)
    X = np.hstack([X_text, category_features])
    
    # Encode labels
    label_encoder = LabelEncoder()
    y = label_encoder.fit_transform(df['attack_type'])
    
    # Split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    # Train
    model = LogisticRegression(
        max_iter=1000,
        class_weight='balanced',
        C=1.0,
        random_state=42
    )
    model.fit(X_train, y_train)
    
    accuracy, f1 = evaluate_model(model, X_test, y_test, 'UNIFIED')
    
    # Save
    unified_artifacts = {
        'model': model,
        'vectorizer': vectorizer,
        'category_encoder': category_encoder,
        'label_encoder': label_encoder,
        'accuracy': accuracy,
        'f1_score': f1
    }
    
    with open(os.path.join(OUTPUT_DIR, 'unified_model.pkl'), 'wb') as f:
        pickle.dump(unified_artifacts, f)
    
    print(f"\nUnified model saved to {OUTPUT_DIR}/unified_model.pkl")
    
    return unified_artifacts

def main():
    """Main training pipeline"""
    print("SIEM ML Training Pipeline")
    print("=" * 60)
    
    # Ensure data directory exists
    os.makedirs(DATA_DIR, exist_ok=True)
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    
    # Generate synthetic data if not exists
    if not os.path.exists(os.path.join(DATA_DIR, 'metadata.json')):
        print("Generating synthetic data...")
        from generate_synthetic_data import generate_all_datasets
        generate_all_datasets(DATA_DIR, samples_per_category=5000)
    
    # Step 1: Train base model
    base_artifacts = train_base_model_all_categories()
    
    # Step 2: Train category-specific models
    category_models = train_category_models(base_artifacts)
    
    # Step 3: Create unified model
    unified_artifacts = create_unified_model()
    
    print("\n" + "=" * 60)
    print("TRAINING COMPLETE!")
    print("=" * 60)
    print(f"\nModels saved to: {OUTPUT_DIR}")
    print("  - base_model.pkl")
    print("  - category_models.pkl")
    print("  - unified_model.pkl")

if __name__ == '__main__':
    main()
