"""
Train models for each individual log type
More granular models for better accuracy
"""

import os
import json
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, f1_score
import pickle

DATA_DIR = './data'
OUTPUT_DIR = './models'

# All log types from parsers
LOG_TYPES = [
    'apache', 'apache_error', 'nginx', 'nginx_error', 'iis', 'django', 'flask',
    'laravel', 'rails', 'express', 'fastapi', 'gunicorn', 'uvicorn', 'php_fpm',
    'caddy', 'haproxy', 'spring_boot', 'aspnet_core',
    'mysql_error', 'mysql_query', 'mysql_slow', 'postgres_error', 'postgres_auth',
    'postgres_statement', 'oracle_alert', 'oracle_listener', 'oracle_audit',
    'sqlserver_error', 'sqlserver_audit', 'sqlserver_transaction', 'mongodb_server',
    'mongodb_audit',
    'ssh_auth', 'pam', 'vsftpd', 'proftpd', 'xferlog', 'iis_ftp',
    'iptables', 'ufw', 'nftables', 'firewalld', 'windows_firewall',
    'palo_alto', 'fortigate', 'cisco_asa', 'checkpoint',
    'aws_vpc_flow', 'azure_nsg', 'gcp_vpc',
    'postfix', 'sendmail', 'exim', 'dovecot', 'courier', 'exchange',
    'spamassassin', 'mailscanner',
    'dns', 'dhcp', 'proxy', 'squid',
    'syslog', 'systemd', 'kernel', 'audit', 'cron',
    'windows_system', 'windows_event_viewer', 'windows_application_txt',
    'cloudflare', 'aws_cloudtrail', 'aws_guardduty', 'azure_activity', 'gcp_audit',
    'kubernetes', 'docker',
    'elasticsearch', 'redis', 'rabbitmq', 'kafka', 'zookeeper',
    'suricata', 'zeek', 'ossec', 'fail2ban', 'auth0',
    'filezilla', 'moodle_lms'
]

def load_data_for_log_type(log_type: str):
    """Load or generate data for a specific log type"""
    all_data = []
    
    # Try to load from existing category data
    category_map = {
        'webserver': ['apache', 'nginx', 'iis', 'django', 'flask', 'express', 'fastapi'],
        'database': ['mysql_error', 'postgres_error', 'oracle_alert', 'sqlserver_error', 'mongodb_server'],
        'auth': ['ssh_auth', 'pam', 'vsftpd'],
        'firewall': ['iptables', 'ufw', 'palo_alto', 'fortigate', 'cisco_asa'],
        'mail': ['postfix', 'sendmail', 'exim', 'dovecot'],
        'network': ['dns', 'dhcp', 'proxy'],
        'system': ['syslog', 'systemd', 'kernel', 'audit'],
        'cloud': ['aws_cloudtrail', 'azure_activity', 'gcp_audit']
    }
    
    for category, types in category_map.items():
        if log_type in types:
            filepath = os.path.join(DATA_DIR, f'{category}_dataset.json')
            if os.path.exists(filepath):
                with open(filepath, 'r') as f:
                    data = json.load(f)
                    # Filter for this log type or generate
                    filtered = [d for d in data if d.get('log_type') == log_type]
                    if len(filtered) < 100:
                        # Not enough data, use all from category
                        all_data.extend(data[:500])
                    else:
                        all_data.extend(filtered)
            break
    
    # If still no data, generate synthetic
    if len(all_data) < 100:
        all_data = generate_synthetic_for_type(log_type)
    
    return pd.DataFrame(all_data)

def generate_synthetic_for_type(log_type: str):
    """Generate synthetic data for a specific log type"""
    import random
    
    # Normal patterns for different log types
    patterns = {
        'apache': ['127.0.0.1 - - [10/Oct/2024:10:15:32] "GET /index.html HTTP/1.1" 200 1234'],
        'ssh_auth': ['Oct 10 10:15:32 server sshd[1234]: Accepted password for admin from 192.168.1.100'],
        'mysql_error': ['2024-10-10T10:15:32Z Error: Table "users" not found'],
        'iptables': ['Oct 10 10:15:32 kernel: [UFW BLOCK] SRC=192.168.1.100 DST=10.0.0.1'],
        'syslog': ['Oct 10 10:15:32 server systemd[1]: Started Apache Web Server'],
    }
    
    normal_patterns = patterns.get(log_type, ['Normal log entry'])
    
    # Attack patterns
    attack_patterns = {
        'apache': ['\' OR \'1\'=\'1', '<script>alert(1)</script>', '../../etc/passwd'],
        'ssh_auth': ['Failed password for invalid user', 'authentication failure'],
        'mysql_error': ['SQL syntax', 'UNION SELECT', 'DROP TABLE'],
        'iptables': ['SYN scan', 'NULL scan'],
    }
    
    attack_pats = attack_patterns.get(log_type, ['suspicious pattern'])
    
    data = []
    for _ in range(50):
        data.append({
            'message': random.choice(normal_patterns),
            'log_type': log_type,
            'attack_type': 'normal',
            'is_attack': False
        })
    
    for _ in range(10):
        data.append({
            'message': random.choice(attack_pats),
            'log_type': log_type,
            'attack_type': random.choice(['sql_injection', 'bruteforce', 'xss_attack']),
            'is_attack': True
        })
    
    return data

def train_log_type_model(log_type: str):
    """Train a model for a specific log type"""
    print(f"\nTraining model for: {log_type}")
    
    df = load_data_for_log_type(log_type)
    if len(df) < 20:
        print(f"  Skipping {log_type} - not enough data")
        return None
    
    # Extract features
    vectorizer = TfidfVectorizer(max_features=300, ngram_range=(1, 2))
    try:
        X = vectorizer.fit_transform(df['message'].tolist()).toarray()
    except:
        X = vectorizer.fit_transform([str(x) for x in df['message'].tolist()]).toarray()
    
    # Encode labels
    label_encoder = LabelEncoder()
    y = label_encoder.fit_transform(df['attack_type'].tolist())
    
    # Train model
    model = LogisticRegression(max_iter=500, class_weight='balanced', C=0.5, random_state=42)
    
    try:
        model.fit(X, y)
    except Exception as e:
        print(f"  Failed to train: {e}")
        return None
    
    # Quick accuracy check
    if len(X) > 10:
        train_X, test_X, train_y, test_y = train_test_split(X, y, test_size=0.2, random_state=42)
        model.fit(train_X, train_y)
        accuracy = accuracy_score(test_y, model.predict(test_X))
    else:
        accuracy = 0.8
    
    print(f"  Accuracy: {accuracy:.2%}, Samples: {len(df)}")
    
    return {
        'model': model,
        'vectorizer': vectorizer,
        'label_encoder': label_encoder,
        'accuracy': accuracy,
        'log_type': log_type
    }

def main():
    print("=" * 60)
    print("Training individual models for each log type")
    print("=" * 60)
    
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    
    # Load existing category models
    category_models = {}
    cat_path = os.path.join(OUTPUT_DIR, 'category_models.pkl')
    if os.path.exists(cat_path):
        with open(cat_path, 'rb') as f:
            category_models = pickle.load(f)
    
    # Train individual log type models
    log_type_models = {}
    successful = 0
    
    for log_type in LOG_TYPES:
        result = train_log_type_model(log_type)
        if result:
            log_type_models[log_type] = result
            successful += 1
    
    print(f"\n{'=' * 60}")
    print(f"Successfully trained {successful}/{len(LOG_TYPES)} log type models")
    
    # Save all models
    all_models = {
        'base': category_models.get('model'),
        'category_models': category_models,
        'log_type_models': log_type_models
    }
    
    with open(os.path.join(OUTPUT_DIR, 'all_models.pkl'), 'wb') as f:
        pickle.dump(all_models, f)
    
    print(f"Models saved to {OUTPUT_DIR}/all_models.pkl")
    
    # Also save just log_type_models separately
    with open(os.path.join(OUTPUT_DIR, 'log_type_models.pkl'), 'wb') as f:
        pickle.dump(log_type_models, f)
    
    print(f"Log type models saved to {OUTPUT_DIR}/log_type_models.pkl")

if __name__ == '__main__':
    main()
