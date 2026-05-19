"""ML Module - Feature Extraction, Classification, and Correlation"""

import re
import numpy as np
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
from collections import defaultdict

try:
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from parsers.types import LogEntry


def extract_features(entries: List[dict]) -> np.ndarray:
    """Extract ML features from log entries"""
    if not entries:
        return np.array([])

    features = []
    for entry in entries:
        # Create feature vector
        vector = []

        # IP address hash
        ip = entry.get('source', {}).get('ip', '')
        vector.append(hash(ip) % 1000 / 1000.0 if ip else 0.0)

        # User hash
        user_dict = entry.get('user')
        user = user_dict.get('name', '') if user_dict else ''
        vector.append(hash(user) % 1000 / 1000.0 if user else 0.0)

        # Message length
        message = entry.get('message', '')
        vector.append(len(message) / 1000.0)

        # Severity encoding
        severity = entry.get('severity', 'info')
        severity_map = {'debug': 0, 'info': 1, 'warning': 2, 'error': 3, 'critical': 4}
        vector.append(severity_map.get(severity, 1))

        # Number of fields
        fields = entry.get('fields', {})
        vector.append(len(fields) / 10.0)

        # Hour of day
        timestamp = entry.get('timestamp')
        if timestamp:
            try:
                dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                vector.append(dt.hour / 24.0)
            except:
                vector.append(0.5)
        else:
            vector.append(0.5)

        # Day of week
        if timestamp:
            try:
                dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                vector.append(dt.weekday() / 7.0)
            except:
                vector.append(0.5)
        else:
            vector.append(0.5)

        features.append(vector)

    return np.array(features)


def detect_anomalies(entries: List[dict]) -> List[dict]:
    """Detect anomalies using Isolation Forest"""
    if not ML_AVAILABLE or len(entries) < 10:
        return []

    features = extract_features(entries)

    try:
        scaler = StandardScaler()
        features_scaled = scaler.fit_transform(features)

        iso_forest = IsolationForest(contamination=0.1, random_state=42)
        anomaly_scores = iso_forest.fit_predict(features_scaled)

        anomalies = []
        for i, (entry, score) in enumerate(zip(entries, anomaly_scores)):
            if score == -1:  # Anomaly
                anomaly_score = iso_forest.score_samples([features_scaled[i]])[0]
                anomalies.append({
                    'entry': entry,
                    'anomaly_score': float(abs(anomaly_score))
                })

        return anomalies
    except Exception as e:
        print(f"Anomaly detection error: {e}")
        return []


def correlate_multiple_logs(sources: List[dict]) -> dict:
    """Correlate multiple log sources and detect attack chains"""
    all_entries = []
    for source in sources:
        entries = source.get('entries', [])
        # Tag with source name
        for entry in entries:
            entry['logSource'] = source.get('name', 'unknown')
        all_entries.extend(entries)

    if not all_entries:
        return {
            'attackChains': [],
            'timeline': [],
            'summary': {
                'riskScore': 0,
                'criticalAlerts': 0,
                'falsePositivesFiltered': 0,
                'attackTypesDetected': [],
                'mostActiveSourceIps': [],
                'mostTargetedUsers': []
            },
            'totalEvents': 0,
            'recommendations': []
        }

    # Sort by timestamp
    sorted_entries = sorted(
        [e for e in all_entries if e.get('timestamp')],
        key=lambda x: x.get('timestamp', '')
    )

    # Detect anomalies
    anomalies = detect_anomalies(sorted_entries)
    anomaly_entry_ids = {a['entry'].get('id') for a in anomalies}

    # Find attack patterns
    attack_chains = find_attack_patterns(sorted_entries, anomalies)

    # Generate timeline
    timeline = generate_timeline(sorted_entries, anomalies)

    # Generate summary
    summary = generate_summary(sorted_entries, attack_chains, anomalies)

    # Generate recommendations
    recommendations = generate_recommendations(attack_chains)

    return {
        'attackChains': attack_chains,
        'timeline': timeline,
        'summary': summary,
        'totalEvents': len(all_entries),
        'recommendations': recommendations
    }


def find_attack_patterns(entries: List[dict], anomalies: List[dict]) -> List[dict]:
    """Find attack patterns across log entries"""
    attack_chains = []

    # Group by time windows (5 minutes)
    time_windows = group_by_time_window(entries, 5)

    # Pattern detection within windows
    for window in time_windows:
        if len(window) < 2:
            continue

        # Detect brute force patterns
        bf_chains = detect_bruteforce_chain(window, anomalies)
        attack_chains.extend(bf_chains)

        # Detect password spray patterns
        spray_chains = detect_password_spray_chain(window, anomalies)
        attack_chains.extend(spray_chains)

    return attack_chains


def detect_bruteforce_chain(window: List[dict], anomalies: List[dict]) -> List[dict]:
    """Detect brute force attack chain"""
    chains = []

    # Group failures by (IP, user)
    failures_by_ip_user = defaultdict(list)
    for entry in window:
        if entry.get('outcome') == 'failure' and entry.get('source', {}).get('ip'):
            key = f"{entry['source']['ip']}|{entry.get('user', {}).get('name', '')}"
            failures_by_ip_user[key].append(entry)

    # Check for brute force patterns
    for (ip_user, events) in failures_by_ip_user.items():
        if len(events) >= 5:  # Threshold
            ip, user = ip_user.split('|', 1) if '|' in ip_user else (ip_user, '')

            # Check time span
            timestamps = [e.get('timestamp') for e in events if e.get('timestamp')]
            if len(timestamps) >= 2:
                start = datetime.fromisoformat(timestamps[0].replace('Z', '+00:00'))
                end = datetime.fromisoformat(timestamps[-1].replace('Z', '+00:00'))
                span_minutes = (end - start).total_seconds() / 60

                if span_minutes <= 10:  # Within 10 minutes
                    # Create attack chain
                    chain = {
                        'id': f"bf_{ip}_{len(events)}",
                        'attackType': 'bruteforce',
                        'stage': 'initial_access',
                        'events': events[:10],
                        'sourceIps': [ip],
                        'targetUsers': [user] if user else [],
                        'startTime': timestamps[0],
                        'endTime': timestamps[-1],
                        'prediction': {
                            'confidence': min(0.7 + (len(events) / 50), 0.95),
                            'explanation': [
                                f'Detected {len(events)} failed authentication attempts',
                                f'All within {span_minutes:.1f} minutes',
                                f'Suggests brute force attack'
                            ]
                        },
                        'mitreTactics': ['TA0006'],
                        'mitreTechniques': ['T1110'],
                        'recommendation': 'Implement account lockout policies and monitor for suspicious login patterns'
                    }
                    chains.append(chain)

    return chains


def detect_password_spray_chain(window: List[dict], anomalies: List[dict]) -> List[dict]:
    """Detect password spray attack chain"""
    chains = []

    # Group failures by IP
    failures_by_ip = defaultdict(list)
    for entry in window:
        if entry.get('outcome') == 'failure' and entry.get('source', {}).get('ip'):
            failures_by_ip[entry['source']['ip']].append(entry)

    # Check for spray patterns (many unique users)
    for (ip, events) in failures_by_ip.items():
        unique_users = set()
        for e in events:
            user = e.get('user', {}).get('name')
            if user:
                unique_users.add(user)

        if len(unique_users) >= 10:  # Threshold
            # Check time span
            timestamps = [e.get('timestamp') for e in events if e.get('timestamp')]
            if timestamps:
                start = datetime.fromisoformat(timestamps[0].replace('Z', '+00:00'))
                end = datetime.fromisoformat(timestamps[-1].replace('Z', '+00:00'))
                span_minutes = (end - start).total_seconds() / 60

                if span_minutes <= 15:  # Within 15 minutes
                    chain = {
                        'id': f"spray_{ip}_{len(unique_users)}",
                        'attackType': 'password_spray',
                        'stage': 'initial_access',
                        'events': events[:10],
                        'sourceIps': [ip],
                        'targetUsers': list(unique_users),
                        'startTime': timestamps[0],
                        'endTime': timestamps[-1],
                        'prediction': {
                            'confidence': min(0.7 + (len(unique_users) / 50), 0.95),
                            'explanation': [
                                f'Detected {len(unique_users)} unique targeted users',
                                f'All within {span_minutes:.1f} minutes',
                                f'Suggests password spray attack'
                            ]
                        },
                        'mitreTactics': ['TA0006'],
                        'mitreTechniques': ['T1110'],
                        'recommendation': 'Implement MFA and monitor for authentication anomalies across multiple accounts'
                    }
                    chains.append(chain)

    return chains


def group_by_time_window(entries: List[dict], window_minutes: int) -> List[List[dict]]:
    """Group entries by time windows"""
    if not entries:
        return []

    # Filter entries with timestamps and sort
    sorted_entries = sorted(
        [e for e in entries if e.get('timestamp')],
        key=lambda x: datetime.fromisoformat(x['timestamp'].replace('Z', '+00:00'))
    )

    if not sorted_entries:
        return [entries]

    windows = []
    current_window = [sorted_entries[0]]
    window_start = datetime.fromisoformat(sorted_entries[0]['timestamp'].replace('Z', '+00:00'))

    for entry in sorted_entries[1:]:
        if entry.get('timestamp'):
            entry_time = datetime.fromisoformat(entry['timestamp'].replace('Z', '+00:00'))
            if (entry_time - window_start).total_seconds() / 60 <= window_minutes:
                current_window.append(entry)
            else:
                if current_window:
                    windows.append(current_window)
                current_window = [entry]
                window_start = entry_time

    if current_window:
        windows.append(current_window)

    return windows


def generate_timeline(entries: List[dict], anomalies: List[dict]) -> List[dict]:
    """Generate timeline for visualization"""
    timeline = []
    anomaly_map = {a['entry'].get('id'): a for a in anomalies}

    for entry in entries[:500]:  # Limit to 500 for performance
        if entry.get('timestamp'):
            anomaly_data = anomaly_map.get(entry.get('id'))
            timeline.append({
                'id': entry.get('id'),
                'timestamp': entry['timestamp'],
                'count': 1,
                'isAnomaly': anomaly_data is not None,
                'severity': entry.get('severity', 'info'),
                'logSource': entry.get('logSource', 'unknown'),
                'title': entry.get('action', entry.get('message', '')[:50]),
                'description': entry.get('message', ''),
                'sourceIp': entry.get('source', {}).get('ip'),
                'anomalyScore': anomaly_data.get('anomaly_score') if anomaly_data else None,
                'correlationScore': anomaly_data.get('anomaly_score') if anomaly_data else None
            })

    return timeline


def generate_summary(entries: List[dict], attack_chains: List[dict], anomalies: List[dict]) -> dict:
    """Generate summary statistics"""
    # Count by severity
    severity_counts = defaultdict(int)
    for entry in entries:
        severity_counts[entry.get('severity', 'info')] += 1

    # Count source IPs
    ip_counts = defaultdict(int)
    for entry in entries:
        ip = entry.get('source', {}).get('ip')
        if ip:
            ip_counts[ip] += 1

    # Count users
    user_counts = defaultdict(int)
    for entry in entries:
        user_dict = entry.get('user')
        user = user_dict.get('name') if user_dict else None
        if user:
            user_counts[user] += 1

    # Calculate risk score
    risk_score = min(100, len(attack_chains) * 20 + severity_counts.get('critical', 0) * 10 + severity_counts.get('error', 0) * 5)

    # Top source IPs with threat scores
    most_active_ips = []
    for ip, count in sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:10]:
        threat_score = 0
        for chain in attack_chains:
            if ip in chain.get('sourceIps', []):
                threat_score += chain['prediction']['confidence']
        most_active_ips.append({
            'ip': ip,
            'count': count,
            'threatScore': min(threat_score, 1.0)
        })

    # Top users
    most_targeted_users = []
    for user, count in sorted(user_counts.items(), key=lambda x: x[1], reverse=True)[:10]:
        most_targeted_users.append({
            'user': user,
            'count': count
        })

    # Attack types detected
    attack_types = list(set(chain.get('attackType') for chain in attack_chains))

    return {
        'riskScore': int(risk_score),
        'criticalAlerts': severity_counts.get('critical', 0),
        'falsePositivesFiltered': int(len(anomalies) * 0.1),  # Assume 10% false positives
        'attackTypesDetected': attack_types,
        'mostActiveSourceIps': most_active_ips,
        'mostTargetedUsers': most_targeted_users
    }


def generate_recommendations(attack_chains: List[dict]) -> List[str]:
    """Generate security recommendations"""
    recommendations = []

    if any(chain.get('attackType') == 'bruteforce' for chain in attack_chains):
        recommendations.extend([
            'Implement multi-factor authentication (MFA) for all user accounts',
            'Configure account lockout policies after failed login attempts',
            'Monitor and alert on suspicious login patterns',
            'Consider implementing rate limiting on authentication endpoints'
        ])

    if any(chain.get('attackType') == 'password_spray' for chain in attack_chains):
        recommendations.extend([
            'Implement MFA to prevent password spray attacks',
            'Use strong password policies and regular rotation',
            'Monitor for login attempts from unusual locations',
            'Consider using CAPTCHA for failed login attempts'
        ])

    if not recommendations:
        recommendations.append('Continue monitoring log files for security events')

    return recommendations


MODEL_CACHE = None

def load_trained_model() -> Optional[Any]:
    """Load the trained attack classification model"""
    global MODEL_CACHE
    if MODEL_CACHE is not None:
        return MODEL_CACHE

    try:
        import joblib
        model_path = os.path.join(os.path.dirname(__file__), '..', 'models', 'attack_classifier.joblib')
        if os.path.exists(model_path):
            MODEL_CACHE = joblib.load(model_path)
            return MODEL_CACHE
    except Exception as e:
        print(f"Warning: Could not load trained model: {e}")
    return None


ATTACK_PATTERNS = {
    'sql_injection': [
        r"(\%27)|(\')|(\-\-)|(\%23)|(#)",
        r"(\%3D)|(=)[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))",
        r"union\s+select",
        r"exec(\s|\+)+(s|x)p\w+",
        r"' OR '1'='1",
        r"DROP TABLE",
    ],
    'xss': [
        r"<script>",
        r"javascript:",
        r"onerror=",
        r"onload=",
        r"onmouseover=",
        r"alert\(",
        r"document\.cookie",
    ],
    'command_injection': [
        r";\s*(cat|ls|wget|curl|nc|bash|sh)\s",
        r"\|\s*(cat|ls|wget|curl|nc|bash|sh)\s",
        r"`\s*(cat|ls|wget|curl|nc|bash|sh)\s`",
        r"\$\(.*\)",
        r"chmod\s+\d{3,4}",
        r"wget\s+http",
        r"curl\s+http",
    ],
    'directory_traversal': [
        r"\.\./",
        r"\.\.\\",
        r"%2e%2e",
        r"etc/passwd",
        r"win.ini",
        r"boot.ini",
    ],
    'file_inclusion': [
        r"\?page=http",
        r"\?file=http",
        r"include\s*\(",
        r"require\s*\(",
    ],
}


def extract_attack_features(entry: dict) -> List[float]:
    """Extract features for attack classification from a log entry dict"""
    features = []
    message = (entry.get('message') or '').lower()
    raw_line = (entry.get('rawLine') or '').lower()
    action = (entry.get('action') or '').lower()
    source = entry.get('source') or {}
    source_ip = source.get('ip') or ''
    severity = entry.get('severity') or 'info'
    outcome = (entry.get('outcome') or '') or ''
    user_dict = entry.get('user')
    user = user_dict.get('name', '') if user_dict else ''
    
    # For web server logs, also check path and query parameters from raw line
    fields = entry.get('fields') or {}
    path = (fields.get('path') or '').lower()
    
    # Combine message, path, and raw line for comprehensive attack detection
    # Use raw_line for web logs as it contains the full request with query params
    search_text = raw_line if raw_line else message

    is_external = 1.0 if not (
        source_ip.startswith('192.168.') or
        source_ip.startswith('10.') or
        source_ip.startswith('172.16') or
        source_ip.startswith('172.17') or
        source_ip.startswith('172.18') or
        source_ip.startswith('172.19') or
        source_ip.startswith('172.20') or
        source_ip.startswith('172.21') or
        source_ip.startswith('172.22') or
        source_ip.startswith('172.23') or
        source_ip.startswith('172.24') or
        source_ip.startswith('172.25') or
        source_ip.startswith('172.26') or
        source_ip.startswith('172.27') or
        source_ip.startswith('172.28') or
        source_ip.startswith('172.29') or
        source_ip.startswith('172.30') or
        source_ip.startswith('172.31')
    ) else 0.0
    features.append(is_external)

    features.append(min(len(search_text) / 500.0, 1.0))

    # SQL Injection patterns - check in full request text (case-insensitive, flexible spacing)
    sql_patterns = len(re.findall(
        r"union\s+select|"  # UNION SELECT
        r"select\s+.*\s+from|"  # SELECT ... FROM
        r"drop\s+table|"  # DROP TABLE
        r";\s*--|"  # Semicolon followed by comment
        r"--\s*$|"  # Comment at end
        r"'\s*or\s+'?1'?\s*=\s*'?1|"  # ' OR '1'='1 variations (flexible spacing and quotes)
        r"\"\s*or\s+\"?1\"?\s*=\s*\"?1|"  # " OR "1"="1 variations
        r"or\s+'1'\s*=\s*'1|"  # OR '1'='1 (without leading quote)
        r"or\s+1\s*=\s*1|"  # OR 1=1 (numeric)
        r"and\s+1\s*=\s*1|"  # AND 1=1 (numeric)
        r"\bor\b.*=.*\bor\b|\band\b.*=.*\band\b",  # Generic OR/AND patterns
        search_text, re.IGNORECASE))
    features.append(min(sql_patterns / 3.0, 1.0))

    # XSS patterns
    xss_patterns = len(re.findall(r"<script|javascript:|on\w+\s*=|<iframe|<object|<embed|alert\(|document\.cookie|document\.location", search_text, re.IGNORECASE))
    features.append(min(xss_patterns / 3.0, 1.0))

    # Command Injection patterns
    cmd_patterns = len(re.findall(r"[;|`]\s*(cat|ls|wget|curl|nc|bash|sh|whoami|id|uname|pwd|echo|chmod)\s|chmod\s+\d+|wget\s+http|curl\s+http|\$\(|\$\{|\`.*\`", search_text, re.IGNORECASE))
    features.append(min(cmd_patterns / 3.0, 1.0))

    # Directory Traversal patterns
    dt_patterns = len(re.findall(r"\.\.(\/|\\)|%2e%2e|\.\.\\|%252e%252e|etc/passwd|win\.ini|boot\.ini|\.htaccess|\.htpasswd", search_text, re.IGNORECASE))
    features.append(min(dt_patterns / 3.0, 1.0))

    # File Inclusion patterns
    fi_patterns = len(re.findall(r"\?(page|file|path|include|document)\s*=.*http|\?.*=.*\.\.|include\s*\(|require\s*\(|require_once\s*\(|virtual\s*\(", search_text, re.IGNORECASE))
    features.append(min(fi_patterns / 3.0, 1.0))

    is_http = 1.0 if re.search(r'\b(get|post|put|delete|patch)\s+/[^\s]*', search_text, re.IGNORECASE) else 0.0
    features.append(is_http)

    # Check for failure - both 'failure' outcome and HTTP error codes (4xx, 5xx)
    has_failure = 1.0 if outcome == 'failure' or re.match(r'^(4|5)\d{2}$', str(outcome)) else 0.0
    features.append(has_failure)

    severity_val = {'debug': 0, 'info': 0, 'warning': 1, 'error': 1, 'critical': 1}
    features.append(severity_val.get(severity, 0))

    is_anonymous = 1.0 if user in ['', 'anonymous', 'www-data', 'nobody', 'root'] else 0.0
    features.append(is_anonymous)

    has_url_encoding = 1.0 if re.search(r'%[0-9a-fA-F]{2}', search_text) else 0.0
    features.append(has_url_encoding)

    has_ip_in_message = 1.0 if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', search_text) else 0.0
    features.append(has_ip_in_message)

    has_port = 1.0 if re.search(r'port\s+\d+|:\d{2,5}', search_text) else 0.0
    features.append(has_port)

    system_files = len(re.findall(r'/etc/|/proc/|/var/|/usr/|\\windows\\|\\system32\\', search_text))
    features.append(min(system_files / 3.0, 1.0))

    sensitive_keywords = sum(1 for kw in ['password', 'credential', 'token', 'secret', 'key', 'auth'] if kw in search_text)
    features.append(min(sensitive_keywords / 3.0, 1.0))

    is_login = 1.0 if 'login' in action or 'auth' in search_text or 'password' in search_text else 0.0
    features.append(is_login)

    has_angle_brackets = 1.0 if re.search(r'<[^>]+>', search_text) else 0.0
    features.append(has_angle_brackets)

    has_single_quote = 1.0 if "'" in search_text else 0.0
    features.append(has_single_quote)

    has_eq_quotes = 1.0 if re.search(r"=\s*['\"]", search_text) else 0.0
    features.append(has_eq_quotes)

    has_double_dash = 1.0 if '--' in search_text else 0.0
    features.append(has_double_dash)

    has_semicolon = 1.0 if ';' in search_text else 0.0
    features.append(has_semicolon)

    has_pipe = 1.0 if '|' in search_text else 0.0
    features.append(has_pipe)

    has_backtick = 1.0 if '`' in search_text else 0.0
    features.append(has_backtick)

    is_connection = 1.0 if 'connection' in search_text or 'port' in search_text else 0.0
    features.append(is_connection)

    return features

    cmd_patterns = sum(1 for pattern in ATTACK_PATTERNS['command_injection'] if re.search(pattern, message, re.I))
    features.append(min(cmd_patterns / 3.0, 1.0))

    dt_patterns = sum(1 for pattern in ATTACK_PATTERNS['directory_traversal'] if re.search(pattern, message, re.I))
    features.append(min(dt_patterns / 3.0, 1.0))

    fi_patterns = sum(1 for pattern in ATTACK_PATTERNS['file_inclusion'] if re.search(pattern, message, re.I))
    features.append(min(fi_patterns / 3.0, 1.0))

    is_http = 1.0 if action == 'http_request' or message.startswith(('GET ', 'POST ', 'PUT ', 'DELETE ')) else 0.0
    features.append(is_http)

    has_failure = 1.0 if outcome == 'failure' else 0.0
    features.append(has_failure)

    severity_val = {'debug': 0, 'info': 0, 'warning': 1, 'error': 2, 'critical': 2}
    features.append(min(severity_val.get(severity, 0) / 2.0, 1.0))

    is_anonymous = 1.0 if user in ['', 'anonymous', 'www-data', 'nobody'] else 0.0
    features.append(is_anonymous)

    has_url_encoding = 1.0 if re.search(r'%[0-9a-fA-F]{2}', message) else 0.0
    features.append(has_url_encoding)

    has_ip_in_message = 1.0 if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', message) else 0.0
    features.append(has_ip_in_message)

    has_port = 1.0 if re.search(r':\d{2,5}', message) else 0.0
    features.append(has_port)

    system_files = len(re.findall(r'/etc/|/proc/|/var/|/usr/|\\windows\\|\\system32\\', message, re.I))
    features.append(min(system_files / 3.0, 1.0))

    sensitive_keywords = sum(1 for kw in ['password', 'credential', 'token', 'secret', 'key', 'auth'] if kw in message)
    features.append(min(sensitive_keywords / 3.0, 1.0))

    is_login = 1.0 if 'login' in action or 'auth' in action or 'password' in message else 0.0
    features.append(is_login)

    has_escape = 1.0 if re.search(r"\\['\";]|&#x", message) else 0.0
    features.append(has_escape)

    request_method = 1.0 if re.search(r'^(GET|POST|PUT|DELETE|PATCH)\s', message) else 0.0
    features.append(request_method)

    return features


MITRE_MAPPING = {
    'sql_injection': {'tactics': ['TA0006'], 'techniques': ['T1190']},
    'xss': {'tactics': ['TA0006'], 'techniques': ['T1190']},
    'command_injection': {'tactics': ['TA0001', 'TA0002'], 'techniques': ['T1059']},
    'directory_traversal': {'tactics': ['TA0006'], 'techniques': ['T1083']},
    'file_inclusion': {'tactics': ['TA0006'], 'techniques': ['T1190']},
    'port_scan': {'tactics': ['TA0043'], 'techniques': ['T1595']},
    'bruteforce': {'tactics': ['TA0006'], 'techniques': ['T1110']},
    'password_spray': {'tactics': ['TA0006'], 'techniques': ['T1110']},
}


def predict_attack_type(entry: dict, threshold: float = 0.3) -> Optional[Dict[str, Any]]:
    """Predict attack type for a log entry using the trained model"""
    model_data = load_trained_model()
    if model_data is None:
        return None

    features = np.array(extract_attack_features(entry)).reshape(1, -1)

    pipeline = model_data['pipeline']
    label_encoder = model_data['label_encoder']

    prediction = pipeline.predict(features)
    probability = pipeline.predict_proba(features)[0]

    attack_type = label_encoder.inverse_transform(prediction)[0]
    confidence = float(max(probability))

    if attack_type == 'normal' or confidence < threshold:
        return None

    mitre = MITRE_MAPPING.get(attack_type, {'tactics': ['TA0006'], 'techniques': ['T1055']})

    return {
        'attackType': attack_type,
        'confidence': confidence,
        'mitreTactics': mitre['tactics'],
        'mitreTechniques': mitre['techniques']
    }


def detect_attack_types(entries: List[dict]) -> List[dict]:
    """Detect attack types for all log entries using trained model"""
    attacks = []

    for entry in entries:
        result = predict_attack_type(entry)
        if result:
            result['entry'] = entry
            attacks.append(result)

    return attacks


def correlate_attacks(entries: List[dict], attacks: List[dict]) -> List[dict]:
    """Correlate detected attacks into attack chains"""
    if not attacks:
        return []

    attacks_by_ip = defaultdict(list)
    attacks_by_user = defaultdict(list)
    attacks_by_time = defaultdict(list)

    for attack in attacks:
        entry = attack['entry']
        ip = entry.get('source', {}).get('ip', '')
        user_dict = entry.get('user')
        user = user_dict.get('name', '') if user_dict else ''
        timestamp = entry.get('timestamp', '')

        if ip:
            attacks_by_ip[ip].append(attack)
        if user:
            attacks_by_user[user].append(attack)
        if timestamp:
            attacks_by_time[timestamp].append(attack)

    chains = []

    for ip, ip_attacks in attacks_by_ip.items():
        if len(ip_attacks) >= 3:
            chain = {
                'id': f"chain_{hash(ip) % 100000}",
                'attackType': ip_attacks[0]['attackType'],
                'stage': 'initial_access',
                'events': [a['entry'] for a in ip_attacks[:10]],
                'sourceIps': [ip],
                'targetUsers': list(set(a['entry'].get('user', {}).get('name', '') for a in ip_attacks)),
                'startTime': min(a['entry'].get('timestamp', '') for a in ip_attacks),
                'endTime': max(a['entry'].get('timestamp', '') for a in ip_attacks),
                'prediction': {
                    'confidence': sum(a['confidence'] for a in ip_attacks) / len(ip_attacks),
                    'explanation': [f'Detected {len(ip_attacks)} {ip_attacks[0]["attackType"]} attempts from {ip}']
                },
                'mitreTactics': ip_attacks[0]['mitreTactics'],
                'mitreTechniques': ip_attacks[0]['mitreTechniques'],
                'recommendation': f'Monitor and block traffic from {ip}. Consider implementing rate limiting.'
            }
            chains.append(chain)

    return chains
