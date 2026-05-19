"""Enhanced Multi-Log Correlation Engine - Port from siem-tool"""

import re
import hashlib
from typing import List, Dict, Any, Optional, Set, Tuple
from datetime import datetime, timedelta
from collections import defaultdict
import json

try:
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False

import sys
import os
sys.path.insert(0, os.path.dirname(__file__))
from parsers.types import LogEntry


ATTACK_TYPE = str
ML_PREDICTION = Dict[str, Any]
CORRELATED_EVENT = Dict[str, Any]
ATTACK_CHAIN = Dict[str, Any]
TIMELINE_EVENT = Dict[str, Any]
CORRELATION_RESULT = Dict[str, Any]


def generate_id() -> str:
    """Generate a unique ID for attack chains and events"""
    return hashlib.md5(f"{datetime.now().timestamp()}{hashlib.md5(os.urandom(16)).hexdigest()}".encode()).hexdigest()[:8]


MITRE_TACTICS = {
    'bruteforce': ['TA0006 - Credential Access', 'TA0001 - Initial Access'],
    'password_spray': ['TA0006 - Credential Access', 'TA0001 - Initial Access'],
    'sql_injection': ['TA0006 - Credential Access', 'TA0002 - Execution'],
    'xss_attack': ['TA0006 - Credential Access', 'TA0002 - Execution'],
    'command_injection': ['TA0001 - Initial Access', 'TA0002 - Execution'],
    'path_traversal': ['TA0006 - Credential Access', 'TA0007 - Discovery'],
    'file_inclusion': ['TA0006 - Credential Access', 'TA0002 - Execution'],
    'privilege_escalation': ['TA0004 - Privilege Escalation'],
    'lateral_movement': ['TA0008 - Lateral Movement'],
    'data_exfiltration': ['TA0010 - Exfiltration'],
    'ransomware': ['TA0040 - Impact'],
    'webshell': ['TA0003 - Persistence', 'TA0002 - Execution'],
    'c2_communication': ['TA0011 - Command and Control'],
    'account_takeover': ['TA0006 - Credential Access', 'TA0001 - Initial Access'],
    'mfa_bypass': ['TA0006 - Credential Access'],
    'mfa_fatigue': ['TA0006 - Credential Access'],
    'session_hijacking': ['TA0006 - Credential Access'],
    'credential_stuffing': ['TA0006 - Credential Access'],
    'malware_activity': ['TA0002 - Execution', 'TA0003 - Persistence'],
    'insider_threat': ['TA0003 - Persistence', 'TA0010 - Exfiltration'],
    'reconnaissance': ['TA0043 - Reconnaissance'],
    'port_scan': ['TA0043 - Reconnaissance'],
    'ddos': ['TA0040 - Impact'],
}


MITRE_TECHNIQUES = {
    'bruteforce': ['T1110 - Brute Force'],
    'password_spray': ['T1110 - Brute Force'],
    'sql_injection': ['T1190 - Exploit Public-Facing Application'],
    'xss_attack': ['T1190 - Exploit Public-Facing Application'],
    'command_injection': ['T1059 - Command and Scripting Interpreter'],
    'path_traversal': ['T1083 - File and Directory Discovery'],
    'file_inclusion': ['T1190 - Exploit Public-Facing Application'],
    'privilege_escalation': ['T1068 - Exploitation for Privilege Escalation'],
    'lateral_movement': ['T1021 - Remote Services'],
    'data_exfiltration': ['T1041 - Exfiltration Over C2'],
    'ransomware': ['T1486 - Data Encrypted for Impact'],
    'webshell': ['T1505 - Server Software Component'],
    'c2_communication': ['T1071 - Application Layer Protocol'],
    'account_takeover': ['T1078 - Valid Accounts'],
    'mfa_bypass': ['T1556 - Modify Authentication Process'],
    'mfa_fatigue': ['T1556 - Modify Authentication Process'],
    'session_hijacking': ['T1550 - Steal Application Access Token'],
    'credential_stuffing': ['T1110 - Brute Force'],
    'malware_activity': ['T1204 - User Execution'],
    'insider_threat': ['TA0003 - Persistence'],
    'reconnaissance': ['T1595 - Gather Victim Host Information'],
    'port_scan': ['T1046 - Network Service Discovery'],
    'ddos': ['T1498 - Network Denial of Service'],
}


ATTACK_TYPE_PATTERNS = {
    'sql_injection': [
        r"union\s+select",
        r"'\s+or\s+'1'='1",
        r"'\s+or\s+1=1",
        r"drop\s+table",
        r"exec\s*\(",
        r"xp_cmdshell",
        r"0x41414141",
    ],
    'xss_attack': [
        r"<script>",
        r"javascript:",
        r"onerror=",
        r"onload=",
        r"document\.cookie",
    ],
    'command_injection': [
        r";\s*(cat|ls|wget|curl|nc|bash|sh)\s",
        r"\|\s*(cat|ls|wget|curl|nc|bash|sh)\s",
        r"`.*`",
        r"\$\(.*\)",
        r"chmod\s+\d{3,4}",
    ],
    'path_traversal': [
        r"\.\./",
        r"\.\.\\",
        r"%2e%2e",
        r"etc/passwd",
        r"win.ini",
    ],
    'webshell': [
        r"\.(php|asp|aspx|jsp)\?cmd=",
        r"c99|r57|b374k|wso",
        r"eval\s*\(",
        r"base64_decode",
    ],
    'ransomware': [
        r"vssadmin.*delete",
        r"shadowcopy.*delete",
        r"\.locked",
        r"bcditedit.*recoverydisabled",
        r"encrypt.*files",
    ],
    'bruteforce': [
        r"failed\s+password",
        r"authentication\s+failure",
        r"invalid\s+user",
    ],
    'password_spray': [
        r"authentication\s+failure",
        r"unknown\s+user",
    ],
}


def get_log_source(log_type: str) -> str:
    """Map log type to log source category"""
    source_map = {
        'ssh_auth': 'auth', 'pam': 'auth', 'vsftpd': 'auth', 'proftpd': 'auth',
        'apache': 'web', 'nginx': 'web', 'iis': 'web', 'django': 'web', 'flask': 'web',
        'rails': 'web', 'express': 'web', 'fastapi': 'web', 'gunicorn': 'web', 'uvicorn': 'web',
        'mysql_error': 'database', 'mysql_query': 'database', 'mysql_slow': 'database',
        'postgres_error': 'database', 'postgres_auth': 'database', 'postgres_statement': 'database',
        'oracle_alert': 'database', 'oracle_listener': 'database', 'oracle_audit': 'database',
        'sqlserver_error': 'database', 'sqlserver_audit': 'database', 'sqlserver_transaction': 'database',
        'mongodb_server': 'database', 'mongodb_audit': 'database',
        'iptables': 'firewall', 'ufw': 'firewall', 'nftables': 'firewall', 'firewalld': 'firewall',
        'windows_firewall': 'firewall', 'palo_alto': 'firewall', 'fortigate': 'firewall',
        'cisco_asa': 'firewall', 'checkpoint': 'firewall', 'aws_vpc_flow': 'firewall',
        'azure_nsg': 'firewall', 'gcp_vpc': 'firewall',
        'syslog': 'system', 'systemd': 'system', 'kernel': 'system', 'audit': 'system',
        'package': 'system', 'cron': 'system', 'daemon': 'system',
        'windows_security': 'system', 'windows_system': 'system', 'windows_application': 'system',
        'postfix': 'mail', 'sendmail': 'mail', 'exim': 'mail', 'dovecot': 'mail', 'exchange': 'mail',
        'dns': 'network', 'dhcp': 'network', 'proxy': 'network',
    }
    return source_map.get(log_type, 'other')


def classify_attack(entry: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Classify a log entry as an attack type"""
    message = entry.get('message', '').lower()
    action = entry.get('action', '').lower()
    raw_line = entry.get('raw_line', '').lower()
    
    search_text = f"{message} {raw_line} {action}"
    
    for attack_type, patterns in ATTACK_TYPE_PATTERNS.items():
        matches = 0
        for pattern in patterns:
            if re.search(pattern, search_text, re.IGNORECASE):
                matches += 1
        
        if matches >= 1:
            confidence = min(0.5 + (matches * 0.15), 0.95)
            
            return {
                'attackType': attack_type,
                'confidence': confidence,
                'probability': confidence,
                'features': {'pattern_matches': matches},
                'explanation': [f"Found {matches} pattern(s) matching {attack_type}"],
                'isFalsePositive': False,
            }
    
    return None


def get_mitre_tactics(attack_type: str) -> List[str]:
    """Get MITRE ATT&CK tactics for an attack type"""
    return MITRE_TACTICS.get(attack_type, ['TA0006 - Credential Access'])


def get_mitre_techniques(attack_type: str) -> List[str]:
    """Get MITRE ATT&CK techniques for an attack type"""
    return MITRE_TECHNIQUES.get(attack_type, ['T1059 - Command and Scripting Interpreter'])


def extract_features(entries: List[Dict[str, Any]]) -> Optional[Any]:
    """Extract features for ML-based attack detection"""
    if not ML_AVAILABLE or len(entries) < 10:
        return None
    
    try:
        features = []
        for entry in entries:
            vector = []
            
            ip = entry.get('source', {}).get('ip', '')
            vector.append(hash(ip) % 1000 / 1000.0 if ip else 0.0)
            
            user = entry.get('user', {}).get('name', '')
            vector.append(hash(user) % 1000 / 1000.0 if user else 0.0)
            
            message = entry.get('message', '')
            vector.append(min(len(message) / 1000.0, 1.0))
            
            severity = entry.get('severity', 'info')
            severity_map = {'debug': 0, 'info': 1, 'warning': 2, 'error': 3, 'critical': 4}
            vector.append(severity_map.get(severity, 1) / 4.0)
            
            timestamp = entry.get('timestamp')
            if timestamp:
                try:
                    dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                    vector.append(dt.hour / 24.0)
                    vector.append(dt.weekday() / 7.0)
                except:
                    vector.extend([0.5, 0.5])
            else:
                vector.extend([0.5, 0.5])
            
            features.append(vector)
        
        return features
    except Exception as e:
        print(f"Feature extraction error: {e}")
        return None


def detect_ml_attacks(entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Detect attacks using ML-based anomaly detection"""
    features = extract_features(entries)
    if features is None:
        return []
    
    try:
        import numpy as np
        features_array = np.array(features)
        
        scaler = StandardScaler()
        features_scaled = scaler.fit_transform(features_array)
        
        iso_forest = IsolationForest(contamination=0.1, random_state=42)
        predictions = iso_forest.fit_predict(features_scaled)
        scores = iso_forest.decision_function(features_scaled)
        
        attacks = []
        for i, (entry, pred, score) in enumerate(zip(entries, predictions, scores)):
            if pred == -1:
                anomaly_score = abs(float(score))
                attacks.append({
                    'entry': entry,
                    'attackType': 'anomaly',
                    'confidence': min(anomaly_score * 1.5, 0.95),
                    'anomalyScore': anomaly_score,
                })
        
        return attacks
    except Exception as e:
        print(f"ML attack detection error: {e}")
        return []


def group_by_source_ip(entries: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    """Group entries by source IP"""
    groups = defaultdict(list)
    for entry in entries:
        ip = entry.get('source', {}).get('ip')
        if ip:
            groups[ip].append(entry)
    return dict(groups)


def group_by_user(entries: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    """Group entries by username"""
    groups = defaultdict(list)
    for entry in entries:
        user = entry.get('user', {}).get('name')
        if user:
            groups[user].append(entry)
    return dict(groups)


def build_ip_attack_chain(ip: str, entries: List[Dict[str, Any]], source_names: Dict[str, str]) -> Optional[ATTACK_CHAIN]:
    """Build attack chain for a single IP"""
    if len(entries) < 3:
        return None
    
    for entry in entries:
        classification = classify_attack(entry)
        if classification:
            events = sorted(entries, key=lambda e: e.get('timestamp', ''))
            
            start_time = events[0].get('timestamp', '')
            end_time = events[-1].get('timestamp', '')
            
            try:
                start = datetime.fromisoformat(start_time.replace('Z', '+00:00'))
                end = datetime.fromisoformat(end_time.replace('Z', '+00:00'))
                duration_minutes = (end - start).total_seconds() / 60
            except:
                duration_minutes = 0
            
            unique_users = list(set(e.get('user', {}).get('name', '') for e in events if e.get('user', {}).get('name')))
            
            return {
                'id': generate_id(),
                'startTime': start_time,
                'endTime': end_time,
                'attackType': classification['attackType'],
                'stage': 'execution',
                'events': events[:50],
                'sourceIps': [ip],
                'targetUsers': unique_users,
                'targetHosts': [],
                'prediction': classification,
                'mitreTactics': get_mitre_tactics(classification['attackType']),
                'mitreTechniques': get_mitre_techniques(classification['attackType']),
                'recommendation': generate_recommendation(classification['attackType'], duration_minutes),
            }
    
    return None


def build_user_attack_chain(user: str, entries: List[Dict[str, Any]], source_names: Dict[str, str]) -> Optional[ATTACK_CHAIN]:
    """Build attack chain for a single user"""
    if len(entries) < 3:
        return None
    
    for entry in entries:
        classification = classify_attack(entry)
        if classification:
            events = sorted(entries, key=lambda e: e.get('timestamp', ''))
            unique_ips = list(set(e.get('source', {}).get('ip', '') for e in events if e.get('source', {}).get('ip')))
            
            try:
                start = datetime.fromisoformat(events[0].get('timestamp', '').replace('Z', '+00:00'))
                end = datetime.fromisoformat(events[-1].get('timestamp', '').replace('Z', '+00:00'))
                duration_minutes = (end - start).total_seconds() / 60
            except:
                duration_minutes = 0
            
            return {
                'id': generate_id(),
                'startTime': events[0].get('timestamp', ''),
                'endTime': events[-1].get('timestamp', ''),
                'attackType': classification['attackType'],
                'stage': 'initial_access',
                'events': events[:50],
                'sourceIps': unique_ips,
                'targetUsers': [user],
                'targetHosts': [],
                'prediction': classification,
                'mitreTactics': get_mitre_tactics(classification['attackType']),
                'mitreTechniques': get_mitre_techniques(classification['attackType']),
                'recommendation': generate_recommendation(classification['attackType'], duration_minutes),
            }
    
    return None


def detect_sql_injection_chain(web_entries: List[Dict[str, Any]], db_entries: List[Dict[str, Any]]) -> Optional[ATTACK_CHAIN]:
    """Detect SQL injection chain: web request -> database error"""
    for web_entry in web_entries:
        message = web_entry.get('message', '').lower()
        if any(p in message for p in ['sql', 'union', 'select', "' or", '1=1']):
            web_time = web_entry.get('timestamp', '')
            try:
                web_ts = datetime.fromisoformat(web_time.replace('Z', '+00:00'))
                for db_entry in db_entries:
                    db_time = db_entry.get('timestamp', '')
                    db_ts = datetime.fromisoformat(db_time.replace('Z', '+00:00'))
                    if 0 < (db_ts - web_ts).total_seconds() < 60:
                        return {
                            'id': generate_id(),
                            'startTime': web_time,
                            'endTime': db_time,
                            'attackType': 'sql_injection',
                            'stage': 'execution',
                            'events': [web_entry, db_entry],
                            'sourceIps': [web_entry.get('source', {}).get('ip', '')],
                            'targetUsers': [],
                            'targetHosts': [],
                            'prediction': {
                                'attackType': 'sql_injection',
                                'confidence': 0.85,
                                'probability': 0.85,
                                'features': {},
                                'explanation': ['SQL injection attempt detected', 'Followed by database query execution'],
                                'isFalsePositive': False,
                            },
                            'mitreTactics': get_mitre_tactics('sql_injection'),
                            'mitreTechniques': get_mitre_techniques('sql_injection'),
                            'recommendation': 'Review web application input validation. Patch vulnerable endpoints. Implement prepared statements.',
                        }
            except:
                pass
    return None


def detect_account_takeover(auth_entries: List[Dict[str, Any]]) -> Optional[ATTACK_CHAIN]:
    """Detect account takeover: multiple failures followed by success"""
    user_groups = defaultdict(list)
    for entry in auth_entries:
        user = entry.get('user', {}).get('name')
        if user:
            user_groups[user].append(entry)
    
    for user, events in user_groups.items():
        failures = [e for e in events if e.get('outcome') == 'failure']
        successes = [e for e in events if e.get('outcome') == 'success']
        
        if len(failures) >= 5 and len(successes) > 0:
            unique_ips = list(set(e.get('source', {}).get('ip', '') for e in failures if e.get('source', {}).get('ip')))
            
            if len(unique_ips) >= 1:
                all_events = sorted(failures + successes, key=lambda e: e.get('timestamp', ''))
                
                return {
                    'id': generate_id(),
                    'startTime': failures[0].get('timestamp', ''),
                    'endTime': successes[0].get('timestamp', ''),
                    'attackType': 'account_takeover',
                    'stage': 'initial_access',
                    'events': all_events[:50],
                    'sourceIps': unique_ips,
                    'targetUsers': [user],
                    'targetHosts': [],
                    'prediction': {
                        'attackType': 'account_takeover',
                        'confidence': 0.9,
                        'probability': 0.9,
                        'features': {},
                        'explanation': [
                            f'{len(failures)} failed login attempts',
                            f'Successful login detected',
                            'Account compromise likely'
                        ],
                        'isFalsePositive': False,
                    },
                    'mitreTactics': get_mitre_tactics('account_takeover'),
                    'mitreTechniques': get_mitre_techniques('account_takeover'),
                    'recommendation': f'Force password reset for user "{user}". Review recent login locations. Enable MFA.',
                }
    return None


def detect_privilege_escalation(auth_entries: List[Dict[str, Any]]) -> Optional[ATTACK_CHAIN]:
    """Detect privilege escalation from auth logs"""
    admin_access = []
    for entry in auth_entries:
        if entry.get('outcome') == 'success':
            user = entry.get('user', {}).get('name', '')
            if any(admin in user.lower() for admin in ['admin', 'root', 'administrator', 'system']):
                admin_access.append(entry)
    
    if len(admin_access) >= 1:
        return {
            'id': generate_id(),
            'startTime': admin_access[0].get('timestamp', ''),
            'endTime': admin_access[-1].get('timestamp', ''),
            'attackType': 'privilege_escalation',
            'stage': 'privilege_escalation',
            'events': admin_access[:20],
            'sourceIps': list(set(e.get('source', {}).get('ip', '') for e in admin_access)),
            'targetUsers': list(set(e.get('user', {}).get('name', '') for e in admin_access)),
            'targetHosts': [],
            'prediction': {
                'attackType': 'privilege_escalation',
                'confidence': 0.75,
                'probability': 0.75,
                'features': {},
                'explanation': ['Admin/root access detected'],
                'isFalsePositive': False,
            },
            'mitreTactics': get_mitre_tactics('privilege_escalation'),
            'mitreTechniques': get_mitre_techniques('privilege_escalation'),
            'recommendation': 'Review sudo/admin permissions. Enable LSA protection. Monitor admin activity.',
        }
    return None


def detect_ransomware(sys_entries: List[Dict[str, Any]]) -> Optional[ATTACK_CHAIN]:
    """Detect ransomware indicators"""
    indicators = []
    for entry in sys_entries:
        message = entry.get('message', '').lower()
        if any(p in message for p in ['vssadmin.*delete', 'shadowcopy.*delete', 'encrypt', '.locked', 'bcditedit']):
            indicators.append(entry)
    
    if len(indicators) >= 2:
        return {
            'id': generate_id(),
            'startTime': indicators[0].get('timestamp', ''),
            'endTime': indicators[-1].get('timestamp', ''),
            'attackType': 'ransomware',
            'stage': 'complete',
            'events': indicators[:20],
            'sourceIps': list(set(e.get('source', {}).get('ip', '') for e in indicators)),
            'targetUsers': [],
            'targetHosts': list(set(e.get('destination', {}).get('hostname', '') for e in indicators if e.get('destination', {}).get('hostname'))),
            'prediction': {
                'attackType': 'ransomware',
                'confidence': 0.9,
                'probability': 0.9,
                'features': {},
                'explanation': ['Ransomware indicators detected', 'Volume shadow copy deletion', 'File encryption activity'],
                'isFalsePositive': False,
            },
            'mitreTactics': get_mitre_tactics('ransomware'),
            'mitreTechniques': get_mitre_techniques('ransomware'),
            'recommendation': 'CRITICAL: Restore from backups immediately. Isolate affected systems. Do not pay ransom.',
        }
    return None


def detect_webshell(web_entries: List[Dict[str, Any]]) -> Optional[ATTACK_CHAIN]:
    """Detect web shell patterns"""
    webshell_patterns = []
    for entry in web_entries:
        message = entry.get('message', '')
        if re.search(r'\.(php|asp|aspx|jsp)\?cmd=|c99|r57|b374k|wso|eval\s*\(', message, re.IGNORECASE):
            webshell_patterns.append(entry)
    
    if len(webshell_patterns) >= 1:
        return {
            'id': generate_id(),
            'startTime': webshell_patterns[0].get('timestamp', ''),
            'endTime': webshell_patterns[-1].get('timestamp', ''),
            'attackType': 'webshell',
            'stage': 'persistence',
            'events': webshell_patterns[:20],
            'sourceIps': list(set(e.get('source', {}).get('ip', '') for e in webshell_patterns)),
            'targetUsers': [],
            'targetHosts': list(set(e.get('destination', {}).get('hostname', '') for e in webshell_patterns if e.get('destination', {}).get('hostname'))),
            'prediction': {
                'attackType': 'webshell',
                'confidence': 0.8,
                'probability': 0.8,
                'features': {},
                'explanation': ['Web shell patterns detected'],
                'isFalsePositive': False,
            },
            'mitreTactics': get_mitre_tactics('webshell'),
            'mitreTechniques': get_mitre_techniques('webshell'),
            'recommendation': 'Remove webshell files. Review web server logs. Check file integrity.',
        }
    return None


def detect_bruteforce_pattern(auth_entries: List[Dict[str, Any]]) -> Optional[ATTACK_CHAIN]:
    """Detect brute force attack pattern"""
    failures = [e for e in auth_entries if e.get('outcome') == 'failure']
    ip_groups = group_by_source_ip(failures)
    
    for ip, ip_failures in ip_groups.items():
        if len(ip_failures) >= 5:
            return {
                'id': generate_id(),
                'startTime': ip_failures[0].get('timestamp', ''),
                'endTime': ip_failures[-1].get('timestamp', ''),
                'attackType': 'bruteforce',
                'stage': 'reconnaissance',
                'events': ip_failures[:50],
                'sourceIps': [ip],
                'targetUsers': list(set(e.get('user', {}).get('name', '') for e in ip_failures if e.get('user', {}).get('name'))),
                'targetHosts': [],
                'prediction': {
                    'attackType': 'bruteforce',
                    'confidence': 0.85,
                    'probability': 0.85,
                    'features': {},
                    'explanation': [f'{len(ip_failures)} failed login attempts from {ip}'],
                    'isFalsePositive': False,
                },
                'mitreTactics': get_mitre_tactics('bruteforce'),
                'mitreTechniques': get_mitre_techniques('bruteforce'),
                'recommendation': 'Implement account lockout policies. Use strong passwords. Enable MFA.',
            }
    return None


def detect_kill_chains(entries: List[Dict[str, Any]]) -> List[ATTACK_CHAIN]:
    """Detect cross-source attack chains (kill chain detection)"""
    chains = []
    
    web_entries = [e for e in entries if get_log_source(e.get('log_type', '')) == 'web']
    db_entries = [e for e in entries if get_log_source(e.get('log_type', '')) == 'database']
    auth_entries = [e for e in entries if get_log_source(e.get('log_type', '')) == 'auth']
    sys_entries = [e for e in entries if get_log_source(e.get('log_type', '')) == 'system']
    
    if web_entries and db_entries:
        chain = detect_sql_injection_chain(web_entries, db_entries)
        if chain:
            chains.append(chain)
    
    if auth_entries:
        chain = detect_account_takeover(auth_entries)
        if chain:
            chains.append(chain)
    
    chain = detect_privilege_escalation(auth_entries)
    if chain:
        chains.append(chain)
    
    if sys_entries:
        chain = detect_ransomware(sys_entries)
        if chain:
            chains.append(chain)
    
    if web_entries:
        chain = detect_webshell(web_entries)
        if chain:
            chains.append(chain)
    
    chain = detect_bruteforce_pattern(auth_entries)
    if chain:
        chains.append(chain)
    
    return chains


def detect_temporal_patterns(entries: List[Dict[str, Any]]) -> List[ATTACK_CHAIN]:
    """Detect burst activity patterns"""
    chains = []
    ip_groups = group_by_source_ip(entries)
    
    for ip, ip_entries in ip_groups.items():
        if len(ip_entries) < 10:
            continue
        
        sorted_entries = sorted(ip_entries, key=lambda e: e.get('timestamp', ''))
        
        try:
            first_time = datetime.fromisoformat(sorted_entries[0].get('timestamp', '').replace('Z', '+00:00'))
            burst_entries = []
            
            for entry in sorted_entries:
                entry_time = datetime.fromisoformat(entry.get('timestamp', '').replace('Z', '+00:00'))
                if (entry_time - first_time).total_seconds() < 60:
                    burst_entries.append(entry)
            
            if len(burst_entries) >= 10:
                chains.append({
                    'id': generate_id(),
                    'startTime': burst_entries[0].get('timestamp', ''),
                    'endTime': burst_entries[-1].get('timestamp', ''),
                    'attackType': 'ddos',
                    'stage': 'execution',
                    'events': burst_entries[:50],
                    'sourceIps': [ip],
                    'targetUsers': [],
                    'targetHosts': [],
                    'prediction': {
                        'attackType': 'ddos',
                        'confidence': 0.7,
                        'probability': 0.7,
                        'features': {},
                        'explanation': [f'Burst activity: {len(burst_entries)} events in 1 minute'],
                        'isFalsePositive': False,
                    },
                    'mitreTactics': get_mitre_tactics('ddos'),
                    'mitreTechniques': get_mitre_techniques('ddos'),
                    'recommendation': 'Review request patterns. Implement rate limiting. Consider DDoS protection.',
                })
        except:
            pass
    
    return chains


def create_correlated_event(entry: Dict[str, Any], source_name: str, attack_type: str = '', progress: float = 0) -> CORRELATED_EVENT:
    """Create a correlated event from a log entry"""
    severity_scores = {'critical': 1.0, 'high': 0.8, 'error': 0.6, 'warning': 0.4, 'info': 0.2, 'debug': 0.1, 'unknown': 0.2}
    
    return {
        'id': entry.get('id', generate_id()),
        'timestamp': entry.get('timestamp', ''),
        'logSource': get_log_source(entry.get('log_type', '')),
        'logType': entry.get('log_type', ''),
        'severity': entry.get('severity', 'unknown'),
        'sourceIp': entry.get('source', {}).get('ip', ''),
        'targetUser': entry.get('user', {}).get('name', ''),
        'targetHost': entry.get('destination', {}).get('hostname', '') or entry.get('source', {}).get('hostname', ''),
        'action': entry.get('action', ''),
        'outcome': entry.get('outcome', ''),
        'message': entry.get('message', '')[:500],
        'relatedEventIds': [],
        'correlationScore': min(0.5 + progress * 0.5, severity_scores.get(entry.get('severity', ''), 0.5)),
    }


def determine_attack_stage(events: List[CORRELATED_EVENT], attack_type: str) -> str:
    """Determine the stage of an attack chain"""
    sources = set(e['logSource'] for e in events)
    has_success = any(e['outcome'] == 'success' for e in events)
    has_failure = any(e['outcome'] == 'failure' for e in events)
    
    stages = {
        'bruteforce': 'initial_access' if has_success else 'reconnaissance',
        'password_spray': 'initial_access' if has_success else 'reconnaissance',
        'sql_injection': 'execution',
        'xss_attack': 'execution',
        'command_injection': 'execution',
        'privilege_escalation': 'privilege_escalation',
        'lateral_movement': 'lateral_movement',
        'data_exfiltration': 'exfiltration',
        'ransomware': 'complete',
        'webshell': 'persistence',
        'c2_communication': 'execution',
        'ddos': 'execution',
    }
    
    if attack_type in stages:
        return stages[attack_type]
    
    if len(sources) > 2:
        return 'execution'
    if has_success and not has_failure:
        return 'complete'
    return 'execution'


def generate_recommendation(attack_type: str, duration_minutes: float = 0) -> str:
    """Generate security recommendation for an attack type"""
    recommendations = {
        'bruteforce': 'Implement account lockout policies. Use strong passwords. Enable MFA.',
        'password_spray': 'Monitor for unusual login patterns. Block suspicious IPs. Use MFA.',
        'sql_injection': 'Review input validation. Use prepared statements. Patch vulnerabilities.',
        'xss_attack': 'Implement CSP headers. Sanitize user inputs. Use framework security features.',
        'command_injection': 'Avoid system() calls. Use parameterized commands. Validate all inputs.',
        'privilege_escalation': 'Review sudo/admin permissions. Enable LSA protection. Monitor admin activity.',
        'lateral_movement': 'Implement network segmentation. Restrict remote access. Monitor authentication patterns.',
        'data_exfiltration': 'Block unusual data transfers. Implement DLP. Monitor DNS queries.',
        'ransomware': 'CRITICAL: Restore from backups immediately. Isolate affected systems. Do not pay ransom.',
        'webshell': 'Remove webshell files. Review web server logs. Check file integrity.',
        'c2_communication': 'Block suspicious domains. Implement DNS filtering. Investigate hosts.',
        'account_takeover': 'Force password reset for compromised accounts. Review recent activity. Enable MFA.',
        'default': 'Review the attack chain. Implement defense-in-depth. Enable enhanced monitoring.',
    }
    
    prefix = f'Attack occurred over {duration_minutes:.1f} minutes. ' if duration_minutes > 0 else ''
    return prefix + (recommendations.get(attack_type, recommendations['default']))


def build_enhanced_timeline(entries: List[Dict[str, Any]], chains: List[ATTACK_CHAIN], source_names: Dict[str, str]) -> List[TIMELINE_EVENT]:
    """Build enhanced timeline with attack chain correlation"""
    events = []
    chain_ids = {c['id'] for c in chains}
    
    for entry in entries:
        chain = next((c for c in chains if any(e.get('id') == entry.get('id') for e in c.get('events', []))), None)
        is_anomaly = chain is not None
        
        events.append({
            'id': entry.get('id', generate_id()),
            'timestamp': entry.get('timestamp', ''),
            'logSource': get_log_source(entry.get('log_type', '')),
            'eventType': entry.get('log_type', ''),
            'severity': entry.get('severity', 'info'),
            'title': generate_event_title(entry),
            'description': entry.get('message', '')[:200],
            'sourceIp': entry.get('source', {}).get('ip', ''),
            'targetUser': entry.get('user', {}).get('name', ''),
            'relatedAttackChainId': chain.get('id') if chain else None,
            'isAnomaly': is_anomaly,
            'anomalyScore': chain.get('prediction', {}).get('confidence', 0) if chain else 0,
        })
    
    return sorted(events, key=lambda e: e['timestamp'])


def generate_event_title(entry: Dict[str, Any]) -> str:
    """Generate a title for an event"""
    if entry.get('source', {}).get('ip') and entry.get('action'):
        return f"{entry['source']['ip']} {entry['action']}"
    if entry.get('user', {}).get('name'):
        user = entry['user']['name']
        outcome = entry.get('outcome', '')
        return f"{user} {outcome}".strip()
    if entry.get('severity'):
        return f"{entry['severity'].upper()} event"
    return 'Log Entry'


def generate_enhanced_summary(entries: List[Dict[str, Any]], chains: List[ATTACK_CHAIN]) -> Dict[str, Any]:
    """Generate enhanced summary with attack statistics"""
    severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
    for entry in entries:
        s = entry.get('severity', '').lower()
        if s in severity_counts:
            severity_counts[s] += 1
    
    ip_threats = defaultdict(lambda: {'count': 0, 'types': set()})
    user_targets = defaultdict(int)
    
    for chain in chains:
        for ip in chain.get('sourceIps', []):
            ip_threats[ip]['count'] += 1
            ip_threats[ip]['types'].add(chain['attackType'])
        for user in chain.get('targetUsers', []):
            user_targets[user] += 1
    
    sorted_ip_threats = sorted(
        [{'ip': ip, 'count': data['count'], 'threatScore': data['count'] * len(data['types']), 'attackTypes': list(data['types'])} 
         for ip, data in ip_threats.items()],
        key=lambda x: x['threatScore'],
        reverse=True
    )[:10]
    
    sorted_users = sorted(
        [{'user': user, 'count': count} for user, count in user_targets.items()],
        key=lambda x: x['count'],
        reverse=True
    )[:10]
    
    attack_types_detected = list(set(c['attackType'] for c in chains))
    
    risk_score = min(
        len(chains) * 15 +
        severity_counts['critical'] * 20 +
        severity_counts['high'] * 10 +
        len(sorted_ip_threats) * 5,
        100
    )
    
    return {
        'totalAlerts': len(entries),
        'criticalAlerts': severity_counts['critical'],
        'falsePositivesFiltered': len([c for c in chains if c.get('prediction', {}).get('isFalsePositive')]),
        'attackTypesDetected': attack_types_detected,
        'mostTargetedUsers': sorted_users,
        'mostActiveSourceIps': sorted_ip_threats,
        'riskScore': risk_score,
    }


def generate_recommendations_list(chains: List[ATTACK_CHAIN]) -> List[str]:
    """Generate security recommendations list"""
    recs = set()
    
    for chain in chains:
        recs.add(chain.get('recommendation', ''))
        
        if chain['attackType'] == 'bruteforce':
            recs.add('Consider implementing rate limiting on authentication endpoints')
        if chain['attackType'] == 'sql_injection':
            recs.add('Review and patch all web application inputs')
        if chain['stage'] == 'complete':
            recs.add('CRITICAL: Immediate investigation required - attack completed')
    
    if not recs:
        return ['No anomalies detected in the provided logs']
    
    return list(recs)[:10]


def correlate_multiple_logs_enhanced(log_sources: List[Dict[str, Any]]) -> CORRELATION_RESULT:
    """Main entry point for enhanced multi-log correlation"""
    all_entries = []
    source_names = {}
    
    for source in log_sources:
        for entry in source.get('entries', []):
            entry['log_type'] = entry.get('log_type', entry.get('logType', ''))
            all_entries.append(entry)
            source_names[entry.get('id', '')] = source.get('name', 'unknown')
    
    if not all_entries:
        return {
            'success': True,
            'totalEvents': 0,
            'correlatedEvents': 0,
            'attackChains': [],
            'timeline': [],
            'summary': {
                'totalAlerts': 0,
                'criticalAlerts': 0,
                'falsePositivesFiltered': 0,
                'attackTypesDetected': [],
                'mostTargetedUsers': [],
                'mostActiveSourceIps': [],
                'riskScore': 0,
            },
            'recommendations': ['No anomalies detected in the provided logs'],
        }
    
    sorted_entries = sorted(
        [e for e in all_entries if e.get('timestamp')],
        key=lambda x: x.get('timestamp', '')
    )
    
    attack_chains = []
    processed_ids = set()
    
    by_ip = group_by_source_ip(sorted_entries)
    for ip, ip_entries in by_ip.items():
        chain = build_ip_attack_chain(ip, ip_entries, source_names)
        if chain:
            attack_chains.append(chain)
            for e in chain['events']:
                processed_ids.add(e.get('id'))
    
    by_user = group_by_user(sorted_entries)
    for user, user_entries in by_user.items():
        uncovered = [e for e in user_entries if e.get('id') not in processed_ids]
        if len(uncovered) >= 3:
            chain = build_user_attack_chain(user, uncovered, source_names)
            if chain:
                attack_chains.append(chain)
                for e in chain['events']:
                    processed_ids.add(e.get('id'))
    
    cross_chains = detect_kill_chains(sorted_entries)
    for chain in cross_chains:
        if not any(e.get('id') in [ev.get('id') for ev in chain.get('events', [])] for c in attack_chains for ev in c.get('events', [])):
            attack_chains.append(chain)
    
    temporal_chains = detect_temporal_patterns(sorted_entries)
    for chain in temporal_chains:
        if not any(e.get('id') in [ev.get('id') for ev in chain.get('events', [])] for c in attack_chains for ev in c.get('events', [])):
            attack_chains.append(chain)
    
    attack_chains = [c for c in attack_chains if not c.get('prediction', {}).get('isFalsePositive', False)]
    
    timeline = build_enhanced_timeline(sorted_entries, attack_chains, source_names)
    summary = generate_enhanced_summary(sorted_entries, attack_chains)
    recommendations = generate_recommendations_list(attack_chains)
    
    return {
        'success': True,
        'totalEvents': len(all_entries),
        'correlatedEvents': sum(len(c.get('events', [])) for c in attack_chains),
        'attackChains': attack_chains,
        'timeline': timeline,
        'summary': summary,
        'recommendations': recommendations,
    }
