"""
Alert Detection System - Enhanced Rule-Based Analysis with MITRE Mapping
"""

from typing import List, Dict, Any
from collections import defaultdict

MITRE_MAPPING = {
    "bruteforce": ["Credential Access"],
    "credential_stuffing": ["Credential Access"],
    "sql_injection": ["Initial Access", "Execution"],
    "xss_attack": ["Initial Access"],
    "path_traversal": ["Initial Access", "Exfiltration"],
    "port_scan": ["Reconnaissance"],
    "threat_intel": ["Reconnaissance"],
    "anomaly": ["Suspicious Activity"],
    "spam_activity": ["Resource Hijacking"]
}

def run_detections(entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Run enhanced detection rules on parsed entries"""
    alerts = []
    
    # Stateful tracking within this batch
    ip_stats = defaultdict(lambda: {'failed': 0, 'users': set(), 'ports': set(), 'entries': [], 'actions': set()})
    user_stats = defaultdict(lambda: {'failed': 0, 'ips': set(), 'entries': []})
    
    for entry in entries:
        # Extract source IP, user, and other metadata
        source_ip = entry.get('source', {}).get('ip') or entry.get('fields', {}).get('ip')
        user_name = entry.get('user', {}).get('name') or entry.get('fields', {}).get('user')
        port = entry.get('source', {}).get('port') or entry.get('fields', {}).get('port') or entry.get('fields', {}).get('dst_port')
        outcome = entry.get('outcome', 'unknown')
        action = entry.get('action', 'unknown')
        
        # 1. Basic attack detection from ML/Keywords
        if entry.get('attackType') and entry.get('attackType') not in ['safe', 'normal']:
            at = entry.get('attackType')
            confidence_val = entry.get('attackConfidence', 0.8)
            confidence_pct = f"{confidence_val * 100:.0f}%"
            
            alerts.append({
                'id': entry.get('id'),
                'type': at,
                'title': f"Detected {at.replace('_', ' ').title()}",
                'description': entry.get('message', 'No message available'),
                'severity': entry.get('severity', 'high'),
                'confidence': confidence_pct,
                'message': f"Attack detected: {at} (confidence: {confidence_pct})",
                'sourceIps': [source_ip] if source_ip else [],
                'timestamp': entry.get('timestamp'),
                'mitreTactics': MITRE_MAPPING.get(at, ["Unknown"]),
                'entry': entry,
            })

        # 2. Track stats for behavioral rules
        if source_ip and source_ip != 'LOCAL':
            ip_stats[source_ip]['entries'].append(entry)
            ip_stats[source_ip]['actions'].add(action)
            if outcome == 'failure':
                ip_stats[source_ip]['failed'] += 1
            if user_name:
                ip_stats[source_ip]['users'].add(user_name)
                user_stats[user_name]['failed'] += (1 if outcome == 'failure' else 0)
                user_stats[user_name]['ips'].add(source_ip)
                user_stats[user_name]['entries'].append(entry)
            if port:
                ip_stats[source_ip]['ports'].add(port)

    # 3. Apply Behavioral Rules on aggregated data
    
    # Rule: Port Scanning Detection
    for ip, stats in ip_stats.items():
        if len(stats['ports']) >= 10:
            last_entry = stats['entries'][-1]
            alerts.append({
                'id': f"port-scan-{ip}",
                'type': 'port_scan',
                'title': 'Potential Port Scan Detected',
                'description': f"IP {ip} targeted {len(stats['ports'])} unique ports in a short period.",
                'severity': 'medium',
                'confidence': '85%',
                'message': f"Port scanning activity from {ip}",
                'sourceIps': [ip],
                'timestamp': last_entry.get('timestamp'),
                'mitreTactics': ["Reconnaissance"],
                'entry': last_entry,
            })

    # Rule: Brute Force Detection
    for ip, stats in ip_stats.items():
        if stats['failed'] >= 5:
            severity = 'high' if stats['failed'] >= 15 else 'medium'
            last_entry = stats['entries'][-1]
            alerts.append({
                'id': f"brute-force-{ip}",
                'type': 'bruteforce',
                'title': 'Brute Force Attack Detected',
                'description': f"IP {ip} had {stats['failed']} failed login attempts for users: {', '.join(list(stats['users'])[:3])}",
                'severity': severity,
                'confidence': '90%',
                'message': f"Likely brute force from {ip} ({stats['failed']} failures)",
                'sourceIps': [ip],
                'timestamp': last_entry.get('timestamp'),
                'mitreTactics': ["Credential Access"],
                'entry': last_entry,
            })

    # Rule: Credential Stuffing
    for ip, stats in ip_stats.items():
        if len(stats['users']) >= 3 and stats['failed'] >= 5:
            last_entry = stats['entries'][-1]
            alerts.append({
                'id': f"cred-stuffing-{ip}",
                'type': 'credential_stuffing',
                'title': 'Credential Stuffing Detected',
                'description': f"IP {ip} attempted to login as {len(stats['users'])} different users",
                'severity': 'high',
                'confidence': '85%',
                'message': f"Credential stuffing from {ip} across {len(stats['users'])} users",
                'sourceIps': [ip],
                'timestamp': last_entry.get('timestamp'),
                'mitreTactics': ["Credential Access"],
                'entry': last_entry,
            })

    return alerts

def generate_stats(entries: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Generate statistics from entries"""
    by_severity = {}
    by_outcome = {}
    by_type = {}
    source_ips = set()
    users = set()
    
    for entry in entries:
        # By severity
        severity = entry.get('severity', 'unknown')
        by_severity[severity] = by_severity.get(severity, 0) + 1
        
        # By outcome
        outcome = entry.get('outcome', 'unknown')
        by_outcome[outcome] = by_outcome.get(outcome, 0) + 1
        
        # By type
        log_type = entry.get('logType', 'unknown')
        by_type[log_type] = by_type.get(log_type, 0) + 1
        
        # Source IPs
        if entry.get('source', {}).get('ip'):
            source_ips.add(entry['source']['ip'])
        
        # Users
        if entry.get('user', {}).get('name'):
            users.add(entry['user']['name'])
    
    return {
        'bySeverity': by_severity,
        'byOutcome': by_outcome,
        'byType': by_type,
        'uniqueSources': len(source_ips),
        'uniqueUsers': len(users),
    }
