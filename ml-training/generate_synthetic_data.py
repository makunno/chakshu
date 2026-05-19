"""
Synthetic Data Generator for SIEM ML Training
Generates realistic log data with attack patterns for each log type category
"""

import random
import json
from datetime import datetime, timedelta
from typing import List, Dict, Any
import os

# Log Categories and their attack patterns
LOG_CATEGORIES = {
    'webserver': ['apache', 'nginx', 'iis', 'django', 'flask', 'express', 'rails'],
    'database': ['mysql_error', 'mysql_query', 'postgres_error', 'oracle_alert', 'sqlserver_error', 'mongodb'],
    'auth': ['ssh_auth', 'pam', 'windows_auth', 'ldap', 'kerberos'],
    'firewall': ['iptables', 'ufw', 'palo_alto', 'fortigate', 'cisco_asa', 'windows_firewall'],
    'mail': ['postfix', 'sendmail', 'exchange', 'dovecot'],
    'network': ['dns', 'dhcp', 'ftp', 'proxy', 'snort'],
    'system': ['syslog', 'systemd', 'kernel', 'audit', 'windows_event'],
    'cloud': ['aws_cloudtrail', 'azure_activity', 'gcp_audit', 'cloudflare']
}

# Attack patterns for each category
ATTACK_PATTERNS = {
    'webserver': [
        {'type': 'sql_injection', 'patterns': ["' OR '1'='1", "UNION SELECT", "1=1--", "admin'--", "<script>"]},
        {'type': 'xss_attack', 'patterns': ["<script>", "javascript:", "onerror=", "onload="]},
        {'type': 'path_traversal', 'patterns': ["../../etc/passwd", "..\\..\\windows", "/etc/shadow"]},
        {'type': 'command_injection', 'patterns': ["; ls -la", "| cat /etc/passwd", "`whoami`", "$(whoami)"]},
        {'type': 'bruteforce', 'patterns': ["Failed password", "authentication failure"]},
        {'type': 'ddos', 'patterns': []},  # Volume-based
    ],
    'database': [
        {'type': 'sql_injection', 'patterns': ["' OR '1'='1", "UNION ALL", "DROP TABLE", "1=1--"]},
        {'type': 'bruteforce', 'patterns': ["Access denied", "Failed login", "invalid password"]},
        {'type': 'privilege_escalation', 'patterns': ["GRANT ALL", "CREATE USER", "SUPER privilege"]},
        {'type': 'data_exfiltration', 'patterns': ["SELECT * FROM users", "COPY TO"]},
    ],
    'auth': [
        {'type': 'bruteforce', 'patterns': ["Failed password", "authentication failure", "Invalid user"]},
        {'type': 'password_spray', 'patterns': ["Failed password", "authentication failure"]},
        {'type': 'credential_stuffing', 'patterns': ["Accepted password", "session opened"]},
        {'type': 'mfa_bypass', 'patterns': ["MFA failed", "MFA bypass attempt"]},
        {'type': 'mfa_fatigue', 'patterns': ["MFA push approved", "Multiple MFA requests"]},
        {'type': 'session_hijacking', 'patterns': ["Session hijack", "Cookie stolen"]},
        {'type': 'privilege_escalation', 'patterns': ["sudo", "su: root", "admin"]},
    ],
    'firewall': [
        {'type': 'port_scan', 'patterns': ["SYN scan", "NULL scan", "XMAS scan", "FIN scan"]},
        {'type': 'ddos', 'patterns': []},  # Volume-based
        {'type': 'reconnaissance', 'patterns': ["Allowed", "Deny"]},
        {'type': 'lateral_movement', 'patterns': ["Internal connection", "East-West traffic"]},
    ],
    'mail': [
        {'type': 'phishing', 'patterns': ["Suspicious link", "Phishing attempt", "SPF fail"]},
        {'type': 'spam', 'patterns': ["Spam detected", "Bulk mail"]},
        {'type': 'data_exfiltration', 'patterns': ["Attachment sent", "Large attachment"]},
    ],
    'network': [
        {'type': 'dns_tunneling', 'patterns': ["Long DNS query", "Unusual DNS"]},
        {'type': 'port_scan', 'patterns': ["Scan detected", "Port probe"]},
        {'type': 'data_exfiltration', 'patterns': ["Large upload", "High bandwidth"]},
    ],
    'system': [
        {'type': 'privilege_escalation', 'patterns': ["sudo", "su root", "admin"]},
        {'type': 'malware_activity', 'patterns': ["Suspicious process", "Malware detected"]},
        {'type': 'insider_threat', 'patterns': ["Large file access", "Off hours"]},
    ],
    'cloud': [
        {'type': 'privilege_escalation', 'patterns': ["CreateUser", "AttachRole"]},
        {'type': 'data_exfiltration', 'patterns': ["GetObject", "Download"]},
        {'type': 'cryptomining', 'patterns': ["Cryptocurrency", "Mining"]},
        {'type': 'supply_chain', 'patterns': ["CodeBuild", "Pipeline"]},
    ]
}

NORMAL_PATTERNS = {
    'webserver': [
        '192.168.1.100 - - [10/Oct/2024:10:15:32] "GET /index.html HTTP/1.1" 200 1234',
        '10.0.0.5 - - [10/Oct/2024:10:15:33] "POST /login HTTP/1.1" 302 0',
        '192.168.1.101 - - [10/Oct/2024:10:15:34] "GET /api/users HTTP/1.1" 200 5678',
    ],
    'database': [
        '2024-10-10T10:15:32.123Z Query: SELECT * FROM users WHERE id=1',
        '2024-10-10T10:15:33.456Z Connect: root@localhost on test',
        '2024-10-10T10:15:34.789Z Query: INSERT INTO logs (msg) VALUES ("test")',
    ],
    'auth': [
        'Oct 10 10:15:32 server sshd[1234]: Accepted password for admin from 192.168.1.100 port 22',
        'Oct 10 10:15:33 server sudo: admin : TTY=pts/0 ; PWD=/home ; USER=root ; COMMAND=/bin/ls',
        'Oct 10 10:15:34 server pam[5678]: login succeeded for user admin',
    ],
    'firewall': [
        'Oct 10 10:15:32 fw kernel: [UFW BLOCK] IN=eth0 OUT= MAC=00:11:22 SRC=192.168.1.100 DST=10.0.0.1 PROTO=TCP',
        'Oct 10 10:15:33 fw kernel: [UFW ALLOW] IN=eth0 OUT= SRC=192.168.1.100 DST=8.8.8.8 PROTO=UDP',
    ],
    'mail': [
        'Oct 10 10:15:32 mail postfix/smtp[1234]: connect from unknown[192.168.1.100]',
        'Oct 10 10:15:33 mail postfix/cleanup[5678]: message-id=<test@example.com>',
    ],
    'network': [
        'Oct 10 10:15:32 dns named[1234]: query: example.com IN A +EDC',
        'Oct 10 10:15:33 dhcp dhcpd[5678]: DHCPDISCOVER from 00:11:22:33:44:55',
    ],
    'system': [
        'Oct 10 10:15:32 server systemd[1]: Started Apache Web Server',
        'Oct 10 10:15:33 server kernel: [1234.567] CPU0: Core temperature above threshold',
    ],
    'cloud': [
        '{"eventTime": "2024-10-10T10:15:32Z", "eventName": "ConsoleLogin", "sourceIPAddress": "192.168.1.100"}',
    ]
}

def generate_ip(private=True):
    """Generate random IP address"""
    if private:
        return f"{random.choice([10, 192, 172])}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
    return f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"

def generate_timestamp(base_time=None):
    """Generate random timestamp"""
    if base_time is None:
        base_time = datetime.now()
    delta = timedelta(seconds=random.randint(0, 3600))
    return (base_time - delta).strftime('%d/%b/%Y:%H:%M:%S')

def generate_log_entry(log_type: str, is_attack: bool = False, attack_type: str = None) -> Dict[str, Any]:
    """Generate a single log entry"""
    category = None
    for cat, types in LOG_CATEGORIES.items():
        if log_type in types:
            category = cat
            break
    
    if category is None:
        category = 'system'
    
    normal_patterns = NORMAL_PATTERNS.get(category, NORMAL_PATTERNS['system'])
    attack_patterns = ATTACK_PATTERNS.get(category, [])
    
    if is_attack and attack_patterns and attack_patterns[0].get('patterns'):
        attack_info = random.choice(attack_patterns)
        if attack_type and attack_type != attack_info['type']:
            return generate_log_entry(log_type, False)
        
        patterns = attack_info.get('patterns', [])
        pattern = random.choice(patterns) if patterns else f"Attack pattern {attack_info.get('type', 'unknown')}"
        
        entry = {
            'timestamp': generate_timestamp(),
            'source_ip': generate_ip(),
            'log_type': log_type,
            'attack_type': attack_info.get('type', 'unknown'),
            'message': f"{pattern} from {generate_ip()}",
            'is_attack': True
        }
    else:
        entry = {
            'timestamp': generate_timestamp(),
            'source_ip': generate_ip(),
            'log_type': log_type,
            'attack_type': 'normal',
            'message': random.choice(normal_patterns) if normal_patterns else 'Normal activity',
            'is_attack': False
        }
    
    return entry

def generate_dataset(category: str, num_samples: int = 10000, attack_ratio: float = 0.1) -> List[Dict[str, Any]]:
    """Generate dataset for a log category"""
    log_types = LOG_CATEGORIES.get(category, ['syslog'])
    dataset = []
    
    num_attacks = int(num_samples * attack_ratio)
    num_normal = num_samples - num_attacks
    
    for _ in range(num_normal):
        log_type = random.choice(log_types)
        dataset.append(generate_log_entry(log_type, False))
    
    for _ in range(num_attacks):
        log_type = random.choice(log_types)
        dataset.append(generate_log_entry(log_type, True))
    
    random.shuffle(dataset)
    return dataset

def generate_all_datasets(output_dir: str, samples_per_category: int = 10000):
    """Generate datasets for all categories"""
    os.makedirs(output_dir, exist_ok=True)
    
    # Real datasets to download
    real_datasets = {
        'ssh': 'https://raw.githubusercontent.com/otoolep/hdfs/master/tests/data/ssh_logs.txt',
        'apache': 'https://raw.githubusercontent.com/elastic/examples/master/ML%20Anomaly%20Detection/ApacheLogs/data/apache_logs.txt',
    }
    
    print("Generating synthetic datasets...")
    print("=" * 50)
    print("Note: Using SYNTHETIC data for all categories")
    print("The following log categories will have synthetic attack patterns:")
    
    for category in LOG_CATEGORIES.keys():
        print(f"  - {category}: {len(LOG_CATEGORIES[category])} log types")
        dataset = generate_dataset(category, samples_per_category)
        
        output_file = os.path.join(output_dir, f'{category}_dataset.json')
        with open(output_file, 'w') as f:
            json.dump(dataset, f, indent=2)
        
        attacks = sum(1 for d in dataset if d['is_attack'])
        normals = len(dataset) - attacks
        print(f"    Generated: {normals} normal, {attacks} attacks")
    
    # Save categories metadata
    metadata = {
        'categories': LOG_CATEGORIES,
        'attack_patterns': ATTACK_PATTERNS,
        'samples_per_category': samples_per_category,
        'data_source': 'synthetic'
    }
    
    with open(os.path.join(output_dir, 'metadata.json'), 'w') as f:
        json.dump(metadata, f, indent=2)
    
    print("=" * 50)
    print(f"Datasets saved to: {output_dir}")
    print("Synthetic data generation complete!")

if __name__ == '__main__':
    import sys
    output_dir = sys.argv[1] if len(sys.argv) > 1 else './data'
    samples = int(sys.argv[2]) if len(sys.argv) > 2 else 10000
    generate_all_datasets(output_dir, samples)
