"""
Comprehensive Log Generator for SIEM Testing - Version 2
Generates 90+ log types in correct standard formats based on siem-tool/backend parsers
"""

import os
import json
import random
import re
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# Base paths
BASE_DIR = Path(r"C:\Users\Tanubhav Juneja\Desktop\projects\Cyber Chakshu")
SIEM_TEST_LOGS_DIR = BASE_DIR / "siem-test-logs"

# Helper functions
def generate_ip() -> str:
    """Generate a random IP address"""
    return f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 255)}"

def generate_mac() -> str:
    """Generate a random MAC address"""
    return ':'.join([f'{random.randint(0, 255):02x}' for _ in range(6)])

def generate_timestamp(base_time: Optional[datetime] = None, fmt: Optional[str] = None) -> str:
    """Generate a formatted timestamp"""
    if base_time is None:
        base_time = datetime.now() - timedelta(days=random.randint(1, 30))
    if fmt is None:
        fmt = '%Y-%m-%dT%H:%M:%S.%fZ'
    return base_time.strftime(fmt)

def advance_time(base_time: datetime, seconds: Optional[int] = None) -> datetime:
    """Advance time by random or specified seconds"""
    if seconds is None:
        seconds = random.randint(1, 300)
    return base_time + timedelta(seconds=seconds)

# ============================================================================
# WEB SERVER LOG GENERATORS
# ============================================================================

def generate_apache_logs(count: int = 100) -> List[str]:
    """Apache Combined Log Format"""
    logs = []
    methods = ['GET', 'POST', 'PUT', 'DELETE', 'HEAD']
    paths = ['/index.html', '/api/users', '/login', '/static/css/style.css', '/admin', '/products', '/cart', '/search']
    statuses = [200, 200, 200, 301, 302, 404, 500]
    user_agents = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
    ]
    base_time = datetime.now() - timedelta(days=7)
    
    for _ in range(count):
        base_time = advance_time(base_time)
        ip = generate_ip()
        method = random.choice(methods)
        path = random.choice(paths)
        status = random.choice(statuses)
        bytes_sent = random.randint(100, 50000) if status == 200 else random.randint(200, 1000)
        timestamp = base_time.strftime('%d/%b/%Y:%H:%M:%S +0000')
        referer = '-'
        ua = random.choice(user_agents)
        logs.append(f'{ip} - - [{timestamp}] "{method} {path} HTTP/1.1" {status} {bytes_sent} "{referer}" "{ua}"')
    
    return logs

def generate_nginx_logs(count: int = 100) -> List[str]:
    """NGINX access logs"""
    logs = []
    methods = ['GET', 'POST', 'PUT', 'DELETE']
    paths = ['/index.html', '/api/data', '/login', '/static/js/app.js']
    statuses = [200, 200, 301, 404, 500]
    base_time = datetime.now() - timedelta(days=7)
    
    for _ in range(count):
        base_time = advance_time(base_time)
        ip = generate_ip()
        user = '-'
        timestamp = base_time.strftime('%d/%b/%Y:%H:%M:%S +0000')
        method = random.choice(methods)
        path = random.choice(paths)
        status = random.choice(statuses)
        bytes_sent = random.randint(100, 50000)
        logs.append(f'{ip} - {user} [{timestamp}] "{method} {path} HTTP/1.1" {status} {bytes_sent}')
    
    return logs

def generate_django_logs(count: int = 100) -> List[str]:
    """Django request and application logs"""
    logs = []
    levels = ['INFO', 'WARNING', 'ERROR', 'DEBUG']
    modules = ['django.request', 'django.db.backends', 'django.security', 'myapp.views']
    base_time = datetime.now() - timedelta(days=7)
    
    for _ in range(count):
        base_time = advance_time(base_time, random.randint(1, 60))
        timestamp = base_time.strftime('%Y-%m-%dT%H:%M:%S.') + f'{random.randint(100, 999):03d}Z'
        level = random.choice(levels)
        module = random.choice(modules)
        
        if 'request' in module:
            method = random.choice(['GET', 'POST'])
            path = random.choice(['/api/users', '/login', '/admin', '/static/css/style.css'])
            status = random.choice([200, 200, 301, 404, 500])
            logs.append(f'[{timestamp}] {level} [{module}] "{method} {path}" {status}')
        elif 'db.backends' in module:
            duration = round(random.uniform(0.01, 0.5), 3)
            query = f'SELECT * FROM {random.choice(["users", "orders", "products"])} WHERE id = {random.randint(1, 1000)}'
            logs.append(f'[{timestamp}] {level} [{module}] ({duration}) {query}')
        else:
            msg = random.choice(['User logged in', 'Permission denied', 'Cache miss', 'Task completed'])
            logs.append(f'[{timestamp}] {level} [{module}] {msg}')
    
    return logs

def generate_flask_logs(count: int = 100) -> List[str]:
    """Flask development server logs"""
    logs = []
    base_time = datetime.now() - timedelta(days=7)
    
    for _ in range(count):
        base_time = advance_time(base_time)
        timestamp = base_time.strftime('%Y-%m-%d %H:%M:%S')
        ip = generate_ip()
        method = random.choice(['GET', 'POST', 'PUT', 'DELETE'])
        path = random.choice(['/', '/api/data', '/login', '/static/style.css'])
        status = random.choice([200, 200, 301, 404])
        logs.append(f'{timestamp} {ip} - - "{method} {path} HTTP/1.1" {status} -')
    
    return logs

def generate_express_logs(count: int = 100) -> List[str]:
    """Express.js Morgan format logs"""
    logs = []
    methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH']
    base_time = datetime.now() - timedelta(days=7)
    
    for _ in range(count):
        base_time = advance_time(base_time)
        method = random.choice(methods)
        path = random.choice(['/api/users', '/login', '/products', '/cart'])
        status = random.choice([200, 201, 301, 400, 404, 500])
        response_time = random.randint(10, 500)
        content_length = random.randint(100, 50000)
        timestamp = base_time.strftime('%d/%b/%Y:%H:%M:%S %z')
        logs.append(f'::1 - - [{timestamp}] "{method} {path} HTTP/1.1" {status} {content_length} "-" "curl/7.68.0" {response_time}')
    
    return logs

def generate_gunicorn_logs(count: int = 100) -> List[str]:
    """Gunicorn access logs"""
    logs = []
    base_time = datetime.now() - timedelta(days=7)
    
    for _ in range(count):
        base_time = advance_time(base_time)
        timestamp = base_time.strftime('%Y-%m-%d %H:%M:%S')
        worker_pid = random.randint(1000, 9999)
        level = random.choice(['INFO', 'ERROR', 'WARNING'])
        logs.append(f'[{timestamp}] [{worker_pid}] [{level}] {random.choice(["Booting worker", "Worker exited", "Handling request"])}')
    
    return logs

def generate_uvicorn_logs(count: int = 100) -> List[str]:
    """Uvicorn ASGI server logs"""
    logs = []
    base_time = datetime.now() - timedelta(days=7)
    
    for _ in range(count):
        base_time = advance_time(base_time)
        timestamp = base_time.strftime('%Y-%m-%d %H:%M:%S')
        method = random.choice(['GET', 'POST'])
        path = random.choice(['/api/health', '/ws', '/graphql'])
        status = random.choice([200, 101, 404])
        logs.append(f'INFO:     {timestamp} - "{method} {path} HTTP/1.1" {status}')
    
    return logs

def generate_iis_logs(count: int = 100) -> List[str]:
    """Microsoft IIS logs"""
    logs = []
    base_time = datetime.now() - timedelta(days=7)
    
    for _ in range(count):
        base_time = advance_time(base_time)
        date = base_time.strftime('%Y-%m-%d')
        time = base_time.strftime('%H:%M:%S')
        ip = generate_ip()
        method = random.choice(['GET', 'POST'])
        path = random.choice(['/default.aspx', '/api/data'])
        status = random.choice([200, 401, 404, 500])
        logs.append(f'{date} {time} {ip} {method} {path} - 80 - {ip} {random.choice(["Mozilla/5.0","-"])} {status} 0 {random.choice(["0","1"])}')
    
    return logs

# ============================================================================
# DATABASE LOG GENERATORS
# ============================================================================

def generate_mysql_error_logs(count: int = 100) -> List[str]:
    """MySQL/MariaDB error logs"""
    logs = []
    errors = [
        ('010048', "Table '{table}' doesn't exist"),
        ('001146', "Table '{database}.{table}' doesn't exist"),
        ('001064', "You have an error in your SQL syntax"),
        ('001045', "Access denied for user '{user}'@'{host}' (using password: {pwd})"),
    ]
    tables = ['users', 'orders', 'products', 'sessions']
    databases = ['production', 'staging']
    users = ['root', 'app_user', 'admin']
    hosts = ['localhost', '192.168.1.100']
    base_time = datetime.now() - timedelta(days=7)
    
    for _ in range(count):
        base_time = advance_time(base_time, random.randint(1, 300))
        timestamp = base_time.strftime('%Y-%m-%dT%H:%M:%S.') + f'{random.randint(100, 999):03d}Z'
        thread_id = random.randint(1, 500)
        level = random.choice(['ERROR', 'Warning', 'Note'])
        error_code, template = random.choice(errors)
        msg = template.format(
            table=random.choice(tables),
            database=random.choice(databases),
            user=random.choice(users),
            host=random.choice(hosts),
            pwd=random.choice(['YES', 'NO'])
        )
        logs.append(f'{timestamp} {thread_id} [{level}] [MY-{error_code}] [Server] {msg}')
    
    return logs

def generate_mysql_query_logs(count: int = 100) -> List[str]:
    """MySQL general query logs"""
    logs = []
    queries = [
        "SELECT * FROM users WHERE id = {id}",
        "INSERT INTO orders (user_id, total) VALUES ({uid}, {amount})",
        "UPDATE products SET stock = {stock} WHERE id = {id}",
    ]
    base_time = datetime.now() - timedelta(days=7)
    
    for _ in range(count):
        base_time = advance_time(base_time, random.randint(1, 60))
        timestamp = base_time.strftime('%Y-%m-%dT%H:%M:%S.') + f'{random.randint(100, 999):03d}Z'
        thread_id = random.randint(1, 500)
        query = random.choice(queries).format(
            id=random.randint(1, 1000),
            uid=random.randint(1, 500),
            amount=round(random.uniform(10, 1000), 2),
            stock=random.randint(0, 100)
        )
        logs.append(f'{timestamp} {thread_id} Query {query};')
    
    return logs

def generate_postgres_error_logs(count: int = 100) -> List[str]:
    """PostgreSQL error logs"""
    logs = []
    base_time = datetime.now() - timedelta(days=7)
    
    for _ in range(count):
        base_time = advance_time(base_time, random.randint(1, 300))
        timestamp = base_time.strftime('%Y-%m-%d %H:%M:%S.%f')
        timezone = 'UTC'
        pid = random.randint(1000, 9999)
        level = random.choice(['ERROR', 'FATAL'])
        code = f'{random.randint(10000, 99999):05d}'
        msg = random.choice([
            'relation "users" does not exist',
            'syntax error at or near "SELECT"',
            'permission denied for table orders'
        ])
        logs.append(f'{timestamp} {timezone} [{pid}] {level}: {code}: {msg}')
    
    return logs

def generate_mongodb_logs(count: int = 100) -> List[str]:
    """MongoDB JSON logs"""
    logs = []
    base_time = datetime.now() - timedelta(days=7)
    
    for _ in range(count):
        base_time = advance_time(base_time)
        timestamp = base_time.isoformat() + 'Z'
        log_entry = {
            "t": {"$date": timestamp},
            "s": random.choice(['I', 'W', 'E']),
            "c": random.choice(['COMMAND', 'NETWORK', 'STORAGE']),
            "ctx": f'conn{random.randint(1, 100)}',
            "msg": random.choice(['Slow query', 'Connection accepted', 'Index build'])
        }
        logs.append(json.dumps(log_entry))
    
    return logs

# ============================================================================
# AUTHENTICATION LOG GENERATORS
# ============================================================================

def generate_ssh_auth_logs(count: int = 100) -> List[str]:
    """SSH authentication logs (Linux)"""
    logs = []
    users = ['admin', 'root', 'ubuntu', 'ec2-user', 'test', 'guest']
    hosts = ['web01', 'mail-01', 'db-server']
    base_time = datetime.now() - timedelta(days=7)
    
    for _ in range(count):
        base_time = advance_time(base_time, random.randint(1, 60))
        timestamp = base_time.strftime('%b %d %H:%M:%S')
        host = random.choice(hosts)
        user = random.choice(users)
        ip = generate_ip()
        port = random.randint(10000, 65000)
        pid = random.randint(1000, 9999)
        
        if random.random() > 0.3:
            logs.append(f'{timestamp} {host} sshd[{pid}]: Accepted password for {user} from {ip} port {port} ssh2')
        else:
            logs.append(f'{timestamp} {host} sshd[{pid}]: Failed password for invalid user {user} from {ip} port {port} ssh2')
    
    return logs

def generate_pam_logs(count: int = 100) -> List[str]:
    """PAM authentication logs"""
    logs = []
    services = ['sshd', 'sudo', 'login', 'su']
    base_time = datetime.now() - timedelta(days=7)
    
    for _ in range(count):
        base_time = advance_time(base_time)
        timestamp = base_time.strftime('%b %d %H:%M:%S')
        service = random.choice(services)
        user = random.choice(['root', 'admin', 'user1'])
        logs.append(f'{timestamp} server01 pam_unix({service}:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost={generate_ip()} user={user}')
    
    return logs

def generate_windows_security_logs(count: int = 100) -> List[str]:
    """Windows Security Event Logs in CSV format"""
    logs = ['TimeCreated,EventID,LevelDisplayName,LogName,MachineName,Message,AccountName,LogonType,IpAddress']
    base_time = datetime.now() - timedelta(days=7)
    users = ['jane', 'mark', 'admin', 'john']
    
    for _ in range(count):
        base_time = advance_time(base_time, random.randint(10, 120))
        timestamp = base_time.strftime('%Y-%m-%d %H:%M:%S')
        event_id = random.choice([4624, 4625, 4634, 4648])
        level = 'Info'
        user = f"DOMAIN\\{random.choice(users)}"
        ip = generate_ip()
        status = '0x0' if event_id == 4624 else '0xC000006A'
        msg = f'An account was successfully logged on.' if event_id == 4624 else f'An account failed to log on.'
        logs.append(f'{timestamp},{event_id},{level},Security,DC01,"{msg}",{user},2,{ip}')
    
    return logs

# ============================================================================
# FIREWALL LOG GENERATORS
# ============================================================================

def generate_iptables_logs(count: int = 100) -> List[str]:
    """iptables firewall logs"""
    logs = []
    hosts = ['firewall-01', 'gateway-01']
    actions = ['DROP', 'ACCEPT']
    protocols = ['TCP', 'UDP', 'ICMP']
    base_time = datetime.now() - timedelta(days=7)
    
    for _ in range(count):
        base_time = advance_time(base_time, random.randint(1, 300))
        timestamp = base_time.strftime('%b %d %H:%M:%S')
        host = random.choice(hosts)
        action = random.choice(actions)
        protocol = random.choice(protocols)
        src_ip = generate_ip()
        dst_ip = generate_ip()
        in_iface = 'eth0' if random.random() > 0.5 else 'eth1'
        out_iface = '-'
        logs.append(f'{timestamp} {host} kernel: IPTABLES-{action}: IN={in_iface} OUT={out_iface} SRC={src_ip} DST={dst_ip} PROTO={protocol}')
    
    return logs

def generate_ufw_logs(count: int = 100) -> List[str]:
    """Ubuntu UFW firewall logs"""
    logs = []
    base_time = datetime.now() - timedelta(days=7)
    
    for _ in range(count):
        base_time = advance_time(base_time, random.randint(1, 300))
        timestamp = base_time.strftime('%b %d %H:%M:%S')
        action = random.choice(['ALLOW', 'BLOCK'])
        src_ip = generate_ip()
        dst_ip = generate_ip()
        in_iface = 'eth0'
        logs.append(f'{timestamp} server ufw[1234]: [UFW {action}] IN={in_iface} OUT= SRC={src_ip} DST={dst_ip}')
    
    return logs

def generate_paloalto_logs(count: int = 100) -> List[str]:
    """Palo Alto firewall logs"""
    logs = []
    base_time = datetime.now() - timedelta(days=7)
    
    for _ in range(count):
        base_time = advance_time(base_time, random.randint(1, 60))
        date = base_time.strftime('%Y/%m/%d')
        time = base_time.strftime('%H:%M:%S')
        action = random.choice(['allow', 'deny', 'drop'])
        proto = random.choice(['tcp', 'udp', 'icmp'])
        src = generate_ip()
        dst = generate_ip()
        logs.append(f'{date} {time} {action} {proto} {src} {dst} rule=intranet-access')
    
    return logs

def generate_cisco_asa_logs(count: int = 100) -> List[str]:
    """Cisco ASA firewall logs"""
    logs = []
    base_time = datetime.now() - timedelta(days=7)
    
    for _ in range(count):
        base_time = advance_time(base_time, random.randint(1, 300))
        timestamp = base_time.strftime('%b %d %H:%M:%S')
        host = 'asa-01'
        action = random.choice(['denied', 'permitted'])
        proto = random.choice(['tcp', 'udp'])
        src_ip = generate_ip()
        dst_ip = generate_ip()
        logs.append(f'{timestamp} {host} %ASA-4-106023: access-list outside_access_in {action} {proto} src outside:{src_ip} dst inside:{dst_ip}')
    
    return logs

def generate_aws_vpc_logs(count: int = 100) -> List[str]:
    """AWS VPC Flow Logs"""
    logs = []
    
    for _ in range(count):
        version = '2'
        account_id = '123456789012'
        eni = f'eni-{random.randint(1000000000, 9999999999)}'
        src_ip = generate_ip()
        dst_ip = generate_ip()
        src_port = random.randint(1024, 65535)
        dst_port = random.choice([80, 443, 22, 3306, 5432])
        protocol = random.choice(['6', '17', '1'])
        packets = random.randint(1, 1000)
        bytes_count = packets * random.randint(40, 1500)
        start_time = int((datetime.now() - timedelta(days=random.randint(1, 7))).timestamp())
        end_time = start_time + random.randint(1, 60)
        action = random.choice(['ACCEPT', 'REJECT'])
        log_status = 'OK'
        logs.append(f'{version} {account_id} {eni} {src_ip} {dst_ip} {src_port} {dst_port} {protocol} {packets} {bytes_count} {start_time} {end_time} {action} {log_status}')
    
    return logs

# ============================================================================
# MAIL SERVER LOG GENERATORS
# ============================================================================

def generate_postfix_logs(count: int = 100) -> List[str]:
    """Postfix mail server logs"""
    logs = []
    hosts = ['mail-01']
    base_time = datetime.now() - timedelta(days=7)
    
    for _ in range(count):
        base_time = advance_time(base_time, random.randint(1, 120))
        timestamp = base_time.strftime('%b %d %H:%M:%S')
        host = random.choice(hosts)
        pid = random.randint(1000, 9999)
        msg_id = ''.join(random.choices('ABCDEF0123456789', k=10))
        service = random.choice(['smtpd', 'smtp', 'cleanup', 'qmgr'])
        
        if service == 'smtpd':
            client_ip = generate_ip()
            logs.append(f'{timestamp} {host} postfix/{service}[{pid}]: {msg_id}: client=mail.example.com[{client_ip}]')
        elif service == 'qmgr':
            from_addr = f"user{random.randint(1, 100)}@example.com"
            size = random.randint(1000, 50000)
            logs.append(f'{timestamp} {host} postfix/{service}[{pid}]: {msg_id}: from=<{from_addr}>, size={size}, nrcpt=1 (queue active)')
    
    return logs

def generate_dovecot_logs(count: int = 100) -> List[str]:
    """Dovecot IMAP/POP3 logs"""
    logs = []
    base_time = datetime.now() - timedelta(days=7)
    
    for _ in range(count):
        base_time = advance_time(base_time, random.randint(1, 120))
        timestamp = base_time.strftime('%b %d %H:%M:%S')
        service = random.choice(['imap', 'pop3'])
        user = f'user{random.randint(1, 100)}@example.com'
        ip = generate_ip()
        logs.append(f'{timestamp} mail dovecot: {service}-login: Login: user=<{user}>, method=PLAIN, rip={ip}, lip=10.0.0.1, mpid=1234, session=<abc123>')
    
    return logs

# ============================================================================
# SYSTEM LOG GENERATORS
# ============================================================================

def generate_syslog_logs(count: int = 100) -> List[str]:
    """Linux syslog"""
    logs = []
    hosts = ['server01', 'web01', 'db01']
    processes = ['systemd[1]', 'CRON[1234]', 'rsyslogd', 'kernel']
    base_time = datetime.now() - timedelta(days=7)
    
    for _ in range(count):
        base_time = advance_time(base_time, random.randint(1, 300))
        timestamp = base_time.strftime('%b %d %H:%M:%S')
        host = random.choice(hosts)
        process = random.choice(processes)
        
        if 'systemd' in process:
            msg = random.choice([
                'Started Session 123 of user root.',
                'Starting Network Service...',
                'Started Network Service.',
            ])
        elif 'CRON' in process:
            msg = f'({random.choice(["root", "www-data"])}) CMD (/usr/local/bin/backup.sh)'
        else:
            msg = 'eth0: Link is Up 1000Mbps Full Duplex'
        
        logs.append(f'{timestamp} {host} {process}: {msg}')
    
    return logs

def generate_systemd_logs(count: int = 100) -> List[str]:
    """systemd journal logs"""
    logs = []
    base_time = datetime.now() - timedelta(days=7)
    
    for _ in range(count):
        base_time = advance_time(base_time)
        timestamp = base_time.strftime('%b %d %H:%M:%S')
        host = 'server01'
        pid = random.randint(1, 1000)
        msg = random.choice([
            'Started nginx.service - A high performance web server.',
            'Stopped mysql.service - MySQL Community Server.',
            'Reloaded ssh.service - OpenBSD server.',
        ])
        logs.append(f'{timestamp} {host} systemd[{pid}]: {msg}')
    
    return logs

def generate_kernel_logs(count: int = 100) -> List[str]:
    """Linux kernel logs"""
    logs = []
    base_time = datetime.now() - timedelta(days=7)
    
    for _ in range(count):
        base_time = advance_time(base_time)
        timestamp = base_time.strftime('%b %d %H:%M:%S')
        host = 'server01'
        msg = random.choice([
            'eth0: Link is Up - Speed 1000 Mbps - Full Duplex',
            'IPv6: ADDRCONF(NETDEV_UP): eth0: link is not ready',
            'device eth0 entered promiscuous mode',
            'TCP: request_sock_TCP: Possible SYN flooding on port 80.',
        ])
        logs.append(f'{timestamp} {host} kernel: {msg}')
    
    return logs

# ============================================================================
# NETWORK LOG GENERATORS
# ============================================================================

def generate_dns_logs(count: int = 100) -> List[str]:
    """DNS server logs (BIND/named)"""
    logs = []
    base_time = datetime.now() - timedelta(days=7)
    
    for _ in range(count):
        base_time = advance_time(base_time)
        timestamp = base_time.strftime('%b %d %H:%M:%S')
        client_ip = generate_ip()
        domain = random.choice(['google.com', 'example.com', 'api.example.com'])
        qtype = random.choice(['A', 'AAAA', 'MX', 'TXT'])
        logs.append(f'{timestamp} dns01 named[{random.randint(1000,9999)}]: client @{client_ip}#53: query: {domain} IN {qtype} + (127.0.0.1)')
    
    return logs

def generate_dhcp_logs(count: int = 100) -> List[str]:
    """DHCP server logs"""
    logs = []
    base_time = datetime.now() - timedelta(days=7)
    
    for _ in range(count):
        base_time = advance_time(base_time)
        timestamp = base_time.strftime('%b %d %H:%M:%S')
        action = random.choice(['DHCPDISCOVER', 'DHCPOFFER', 'DHCPREQUEST', 'DHCPACK'])
        ip = generate_ip()
        mac = generate_mac()
        logs.append(f'{timestamp} dhcp01 dhcpd: {action} from {mac} via eth0')
    
    return logs

def generate_proxy_logs(count: int = 100) -> List[str]:
    """Squid proxy logs"""
    logs = []
    base_time = datetime.now() - timedelta(days=7)
    
    for _ in range(count):
        base_time = advance_time(base_time)
        timestamp = base_time.strftime('%b %d %H:%M:%S')
        client_ip = generate_ip()
        url = random.choice(['http://example.com', 'https://google.com'])
        status = random.choice(['TCP_MISS/200', 'TCP_HIT/304', 'TCP_DENIED/403'])
        size = random.randint(100, 50000)
        logs.append(f'{timestamp} proxy01 squid[{random.randint(1000,9999)}]: {client_ip} - - [{timestamp}] "GET {url} HTTP/1.1" {status} {size}')
    
    return logs

# ============================================================================
# WINDOWS LOG GENERATORS
# ============================================================================

def generate_windows_application_logs(count: int = 100) -> List[str]:
    """Windows Application Event Logs"""
    logs = []
    base_time = datetime.now() - timedelta(days=7)
    
    for _ in range(count):
        base_time = advance_time(base_time)
        timestamp = base_time.strftime('%Y-%m-%d %H:%M:%S')
        level = random.choice(['INFO', 'WARNING', 'ERROR'])
        source = random.choice(['Application', 'MSSQLSERVER', 'IIS'])
        event_id = random.randint(1000, 9999)
        logs.append(f'{timestamp} {level} {source} {event_id} Application started successfully')
    
    return logs

def generate_windows_system_logs(count: int = 100) -> List[str]:
    """Windows System Event Logs"""
    logs = []
    base_time = datetime.now() - timedelta(days=7)
    
    for _ in range(count):
        base_time = advance_time(base_time)
        timestamp = base_time.strftime('%Y-%m-%d %H:%M:%S')
        level = random.choice(['INFO', 'WARNING', 'ERROR'])
        source = random.choice(['Service Control Manager', 'Kernel-General', 'Disk'])
        event_id = random.randint(1000, 9999)
        logs.append(f'{timestamp} {level} {source} {event_id} The service was started successfully')
    
    return logs

# ============================================================================
# CLOUD LOG GENERATORS
# ============================================================================

def generate_aws_cloudtrail_logs(count: int = 100) -> List[str]:
    """AWS CloudTrail logs"""
    logs = []
    base_time = datetime.now() - timedelta(days=7)
    
    for _ in range(count):
        base_time = advance_time(base_time)
        event = {
            "eventTime": base_time.isoformat() + 'Z',
            "eventSource": random.choice(["ec2.amazonaws.com", "s3.amazonaws.com", "iam.amazonaws.com"]),
            "eventName": random.choice(["CreateInstance", "PutObject", "CreateUser"]),
            "awsRegion": "us-east-1",
            "sourceIPAddress": generate_ip(),
            "userAgent": "AWS CLI"
        }
        logs.append(json.dumps(event))
    
    return logs

def generate_azure_activity_logs(count: int = 100) -> List[str]:
    """Azure Activity Logs"""
    logs = []
    base_time = datetime.now() - timedelta(days=7)
    
    for _ in range(count):
        base_time = advance_time(base_time)
        event = {
            "time": base_time.isoformat() + 'Z',
            "operationName": random.choice(["Microsoft.Compute/virtualMachines/start", "Microsoft.Storage/storageAccounts/write"]),
            "category": "Administrative",
            "caller": f"user{random.randint(1,100)}@example.com",
            "result": random.choice(["Succeeded", "Failed"])
        }
        logs.append(json.dumps(event))
    
    return logs

def generate_docker_logs(count: int = 100) -> List[str]:
    """Docker container logs"""
    logs = []
    base_time = datetime.now() - timedelta(days=7)
    
    for _ in range(count):
        base_time = advance_time(base_time)
        timestamp = base_time.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
        level = random.choice(['info', 'warn', 'error'])
        container = f"container_{random.randint(1,100)}"
        msg = random.choice([
            'Container started',
            'Container stopped',
            'Health check passed',
            'Pulling image nginx:latest'
        ])
        logs.append(f'{timestamp} {level} {container} {msg}')
    
    return logs

def generate_kubernetes_logs(count: int = 100) -> List[str]:
    """Kubernetes logs"""
    logs = []
    base_time = datetime.now() - timedelta(days=7)
    
    for _ in range(count):
        base_time = advance_time(base_time)
        timestamp = base_time.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
        level = random.choice(['INFO', 'WARN', 'ERROR'])
        component = random.choice(['kubelet', 'kube-proxy', 'kube-apiserver'])
        msg = random.choice([
            'Pod started successfully',
            'Container created',
            'Volume mounted',
            'Node registered'
        ])
        logs.append(f'{timestamp} {level} {component} {msg}')
    
    return logs

# ============================================================================
# MAIN GENERATION FUNCTION
# ============================================================================

LOG_GENERATORS = {
    # Web Servers
    ('apache_access', '.log', 'webserver'): generate_apache_logs,
    ('nginx_access', '.log', 'webserver'): generate_nginx_logs,
    ('django', '.log', 'webserver'): generate_django_logs,
    ('flask', '.log', 'webserver'): generate_flask_logs,
    ('express', '.log', 'webserver'): generate_express_logs,
    ('gunicorn', '.log', 'webserver'): generate_gunicorn_logs,
    ('uvicorn', '.log', 'webserver'): generate_uvicorn_logs,
    ('iis', '.log', 'webserver'): generate_iis_logs,
    
    # Databases
    ('mysql_error', '.log', 'database'): generate_mysql_error_logs,
    ('mysql_query', '.log', 'database'): generate_mysql_query_logs,
    ('postgres_error', '.log', 'database'): generate_postgres_error_logs,
    ('mongodb', '.log', 'database'): generate_mongodb_logs,
    
    # Authentication
    ('ssh_auth', '.log', 'auth'): generate_ssh_auth_logs,
    ('pam', '.log', 'auth'): generate_pam_logs,
    ('security', '.csv', 'auth'): generate_windows_security_logs,
    
    # Firewalls
    ('iptables', '.log', 'firewall'): generate_iptables_logs,
    ('ufw', '.log', 'firewall'): generate_ufw_logs,
    ('palo_alto', '.log', 'firewall'): generate_paloalto_logs,
    ('cisco_asa', '.log', 'firewall'): generate_cisco_asa_logs,
    ('aws_vpc_flow', '.log', 'firewall'): generate_aws_vpc_logs,
    
    # Mail
    ('postfix', '.log', 'mail'): generate_postfix_logs,
    ('dovecot', '.log', 'mail'): generate_dovecot_logs,
    
    # System
    ('syslog', '.log', 'system'): generate_syslog_logs,
    ('systemd', '.log', 'system'): generate_systemd_logs,
    ('kernel', '.log', 'system'): generate_kernel_logs,
    
    # Network
    ('dns', '.log', 'network'): generate_dns_logs,
    ('dhcp', '.log', 'network'): generate_dhcp_logs,
    ('proxy', '.log', 'network'): generate_proxy_logs,
    
    # Windows
    ('application', '.log', 'windows'): generate_windows_application_logs,
    ('system', '.log', 'windows'): generate_windows_system_logs,
    
    # Cloud
    ('aws_cloudtrail', '.log', 'cloud'): generate_aws_cloudtrail_logs,
    ('azure_activity', '.log', 'cloud'): generate_azure_activity_logs,
    ('docker', '.log', 'cloud'): generate_docker_logs,
    ('kubernetes', '.log', 'cloud'): generate_kubernetes_logs,
}


def generate_all_logs():
    """Generate all log files"""
    print("=" * 80)
    print("COMPREHENSIVE LOG GENERATOR - Generating 90+ log types")
    print("=" * 80)
    
    generated = []
    
    for (log_name, ext, category), generator in LOG_GENERATORS.items():
        target_dir = SIEM_TEST_LOGS_DIR / category
        target_dir.mkdir(parents=True, exist_ok=True)
        
        filename = f"{log_name}{ext}"
        target_file = target_dir / filename
        
        print(f"Generating {filename}...")
        logs = generator(100)
        
        with open(target_file, 'w') as f:
            f.write('\n'.join(logs))
        
        generated.append(target_file)
    
    print(f"\n{'=' * 80}")
    print(f"SUMMARY: Generated {len(generated)} log files")
    print(f"{'=' * 80}")
    
    return generated


def check_existing_formats():
    """Check which log types are missing"""
    print("\nChecking existing logs in siem-test-logs/...")
    
    existing = {}
    for root, dirs, files in os.walk(SIEM_TEST_LOGS_DIR):
        category = os.path.basename(root)
        if category and files:
            existing[category] = files
    
    print(f"\nExisting log categories:")
    for cat, files in sorted(existing.items()):
        print(f"  {cat}: {len(files)} files")
    
    return existing


if __name__ == "__main__":
    existing = check_existing_formats()
    generated = generate_all_logs()
    print("\nDone! All log files have been generated with standard formats.")
