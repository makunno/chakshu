"""Parser Registry - Synced from siem-tool with auto_parse function"""

import re
import json
from typing import Dict, Any, List, Optional
from datetime import datetime
from parsers.log_detector import LogDetector
from parsers.types import LogEntry
from parsers.multiline import (
    is_multiline_log,
    group_multiline_entries,
    parse_multiline_block,
    MULTILINE_TYPES,
)

ALL_PARSERS = [
    {'name': 'Apache', 'logType': 'apache', 'category': 'webserver'},
    {'name': 'Apache Error', 'logType': 'apache_error', 'category': 'webserver'},
    {'name': 'NGINX', 'logType': 'nginx', 'category': 'webserver'},
    {'name': 'NGINX Error', 'logType': 'nginx_error', 'category': 'webserver'},
    {'name': 'IIS', 'logType': 'iis', 'category': 'webserver'},
    {'name': 'Django', 'logType': 'django', 'category': 'webserver'},
    {'name': 'Flask', 'logType': 'flask', 'category': 'webserver'},
    {'name': 'Laravel', 'logType': 'laravel', 'category': 'webserver'},
    {'name': 'Rails', 'logType': 'rails', 'category': 'webserver'},
    {'name': 'Express.js', 'logType': 'express', 'category': 'webserver'},
    {'name': 'FastAPI', 'logType': 'fastapi', 'category': 'webserver'},
    {'name': 'Gunicorn', 'logType': 'gunicorn', 'category': 'webserver'},
    {'name': 'Uvicorn', 'logType': 'uvicorn', 'category': 'webserver'},
    {'name': 'PHP-FPM', 'logType': 'php_fpm', 'category': 'webserver'},
    {'name': 'Caddy', 'logType': 'caddy', 'category': 'webserver'},
    {'name': 'HAProxy', 'logType': 'haproxy', 'category': 'webserver'},
    {'name': 'Spring Boot', 'logType': 'spring_boot', 'category': 'webserver'},
    {'name': 'ASP.NET Core', 'logType': 'aspnet_core', 'category': 'webserver'},
    {'name': 'MySQL Error', 'logType': 'mysql_error', 'category': 'database'},
    {'name': 'MySQL Query', 'logType': 'mysql_query', 'category': 'database'},
    {'name': 'MySQL Slow', 'logType': 'mysql_slow', 'category': 'database'},
    {'name': 'PostgreSQL Error', 'logType': 'postgres_error', 'category': 'database'},
    {'name': 'PostgreSQL Auth', 'logType': 'postgres_auth', 'category': 'database'},
    {'name': 'PostgreSQL Stmt', 'logType': 'postgres_statement', 'category': 'database'},
    {'name': 'Oracle Alert', 'logType': 'oracle_alert', 'category': 'database'},
    {'name': 'Oracle Listener', 'logType': 'oracle_listener', 'category': 'database'},
    {'name': 'Oracle Audit', 'logType': 'oracle_audit', 'category': 'database'},
    {'name': 'SQL Server Error', 'logType': 'sqlserver_error', 'category': 'database'},
    {'name': 'SQL Server Audit', 'logType': 'sqlserver_audit', 'category': 'database'},
    {'name': 'SQL Server Tx', 'logType': 'sqlserver_transaction', 'category': 'database'},
    {'name': 'MongoDB', 'logType': 'mongodb_server', 'category': 'database'},
    {'name': 'MongoDB Audit', 'logType': 'mongodb_audit', 'category': 'database'},
    {'name': 'Windows FW', 'logType': 'windows_firewall', 'category': 'firewall'},
    {'name': 'iptables', 'logType': 'iptables', 'category': 'firewall'},
    {'name': 'UFW', 'logType': 'ufw', 'category': 'firewall'},
    {'name': 'nftables', 'logType': 'nftables', 'category': 'firewall'},
    {'name': 'firewalld', 'logType': 'firewalld', 'category': 'firewall'},
    {'name': 'Palo Alto', 'logType': 'palo_alto', 'category': 'firewall'},
    {'name': 'FortiGate', 'logType': 'fortigate', 'category': 'firewall'},
    {'name': 'Cisco ASA', 'logType': 'cisco_asa', 'category': 'firewall'},
    {'name': 'Check Point', 'logType': 'checkpoint', 'category': 'firewall'},
    {'name': 'AWS VPC', 'logType': 'aws_vpc_flow', 'category': 'firewall'},
    {'name': 'Azure NSG', 'logType': 'azure_nsg', 'category': 'firewall'},
    {'name': 'GCP VPC', 'logType': 'gcp_vpc', 'category': 'firewall'},
    {'name': 'Postfix', 'logType': 'postfix', 'category': 'mail'},
    {'name': 'Sendmail', 'logType': 'sendmail', 'category': 'mail'},
    {'name': 'Exim', 'logType': 'exim', 'category': 'mail'},
    {'name': 'Dovecot', 'logType': 'dovecot', 'category': 'mail'},
    {'name': 'Courier', 'logType': 'courier', 'category': 'mail'},
    {'name': 'Exchange', 'logType': 'exchange', 'category': 'mail'},
    {'name': 'Amavis', 'logType': 'amavis', 'category': 'mail'},
    {'name': 'SpamAssassin', 'logType': 'spamassassin', 'category': 'mail'},
    {'name': 'MailScanner', 'logType': 'mailscanner', 'category': 'mail'},
    {'name': 'SSH Auth', 'logType': 'ssh_auth', 'category': 'auth'},
    {'name': 'PAM', 'logType': 'pam', 'category': 'auth'},
    {'name': 'Syslog', 'logType': 'syslog', 'category': 'system'},
    {'name': 'Systemd', 'logType': 'systemd', 'category': 'system'},
    {'name': 'Kernel', 'logType': 'kernel', 'category': 'system'},
    {'name': 'Audit', 'logType': 'audit', 'category': 'system'},
    {'name': 'Windows Sys', 'logType': 'windows_system', 'category': 'system'},
    {'name': 'Windows Event', 'logType': 'windows_event_viewer', 'category': 'system'},
    {'name': 'Windows App TXT', 'logType': 'windows_application_txt', 'category': 'system'},
    {'name': 'FileZilla', 'logType': 'filezilla', 'category': 'network'},
    {'name': 'vsftpd', 'logType': 'vsftpd', 'category': 'network'},
    {'name': 'ProFTPD', 'logType': 'proftpd', 'category': 'network'},
    {'name': 'xferlog', 'logType': 'xferlog', 'category': 'network'},
    {'name': 'IIS FTP', 'logType': 'iis_ftp', 'category': 'network'},
    {'name': 'DHCP', 'logType': 'dhcp', 'category': 'network'},
    {'name': 'DNS', 'logType': 'dns', 'category': 'network'},
    {'name': 'Proxy', 'logType': 'proxy', 'category': 'network'},
    {'name': 'Cloudflare', 'logType': 'cloudflare', 'category': 'cloud'},
    {'name': 'AWS CloudTrail', 'logType': 'aws_cloudtrail', 'category': 'cloud'},
    {'name': 'AWS GuardDuty', 'logType': 'aws_guardduty', 'category': 'cloud'},
    {'name': 'Azure', 'logType': 'azure_activity', 'category': 'cloud'},
    {'name': 'GCP Audit', 'logType': 'gcp_audit', 'category': 'cloud'},
    {'name': 'Kubernetes', 'logType': 'kubernetes', 'category': 'container'},
    {'name': 'Docker', 'logType': 'docker', 'category': 'container'},
    {'name': 'Elasticsearch', 'logType': 'elasticsearch', 'category': 'application'},
    {'name': 'Redis', 'logType': 'redis', 'category': 'application'},
    {'name': 'RabbitMQ', 'logType': 'rabbitmq', 'category': 'application'},
    {'name': 'Kafka', 'logType': 'kafka', 'category': 'application'},
    {'name': 'Zookeeper', 'logType': 'zookeeper', 'category': 'application'},
    {'name': 'Moodle', 'logType': 'moodle_lms', 'category': 'application'},
    {'name': 'Squid', 'logType': 'squid', 'category': 'application'},
    {'name': 'Suricata', 'logType': 'suricata', 'category': 'security'},
    {'name': 'Zeek', 'logType': 'zeek', 'category': 'security'},
    {'name': 'Ossec', 'logType': 'ossec', 'category': 'security'},
    {'name': 'Fail2ban', 'logType': 'fail2ban', 'category': 'security'},
    {'name': 'Auth0', 'logType': 'auth0', 'category': 'security'},
    {'name': 'Unknown', 'logType': 'unknown', 'category': 'generic'},
]


def detect_log_type(content: str) -> str:
    """Detect log type using ISEA-style LogDetector"""
    return LogDetector.detect(content)


def generate_id() -> str:
    """Generate unique ID for entries"""
    import hashlib
    import time
    return hashlib.md5(f"{time.time()}{id}".encode()).hexdigest()[:12]


def parse_timestamp(ts_str: str) -> Optional[str]:
    """Parse various timestamp formats to ISO format"""
    if not ts_str:
        return None
    
    ts_str = ts_str.strip()
    
    formats = [
        '%Y-%m-%d %H:%M:%S',
        '%Y-%m-%dT%H:%M:%S',
        '%d/%b/%Y:%H:%M:%S',
        '%b %d %H:%M:%S',
        '%Y-%m-%dT%H:%M:%SZ',
        '%Y-%m-%dT%H:%M:%S.%fZ',
        '%Y-%m-%dT%H:%M:%S.%f',
    ]
    
    for fmt in formats:
        try:
            dt = datetime.strptime(ts_str, fmt)
            return dt.isoformat() + 'Z'
        except ValueError:
            continue
    
    return None


def create_entry(
    log_type: str,
    message: str,
    timestamp: Optional[str] = None,
    source_ip: Optional[str] = None,
    source_hostname: Optional[str] = None,
    destination_ip: Optional[str] = None,
    destination_hostname: Optional[str] = None,
    user_name: Optional[str] = None,
    user_id: Optional[str] = None,
    action: Optional[str] = None,
    outcome: Optional[str] = None,
    severity: str = 'info',
    fields: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Create a standardized log entry"""
    return {
        'id': generate_id(),
        'timestamp': timestamp or datetime.now().isoformat() + 'Z',
        'log_type': log_type,
        'message': message[:1000],
        'source': {
            'ip': source_ip,
            'hostname': source_hostname,
            'port': None,
        },
        'destination': {
            'ip': destination_ip,
            'hostname': destination_hostname,
            'port': None,
        },
        'user': {
            'name': user_name,
            'id': user_id,
        },
        'action': action,
        'outcome': outcome,
        'severity': severity,
        'fields': fields or {},
        'raw_line': message,
    }


def parse_syslog_line(line: str, log_type: str = 'syslog') -> Optional[Dict[str, Any]]:
    """Parse syslog-style lines"""
    m = re.match(r'^(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+([\w\-/]+)\[(\d+)\]:\s*(.*)', line)
    if not m:
        m = re.match(r'^(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+kernel:\s*(.*)', line)
        if m:
            timestamp, hostname, message = m.groups()
            return create_entry(
                log_type=log_type,
                timestamp=parse_timestamp(timestamp),
                message=message,
                source_hostname=hostname,
                severity='info',
            )
        return None
    
    timestamp, hostname, process, pid, message = m.groups()
    
    severity = 'info'
    if 'error' in message.lower():
        severity = 'error'
    elif 'warning' in message.lower():
        severity = 'warning'
    elif 'critical' in message.lower():
        severity = 'critical'
    
    return create_entry(
        log_type=log_type,
        timestamp=parse_timestamp(timestamp),
        message=message,
        source_hostname=hostname,
        severity=severity,
    )


def parse_ssh_line(line: str, log_type: str = 'ssh_auth') -> Optional[Dict[str, Any]]:
    """Parse SSH authentication lines"""
    patterns = [
        (r'^(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+sshd\[\d+\]:\s+Failed\s+password\s+for\s+(?:invalid\s+user\s+)?(\S+)\s+from\s+(\d{1,3}(?:\.\d{1,3}){3})\s+port\s+(\d+)', 'failure'),
        (r'^(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+sshd\[\d+\]:\s+Accepted\s+password\s+for\s+(\S+)\s+from\s+(\d{1,3}(?:\.\d{1,3}){3})\s+port\s+(\d+)', 'success'),
        (r'^(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+sshd\[\d+\]:\s+Accepted\s+publickey\s+for\s+(\S+)\s+from\s+(\d{1,3}(?:\.\d{1,3}){3})\s+port\s+(\d+)', 'success'),
    ]
    
    for pattern, outcome in patterns:
        m = re.match(pattern, line)
        if m:
            timestamp, hostname, user, ip, port = m.groups()
            return create_entry(
                log_type=log_type,
                timestamp=parse_timestamp(timestamp),
                message=line,
                source_ip=ip,
                source_hostname=hostname,
                user_name=user,
                action='login',
                outcome=outcome,
                severity='warning' if outcome == 'failure' else 'info',
            )
    
    return None


def parse_apache_line(line: str, log_type: str = 'apache') -> Optional[Dict[str, Any]]:
    """Parse Apache/Nginx access log lines"""
    m = re.match(r'(\S+)\s+-\s+-\s+\[(.*?)\]\s+"(\d+)\s+(\d+)', line)
    if not m:
        m = re.match(r'(\S+)\s+-\s+(\S+)\s+\[(.*?)\]\s+"(\d+)\s+(\d+)', line)
    
    if m:
        if len(m.groups()) >= 4:
            ip = m.group(1)
            timestamp_str = m.group(2)
            status = int(m.group(3) if len(m.groups()) >= 3 else '200')
            
            severity = 'info'
            if status >= 500:
                severity = 'error'
            elif status >= 400:
                severity = 'warning'
            
            return create_entry(
                log_type=log_type,
                timestamp=parse_timestamp(timestamp_str.replace(':', ' ', 1)),
                message=line,
                source_ip=ip,
                severity=severity,
            )
    
    return None


def parse_firewall_line(line: str, log_type: str = 'iptables') -> Optional[Dict[str, Any]]:
    """Parse firewall log lines"""
    m = re.search(r'SRC=(\d{1,3}(?:\.\d{1,3}){3})\s+DST=(\d{1,3}(?:\.\d{1,3}){3})', line)
    if m:
        src_ip = m.group(1)
        dst_ip = m.group(2)
        
        outcome = 'blocked' if 'DROP' in line or 'BLOCK' in line else 'allowed'
        severity = 'warning' if outcome == 'blocked' else 'info'
        
        return create_entry(
            log_type=log_type,
            message=line,
            source_ip=src_ip,
            destination_ip=dst_ip,
            action='firewall_block' if outcome == 'blocked' else 'firewall_allow',
            outcome=outcome,
            severity=severity,
        )
    
    return None


def parse_json_line(line: str) -> Optional[Dict[str, Any]]:
    """Parse JSON log lines"""
    try:
        data = json.loads(line)
        if isinstance(data, dict):
            return {
                'id': generate_id(),
                'timestamp': data.get('timestamp') or data.get('time') or data.get('date') or datetime.now().isoformat() + 'Z',
                'log_type': data.get('log_type') or data.get('logType') or data.get('level') or 'json',
                'message': json.dumps(data),
                'source': {'ip': data.get('source_ip') or data.get('sourceIp'), 'hostname': None, 'port': None},
                'destination': {'ip': None, 'hostname': None, 'port': None},
                'user': {'name': data.get('user') or data.get('username'), 'id': None},
                'action': data.get('action'),
                'outcome': data.get('outcome') or data.get('status'),
                'severity': data.get('severity') or data.get('level') or 'info',
                'fields': data,
                'raw_line': line,
            }
    except json.JSONDecodeError:
        pass
    
    return None


def parse_windows_event_line(line: str) -> Optional[Dict[str, Any]]:
    """Parse Windows Event Viewer lines"""
    patterns = [
        (r'^(Audit (?:Success|Failure|Error|Warning)|Success|Failure|Error|Warning)\s+(\d{2})-(\d{2})-(\d{4})\s+(\d{2}:\d{2}:\d{2})\s+(.*)', 'windows_event_viewer'),
    ]
    
    for pattern, log_type in patterns:
        m = re.match(pattern, line)
        if m:
            status, month, day, year, time, message = m.groups()
            
            severity = 'info'
            if status in ['Error', 'Failure']:
                severity = 'error'
            elif status in ['Warning', 'Audit Failure']:
                severity = 'warning'
            elif status in ['Critical']:
                severity = 'critical'
            
            timestamp = f"{year}-{month}-{day}T{time}Z"
            
            return create_entry(
                log_type=log_type,
                timestamp=timestamp,
                message=message,
                severity=severity,
            )
    
    return None


def parse_windows_csv_line(line: str, log_type: str) -> Optional[Dict[str, Any]]:
    """Parse Windows Security/Application CSV lines"""
    if line.startswith('TimeCreated,') or line.startswith('EventID,') or line.startswith('Level,'):
        return None
    
    parts = line.split(',')
    if len(parts) < 6:
        return None
        
    try:
        timestamp = parse_timestamp(parts[0].strip())
        event_id = parts[1].strip()
        level = parts[2].strip().lower()
        
        severity = 'info'
        if level in ['error', 'failure', 'audit failure']:
            severity = 'error'
        elif level in ['warning']:
            severity = 'warning'
            
        if 'Security' in log_type or (len(parts) > 3 and parts[3] == 'Security'):
            return create_entry(
                log_type=log_type,
                timestamp=timestamp,
                message=parts[5].strip() if len(parts) > 5 else line,
                user_name=parts[6].strip() if len(parts) > 6 else None,
                source_ip=parts[8].strip() if len(parts) > 8 else None,
                severity=severity,
                fields={
                    'event_id': event_id,
                    'level': level,
                    'log_name': parts[3].strip() if len(parts) > 3 else '',
                    'machine_name': parts[4].strip() if len(parts) > 4 else '',
                    'logon_type': parts[7].strip() if len(parts) > 7 else '',
                }
            )
        else:
            return create_entry(
                log_type=log_type,
                timestamp=timestamp,
                message=parts[6].strip() if len(parts) > 6 else line,
                severity=severity,
                fields={
                    'event_id': event_id,
                    'level': level,
                    'log_name': parts[3].strip() if len(parts) > 3 else '',
                    'machine_name': parts[4].strip() if len(parts) > 4 else '',
                    'provider_name': parts[5].strip() if len(parts) > 5 else '',
                }
            )
    except:
        return None


PARSERS = {
    'ssh_auth': parse_ssh_line,
    'Linux SSHD Failed': parse_ssh_line,
    'Linux SSHD Accepted': parse_ssh_line,
    'pam': parse_syslog_line,
    'apache': parse_apache_line,
    'nginx': parse_apache_line,
    'flask': parse_apache_line,
    'syslog': parse_syslog_line,
    'Linux Syslog': parse_syslog_line,
    'systemd': parse_syslog_line,
    'kernel': parse_syslog_line,
    'iptables': parse_firewall_line,
    'ufw': parse_firewall_line,
    'firewalld': parse_syslog_line,
    'windows_firewall': parse_firewall_line,
    'windows_event_viewer': parse_windows_event_line,
    'windows_application_txt': parse_windows_event_line,
    'Windows Event Viewer': parse_windows_event_line,
    'Windows Security CSV': lambda line: parse_windows_csv_line(line, 'Windows Security CSV'),
    'Windows Application CSV': lambda line: parse_windows_csv_line(line, 'Windows Application CSV'),
}


def auto_parse(content: str) -> Dict[str, Any]:
    """Auto-detect and parse log content"""
    lines = content.split('\n')
    entries = []
    failed_lines = 0
    total_lines = len(lines)
    detected_type = 'unknown'
    
    if not content.strip():
        return {
            'detectedType': 'unknown',
            'entries': [],
            'stats': {
                'totalLines': 0,
                'parsedLines': 0,
                'failedLines': 0,
                'successRate': 0,
            }
        }
    
    detected_type = detect_log_type(content)
    
    # Handle multiline logs (Oracle Alert, Oracle Audit, MySQL Slow)
    if is_multiline_log(detected_type):
        line_groups = group_multiline_entries(lines, detected_type)
        
        for group in line_groups:
            if not group or not any(l.strip() for l in group):
                continue
            
            block = '\n'.join(group)
            parsed = parse_multiline_block(block, detected_type)
            
            if parsed:
                parsed['log_type'] = detected_type
                entries.append(parsed)
            else:
                # Fallback: treat first line as entry
                first_line = group[0].strip() if group else ''
                if first_line:
                    entries.append(create_entry(
                        log_type=detected_type,
                        message='\n'.join([l.strip() for l in group[:5]]),
                    ))
                    failed_lines += len(group)
        
    else:
        # Handle regular single-line logs
        for line in lines:
            line = line.strip()
            if not line:
                continue
            
            parsed = None
            
            json_entry = parse_json_line(line)
            if json_entry:
                parsed = json_entry
            elif detected_type in PARSERS:
                parsed = PARSERS[detected_type](line)
            
            if parsed:
                parsed['log_type'] = detected_type
                entries.append(parsed)
            else:
                entries.append(create_entry(
                    log_type=detected_type,
                    message=line,
                ))
                failed_lines += 1
    
    success_rate = 0
    if total_lines > 0:
        success_rate = round(((total_lines - failed_lines) / total_lines) * 100)
    
    return {
        'detectedType': detected_type,
        'entries': entries,
        'stats': {
            'totalLines': total_lines,
            'parsedLines': total_lines - failed_lines,
            'failedLines': failed_lines,
            'successRate': success_rate,
        }
    }
