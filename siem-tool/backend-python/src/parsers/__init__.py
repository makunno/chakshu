"""
Log Parsers - Auto-detection and parsing for various log types
Uses ISEA-style detection from log_detector.py
"""

from typing import Dict, Any, Optional, List
import re
import json
import uuid
from datetime import datetime
from .log_detector import LogDetector, preprocess_json_array
from .log_parsers import LogParsers


def detect_log_type(content: str) -> str:
    """Auto-detect log type from content using ISEA-style detection"""
    processed = preprocess_json_array(content)
    return LogDetector.detect(processed)


def auto_parse(content: str, force_type: Optional[str] = None) -> Dict[str, Any]:
    """Auto-parse log content with full field extraction"""
    processed = preprocess_json_array(content)
    log_type = force_type or detect_log_type(processed)
    
    all_lines = [l for l in processed.split('\n') if l.strip()]
    # Limit processing to 5000 lines to avoid hanging the backend
    limit = 5000
    lines = all_lines[:limit]
    
    if len(all_lines) > limit:
        print(f"Auto-parse: TRUNCATED processing to {limit} lines (original: {len(all_lines)})")
    
    print(f"Auto-parse: Detected type '{log_type}', processing {len(lines)} lines")
    
    entries = []
    ips_to_lookup = []
    
    # Track failed lines to limit AI fallback
    failed_lines_count = 0
    max_ai_fallbacks = 3
    
    for i, line in enumerate(lines):
        try:
            # Pass a flag to parse_line to control AI fallback
            use_ai = failed_lines_count < max_ai_fallbacks
            entry = parse_line(line, log_type, allow_ai=use_ai)
            
            if entry:
                entries.append(entry)
                # If it was an AI-parsed entry or generic entry, count it as a "weak" match
                if entry.get('fields', {}).get('_ai_parsed'):
                    failed_lines_count += 1
                
                # Collect IPs for bulk lookup
                ip = entry.get('source', {}).get('ip')
                if ip and ip != 'LOCAL':
                    ips_to_lookup.append(ip)
            else:
                failed_lines_count += 1
        except Exception as e:
            failed_lines_count += 1
            if i < 5: # Only log first few errors to avoid spam
                print(f"Error parsing line {i}: {e}")
    
    # Perform Bulk GeoIP Lookup
    if ips_to_lookup:
        try:
            from utils.geoip import get_country_codes_bulk
            # Limit bulk lookup to unique IPs and max 100 to avoid long hangs
            unique_ips = list(set(ips_to_lookup))[:100]
            geo_map = get_country_codes_bulk(unique_ips)
            for entry in entries:
                ip = entry.get('source', {}).get('ip')
                if ip and ip in geo_map:
                    entry['countryCode'] = geo_map[ip]
        except Exception as e:
            print(f"Bulk GeoIP lookup failed: {e}")
    
    print(f"Auto-parse: Successfully parsed {len(entries)}/{len(lines)} entries")
    stats = generate_stats(entries)
    
    return {
        'detectedType': log_type,
        'entries': entries,
        'stats': stats,
        'totalLines': len(all_lines),
        'parsedLines': len(entries),
        'limitApplied': len(all_lines) > limit
    }


def semantic_fallback_parse(line: str) -> Optional[Dict[str, Any]]:
    """Use AI to parse a log line that regex failed to handle"""
    # Safety check: if we are in a high-volume loop, this will kill performance
    # The caller (auto_parse) should limit calls to this function.
    
    from ai_client import get_soc_client
    
    client = get_soc_client()
    if not client:
        return None
        
    print(f"AI Fallback: Attempting to parse line with LLM...")
    prompt = f"""Parse the following raw log line into a JSON object with standard SIEM fields.
Standard fields to include (if present): timestamp, ip, user, action, outcome, status, severity, service, message.
Raw Log: {line}
Output only the JSON object."""

    try:
        response = client.chat("Parse this log line", prompt)
        # Try to find JSON in response
        json_match = re.search(r'\{.*\}', response, re.DOTALL)
        if json_match:
            data = json.loads(json_match.group(0))
            data['_ai_parsed'] = True
            return data
    except Exception as e:
        print(f"Semantic fallback parse failed: {e}")
    
    return None


def parse_line(line: str, log_type: str, allow_ai: bool = False) -> Optional[Dict[str, Any]]:
    """Parse a single log line with regex and semantic fallbacks"""
    try:
        parsed_data = LogParsers.parse_by_type(line, log_type)
        
        # If no specific parser matched, try generic parsing
        if not parsed_data:
            parsed_data = generic_parse(line)
            
        # If generic parsing is still very empty, try semantic AI parsing (if allowed)
        if allow_ai and (not parsed_data or len(parsed_data) <= 1):
            ai_data = semantic_fallback_parse(line)
            if ai_data:
                parsed_data = ai_data
        
        source = extract_source(line, parsed_data)
        
        entry: Dict[str, Any] = {
            'id': str(uuid.uuid4()),
            'timestamp': extract_timestamp(line, parsed_data),
            'logType': map_log_type(log_type),
            'severity': extract_severity(line, log_type),
            'source': source,
            'countryCode': '??', # Updated in bulk by auto_parse
            'user': extract_user(line, parsed_data),
            'action': extract_action(line, parsed_data, log_type),
            'outcome': extract_outcome(line, parsed_data, log_type),
            'message': line,
            'rawLine': line,
            'fields': parsed_data or {},
            'tags': generate_tags(log_type, line),
        }
        
        return entry
    except Exception:
        return None


def generic_parse(line: str) -> Optional[Dict[str, Any]]:
    """Enhanced generic parser for any log format - extracts common fields and structure"""
    result = {}
    
    # 1. Try to extract Key-Value pairs (e.g., key=value, key:value, "key": "value")
    kv_patterns = [
        r'(\w+)=([^,\s]+)',
        r'(\w+):\s*([^,\s]+)',
        r'"(\w+)":\s*"([^"]+)"',
        r'"(\w+)":\s*(\d+)',
    ]
    for pattern in kv_patterns:
        matches = re.findall(pattern, line)
        for key, value in matches:
            if key.lower() not in result:
                result[key.lower()] = value
    
    # 2. Extract IP addresses (source/destination)
    ip_patterns = [
        (r'SRC[=_](\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', 'src_ip'),
        (r'DST[=_](\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', 'dst_ip'),
        (r'from\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', 'src_ip'),
        (r'to\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', 'dst_ip'),
        (r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', 'ip'),
    ]
    for pattern, key in ip_patterns:
        match = re.search(pattern, line, re.IGNORECASE)
        if match:
            if key not in result:
                result[key] = match.group(1)
    
    # 3. Extract common fields if not already found
    if 'user' not in result:
        user_match = re.search(r'user[=:\s]+(\w+)|account[=:\s]+(\w+)|for\s+(\S+)\s+from', line, re.IGNORECASE)
        if user_match:
            result['user'] = next(g for g in user_match.groups() if g)
            
    if 'status' not in result:
        status_match = re.search(r'\s(\d{3})\s|status[=:](\d+)', line)
        if status_match:
            result['status'] = int(next(g for g in status_match.groups() if g))
            
    if 'method' not in result:
        method_match = re.search(r'(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)', line)
        if method_match:
            result['method'] = method_match.group(1)
            
    # 4. Extract service/process
    if 'service' not in result:
        service_match = re.search(r'(\w+)(?:\[\d+\])?:', line)
        if service_match and not service_match.group(1).isdigit():
            result['service'] = service_match.group(1)
            
    return result if result else None


def extract_timestamp(line: str, parsed: Optional[Dict[str, Any]]) -> str:
    """Extract timestamp from log line"""
    if parsed and 'timestamp' in parsed:
        ts = parsed['timestamp']
        try:
            return datetime.strptime(ts[:19], '%Y-%m-%d %H:%M:%S').isoformat()
        except:
            pass
    
    patterns = [
        (r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})', '%Y-%m-%dT%H:%M:%S'),
        (r'(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2})', '%d/%b/%Y:%H:%M:%S'),
        (r'(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})', '%b %d %H:%M:%S'),
        (r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})', '%Y-%m-%d %H:%M:%S'),
    ]
    
    for pattern, fmt in patterns:
        match = re.search(pattern, line)
        if match:
            try:
                return datetime.strptime(match.group(1)[:19], fmt).isoformat()
            except:
                pass
    
    return datetime.now().isoformat()


def extract_severity(line: str, log_type: str) -> str:
    """Extract severity from log line"""
    line_lower = line.lower()
    
    if any(x in line_lower for x in ['critical', 'fatal', 'crit']):
        return 'critical'
    if any(x in line_lower for x in ['error', 'err', 'fail', 'failed', 'denied', 'reject']):
        return 'error'
    if any(x in line_lower for x in ['warning', 'warn', 'alert']):
        return 'warning'
    if any(x in line_lower for x in ['debug', 'trace']):
        return 'debug'
    return 'info'


def extract_source(line: str, parsed: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Extract source information (IP, hostname, etc.)"""
    source: Dict[str, Any] = {}
    
    ip_patterns = [
        r'from\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',
        r'SRC=(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',
        r'srcip=(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',
        r'src_ip=(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',
    ]
    
    for pattern in ip_patterns:
        match = re.search(pattern, line, re.IGNORECASE)
        if match:
            source['ip'] = match.group(1)
            break
    
    port_patterns = [
        r'port\s+(\d+)',
        r'DPT=(\d+)',
        r'dstport=(\d+)',
    ]
    
    for pattern in port_patterns:
        match = re.search(pattern, line, re.IGNORECASE)
        if match:
            source['port'] = int(match.group(1))
            break
    
    if parsed:
        if 'host' in parsed:
            source['hostname'] = parsed['host']
        if 'ip' in parsed:
            source['ip'] = parsed['ip']
        if 'source_ip' in parsed:
            source['ip'] = parsed['source_ip']
        if 'src_ip' in parsed:
            source['ip'] = parsed['src_ip']
        if 'server_ip' in parsed:
            source['ip'] = parsed['server_ip']
        if 'service' in parsed:
            source['service'] = parsed['service']
    
    # Generic IP fallback if still not found
    if not source.get('ip'):
        generic_ip = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
        if generic_ip:
            source['ip'] = generic_ip.group(1)
    
    return source


def extract_user(line: str, parsed: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Extract user information"""
    user: Dict[str, Any] = {}
    
    user_patterns = [
        r'for\s+(\S+)\s+from',
        r'user[=:\s]+(\w+)',
        r'User:\s*(\S+)',
        r'server_principal_name=([^=,\s]+)',
    ]
    
    for pattern in user_patterns:
        match = re.search(pattern, line, re.IGNORECASE)
        if match:
            user['name'] = match.group(1)
            break
    
    if parsed and 'user' in parsed:
        user['name'] = parsed['user']
    
    return user


def extract_action(line: str, parsed: Optional[Dict[str, Any]], log_type: str) -> str:
    """Extract action from log line"""
    if parsed:
        # Try to get from parsed data
        if 'action' in parsed:
            return parsed['action']
        # Extract HTTP method from request (e.g., "GET /admin HTTP/1.1")
        if 'request' in parsed:
            request = parsed['request']
            method = request.split()[0] if request else ''
            if method:
                return method.lower()
    
    line_lower = line.lower()
    
    if 'accepted' in line_lower or 'success' in line_lower or 'allow' in line_lower:
        return 'allow'
    if 'failed' in line_lower or 'denied' in line_lower or 'reject' in line_lower or 'drop' in line_lower:
        return 'deny'
    if 'connect' in line_lower or 'login' in line_lower:
        return 'connect'
    if 'disconnect' in line_lower or 'logout' in line_lower:
        return 'disconnect'
    
    return 'unknown'


def extract_outcome(line: str, parsed: Optional[Dict[str, Any]], log_type: str) -> str:
    """Extract outcome (success/failure)"""
    if parsed and 'outcome' in parsed:
        return parsed['outcome']
        
    # Use status code from parsed data if available
    if parsed and 'status' in parsed:
        status = parsed['status']
        if isinstance(status, int):
            if 200 <= status < 300:
                return 'success'
            elif status >= 400:
                return 'failure'
    
    line_lower = line.lower()
    
    if any(x in line_lower for x in ['accepted', 'success', 'allowed', 'completed']):
        return 'success'
    if any(x in line_lower for x in ['failed', 'denied', 'reject', 'error', 'deny', 'drop']):
        return 'failure'
    
    return 'unknown'


def generate_tags(log_type: str, line: str) -> List[str]:
    """Generate tags based on log type"""
    tags = []
    
    type_tag = map_log_type(log_type)
    if type_tag:
        tags.append(type_tag)
    
    line_lower = line.lower()
    if any(x in line_lower for x in ['error', 'fail', 'critical']):
        tags.append('error')
    if any(x in line_lower for x in ['warning', 'warn']):
        tags.append('warning')
    if any(x in line_lower for x in ['auth', 'login', 'password', 'ssh']):
        tags.append('auth')
    if any(x in line_lower for x in ['attack', 'injection', 'exploit']):
        tags.append('security')
    
    return tags


def map_log_type(detected_type: str) -> str:
    """Map detected type to normalized log type"""
    mapping = {
        'Apache': 'apache',
        'Apache Error': 'apache',
        'NGINX': 'nginx',
        'Nginx Error': 'nginx',
        'Django': 'django',
        'Flask': 'flask',
        'Node.js': 'express',
        'Express.js': 'express',
        'Laravel': 'laravel',
        'Ruby on Rails': 'rails',
        'Gunicorn': 'gunicorn',
        'Uvicorn': 'uvicorn',
        'FastAPI': 'fastapi',
        'IIS': 'iis',
        'Postfix': 'postfix',
        'Sendmail': 'sendmail',
        'Exim': 'exim',
        'Dovecot': 'dovecot',
        'iptables': 'iptables',
        'UFW': 'ufw',
        'nftables': 'nftables',
        'firewalld': 'firewalld',
        'Palo Alto Firewall': 'palo_alto',
        'FortiGate': 'fortigate',
        'Cisco ASA': 'cisco_asa',
        'Check Point Firewall': 'checkpoint',
        'AWS VPC Flow Logs': 'aws_vpc_flow',
        'Azure NSG Flow Logs': 'azure_nsg',
        'GCP VPC Firewall': 'gcp_vpc',
        'MySQL Error': 'mysql_error',
        'MySQL Query': 'mysql_query',
        'MySQL Slow Query': 'mysql_slow',
        'PostgreSQL Error': 'postgres_error',
        'PostgreSQL Auth': 'postgres_auth',
        'PostgreSQL Statement': 'postgres_statement',
        'Oracle Alert': 'oracle_alert',
        'Oracle Listener': 'oracle_listener',
        'Oracle Audit': 'oracle_audit',
        'SQL Server Error': 'sqlserver_error',
        'SQL Server Audit': 'sqlserver_audit',
        'SQL Server Transaction': 'sqlserver_transaction',
        'MongoDB Server': 'mongodb_server',
        'MongoDB Audit': 'mongodb_audit',
        'Linux SSHD Failed': 'ssh_auth',
        'Linux SSHD Accepted': 'ssh_auth',
        'Linux Syslog': 'syslog',
        'Linux Systemd': 'systemd',
        'Linux Kernel': 'kernel',
        'Linux Audit': 'audit',
        'Windows Event': 'windows_event',
        'Windows Security': 'windows_security',
        'Windows Application': 'windows_application',
        'Windows System': 'windows_system',
        'VSFTPD': 'vsftpd',
        'ProFTPD': 'proftpd',
        'FileZilla FTP': 'vsftpd',
        'IIS FTP': 'iis_ftp',
        'xferlog': 'vsftpd',
        'DHCP': 'dhcp',
        'DNS': 'dns',
        'Proxy': 'proxy',
        'Cloudflare': 'cloudflare',
        'AWS CloudTrail': 'cloudtrail',
        'AWS GuardDuty': 'aws_guardduty',
        'Azure Activity': 'azure_activity',
        'GCP Audit': 'gcp_audit',
        'Kubernetes': 'kubernetes',
        'Docker': 'docker',
        'Elasticsearch': 'elasticsearch',
        'Redis': 'redis',
        'RabbitMQ': 'rabbitmq',
        'Kafka': 'kafka',
        'Zookeeper': 'zookeeper',
        'Squid': 'squid',
        'Suricata': 'suricata',
        'Zeek': 'zeek',
        'Ossec': 'ossec',
        'Fail2ban': 'fail2ban',
        'Auth0': 'auth0',
    }
    
    return mapping.get(detected_type, 'raw')


def generate_stats(entries: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Generate statistics from parsed entries"""
    if not entries:
        return {
            'total': 0,
            'parsed': 0,
            'failed': 0,
        }
    
    by_severity: Dict[str, int] = {}
    by_type: Dict[str, int] = {}
    by_outcome: Dict[str, int] = {}
    top_sources: List[Dict[str, Any]] = []
    top_users: List[Dict[str, Any]] = []
    timeline_counts: Dict[str, int] = {}
    
    ip_counts: Dict[str, int] = {}
    user_counts: Dict[str, int] = {}
    
    for entry in entries:
        severity = entry.get('severity', 'unknown')
        by_severity[severity] = by_severity.get(severity, 0) + 1
        
        log_type = entry.get('logType', 'unknown')
        by_type[log_type] = by_type.get(log_type, 0) + 1
        
        outcome = entry.get('outcome', 'unknown')
        by_outcome[outcome] = by_outcome.get(outcome, 0) + 1
        
        # Extract timestamp for timeline
        timestamp = entry.get('timestamp', '')
        if timestamp:
            # Group by hour: minute
            time_key = timestamp[:16] if len(timestamp) >= 16 else timestamp
            timeline_counts[time_key] = timeline_counts.get(time_key, 0) + 1
        
        source = entry.get('source', {})
        if source.get('ip'):
            ip = source['ip']
            ip_counts[ip] = ip_counts.get(ip, 0) + 1
        
        user = entry.get('user', {})
        if user.get('name'):
            username = user['name']
            user_counts[username] = user_counts.get(username, 0) + 1
    
    top_sources = [{'ip': ip, 'count': count} for ip, count in sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:10]]
    top_users = [{'user': user, 'count': count} for user, count in sorted(user_counts.items(), key=lambda x: x[1], reverse=True)[:10]]
    
    # Sort timeline by time
    timeline = [{'time': time, 'count': count} for time, count in sorted(timeline_counts.items())]
    
    return {
        'total': len(entries),
        'parsed': len(entries),
        'failed': 0,
        'bySeverity': by_severity,
        'byType': by_type,
        'byOutcome': by_outcome,
        'topSources': top_sources,
        'topUsers': top_users,
        'timeline': timeline,
    }


all_parsers = {
    'apache': parse_line,
    'nginx': parse_line,
    'ssh_auth': parse_line,
    'iptables': parse_line,
    'syslog': parse_line,
    'systemd': parse_line,
    'mysql_error': parse_line,
    'postgres_error': parse_line,
    'windows_event': parse_line,
    'raw': parse_line,
}
