"""
Legacy Parser Wrapper - Converts ISEA-style simple parsing to LogEntry
"""

import re
from typing import Optional, Dict, Any
from datetime import datetime, timezone
from .log_parsers import LogParsers
from .type_mapping import TYPE_MAPPING
from .base import Parser, LogEntry, Severity


def normalize_user(user_str: Optional[str]) -> tuple[Optional[str], Optional[str]]:
    """Normalize user string to (user, domain) format"""
    if not user_str:
        return None, None
    user_str = user_str.strip()
    if "\\" in user_str:
        dom, usr = user_str.split("\\", 1)
        return usr.lower(), dom.lower()
    if "@" in user_str:
        usr, dom = user_str.split("@", 1)
        return usr.lower(), dom.lower()
    return user_str.lower(), None


def parse_with_legacy_parser(log_type: str, line: str) -> Optional[LogEntry]:
    """Parse using ISEA-style parser and convert to LogEntry"""
    parser_method_name = f"parse{log_type.replace('-', '_').lower()}"
    if not hasattr(LogParsers, parser_method_name):
        return None
    
    parser_method = getattr(LogParsers, parser_method_name)
    parsed = parser_method(line)
    
    if not parsed:
        return None
    
    mapped_type = TYPE_MAPPING.get(log_type, LogType.UNKNOWN)
    return convert_to_log_entry(parsed, mapped_type, line)


def convert_to_log_entry(
    parsed: Dict[str, Any],
    log_type,
    raw_line: str
) -> LogEntry:
    """Convert ISEA-style parsed dict to LogEntry"""
    result = LogEntry(
        raw_line=raw_line,
        log_type=log_type,
        severity=Severity.INFO,
        timestamp=None,
        hostname=None,
        service=None,
        pid=None,
        user=None,
        ip=None,
        port=None,
        message=raw_line,
        fields=parsed.copy()
    )
    
    if parsed.get('timestamp'):
        result.timestamp = parsed['timestamp']
    
    if parsed.get('host'):
        result.hostname = parsed['host']
    
    if parsed.get('ip') or parsed.get('ip_address'):
        result.ip = parsed.get('ip') or parsed.get('ip_address')
    
    if parsed.get('port') or parsed.get('src_port'):
        result.port = parsed.get('port') or parsed.get('src_port')
    
    if parsed.get('pid'):
        result.pid = int(parsed['pid']) if parsed['pid'] else None
    
    if parsed.get('service'):
        result.service = parsed['service']
    
    if parsed.get('user') or parsed.get('username'):
        user_str = parsed.get('user') or parsed.get('username')
        user, domain = normalize_user(user_str)
        result.user = user
        result.domain = domain
    
    if parsed.get('dst_ip'):
        result.dst_ip = parsed['dst_ip']
    
    if parsed.get('dst_port'):
        result.dst_port = parsed['dst_port']
    
    if parsed.get('status') or parsed.get('outcome'):
        status_str = str(parsed.get('status') or parsed.get('outcome', ''))
        try:
            status_num = int(status_str)
            if status_num >= 400:
                result.outcome = 'failure'
                result.severity = Severity.CRITICAL if status_num >= 500 else Severity.WARNING
            elif 200 <= status_num < 300:
                result.outcome = 'success'
        except (ValueError, TypeError):
            pass
    
    result.fields = parsed.copy()
    
    result.message = parsed.get('message', raw_line)
    
    return result


def generate_tags(log_type, parsed: Dict[str, Any], raw_line: str) -> list[str]:
    """Generate tags based on log type and parsed data"""
    tags = []
    
    if 'ssh_auth' in str(log_type).lower():
        tags.extend(['auth', 'ssh', 'security'])
        if parsed.get('auth_method'):
            tags.append(f"auth_{parsed['auth_method'].lower()}")
    elif 'mysql' in str(log_type).lower():
        tags.extend(['database', 'mysql'])
        if 'slow' in str(log_type).lower():
            tags.extend(['slow_query', 'performance'])
        if 'error' in str(log_type).lower():
            tags.append('error')
    elif 'postgres' in str(log_type).lower():
        tags.extend(['database', 'postgresql'])
        if 'error' in str(log_type).lower():
            tags.append('error')
    elif 'oracle' in str(log_type).lower():
        tags.extend(['database', 'oracle'])
        if 'audit' in str(log_type).lower():
            tags.append('audit')
        if 'alert' in str(log_type).lower():
            tags.extend(['alert', 'error'])
    elif 'sqlserver' in str(log_type).lower():
        tags.extend(['database', 'sqlserver'])
    elif 'mongodb' in str(log_type).lower():
        tags.extend(['database', 'mongodb'])
        if 'audit' in str(log_type).lower():
            tags.append('audit')
    elif 'iptables' in str(log_type).lower() or 'ufw' in str(log_type).lower():
        tags.extend(['firewall', 'linux', 'network'])
    elif 'windows_firewall' in str(log_type).lower():
        tags.extend(['firewall', 'windows', 'network'])
    elif 'apache' in str(log_type).lower() or 'nginx' in str(log_type).lower():
        tags.extend(['webserver', 'http', 'access'])
    elif 'postfix' in str(log_type).lower() or 'sendmail' in str(log_type).lower():
        tags.extend(['mail', 'smtp', 'email'])
    elif 'syslog' in str(log_type).lower() or 'systemd' in str(log_type).lower():
        tags.extend(['system', 'linux'])
    elif 'kernel' in str(log_type).lower():
        tags.extend(['system', 'linux', 'kernel'])
    elif 'audit' in str(log_type).lower():
        tags.extend(['system', 'linux', 'audit', 'security'])
    
    return tags
