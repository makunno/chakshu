"""Multiline Log Parser - Support for multi-line log formats"""

import re
from typing import List, Optional, Dict, Any
from datetime import datetime


MULTILINE_TYPES = ['mysql_slow', 'mysql_slow_query', 'oracle_alert', 'oracle_audit']


def is_multiline_log(log_type: str) -> bool:
    """Check if log type requires multiline parsing"""
    return log_type.lower().replace(' ', '_').replace('-', '_') in MULTILINE_TYPES


def parse_multiline_block(lines: List[str], log_type: str) -> Optional[Dict[str, Any]]:
    """Parse a block of lines as a single multiline log entry"""
    if isinstance(lines, str):
        lines = lines.split('\n')
    
    block = '\n'.join([l.strip() for l in lines if l.strip()])
    
    if not block:
        return None
    
    normalized_type = log_type.lower().replace(' ', '_').replace('-', '_')
    
    if normalized_type in ('mysql_slow', 'mysql_slow_query'):
        return parse_mysql_slow_block(block)
    elif normalized_type == 'oracle_alert':
        return parse_oracle_alert_block(block)
    elif normalized_type == 'oracle_audit':
        return parse_oracle_audit_block(block)
    
    return None


def parse_mysql_slow_block(block: str) -> Optional[Dict[str, Any]]:
    """Parse MySQL slow query block"""
    time_match = re.search(r'# Time: (\S+)', block)
    user_match = re.search(r'# User@Host: (\w+)\[(\w+)\] @ (\S+) \[(.*?)\]', block)
    query_match = re.search(r'# Query_time: ([\d.]+).*Rows_examined: (\d+)', block)
    sql_match = re.search(r'\n(.*?);$', block, re.DOTALL | re.IGNORECASE)
    
    if not time_match or not sql_match:
        return None
    
    timestamp = None
    if time_match:
        ts_str = time_match.group(1)
        try:
            dt = datetime.fromisoformat(ts_str.replace('Z', '+00:00'))
            timestamp = dt.isoformat() + 'Z'
        except:
            timestamp = ts_str
    
    user = None
    host = None
    ip = None
    if user_match:
        user = user_match.group(1)
        host = user_match.group(3)
        ip = user_match.group(4) if user_match.group(4) else None
    
    query_time = None
    rows_examined = None
    if query_match:
        query_time = float(query_match.group(1))
        rows_examined = int(query_match.group(2))
    
    sql = None
    if sql_match:
        sql = sql_match.group(1).strip()
    
    return {
        'log_type': 'mysql_slow',
        'timestamp': timestamp,
        'severity': 'warning',
        'source': {'hostname': host, 'ip': ip},
        'user': {'name': user},
        'message': f"Slow query: {sql[:200]}" if sql else 'Slow query detected',
        'raw_line': block,
        'fields': {
            'user': user,
            'host': host,
            'ip': ip,
            'query_time': query_time,
            'rows_examined': rows_examined,
            'sql': sql,
        },
        'tags': ['database', 'mysql', 'slow_query'],
    }


def parse_oracle_alert_block(block: str) -> Optional[Dict[str, Any]]:
    """Parse Oracle Alert log block (date on first line, message on next)"""
    lines = block.strip().split('\n')
    if len(lines) < 2:
        return None
    
    first_line = lines[0].strip()
    message_lines = lines[1:]
    message = '\n'.join(message_lines).strip()
    
    date_match = re.match(r'([A-Za-z]{3}\s+[A-Za-z]{3}\s+\d+\s+\d{2}:\d{2}:\d{2}\s+\d{4})', first_line)
    
    if not date_match:
        return None
    
    timestamp_str = date_match.group(1)
    try:
        dt = datetime.strptime(timestamp_str, '%a %b %d %H:%M:%S %Y')
        timestamp = dt.strftime('%Y-%m-%dT%H:%M:%SZ')
    except:
        timestamp = first_line
    
    severity = 'info'
    if 'ORA-' in message or 'ERROR' in message.upper():
        severity = 'error'
    elif 'WARNING' in message.upper():
        severity = 'warning'
    
    ora_match = re.search(r'ORA-(\d+):\s*(.+)', message)
    error_code = None
    error_message = None
    if ora_match:
        error_code = ora_match.group(1)
        error_message = ora_match.group(2).strip()
    
    return {
        'log_type': 'oracle_alert',
        'timestamp': timestamp,
        'severity': severity,
        'source': {'service': 'oracle'},
        'message': message[:500],
        'raw_line': block,
        'fields': {
            'error_code': error_code,
            'error_message': error_message,
            'full_message': message,
        },
        'tags': ['database', 'oracle', 'alert'],
    }


def parse_oracle_audit_block(block: str) -> Optional[Dict[str, Any]]:
    """Parse Oracle Audit log block"""
    time_match = re.search(r'TIMESTAMP:\s*(\S+)', block)
    action_match = re.search(r"ACTION:\s*'([^']+)'", block)
    user_match = re.search(r"DATABASE USER:\s*'([^']+)'", block)
    
    if not time_match or not action_match:
        return None
    
    timestamp = None
    if time_match:
        ts_str = time_match.group(1)
        try:
            dt = datetime.fromisoformat(ts_str.replace('Z', '+00:00'))
            timestamp = dt.isoformat() + 'Z'
        except:
            timestamp = ts_str
    
    action = action_match.group(1).strip() if action_match else None
    user = user_match.group(1).strip() if user_match else None
    
    return {
        'log_type': 'oracle_audit',
        'timestamp': timestamp,
        'severity': 'info',
        'source': {'service': 'oracle'},
        'user': {'name': user},
        'action': action,
        'message': f"Oracle audit: {action} by {user}" if action and user else 'Oracle audit entry',
        'raw_line': block,
        'fields': {
            'action': action,
            'user': user,
        },
        'tags': ['database', 'oracle', 'audit'],
    }


def group_multiline_entries(lines: List[str], log_type: str) -> List[List[str]]:
    """Group lines into multiline entries"""
    normalized_type = log_type.lower().replace(' ', '_').replace('-', '_')
    
    if normalized_type == 'oracle_alert':
        return group_oracle_alert_entries(lines)
    elif normalized_type == 'oracle_audit':
        return group_oracle_audit_entries(lines)
    elif normalized_type in ('mysql_slow', 'mysql_slow_query'):
        return group_mysql_slow_entries(lines)
    
    return [[line] for line in lines if line.strip()]


def group_oracle_alert_entries(lines: List[str]) -> List[List[str]]:
    """Group Oracle Alert log lines into entries"""
    entries = []
    current_entry = []
    
    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue
        
        is_timestamp_line = bool(re.match(r'^[A-Za-z]{3}\s+[A-Za-z]{3}\s+\d+\s+\d{2}:\d{2}:\d{2}\s+\d{4}$', stripped))
        
        if is_timestamp_line:
            if current_entry:
                entries.append(current_entry)
            current_entry = [stripped]
        elif current_entry:
            current_entry.append(stripped)
    
    if current_entry:
        entries.append(current_entry)
    
    return entries


def group_oracle_audit_entries(lines: List[str]) -> List[List[str]]:
    """Group Oracle Audit log lines into entries"""
    entries = []
    
    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue
        entries.append([stripped])
    
    return entries


def group_mysql_slow_entries(lines: List[str]) -> List[List[str]]:
    """Group MySQL Slow Query log lines into entries"""
    entries = []
    current_entry = []
    
    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue
        
        if stripped.startswith('# Time:'):
            if current_entry:
                entries.append(current_entry)
            current_entry = [stripped]
        elif stripped.startswith('# User@Host:') or stripped.startswith('# Query_time:'):
            if current_entry is not None:
                current_entry.append(stripped)
        elif current_entry is not None and not stripped.startswith('#'):
            current_entry.append(stripped)
        elif current_entry is not None and stripped.startswith('#'):
            entries.append(current_entry)
            current_entry = None
    
    if current_entry:
        entries.append(current_entry)
    
    return entries
