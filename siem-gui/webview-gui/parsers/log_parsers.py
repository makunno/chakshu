"""
LogParsers - ISEA-style static parser methods returning simple structures
"""

import re
from typing import Optional, Dict, Any


class LogParsers:
    
    @staticmethod
    def apache(line: str) -> Optional[Dict[str, Any]]:
        m = re.match(r'(\S+) - - \[(.*?)\] "(.*?)" (\d+) (\d+)', line)
        if not m:
            return None
        ip, timestamp, request, status, bytes = m.groups()
        return {
            'ip': ip,
            'timestamp': timestamp,
            'request': request,
            'status': int(status),
            'bytes': int(bytes)
        }
    
    @staticmethod
    def nginx(line: str) -> Optional[Dict[str, Any]]:
        m = re.match(r'(\S+) - (\S+) \[(.*?)\] "(.*?)" (\d+) (\d+)', line)
        if not m:
            return None
        ip, user, timestamp, request, status, bytes = m.groups()
        return {
            'ip': ip,
            'user': user if user != '-' else None,
            'timestamp': timestamp,
            'request': request,
            'status': int(status),
            'bytes': int(bytes)
        }
    
    @staticmethod
    def sshd_failed(line: str) -> Optional[Dict[str, Any]]:
        m = re.match(
            r'^(?P<ts>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+sshd\[(?P<pid>\d+)\]:\s+'
            r'Failed\s+(?P<method>\w+)\s+for\s+(invalid\s+user\s+)?(?P<user>\S+)\s+'
            r'from\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+port\s+(?P<port>\d+)',
            line
        )
        if not m:
            return None
        return m.groupdict()
    
    @staticmethod
    def sshd_accepted(line: str) -> Optional[Dict[str, Any]]:
        m = re.match(
            r'^(?P<ts>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+sshd\[(?P<pid>\d+)\]:\s+'
            r'Accepted\s+(?P<method>\w+)\s+for\s+(?P<user>\S+)\s+'
            r'from\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+port\s+(?P<port>\d+)',
            line
        )
        if not m:
            return None
        return m.groupdict()
    
    @staticmethod
    def postfix(line: str) -> Optional[Dict[str, Any]]:
        m = re.match(
            r'^[A-Z][a-z]{2}\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})\s+(\S+)\s+postfix\/(smtpd|smtp|cleanup|qmgr)\[(\d+)\]:\s+(.+)$',
            line
        )
        if not m:
            return None
        date, time, host, service, pid, message = m.groups()
        return {
            'timestamp': f'{date} {time}',
            'host': host,
            'service': f'postfix/{service}',
            'pid': int(pid),
            'message': message
        }
    
    @staticmethod
    def iptables(line: str) -> Optional[Dict[str, Any]]:
        m = re.match(
            r'^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+kernel:\s+IPTABLES-(DROP|ACCEPT):\s+IN=(\S*)\s+OUT=(\S*)\s+.*SRC=(\d+\.\d+\.\d+\.\d+)\s+DST=(\d+\.\d+\.\d+\.\d+).*PROTO=(TCP|UDP|ICMP).*',
            line
        )
        if not m:
            return None
        timestamp, host, action, in_iface, out_iface, src_ip, dst_ip, proto = m.groups()
        return {
            'timestamp': timestamp,
            'host': host,
            'action': action.lower(),
            'in_iface': in_iface if in_iface else '-',
            'out_iface': out_iface if out_iface else '-',
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'protocol': proto
        }
    
    @staticmethod
    def mysql_error(line: str) -> Optional[Dict[str, Any]]:
        m = re.match(r'(\S+Z)\s+(\d+)\s+\[ERROR\]\s+\[MY-(\d+)\]\s+\[Server\]\s+(.*)', line)
        if not m:
            return None
        timestamp, thread_id, error_code, error_message = m.groups()
        return {
            'timestamp': timestamp,
            'thread_id': int(thread_id),
            'error_level': 'ERROR',
            'error_code': error_code,
            'component': 'Server',
            'error_message': error_message
        }
    
    @staticmethod
    def mysql_query(line: str) -> Optional[Dict[str, Any]]:
        m = re.match(r'(\S+Z)\s+(\d+)\s+Query\s+(.*);', line)
        if not m:
            return None
        timestamp, thread_id, sql_statement = m.groups()
        return {
            'timestamp': timestamp,
            'thread_id': int(thread_id),
            'sql_statement': sql_statement
        }
    
    @staticmethod
    def mysql_slow(block: str) -> Optional[Dict[str, Any]]:
        time_match = re.search(r'# Time: (\S+)', block)
        user_match = re.search(r'# User@Host: (\w+)\[\w+\] @ (\S+) \[(.*?)\]', block)
        query_match = re.search(r'# Query_time: ([\d.]+).*Rows_examined: (\d+)', block)
        sql_match = re.search(r'\n(SELECT.*);', block)
        
        if not (time_match and user_match and query_match and sql_match):
            return None
        
        return {
            'timestamp': time_match.group(1),
            'user': user_match.group(1),
            'host': user_match.group(2),
            'ip': user_match.group(3),
            'query_time': float(query_match.group(1)),
            'rows_examined': int(query_match.group(2)),
            'sql_statement': sql_match.group(1).strip()
        }
    
    @staticmethod
    def postgres_error(line: str) -> Optional[Dict[str, Any]]:
        m = re.match(r'^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?\s+\w+)\s+\[(\d+)\]\s+(?:\S+@\S+\s+)?(ERROR|FATAL):\s+([0-9A-Z]{5}):\s+(.*)$', line)
        if not m:
            return None
        timestamp, timezone, pid, level, code, message = m.groups()
        return {
            'timestamp': timestamp,
            'timezone': timezone,
            'pid': int(pid),
            'level': level,
            'code': code,
            'message': message
        }
    
    @staticmethod
    def postgres_auth(line: str) -> Optional[Dict[str, Any]]:
        m = re.match(r'(\S+)\s+(\S+)\s+\[(\d+)\].*user=(\w+)\s+database=(\w+)', line)
        if not m:
            return None
        timestamp, timezone, pid, user, database = m.groups()
        return {
            'timestamp': timestamp,
            'timezone': timezone,
            'pid': int(pid),
            'user': user,
            'database': database
        }
    
    @staticmethod
    def postgres_statement(line: str) -> Optional[Dict[str, Any]]:
        m = re.match(r'(\S+)\s+(\S+)\s+\[(\d+)\]\s+STATEMENT:\s+(.*);', line)
        if not m:
            return None
        timestamp, timezone, pid, sql_statement = m.groups()
        return {
            'timestamp': timestamp,
            'timezone': timezone,
            'pid': int(pid),
            'sql_statement': sql_statement
        }
    
    @staticmethod
    def filezilla(line: str) -> Optional[Dict[str, Any]]:
        m = re.match(
            r'\(\d+\)(\d{1,2}\/\d{1,2}\/\d{4})\s+(\d{2}:\d{2}:\d{2})\s+-\s+(\S+)\s+\(([\d\.]+)\)>\s+(\d+)\s+(.*)',
            line
        )
        if not m:
            return None
        date, time, user, ip, code, message = m.groups()
        return {
            'timestamp': f'{date} {time}',
            'username': user,
            'ip_address': ip,
            'code': int(code),
            'message': message
        }
    
    @staticmethod
    def iis_ftp(line: str) -> Optional[Dict[str, Any]]:
        if line.startswith('#'):
            return None
        m = re.match(
            r'(\d{4}-\d{2}-\d{2})\s+(\d{2}:\d{2}:\d{2})\s+([\d\.]+)\s+([\w\-]+)\s+[\d\.]+\s+\d+\s+(\w+)\s+([\S]*)\s+(\d+)',
            line
        )
        if not m:
            return None
        date, time, ip, user, command, file, code = m.groups()
        return {
            'timestamp': f'{date} {time}',
            'ip_address': ip,
            'username': user,
            'command': command,
            'file': file,
            'code': int(code)
        }
    
    @staticmethod
    def xferlog(line: str) -> Optional[Dict[str, Any]]:
        m = re.match(
            r'(\w{3})\s+(\w{3})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})\s+(\d{4})\s+\d+\s+([\d\.]+)\s+\d+\s+(\S+)\s+[ab]\s+[_]\s+([io])\s+[ra]\s+(\S+)\s+\w+\s+[01]\s+\*\s+([ci])',
            line
        )
        if not m:
            return None
        day, month, date, time, year, ip, file, direction, user, status = m.groups()
        return {
            'timestamp': f'{day} {month} {date} {time} {year}',
            'ip_address': ip,
            'file': file,
            'direction': direction,
            'username': user,
            'status': status
        }
    
    @staticmethod
    def syslog(line: str) -> Optional[Dict[str, Any]]:
        m = re.match(
            r'(?P<timestamp>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+(?P<service>[\w\-\/]+)\[(?P<pid>\d+)\]:\s+(?P<message>.*)',
            line
        )
        if not m:
            return None
        return m.groupdict()
    
    @staticmethod
    def systemd(line: str) -> Optional[Dict[str, Any]]:
        m = re.match(
            r'(?P<timestamp>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+systemd\[(?P<pid>\d+)\]:\s+(?P<message>.*)',
            line
        )
        if not m:
            return None
        timestamp, host, pid, message = m.groups()
        return {
            'timestamp': timestamp,
            'host': host,
            'service': 'systemd',
            'pid': int(pid),
            'message': message
        }
    
    @staticmethod
    def kernel(line: str) -> Optional[Dict[str, Any]]:
        m = re.match(
            r'(?P<timestamp>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+kernel:\s+(?P<message>.*)',
            line
        )
        if not m:
            return None
        timestamp, host, message = m.groups()
        return {
            'timestamp': timestamp,
            'host': host,
            'service': 'kernel',
            'pid': None,
            'message': message
        }
    
    @staticmethod
    def audit(line: str) -> Optional[Dict[str, Any]]:
        m = re.match(
            r'type=(?P<event_type>\w+)\s+msg=audit\((?P<epoch>\d+)\.\d+:(?P<event_id>\d+)\):\s*(?P<rest>.*)',
            line
        )
        if not m:
            return None
        event_type, epoch, event_id, rest = m.groups()
        from datetime import datetime
        timestamp = datetime.fromtimestamp(int(epoch)).isoformat()
        return {
            'timestamp': timestamp,
            'event_type': event_type,
            'epoch': int(epoch),
            'event_id': int(event_id),
            'message': rest
        }
    
    @staticmethod
    def fastapi(line: str) -> Optional[Dict[str, Any]]:
        m = re.match(
            r'(?P<timestamp>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d+)\s+(?P<level>INFO|WARNING|ERROR|DEBUG).*?"(?P<method>GET|POST|PUT|DELETE|PATCH)\s+(?P<path>\S+)\s+HTTP/\d\.\d"\s+(?P<status>\d{3})',
            line
        )
        if not m:
            return None
        timestamp, level, method, path, status = m.groups()
        return {
            'timestamp': timestamp,
            'level': level,
            'method': method,
            'path': path,
            'status': int(status)
        }
    
    @staticmethod
    def windows_security_csv(line: str) -> Optional[Dict[str, Any]]:
        # Windows Security CSV format: TimeCreated,EventID,LevelDisplayName,LogName,MachineName,Message,...
        # Skip header lines
        if line.startswith('TimeCreated,') or line.startswith('EventID,'):
            return None
        if not line or ',' not in line:
            return None
        parts = line.split(',')
        if len(parts) < 8:
            return None
        try:
            # Check if first part is a timestamp
            first = parts[0].strip()
            if not re.match(r'\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}', first):
                return None
            return {
                'timestamp': first,
                'event_id': int(parts[1]) if parts[1].isdigit() else 0,
                'level': parts[2].strip().lower() if len(parts) > 2 else 'info',
                'log_name': parts[3].strip() if len(parts) > 3 else '',
                'machine_name': parts[4].strip() if len(parts) > 4 else '',
                'message': parts[5].strip() if len(parts) > 5 else '',
                'account_name': parts[6].strip() if len(parts) > 6 else '',
                'logon_type': parts[7].strip() if len(parts) > 7 else '',
                'ip_address': parts[8].strip() if len(parts) > 8 else '',
            }
        except:
            return None
    
    @staticmethod
    def windows_application_csv(line: str) -> Optional[Dict[str, Any]]:
        # Windows Application CSV format
        # Skip header lines
        if line.startswith('TimeCreated,') or line.startswith('EventID,') or line.startswith('Level,'):
            return None
        if not line or ',' not in line:
            return None
        parts = line.split(',')
        if len(parts) < 6:
            return None
        try:
            first = parts[0].strip()
            if not re.match(r'\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}', first):
                return None
            return {
                'timestamp': first,
                'event_id': int(parts[1]) if parts[1].isdigit() else 0,
                'level': parts[2].strip().lower() if len(parts) > 2 else 'info',
                'log_name': parts[3].strip() if len(parts) > 3 else '',
                'machine_name': parts[4].strip() if len(parts) > 4 else '',
                'provider_name': parts[5].strip() if len(parts) > 5 else '',
                'message': parts[6].strip() if len(parts) > 6 else '',
            }
        except:
            return None
    
    @staticmethod
    def raw(line: str) -> Dict[str, Any]:
        return {
            'timestamp': None,
            'host': None,
            'service': None,
            'pid': None,
            'message': line
        }
