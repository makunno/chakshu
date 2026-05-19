"""
LogParsers - ISEA-style static parser methods returning simple structures
Migrated from siem-gui/webview-gui/parsers/log_parsers.py
"""

import re
import json
from typing import Optional, Dict, Any
from datetime import datetime


class LogParsers:
    
    @staticmethod
    def apache(line: str) -> Optional[Dict[str, Any]]:
        # Standard Apache/Nginx format
        m = re.match(r'(\S+) - - \[(.*?)\] "(.*?)" (\d+) (\d+)', line)
        if not m:
            # Flask access log format: 10.0.5.71 - - [2026-01-15T16:14:37.848Z] "POST /api/search HTTP/1.1" 201 -
            m = re.match(r'(\S+) - - \[(.*?)\] "(.*?)" (\d+) (\S+)', line)
        if not m:
            return None
        ip, timestamp, request, status, bytes_sent = m.groups()
        try:
            status_code = int(status)
        except:
            status_code = 0
        try:
            bytes_val = int(bytes_sent) if bytes_sent != '-' else 0
        except:
            bytes_val = 0
        return {
            'ip': ip,
            'timestamp': timestamp,
            'request': request,
            'status': status_code,
            'bytes': bytes_val
        }
    
    @staticmethod
    def nginx(line: str) -> Optional[Dict[str, Any]]:
        m = re.match(r'(\S+) - (\S+) \[(.*?)\] "(.*?)" (\d+) (\d+)', line)
        if not m:
            return None
        ip, user, timestamp, request, status, bytes_sent = m.groups()
        return {
            'ip': ip,
            'user': user if user != '-' else None,
            'timestamp': timestamp,
            'request': request,
            'status': int(status),
            'bytes': int(bytes_sent)
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
        # Handle formats:
        # Mar 18 16:09:54 mail amavis[201502]: ...
        # Mar 18 16:09:54 mail postfix/smtpd[123]: ...
        # Mar 18 16:10:13 mail roundcube: ...
        m = re.match(
            r'^[A-Z][a-z]{2}\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})\s+(\S+)\s+((?:postfix\/(?:smtpd|smtp|cleanup|qmgr|pipe|submission\/smtpd|10025\/smtpd|anvil|postscreen|bounce|dnsblog|amavis\/smtp)|amavis|opendkim|roundcube)(?:\[(\d+)\])?):\s+(.+)$',
            line
        )
        if not m:
            return None
        date, time, host, service_full, pid, message = m.groups()
        
        # Try to extract IP from message
        ip_match = re.search(r'(\d{1,3}(?:\.\d{1,3}){3})', message)
        source_ip = ip_match.group(1) if ip_match else None
        
        # Try to extract user
        user_match = re.search(r'(?:sasl_username|to|from|user)=<?([^>,\s]+)>?|User\s+([^,\s\[\]]+)', message, re.IGNORECASE)
        user = None
        if user_match:
            user = user_match.group(1) or user_match.group(2)
        
        # Try to extract action
        action = None
        outcome = 'unknown'
        if 'Passed CLEAN' in message: 
            action = 'allow'
            outcome = 'success'
        elif 'connect from' in message: 
            action = 'connect'
            outcome = 'success'
        elif 'disconnect from' in message: 
            action = 'disconnect'
            outcome = 'success'
        elif 'authentication failed' in message or 'denied' in message or 'reject' in message: 
            action = 'deny'
            outcome = 'failure'
        elif 'status=sent' in message: 
            action = 'deliver'
            outcome = 'success'
        
        return {
            'timestamp': f'{date} {time}',
            'host': host,
            'service': service_full.split('[')[0],
            'pid': int(pid) if pid else None,
            'message': message,
            'source_ip': source_ip,
            'user': user,
            'action': action,
            'outcome': outcome
        }

    @staticmethod
    def opendkim(line: str) -> Optional[Dict[str, Any]]:
        m = re.match(
            r'^[A-Z][a-z]{2}\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})\s+(\S+)\s+opendkim\[(\d+)\]:\s+(.+)$',
            line
        )
        if not m:
            return None
        date, time, host, pid, message = m.groups()
        return {
            'timestamp': f'{date} {time}',
            'host': host,
            'service': 'opendkim',
            'pid': int(pid),
            'message': message
        }

    @staticmethod
    def roundcube(line: str) -> Optional[Dict[str, Any]]:
        m = re.match(
            r'^[A-Z][a-z]{2}\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})\s+(\S+)\s+roundcube:\s+(.+)$',
            line
        )
        if not m:
            return None
        date, time, host, message = m.groups()
        return {
            'timestamp': f'{date} {time}',
            'host': host,
            'service': 'roundcube',
            'message': message
        }
    
    @staticmethod
    def dovecot(line: str) -> Optional[Dict[str, Any]]:
        # Format: Jan 13 10:56:03 mailserver dovecot: imap-login: Login: user=<bob>, rip=192.168.1.10
        # Or: Jan 13 10:56:03 mailserver dovecot: imap(bob): Logged out: bytes=1234/5678, files=5/10
        m = re.match(r'^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+dovecot:\s+(imap|pop3)-login:\s+Login:\s+user=<([^>]+)>,\s+rip=([\d.]+)(?:,\s+lip=([\d.]+))?(?:,\s+mpid=(\d+))?(?:,\s+session=<([^>]+)>)?', line)
        if m:
            timestamp, hostname, protocol, user, remote_ip, local_ip, master_pid, session_id = m.groups()
            return {
                'timestamp': timestamp,
                'hostname': hostname,
                'protocol': protocol,
                'login_type': 'login',
                'user': user,
                'remote_ip': remote_ip,
                'local_ip': local_ip,
                'master_pid': int(master_pid) if master_pid else None,
                'session_id': session_id
            }
        
        # Logout format
        m = re.match(r'^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+dovecot:\s+(\w+)\(([^)]+)\):\s+Logged out:(.*)', line)
        if m:
            timestamp, hostname, protocol, user, details = m.groups()
            return {
                'timestamp': timestamp,
                'hostname': hostname,
                'protocol': protocol,
                'login_type': 'logout',
                'user': user,
                'details': details.strip()
            }
        
        return None
    
    @staticmethod
    def exim(line: str) -> Optional[Dict[str, Any]]:
        # Format: 2026-01-13 10:56:03 HHVTKB5I3PCB => user@example.com H=mail.example.com [192.168.1.10]
        m = re.match(r'^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+([A-Z0-9]+)\s+(=>|<=)\s+<?([^>\s]+)>?\s+H=([^[]+)\s+\[([\d.]+)\](?:\s+P=(\w+))?(?:\s+S=(\d+))?', line)
        if not m:
            return None
        timestamp, msg_id, direction, recipient, helo, ip, protocol, size = m.groups()
        return {
            'timestamp': timestamp,
            'message_id': msg_id,
            'direction': 'incoming' if direction == '<=' else 'outgoing',
            'recipient': recipient,
            'helo': helo,
            'ip': ip,
            'protocol': protocol,
            'size': int(size) if size else None
        }
    
    @staticmethod
    def iptables(line: str) -> Optional[Dict[str, Any]]:
        # Standard: Jan 13 14:54:30 server kernel: IPTABLES-DROP: IN=eth0 OUT= MAC=aa:bb:cc SRC=172.16.0.2 DST=10.0.0.5 PROTO=ICMP SPT=443 DPT=22
        m = re.match(
            r'^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+kernel:\s*(?:\[[\d.]+\])?\s*IPTABLES-(DROP|ACCEPT):\s+IN=(\S*)\s+OUT=(\S*)\s+.*SRC=([\d.]+)\s+DST=([\d.]+).*PROTO=(TCP|UDP|ICMP)(?:\s+SPT=(\d+))?(?:\s+DPT=(\d+))?',
            line, re.IGNORECASE
        )
        if not m:
            return None
        timestamp, host, action, in_iface, out_iface, src_ip, dst_ip, proto, src_port, dst_port = m.groups()
        return {
            'timestamp': timestamp,
            'hostname': host,
            'action': action.lower(),
            'in_iface': in_iface if in_iface else '-',
            'out_iface': out_iface if out_iface else '-',
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'protocol': proto,
            'src_port': int(src_port) if src_port else None,
            'dst_port': int(dst_port) if dst_port else None
        }
    
    @staticmethod
    def ufw(line: str) -> Optional[Dict[str, Any]]:
        # Format: Jan 13 14:54:30 server ufw[1234]: [UFW BLOCK] IN=eth0 OUT= SRC=192.168.1.10 DST=172.16.0.2
        m = re.match(r'^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+ufw\[\d+\]:\s*\[UFW\s+(ALLOW|BLOCK)\]\s+IN=(\S*)\s+OUT=(\S*)\s+.*SRC=([\d.]+)\s+DST=([\d.]+)', line, re.IGNORECASE)
        if not m:
            return None
        timestamp, host, action, in_iface, out_iface, src_ip, dst_ip = m.groups()
        return {
            'timestamp': timestamp,
            'hostname': host,
            'action': action.lower(),
            'in_iface': in_iface if in_iface else '-',
            'out_iface': out_iface if out_iface else '-',
            'src_ip': src_ip,
            'dst_ip': dst_ip
        }
    
    @staticmethod
    def windows_firewall(line: str) -> Optional[Dict[str, Any]]:
        # Format: 2026-01-13 14:54:30 ALLOW ICMP 127.0.0.1 172.16.0.2 22 443
        m = re.match(r'^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+(ALLOW|DROP|BLOCK)\s+(TCP|UDP|ICMP)\s+([\d.]+)\s+([\d.]+)\s+(\d+)\s+(\d+)', line, re.IGNORECASE)
        if not m:
            return None
        timestamp, action, protocol, src_ip, dst_ip, src_port, dst_port = m.groups()
        return {
            'timestamp': timestamp,
            'action': action.lower(),
            'protocol': protocol,
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'src_port': int(src_port),
            'dst_port': int(dst_port)
        }
    
    @staticmethod
    def mysql_error(line: str) -> Optional[Dict[str, Any]]:
        m = re.match(r'(\d{4}-\d{2}-\d{2}T[\d:.]+Z?)\s+(\d+)\s+\[(ERROR|Warning|Note)\]\s+\[MY-(\d+)\]\s+\[(\w+)\]\s+(.*)', line)
        if not m:
            return None
        timestamp, thread_id, level, error_code, component, message = m.groups()
        return {
            'timestamp': timestamp,
            'thread_id': int(thread_id),
            'error_level': level.lower(),
            'error_code': error_code,
            'component': component,
            'error_message': message
        }
    
    @staticmethod
    def mysql_query(line: str) -> Optional[Dict[str, Any]]:
        m = re.match(r'(\d{4}-\d{2}-\d{2}T[\d:.]+Z?)\s+(\d+)\s+(Query|Connect|Execute)\s+(.*)', line)
        if not m:
            return None
        timestamp, thread_id, query_type, sql_statement = m.groups()
        return {
            'timestamp': timestamp,
            'thread_id': int(thread_id),
            'query_type': query_type,
            'sql_statement': sql_statement
        }
    @staticmethod
    def postgres_error(line: str) -> Optional[Dict[str, Any]]:
        # Format: 2024-01-01 00:03:14.000 UTC [7475] readonly@staging ERROR: 42P01: relation "inventory" does not exist
        m = re.match(r'^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d+)\s+UTC\s+\[(\d+)\]\s+(\S+)@(\S+)\s+(LOG|ERROR|FATAL|WARNING):\s+(.*)', line)
        if not m:
            return None
        timestamp, pid, username, database, level, message = m.groups()
        return {
            'timestamp': timestamp,
            'pid': int(pid),
            'username': username,
            'database': database,
            'level': level.lower(),
            'message': message
        }
    
    @staticmethod
    def postgres_auth(line: str) -> Optional[Dict[str, Any]]:
        m = re.match(r'^(\d{4}-\d{2}-\d{2}T[\d:.]+Z?)\s+\[(\d+)\]\s+(\S+)\s+(\S+)\s+LOG:\s+connection received:.*host=(\d+\.\d+\.\d+\.\d+)\s+port=(\d+)', line)
        if not m:
            return None
        timestamp, pid, host, process, src_ip, src_port = m.groups()
        return {
            'timestamp': timestamp,
            'host': host,
            'process': process,
            'pid': int(pid),
            'ip': src_ip,
            'port': int(src_port)
        }
    
    @staticmethod
    def syslog(line: str) -> Optional[Dict[str, Any]]:
        m = re.match(r'(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+([\w\-\/]+)\[(\d+)\]:\s+(.*)', line)
        if not m:
            return None
        timestamp, host, process, pid, message = m.groups()
        return {
            'timestamp': timestamp,
            'host': host,
            'process': process,
            'pid': int(pid),
            'message': message
        }
    
    @staticmethod
    def systemd(line: str) -> Optional[Dict[str, Any]]:
        m = re.match(r'(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+systemd\[(\d+)\]:\s+(.*)', line)
        if not m:
            return None
        timestamp, host, pid, message = m.groups()
        return {
            'timestamp': timestamp,
            'host': host,
            'pid': int(pid),
            'message': message
        }
    
    @staticmethod
    def iis(line: str) -> Optional[Dict[str, Any]]:
        m = re.match(r'^(\d{4}-\d{2}-\d{2})\s+(\d{2}:\d{2}:\d{2})\s+(\S+)\s+(GET|POST|PUT|DELETE)\s+(\S+)\s+(\S+)\s+(\d+)\s+(\d+)\s+(\S+)\s+(\S+)\s+(.*)', line)
        if not m:
            return None
        date, time, server_ip, method, path, query, status, bytes_sent, referer, user_agent, message = m.groups()
        return {
            'date': date,
            'time': time,
            'server_ip': server_ip,
            'method': method,
            'path': path,
            'query': query,
            'status': int(status),
            'bytes': int(bytes_sent),
            'referer': referer,
            'user_agent': user_agent
        }
    
    @staticmethod
    def windows_event(line: str) -> Optional[Dict[str, Any]]:
        m = re.match(r'^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s*,?\s*(INFO|WARNING|ERROR|DEBUG)\s*,?\s*(\S+)\s*,?\s*(\d+)\s*,?\s*(.*)', line)
        if not m:
            return None
        timestamp, level, source, event_id, message = m.groups()
        return {
            'timestamp': timestamp,
            'level': level.lower(),
            'source': source,
            'event_id': int(event_id),
            'message': message
        }
    
    @staticmethod
    def windows_security(line: str) -> Optional[Dict[str, Any]]:
        m = re.match(r'^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+(INFO|WARNING|ERROR)\s+Security\s+(\d+)\s+(?:User:\s*(\S+))?\s*(.*)?', line)
        if not m:
            return None
        timestamp, level, event_id, user, message = m.groups()
        return {
            'timestamp': timestamp,
            'level': level.lower(),
            'event_id': int(event_id),
            'user': user,
            'message': message or ''
        }
    
    @staticmethod
    def palo_alto(line: str) -> Optional[Dict[str, Any]]:
        m = re.match(r'^(\d{4}/\d{2}/\d{2})\s+(\d{2}:\d{2}:\d{2})\s+(allow|deny|drop)\s+(tcp|udp|icmp)\s+(\S+)\s+(\S+)\s+rule=(\S+).*$', line)
        if not m:
            return None
        date, time, action, proto, src_ip, dst_ip, rule = m.groups()
        return {
            'timestamp': f'{date} {time}',
            'action': action,
            'protocol': proto,
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'rule': rule
        }
    
    @staticmethod
    def fortigate(line: str) -> Optional[Dict[str, Any]]:
        m = re.match(r'^date=(\d{4}-\d{2}-\d{2})\s+time=(\d{2}:\d{2}:\d{2})\s+action=(allow|deny)\s+srcip=(?:\d{1,3}\.){3}\d{1,3}\s+dstip=(?:\d{1,3}\.){3}\d{1,3}.*$', line)
        if not m:
            return None
        date, time, action = m.groups()
        return {
            'timestamp': f'{date} {time}',
            'action': action
        }
    
    @staticmethod
    def cisco_asa(line: str) -> Optional[Dict[str, Any]]:
        m = re.compile(r'^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\S+\s+%ASA-\d-\d+:\s+access-list\s+\S+\s+(denied|permitted)\s+(tcp|udp|icmp)\s+\S+\/(?:\d{1,3}\.){3}\d{1,3}\s+to\s+\S+\/(?:\d{1,3}\.){3}\d{1,3}.*$').match(line)
        if not m:
            return None
        action, proto = m.groups()
        return {
            'action': action,
            'protocol': proto
        }
    
    @staticmethod
    def vsftpd(line: str) -> Optional[Dict[str, Any]]:
        # Format: Jan 14 18:55:21 ftp-prod vsftpd[11119]: [backup_user] OK LOGIN: Client "198.51.100.42"
        # Or: Thu Jan 14 18:55:21 2026 vsftpd[11119]: [backup_user] OK LOGIN: Client "198.51.100.42"
        m = re.match(r'^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+vsftpd\[(\d+)\]:\s+\[(\S+)\]\s+(OK|FAIL)\s+(\w+):\s+Client\s+"([^"]+)"(?:,\s+"([^"]+)")?', line)
        if not m:
            return None
        timestamp, host, pid, username, status, action, client_ip, filename = m.groups()
        return {
            'timestamp': timestamp,
            'hostname': host,
            'pid': int(pid),
            'username': username,
            'status': status.lower(),
            'action': action.lower(),
            'client_ip': client_ip,
            'filename': filename
        }
    
    @staticmethod
    def filezilla(line: str) -> Optional[Dict[str, Any]]:
        # Format: (000001)01/14/2026 18:55:15 - alice (66.249.66.1)> 230 User alice logged in
        # (000002)01/14/2026 18:55:24 - bob (8.8.8.8)> 226 Closing data connection...
        m = re.match(r'^\((\d+)\)(\d{2}/\d{2}/\d{4})\s+(\d{2}:\d{2}:\d{2})\s+-\s+(\S+)\s+\(([^)]+)\)>?\s+(\d{3})\s+(.*)', line)
        if not m:
            return None
        conn_id, date, time, username, ip, status_code, message = m.groups()
        return {
            'connection_id': int(conn_id),
            'date': date,
            'time': time,
            'username': username,
            'ip': ip,
            'status_code': int(status_code),
            'message': message
        }
    
    @staticmethod
    def xferlog(line: str) -> Optional[Dict[str, Any]]:
        # Format: Wed Jan 14 18:55:15 2026 25 172.16.5.21 12766578 /home/guest/notes.txt b _ i a guest ftp 0 * c
        # Standard wu-ftpd/xferlog format
        # weekday month day time year size host bytes filename type special direction mode user service auth restart operation
        m = re.match(
            r'^(\w{3})\s+(\w{3})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})\s+(\d{4})\s+(\d+)\s+([\d.]+)\s+(\d+)\s+(\S+)\s+([a-z])\s+([_\*])\s+([io])\s+([ra])\s+(\S+)\s+(\w+)\s+(\d)\s+([\*c])\s+([ci])',
            line
        )
        if not m:
            return None
        weekday, month, day, time_val, year, transfer_size_kb, remote_host, bytes_sent, filename, file_type, special_action, direction, access_mode, username, service_name, auth_method, completed, operation = m.groups()
        return {
            'weekday': weekday,
            'month': month,
            'day': int(day),
            'time': time_val,
            'year': int(year),
            'transfer_size_kb': int(transfer_size_kb),
            'remote_host': remote_host,
            'bytes_sent': int(bytes_sent),
            'filename': filename,
            'file_type': 'ascii' if file_type == 'a' else 'binary',
            'special_action': special_action,
            'direction': 'incoming' if direction == 'i' else 'outgoing',
            'access_mode': 'anonymous' if access_mode == 'a' else 'real',
            'username': username,
            'service_name': service_name,
            'authentication_method': auth_method,
            'completed': completed == '*',
            'restart_marker': operation == '*',
            'transfer_type': 'connect' if operation == 'c' else 'incomplete'
        }
    
    @staticmethod
    def iis_ftp(line: str) -> Optional[Dict[str, Any]]:
        # IIS FTP log format with header lines
        # #Software: Microsoft Internet Information Services 10.0
        # #Fields: date time c-ip cs-username s-ip s-port cs-method cs-uri-stem sc-status sc-bytes cs-bytes
        # 2026-01-14 18:55:07 103.21.244.11 dev01 192.168.1.1 21 PASS - 530 0 0
        if line.startswith('#'):
            return None
        m = re.match(
            r'^(\d{4}-\d{2}-\d{2})\s+(\d{2}:\d{2}:\d{2})\s+([\d.]+)\s+(\S+)\s+([\d.]+)\s+(\d+)\s+(\S+)\s+(\S+)\s+(\d+)\s+(\d+)\s+(\d+)',
            line
        )
        if not m:
            return None
        date, time, client_ip, username, server_ip, server_port, method, uri_stem, status, sc_bytes, cs_bytes = m.groups()
        return {
            'date': date,
            'time': time,
            'client_ip': client_ip,
            'username': username if username != '-' else None,
            'server_ip': server_ip,
            'server_port': int(server_port),
            'method': method,
            'uri_stem': uri_stem if uri_stem != '-' else None,
            'status': int(status),
            'sc_bytes': int(sc_bytes),
            'cs_bytes': int(cs_bytes)
        }
    
    @staticmethod
    def django(line: str) -> Optional[Dict[str, Any]]:
        # Format: [2026-01-15T16:14:40.793Z] INFO [django.request] "GET /static/css/style.css" 200
        # Format: [2026-01-15T16:14:42.793Z] INFO [myapp.views] Permission denied for user
        # Format: [2026-01-15T16:15:05.793Z] DEBUG [django.db.backends] (0.163) SELECT * FROM users WHERE id = 1
        
        # Request log format
        m = re.match(r'\[([^\]]+)\] (\w+)\s+\[([^\]]+)\]\s+"(\w+)\s+(\S+)"\s+(\d+)', line)
        if m:
            timestamp, level, module, method, path, status = m.groups()
            return {
                'timestamp': timestamp,
                'level': level.lower(),
                'module': module,
                'method': method,
                'path': path,
                'status': int(status),
            }
        
        # Database query format
        m = re.match(r'\[([^\]]+)\]\s+(\w+)\s+\[([^\]]+)\]\s+\(([\d.]+)\)\s+(.+)', line)
        if m:
            timestamp, level, module, duration, query = m.groups()
            return {
                'timestamp': timestamp,
                'level': level.lower(),
                'module': module,
                'duration_sec': float(duration),
                'query': query.strip(),
            }
        
        # General log format
        m = re.match(r'\[([^\]]+)\]\s+(\w+)\s+\[([^\]]+)\]\s+(.+)', line)
        if m:
            timestamp, level, module, message = m.groups()
            return {
                'timestamp': timestamp,
                'level': level.lower(),
                'module': module,
                'message': message,
            }
        
        return None
    
    @staticmethod
    def json_log(line: str) -> Optional[Dict[str, Any]]:
        try:
            return json.loads(line)
        except:
            return None
    
    @staticmethod
    def json_ftp(line: str) -> Optional[Dict[str, Any]]:
        """Parse JSON FTP log format [[{timestamp:...}]]"""
        try:
            data = json.loads(line)
            if isinstance(data, list) and len(data) > 0 and isinstance(data[0], list):
                # Extract first entry from nested list format [[{...}]]
                entry = data[0][0] if data[0] else None
                if entry and isinstance(entry, dict):
                    return {
                        'timestamp': entry.get('timestamp', ''),
                        'user': entry.get('user', ''),
                        'ip': entry.get('ip', ''),
                        'action': entry.get('action', ''),
                        'file': entry.get('file', '')
                    }
            return None
        except:
            return None
    
    @staticmethod
    def parse_by_type(line: str, log_type: str) -> Optional[Dict[str, Any]]:
        """Parse a line based on its detected type"""
        parsers = {
            'Apache': LogParsers.apache,
            'NGINX': LogParsers.nginx,
            'Django': LogParsers.django,
            'Flask': LogParsers.django,
            'Node.js': LogParsers.django,
            'Express.js': LogParsers.django,
            'FastAPI': LogParsers.django,
            'Gunicorn': LogParsers.django,
            'Linux SSHD Failed': LogParsers.sshd_failed,
            'Linux SSHD Accepted': LogParsers.sshd_accepted,
            'Postfix': LogParsers.postfix,
            'OpenDKIM': LogParsers.postfix,
            'Roundcube': LogParsers.postfix,
            'Sendmail': LogParsers.postfix,
            'Exim': LogParsers.postfix,
            'Dovecot': LogParsers.dovecot,
            'iptables': LogParsers.iptables,
            'UFW': LogParsers.ufw,
            'nftables': LogParsers.iptables,
            'firewalld': LogParsers.iptables,
            'Palo Alto Firewall': LogParsers.palo_alto,
            'FortiGate': LogParsers.fortigate,
            'Cisco ASA': LogParsers.cisco_asa,
            'VSFTPD': LogParsers.vsftpd,
            'ProFTPD': LogParsers.vsftpd,
            'FileZilla FTP': LogParsers.filezilla,
            'IIS FTP': LogParsers.iis_ftp,
            'xferlog': LogParsers.xferlog,
            'MySQL Error': LogParsers.mysql_error,
            'MySQL Query': LogParsers.mysql_query,
            'MySQL Slow Query': LogParsers.mysql_slow,
            'PostgreSQL Error': LogParsers.postgres_error,
            'PostgreSQL Auth': LogParsers.postgres_auth,
            'PostgreSQL Statement': LogParsers.postgres_statement,
            'Oracle Alert': LogParsers.postgres_error,
            'Oracle Listener': LogParsers.oracle_listener,
            'SQL Server Error': LogParsers.sqlserver_error,
            'SQL Server Audit': LogParsers.sqlserver_audit,
            'SQL Server Transaction': LogParsers.sqlserver_transaction,
            'MongoDB Server': LogParsers.mongodb_server,
            'MongoDB Audit': LogParsers.mongodb_audit,
            'Linux Syslog': LogParsers.syslog,
            'Linux Systemd': LogParsers.systemd,
            'Linux Kernel': LogParsers.syslog,
            'Linux Audit': LogParsers.syslog,
            'IIS': LogParsers.iis,
            'Windows Event': LogParsers.windows_event,
            'Windows Security CSV': LogParsers.windows_security_csv,
            'Windows Application CSV': LogParsers.windows_application_csv,
            'JSON FTP Logs': LogParsers.json_ftp,
            'AWS CloudTrail': LogParsers.aws_cloudtrail,
            'AWS GuardDuty': LogParsers.aws_cloudtrail,
            'Azure Activity': LogParsers.aws_cloudtrail,
            'GCP Audit': LogParsers.aws_cloudtrail,
            'Kubernetes': LogParsers.kubernetes,
            'Docker': LogParsers.docker,
            'Squid': LogParsers.squid,
            'Suricata': LogParsers.suricata,
            'Redis': LogParsers.redis,
            'Elasticsearch': LogParsers.elasticsearch,
        }
        
        parser = parsers.get(log_type)
        if parser:
            return parser(line)
        
        # Try matching by partial type name
        for type_name, parser_func in parsers.items():
            if type_name.lower() in log_type.lower():
                return parser_func(line)
        
        return None
    
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
    def postgres_statement(line: str) -> Optional[Dict[str, Any]]:
        # Format: 2025-09-15 00:00:49.147 PST [17508] STATEMENT: SELECT ip_address, name FROM staging.payments WHERE id = 8712901;
        # Or: 2025-09-15 00:01:44.651 IST [34055] LOG: duration: 123.456 ms statement: UPDATE ...
        # Note: Some logs have "STATEMENT:" and directly the query (no "statement:" prefix again)
        m = re.match(r'^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d+)\s+([A-Z]{3,4})\s+\[(\d+)\]\s+(STATEMENT|LOG):\s+(?:duration:\s+([\d.]+)\s+ms\s+)?(?:statement:\s+)?(.*)', line, re.IGNORECASE)
        if not m:
            return None
        timestamp, timezone, pid, log_type, duration_ms, statement = m.groups()
        return {
            'timestamp': timestamp,
            'timezone': timezone,
            'pid': int(pid),
            'log_type': log_type.lower(),
            'duration_ms': float(duration_ms) if duration_ms else None,
            'statement': statement
        }
    
    @staticmethod
    def oracle_listener(line: str) -> Optional[Dict[str, Any]]:
        """Special parser for Oracle TNS Listener logs with nested CONNECT_DATA"""
        # Format: 01-JAN-2026 00:00:06 * (CONNECT_DATA=(SERVICE_NAME=crmdb)) * (ADDRESS=(PROTOCOL=tcp)(HOST=172.3.232.14)(PORT=12169)) * establish * crmdb * 0
        m = re.match(r'^(\d{2}-\w{3}-\d{4}\s+\d{2}:\d{2}:\d{2})\s+\*\s+(.*)', line)
        if not m:
            return None
        
        timestamp = m.group(1)
        rest = m.group(2)
        
        # Extract CONNECT_DATA - find balanced parens until ") *"
        conn_data = {}
        conn_match = re.search(r'CONNECT_DATA=(.+)', rest)
        if conn_match:
            conn_str = conn_match.group(1)
            # Find "*) *" pattern to end CONNECT_DATA section
            m2 = re.match(r'(.*?)\)\s+\*\s+(.*)', conn_str)
            if m2:
                conn_inner = m2.group(1)
                for field, value in re.findall(r'(\w+)=([^\s()]+)', conn_inner):
                    conn_data[field.lower()] = value
        
        # Extract ADDRESS - find balanced parens until ") *"
        addr_data = {}
        addr_match = re.search(r'ADDRESS=(.+)', rest)
        if addr_match:
            addr_str = addr_match.group(1)
            m2 = re.match(r'(.*?)\)\s+\*\s+(.*)', addr_str)
            if m2:
                addr_inner = m2.group(1)
                for field, value in re.findall(r'(\w+)=([^\s()]+)', addr_inner):
                    addr_data[field.lower()] = value
        
        # Extract action and result
        action_match = re.search(r'\*\s+(establish|accept|reject|update)\s+\*\s+(\S+)', rest)
        action = action_match.group(1) if action_match else ''
        service = action_match.group(2) if action_match else ''
        
        result_match = re.search(r'\*\s+(\d+)\s*$', rest)
        result = int(result_match.group(1)) if result_match else 0
        
        return {
            'timestamp': timestamp,
            'protocol': conn_data.get('protocol', ''),
            'host': addr_data.get('host', ''),
            'port': int(addr_data.get('port', 0)) if addr_data.get('port', '').isdigit() else 0,
            'service_name': conn_data.get('service_name', ''),
            'cid_program': conn_data.get('cid_program', ''),
            'cid_host': conn_data.get('cid_host', ''),
            'cid_user': conn_data.get('cid_user', ''),
            'action': action,
            'service': service,
            'result': result
        }
    
    @staticmethod
    def mongodb_server(line: str) -> Optional[Dict[str, Any]]:
        """Special parser for MongoDB BSON-like JSON logs"""
        try:
            data = json.loads(line)
            severity_map = {'I': 'info', 'W': 'warning', 'E': 'error', 'F': 'fatal'}
            return {
                'timestamp': data.get('t', {}).get('$date', ''),
                'severity': severity_map.get(data.get('s', ''), data.get('s', '').lower()),
                'component': data.get('c', ''),
                'message': data.get('msg', ''),
                'remote': data.get('attr', {}).get('remote', ''),
                'connection_id': data.get('attr', {}).get('connectionId', 0),
                'user': data.get('attr', {}).get('user', ''),
                'database': data.get('attr', {}).get('db', ''),
                'command': data.get('attr', {}).get('command', ''),
                'duration_ms': data.get('attr', {}).get('duration', 0),
                'plan_summary': data.get('attr', {}).get('planSummary', ''),
                'roles': data.get('attr', {}).get('roles', [])
            }
        except:
            return None
    
    @staticmethod
    def mongodb_audit(line: str) -> Optional[Dict[str, Any]]:
        """Special parser for MongoDB audit logs (JSON format)"""
        try:
            data = json.loads(line)
            return {
                'timestamp': data.get('ts', {}).get('$date', ''),
                'atype': data.get('atype', ''),
                'action': data.get('action', ''),
                'user': data.get('param', {}).get('user', ''),
                'database': data.get('param', {}).get('db', ''),
                'collection': data.get('param', {}).get('collection', ''),
                'ip': data.get('param', {}).get('ip', ''),
                'port': data.get('param', {}).get('port', 0)
            }
        except:
            return None
    
    @staticmethod
    def sqlserver_error(line: str) -> Optional[Dict[str, Any]]:
        """Parser for SQL Server error logs"""
        # Format: 2024-01-01 00:13:27.000 Logon Server Error: 1205, Severity: 13, State: 68. Transaction...
        m = re.match(r'^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d+)\s+(?:Logon\s+)?(?:spid\d+\w*)?s?\s*(?:Server\s+)?Error:\s+(\d+),\s+Severity:\s+(\d+),\s+State:\s+(\d+).\s*(.*)', line)
        if not m:
            return None
        timestamp, error_num, severity, state, message = m.groups()
        return {
            'timestamp': timestamp,
            'error_number': int(error_num),
            'severity': int(severity),
            'state': int(state),
            'message': message
        }
    
    @staticmethod
    def sqlserver_audit(line: str) -> Optional[Dict[str, Any]]:
        """Parser for SQL Server audit logs with key=value pairs"""
        # Format can include: event_time=... action_id=... name=... database_name=... statement=...
        result = {}
        
        # Extract timestamp if present (event_time=2024-01-15 10:00:00)
        ts_match = re.search(r'event_time=([^=]+?)(?=\s+\w+=|$)', line)
        if ts_match:
            result['timestamp'] = ts_match.group(1).strip()
            
        # Extract statement separately as it can contain spaces and special characters
        stmt_match = re.search(r'statement=([\s\S]+)$', line)
        if stmt_match:
            result['statement'] = stmt_match.group(1).strip().strip('\'"')
            # Remove statement part from line for easier KV parsing of other fields
            kv_part = line[:stmt_match.start()]
        else:
            kv_part = line
            
        # Parse remaining key=value pairs
        # Matches key=value where value is either quoted or non-spaced
        kv_pairs = re.findall(r'(\w+)=((?:\'[^\']*\')|(?:"[^"]*")|(?:\S+))', kv_part)
        for key, value in kv_pairs:
            key = key.lower()
            if key not in result:
                result[key] = value.strip('\'"')
                
        # Map common fields for SIEM consistency
        if 'database_name' in result:
            result['database'] = result['database_name']
        if 'server_principal_name' in result:
            result['user'] = result['server_principal_name']
            
        return result if result else None
    
    @staticmethod
    def sqlserver_transaction(line: str) -> Optional[Dict[str, Any]]:
        """Parser for SQL Server transaction logs"""
        # Format: (55:1:1) Transaction begin, spid 55, Excluive Table lock on OBJECT:...
        m = re.match(r'\((\d+):(\d+):(\d+)\)\s+(Transaction\s+\w+|.*)', line)
        if not m:
            return None
        spid, slot, sequence, description = m.groups()
        return {
            'spid': int(spid),
            'slot': int(slot),
            'sequence': int(sequence),
            'description': description
        }
    
    @staticmethod
    def mysql_slow(block: str) -> Optional[Dict[str, Any]]:
        """Special parser for MySQL slow query logs (multi-line)"""
        lines = block.strip().split('\n')
        if not lines:
            return None
        
        result = {
            'timestamp': '',
            'user': '',
            'db_user': '',
            'host': '',
            'ip': '',
            'query_time': 0.0,
            'lock_time': 0.0,
            'rows_examined': 0,
            'rows_sent': 0,
            'sql_statement': ''
        }
        
        sql_lines = []
        for line in lines:
            line = line.strip()
            if line.startswith('# Time:'):
                match = re.search(r'# Time:\s+(\S+)', line)
                if match:
                    result['timestamp'] = match.group(1)
            elif line.startswith('# User@Host:'):
                match = re.search(r'# User@Host:\s+(\w+)\[(\w+)\]\s+@\s+(\S+)\s+\[([\d.]+)\]', line)
                if match:
                    result['user'] = match.group(1)
                    result['db_user'] = match.group(2)
                    result['host'] = match.group(3)
                    result['ip'] = match.group(4)
            elif line.startswith('# Query_time:'):
                match = re.search(r'# Query_time:\s+([\d.]+).*Lock_time:\s+([\d.]+).*Rows_examined:\s+(\d+).*Rows_sent:\s+(\d+)', line)
                if match:
                    result['query_time'] = float(match.group(1))
                    result['lock_time'] = float(match.group(2))
                    result['rows_examined'] = int(match.group(3))
                    result['rows_sent'] = int(match.group(4))
            elif line.startswith('SELECT') or line.startswith('INSERT') or line.startswith('UPDATE') or line.startswith('DELETE') or line.startswith('CREATE') or line.startswith('ALTER') or line.startswith('DROP'):
                sql_lines.append(line.rstrip(';'))
        
        result['sql_statement'] = ' '.join(sql_lines)
        return result if result['sql_statement'] else None
    
    @staticmethod
    def aws_cloudtrail(line: str) -> Optional[Dict[str, Any]]:
        # AWS CloudTrail JSON format
        try:
            if line.strip().startswith('{'):
                data = json.loads(line)
                return {
                    'timestamp': data.get('eventTime', ''),
                    'event_name': data.get('eventName', ''),
                    'event_source': data.get('eventSource', ''),
                    'user_identity': data.get('userIdentity', {}).get('arn', ''),
                    'source_ip': data.get('sourceIPAddress', ''),
                    'user_agent': data.get('userAgent', ''),
                    'request_params': data.get('requestParameters', {}),
                    'response_elements': data.get('responseElements', {}),
                }
        except:
            pass
        return None
    
    @staticmethod
    def kubernetes(line: str) -> Optional[Dict[str, Any]]:
        # Kubernetes JSON log format
        try:
            if line.strip().startswith('{'):
                data = json.loads(line)
                return {
                    'timestamp': data.get('time', ''),
                    'stream': data.get('stream', ''),
                    'message': data.get('log', ''),
                    'container': data.get('container', {}).get('name', ''),
                    'pod': data.get('pod', {}).get('name', ''),
                    'namespace': data.get('pod', {}).get('namespace', ''),
                }
        except:
            pass
        return None
    
    @staticmethod
    def docker(line: str) -> Optional[Dict[str, Any]]:
        # Docker JSON log format
        try:
            if line.strip().startswith('{'):
                data = json.loads(line)
                return {
                    'timestamp': data.get('time', ''),
                    'stream': data.get('stream', ''),
                    'message': data.get('log', ''),
                }
        except:
            pass
        return None
    
    @staticmethod
    def squid(line: str) -> Optional[Dict[str, Any]]:
        # Squid format: timestamp duration IP/Status Code/Method/URL/Peer/...
        m = re.match(r'(\d+\.\d+)\s+(\d+)\s+(\d+\.\d+\.\d+\.\d+)\s+(TCP_|UDP_|CONNECT)\s*(\d+)?\s*(\d+)?\s*(\S+)\s+(.*)', line)
        if m:
            return {
                'timestamp': m.group(1),
                'duration': m.group(2),
                'ip': m.group(3),
                'code': m.group(4),
                'status': m.group(5),
                'method': m.group(6),
                'url': m.group(7),
                'message': m.group(8),
            }
        return None
    
    @staticmethod
    def suricata(line: str) -> Optional[Dict[str, Any]]:
        # Suricata eve.json format
        try:
            if line.strip().startswith('{'):
                data = json.loads(line)
                return {
                    'timestamp': data.get('timestamp', ''),
                    'event_type': data.get('event_type', ''),
                    'src_ip': data.get('src_ip', ''),
                    'dest_ip': data.get('dest_ip', ''),
                    'src_port': data.get('src_port', 0),
                    'dest_port': data.get('dest_port', 0),
                    'proto': data.get('proto', ''),
                    'alert': data.get('alert', {}),
                    'signature': data.get('alert', {}).get('signature', ''),
                }
        except:
            pass
        return None
    
    @staticmethod
    def redis(line: str) -> Optional[Dict[str, Any]]:
        # Redis log format: timestamp level: message
        m = re.match(r'(\d+:)?(\d+\s+\S+\s+\d+)\s+(\d+)\s+(\S+)\s+(.*)', line)
        if m:
            return {
                'timestamp': m.group(2),
                'pid': m.group(3),
                'level': m.group(4),
                'message': m.group(5),
            }
        return None
    
    @staticmethod
    def elasticsearch(line: str) -> Optional[Dict[str, Any]]:
        # Elasticsearch JSON format
        try:
            if line.strip().startswith('{'):
                data = json.loads(line)
                return {
                    'timestamp': data.get('@timestamp', ''),
                    'level': data.get('log.level', ''),
                    'logger': data.get('log.logger', ''),
                    'message': data.get('message', ''),
                    'host': data.get('host', {}).get('name', ''),
                }
        except:
            pass
        return None
