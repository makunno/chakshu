"""
FTP Server Log Parsers - VSFTPD, PROFTPD, FileZilla, xferlog
"""

import re
from typing import Optional, Dict, Any
from datetime import datetime


class FTPParsers:
    """ISEA-style FTP server log parsers"""

    @staticmethod
    def vsftpd(line: str) -> Optional[Dict[str, Any]]:
        """Parse VSFTPD log line"""
        # VSFTPD syslog format: "Sun Feb  2 12:00:00 2025 [pid 1234] [user] OK UPLOAD: Client: ..."
        m = re.match(
            r'^[A-Z][a-z]{2}\s+([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})\s+(\d{4})\s+\[pid\s+(\d+)\](?:\s+\[(.+)\])?\s+(.+)$',
            line
        )
        if not m:
            return None
        
        month, day, time, year, pid, user, message = m.groups()
        timestamp = f"{year}-{FTPParsers._month_to_num(month)}-{day.zfill(2)} {time}"
        
        result = {
            'timestamp': timestamp,
            'host': 'localhost',
            'service': 'vsftpd',
            'pid': int(pid),
            'user': user,
            'message': message
        }
        
        # Parse specific VSFTPD events
        if 'OK UPLOAD' in message or 'OK DOWNLOAD' in message:
            file_match = re.search(r'"(.+)"', message)
            size_match = re.search(r'(\d+)\s+bytes', message)
            if file_match:
                result['filename'] = file_match.group(1)
            if size_match:
                result['bytes'] = int(size_match.group(1))
            result['action'] = 'upload' if 'UPLOAD' in message else 'download'
        elif 'OK LOGIN' in message:
            client_match = re.search(r'Client:\s*"(.+)"', message)
            if client_match:
                result['client_ip'] = client_match.group(1)
            result['action'] = 'login'
        elif 'FAIL LOGIN' in message or 'Login incorrect' in message:
            client_match = re.search(r'Client:\s*"(.+)"', message)
            if client_match:
                result['client_ip'] = client_match.group(1)
            result['action'] = 'login_failed'
            result['outcome'] = 'failure'
        elif 'Entering directory' in message:
            dir_match = re.search(r'directory\s+(.+)', message)
            if dir_match:
                result['directory'] = dir_match.group(1)
            result['action'] = 'cwd'
        
        return result

    @staticmethod
    def proftpd(line: str) -> Optional[Dict[str, Any]]:
        """Parse PROFTPD log line"""
        # PROFTPD format: "Feb 02 12:00:00 proftpd[1234]: user (host): message"
        m = re.match(
            r'^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})\s+(\S+)\s+\[(\d+)\]:\s+(.+?)\s+\((.+?)\):\s+(.+)$',
            line
        )
        if not m:
            return None
        
        month, day, time, daemon, pid, user, host, message = m.groups()
        timestamp = f"{datetime.now().year}-{FTPParsers._month_to_num(month)}-{day.zfill(2)} {time}"
        
        return {
            'timestamp': timestamp,
            'host': daemon,
            'service': 'proftpd',
            'pid': int(pid),
            'user': user,
            'client_ip': host,
            'message': message
        }

    @staticmethod
    def filezilla(line: str) -> Optional[Dict[str, Any]]:
        """Parse FileZilla Server log line"""
        # FileZilla format: "(000025)2/2/2025 12:00:00 PM - (not logged in) (1.2.3.4)> 530 Logon incorrect"
        m = re.match(
            r'^\((\d+)\)(\d{1,2})\/(\d{1,2})\/(\d{4})\s+(\d{1,2}:\d{2}:\d{2}\s+(?:AM|PM))\s+-\s+\((.+?)\)\s+\(([\d\.]+)\)(?:\s+>\s+)?(\d{3})(?:\s+(.+))?$',
            line
        )
        if not m:
            return None
        
        seq_num, month, day, year, time_ampm, user, ip, code, message = m.groups()
        
        # Convert 12-hour time to 24-hour
        time_24 = FTPParsers._convert_to_24hour(time_ampm)
        timestamp = f"{year}-{month.zfill(2)}-{day.zfill(2)} {time_24}"
        
        result = {
            'timestamp': timestamp,
            'host': 'filezilla',
            'service': 'filezilla',
            'user': user if user != 'not logged in' else None,
            'client_ip': ip,
            'message': message or '',
            'fields': {
                'seq_num': int(seq_num),
                'response_code': code
            }
        }
        
        # Classify by response code
        if code.startswith('2'):
            result['outcome'] = 'success'
        elif code.startswith('4') or code.startswith('5'):
            result['outcome'] = 'failure'
        
        return result

    @staticmethod
    def xferlog(line: str) -> Optional[Dict[str, Any]]:
        """Parse xferlog format (standard FTP transfer log)"""
        # xferlog format:
        # Sun Feb  2 12:00:00 2025 1 user 1234 _ o 0 ? test.txt c 0 * 1
        m = re.match(
            r'^(\w{3})\s+(\w{3})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})\s+(\d{4})\s+(\d+)\s+(\S+)\s+(\d+)\s+([a-z])\s+(\d+)\s+\?\s+(\S+)\s+([a-z])\s+(\d+)\s+\*\s+(\d+)$',
            line
        )
        if not m:
            return None
        
        wday, month, day, time, year, transfer_id, user, file_size, transfer_mode, bytes_received, code, filename, direction, access_mode, restart_offset, completion_status = m.groups()
        
        timestamp = f"{year}-{FTPParsers._month_to_num(month)}-{day.zfill(2)} {time}"
        
        return {
            'timestamp': timestamp,
            'host': 'ftp',
            'service': 'xferlog',
            'user': user,
            'filename': filename,
            'bytes': int(file_size),
            'direction': 'upload' if direction == 'o' else 'download' if direction == 'i' else None,
            'access_mode': access_mode,
            'completion_status': 'complete' if completion_status == 'c' else 'incomplete'
        }

    @staticmethod
    def _month_to_num(month: str) -> str:
        """Convert month abbreviation to number"""
        months = {
            'Jan': '01', 'Feb': '02', 'Mar': '03', 'Apr': '04',
            'May': '05', 'Jun': '06', 'Jul': '07', 'Aug': '08',
            'Sep': '09', 'Oct': '10', 'Nov': '11', 'Dec': '12'
        }
        return months.get(month, '01')

    @staticmethod
    def _convert_to_24hour(time_ampm: str) -> str:
        """Convert 12-hour AM/PM time to 24-hour format"""
        try:
            dt = datetime.strptime(time_ampm, '%I:%M:%S %p')
            return dt.strftime('%H:%M:%S')
        except ValueError:
            return time_ampm
