"""Web Server Log Parsers"""

import re
from datetime import datetime
from .base import Parser
from .types import LogType, LogEntry, Severity


class ApacheParser(Parser):
    """Parser for Apache access and error logs"""

    def __init__(self):
        super().__init__("Apache Access", LogType.APACHE)
        # Combined log format
        self.access_pattern = re.compile(
            r'(\d+\.\d+\.\d+\.\d+) - ([^ ]+) \[([^\]]+)\] "([^"]*)" (\d+) (\d+|-) "([^"]*)" "([^"]*)"'
        )
        # Error log format
        self.error_pattern = re.compile(
            r'\[([^\]]+)\] \[([^\]]+)\] (?:\[pid\s+(\d+)\]:)?\s+(.+)'
        )

    def detect(self, line: str) -> bool:
        """Detect Apache log lines"""
        return bool(self.access_pattern.match(line) or self.error_pattern.match(line))

    def parse(self, line: str) -> LogEntry:
        """Parse Apache log line"""
        # Try access format first
        match = self.access_pattern.match(line)
        if match:
            return self._parse_access(match, line)

        # Try error format
        match = self.error_pattern.match(line)
        if match:
            return self._parse_error(match, line)

        return LogEntry(line, log_type=self.log_type, severity=Severity.INFO, message=line)

    def _parse_access(self, match, line: str) -> LogEntry:
        """Parse Apache access log"""
        ip, user, timestamp_str, request, status, size, referer, user_agent = match.groups()

        # Parse timestamp
        timestamp = None
        try:
            timestamp = datetime.strptime(timestamp_str, "%d/%b/%Y:%H:%M:%S %z").isoformat()
        except:
            pass

        # Parse request - handle URLs with spaces (e.g., SQL injection attempts)
        # Request format: "METHOD PATH PROTOCOL" where PROTOCOL is HTTP/x.x
        method = ""
        path = ""
        protocol = ""

        if request:
            # Split from the right to separate protocol first (in case URL has spaces)
            if ' HTTP/' in request:
                request_body, protocol_suffix = request.rsplit(' HTTP/', 1)
                protocol = 'HTTP/' + protocol_suffix
            else:
                request_body = request
            
            # Now split method from path
            parts = request_body.split(' ', 1)
            method = parts[0] if len(parts) > 0 else ""
            path = parts[1] if len(parts) > 1 else ""

        # Determine severity
        severity = Severity.INFO
        if status.startswith('4'):
            severity = Severity.WARNING
        elif status.startswith('5'):
            severity = Severity.ERROR

        # Store full request for attack detection (includes query string with spaces)
        full_path = path

        return LogEntry(
            line,
            timestamp=timestamp,
            log_type=self.log_type,
            severity=severity,
            source={'ip': ip, 'service': 'apache'},
            user={'name': user} if user != '-' else None,
            action=method,
            outcome=status,
            message=f"{method} {full_path} {status}",
            fields={
                'method': method,
                'path': full_path,
                'status': int(status),
                'size': int(size) if size != '-' else 0,
                'referer': referer,
                'user_agent': user_agent
            },
            tags=['web', 'http', 'access']
        )

    def _parse_error(self, match, line: str) -> LogEntry:
        """Parse Apache error log"""
        timestamp_str, level, pid, message = match.groups()

        # Parse timestamp
        timestamp = None
        try:
            timestamp = datetime.strptime(timestamp_str, "%a %b %d %H:%M:%S.%f %Y").isoformat()
        except:
            try:
                timestamp = datetime.strptime(timestamp_str.split()[0] + " " + timestamp_str.split()[1] + " " + timestamp_str.split()[2],
                                        "%a %b %d %H:%M:%S %Y").isoformat()
            except:
                pass

        # Determine severity based on level
        severity = Severity.INFO
        level_lower = level.lower() if level else ''
        if 'error' in level_lower or 'crit' in level_lower:
            severity = Severity.ERROR
        elif 'warn' in level_lower:
            severity = Severity.WARNING

        return LogEntry(
            line,
            timestamp=timestamp,
            log_type=self.log_type,
            severity=severity,
            source={
                'service': 'apache',
                'pid': int(pid) if pid and pid.isdigit() else None
            },
            message=message,
            fields={
                'level': level,
                'pid': pid
            },
            tags=['web', 'http', 'error']
        )


class NginxParser(Parser):
    """Parser for Nginx access and error logs"""

    def __init__(self):
        super().__init__("Nginx Access", LogType.NGINX)
        self.access_pattern = re.compile(
            r'(\d+\.\d+\.\d+\.\d+) - ([^ ]+) \[([^\]]+)\] "([^"]*)" (\d+) (\d+) "([^"]*)" "([^"]*)"'
        )

    def detect(self, line: str) -> bool:
        """Detect Nginx log lines"""
        # Nginx looks similar to Apache but has subtle differences
        # Check for common Nginx patterns
        if self.access_pattern.match(line):
            return True
        # Check for error logs
        if 'nginx' in line.lower() and (':' in line):
            return True
        return False

    def parse(self, line: str) -> LogEntry:
        """Parse Nginx log line"""
        match = self.access_pattern.match(line)
        if match:
            return self._parse_access(match, line)

        # Try error format
        return LogEntry(
            line,
            timestamp=None,
            log_type=self.log_type,
            severity=Severity.INFO,
            source={'service': 'nginx'},
            message=line,
            fields={},
            tags=['web', 'http', 'access']
        )

    def _parse_access(self, match, line: str) -> LogEntry:
        """Parse Nginx access log (same format as Apache)"""
        ip, user, timestamp_str, request, status, size, referer, user_agent = match.groups()

        # Parse timestamp
        timestamp = None
        try:
            timestamp = datetime.strptime(timestamp_str, "%d/%b/%Y:%H:%M:%S %z").isoformat()
        except:
            pass

        # Parse request - handle URLs with spaces (e.g., SQL injection attempts)
        # Request format: "METHOD PATH PROTOCOL" where PROTOCOL is HTTP/x.x
        method = ""
        path = ""
        protocol = ""

        if request:
            # Split from the right to separate protocol first (in case URL has spaces)
            if ' HTTP/' in request:
                request_body, protocol_suffix = request.rsplit(' HTTP/', 1)
                protocol = 'HTTP/' + protocol_suffix
            else:
                request_body = request
            
            # Now split method from path
            parts = request_body.split(' ', 1)
            method = parts[0] if len(parts) > 0 else ""
            path = parts[1] if len(parts) > 1 else ""

        # Determine severity
        severity = Severity.INFO
        if status.startswith('4'):
            severity = Severity.WARNING
        elif status.startswith('5'):
            severity = Severity.ERROR

        return LogEntry(
            line,
            timestamp=timestamp,
            log_type=self.log_type,
            severity=severity,
            source={'ip': ip, 'service': 'nginx'},
            user={'name': user} if user != '-' else None,
            action=method,
            outcome=status,
            message=f"{method} {path} {status}",
            fields={
                'method': method,
                'path': path,
                'status': int(status),
                'size': int(size) if size != '-' else 0,
                'referer': referer,
                'user_agent': user_agent
            },
            tags=['web', 'http', 'access']
        )


class IISParser(Parser):
    """Parser for IIS Log"""

    def __init__(self):
        super().__init__("IIS Log", LogType.IIS)

    def detect(self, line: str) -> bool:
        return bool(re.search(r'^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\s+\d+\.\d+\.\d+\.\d+\s+(GET|POST|PUT|DELETE)', line))

    def parse(self, line: str) -> LogEntry:
        match = re.search(
            r'^(\d{4}-\d{2}-\d{2})\s+(\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\w+)\s+(\S+)\s+.*\s+(\d{3})\s*$',
            line
        )
        if not match:
            return LogEntry(line, log_type=self.log_type, severity=Severity.INFO, message=line)

        date, time, server_ip, method, path, status = match.groups()
        status_code = int(status)

        timestamp_parsed = None
        try:
            timestamp_parsed = datetime.strptime(f"{date} {time}", '%Y-%m-%d %H:%M:%S').isoformat()
        except:
            pass

        severity = Severity.ERROR if status_code >= 500 else Severity.WARNING if status_code >= 400 else Severity.INFO

        return LogEntry(
            line,
            timestamp=timestamp_parsed,
            log_type=self.log_type,
            severity=severity,
            source={'ip': server_ip, 'service': 'iis'},
            action=method,
            outcome='success' if status_code < 400 else 'failure',
            message=f"{method} {path} - {status}",
            fields={
                'date': date,
                'time': time,
                'server_ip': server_ip,
                'method': method,
                'path': path,
                'status': status_code,
            },
            tags=['webserver', 'iis', 'http', 'windows']
        )


class DjangoParser(Parser):
    """Parser for Django Log"""

    def __init__(self):
        super().__init__("Django Log", LogType.DJANGO)

    def detect(self, line: str) -> bool:
        return bool(re.search(r'^\[.*?\]\s+"(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+\S+"\s+\d+', line))

    def parse(self, line: str) -> LogEntry:
        match = re.search(r'^\[(.*?)\]\s+"(\w+)\s+(\S+)"\s+(\d+)', line)
        if not match:
            return LogEntry(line, log_type=self.log_type, severity=Severity.INFO, message=line)

        timestamp, method, path, status = match.groups()
        status_code = int(status)

        timestamp_parsed = None
        try:
            timestamp_parsed = datetime.fromisoformat(timestamp.replace(' ', 'T').replace('Z', '+00:00')).isoformat()
        except:
            pass

        severity = Severity.ERROR if status_code >= 500 else Severity.WARNING if status_code >= 400 else Severity.INFO

        return LogEntry(
            line,
            timestamp=timestamp_parsed,
            log_type=self.log_type,
            severity=severity,
            source={'service': 'django'},
            action=method,
            outcome='success' if status_code < 400 else 'failure',
            message=f"{method} {path} - {status}",
            fields={'method': method, 'path': path, 'status': status_code},
            tags=['webserver', 'django', 'python', 'http']
        )


class FlaskParser(Parser):
    """Parser for Flask Log"""

    def __init__(self):
        super().__init__("Flask Log", LogType.FLASK)

    def detect(self, line: str) -> bool:
        return bool(re.search(r'^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+\/\S*\s+\d{3}', line))

    def parse(self, line: str) -> LogEntry:
        match = re.search(r'^(\w+)\s+(\S+)\s+(\d+)', line)
        if not match:
            return LogEntry(line, log_type=self.log_type, severity=Severity.INFO, message=line)

        method, path, status = match.groups()
        status_code = int(status)

        severity = Severity.ERROR if status_code >= 500 else Severity.WARNING if status_code >= 400 else Severity.INFO

        return LogEntry(
            line,
            timestamp=None,
            log_type=self.log_type,
            severity=severity,
            source={'service': 'flask'},
            action=method,
            outcome='success' if status_code < 400 else 'failure',
            message=f"{method} {path} - {status}",
            fields={'method': method, 'path': path, 'status': status_code},
            tags=['webserver', 'flask', 'python', 'http']
        )


class ExpressParser(Parser):
    """Parser for Express.js Log"""

    def __init__(self):
        super().__init__("Express.js Log", LogType.EXPRESS)

    def detect(self, line: str) -> bool:
        try:
            import json
            j = json.loads(line)
            return bool(j.get('method') and j.get('url') and j.get('status') is not None)
        except:
            return False

    def parse(self, line: str) -> LogEntry:
        try:
            import json
            j = json.loads(line)
            if not (j.get('method') and j.get('url') and j.get('status') is not None):
                return LogEntry(line, log_type=self.log_type, severity=Severity.INFO, message=line)

            status_code = int(j.get('status', 0))
            severity = Severity.ERROR if status_code >= 500 else Severity.WARNING if status_code >= 400 else Severity.INFO

            return LogEntry(
                line,
                timestamp=j.get('timestamp') or j.get('time'),
                log_type=self.log_type,
                severity=severity,
                source={'service': 'express', 'ip': j.get('ip') or j.get('remoteAddress')},
                action=j.get('method'),
                outcome='success' if status_code < 400 else 'failure',
                message=f"{j.get('method')} {j.get('url')} - {j.get('status')}",
                fields=j,  # Include all fields
                tags=['webserver', 'express', 'nodejs', 'http']
            )
        except:
            return LogEntry(line, log_type=self.log_type, severity=Severity.INFO, message=line)


class LaravelParser(Parser):
    """Parser for Laravel Log"""

    def __init__(self):
        super().__init__("Laravel Log", LogType.LARAVEL)

    def detect(self, line: str) -> bool:
        return bool(re.search(r'^\[\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\]\s+\w+\.\w+:', line))

    def parse(self, line: str) -> LogEntry:
        match = re.search(r'^\[(.*?)\]\s+(\w+)\.(\w+):\s+(.*)', line)
        if not match:
            return LogEntry(line, log_type=self.log_type, severity=Severity.INFO, message=line)

        timestamp, env, level, message = match.groups()

        timestamp_parsed = None
        try:
            timestamp_parsed = datetime.fromisoformat(timestamp.replace(' ', 'T').replace('Z', '+00:00')).isoformat()
        except:
            pass

        return LogEntry(
            line,
            timestamp=timestamp_parsed,
            log_type=self.log_type,
            severity=self._parse_laravel_severity(level),
            source={'service': 'laravel'},
            message=message,
            fields={'env': env, 'level': level, 'message': message},
            tags=['webserver', 'laravel', 'php']
        )

    def _parse_laravel_severity(self, level: str) -> Severity:
        level_lower = level.lower()
        if level_lower in ['error', 'critical', 'alert', 'emergency']:
            return Severity.ERROR
        elif level_lower in ['warning', 'notice']:
            return Severity.WARNING
        else:
            return Severity.INFO


class GunicornParser(Parser):
    """Parser for Gunicorn Log"""

    def __init__(self):
        super().__init__("Gunicorn Log", LogType.GUNICORN)

    def detect(self, line: str) -> bool:
        return bool(re.search(r'^\[\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}.*\]\s+\[\d+\]\s+\[(INFO|ERROR|WARNING|DEBUG)\]', line))

    def parse(self, line: str) -> LogEntry:
        match = re.search(r'^\[([\d\-:\s\+]+)\]\s+\[(\d+)\]\s+\[(\w+)\]\s+(.*)', line)
        if not match:
            return LogEntry(line, log_type=self.log_type, severity=Severity.INFO, message=line)

        timestamp, pid, level, message = match.groups()

        timestamp_parsed = None
        try:
            timestamp_parsed = datetime.strptime(timestamp.strip(), '%Y-%m-%d %H:%M:%S %z').isoformat()
        except:
            pass

        # Extract HTTP info if present
        http_match = re.search(r'(GET|POST|PUT|DELETE)\s+(\S+)', message)

        return LogEntry(
            line,
            timestamp=timestamp_parsed,
            log_type=self.log_type,
            severity=self._parse_gunicorn_severity(level),
            source={'service': 'gunicorn', 'pid': int(pid)},
            action=http_match.group(1) if http_match else None,
            message=message,
            fields={
                'pid': int(pid),
                'level': level,
                'method': http_match.group(1) if http_match else None,
                'path': http_match.group(2) if http_match else None,
            },
            tags=['webserver', 'gunicorn', 'python']
        )

    def _parse_gunicorn_severity(self, level: str) -> Severity:
        level_upper = level.upper()
        if level_upper == 'ERROR':
            return Severity.ERROR
        elif level_upper == 'WARNING':
            return Severity.WARNING
        elif level_upper == 'DEBUG':
            return Severity.DEBUG
        else:
            return Severity.INFO


class UvicornParser(Parser):
    """Parser for Uvicorn Log"""

    def __init__(self):
        super().__init__("Uvicorn Log", LogType.UVICORN)

    def detect(self, line: str) -> bool:
        return bool(re.search(r'^(INFO|ERROR|WARNING):\s+\d+\.\d+\.\d+\.\d+:\d+\s+-\s+"', line))

    def parse(self, line: str) -> LogEntry:
        match = re.search(
            r'^(\w+):\s+(\d+\.\d+\.\d+\.\d+):(\d+)\s+-\s+"(\w+)\s+(\S+)\s+HTTP\/[\d.]+"\s+(\d+)',
            line
        )
        if not match:
            return LogEntry(line, log_type=self.log_type, severity=Severity.INFO, message=line)

        level, client_ip, client_port, method, path, status = match.groups()
        status_code = int(status)

        return LogEntry(
            line,
            timestamp=None,  # Uvicorn logs don't include timestamps in this format
            log_type=self.log_type,
            severity=self._parse_uvicorn_severity(level),
            source={'service': 'uvicorn', 'ip': client_ip, 'port': int(client_port)},
            action=method,
            outcome='success' if status_code < 400 else 'failure',
            message=f"{method} {path} - {status}",
            fields={
                'level': level,
                'client_ip': client_ip,
                'client_port': int(client_port),
                'method': method,
                'path': path,
                'status': status_code,
            },
            tags=['webserver', 'uvicorn', 'python', 'http']
        )

    def _parse_uvicorn_severity(self, level: str) -> Severity:
        level_upper = level.upper()
        if level_upper == 'ERROR':
            return Severity.ERROR
        elif level_upper == 'WARNING':
            return Severity.WARNING
        else:
            return Severity.INFO


class RailsParser(Parser):
    """Parser for Rails Log"""

    def __init__(self):
        super().__init__("Rails Log", LogType.RAILS)

    def detect(self, line: str) -> bool:
        return 'Processing by' in line or 'Started' in line

    def parse(self, line: str) -> LogEntry:
        # Check for "Processing by" pattern
        processing_match = re.search(r'Processing by (\S+)#(\S+)', line)
        if processing_match:
            controller, action = processing_match.groups()
            return LogEntry(
                line,
                timestamp=None,
                log_type=self.log_type,
                severity=Severity.INFO,
                source={'service': 'rails'},
                action=action,
                message=line,
                fields={
                    'controller': controller,
                    'action': action,
                },
                tags=['webserver', 'rails', 'ruby', 'http']
            )

        # Check for "Started" pattern
        started_match = re.search(r'Started (\w+) "(\S+)"', line)
        if started_match:
            method, path = started_match.groups()
            return LogEntry(
                line,
                timestamp=None,
                log_type=self.log_type,
                severity=Severity.INFO,
                source={'service': 'rails'},
                action=method,
                message=line,
                fields={
                    'method': method,
                    'path': path,
                },
                tags=['webserver', 'rails', 'ruby', 'http']
            )

        return LogEntry(line, log_type=self.log_type, severity=Severity.INFO, message=line)


class FastAPIParser(Parser):
    """Parser for FastAPI Log"""

    def __init__(self):
        super().__init__("FastAPI Log", LogType.FASTAPI)

    def detect(self, line: str) -> bool:
        return bool(re.search(r'^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d+\s+(INFO|WARNING|ERROR|DEBUG).*?"(GET|POST|PUT|DELETE|PATCH)\s+\S+\s+HTTP/\d\.\d"\s+\d{3}', line))

    def parse(self, line: str) -> LogEntry:
        match = re.search(
            r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d+)\s+(INFO|WARNING|ERROR|DEBUG).*?"(GET|POST|PUT|DELETE|PATCH)\s+(\S+)\s+HTTP/\d\.\d"\s+(\d{3})',
            line
        )
        if not match:
            return LogEntry(line, log_type=self.log_type, severity=Severity.INFO, message=line)

        timestamp, level, method, path, status = match.groups()
        status_code = int(status)

        return LogEntry(
            line,
            timestamp=timestamp,
            log_type=self.log_type,
            severity=self._parse_fastapi_severity(level),
            source={'service': 'fastapi'},
            action=method,
            outcome='success' if status_code < 400 else 'failure',
            message=f"{method} {path} - {status}",
            fields={
                'level': level,
                'method': method,
                'path': path,
                'status': status_code,
            },
            tags=['webserver', 'fastapi', 'python', 'http']
        )

    def _parse_fastapi_severity(self, level: str) -> Severity:
        level_upper = level.upper()
        if level_upper == 'ERROR':
            return Severity.ERROR
        elif level_upper == 'WARNING':
            return Severity.WARNING
        else:
            return Severity.INFO


# Export all webserver parsers
PARSERS = [
    ApacheParser(),
    NginxParser(),
    IISParser(),
    DjangoParser(),
    FlaskParser(),
    LaravelParser(),
    ExpressParser(),
    GunicornParser(),
    UvicornParser(),
    RailsParser(),
    FastAPIParser(),
]
