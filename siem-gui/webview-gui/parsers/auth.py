"""Authentication Log Parsers"""

import re
from datetime import datetime
from .base import Parser
from .types import LogType, LogEntry, Severity


class SSHAuthParser(Parser):
    """Parser for SSH authentication logs"""

    def __init__(self):
        super().__init__("SSH Authentication", LogType.SSH_AUTH)
        # Multiple patterns for different SSH log formats
        self.patterns = [
            re.compile(r'(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\w+)\s+sshd\[(\d+)\]:\s+(.+)'),
            re.compile(r'(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\w+)\s+sshd:\s+(.+)'),
        ]

    def detect(self, line: str) -> bool:
        """Detect SSH auth log lines"""
        if not line:
            return False
        return any(pattern.search(line) for pattern in self.patterns) and 'sshd' in line

    def parse(self, line: str) -> LogEntry:
        """Parse SSH auth log line"""
        for pattern in self.patterns:
            match = pattern.search(line)
            if match:
                return self._parse_match(match, line)
        return LogEntry(line, log_type=self.log_type, severity=Severity.INFO, message=line)

    def _parse_match(self, match, line: str) -> LogEntry:
        """Parse matched SSH log"""
        groups = match.groups()
        timestamp_str = groups[0]
        hostname = groups[1]
        pid = groups[2] if len(groups) > 2 else None
        message = groups[3] if len(groups) > 3 else groups[2]

        # Parse timestamp
        timestamp = None
        try:
            timestamp = datetime.strptime(f"{datetime.now().year} {timestamp_str}", "%Y %b %d %H:%M:%S").isoformat()
        except:
            pass

        # Determine severity and details
        severity = Severity.INFO
        user = None
        ip = None
        action = None
        outcome = None
        tags = ['auth', 'ssh']

        if 'Failed password' in message or 'authentication failure' in message:
            severity = Severity.WARNING
            outcome = 'failure'
            action = 'login'

            user_match = re.search(r'for\s+(\w+)', message)
            ip_match = re.search(r'from\s+([^\s:]+)', message)
            if user_match:
                user = {'name': user_match.group(1)}
            if ip_match:
                ip = ip_match.group(1)

        elif 'Accepted password' in message or 'Accepted publickey' in message:
            severity = Severity.INFO
            outcome = 'success'
            action = 'login'

            user_match = re.search(r'for\s+(\w+)', message)
            ip_match = re.search(r'from\s+([^\s:]+)', message)
            if user_match:
                user = {'name': user_match.group(1)}
            if ip_match:
                ip = ip_match.group(1)

        elif 'Failed' in message:
            severity = Severity.WARNING
            outcome = 'failure'

        elif 'error' in message.lower():
            severity = Severity.ERROR
            outcome = 'error'

        return LogEntry(
            line,
            timestamp=timestamp,
            log_type=self.log_type,
            severity=severity,
            source={
                'hostname': hostname,
                'service': 'sshd',
                'pid': int(pid) if pid and pid.isdigit() else None,
                'ip': ip
            } if any([hostname, pid, ip]) else {},
            user=user,
            action=action,
            outcome=outcome,
            message=message,
            fields={
                'original_message': message,
                'hostname': hostname
            },
            tags=tags
        )


class PAMParser(Parser):
    """Parser for PAM authentication logs"""

    def __init__(self):
        super().__init__("PAM Authentication", LogType.PAM)
        self.pattern = re.compile(r'(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\w+)\s+(\w+)\[?\d*\]?:\s*(.+)')

    def detect(self, line: str) -> bool:
        """Detect PAM log lines"""
        match = self.pattern.search(line)
        if match:
            service = match.group(3).lower()
            # Check if it's a PAM service (login, su, sudo, etc.)
            return any(s in service for s in ['pam', 'login', 'su', 'sudo', 'ssh', 'passwd', 'sudo:'])

    def parse(self, line: str) -> LogEntry:
        """Parse PAM log line"""
        match = self.pattern.search(line)
        if not match:
            return LogEntry(line, log_type=self.log_type, severity=Severity.INFO, message=line)

        timestamp_str, hostname, service, message = match.groups()

        # Parse timestamp
        timestamp = None
        try:
            timestamp = datetime.strptime(f"{datetime.now().year} {timestamp_str}", "%Y %b %d %H:%M:%S").isoformat()
        except:
            pass

        # Determine severity and details
        severity = Severity.INFO
        user = None
        action = None
        outcome = None

        if 'authentication failure' in message or 'failed' in message.lower():
            severity = Severity.WARNING
            outcome = 'failure'
            action = 'login'

            user_match = re.search(r'user=(\w+)', message)
            if user_match:
                user = {'name': user_match.group(1)}

        elif 'session opened' in message or 'success' in message.lower():
            severity = Severity.INFO
            outcome = 'success'
            action = 'login'

            user_match = re.search(r'user=(\w+)', message)
            if user_match:
                user = {'name': user_match.group(1)}

        elif 'sudo' in service.lower():
            action = 'sudo'
            user_match = re.search(r'user=(\w+)', message)
            if user_match:
                user = {'name': user_match.group(1)}

        return LogEntry(
            line,
            timestamp=timestamp,
            log_type=self.log_type,
            severity=severity,
            source={
                'hostname': hostname,
                'service': service
            },
            user=user,
            action=action,
            outcome=outcome,
            message=message,
            fields={
                'service': service,
                'hostname': hostname
            },
            tags=['auth', 'pam']
        )


# Export all auth parsers
PARSERS = [SSHAuthParser(), PAMParser()]
