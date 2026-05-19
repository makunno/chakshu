"""System Log Parsers - Linux/Unix syslog, systemd, kernel, audit"""

import re
from datetime import datetime
from ..base import Parser
from ..types import LogType, LogEntry, Severity


class SyslogParser(Parser):
    """Parser for Syslog"""

    def __init__(self):
        super().__init__("Syslog", LogType.SYSLOG)

    def detect(self, line: str) -> bool:
        return bool(re.search(r'^\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\S+\s+[\w\-\/]+\[\d+\]:', line))

    def parse(self, line: str) -> LogEntry:
        match = re.search(
            r'^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+([\w\-\/]+)\[(\d+)\]:\s+(.*)',
            line
        )
        if not match:
            return LogEntry(line, log_type=self.log_type, severity=Severity.INFO, message=line)

        timestamp, host, service, pid, message = match.groups()

        timestamp_parsed = None
        try:
            timestamp_parsed = datetime.strptime(timestamp, '%b %d %H:%M:%S').replace(year=datetime.now().year).isoformat()
        except:
            pass

        return LogEntry(
            line,
            timestamp=timestamp_parsed,
            log_type=self.log_type,
            severity=Severity.INFO,
            source={'hostname': host, 'service': service, 'pid': int(pid)},
            message=message,
            fields={
                'host': host,
                'service': service,
                'pid': int(pid),
            },
            tags=['system', 'linux', 'syslog']
        )


class SystemdParser(Parser):
    """Parser for Systemd Journal"""

    def __init__(self):
        super().__init__("Systemd Journal", LogType.SYSTEMD)

    def detect(self, line: str) -> bool:
        return 'systemd[' in line

    def parse(self, line: str) -> LogEntry:
        # Pattern 1: With timestamp
        match1 = re.search(
            r'^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+systemd\[(\d+)\]:\s+(.*)',
            line
        )
        if match1:
            timestamp, host, pid, message = match1.groups()
            timestamp_parsed = None
            try:
                timestamp_parsed = datetime.strptime(timestamp, '%b %d %H:%M:%S').replace(year=datetime.now().year).isoformat()
            except:
                pass

            return LogEntry(
                line,
                timestamp=timestamp_parsed,
                log_type=self.log_type,
                severity=Severity.INFO,
                source={'hostname': host, 'service': 'systemd', 'pid': int(pid)},
                message=message,
                fields={'host': host, 'pid': int(pid)},
                tags=['system', 'linux', 'systemd']
            )

        # Pattern 2: Without timestamp
        match2 = re.search(r'systemd\[(\d+)\]:\s+(.*)', line)
        if match2:
            pid, message = match2.groups()
            return LogEntry(
                line,
                timestamp=None,
                log_type=self.log_type,
                severity=Severity.INFO,
                source={'service': 'systemd', 'pid': int(pid)},
                message=message,
                fields={'pid': int(pid)},
                tags=['system', 'linux', 'systemd']
            )

        return LogEntry(line, log_type=self.log_type, severity=Severity.INFO, message=line)


class KernelParser(Parser):
    """Parser for Kernel Log"""

    def __init__(self):
        super().__init__("Kernel Log", LogType.KERNEL)

    def detect(self, line: str) -> bool:
        return 'kernel:' in line or bool(re.search(r'^\[\s*\d+\.\d+\]', line))

    def parse(self, line: str) -> LogEntry:
        # Pattern 1: Syslog-style kernel message
        match1 = re.search(
            r'^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+kernel:\s+(.*)',
            line
        )
        if match1:
            timestamp, host, message = match1.groups()
            timestamp_parsed = None
            try:
                timestamp_parsed = datetime.strptime(timestamp, '%b %d %H:%M:%S').replace(year=datetime.now().year).isoformat()
            except:
                pass

            return LogEntry(
                line,
                timestamp=timestamp_parsed,
                log_type=self.log_type,
                severity=Severity.INFO,
                source={'hostname': host, 'service': 'kernel'},
                message=message,
                fields={'host': host},
                tags=['system', 'linux', 'kernel']
            )

        # Pattern 2: dmesg-style with uptime
        match2 = re.search(r'^\[\s*(\d+\.\d+)\]\s+(.*)', line)
        if match2:
            uptime, message = match2.groups()
            return LogEntry(
                line,
                timestamp=None,
                log_type=self.log_type,
                severity=Severity.INFO,
                source={'service': 'kernel'},
                message=message,
                fields={'uptime': float(uptime)},
                tags=['system', 'linux', 'kernel', 'dmesg']
            )

        return LogEntry(line, log_type=self.log_type, severity=Severity.INFO, message=line)


class AuditParser(Parser):
    """Parser for Linux Audit Log"""

    def __init__(self):
        super().__init__("Linux Audit Log", LogType.AUDIT)

    def detect(self, line: str) -> bool:
        return 'type=' in line and 'msg=audit(' in line

    def parse(self, line: str) -> LogEntry:
        match = re.search(
            r'^type=(\w+)\s+msg=audit\((\d+)\.\d+:(\d+)\):\s*(.*)',
            line
        )
        if not match:
            return LogEntry(line, log_type=self.log_type, severity=Severity.INFO, message=line)

        event_type, epoch, event_id, rest = match.groups()

        # Convert epoch to timestamp
        timestamp_parsed = None
        try:
            timestamp_parsed = datetime.fromtimestamp(int(epoch)).isoformat()
        except:
            pass

        # Extract user info
        uid_match = re.search(r'uid=(\d+)', rest)
        auid_match = re.search(r'auid=(\d+)', rest)
        comm_match = re.search(r'comm="([^"]+)"', rest)
        exe_match = re.search(r'exe="([^"]+)"', rest)
        res_match = re.search(r'res=(\w+)', rest)

        # Determine severity
        severity = Severity.INFO
        if event_type in ['SYSCALL', 'EXECVE']:
            severity = Severity.INFO
        elif event_type in ['AVC', 'SELINUX_ERR']:
            severity = Severity.WARNING
        elif event_type == 'USER_AUTH' and 'res=failed' in rest:
            severity = Severity.WARNING

        outcome = 'success' if res_match and res_match.group(1) == 'success' else 'failure' if res_match else 'unknown'

        return LogEntry(
            line,
            timestamp=timestamp_parsed,
            log_type=self.log_type,
            severity=severity,
            source={'service': 'auditd'},
            user={'name': uid_match.group(1) if uid_match else None},
            action=event_type,
            outcome=outcome,
            message=rest,
            fields={
                'event_type': event_type,
                'event_id': int(event_id),
                'uid': int(uid_match.group(1)) if uid_match else None,
                'auid': int(auid_match.group(1)) if auid_match else None,
                'comm': comm_match.group(1) if comm_match else None,
                'exe': exe_match.group(1) if exe_match else None,
                'result': res_match.group(1) if res_match else None,
            },
            tags=['system', 'linux', 'audit', 'security']
        )


class CronParser(Parser):
    """Parser for Cron Log"""

    def __init__(self):
        super().__init__("Cron Log", LogType.CRON)

    def detect(self, line: str) -> bool:
        return 'CRON[' in line or 'crond[' in line

    def parse(self, line: str) -> LogEntry:
        match = re.search(
            r'^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(?:CRON|crond)\[(\d+)\]:\s+\((\w+)\)\s+(.*)',
            line
        )
        if not match:
            return LogEntry(line, log_type=self.log_type, severity=Severity.INFO, message=line)

        timestamp, host, pid, user, message = match.groups()

        timestamp_parsed = None
        try:
            timestamp_parsed = datetime.strptime(timestamp, '%b %d %H:%M:%S').replace(year=datetime.now().year).isoformat()
        except:
            pass

        # Extract command
        command_match = re.search(r'CMD \((.*)\)', message)
        command = command_match.group(1) if command_match else message

        return LogEntry(
            line,
            timestamp=timestamp_parsed,
            log_type=self.log_type,
            severity=Severity.INFO,
            source={'hostname': host, 'service': 'cron', 'pid': int(pid)},
            user={'name': user},
            action='cron_job',
            message=message,
            fields={
                'host': host,
                'pid': int(pid),
                'user': user,
                'command': command,
            },
            tags=['system', 'linux', 'cron', 'scheduled']
        )


class DaemonParser(Parser):
    """Parser for Daemon Log (generic)"""

    def __init__(self):
        super().__init__("Daemon Log", LogType.DAEMON)

    def detect(self, line: str) -> bool:
        return bool(re.search(r'^\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\S+\s+\w+\[\d+\]:', line))

    def parse(self, line: str) -> LogEntry:
        match = re.search(
            r'^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\w+)\[(\d+)\]:\s+(.*)',
            line
        )
        if not match:
            return LogEntry(line, log_type=self.log_type, severity=Severity.INFO, message=line)

        timestamp, host, service, pid, message = match.groups()

        timestamp_parsed = None
        try:
            timestamp_parsed = datetime.strptime(timestamp, '%b %d %H:%M:%S').replace(year=datetime.now().year).isoformat()
        except:
            pass

        # Determine severity from message
        severity = Severity.INFO
        if re.search(r'error|fail|critical', message, re.IGNORECASE):
            severity = Severity.ERROR
        elif re.search(r'warn', message, re.IGNORECASE):
            severity = Severity.WARNING

        return LogEntry(
            line,
            timestamp=timestamp_parsed,
            log_type=self.log_type,
            severity=severity,
            source={'hostname': host, 'service': service, 'pid': int(pid)},
            message=message,
            fields={
                'host': host,
                'service': service,
                'pid': int(pid),
            },
            tags=['system', 'linux', 'daemon']
        )


# Export all system parsers
PARSERS = [
    SyslogParser(),
    SystemdParser(),
    KernelParser(),
    AuditParser(),
    CronParser(),
    DaemonParser(),
]