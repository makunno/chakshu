"""Mail Server Log Parsers - Postfix, Sendmail, Exim, Dovecot, Exchange"""

import re
from datetime import datetime
from ..base import Parser
from ..types import LogType, LogEntry, Severity


class PostfixParser(Parser):
    """Parser for Postfix Log"""

    def __init__(self):
        super().__init__("Postfix Log", LogType.POSTFIX)

    def detect(self, line: str) -> bool:
        return bool(re.search(r'postfix\/(smtpd|smtp|cleanup|qmgr|pickup|local)\[\d+\]:', line))

    def parse(self, line: str) -> LogEntry:
        match = re.search(
            r'^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+postfix\/(\w+)\[(\d+)\]:\s+(.*)',
            line
        )
        if not match:
            return LogEntry(line, log_type=self.log_type, severity=Severity.INFO, message=line)

        timestamp, host, process, pid, message = match.groups()

        timestamp_parsed = None
        try:
            timestamp_parsed = datetime.strptime(timestamp, '%b %d %H:%M:%S').replace(year=datetime.now().year).isoformat()
        except:
            pass

        # Extract queue ID
        queue_id = None
        queue_match = re.search(r'^([A-F0-9]{6,}):', message)
        if queue_match:
            queue_id = queue_match.group(1)

        # Extract email addresses
        from_match = re.search(r'from=<([^>]*)>', message)
        to_match = re.search(r'to=<([^>]*)>', message)

        # Extract status
        status = None
        status_match = re.search(r'status=(\w+)', message)
        if status_match:
            status = status_match.group(1)

        # Determine severity
        severity = Severity.INFO
        if status in ['bounced', 'deferred']:
            severity = Severity.WARNING
        if re.search(r'reject|error|fatal', message):
            severity = Severity.ERROR

        outcome = 'unknown'
        if status == 'sent':
            outcome = 'success'
        elif status == 'bounced':
            outcome = 'failure'

        return LogEntry(
            line,
            timestamp=timestamp_parsed,
            log_type=self.log_type,
            severity=severity,
            source={'hostname': host, 'service': f'postfix/{process}', 'pid': int(pid)},
            action=process,
            outcome=outcome,
            message=message,
            fields={
                'host': host,
                'process': process,
                'pid': int(pid),
                'queue_id': queue_id,
                'from': from_match.group(1) if from_match else None,
                'to': to_match.group(1) if to_match else None,
                'status': status,
            },
            tags=['mail', 'postfix', 'smtp']
        )


class SendmailParser(Parser):
    """Parser for Sendmail Log"""

    def __init__(self):
        super().__init__("Sendmail Log", LogType.SENDMAIL)

    def detect(self, line: str) -> bool:
        return 'sendmail[' in line or 'sendmail:' in line

    def parse(self, line: str) -> LogEntry:
        match = re.search(
            r'^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+sendmail\[(\d+)\]:\s+(.*)',
            line
        )
        if not match:
            return LogEntry(line, log_type=self.log_type, severity=Severity.INFO, message=line)

        timestamp, host, pid, message = match.groups()

        timestamp_parsed = None
        try:
            timestamp_parsed = datetime.strptime(timestamp, '%b %d %H:%M:%S').replace(year=datetime.now().year).isoformat()
        except:
            pass

        severity = Severity.ERROR if re.search(r'error|fail|reject', message) else Severity.INFO

        return LogEntry(
            line,
            timestamp=timestamp_parsed,
            log_type=self.log_type,
            severity=severity,
            source={'hostname': host, 'service': 'sendmail', 'pid': int(pid)},
            message=message,
            fields={
                'host': host,
                'pid': int(pid),
            },
            tags=['mail', 'sendmail', 'smtp']
        )


class EximParser(Parser):
    """Parser for Exim Log"""

    def __init__(self):
        super().__init__("Exim Log", LogType.EXIM)

    def detect(self, line: str) -> bool:
        return bool(re.search(r'^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\s+[A-Z0-9]{6,}\s+(<=|=>|\*\*)', line))

    def parse(self, line: str) -> LogEntry:
        match = re.search(
            r'^(\d{4}-\d{2}-\d{2})\s+(\d{2}:\d{2}:\d{2})\s+([A-Z0-9]+)\s+(<=|=>|\*\*)\s+(\S+)\s*(.*)',
            line
        )
        if not match:
            return LogEntry(line, log_type=self.log_type, severity=Severity.INFO, message=line)

        date, time, msg_id, direction, address, rest = match.groups()

        timestamp_parsed = None
        try:
            timestamp_parsed = datetime.strptime(f"{date} {time}", '%Y-%m-%d %H:%M:%S').isoformat()
        except:
            pass

        action = 'unknown'
        severity = Severity.INFO
        outcome = 'unknown'

        if direction == '<=':
            action = 'received'
            outcome = 'success'
        elif direction == '=>':
            action = 'delivered'
            outcome = 'success'
        elif direction == '**':
            action = 'bounced'
            severity = Severity.WARNING
            outcome = 'failure'

        return LogEntry(
            line,
            timestamp=timestamp_parsed,
            log_type=self.log_type,
            severity=severity,
            source={'service': 'exim'},
            action=action,
            outcome=outcome,
            message=f"{direction} {address} {rest}",
            fields={
                'date': date,
                'time': time,
                'message_id': msg_id,
                'direction': direction,
                'address': address,
            },
            tags=['mail', 'exim', 'smtp']
        )


class DovecotParser(Parser):
    """Parser for Dovecot Log"""

    def __init__(self):
        super().__init__("Dovecot Log", LogType.DOVECOT)

    def detect(self, line: str) -> bool:
        return bool(re.search(r'dovecot:\s+(imap|pop3|lmtp|auth)-login:', line))

    def parse(self, line: str) -> LogEntry:
        match = re.search(
            r'^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+dovecot:\s+(imap|pop3|lmtp|auth)-login:\s+(.*)',
            line
        )
        if not match:
            return LogEntry(line, log_type=self.log_type, severity=Severity.INFO, message=line)

        timestamp, host, service, message = match.groups()

        timestamp_parsed = None
        try:
            timestamp_parsed = datetime.strptime(timestamp, '%b %d %H:%M:%S').replace(year=datetime.now().year).isoformat()
        except:
            pass

        # Extract login info
        user_match = re.search(r'user=<([^>]*)>', message)
        lip_match = re.search(r'lip=(\d+\.\d+\.\d+\.\d+)', message)
        rip_match = re.search(r'rip=(\d+\.\d+\.\d+\.\d+)', message)

        outcome = 'unknown'
        severity = Severity.INFO
        if 'Login:' in message:
            outcome = 'success'
        elif re.search(r'failed|error', message):
            outcome = 'failure'
            severity = Severity.WARNING

        return LogEntry(
            line,
            timestamp=timestamp_parsed,
            log_type=self.log_type,
            severity=severity,
            source={'hostname': host, 'service': f'dovecot/{service}', 'ip': rip_match.group(1) if rip_match else None},
            user={'name': user_match.group(1) if user_match else None},
            action='login',
            outcome=outcome,
            message=message,
            fields={
                'host': host,
                'service': service,
                'user': user_match.group(1) if user_match else None,
                'local_ip': lip_match.group(1) if lip_match else None,
                'remote_ip': rip_match.group(1) if rip_match else None,
            },
            tags=['mail', 'dovecot', 'imap', 'pop3', 'auth']
        )


class ExchangeParser(Parser):
    """Parser for Microsoft Exchange Log"""

    def __init__(self):
        super().__init__("Microsoft Exchange Log", LogType.EXCHANGE)

    def detect(self, line: str) -> bool:
        return bool(re.search(r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z,SMTP(Receive|Send|Deliver),', line))

    def parse(self, line: str) -> LogEntry:
        match = re.search(
            r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z),(SMTP(?:Receive|Send|Deliver|Submit)),([^,]*),?(.*)',
            line
        )
        if not match:
            return LogEntry(line, log_type=self.log_type, severity=Severity.INFO, message=line)

        timestamp, source, action, rest = match.groups()

        return LogEntry(
            line,
            timestamp=timestamp,
            log_type=self.log_type,
            severity=Severity.INFO,
            source={'service': 'exchange'},
            action=source.lower(),
            message=f"{source}: {action} {rest}",
            fields={
                'timestamp': timestamp,
                'source': source,
                'action': action,
            },
            tags=['mail', 'exchange', 'microsoft', 'smtp']
        )


# Export all mail parsers
PARSERS = [
    PostfixParser(),
    SendmailParser(),
    EximParser(),
    DovecotParser(),
    ExchangeParser(),
]