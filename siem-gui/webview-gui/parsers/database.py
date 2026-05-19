"""Database Log Parsers - MySQL, PostgreSQL, Oracle, SQL Server, MongoDB"""

import re
from datetime import datetime
from ..base import Parser
from ..types import LogType, LogEntry, Severity


class MySQLErrorParser(Parser):
    """Parser for MySQL Error Log"""

    def __init__(self):
        super().__init__("MySQL Error Log", LogType.MYSQL_ERROR)

    def detect(self, line: str) -> bool:
        return bool(re.search(r'\d{4}-\d{2}-\d{2}T[\d:.]+Z\s+\d+\s+\[(?:ERROR|Warning|Note)\]\s+\[MY-\d+\]', line))

    def parse(self, line: str) -> LogEntry:
        match = re.search(r'(\S+Z)\s+(\d+)\s+\[(ERROR|Warning|Note)\]\s+\[MY-(\d+)\]\s+\[(\w+)\]\s+(.*)', line)
        if not match:
            return LogEntry(line, log_type=self.log_type, severity=Severity.INFO, message=line)

        timestamp, thread_id, level, error_code, component, message = match.groups()

        timestamp_parsed = None
        try:
            timestamp_parsed = datetime.fromisoformat(timestamp.replace('Z', '+00:00')).isoformat()
        except:
            pass

        return LogEntry(
            line,
            timestamp=timestamp_parsed,
            log_type=self.log_type,
            severity=self._parse_severity(level),
            source={'service': 'mysql', 'pid': int(thread_id)},
            message=message,
            fields={
                'thread_id': int(thread_id),
                'error_code': error_code,
                'component': component,
                'error_level': level,
            },
            tags=['database', 'mysql']
        )

    def _parse_severity(self, level: str) -> Severity:
        level_lower = level.lower()
        if level_lower == 'error':
            return Severity.ERROR
        elif level_lower == 'warning':
            return Severity.WARNING
        elif level_lower == 'note':
            return Severity.INFO
        return Severity.INFO


class MySQLSlowParser(Parser):
    """Parser for MySQL Slow Query Log"""

    def __init__(self):
        super().__init__("MySQL Slow Query Log", LogType.MYSQL_SLOW)

    def detect(self, line: str) -> bool:
        return bool(re.search(r'^#\s+Time:\s+\S+Z', line) or re.search(r'^#\s+User@Host:', line) or re.search(r'^#\s+Query_time:', line))

    def parse(self, line: str) -> LogEntry:
        if line.startswith('# Time:'):
            match = re.search(r'# Time:\s+(\S+Z)', line)
            if match:
                timestamp = match.group(1)
                timestamp_parsed = None
                try:
                    timestamp_parsed = datetime.fromisoformat(timestamp.replace('Z', '+00:00')).isoformat()
                except:
                    pass
                return LogEntry(
                    line,
                    timestamp=timestamp_parsed,
                    log_type=self.log_type,
                    severity=Severity.WARNING,
                    source={'service': 'mysql'},
                    message='Slow query detected',
                    fields={},
                    tags=['database', 'mysql', 'slow_query', 'performance']
                )

        if line.startswith('# User@Host:'):
            match = re.search(r'# User@Host:\s+(\w+)\[(\w+)\]\s+@\s+(\S+)\s+\[\]\s+Id:\s+(\d+)', line)
            if match:
                return LogEntry(
                    line,
                    timestamp=None,
                    log_type=self.log_type,
                    severity=Severity.INFO,
                    source={'service': 'mysql', 'pid': int(match.group(4))},
                    message=f"User {match.group(2)} executed slow query",
                    fields={
                        'user': match.group(1),
                        'account': match.group(2),
                        'host': match.group(3),
                        'thread_id': int(match.group(4)),
                    },
                    tags=['database', 'mysql', 'slow_query']
                )

        if line.startswith('# Query_time:'):
            match = re.search(r'# Query_time:\s+([\d.]+)\s+Lock_time:\s+([\d.]+)\s+Rows_sent:\s+(\d+)\s+Rows_examined:\s+(\d+)', line)
            if match:
                return LogEntry(
                    line,
                    timestamp=None,
                    log_type=self.log_type,
                    severity=Severity.WARNING,
                    source={'service': 'mysql'},
                    message=f"Slow query: {match.group(1)}s duration",
                    fields={
                        'query_time': float(match.group(1)),
                        'lock_time': float(match.group(2)),
                        'rows_sent': int(match.group(3)),
                        'rows_examined': int(match.group(4)),
                    },
                    tags=['database', 'mysql', 'slow_query', 'performance']
                )

        if not line.startswith('#') and line.strip():
            return LogEntry(
                line,
                timestamp=None,
                log_type=self.log_type,
                severity=Severity.WARNING,
                source={'service': 'mysql'},
                message=line,
                fields={'sql_statement': line},
                tags=['database', 'mysql', 'slow_query', 'performance']
            )

        return LogEntry(line, log_type=self.log_type, severity=Severity.INFO, message=line)


class PostgresErrorParser(Parser):
    """Parser for PostgreSQL Error Log"""

    def __init__(self):
        super().__init__("PostgreSQL Error Log", LogType.POSTGRES_ERROR)

    def detect(self, line: str) -> bool:
        return bool(re.search(r'^\d{4}-\d{2}-\d{2}T[\d:.]+Z\s+\[\d+\]\s+\S+\s+\S+\s+(?:LOG|ERROR|FATAL|DETAIL):', line))

    def parse(self, line: str) -> LogEntry:
        match = re.search(
            r'^(\d{4}-\d{2}-\d{2}T[\d:.]+Z)\s+\[(\d+)\]\s+(\S+)\s+(\S+)\s+(LOG|ERROR|FATAL|DETAIL):\s+(.*)$',
            line
        )
        if not match:
            return LogEntry(line, log_type=self.log_type, severity=Severity.INFO, message=line)

        timestamp, pid, host, db, level, message = match.groups()

        timestamp_parsed = None
        try:
            timestamp_parsed = datetime.fromisoformat(timestamp.replace('Z', '+00:00')).isoformat()
        except:
            pass

        normalized_level = level if level not in ['DETAIL'] else 'ERROR'

        return LogEntry(
            line,
            timestamp=timestamp_parsed,
            log_type=self.log_type,
            severity=self._parse_severity(normalized_level),
            source={'service': 'postgresql', 'pid': int(pid), 'host': host, 'database': db},
            message=message,
            fields={
                'pid': int(pid),
                'host': host,
                'database': db,
                'level': level,
            },
            tags=['database', 'postgresql']
        )

    def _parse_severity(self, level: str) -> Severity:
        if level.upper() in ['ERROR', 'FATAL', 'DETAIL']:
            return Severity.ERROR
        elif level.upper() == 'WARNING':
            return Severity.WARNING
        return Severity.INFO


class OracleAlertParser(Parser):
    """Parser for Oracle Alert Log"""

    def __init__(self):
        super().__init__("Oracle Alert Log", LogType.ORACLE_ALERT)

    def detect(self, line: str) -> bool:
        return bool(re.search(r'^ORA-\d+:', line) or re.search(r'^[A-Z][a-z]{2}\s+[A-Z][a-z]{2}\s+\d{2}\s+\d{2}:\d{2}:\d{2}\s+\d{4}', line))

    def parse(self, line: str) -> LogEntry:
        ora_match = re.search(r'^ORA-(\d+):\s+(.*)$', line)
        if ora_match:
            return LogEntry(
                line,
                timestamp=None,
                log_type=self.log_type,
                severity=Severity.ERROR,
                source={'service': 'oracle'},
                message=ora_match.group(2),
                fields={'error_code': ora_match.group(1), 'error_message': ora_match.group(2)},
                tags=['database', 'oracle', 'alert']
            )

        date_match = re.search(r'^([A-Z][a-z]{2}\s+[A-Z][a-z]{2}\s+\d{2}\s+\d{2}:\d{2}:\d{2}\s+\d{4})', line)
        if date_match:
            return LogEntry(
                line,
                timestamp=None,
                log_type=self.log_type,
                severity=Severity.INFO,
                source={'service': 'oracle'},
                message=line,
                fields={'raw_message': line},
                tags=['database', 'oracle', 'alert']
            )

        return LogEntry(line, log_type=self.log_type, severity=Severity.INFO, message=line)


class OracleListenerParser(Parser):
    """Parser for Oracle Listener Log"""

    def __init__(self):
        super().__init__("Oracle Listener Log", LogType.ORACLE_LISTENER)

    def detect(self, line: str) -> bool:
        return bool(re.search(r'^\d{4}-\d{2}-\d{2}T[\d:.]+Z\s+\*\s+\S+\s+\*\s+\S+\s+\*\s+\d+', line))

    def parse(self, line: str) -> LogEntry:
        match = re.search(r'^(\d{4}-\d{2}-\d{2}T[\d:.]+Z)\s+\*\s+(\S+)\s+\*\s+(\S+)\s+\*\s+(\d+)', line)
        if not match:
            return LogEntry(line, log_type=self.log_type, severity=Severity.INFO, message=line)

        timestamp, action, service, status = match.groups()
        host_match = re.search(r'HOST=(\d+\.\d+\.\d+\.\d+)', line)
        port_match = re.search(r'PORT=(\d+)', line)

        severity = Severity.INFO
        if action == 'error':
            severity = Severity.ERROR

        return LogEntry(
            line,
            timestamp=timestamp,
            log_type=self.log_type,
            severity=severity,
            source={'service': 'oracle_listener', 'ip': host_match.group(1) if host_match else None, 'port': int(port_match.group(1)) if port_match else None},
            message=f"{action} for {service}",
            fields={
                'action': action,
                'service_name': service,
                'status': int(status),
                'host': host_match.group(1) if host_match else None,
                'port': port_match.group(1) if port_match else None,
            },
            tags=['database', 'oracle', 'listener', 'network']
        )


class OracleAuditParser(Parser):
    """Parser for Oracle Audit Log"""

    def __init__(self):
        super().__init__("Oracle Audit Log", LogType.ORACLE_AUDIT)

    def detect(self, line: str) -> bool:
        return line.startswith('Audit trail:')

    def parse(self, line: str) -> LogEntry:
        match = re.search(r"ACTION:\s*'(\w+)'.*DATABASE USER:\s*'(\w+)'.*CLIENT USER:\s*'(\w+)'.*STATUS:\s*(\d+).*TIMESTAMP:\s*(\S+)", line)
        if not match:
            return LogEntry(line, log_type=self.log_type, severity=Severity.INFO, message=line)

        action, db_user, client_user, status, timestamp = match.groups()
        severity = Severity.INFO if status == '0' else Severity.ERROR

        timestamp_parsed = None
        try:
            timestamp_parsed = datetime.fromisoformat(timestamp.replace('Z', '+00:00')).isoformat()
        except:
            pass

        return LogEntry(
            line,
            timestamp=timestamp_parsed,
            log_type=self.log_type,
            severity=severity,
            source={'service': 'oracle'},
            user={'name': db_user},
            action=action,
            outcome='success' if status == '0' else 'failed',
            message=f"{action} by {db_user}",
            fields={
                'action': action,
                'db_user': db_user,
                'client_user': client_user,
                'status': int(status),
            },
            tags=['database', 'oracle', 'audit']
        )


class SQLServerErrorParser(Parser):
    """Parser for SQL Server Error Log"""

    def __init__(self):
        super().__init__("SQL Server Error Log", LogType.SQLSERVER_ERROR)

    def detect(self, line: str) -> bool:
        return bool(re.search(r'^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d+\s+\S+\s+\S+', line) or re.search(r'Error:\s*\d+,', line))

    def parse(self, line: str) -> LogEntry:
        error_match = re.search(r'Error:\s*(\d+),\s*Severity:\s*(\d+),\s*State:\s*(\d+)', line)
        if error_match:
            client_match = re.search(r'\[CLIENT:\s*([^\]]+)\]', line)
            reason_match = re.search(r'Reason:\s*(.+?)(?:\s*\[CLIENT|$)', line)
            severity_num = int(error_match.group(2))

            if severity_num >= 20:
                sev_level = Severity.CRITICAL
            elif severity_num >= 16:
                sev_level = Severity.ERROR
            elif severity_num >= 11:
                sev_level = Severity.WARNING
            else:
                sev_level = Severity.INFO

            ts_match = re.search(r'^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})', line)
            timestamp_parsed = None
            if ts_match:
                try:
                    timestamp_parsed = datetime.strptime(ts_match.group(1), '%Y-%m-%d %H:%M:%S').isoformat()
                except:
                    pass

            return LogEntry(
                line,
                timestamp=timestamp_parsed,
                log_type=self.log_type,
                severity=sev_level,
                source={'service': 'sqlserver'},
                message=f"Error {error_match.group(1)}: {reason_match.group(1) if reason_match else ''}",
                fields={
                    'error_code': int(error_match.group(1)),
                    'severity': severity_num,
                    'state': int(error_match.group(3)),
                    'client': client_match.group(1) if client_match else None,
                    'reason': reason_match.group(1) if reason_match else None,
                },
                tags=['database', 'sqlserver', 'error']
            )

        match = re.search(r'^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d+)\s+(\S+)\s+(\S+)\s+(.*)', line)
        if match:
            timestamp_parsed = None
            try:
                timestamp_parsed = datetime.strptime(match.group(1), '%Y-%m-%d %H:%M:%S.%f').isoformat()
            except:
                pass

            return LogEntry(
                line,
                timestamp=timestamp_parsed,
                log_type=self.log_type,
                severity=Severity.INFO,
                source={'service': 'sqlserver'},
                message=match.group(4),
                fields={'component': match.group(2), 'spid': match.group(3), 'message': match.group(4)},
                tags=['database', 'sqlserver']
            )

        return LogEntry(line, log_type=self.log_type, severity=Severity.INFO, message=line)


class SQLServerAuditParser(Parser):
    """Parser for SQL Server Audit Log"""

    def __init__(self):
        super().__init__("SQL Server Audit Log", LogType.SQLSERVER_AUDIT)

    def detect(self, line: str) -> bool:
        return bool(re.search(r'^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d+\|[\w]+\|[\w-]+\|[\w-]+\|[\w]+\|[\d.]+\|\d+$', line))

    def parse(self, line: str) -> LogEntry:
        parts = line.split('|')
        if len(parts) < 7:
            return LogEntry(line, log_type=self.log_type, severity=Severity.INFO, message=line)

        timestamp, action, database, user, outcome, ip, duration = parts

        timestamp_parsed = None
        try:
            timestamp_parsed = datetime.strptime(timestamp, '%Y-%m-%d %H:%M:%S.%f').isoformat()
        except:
            pass

        severity = Severity.INFO if outcome == 'SUCCEEDED' else Severity.ERROR

        return LogEntry(
            line,
            timestamp=timestamp_parsed,
            log_type=self.log_type,
            severity=severity,
            source={'service': 'sqlserver', 'ip': ip},
            user={'name': user},
            action=action,
            outcome=outcome.lower(),
            message=f"{action} on {database} by {user}",
            fields={
                'action': action,
                'database': database,
                'user': user,
                'outcome': outcome,
                'ip': ip,
                'duration_ms': int(duration),
            },
            tags=['database', 'sqlserver', 'audit']
        )


class MongoDBServerParser(Parser):
    """Parser for MongoDB Server Log"""

    def __init__(self):
        super().__init__("MongoDB Server Log", LogType.MONGODB_SERVER)

    def detect(self, line: str) -> bool:
        return bool(re.search(r'^\d{4}-\d{2}-\d{2}T[\d:.]+Z\s+[IWDEC]\s+\S+\s+\[.*\]\s+.*', line))

    def parse(self, line: str) -> LogEntry:
        match = re.search(r'^(\d{4}-\d{2}-\d{2}T[\d:.]+Z)\s+([IWDEC])\s+(\S+)\s+\[(\w+)\]\s+(.*)', line)
        if not match:
            return LogEntry(line, log_type=self.log_type, severity=Severity.INFO, message=line)

        timestamp, severity, component, context, message = match.groups()
        conn_match = re.search(r'\[conn(\d+)\]', message)
        ip_match = re.search(r'from\s+(\d+\.\d+\.\d+\.\d+):\d+', message)

        timestamp_parsed = None
        try:
            timestamp_parsed = datetime.fromisoformat(timestamp.replace('Z', '+00:00')).isoformat()
        except:
            pass

        return LogEntry(
            line,
            timestamp=timestamp_parsed,
            log_type=self.log_type,
            severity=self._parse_severity(severity),
            source={'service': 'mongodb', 'ip': ip_match.group(1) if ip_match else None, 'port': None},
            message=message,
            fields={
                'component': component,
                'context': context,
                'connection_id': int(conn_match.group(1)) if conn_match else None,
                'ip': ip_match.group(1) if ip_match else None,
            },
            tags=['database', 'mongodb']
        )

    def _parse_severity(self, level: str) -> Severity:
        level_map = {
            'F': Severity.CRITICAL,
            'E': Severity.ERROR,
            'W': Severity.WARNING,
            'I': Severity.INFO,
            'D': Severity.DEBUG,
            'C': Severity.CRITICAL,
        }
        return level_map.get(level.upper(), Severity.INFO)


PARSERS = [
    MySQLErrorParser(),
    MySQLSlowParser(),
    PostgresErrorParser(),
    OracleAlertParser(),
    OracleListenerParser(),
    OracleAuditParser(),
    SQLServerErrorParser(),
    SQLServerAuditParser(),
    MongoDBServerParser(),
]
