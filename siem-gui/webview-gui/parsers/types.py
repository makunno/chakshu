"""Log Types and Data Models"""

from enum import Enum
from typing import TypedDict, List, Optional, Dict, Any
from dataclasses import dataclass, asdict
from datetime import datetime
import uuid

class LogType(str, Enum):
    """Supported log types"""
    # Database
    MYSQL_ERROR = "mysql_error"
    MYSQL_QUERY = "mysql_query"
    MYSQL_SLOW = "mysql_slow"
    POSTGRES_ERROR = "postgres_error"
    POSTGRES_AUTH = "postgres_auth"
    POSTGRES_STATEMENT = "postgres_statement"
    ORACLE_ALERT = "oracle_alert"
    ORACLE_LISTENER = "oracle_listener"
    ORACLE_AUDIT = "oracle_audit"
    SQLSERVER_ERROR = "sqlserver_error"
    SQLSERVER_AUDIT = "sqlserver_audit"
    SQLSERVER_TRANSACTION = "sqlserver_transaction"
    MONGODB_SERVER = "mongodb_server"
    MONGODB_AUDIT = "mongodb_audit"

    # Webserver
    APACHE = "apache"
    NGINX = "nginx"
    IIS = "iis"
    DJANGO = "django"
    FLASK = "flask"
    LARAVEL = "laravel"
    RAILS = "rails"
    EXPRESS = "express"
    FASTAPI = "fastapi"
    GUNICORN = "gunicorn"
    UVICORN = "uvicorn"

    # System
    SYSLOG = "syslog"
    SYSTEMD = "systemd"
    KERNEL = "kernel"
    AUDIT = "audit"
    PACKAGE = "package"
    CRON = "cron"
    DAEMON = "daemon"

    # Auth
    SSH_AUTH = "ssh_auth"
    PAM = "pam"
    VSFTPD = "vsftpd"
    PROFTPD = "proftpd"

    # Firewall
    IPTABLES = "iptables"
    UFW = "ufw"
    NFTABLES = "nftables"
    FIREWALLD = "firewalld"
    WINDOWS_FIREWALL = "windows_firewall"
    PALO_ALTO = "palo_alto"
    FORTIGATE = "fortigate"
    CISCO_ASA = "cisco_asa"
    CHECKPOINT = "checkpoint"
    AWS_VPC_FLOW = "aws_vpc_flow"
    AZURE_NSG = "azure_nsg"
    GCP_VPC = "gcp_vpc"

    # Mail
    POSTFIX = "postfix"
    SENDMAIL = "sendmail"
    EXIM = "exim"
    DOVECOT = "dovecot"
    EXCHANGE = "exchange"

    # Unknown/Raw
    RAW = "raw"
    UNKNOWN = "unknown"


class Severity(str, Enum):
    """Severity levels"""
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    UNKNOWN = "unknown"


@dataclass
class LogEntry:
    """Parsed log entry"""
    id: str
    timestamp: Optional[str]
    log_type: LogType
    severity: Severity
    source: Dict[str, Any]
    user: Optional[Dict[str, str]]
    action: Optional[str]
    outcome: Optional[str]
    message: str
    raw_line: str
    fields: Dict[str, Any]
    tags: List[str]

    def __init__(self, raw_line: str, **kwargs):
        self.id = kwargs.get('id', str(uuid.uuid4()))
        self.timestamp = kwargs.get('timestamp')
        self.log_type = kwargs.get('log_type', LogType.UNKNOWN)
        self.severity = kwargs.get('severity', Severity.UNKNOWN)
        self.source = kwargs.get('source', {})
        self.user = kwargs.get('user')
        self.action = kwargs.get('action')
        self.outcome = kwargs.get('outcome')
        self.message = kwargs.get('message', raw_line)
        self.raw_line = raw_line
        self.fields = kwargs.get('fields', {})
        self.tags = kwargs.get('tags', [])

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            'id': self.id,
            'timestamp': self.timestamp,
            'logType': self.log_type.value if isinstance(self.log_type, LogType) else str(self.log_type),
            'severity': self.severity.value if isinstance(self.severity, Severity) else str(self.severity),
            'source': self.source,
            'user': self.user,
            'action': self.action,
            'outcome': self.outcome,
            'message': self.message,
            'rawLine': self.raw_line,
            'fields': self.fields,
            'tags': self.tags
        }


@dataclass
class Alert:
    """Security alert"""
    id: str
    type: str
    severity: str
    confidence: str
    title: str
    description: str
    timestamp: str
    source_ips: List[str]
    target_users: List[str]
    related_events: List[str]
    metadata: Dict[str, Any]


@dataclass
class AttackChain:
    """Attack chain detected by ML correlation"""
    id: str
    attack_type: str
    stage: str
    events: List[Dict[str, Any]]
    source_ips: List[str]
    target_users: List[str]
    start_time: str
    end_time: str
    prediction: Dict[str, Any]
    mitre_tactics: List[str]
    mitre_techniques: List[str]
    recommendation: str


@dataclass
class TimelineEvent:
    """Timeline event for visualization"""
    id: str
    timestamp: str
    count: int
    is_anomaly: bool
    severity: str
    log_source: str
    title: str
    description: str
    source_ip: Optional[str]
    anomaly_score: Optional[float]
    correlation_score: Optional[float]


@dataclass
class CorrelationResult:
    """Result of ML correlation analysis"""
    attack_chains: List[AttackChain]
    timeline: List[TimelineEvent]
    summary: Dict[str, Any]
    total_events: int
    recommendations: List[str]


@dataclass
class ParseResponse:
    """Response from log parsing"""
    success: bool
    detected_type: str
    total_lines: int
    parsed_lines: int
    failed_lines: int
    entries: List[LogEntry]
    alerts: List[Alert]
    stats: Dict[str, Any]


@dataclass
class CorrelateResponse:
    """Response from correlation analysis"""
    success: bool
    sources: List[Dict[str, Any]]
    correlation: CorrelationResult
    traditional_alerts: List[Alert]
    stats: Dict[str, Any]
