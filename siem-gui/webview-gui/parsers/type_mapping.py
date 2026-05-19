"""
Type Mapping - Maps ISEA-style type names to Cyber Chakshu LogType enum
"""

from enum import Enum


class LogType(Enum):
    # Web Server
    APACHE = 'apache'
    NGINX = 'nginx'
    IIS = 'iis'
    DJANGO = 'django'
    FLASK = 'flask'
    LARAVEL = 'laravel'
    RAILS = 'rails'
    EXPRESS = 'express'
    GUNICORN = 'gunicorn'
    UVICORN = 'uvicorn'
    PHP = 'php'
    CADDY = 'apache'
    HAPROXY = 'apache'
    SPRING_BOOT = 'java'
    ASP_NET_CORE = 'iis'
    
    # SSH/Auth
    SSH_AUTH = 'ssh_auth'
    
    # Mail
    POSTFIX = 'postfix'
    SENDMAIL = 'sendmail'
    EXIM = 'exim'
    DOVECOT = 'dovecot'
    COURIER = 'dovecot'
    EXCHANGE = 'exchange'
    SMTP = 'smtp'
    
    # Firewall
    WINDOWS_FIREWALL = 'windows_firewall'
    IPTABLES = 'iptables'
    UFW = 'ufw'
    NFTABLES = 'nftables'
    FIREWALLD = 'firewalld'
    PALO_ALTO = 'palo_alto'
    FORTIGATE = 'fortigate'
    CISCO_ASA = 'cisco_asa'
    CHECKPOINT = 'checkpoint'
    AWS_VPC_FLOW = 'aws_vpc_flow'
    AZURE_NSG = 'azure_nsg'
    GCP_VPC = 'gcp_vpc'
    
    # Database
    MYSQL_ERROR = 'mysql_error'
    MYSQL_QUERY = 'mysql_query'
    MYSQL_SLOW = 'mysql_slow'
    POSTGRES_ERROR = 'postgres_error'
    POSTGRES_AUTH = 'postgres_auth'
    POSTGRES_STATEMENT = 'postgres_statement'
    ORACLE_ALERT = 'oracle_alert'
    ORACLE_LISTENER = 'oracle_listener'
    ORACLE_AUDIT = 'oracle_audit'
    SQLSERVER_ERROR = 'sqlserver_error'
    SQLSERVER_AUDIT = 'sqlserver_audit'
    SQLSERVER_TRANSACTION = 'sqlserver_transaction'
    MONGODB_SERVER = 'mongodb_server'
    MONGODB_AUDIT = 'mongodb_audit'
    
    # System
    SYSLOG = 'syslog'
    SYSTEMD = 'systemd'
    KERNEL = 'kernel'
    AUDIT = 'audit'
    PACKAGE = 'package'
    WINDOWS_SYSTEM = 'windows_system'
    
    # FTP
    VSFTPD = 'vsftpd'
    PROFTPD = 'proftpd'
    
    # Unknown/Raw
    UNKNOWN = 'raw'


TYPE_MAPPING = {
    # Web Server
    'Apache': LogType.APACHE,
    'NGINX': LogType.NGINX,
    'IIS': LogType.IIS,
    'Django': LogType.DJANGO,
    'Flask': LogType.FLASK,
    'Laravel': LogType.LARAVEL,
    'Ruby on Rails': LogType.RAILS,
    'Node.js': LogType.EXPRESS,
    'Express.js': LogType.EXPRESS,
    'Gunicorn': LogType.GUNICORN,
    'Uvicorn': LogType.UVICORN,
    'PHP-FPM': LogType.PHP,
    'Caddy': LogType.APACHE,
    'HAProxy': LogType.APACHE,
    'Spring Boot': LogType.SPRING_BOOT,
    'ASP.NET Core': LogType.ASP_NET_CORE,
    
    # SSH/Auth
    'Linux SSHD Failed': LogType.SSH_AUTH,
    'Linux SSHD Accepted': LogType.SSH_AUTH,
    
    # Mail
    'Postfix': LogType.POSTFIX,
    'Sendmail': LogType.SENDMAIL,
    'Exim': LogType.EXIM,
    'Dovecot': LogType.DOVECOT,
    'Courier': LogType.COURIER,
    'Microsoft Exchange': LogType.EXCHANGE,
    'SMTP Server': LogType.SMTP,
    
    # Firewall
    'Windows Firewall': LogType.WINDOWS_FIREWALL,
    'iptables': LogType.IPTABLES,
    'UFW': LogType.UFW,
    'nftables': LogType.NFTABLES,
    'firewalld': LogType.FIREWALLD,
    'macOS PF': LogType.IPTABLES,
    'macOS App Firewall': LogType.WINDOWS_FIREWALL,
    'Palo Alto Firewall': LogType.PALO_ALTO,
    'FortiGate': LogType.FORTIGATE,
    'Cisco ASA': LogType.CISCO_ASA,
    'Check Point Firewall': LogType.CHECKPOINT,
    'AWS VPC Flow Logs': LogType.AWS_VPC_FLOW,
    'Azure NSG Flow Logs': LogType.AZURE_NSG,
    'GCP VPC Firewall': LogType.GCP_VPC,
    
    # Database
    'MySQL Error': LogType.MYSQL_ERROR,
    'MySQL Query': LogType.MYSQL_QUERY,
    'MySQL Slow Query': LogType.MYSQL_SLOW,
    'PostgreSQL Error': LogType.POSTGRES_ERROR,
    'PostgreSQL Auth': LogType.POSTGRES_AUTH,
    'PostgreSQL Statement': LogType.POSTGRES_STATEMENT,
    'Oracle Alert': LogType.ORACLE_ALERT,
    'Oracle Listener': LogType.ORACLE_LISTENER,
    'Oracle Audit': LogType.ORACLE_AUDIT,
    'SQL Server Error': LogType.SQLSERVER_ERROR,
    'SQL Server Audit': LogType.SQLSERVER_AUDIT,
    'SQL Server Transaction': LogType.SQLSERVER_TRANSACTION,
    'MongoDB Server': LogType.MONGODB_SERVER,
    'MongoDB Audit': LogType.MONGODB_AUDIT,
    
    # System
    'Linux Syslog': LogType.SYSLOG,
    'Linux Systemd': LogType.SYSTEMD,
    'Linux Kernel': LogType.KERNEL,
    'Linux Audit': LogType.AUDIT,
    'Linux Package': LogType.PACKAGE,
    'Windows Text': LogType.WINDOWS_SYSTEM,
    
    # FTP
    'FileZilla FTP': LogType.VSFTPD,
    'IIS FTP': LogType.PROFTPD,
    'xferlog': LogType.VSFTPD,
    
    # Application
    'Application Logs JSON': LogType.UNKNOWN,
    
    # Unknown/Raw
    'Custom / Raw': LogType.UNKNOWN,
}


REVERSE_TYPE_MAPPING = {v.value: k for k, v in TYPE_MAPPING.items()}
