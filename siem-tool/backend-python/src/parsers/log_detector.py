"""
LogDetector - ISEA-style log detection with precompiled regex patterns
Migrated from siem-gui/webview-gui/parsers/log_detector.py
"""

import re
import json
from typing import List, Tuple, Callable, Optional


class LogDetector:
    SAMPLE_LINES = 50

    EXPRESS_JSON_RE = re.compile(r'^\{')
    APACHE_RE = re.compile(r'\S+ - - \[.*?\] ".*?" \d+ \S+')
    LARAVEL_RE = re.compile(r'\[\d{4}-\d{2}-\d{2} .*?\] \w+\.\w+:')
    NODE_RE = re.compile(r'\w+ /\S+ \d+ \d+ms')
    DJANGO_RE = re.compile(r'\[.*?\] "\w+ /\S+" \d+')
    FLASK_RE = re.compile(r'\[[\d/\-]+ [\d:]+\] "\w+ \S+ \S+" \d+|\* (Running on|Restarting)|http://\d+\.\d+\.\d+\.\d+|^((GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+/\S+\s+\d{3}$)')
    GUNICORN_RE = re.compile(r'\[\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}.*\] \[\d+\] \[(INFO|ERROR|WARNING)\]')
    UVICORN_RE = re.compile(r'INFO:\s+.* - "\w+ .* HTTP/\d\.\d" \d{3}')
    PHP_FPM_RE = re.compile(r'\] (NOTICE|WARNING|ERROR):')
    NGINX_RE = re.compile(r'\S+ - \S+ \[.*?\] ".*?" \d+ \d+')
    CADDY_RE = re.compile(r'^(?:\d{1,3}\.){3}\d{1,3}\s+-\s+-\s+\[INFO\]\s+http\.log:\s+handled\s+(GET|POST|PUT|DELETE)\s+\S+\s+\d{3}$')
    HAPROXY_RE = re.compile(r'^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+haproxy\[\d+\]:\s+(GET|POST|PUT|DELETE)\s+\S+\s+\d{3}$')
    SPRING_BOOT_RE = re.compile(r'^\d{4}-\d{2}-\d{2} .* (INFO|WARN|ERROR|DEBUG) .*$')
    IIS_RE = re.compile(r'^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\s+\d{1,3}(?:\.\d{1,3}){3}\s+(GET|POST|PUT|DELETE)\s+/\S*\s+.*\s+\d{3}\s*')
    ASPNET_CORE_RE = re.compile(r'microsoft\.aspnetcore', re.IGNORECASE)

    POSTFIX_RE = re.compile(r'^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\S+\s+(postfix\/(smtpd|smtp|cleanup|qmgr|pipe|submission\/smtpd|10025\/smtpd|anvil|postscreen|bounce|dnsblog|amavis\/smtp)|amavis|opendkim|roundcube)\[?\d*\]?:\s+.+$')
    SENDMAIL_RE = re.compile(r'^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\S+\s+sendmail\[\d+\]:\s+.+$')
    EXIM_RE = re.compile(r'^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\s+[A-Z0-9]{6,}\s+(<=|=>|\*\*)\s+\S+.*$')
    DOVECOT_RE = re.compile(r'^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\S+\s+dovecot:\s+(imap|pop3)-login:\s+.+$')
    COURIER_RE = re.compile(r'^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\s+\S+\s+courier(imap|pop3):\s+.+$')
    EXCHANGE_RE = re.compile(r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z,SMTP(Receive|Send|Deliver),.+$')
    AMAVIS_RE = re.compile(r'^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\S+\s+amavis\[\d+\]:\s+.+$')
    SPAMASSASSIN_RE = re.compile(r'^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\S+\s+spamd\[\d+\]:\s+.+$')
    MAILSCANNER_RE = re.compile(r'^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\S+\s+MailScanner\[\d+\]:\s+.+$')
    SMTP_GENERIC_RE = re.compile(r'^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\s+SMTP\s+(connect|disconnect|from=|to=).+$')

    WINDOWS_FW_RE = re.compile(r'^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\s+(ALLOW|DROP|BLOCK)\s+(TCP|UDP|ICMP)\s+(?:\d{1,3}\.){3}\d{1,3}\s+(?:\d{1,3}\.){3}\d{1,3}\s+\d+\s+\d+.*$')
    IPTABLES_RE = re.compile(r'^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\S+\s+kernel:\s*(?:\[[\d.]+\])?\s*IPTABLES-(DROP|ACCEPT):\s+IN=\S*\s+OUT=\S*\s+.*SRC=(?:\d{1,3}\.){3}\d{1,3}\s+DST=(?:\d{1,3}\.){3}\d{1,3}.*PROTO=(TCP|UDP|ICMP).*$', re.IGNORECASE)
    UFW_RE = re.compile(r'^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\S+\s+kernel:\s*\[\d+\.\d+\]\s*\[UFW (ALLOW|BLOCK)\]\s+IN=\S*\s+OUT=\S*\s+SRC=(?:\d{1,3}\.){3}\d{1,3}\s+DST=(?:\d{1,3}\.){3}\d{1,3}', re.IGNORECASE)
    NFTABLES_RE = re.compile(r'^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\S+\s+kernel:\s+nftables:\s+rule\s+(accept|drop|reject)\s+.*(tcp|udp|icmp).*$')
    FIREWALLD_RE = re.compile(r'^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\S+\s+firewalld:\s+(INFO|WARNING|ERROR):\s+.*$')
    MACOS_PF_RE = re.compile(r'^\d{2}:\d{2}:\d{2}\.\d+\s+rule\s+\d+\/\d+\(match\):\s+(block|pass)\s+(in|out)\s+on\s+\S+:\s+(?:\d{1,3}\.){3}\d{1,3}\.\d+\s+>\s+(?:\d{1,3}\.){3}\d{1,3}\.\d+.*$')
    MACOS_APP_FW_RE = re.compile(r'^Firewall:\s+(Blocked|Allowed)\s+(incoming|outgoing)\s+connection from\s+(?:\d{1,3}\.){3}\d{1,3}\s+to\s+app\s+\S+.*$')
    PALO_ALTO_RE = re.compile(r'^\d{4}\/\d{2}\/\d{2}\s+\d{2}:\d{2}:\d{2}\s+(allow|deny|drop)\s+(tcp|udp|icmp)\s+(?:\d{1,3}\.){3}\d{1,3}\s+(?:\d{1,3}\.){3}\d{1,3}\s+rule=\S+.*$')
    FORTIGATE_RE = re.compile(r'^date=\d{4}-\d{2}-\d{2}\s+time=\d{2}:\d{2}:\d{2}\s+action=(allow|deny)\s+srcip=(?:\d{1,3}\.){3}\d{1,3}\s+dstip=(?:\d{1,3}\.){3}\d{1,3}.*$')
    CISCO_ASA_RE = re.compile(r'^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\S+\s+%ASA-\d-\d+:\s+access-list\s+\S+\s+(denied|permitted)\s+(tcp|udp|icmp)\s+\S+\/(?:\d{1,3}\.){3}\d{1,3}\s+to\s+\S+\/(?:\d{1,3}\.){3}\d{1,3}.*$')
    CHECKPOINT_RE = re.compile(r'^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\s+(accept|drop|reject)\s+(TCP|UDP|ICMP)\s+src=(?:\d{1,3}\.){3}\d{1,3}\s+dst=(?:\d{1,3}\.){3}\d{1,3}\s+rule=\S+.*$')
    AWS_VPC_RE = re.compile(r'^(\d+)\s+(\d+)\s+(eni-\S+)\s+(?:(?:\d{1,3}\.){3}\d{1,3})\s+(?:(?:\d{1,3}\.){3}\d{1,3})\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(ACCEPT|REJECT)\s+(\S+)$')
    AZURE_NSG_RE = re.compile(r'^\{(?=.*"time"\s*:\s*"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z")(?=.*"properties"\s*:\s*\{)(?=.*"flows"\s*:\s*\[)(?=.*"flowTuples"\s*:\s*\[).*\}$', re.DOTALL)
    GCP_VPC_RE = re.compile(r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\s+(allow|deny)\s+(tcp|udp|icmp)\s+(?:\d{1,3}\.){3}\d{1,3}:\d+\s+(?:\d{1,3}\.){3}\d{1,3}:\d+.*$')
    DISK_TRAFFIC_RE = re.compile(r'type="traffic"')
    APPLICATION_JSON_RE = re.compile(r'^\[\[.*\]\]$')

    APACHE_ERROR_RES = [
        re.compile(r'^\[.*?\] \[.*?:.*?\] \[pid \d+:tid \d+\] .*'),
        re.compile(r'^\[.*?\] \[.*?:.*?\] \[pid \d+\] .*'),
        re.compile(r'^\[.*?\] \[.*?:.*?\] \[pid \d+:tid \d+\] \[client .*?\] .*'),
    ]

    MYSQL_ERROR_RE = re.compile(r'(\d{4}-\d{2}-\d{2}T[\d:.]+Z?)\s+(\d+)\s+\[(ERROR|Warning|Note)\]\s+\[MY-(\d+)\]\s+\[(\w+)\]\s+(.*)')
    MYSQL_QUERY_RE = re.compile(r'^\d{4}-\d{2}-\d{2}T[\d:.]+Z?\s+\d+\s+(Query|Connect|Execute)\s+')
    MYSQL_SLOW_RE = re.compile(r'^# Time:')
    POSTGRES_ERROR_RE = re.compile(r'^\d{4}-\d{2}-\d{2}\s+[\d:.]+\s+UTC\s+\[\d+\]\s+\S+\s+(LOG|ERROR|FATAL|PANIC):\s*(.*)$')
    POSTGRES_AUTH_RE = re.compile(r'^\d{4}-\d{2}-\d{2}\s+[\d:.]+\s+UTC\s+\[\d+\]\s+\S+\s+LOG:\s+connection received:.*host=(\d+\.\d+\.\d+\.\d+)\s+port=(\d+)')
    POSTGRES_STATEMENT_RE = re.compile(r'^\d{4}-\d{2}-\d{2}\s+[\d:.]+\s+[A-Za-z]{3,4}(?:/[A-Za-z]+)?\s+\[\d+\]\s+STATEMENT:\s+(.*);')

    ORACLE_ALERT_RE = re.compile(r'^[A-Za-z]{3}\s+[A-Za-z]{3}\s+\d{2}\s+\d{2}:\d{2}:\d{2}\s+\d{4}')
    ORACLE_LISTENER_RE = re.compile(r'(.*?)\s+\*.*SERVICE_NAME=(\w+).*PROTOCOL=(\w+).*HOST=(\d+\.\d+\.\d+\.\d+).*PORT=(\d+).*\*\s+(\d+)')
    ORACLE_AUDIT_RE = re.compile(r'^Audit trail:')
    SQLSERVER_ERROR_RE = re.compile(r'(.*?) Server Error: (\d+), Severity: (\d+), State: (\d+)')
    SQLSERVER_AUDIT_RE = re.compile(r'action_id=\w+.*(?:name=\S+|database_name=\S+|statement=.*)', re.IGNORECASE)
    SQLSERVER_TRANSACTION_RE = re.compile(r'\((\d+):(\d+):(\d+)\).*Operation:\s+(.*)')
    MONGODB_SERVER_RE = re.compile(r'^\{.*"t".*:.*"s".*:.*"c".*:.*"msg".*.*\}$')
    MONGODB_AUDIT_RE = re.compile(r'^\{.*"atype".*:.*"ts".*.*\}$')

    FILEZILLA_RE = re.compile(r'^\((\d+)\)(\d{2}/\d{2}/\d{4}) (\d{2}:\d{2}:\d{2}) - (\S+) \(([\d.]+)\)> (\d+) (.*)$')
    VSFTPD_RE = re.compile(r'^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+vsftpd\[(\d+)\]:\s+\[([^\]]+)\]\s+(OK|FAIL)\s+(\w+):\s+(.*)$')
    XFERLOG_RE = re.compile(r'(\w{3})\s+(\w{3})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})\s+(\d{4})\s+\d+\s+([\d.]+)\s+\d+\s+(\S+)\s+[ab]\s+[_]\s+([io])\s+[ra]\s+(\S+)\s+\w+\s+[01]\s+\*\s+([ci])')

    LINUX_SSHD_FAILED_RE = re.compile(r'^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+sshd\[\d+\]:\s+Failed\s+\w+\s+for\s+(?:invalid\s+user\s+)?(\S+)\s+from\s+(\d{1,3}(?:\.\d{1,3}){3})\s+port\s+(\d+)')
    LINUX_SSHD_ACCEPTED_RE = re.compile(r'^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+sshd\[\d+\]:\s+Accepted\s+\w+\s+for\s+(\S+)\s+from\s+(\d{1,3}(?:\.\d{1,3}){3})\s+port\s+(\d+)')
    LINUX_SYSLOG_RE = re.compile(r'(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+([\w\-\/]+)\[(\d+)\]:\s+(.*)')
    LINUX_SYSTEMD_RE = re.compile(r'(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+systemd\[(\d+)\]:\s+(.*)')
    LINUX_KERNEL_RE = re.compile(r'(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+kernel:\s+(.*)')
    LINUX_AUDIT_RE = re.compile(r'type=(\w+)\s+msg=audit\((\d+)\.\d+:(\d+)\):\s*(.*)')
    LINUX_PACKAGE_RE = re.compile(r'(\d{4}-\d{2}-\d{2})\s+\d{2}:\d{2}:\d{2}\s+(status|configure|install|trigproc|upgrade)\s+')

    WINDOWS_TEXT_RE = re.compile(r'(\d{4}-\d{2}-\d{2}[\sT]\d{2}:\d{2}:\d{2}),\s*([^,]+),\s*([^,]+),\s*(\d+),\s*(.*)')
    IIS_FTP_RE = re.compile(r'(\d{4}-\d{2}-\d{2})\s+(\d{2}:\d{2}:\d{2})\s+([\d\.]+)\s+([\w\-]+)\s+[\d\.]+\s+\d+\s+(\w+)\s+([\S]*)\s+(\d+)')
    JSON_FTP_RE = re.compile(r'^\[\[.*\]\]$')  # JSON FTP logs format [[{timestamp:...}]]

    LINUX_SSHD_PAM_RE = re.compile(r'^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+sshd\(pam_unix\)\[\d+\]:\s+(authentication failure|check pass|session (?:opened|closed)).*$')

    DHCP_RE = re.compile(r'^(\w{3})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})\s+(\S+)\s+(.*)')
    DNS_RE = re.compile(r'^(\w{3})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})\s+(\S+)\s+(.*)')
    PROXY_RE = re.compile(r'^(\w{3})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})\s+(\S+)\s+(.*)')

    FASTAPI_RE = re.compile(r'^\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}\.\d+.*?(INFO|WARNING|ERROR|DEBUG).*?"(GET|POST|PUT|DELETE|PATCH)\s+\S+\s+HTTP/\d\.\d"\s+\d{3}')
    AIOHTTP_RE = re.compile(r'^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d+\s+(INFO|WARNING|ERROR|DEBUG).*\"(GET|POST|PUT|DELETE)\s+\S+\s+\d{3}\"')
    STARLETTE_RE = re.compile(r'^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d+\s+(INFO|WARNING|ERROR|DEBUG).*\"(GET|POST|PUT|DELETE|PATCH)\s+\S+\s+\d{3}\"')

    WINDOWS_EVENT_RE = re.compile(r'^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s*,?\s*(INFO|WARNING|ERROR|DEBUG)\s*,?\s*(\S+)\s*,?\s*(\d+)\s*,?\s*(.*)')
    WINDOWS_SECURITY_RE = re.compile(r'^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+(INFO|WARNING|ERROR)\s+Security\s+(\d+)\s+(?:User:\s*(\S+))?\s*(.*)?')
    WINDOWS_APPLICATION_RE = re.compile(r'^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+(INFO|WARNING|ERROR)\s+Application\s+(\d+)\s+(?:Product:\s*(\S+))?\s+(?:EventCode:\s*(\d+))?\s*(.*)?')
    WINDOWS_SYSTEM_RE = re.compile(r'^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+(INFO|WARNING|ERROR)\s+System\s+(\d+)\s+(?:Source:\s*(\S+))?\s*(.*)?')

    WINDOWS_EVENTVIEWER_RE = re.compile(r'^(Audit (?:Success|Failure|Error|Warning)|Success|Failure|Error|Warning) \d{2}-\d{2}-\d{4} \d{2}:\d{2}:\d{2} ')
    WINDOWS_EVENTVIEWER_TAB_RE = re.compile(r'^(Audit (?:Success|Failure|Error|Warning)|Success|Failure|Error|Warning)\t\d{2}-\d{2}-\d{4} \d{2}:\d{2}:\d{2}\t')
    WINDOWS_APPLICATION_TXT_RE = re.compile(r'^(Information|Warning|Error|Critical)\t\d{2}-\d{2}-\d{4} \d{2}:\d{2}:\d{2}\t')
    WINDOWS_APPLICATION_CSV_RE = re.compile(r'^(Information|Warning|Error|Critical),\d{2}-\d{2}-\d{4} \d{2}:\d{2}:\d{2},[^,]+,\d+,[^,]+,')
    WINDOWS_EVENTVIEWER_CSV_RE = re.compile(r'^(Audit (?:Success|Failure|Error|Warning)),\d{2}-\d{2}-\d{4} \d{2}:\d{2}:\d{2},[^,]+,\d+,[^,]+,')
    WINDOWS_SECURITY_CSV_RE = re.compile(r'^TimeCreated,EventID,LevelDisplayName,LogName,MachineName,Message,AccountName,LogonType,IpAddress')
    WINDOWS_SECURITY_CSV_LINE_RE = re.compile(r'^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2},\d+,[^,]+,[^,]+,[^,]+,')
    WINDOWS_SETUP_RE = re.compile(r'^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\s+Setup\s+\d+\s+(INFO|WARNING|ERROR|CRITICAL)')
    WINDOWS_FORWARDED_RE = re.compile(r'^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\s+ForwardedEvents\s+\d+\s+(INFO|WARNING|ERROR|CRITICAL)')

    PROFTPD_RE = re.compile(r'^(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(?:proftpd|pure-ftpd)\[\d+\]:\s+(.*)')

    FASTAPI_JSON_RE = re.compile(r'^\{"time":\s*".*?",\s*"framework":\s*"FastAPI"')
    HAPROXY_RE = re.compile(r'^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+haproxy\[\d+\]:\s+(?:GET|POST|PUT|DELETE)\s+\S+\s+\d{3}$')
    SPRING_BOOT_RE = re.compile(r'^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d+\s+(?:INFO|WARN|ERROR|DEBUG)\s+\S+\s+-\s+(?:GET|POST|PUT|DELETE|PATCH)\s+\S+\s+\d{3}$')
    ASPNET_CORE_RE = re.compile(r'^(?:info|warn|error|debug):\s+Microsoft\.AspNetCore')
    COURIER_RE = re.compile(r'^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\s+\S+\s+courier(?:imap|pop3):\s+(?:LOGIN|LOGOUT),\s+user=')
    AMAVIS_RE = re.compile(r'^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\S+\s+amavis\[\d+\]:\s+.+$')
    SPAMASSASSIN_RE = re.compile(r'^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\S+\s+spamd\[\d+\]:\s+.+$')
    MAILSCANNER_RE = re.compile(r'^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\S+\s+MailScanner\[\d+\]:\s+.+$')
    MACOS_PF_RE = re.compile(r'^\d{2}:\d{2}:\d{2}\.\d+\s+rule\s+\d+\/\d+\s+\((?:match)\):\s+(?:block|pass)\s+(?:in|out)\s+on\s+\S+:\s+(?:\d{1,3}\.){3}\d{1,3}\.\d+\s+>\s+(?:\d{1,3}\.){3}\d{1,3}\.\d+.*$')
    MACOS_APP_FW_RE = re.compile(r'^Firewall:\s+(?:Blocked|Allowed)\s+(?:incoming|outgoing)\s+connection from\s+(?:\d{1,3}\.){3}\d{1,3}\s+to\s+app\s+\S+.*$')
    MOODLE_LMS_RE = re.compile(r'^\[\["19(?:\\\/)?\d{2}(?:\\\/)?\d{2},\s+\d{2}:\d{2}"')

    CLOUDFLARE_RE = re.compile(r'^\{".*?"timestamp".*?".*?"\}')
    AWS_CLOUDTRAIL_RE = re.compile(r'^\{".*?"eventTime".*?"eventName".*?"awsRegion".*?"\}')
    AWS_GUARDDUTY_RE = re.compile(r'^\{".*?"schemaVersion".*?"accountId".*?"type".*?"severity".*?"\}')
    AZURE_ACTIVITY_RE = re.compile(r'^\{".*?"time".*?"operationName".*?"resource".*?"status".*?"\}')
    GCP_AUDIT_RE = re.compile(r'^\{".*?"protoPayload".*?"methodName".*?"resourceName".*?"timestamp".*?"\}')
    KUBERNETES_RE = re.compile(r'^\{".*?"log".*?"stream".*?"docker".*?"\}')
    DOCKER_RE = re.compile(r'^\{".*?"log".*?"stream".*?"time".*?"\}')
    ELASTICSEARCH_RE = re.compile(r'^\{".*?"type".*?"timestamp".*?"level".*?"message".*?"\}')
    REDIS_RE = re.compile(r'^\d+:[\sM]\s+\d+\s+\w+\s+\d+\s+\w+\s+\d{2}:\d{2}:\d{2}\.\d+\s+\S+\s+.*')
    RABBITMQ_RE = re.compile(r'^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d+\s+\[info\]\s+<\d+\.\d+>.*')
    KAFKA_RE = re.compile(r'^\[\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2},\d+\s+\w+\]\s+.*')
    ZOOKEEPER_RE = re.compile(r'^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d+\s+\[myid:\d+\]\s+-\s+\w+\s+\[.*\]\s+.*')
    NGINX_ERROR_RE = re.compile(r'^\d{4}\/\d{2}\/\d{2}\s+\d{2}:\d{2}:\d{2}\s+\[(\w+)\]\s+\d+#\d+:\s+.*')
    SQUID_RE = re.compile(r'^\d+\.\d+\s+\d+\s+(?:\d{1,3}\.){3}\d{1,3}\s+\S+\/\d+\s+\d+\s+\S+\s+\S+\s+\S+\s+\S+.*')
    SURICATA_RE = re.compile(r'^\[\d+:\d+:\d+\]\s+\S+\s+\S+\s+\[Classification:.*\]\[Priority:\d+\]\s+\{.*\}.*')
    ZEEK_RE = re.compile(r'^\d+\.\d+\s+\S+\s+(?:\d{1,3}\.){3}\d{1,3}\s+\d+\s+(?:\d{1,3}\.){3}\d{1,3}\s+\d+\s+\S+\s+.*')
    OSSEC_RE = re.compile(r'^\*\*Alert \d+\.\d+\s+-\s+\S+\s+\S+\s+-\s+Rule:\s+\d+\s+-\s+Level:\s+\d+\s+-\s+.*')
    FAIL2BAN_RE = re.compile(r'^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2},\d+\s+\w+\s+\[\d+\]:\s+\w+\s+\[\S+\]\s+.*')
    AUTH0_RE = re.compile(r'^\d{2}\/\w+\/\d{4}:\d{2}:\d{2}:\d{2}\s+\S+\s+\[\d+\]\s+\[\w+\]:.*')
    APACHE_COMBINED_RE = re.compile(r'^\S+\s+-\s+-\s+\[.*?\]\s+".*?"\s+\d+\s+\d+\s+".*?"\s+".*?"')

    @staticmethod
    def is_express_json(line: str) -> bool:
        return bool(LogDetector.EXPRESS_JSON_RE.match(line))

    @staticmethod
    def is_apache(line: str) -> bool:
        return bool(LogDetector.APACHE_RE.match(line))

    @staticmethod
    def is_laravel(line: str) -> bool:
        return bool(LogDetector.LARAVEL_RE.match(line))

    @staticmethod
    def is_node(line: str) -> bool:
        return bool(LogDetector.NODE_RE.match(line))

    @staticmethod
    def is_django(line: str) -> bool:
        return bool(LogDetector.DJANGO_RE.match(line))

    @staticmethod
    def is_flask(line: str) -> bool:
        return bool(LogDetector.FLASK_RE.match(line))

    @staticmethod
    def is_rails(line: str) -> bool:
        return "Processing by" in line or "Started GET" in line

    @staticmethod
    def is_gunicorn(line: str) -> bool:
        return bool(LogDetector.GUNICORN_RE.match(line))

    @staticmethod
    def is_uvicorn(line: str) -> bool:
        return bool(LogDetector.UVICORN_RE.match(line))

    @staticmethod
    def is_php_fpm(line: str) -> bool:
        return "[pool " in line or bool(LogDetector.PHP_FPM_RE.match(line))

    @staticmethod
    def is_haproxy(line: str) -> bool:
        return bool(LogDetector.HAPROXY_RE.match(line))

    @staticmethod
    def is_spring_boot(line: str) -> bool:
        return bool(LogDetector.SPRING_BOOT_RE.match(line))

    @staticmethod
    def is_aspnet_core(line: str) -> bool:
        return bool(LogDetector.ASPNET_CORE_RE.match(line))

    @staticmethod
    def is_nginx(line: str) -> bool:
        return bool(LogDetector.NGINX_RE.match(line))

    @staticmethod
    def is_caddy(line: str) -> bool:
        return bool(LogDetector.CADDY_RE.match(line))

    @staticmethod
    def is_iis(line: str) -> bool:
        return bool(LogDetector.IIS_RE.match(line))

    @staticmethod
    def is_postfix(line: str) -> bool:
        return bool(LogDetector.POSTFIX_RE.match(line)) or "postfix/" in line or "amavis[" in line or "opendkim[" in line or "roundcube:" in line

    @staticmethod
    def is_sendmail(line: str) -> bool:
        return bool(LogDetector.SENDMAIL_RE.match(line))

    @staticmethod
    def is_exim(line: str) -> bool:
        return bool(LogDetector.EXIM_RE.match(line))

    @staticmethod
    def is_dovecot(line: str) -> bool:
        return bool(LogDetector.DOVECOT_RE.match(line))

    @staticmethod
    def is_courier(line: str) -> bool:
        return bool(LogDetector.COURIER_RE.match(line))

    @staticmethod
    def is_exchange(line: str) -> bool:
        return bool(LogDetector.EXCHANGE_RE.match(line))

    @staticmethod
    def is_amavis(line: str) -> bool:
        return bool(LogDetector.AMAVIS_RE.match(line))

    @staticmethod
    def is_spamassassin(line: str) -> bool:
        return bool(LogDetector.SPAMASSASSIN_RE.match(line))

    @staticmethod
    def is_mailscanner(line: str) -> bool:
        return bool(LogDetector.MAILSCANNER_RE.match(line))

    @staticmethod
    def is_smtp_generic(line: str) -> bool:
        return bool(LogDetector.SMTP_GENERIC_RE.match(line))

    @staticmethod
    def is_windows_fw(line: str) -> bool:
        return bool(LogDetector.WINDOWS_FW_RE.match(line))

    @staticmethod
    def is_iptables(line: str) -> bool:
        return bool(LogDetector.IPTABLES_RE.match(line))

    @staticmethod
    def is_ufw(line: str) -> bool:
        return bool(LogDetector.UFW_RE.match(line))

    @staticmethod
    def is_nftables(line: str) -> bool:
        return bool(LogDetector.NFTABLES_RE.match(line))

    @staticmethod
    def is_firewalld(line: str) -> bool:
        return bool(LogDetector.FIREWALLD_RE.match(line))

    @staticmethod
    def is_macos_pf(line: str) -> bool:
        return bool(LogDetector.MACOS_PF_RE.match(line))

    @staticmethod
    def is_macos_app_fw(line: str) -> bool:
        return bool(LogDetector.MACOS_APP_FW_RE.match(line))

    @staticmethod
    def is_palo_alto(line: str) -> bool:
        return bool(LogDetector.PALO_ALTO_RE.match(line))

    @staticmethod
    def is_fortigate(line: str) -> bool:
        return bool(LogDetector.FORTIGATE_RE.match(line))

    @staticmethod
    def is_cisco_asa(line: str) -> bool:
        return bool(LogDetector.CISCO_ASA_RE.match(line))

    @staticmethod
    def is_checkpoint(line: str) -> bool:
        return bool(LogDetector.CHECKPOINT_RE.match(line))

    @staticmethod
    def is_aws_vpc(line: str) -> bool:
        return bool(LogDetector.AWS_VPC_RE.match(line))

    @staticmethod
    def is_azure_nsg(line: str) -> bool:
        return bool(LogDetector.AZURE_NSG_RE.match(line))

    @staticmethod
    def is_gcp_vpc(line: str) -> bool:
        return bool(LogDetector.GCP_VPC_RE.match(line))

    @staticmethod
    def is_disk_traffic(line: str) -> bool:
        return bool(LogDetector.DISK_TRAFFIC_RE.search(line))

    @staticmethod
    def is_application_json(line: str) -> bool:
        try:
            j = json.loads(line)
            return isinstance(j, list) and len(j) > 0
        except:
            return False

    @staticmethod
    def is_moodle_lms(line: str) -> bool:
        return bool(LogDetector.MOODLE_LMS_RE.match(line))

    @staticmethod
    def is_cloudflare(line: str) -> bool:
        try:
            j = json.loads(line)
            return "timestamp" in j and "Edge" in j and "Request" in j
        except:
            return False

    @staticmethod
    def is_aws_cloudtrail(line: str) -> bool:
        try:
            j = json.loads(line)
            return "eventTime" in j and "eventName" in j and "awsRegion" in j
        except:
            return False

    @staticmethod
    def is_aws_guardduty(line: str) -> bool:
        try:
            j = json.loads(line)
            return "schemaVersion" in j and "accountId" in j and "type" in j and "severity" in j
        except:
            return False

    @staticmethod
    def is_azure_activity(line: str) -> bool:
        try:
            j = json.loads(line)
            return "time" in j and "operationName" in j and "resource" in j and "status" in j
        except:
            return False

    @staticmethod
    def is_gcp_audit(line: str) -> bool:
        try:
            j = json.loads(line)
            return "protoPayload" in j and "methodName" in j and "resourceName" in j
        except:
            return False

    @staticmethod
    def is_kubernetes(line: str) -> bool:
        try:
            j = json.loads(line)
            return "log" in j and "stream" in j and "docker" in j
        except:
            return False

    @staticmethod
    def is_docker(line: str) -> bool:
        try:
            j = json.loads(line)
            return "log" in j and "stream" in j and "time" in j
        except:
            return False

    @staticmethod
    def is_elasticsearch(line: str) -> bool:
        try:
            j = json.loads(line)
            return "type" in j and "timestamp" in j and "level" in j and "message" in j
        except:
            return False

    @staticmethod
    def is_redis(line: str) -> bool:
        return bool(LogDetector.REDIS_RE.match(line))

    @staticmethod
    def is_rabbitmq(line: str) -> bool:
        return bool(LogDetector.RABBITMQ_RE.match(line))

    @staticmethod
    def is_kafka(line: str) -> bool:
        return bool(LogDetector.KAFKA_RE.match(line))

    @staticmethod
    def is_zookeeper(line: str) -> bool:
        return bool(LogDetector.ZOOKEEPER_RE.match(line))

    @staticmethod
    def is_nginx_error(line: str) -> bool:
        return bool(LogDetector.NGINX_ERROR_RE.match(line))

    @staticmethod
    def is_squid(line: str) -> bool:
        return bool(LogDetector.SQUID_RE.match(line))

    @staticmethod
    def is_suricata(line: str) -> bool:
        return bool(LogDetector.SURICATA_RE.match(line))

    @staticmethod
    def is_zeek(line: str) -> bool:
        return bool(LogDetector.ZEEK_RE.match(line))

    @staticmethod
    def is_ossec(line: str) -> bool:
        return bool(LogDetector.OSSEC_RE.match(line))

    @staticmethod
    def is_fail2ban(line: str) -> bool:
        return bool(LogDetector.FAIL2BAN_RE.match(line))

    @staticmethod
    def is_auth0(line: str) -> bool:
        return bool(LogDetector.AUTH0_RE.match(line))

    @staticmethod
    def is_apache_combined(line: str) -> bool:
        return bool(LogDetector.APACHE_COMBINED_RE.match(line))

    @staticmethod
    def is_apache_error(line: str) -> bool:
        return any(p.match(line) for p in LogDetector.APACHE_ERROR_RES)

    @staticmethod
    def is_mysql_error(line: str) -> bool:
        return bool(LogDetector.MYSQL_ERROR_RE.match(line))

    @staticmethod
    def is_mysql_query(line: str) -> bool:
        return bool(LogDetector.MYSQL_QUERY_RE.match(line))

    @staticmethod
    def is_mysql_slow(line: str) -> bool:
        return line.startswith("# Time:")

    @staticmethod
    def is_postgres_error(line: str) -> bool:
        return bool(LogDetector.POSTGRES_ERROR_RE.match(line))

    @staticmethod
    def is_postgres_auth(line: str) -> bool:
        return bool(LogDetector.POSTGRES_AUTH_RE.match(line))

    @staticmethod
    def is_postgres_statement(line: str) -> bool:
        return bool(LogDetector.POSTGRES_STATEMENT_RE.match(line))

    @staticmethod
    def is_oracle_alert(line: str) -> bool:
        return bool(LogDetector.ORACLE_ALERT_RE.match(line))

    @staticmethod
    def is_oracle_listener(line: str) -> bool:
        return bool(LogDetector.ORACLE_LISTENER_RE.match(line))

    @staticmethod
    def is_oracle_audit(line: str) -> bool:
        return bool(LogDetector.ORACLE_AUDIT_RE.match(line))

    @staticmethod
    def is_sqlserver_error(line: str) -> bool:
        return bool(LogDetector.SQLSERVER_ERROR_RE.match(line))

    @staticmethod
    def is_sqlserver_audit(line: str) -> bool:
        return bool(LogDetector.SQLSERVER_AUDIT_RE.match(line))

    @staticmethod
    def is_sqlserver_transaction(line: str) -> bool:
        return bool(LogDetector.SQLSERVER_TRANSACTION_RE.match(line))

    @staticmethod
    def is_mongodb_server(line: str) -> bool:
        try:
            json.loads(line)
            return True
        except:
            return False

    @staticmethod
    def is_mongodb_audit(line: str) -> bool:
        try:
            j = json.loads(line)
            return "atype" in j and "ts" in j
        except:
            return False

    @staticmethod
    def is_sshd_failed(line: str) -> bool:
        return bool(LogDetector.LINUX_SSHD_FAILED_RE.match(line))

    @staticmethod
    def is_sshd_accepted(line: str) -> bool:
        return bool(LogDetector.LINUX_SSHD_ACCEPTED_RE.match(line))

    @staticmethod
    def is_linux_sshd_pam(line: str) -> bool:
        return bool(LogDetector.LINUX_SSHD_PAM_RE.match(line))

    @staticmethod
    def is_syslog(line: str) -> bool:
        return bool(LogDetector.LINUX_SYSLOG_RE.match(line))

    @staticmethod
    def is_systemd(line: str) -> bool:
        return bool(LogDetector.LINUX_SYSTEMD_RE.match(line))

    @staticmethod
    def is_kernel(line: str) -> bool:
        return bool(LogDetector.LINUX_KERNEL_RE.match(line))

    @staticmethod
    def is_audit(line: str) -> bool:
        return bool(LogDetector.LINUX_AUDIT_RE.match(line))

    @staticmethod
    def is_linux_package(line: str) -> bool:
        return bool(LogDetector.LINUX_PACKAGE_RE.match(line))

    @staticmethod
    def is_windows_text(line: str) -> bool:
        return bool(LogDetector.WINDOWS_TEXT_RE.match(line))

    @staticmethod
    def is_filezilla(line: str) -> bool:
        return bool(LogDetector.FILEZILLA_RE.match(line))

    @staticmethod
    def is_iis_ftp(line: str) -> bool:
        return bool(LogDetector.IIS_FTP_RE.match(line))

    @staticmethod
    def is_json_ftp(line: str) -> bool:
        return bool(LogDetector.JSON_FTP_RE.match(line))

    @staticmethod
    def is_xferlog(line: str) -> bool:
        return bool(LogDetector.XFERLOG_RE.match(line))

    @staticmethod
    def is_dhcp(line: str) -> bool:
        m = LogDetector.DHCP_RE.match(line)
        if m:
            service_line = m.group(4)
            return bool(re.match(r'(?:dhcpd?|dhclient)\[\d+\]:', service_line))
        return False

    @staticmethod
    def is_dns(line: str) -> bool:
        m = LogDetector.DNS_RE.match(line)
        if m:
            service_line = m.group(4)
            return bool(re.match(r'(?:named|bind|dnsmasq|unbound)\[\d+\]:', service_line))
        return False

    @staticmethod
    def is_proxy(line: str) -> bool:
        m = LogDetector.PROXY_RE.match(line)
        if m:
            service_line = m.group(4)
            return bool(re.match(r'(?:squid|haproxy|nginx|microsocks)\[\d+\]:', service_line))
        return False

    @staticmethod
    def is_fastapi(line: str) -> bool:
        return bool(LogDetector.FASTAPI_RE.match(line))

    @staticmethod
    def is_aiohttp(line: str) -> bool:
        return bool(LogDetector.AIOHTTP_RE.match(line))

    @staticmethod
    def is_starlette(line: str) -> bool:
        return bool(LogDetector.STARLETTE_RE.match(line))

    @staticmethod
    def is_windows_event(line: str) -> bool:
        return bool(LogDetector.WINDOWS_EVENT_RE.match(line))

    @staticmethod
    def is_windows_security(line: str) -> bool:
        return bool(LogDetector.WINDOWS_SECURITY_RE.match(line))

    @staticmethod
    def is_windows_application(line: str) -> bool:
        return bool(LogDetector.WINDOWS_APPLICATION_RE.match(line))

    @staticmethod
    def is_windows_system(line: str) -> bool:
        return bool(LogDetector.WINDOWS_SYSTEM_RE.match(line))

    @staticmethod
    def is_windows_event_viewer(line: str) -> bool:
        if LogDetector.WINDOWS_EVENTVIEWER_TAB_RE.match(line):
            return True
        if LogDetector.WINDOWS_EVENTVIEWER_RE.match(line):
            return True
        if 'Microsoft-Windows-' in line or 'Security-Auditing' in line:
            return bool(re.match(r'^(Audit|Success|Failure|Error|Warning)\s+\d{2}-\d{2}-\d{4}', line))
        return False

    @staticmethod
    def is_windows_application_txt(line: str) -> bool:
        if LogDetector.WINDOWS_APPLICATION_TXT_RE.match(line):
            return True
        if line.startswith('Level\tDate and Time\tSource\tEvent ID\tTask Category'):
            return True
        return False

    @staticmethod
    def is_windows_application_csv(line: str) -> bool:
        if LogDetector.WINDOWS_APPLICATION_CSV_RE.match(line):
            return True
        if LogDetector.WINDOWS_EVENTVIEWER_CSV_RE.match(line):
            return True
        if LogDetector.WINDOWS_SECURITY_CSV_RE.match(line):
            return True
        if LogDetector.WINDOWS_SECURITY_CSV_LINE_RE.match(line):
            return True
        if line.startswith('Level,') or line.startswith('Keywords,') or line.startswith('TimeCreated,'):
            return True
        return False

    @staticmethod
    def is_windows_setup(line: str) -> bool:
        return bool(LogDetector.WINDOWS_SETUP_RE.match(line))

    @staticmethod
    def is_windows_forwarded(line: str) -> bool:
        return bool(LogDetector.WINDOWS_FORWARDED_RE.match(line))

    @staticmethod
    def is_vsftpd(line: str) -> bool:
        return bool(LogDetector.VSFTPD_RE.match(line))

    @staticmethod
    def is_proftpd(line: str) -> bool:
        return bool(LogDetector.PROFTPD_RE.match(line))

    @staticmethod
    def is_fastapi_json(line: str) -> bool:
        return bool(LogDetector.FASTAPI_JSON_RE.match(line))

    @staticmethod
    def is_windows_security_csv(line: str) -> bool:
        if LogDetector.WINDOWS_SECURITY_CSV_RE.match(line):
            return True
        if "Security" in line and "," in line and "TimeCreated" not in line:
            # Check if it looks like security CSV line
            parts = line.split(',')
            if len(parts) >= 9 and parts[3] == "Security":
                return True
        return False

    @staticmethod
    def get_priority_order() -> List[Tuple[str, Callable[[str], bool]]]:
        return [
            ("Apache", LogDetector.is_apache),
            ("Apache Error", LogDetector.is_apache_error),
            ("NGINX", LogDetector.is_nginx),
            ("Django", LogDetector.is_django),
            ("Flask", LogDetector.is_flask),
            ("Node.js", LogDetector.is_node),
            ("MongoDB Server", LogDetector.is_mongodb_server),
            ("Express.js", LogDetector.is_express_json),
            ("Laravel", LogDetector.is_laravel),
            ("Ruby on Rails", LogDetector.is_rails),
            ("Gunicorn", LogDetector.is_gunicorn),
            ("Uvicorn", LogDetector.is_uvicorn),
            ("PHP-FPM", LogDetector.is_php_fpm),
            ("FastAPI", LogDetector.is_fastapi),
            ("aiohttp", LogDetector.is_aiohttp),
            ("Starlette", LogDetector.is_starlette),
            ("Caddy", LogDetector.is_caddy),
            ("HAProxy", LogDetector.is_haproxy),
            ("Spring Boot", LogDetector.is_spring_boot),
            ("ASP.NET Core", LogDetector.is_aspnet_core),
            ("IIS", LogDetector.is_iis),
            ("Postfix", LogDetector.is_postfix),
            ("Sendmail", LogDetector.is_sendmail),
            ("Exim", LogDetector.is_exim),
            ("Dovecot", LogDetector.is_dovecot),
            ("Courier", LogDetector.is_courier),
            ("Microsoft Exchange", LogDetector.is_exchange),
            ("SMTP Server", LogDetector.is_smtp_generic),
            ("Amavis", LogDetector.is_amavis),
            ("SpamAssassin", LogDetector.is_spamassassin),
            ("MailScanner", LogDetector.is_mailscanner),
            ("Windows Firewall", LogDetector.is_windows_fw),
            ("Windows Event Viewer", LogDetector.is_windows_event_viewer),
            ("Windows Application TXT", LogDetector.is_windows_application_txt),
            ("Windows Security CSV", LogDetector.is_windows_security_csv),
            ("Windows Application CSV", LogDetector.is_windows_application_csv),
            ("Windows Event", LogDetector.is_windows_event),
            ("Windows Security", LogDetector.is_windows_security),
            ("Windows Application", LogDetector.is_windows_application),
            ("Windows System", LogDetector.is_windows_system),
            ("Windows Setup", LogDetector.is_windows_setup),
            ("Windows Forwarded Events", LogDetector.is_windows_forwarded),
            ("Windows Text", LogDetector.is_windows_text),
            ("iptables", LogDetector.is_iptables),
            ("UFW", LogDetector.is_ufw),
            ("nftables", LogDetector.is_nftables),
            ("firewalld", LogDetector.is_firewalld),
            ("macOS PF", LogDetector.is_macos_pf),
            ("macOS App Firewall", LogDetector.is_macos_app_fw),
            ("Palo Alto Firewall", LogDetector.is_palo_alto),
            ("FortiGate", LogDetector.is_fortigate),
            ("Cisco ASA", LogDetector.is_cisco_asa),
            ("Check Point Firewall", LogDetector.is_checkpoint),
            ("AWS VPC Flow Logs", LogDetector.is_aws_vpc),
            ("Azure NSG Flow Logs", LogDetector.is_azure_nsg),
            ("GCP VPC Firewall", LogDetector.is_gcp_vpc),
            ("Disk Traffic", LogDetector.is_disk_traffic),
            ("Moodle LMS", LogDetector.is_moodle_lms),
            ("Application Logs JSON", LogDetector.is_application_json),
            ("MySQL Error", LogDetector.is_mysql_error),
            ("MySQL Query", LogDetector.is_mysql_query),
            ("MySQL Slow Query", LogDetector.is_mysql_slow),
            ("PostgreSQL Error", LogDetector.is_postgres_error),
            ("PostgreSQL Auth", LogDetector.is_postgres_auth),
            ("PostgreSQL Statement", LogDetector.is_postgres_statement),
            ("Oracle Alert", LogDetector.is_oracle_alert),
            ("Oracle Listener", LogDetector.is_oracle_listener),
            ("Oracle Audit", LogDetector.is_oracle_audit),
            ("SQL Server Error", LogDetector.is_sqlserver_error),
            ("SQL Server Audit", LogDetector.is_sqlserver_audit),
            ("SQL Server Transaction", LogDetector.is_sqlserver_transaction),
            ("MongoDB Server", LogDetector.is_mongodb_server),
            ("MongoDB Audit", LogDetector.is_mongodb_audit),
            ("Linux SSHD Failed", LogDetector.is_sshd_failed),
            ("Linux SSHD Accepted", LogDetector.is_sshd_accepted),
            ("Linux Syslog", LogDetector.is_syslog),
            ("Linux Systemd", LogDetector.is_systemd),
            ("Linux Kernel", LogDetector.is_kernel),
            ("Linux Audit", LogDetector.is_audit),
            ("Linux Package", LogDetector.is_linux_package),
            ("Windows Text", LogDetector.is_windows_text),
            ("FileZilla FTP", LogDetector.is_filezilla),
            ("IIS FTP", LogDetector.is_iis_ftp),
            ("xferlog", LogDetector.is_xferlog),
            ("VSFTPD", LogDetector.is_vsftpd),
            ("ProFTPD", LogDetector.is_proftpd),
            ("DHCP", LogDetector.is_dhcp),
            ("DNS", LogDetector.is_dns),
            ("Proxy", LogDetector.is_proxy),
            ("Cloudflare", LogDetector.is_cloudflare),
            ("AWS CloudTrail", LogDetector.is_aws_cloudtrail),
            ("AWS GuardDuty", LogDetector.is_aws_guardduty),
            ("Azure Activity", LogDetector.is_azure_activity),
            ("GCP Audit", LogDetector.is_gcp_audit),
            ("Kubernetes", LogDetector.is_kubernetes),
            ("Docker", LogDetector.is_docker),
            ("Elasticsearch", LogDetector.is_elasticsearch),
            ("Redis", LogDetector.is_redis),
            ("RabbitMQ", LogDetector.is_rabbitmq),
            ("Kafka", LogDetector.is_kafka),
            ("Zookeeper", LogDetector.is_zookeeper),
            ("Nginx Error", LogDetector.is_nginx_error),
            ("Squid", LogDetector.is_squid),
            ("Suricata", LogDetector.is_suricata),
            ("Zeek", LogDetector.is_zeek),
            ("Ossec", LogDetector.is_ossec),
            ("Fail2ban", LogDetector.is_fail2ban),
            ("Auth0", LogDetector.is_auth0),
            ("Apache Combined", LogDetector.is_apache_combined),
        ]

    @staticmethod
    def check_line(line: str, log_type: str) -> bool:
        check_functions = {
            "Apache": LogDetector.is_apache,
            "Apache Error": LogDetector.is_apache_error,
            "NGINX": LogDetector.is_nginx,
            "Django": LogDetector.is_django,
            "Flask": LogDetector.is_flask,
            "Node.js": LogDetector.is_node,
            "MongoDB Server": LogDetector.is_mongodb_server,
            "Express.js": LogDetector.is_express_json,
            "Laravel": LogDetector.is_laravel,
            "Ruby on Rails": LogDetector.is_rails,
            "Gunicorn": LogDetector.is_gunicorn,
            "Uvicorn": LogDetector.is_uvicorn,
            "PHP-FPM": LogDetector.is_php_fpm,
            "FastAPI": LogDetector.is_fastapi,
            "aiohttp": LogDetector.is_aiohttp,
            "Starlette": LogDetector.is_starlette,
            "Caddy": LogDetector.is_caddy,
            "HAProxy": LogDetector.is_haproxy,
            "Spring Boot": LogDetector.is_spring_boot,
            "ASP.NET Core": LogDetector.is_aspnet_core,
            "IIS": LogDetector.is_iis,
            "Postfix": LogDetector.is_postfix,
            "Sendmail": LogDetector.is_sendmail,
            "Exim": LogDetector.is_exim,
            "Dovecot": LogDetector.is_dovecot,
            "Courier": LogDetector.is_courier,
            "Microsoft Exchange": LogDetector.is_exchange,
            "SMTP Server": LogDetector.is_smtp_generic,
            "Amavis": LogDetector.is_amavis,
            "SpamAssassin": LogDetector.is_spamassassin,
            "MailScanner": LogDetector.is_mailscanner,
            "Windows Firewall": LogDetector.is_windows_fw,
            "Windows Event Viewer": LogDetector.is_windows_event_viewer,
            "Windows Application TXT": LogDetector.is_windows_application_txt,
            "Windows Security CSV": LogDetector.is_windows_security_csv,
            "Windows Application CSV": LogDetector.is_windows_application_csv,
            "Windows Event": LogDetector.is_windows_event,
            "Windows Security": LogDetector.is_windows_security,
            "Windows Application": LogDetector.is_windows_application,
            "Windows System": LogDetector.is_windows_system,
            "Windows Setup": LogDetector.is_windows_setup,
            "Windows Forwarded Events": LogDetector.is_windows_forwarded,
            "Windows Text": LogDetector.is_windows_text,
            "iptables": LogDetector.is_iptables,
            "UFW": LogDetector.is_ufw,
            "nftables": LogDetector.is_nftables,
            "firewalld": LogDetector.is_firewalld,
            "macOS PF": LogDetector.is_macos_pf,
            "macOS App Firewall": LogDetector.is_macos_app_fw,
            "Palo Alto Firewall": LogDetector.is_palo_alto,
            "FortiGate": LogDetector.is_fortigate,
            "Cisco ASA": LogDetector.is_cisco_asa,
            "Check Point Firewall": LogDetector.is_checkpoint,
            "AWS VPC Flow Logs": LogDetector.is_aws_vpc,
            "Azure NSG Flow Logs": LogDetector.is_azure_nsg,
            "GCP VPC Firewall": LogDetector.is_gcp_vpc,
            "Disk Traffic": LogDetector.is_disk_traffic,
            "Moodle LMS": LogDetector.is_moodle_lms,
            "Application Logs JSON": LogDetector.is_application_json,
            "MySQL Error": LogDetector.is_mysql_error,
            "MySQL Query": LogDetector.is_mysql_query,
            "MySQL Slow Query": LogDetector.is_mysql_slow,
            "PostgreSQL Error": LogDetector.is_postgres_error,
            "PostgreSQL Auth": LogDetector.is_postgres_auth,
            "PostgreSQL Statement": LogDetector.is_postgres_statement,
            "Oracle Alert": LogDetector.is_oracle_alert,
            "Oracle Listener": LogDetector.is_oracle_listener,
            "Oracle Audit": LogDetector.is_oracle_audit,
            "SQL Server Error": LogDetector.is_sqlserver_error,
            "SQL Server Audit": LogDetector.is_sqlserver_audit,
            "SQL Server Transaction": LogDetector.is_sqlserver_transaction,
            "MongoDB Server": LogDetector.is_mongodb_server,
            "MongoDB Audit": LogDetector.is_mongodb_audit,
            "Linux SSHD Failed": LogDetector.is_sshd_failed,
            "Linux SSHD Accepted": LogDetector.is_sshd_accepted,
            "Linux SSHD PAM": LogDetector.is_linux_sshd_pam,
            "Linux Syslog": LogDetector.is_syslog,
            "Linux Systemd": LogDetector.is_systemd,
            "Linux Kernel": LogDetector.is_kernel,
            "Linux Audit": LogDetector.is_audit,
            "Linux Package": LogDetector.is_linux_package,
            "FileZilla FTP": LogDetector.is_filezilla,
            "VSFTPD": LogDetector.is_vsftpd,
            "xferlog": LogDetector.is_xferlog,
            "IIS FTP": LogDetector.is_iis_ftp,
            "JSON FTP Logs": LogDetector.is_json_ftp,
            "Cloudflare": LogDetector.is_cloudflare,
            "AWS CloudTrail": LogDetector.is_aws_cloudtrail,
            "AWS GuardDuty": LogDetector.is_aws_guardduty,
            "Azure Activity": LogDetector.is_azure_activity,
            "GCP Audit": LogDetector.is_gcp_audit,
            "Kubernetes": LogDetector.is_kubernetes,
            "Docker": LogDetector.is_docker,
            "Elasticsearch": LogDetector.is_elasticsearch,
            "Redis": LogDetector.is_redis,
            "RabbitMQ": LogDetector.is_rabbitmq,
            "Kafka": LogDetector.is_kafka,
            "Zookeeper": LogDetector.is_zookeeper,
            "Nginx Error": LogDetector.is_nginx_error,
            "Squid": LogDetector.is_squid,
            "Suricata": LogDetector.is_suricata,
            "Zeek": LogDetector.is_zeek,
            "Ossec": LogDetector.is_ossec,
            "Fail2ban": LogDetector.is_fail2ban,
            "Auth0": LogDetector.is_auth0,
            "Apache Combined": LogDetector.is_apache_combined,
        }
        func = check_functions.get(log_type)
        if func:
            return func(line)
        return False

    CANDIDATE_SAMPLE_LINES = 10

    @staticmethod
    def detect(content: str) -> str:
        all_lines = [line.strip() for line in content.split('\n') if line.strip()]
        
        if not all_lines:
            return 'Custom / Raw'

        # Sample at most 100 lines for detection to avoid hanging on large files
        sample_limit = min(100, len(all_lines))
        lines = all_lines[:sample_limit]

        priority_order = LogDetector.get_priority_order()
        scores = {log_type: 0 for log_type, _ in priority_order}
        scores["Custom / Raw"] = 0

        # Phase 1: Check initial candidates
        phase1_lines = min(LogDetector.CANDIDATE_SAMPLE_LINES, len(lines))
        
        for i in range(phase1_lines):
            line = lines[i]
            for log_type, check_func in priority_order:
                try:
                    if check_func(line):
                        scores[log_type] += 3
                except:
                    continue

        # Phase 2: Refine with more sample lines for candidates
        candidate_types = [k for k, v in scores.items() if v > 0 and k != 'Custom / Raw']
        if not candidate_types:
            candidate_types = [log_type for log_type, _ in priority_order]

        for i in range(phase1_lines, len(lines)):
            line = lines[i]
            matched = False
            for log_type in candidate_types:
                try:
                    if LogDetector.check_line(line, log_type):
                        scores[log_type] += 3
                        matched = True
                        break
                except:
                    continue

            if not matched:
                scores['Custom / Raw'] += 1

        best_type = 'Custom / Raw'
        best_score = 0
        for log_type, score in scores.items():
            if score > best_score:
                best_score = score
                best_type = log_type
        
        return best_type if best_score >= 3 else 'Custom / Raw'


def preprocess_json_array(content: str) -> str:
    """Convert single-line JSON array to multiline format for easier line-by-line parsing."""
    trimmed = content.strip()
    if not (trimmed.startswith('[') and trimmed.endswith(']')):
        return content

    try:
        data = json.loads(trimmed)
        if not isinstance(data, list):
            return content
            
        # If it's a list of lists (nested), flatten it one level if needed
        if len(data) > 0 and isinstance(data[0], list):
            # Special case for some nested JSON formats
            lines = [json.dumps(entry) for sublist in data for entry in sublist if isinstance(entry, dict)]
            if not lines: # Try flattening just one level
                lines = [json.dumps(sublist) for sublist in data]
        else:
            # Standard list of objects
            lines = [json.dumps(entry) if isinstance(entry, (dict, list)) else str(entry) for entry in data]
            
        return '\n'.join(lines)
    except Exception as e:
        print(f"JSON preprocessing failed: {e}")
        return content
