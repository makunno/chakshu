"""Dynamic Parser - Fallback for unknown log formats"""

import re
from datetime import datetime
from .base import Parser
from .types import LogType, LogEntry, Severity


class DynamicParser(Parser):
    """Dynamic parser for unknown log formats"""

    def __init__(self):
        super().__init__("Dynamic Parser", LogType.UNKNOWN)
        self.field_patterns = {
            'timestamp': [
                r'\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}',
                r'\d{2}\/\w{3}\/\d{4}:\d{2}:\d{2}',
                r'\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}',
            ],
            'ip': [
                r'src[_-]ip[=:]\s*"?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',
                r'dst[_-]ip[=:]\s*"?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',
                r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b',
            ],
            'port': [
                r'src[_-]port[=:]\s*"?(\d{1,5})',
                r'dst[_-]port[=:]\s*"?(\d{1,5})',
                r'port[=:]\s*(\d{1,5})\b',
            ],
            'user': [
                r'user[=:]\s*"?(\w[^"]*)"',
                r'username[=:]\s*"?(\w[^"]*)"',
            ],
            'severity': [
                r'\b(debug|info|notice|warn|warning|error|err|fail|fatal|critical|alert)\b',
            ]
        }

    def detect(self, line: str) -> bool:
        """Dynamic parser accepts all lines (fallback)"""
        return True

    def parse(self, line: str) -> LogEntry:
        """Parse line using pattern matching"""
        fields = {}
        message = line.strip()

        # Extract fields using patterns
        for field_type, patterns in self.field_patterns.items():
            for pattern in patterns:
                match = re.search(pattern, line, re.IGNORECASE)
                if match:
                    value = match.group(1) if match.groups() else match.group(0)
                    fields[field_type] = value
                    break

        # Determine severity
        severity_str = fields.get('severity', 'unknown').lower()
        severity_map = {
            'debug': Severity.DEBUG,
            'info': Severity.INFO,
            'warning': Severity.WARNING,
            'error': Severity.ERROR,
            'critical': Severity.CRITICAL,
        }
        severity = severity_map.get(severity_str, Severity.UNKNOWN)

        # Determine timestamp
        timestamp = None
        if 'timestamp' in fields:
            try:
                ts_str = fields['timestamp']
                if 'T' in ts_str:
                    timestamp = datetime.fromisoformat(ts_str.replace(' ', 'T')).isoformat()
                else:
                    # Try various formats
                    for fmt in [
                        "%Y-%m-%d %H:%M:%S",
                        "%d/%b/%Y:%H:%M:%S",
                        "%b %d %H:%M:%S"
                    ]:
                        try:
                            timestamp = datetime.strptime(ts_str, fmt).isoformat()
                            break
                        except:
                            continue
            except:
                pass

        return LogEntry(
            line,
            timestamp=timestamp,
            log_type=LogType.UNKNOWN,
            severity=severity,
            source={'ip': fields.get('ip')},
            user={'name': fields.get('user')} if fields.get('user') else None,
            fields=fields,
            message=message
        )


def analyze_log_structure(lines: list) -> dict:
    """Analyze log structure and suggest labels"""
    if not lines:
        return {
            'structure': {'separator': 'unknown', 'columns': [], 'hasTimestamp': False, 'timestampIndex': -1, 'hasKeyPairs': False},
            'detectedFields': [],
            'suggestedLabels': [],
            'sampleFields': {}
        }

    # Analyze first line
    first_line = lines[0].strip()

    # Detect separator
    separators = [',', '\t', ' | ', ' ']
    separator = 'unknown'
    for sep in separators:
        parts = first_line.split(sep)
        if len(parts) >= 3:
            separator = sep
            break

    # Detect key-value pairs
    has_key_pairs = any('=' in first_line for _ in range(3))

    # Detect columns if separator found
    columns = []
    if separator != 'unknown':
        columns = first_line.split(separator)
        columns = [c.strip().strip('"').strip("'") for c in columns]

    # Detect timestamp
    has_timestamp = False
    timestamp_index = -1
    for i, col in enumerate(columns):
        if re.search(r'\d{4}-\d{2}-\d{2}', col) or re.search(r'\d{2}/\w{3}/\d{4}', col):
            has_timestamp = True
            timestamp_index = i
            break

    # Detect fields across all lines
    field_counts = {}
    ip_pattern = re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
    user_pattern = re.compile(r'user[=:]\s*[\'"]?(\w+)', re.IGNORECASE)

    for line in lines[:50]:
        ips = ip_pattern.findall(line)
        users = user_pattern.findall(line)

        for ip in ips:
            field_counts['ip'] = field_counts.get('ip', 0) + 1
        for user in users:
            field_counts['user'] = field_counts.get('user', 0) + 1

    # Generate suggested labels
    detected_fields = []
    suggested_labels = []

    for field, count in field_counts.items():
        if count > 2:
            detected_fields.append(field)
            suggested_labels.append({
                'field': field,
                'confidence': min(count / 50, 1.0),
                'sample': ''
            })

    return {
        'structure': {
            'separator': separator,
            'columns': columns[:10],  # Limit to first 10
            'hasTimestamp': has_timestamp,
            'timestampIndex': timestamp_index,
            'hasKeyPairs': has_key_pairs,
        },
        'detectedFields': detected_fields,
        'suggestedLabels': suggested_labels,
        'sampleFields': {field: '' for field in detected_fields[:5]}
    }
