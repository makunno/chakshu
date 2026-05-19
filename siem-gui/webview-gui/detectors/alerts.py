"""Security Alert Detection Engine"""

from typing import List, Dict, Any
from datetime import datetime, timedelta
from collections import defaultdict

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from parsers.types import LogEntry


def _get_user_name(entry: dict) -> str:
    """Safely get user name from entry, handling None user field"""
    user = entry.get('user')
    if user is None:
        return ''
    if isinstance(user, dict):
        return user.get('name', '')
    return str(user)


def _get_source_ip(entry: dict) -> str:
    """Safely get source IP from entry, handling None source field"""
    source = entry.get('source')
    if source is None:
        return ''
    if isinstance(source, dict):
        return source.get('ip', '')
    return str(source)


def run_detections(entries: List[dict], config: dict = None) -> List[dict]:
    """Run all detection rules on parsed log entries"""
    if config is None:
        config = {
            'bruteforceThreshold': 10,
            'bruteforceWindowMinutes': 5,
            'sprayUsersThreshold': 10,
            'sprayWindowMinutes': 10,
            'successAfterFailuresThreshold': 3,
            'successAfterWindowMinutes': 10
        }

    alerts = []

    # Sort entries by timestamp
    sorted_entries = sorted(
        [e for e in entries if e.get('timestamp')],
        key=lambda x: x.get('timestamp', '')
    )

    # Run each detection
    alerts.extend(detect_bruteforce(sorted_entries, config))
    alerts.extend(detect_password_spray(sorted_entries, config))
    alerts.extend(detect_success_after_failures(sorted_entries, config))
    alerts.extend(detect_suspicious_activity(sorted_entries))

    return alerts


def detect_bruteforce(entries: List[dict], config: dict) -> List[dict]:
    """Detect brute force attacks - many failures from same IP to same user"""
    alerts = []
    window_ms = config['bruteforceWindowMinutes'] * 60 * 1000

    # Filter to auth failures
    failures = [
        e for e in entries
        if e.get('outcome') == 'failure'
        and _get_source_ip(e)
        and _get_user_name(e)
        and (e.get('tags', []).__contains__('auth') or e.get('tags', []).__contains__('ssh') or e.get('logType') == 'ssh_auth')
    ]

    # Group by (IP, user)
    groups = defaultdict(list)
    for entry in failures:
        key = f"{_get_source_ip(entry)}|{_get_user_name(entry)}"
        groups[key].append(entry)

    # Check each group for brute force pattern
    for (key, group) in groups.items():
        if len(group) < config['bruteforceThreshold']:
            continue

        ip, user = key.split('|', 1) if '|' in key else (key, '')

        # Sliding window check
        for i in range(len(group) - config['bruteforceThreshold'] + 1):
            window_start = datetime.fromisoformat(group[i]['timestamp'].replace('Z', '+00:00'))
            count = 1
            window_end = window_start

            for j in range(i + 1, len(group)):
                time = datetime.fromisoformat(group[j]['timestamp'].replace('Z', '+00:00'))
                if (time - window_start).total_seconds() * 1000 <= window_ms:
                    count += 1
                    window_end = time
                else:
                    break

            if count >= config['bruteforceThreshold']:
                alerts.append({
                    'id': f"bf_alert_{len(alerts)}",
                    'type': 'bruteforce',
                    'severity': 'high',
                    'confidence': 'high',
                    'title': 'Brute Force Attack Detected',
                    'description': f"{count} failed login attempts from {ip} to user \"{user}\" within {config['bruteforceWindowMinutes']} minutes",
                    'timestamp': datetime.now().isoformat(),
                    'sourceIps': [ip],
                    'targetUsers': [user],
                    'relatedEvents': [e['id'] for e in group[i:i + count]],
                    'metadata': {
                        'count': count,
                        'windowStart': window_start.isoformat(),
                        'windowEnd': window_end.isoformat()
                    }
                })
                break

    return alerts


def detect_password_spray(entries: List[dict], config: dict) -> List[dict]:
    """Detect password spray attacks - same IP targeting many users"""
    alerts = []
    window_ms = config['sprayWindowMinutes'] * 60 * 1000

    # Filter to auth failures
    failures = [
        e for e in entries
        if e.get('outcome') == 'failure'
        and _get_source_ip(e)
        and _get_user_name(e)
        and (e.get('tags', []).__contains__('auth') or e.get('tags', []).__contains__('ssh') or e.get('logType') == 'ssh_auth')
    ]

    # Group by IP
    by_ip = defaultdict(list)
    for entry in failures:
        by_ip[_get_source_ip(entry)].append(entry)

    # Check each IP for spray pattern
    for (ip, group) in by_ip.items():
        # Sliding window to find unique users
        for i in range(len(group)):
            window_start = datetime.fromisoformat(group[i]['timestamp'].replace('Z', '+00:00'))
            users_in_window = set()
            window_end = window_start

            for j in range(i, len(group)):
                time = datetime.fromisoformat(group[j]['timestamp'].replace('Z', '+00:00'))
                if (time - window_start).total_seconds() * 1000 <= window_ms:
                    users_in_window.add(_get_user_name(group[j]))
                    window_end = time
                else:
                    break

            if len(users_in_window) >= config['sprayUsersThreshold']:
                alerts.append({
                    'id': f"spray_alert_{len(alerts)}",
                    'type': 'password_spray',
                    'severity': 'high',
                    'confidence': 'high',
                    'title': 'Password Spray Attack Detected',
                    'description': f"{ip} targeted {len(users_in_window)} unique users within {config['sprayWindowMinutes']} minutes",
                    'timestamp': datetime.now().isoformat(),
                    'sourceIps': [ip],
                    'targetUsers': list(users_in_window),
                    'relatedEvents': [e['id'] for e in group if e['user']['name'] in users_in_window],
                    'metadata': {
                        'uniqueUsers': len(users_in_window),
                        'windowStart': window_start.isoformat(),
                        'windowEnd': window_end.isoformat()
                    }
                })
                break

    return alerts


def detect_success_after_failures(entries: List[dict], config: dict) -> List[dict]:
    """Detect successful login after multiple failures"""
    alerts = []
    window_ms = config['successAfterWindowMinutes'] * 60 * 1000

    # Get auth events
    auth_events = [
        e for e in entries
        if _get_user_name(e)
        and (e.get('tags', []).__contains__('auth') or e.get('tags', []).__contains__('ssh') or e.get('logType') == 'ssh_auth')
    ]

    # Group by user
    by_user = defaultdict(list)
    for entry in auth_events:
        by_user[_get_user_name(entry)].append(entry)

    # Check for success-after-failures pattern
    for (user, group) in by_user.items():
        successes = [e for e in group if e.get('outcome') == 'success']
        failures = [e for e in group if e.get('outcome') == 'failure']

        for success in successes:
            success_time = datetime.fromisoformat(success['timestamp'].replace('Z', '+00:00'))

            # Count failures in window before success
            recent_failures = [
                f for f in failures
                if datetime.fromisoformat(f['timestamp'].replace('Z', '+00:00')) < success_time
                and (success_time - datetime.fromisoformat(f['timestamp'].replace('Z', '+00:00'))).total_seconds() * 1000 <= window_ms
            ]

            if len(recent_failures) >= config['successAfterFailuresThreshold']:
                source_ips = list(set(f['source']['ip'] for f in recent_failures if f.get('source', {}).get('ip')))

                alerts.append({
                    'id': f"saf_alert_{len(alerts)}",
                    'type': 'suspicious_activity',
                    'severity': 'medium',
                    'confidence': 'medium',
                    'title': 'Successful Login After Multiple Failures',
                    'description': f"User \"{user}\" logged in successfully after {len(recent_failures)} failed attempts within {config['successAfterWindowMinutes']} minutes",
                    'timestamp': datetime.now().isoformat(),
                    'sourceIps': source_ips,
                    'targetUsers': [user],
                    'relatedEvents': [f['id'] for f in recent_failures] + [success['id']],
                    'metadata': {
                        'failureCount': len(recent_failures),
                        'successTime': success['timestamp']
                    }
                })

    return alerts


def detect_suspicious_activity(entries: List[dict]) -> List[dict]:
    """Detect other suspicious activities"""
    alerts = []

    # Detect privilege escalation (sudo/su)
    priv_esc = [
        e for e in entries
        if e.get('tags', []).__contains__('privilege_escalation')
        or e.get('action') == 'sudo'
        or e.get('action') == 'su'
    ]

    # Group by user
    sudo_by_user = defaultdict(int)
    for entry in priv_esc:
        user = entry.get('user', {}).get('name') or 'unknown'
        sudo_by_user[user] += 1

    # Alert if excessive sudo/su usage
    for (user, count) in sudo_by_user.items():
        if count > 20:
            alerts.append({
                'id': f"priv_alert_{len(alerts)}",
                'type': 'privilege_escalation',
                'severity': 'medium',
                'confidence': 'low',
                'title': 'Excessive Privilege Escalation',
                'description': f"User \"{user}\" performed {count} privilege escalation operations",
                'timestamp': datetime.now().isoformat(),
                'sourceIps': [],
                'targetUsers': [user],
                'relatedEvents': [e['id'] for e in priv_esc[:10] if _get_user_name(e) == user],
                'metadata': {'count': count}
            })

    return alerts


def generate_stats(entries: List[dict]) -> dict:
    """Generate statistics from parsed entries"""
    by_type = defaultdict(int)
    by_severity = defaultdict(int)
    by_outcome = defaultdict(int)
    source_count = defaultdict(int)
    user_count = defaultdict(int)
    timeline_map = defaultdict(int)

    for entry in entries:
        # By type
        by_type[entry.get('logType', 'unknown')] += 1

        # By severity
        by_severity[entry.get('severity', 'info')] += 1

        # By outcome
        if entry.get('outcome'):
            by_outcome[entry['outcome']] += 1

        # Source IPs
        ip = _get_source_ip(entry)
        if ip:
            source_count[ip] += 1

        # Users
        user = _get_user_name(entry)
        if user:
            user_count[user] += 1

        # Timeline (group by minute)
        if entry.get('timestamp'):
            minute = entry['timestamp'][:16]  # YYYY-MM-DDTHH:MM
            timeline_map[minute] += 1

    # Convert to sorted arrays
    top_sources = [
        {'ip': ip, 'count': count}
        for ip, count in sorted(source_count.items(), key=lambda x: x[1], reverse=True)[:20]
    ]

    top_users = [
        {'user': user, 'count': count}
        for user, count in sorted(user_count.items(), key=lambda x: x[1], reverse=True)[:20]
    ]

    timeline = [
        {'time': time, 'count': count}
        for time, count in sorted(timeline_map.items())
    ]

    return {
        'byType': dict(by_type),
        'bySeverity': dict(by_severity),
        'byOutcome': dict(by_outcome),
        'topSources': top_sources,
        'topUsers': top_users,
        'timeline': timeline
    }
