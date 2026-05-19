"""
Windows Event Log Parsers - Application, Security, System logs
"""

import re
from typing import Optional, Dict, Any
from datetime import datetime


class WindowsParsers:
    """ISEA-style Windows event log parsers"""

    @staticmethod
    def windows_event(line: str) -> Optional[Dict[str, Any]]:
        """Parse Windows Event Log line"""
        # Windows event format varies, common pattern:
        # "2025-02-02 12:00:00, EventType=INFO, Source=Application, EventID=1000, Message=..."
        
        m = re.match(
            r'^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})(?:,\s*EventType=(\w+))?(?:,\s*Source=(\w+))?(?:,\s*EventID=(\d+))?(?:,\s*Message=(.+))?$',
            line
        )
        if not m:
            # Try alternate format with tabs
            m = re.match(
                r'^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+(INFO|WARNING|ERROR|DEBUG)\s+(\S+)\s+(\d+)\s+(.+)$',
                line
            )
            if m:
                timestamp, level, source, event_id, message = m.groups()
                return {
                    'timestamp': timestamp,
                    'host': 'windows',
                    'service': source.lower(),
                    'event_id': int(event_id),
                    'level': level,
                    'message': message,
                    'source': 'event_log'
                }
            return None
        
        timestamp, event_type, source, event_id, message = m.groups()
        
        return {
            'timestamp': timestamp.strip(),
            'host': 'windows',
            'service': source.lower() if source else 'application',
            'event_id': int(event_id) if event_id else None,
            'level': event_type.upper() if event_type else 'INFO',
            'message': message.strip() if message else '',
            'source': 'event_log'
        }

    @staticmethod
    def windows_security(line: str) -> Optional[Dict[str, Any]]:
        """Parse Windows Security Event Log"""
        # Security events typically contain Event ID and User
        m = re.match(
            r'^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+(INFO|WARNING|ERROR)\s+Security\s+(\d+)\s+(?:User:\s*(\S+))?\s*(.+)?$',
            line
        )
        if not m:
            return None
        
        timestamp, level, event_id, user, message = m.groups()
        
        return {
            'timestamp': timestamp,
            'host': 'windows',
            'service': 'security',
            'event_id': int(event_id),
            'user': user,
            'level': level,
            'message': message.strip() if message else '',
            'source': 'windows_security'
        }

    @staticmethod
    def windows_application(line: str) -> Optional[Dict[str, Any]]:
        """Parse Windows Application Event Log"""
        m = re.match(
            r'^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+(INFO|WARNING|ERROR)\s+Application\s+(\d+)\s+(?:Product:\s*(\S+))?\s*(?:EventCode:\s*(\d+))?\s*(.+)?$',
            line
        )
        if not m:
            return None
        
        timestamp, level, event_id, product, event_code, message = m.groups()
        
        return {
            'timestamp': timestamp,
            'host': 'windows',
            'service': 'application',
            'event_id': int(event_id),
            'product': product,
            'event_code': int(event_code) if event_code else None,
            'level': level,
            'message': message.strip() if message else '',
            'source': 'windows_application'
        }

    @staticmethod
    def windows_system(line: str) -> Optional[Dict[str, Any]]:
        """Parse Windows System Event Log"""
        m = re.match(
            r'^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+(INFO|WARNING|ERROR)\s+System\s+(\d+)\s+(?:Source:\s*(\S+))?\s*(.+)?$',
            line
        )
        if not m:
            return None
        
        timestamp, level, event_id, source, message = m.groups()
        
        return {
            'timestamp': timestamp,
            'host': 'windows',
            'service': 'system',
            'event_id': int(event_id),
            'source_name': source,
            'level': level,
            'message': message.strip() if message else '',
            'source': 'windows_system'
        }
