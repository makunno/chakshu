"""
Network Service Log Parsers - DHCP, DNS, Proxy
"""

import re
from typing import Optional, Dict, Any


class NetworkParsers:
    """ISEA-style network service log parsers"""

    @staticmethod
    def dhcp(line: str) -> Optional[Dict[str, Any]]:
        """Parse DHCP lease log line"""
        # Common DHCP log formats:
        # "Feb  2 12:00:00 dhcpd: DHCPREQUEST for 192.168.1.100 from 00:11:22:33:44:55 (hostname)"
        # "Sun Feb  2 12:00:00 dhcpd[1234]: DHCPACK to 192.168.1.100 (00:11:22:33:44:55)"
        
        m = re.match(
            r'^[A-Z][a-z]{2}\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})\s+(?:dhcpd|dhclient)(?:\[\d+\])?:\s+(DHCP(?:REQUEST|ACK|OFFER|Discover|Inform))?\s*(?:for\s+(\d+\.\d+\.\d+\.\d+))?(?:\s+from\s+([0-9A-Fa-f:]+))?(?:\s+\((.+)\))?(.+)?$',
            line
        )
        if not m:
            return None
        
        day, time, request_type, ip, mac, hostname, message = m.groups()
        timestamp = f"{NetworkParsers._get_current_year()}-{day.zfill(2)} {time}"
        
        return {
            'timestamp': timestamp,
            'host': 'dhcp',
            'service': 'dhcp',
            'ip': ip,
            'mac': mac,
            'hostname': hostname,
            'action': request_type.lower() if request_type else 'unknown',
            'message': message.strip() if message else ''
        }

    @staticmethod
    def dns(line: str) -> Optional[Dict[str, Any]]:
        """Parse DNS query/response log line"""
        # Common DNS log formats:
        # "02-Feb-2025 12:00:00.123 queries: info: client 192.168.1.100#53 (example.com)"
        # "Feb  2 12:00:00 named[1234]: query: example.com IN A +EDC"
        
        m = re.match(
            r'^(?:(\d{2}-[A-Z][a-z]{2}-\d{4}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?)|([A-Z][a-z]{2}\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})))\s+(?:queries:|named(?:\[\d+\])?:\s+)?(?:info:\s+)?(?:client\s+(\d+\.\d+\.\d+\.\d+)#(\d+))?\s*(?:\((.+)\))?\s*(?:query:\s+)?(?:(\S+)\s+)?(?:IN\s+(\w+))?(?:\s*\+.*)?(.+)?$',
            line
        )
        if not m:
            return None
        
        if m.group(1):
            timestamp = m.group(1)
        else:
            year = NetworkParsers._get_current_year()
            month = m.group(2)
            day = m.group(3).zfill(2)
            time = m.group(4)
            timestamp = f"{day}-{month}-{year} {time}"
        
        client_ip = m.group(5)
        client_port = m.group(6)
        query_name = m.group(8)
        record_type = m.group(9)
        message = m.group(10)
        
        return {
            'timestamp': timestamp,
            'host': 'dns',
            'service': 'dns',
            'client_ip': client_ip,
            'client_port': int(client_port) if client_port else None,
            'query_name': query_name,
            'record_type': record_type,
            'message': message.strip() if message else ''
        }

    @staticmethod
    def proxy(line: str) -> Optional[Dict[str, Any]]:
        """Parse Proxy access log line"""
        # Common proxy log formats:
        # "192.168.1.100 - - [02/Feb/2025:12:00:00 +0000] \"GET http://example.com/ HTTP/1.1\" 200 1234"
        # "Squid proxy: 192.168.1.100 TCP_MISS/200 GET http://example.com - FIRSTUP_PARENT/192.168.1.1"
        
        # Try Squid format first
        m = re.match(
            r'^(\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+)\/(\d+)\s+(\S+)\s+(\S+)\s+(\S+)(?:\s+(.+))?$',
            line
        )
        if m:
            timestamp, client_ip, result, status, method, url, hierarchy = m.groups()
            return {
                'timestamp': NetworkParsers._squid_to_iso(timestamp),
                'host': 'proxy',
                'service': 'squid',
                'client_ip': client_ip,
                'result': result,
                'status': parseInt(status),
                'method': method,
                'url': url,
                'hierarchy': hierarchy,
                'message': line
            }
        
        # Try common format
        m = re.match(
            r'^(\d+\.\d+\.\d+\.\d+)\s+-\s+-\s+\[(\d{2}/[A-Z][a-z]{2}/\d{4}:\d{2}:\d{2}:\d{2}\s+[+-]\d{4})\]\s+"(\S+)\s+(\S+)\s+(\S+)"\s+(\d+)\s+(\d+)(?:\s+"([^"]+)"\s+"([^"]+)")?$',
            line
        )
        if m:
            client_ip, timestamp, method, url, protocol, status, bytes_sent, referrer, user_agent = m.groups()
            
            return {
                'timestamp': NetworkParsers._common_to_iso(timestamp),
                'host': 'proxy',
                'service': 'http_proxy',
                'client_ip': client_ip,
                'method': method,
                'url': url,
                'protocol': protocol,
                'status': parseInt(status),
                'bytes': parseInt(bytes_sent),
                'referrer': referrer,
                'user_agent': user_agent,
                'message': line
            }
        
        return None

    @staticmethod
    def _get_current_year() -> str:
        """Get current year as string"""
        from datetime import datetime
        return str(datetime.now().year)

    @staticmethod
    def _squid_to_iso(timestamp: str) -> str:
        """Convert Squid timestamp to ISO format"""
        try:
            dt = datetime.strptime(timestamp, '%Y/%m/%d %H:%M:%S')
            return dt.isoformat()
        except:
            return timestamp

    @staticmethod
    def _common_to_iso(timestamp: str) -> str:
        """Convert common log timestamp to ISO format"""
        try:
            dt = datetime.strptime(timestamp, '%d/%b/%Y:%H:%M:%S %z')
            return dt.isoformat()
        except:
            return timestamp
