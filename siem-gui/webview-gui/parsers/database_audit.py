"""
Database Audit Log Parsers - MongoDB Audit, Oracle Audit, SQLServer Audit
"""

import re
import json
from typing import Optional, Dict, Any


class DatabaseAuditParsers:
    """ISEA-style database audit log parsers"""

    @staticmethod
    def mongodb_audit(line: str) -> Optional[Dict[str, Any]]:
        """Parse MongoDB audit log (JSON format)"""
        try:
            data = line.strip()
            if not data.startswith('{'):
                return None
            
            audit = json.loads(data)
            
            if 'atype' not in audit and 'ts' not in audit:
                return None
            
            return {
                'timestamp': audit.get('ts') or audit.get('localTime'),
                'host': audit.get('host'),
                'service': 'mongodb',
                'event_type': audit.get('atype'),
                'action': audit.get('action'),
                'database': audit.get('param', {}).get('db'),
                'collection': audit.get('param', {}).get('coll'),
                'user': audit.get('user'),
                'ip': audit.get('ip'),
                'message': str(audit)
            }
        except:
            return None

    @staticmethod
    def oracle_audit(line: str) -> Optional[Dict[str, Any]]:
        """Parse Oracle audit log"""
        # Oracle audit can be in various formats:
        # "Audit record generated at 2025-02-02 12:00:00"
        # "ACTION : CONNECT, USERID : SCOTT, OSUSER : oracle"
        
        m = re.match(
            r'^Audit record generated at (\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})',
            line
        )
        if m:
            return {
                'timestamp': m.group(1),
                'host': 'oracle',
                'service': 'oracle',
                'event_type': 'audit_record',
                'message': line
            }
        
        # Parse ACTION details
        m = re.match(
            r'ACTION\s*:\s*(\w+)(?:,\s*USERID\s*:\s*(\w+))?(?:,\s*OSUSER\s*:\s*(\S+))?(?:,\s*TERMINAL\s*:\s*(\S+))?(?:,\s*STATUS\s*:\s*(\w+))?',
            line
        )
        if m:
            action, userid, osuser, terminal, status = m.groups()
            return {
                'timestamp': None,
                'host': 'oracle',
                'service': 'oracle',
                'event_type': action,
                'user': userid,
                'os_user': osuser,
                'terminal': terminal,
                'status': status,
                'message': line
            }
        
        return None

    @staticmethod
    def oracle_listener(line: str) -> Optional[Dict[str, Any]]:
        """Parse Oracle TNS Listener log"""
        # TNS Listener format:
        # "02-FEB-2025 12:00:00 * (CONNECT_DATA=(SID=ORCL)(HOST=localhost)(PORT=1521)) * (ADDRESS=(PROTOCOL=tcp)(HOST=127.0.0.1)(PORT=12345)) * establish * ORCL * 0"
        
        m = re.match(
            r'^(\d{2}-[A-Z]{3}-\d{4}\s+\d{2}:\d{2}:\d{2})\s+\*\s+\((CONNECT_DATA=.+?)\)\s+\*\s+\((ADDRESS=.+?)\)\s+\*\s+(\w+)(?:\s+\*\s+(\w+))?(?:\s+\*\s+(\d+))?$',
            line
        )
        if not m:
            return None
        
        timestamp, connectData, address, operation, service, error = m.groups()
        
        # Parse CONNECT_DATA
        connMatch = re.search(r'SID=(\w+)', connectData)
        sid = connMatch.group(1) if connMatch else None
        
        # Parse ADDRESS
        addrMatch = re.search(r'HOST=(\d+\.\d+\.\d+\.\d+)', address)
        host = addrMatch.group(1) if addrMatch else None
        portMatch = re.search(r'PORT=(\d+)', address)
        port = int(portMatch.group(1)) if portMatch else None
        
        return {
            'timestamp': timestamp,
            'host': 'oracle',
            'service': 'tnslsnr',
            'sid': sid,
            'client_ip': host,
            'client_port': port,
            'operation': operation,
            'service_name': service,
            'error_code': int(error) if error and error.isdigit() else None,
            'message': line
        }

    @staticmethod
    def sqlserver_audit(line: str) -> Optional[Dict[str, Any]]:
        """Parse SQL Server audit log"""
        # SQL Server audit format:
        # "2025-02-02 12:00:00.123 ServerAuditEvent     SUCCESSFUL_LOGIN   login success"
        
        m = re.match(
            r'^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+(\w+)\s+(\w+)\s+(.+)$',
            line
        )
        if not m:
            return None
        
        timestamp, eventSource, action, details = m.groups()
        
        return {
            'timestamp': timestamp,
            'host': 'sqlserver',
            'service': 'sqlserver',
            'event_source': eventSource,
            'action': action,
            'details': details,
            'message': line
        }

    @staticmethod
    def sqlserver_transaction(line: str) -> Optional[Dict[str, Any]]:
        """Parse SQL Server transaction log entry"""
        # Transaction log typically shows operations
        # "Transaction ID: 0000:12345678 Operation: LOP_BEGIN_XACT"
        
        m = re.match(
            r'^Transaction ID:\s+([0-9A-F:]+)\s+Operation:\s+(\w+)(?:\s+LOP_MODIFY_ROW)?(?:\s+Context:\s*(.+))?$',
            line
        )
        if not m:
            return None
        
        transactionId, operation, context = m.groups()
        
        return {
            'timestamp': None,
            'host': 'sqlserver',
            'service': 'sqlserver_transaction',
            'transaction_id': transactionId,
            'operation': operation,
            'context': context,
            'message': line
        }
