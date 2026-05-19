"""Firewall Log Parsers - iptables, UFW, Windows Firewall, Enterprise firewalls, Cloud firewalls"""

import re
from datetime import datetime
from ..base import Parser
from ..types import LogType, LogEntry, Severity


class IPTablesParser(Parser):
    """Parser for iptables Log"""

    def __init__(self):
        super().__init__("iptables Log", LogType.IPTABLES)

    def detect(self, line: str) -> bool:
        return 'IPTABLES-(DROP|ACCEPT):' in line and 'SRC=' in line and 'DST=' in line

    def parse(self, line: str) -> LogEntry:
        match = re.search(
            r'^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+kernel:.*IPTABLES-(DROP|ACCEPT):\s+IN=(\S*)\s+OUT=(\S*)\s+.*SRC=(\d+\.\d+\.\d+\.\d+)\s+DST=(\d+\.\d+\.\d+\.\d+).*PROTO=(\w+)',
            line
        )
        if not match:
            return LogEntry(line, log_type=self.log_type, severity=Severity.INFO, message=line)

        timestamp, host, action, in_iface, out_iface, src_ip, dst_ip, proto = match.groups()

        timestamp_parsed = None
        try:
            timestamp_parsed = datetime.strptime(timestamp, '%b %d %H:%M:%S').replace(year=datetime.now().year).isoformat()
        except:
            pass

        # Extract ports
        src_port = None
        dst_port = None
        if 'SPT=' in line:
            spt_match = re.search(r'SPT=(\d+)', line)
            if spt_match:
                src_port = int(spt_match.group(1))
        if 'DPT=' in line:
            dpt_match = re.search(r'DPT=(\d+)', line)
            if dpt_match:
                dst_port = int(dpt_match.group(1))

        return LogEntry(
            line,
            timestamp=timestamp_parsed,
            log_type=self.log_type,
            severity=Severity.WARNING if action == 'DROP' else Severity.INFO,
            source={'hostname': host, 'service': 'iptables', 'ip': src_ip, 'port': src_port},
            destination={'ip': dst_ip, 'port': dst_port},
            action=action.lower(),
            outcome='success' if action == 'ACCEPT' else 'failure',
            message=f"{action} {proto} {src_ip} -> {dst_ip}",
            fields={
                'host': host,
                'action': action,
                'in_iface': in_iface or None,
                'out_iface': out_iface or None,
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'protocol': proto,
                'src_port': src_port,
                'dst_port': dst_port,
            },
            tags=['firewall', 'iptables', 'linux', 'network']
        )


class UFWParser(Parser):
    """Parser for UFW Log"""

    def __init__(self):
        super().__init__("UFW Log", LogType.UFW)

    def detect(self, line: str) -> bool:
        return '[UFW ALLOW]' in line or '[UFW BLOCK]' in line

    def parse(self, line: str) -> LogEntry:
        match = re.search(
            r'^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+.*\[UFW\s+(ALLOW|BLOCK)\]\s+IN=(\S*)\s+OUT=(\S*)\s+.*SRC=(\d+\.\d+\.\d+\.\d+)\s+DST=(\d+\.\d+\.\d+\.\d+)',
            line
        )
        if not match:
            return LogEntry(line, log_type=self.log_type, severity=Severity.INFO, message=line)

        timestamp, host, action, in_iface, out_iface, src_ip, dst_ip = match.groups()

        timestamp_parsed = None
        try:
            timestamp_parsed = datetime.strptime(timestamp, '%b %d %H:%M:%S').replace(year=datetime.now().year).isoformat()
        except:
            pass

        # Extract protocol and ports
        proto = None
        src_port = None
        dst_port = None
        if 'PROTO=' in line:
            proto_match = re.search(r'PROTO=(\w+)', line)
            if proto_match:
                proto = proto_match.group(1)
        if 'SPT=' in line:
            spt_match = re.search(r'SPT=(\d+)', line)
            if spt_match:
                src_port = int(spt_match.group(1))
        if 'DPT=' in line:
            dpt_match = re.search(r'DPT=(\d+)', line)
            if dpt_match:
                dst_port = int(dpt_match.group(1))

        return LogEntry(
            line,
            timestamp=timestamp_parsed,
            log_type=self.log_type,
            severity=Severity.WARNING if action == 'BLOCK' else Severity.INFO,
            source={'hostname': host, 'service': 'ufw', 'ip': src_ip, 'port': src_port},
            destination={'ip': dst_ip, 'port': dst_port},
            action=action.lower(),
            outcome='success' if action == 'ALLOW' else 'failure',
            message=f"{action} {proto or 'unknown'} {src_ip} -> {dst_ip}",
            fields={
                'host': host,
                'action': action,
                'in_iface': in_iface or None,
                'out_iface': out_iface or None,
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'protocol': proto,
                'src_port': src_port,
                'dst_port': dst_port,
            },
            tags=['firewall', 'ufw', 'linux', 'network']
        )


class WindowsFirewallParser(Parser):
    """Parser for Windows Firewall Log"""

    def __init__(self):
        super().__init__("Windows Firewall Log", LogType.WINDOWS_FIREWALL)

    def detect(self, line: str) -> bool:
        return bool(re.search(r'^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\s+(ALLOW|DROP|BLOCK)\s+(TCP|UDP|ICMP)', line))

    def parse(self, line: str) -> LogEntry:
        match = re.search(
            r'^(\d{4}-\d{2}-\d{2})\s+(\d{2}:\d{2}:\d{2})\s+(ALLOW|DROP|BLOCK)\s+(TCP|UDP|ICMP)\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+)\s+(\d+)',
            line
        )
        if not match:
            return LogEntry(line, log_type=self.log_type, severity=Severity.INFO, message=line)

        date, time, action, protocol, src_ip, dst_ip, src_port, dst_port = match.groups()

        timestamp_parsed = None
        try:
            timestamp_parsed = datetime.strptime(f"{date} {time}", '%Y-%m-%d %H:%M:%S').isoformat()
        except:
            pass

        return LogEntry(
            line,
            timestamp=timestamp_parsed,
            log_type=self.log_type,
            severity=Severity.WARNING if action in ['DROP', 'BLOCK'] else Severity.INFO,
            source={'service': 'windows_firewall', 'ip': src_ip, 'port': int(src_port)},
            destination={'ip': dst_ip, 'port': int(dst_port)},
            action=action.lower(),
            outcome='success' if action == 'ALLOW' else 'failure',
            message=f"{action} {protocol} {src_ip}:{src_port} -> {dst_ip}:{dst_port}",
            fields={
                'date': date,
                'time': time,
                'action': action,
                'protocol': protocol,
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'src_port': int(src_port),
                'dst_port': int(dst_port),
            },
            tags=['firewall', 'windows', 'network']
        )


class PaloAltoParser(Parser):
    """Parser for Palo Alto Firewall Log"""

    def __init__(self):
        super().__init__("Palo Alto Firewall Log", LogType.PALO_ALTO)

    def detect(self, line: str) -> bool:
        return bool(re.search(r'^\d{4}\/\d{2}\/\d{2}\s+\d{2}:\d{2}:\d{2}\s+(allow|deny|drop)\s+(tcp|udp|icmp)', line))

    def parse(self, line: str) -> LogEntry:
        match = re.search(
            r'^(\d{4}\/\d{2}\/\d{2})\s+(\d{2}:\d{2}:\d{2})\s+(allow|deny|drop)\s+(tcp|udp|icmp)\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)\s+rule=(\S+)',
            line
        )
        if not match:
            return LogEntry(line, log_type=self.log_type, severity=Severity.INFO, message=line)

        date, time, action, protocol, src_ip, dst_ip, rule = match.groups()

        timestamp_parsed = None
        try:
            timestamp_parsed = datetime.strptime(f"{date.replace('/', '-')} {time}", '%Y-%m-%d %H:%M:%S').isoformat()
        except:
            pass

        return LogEntry(
            line,
            timestamp=timestamp_parsed,
            log_type=self.log_type,
            severity=Severity.WARNING if action in ['deny', 'drop'] else Severity.INFO,
            source={'service': 'palo_alto', 'ip': src_ip},
            destination={'ip': dst_ip},
            action=action,
            outcome='success' if action == 'allow' else 'failure',
            message=f"{action} {protocol} {src_ip} -> {dst_ip} (rule: {rule})",
            fields={
                'date': date,
                'time': time,
                'action': action,
                'protocol': protocol,
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'rule': rule,
            },
            tags=['firewall', 'palo_alto', 'enterprise', 'network']
        )


class AWSVPCFlowParser(Parser):
    """Parser for AWS VPC Flow Logs"""

    def __init__(self):
        super().__init__("AWS VPC Flow Logs", LogType.AWS_VPC_FLOW)

    def detect(self, line: str) -> bool:
        return bool(re.search(r'^\d+\s+\d+\s+eni-\S+\s+\d+\.\d+\.\d+\.\d+\s+\d+\.\d+\.\d+\.\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+(ACCEPT|REJECT)', line))

    def parse(self, line: str) -> LogEntry:
        match = re.search(
            r'^(\d+)\s+(\d+)\s+(eni-\S+)\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(ACCEPT|REJECT)\s+(\S+)',
            line
        )
        if not match:
            return LogEntry(line, log_type=self.log_type, severity=Severity.INFO, message=line)

        groups = match.groups()
        version, account_id, interface_id, src_ip, dst_ip, src_port, dst_port, protocol, packets, bytes_count, start_time, end_time, action, status = groups

        # Convert epoch to ISO timestamp
        timestamp_parsed = None
        try:
            timestamp_parsed = datetime.fromtimestamp(int(start_time)).isoformat()
        except:
            pass

        return LogEntry(
            line,
            timestamp=timestamp_parsed,
            log_type=self.log_type,
            severity=Severity.WARNING if action == 'REJECT' else Severity.INFO,
            source={'service': 'aws_vpc', 'ip': src_ip, 'port': int(src_port)},
            destination={'ip': dst_ip, 'port': int(dst_port)},
            action=action.lower(),
            outcome='success' if action == 'ACCEPT' else 'failure',
            message=f"{action} {src_ip}:{src_port} -> {dst_ip}:{dst_port}",
            fields={
                'version': int(version),
                'account_id': account_id,
                'interface_id': interface_id,
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'src_port': int(src_port),
                'dst_port': int(dst_port),
                'protocol': int(protocol),
                'packets': int(packets),
                'bytes': int(bytes_count),
                'start_time': int(start_time),
                'end_time': int(end_time),
                'action': action,
                'status': status,
            },
            tags=['firewall', 'aws', 'vpc', 'cloud', 'network']
        )


class NFTablesParser(Parser):
    """Parser for nftables Log"""

    def __init__(self):
        super().__init__("nftables Log", LogType.NFTABLES)

    def detect(self, line: str) -> bool:
        return 'nftables:' in line and ('accept' in line or 'drop' in line or 'reject' in line)

    def parse(self, line: str) -> LogEntry:
        match = re.search(
            r'^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+kernel:.*nftables:\s+rule\s+(accept|drop|reject)\s+.*(tcp|udp|icmp)',
            line, re.IGNORECASE
        )
        if not match:
            return LogEntry(line, log_type=self.log_type, severity=Severity.INFO, message=line)

        timestamp, host, action, protocol = match.groups()

        timestamp_parsed = None
        try:
            timestamp_parsed = datetime.strptime(timestamp, '%b %d %H:%M:%S').replace(year=datetime.now().year).isoformat()
        except:
            pass

        return LogEntry(
            line,
            timestamp=timestamp_parsed,
            log_type=self.log_type,
            severity=Severity.WARNING if action in ['drop', 'reject'] else Severity.INFO,
            source={'hostname': host, 'service': 'nftables'},
            action=action.lower(),
            outcome='success' if action == 'accept' else 'failure',
            message=f'nftables {action} {protocol}',
            fields={
                'host': host,
                'action': action,
                'protocol': protocol,
            },
            tags=['firewall', 'nftables', 'linux', 'network']
        )


class FirewalldParser(Parser):
    """Parser for firewalld Log"""

    def __init__(self):
        super().__init__("firewalld Log", LogType.FIREWALLD)

    def detect(self, line: str) -> bool:
        return 'firewalld:' in line and any(level in line for level in ['INFO', 'WARNING', 'ERROR'])

    def parse(self, line: str) -> LogEntry:
        match = re.search(
            r'^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+firewalld:\s+(INFO|WARNING|ERROR):\s+(.*)',
            line
        )
        if not match:
            return LogEntry(line, log_type=self.log_type, severity=Severity.INFO, message=line)

        timestamp, host, level, message = match.groups()

        timestamp_parsed = None
        try:
            timestamp_parsed = datetime.strptime(timestamp, '%b %d %H:%M:%S').replace(year=datetime.now().year).isoformat()
        except:
            pass

        severity = Severity.ERROR if level == 'ERROR' else Severity.WARNING if level == 'WARNING' else Severity.INFO

        return LogEntry(
            line,
            timestamp=timestamp_parsed,
            log_type=self.log_type,
            severity=severity,
            source={'hostname': host, 'service': 'firewalld'},
            message=message,
            fields={
                'host': host,
                'level': level,
            },
            tags=['firewall', 'firewalld', 'linux']
        )


class FortiGateParser(Parser):
    """Parser for FortiGate Firewall Log"""

    def __init__(self):
        super().__init__("FortiGate Firewall Log", LogType.FORTIGATE)

    def detect(self, line: str) -> bool:
        return 'action=' in line and any(action in line for action in ['allow', 'deny'])

    def parse(self, line: str) -> LogEntry:
        date_match = re.search(r'date=(\d{4}-\d{2}-\d{2})', line)
        time_match = re.search(r'time=(\d{2}:\d{2}:\d{2})', line)
        action_match = re.search(r'action=(allow|deny)', line)
        src_ip_match = re.search(r'srcip=(\d+\.\d+\.\d+\.\d+)', line)
        dst_ip_match = re.search(r'dstip=(\d+\.\d+\.\d+\.\d+)', line)
        src_port_match = re.search(r'srcport=(\d+)', line)
        dst_port_match = re.search(r'dstport=(\d+)', line)
        proto_match = re.search(r'proto=(\d+)', line)

        if not date_match or not action_match:
            return LogEntry(line, log_type=self.log_type, severity=Severity.INFO, message=line)

        action = action_match.group(1)

        timestamp_parsed = None
        try:
            time_str = time_match.group(1) if time_match else '00:00:00'
            timestamp_parsed = datetime.strptime(f"{date_match.group(1)} {time_str}", '%Y-%m-%d %H:%M:%S').isoformat()
        except:
            pass

        return LogEntry(
            line,
            timestamp=timestamp_parsed,
            log_type=self.log_type,
            severity=Severity.WARNING if action == 'deny' else Severity.INFO,
            source={
                'service': 'fortigate',
                'ip': src_ip_match.group(1) if src_ip_match else None,
                'port': int(src_port_match.group(1)) if src_port_match else None
            },
            destination={
                'ip': dst_ip_match.group(1) if dst_ip_match else None,
                'port': int(dst_port_match.group(1)) if dst_port_match else None
            },
            action=action,
            outcome='success' if action == 'allow' else 'failure',
            message=f"{action} {src_ip_match.group(1) if src_ip_match else 'unknown'} -> {dst_ip_match.group(1) if dst_ip_match else 'unknown'}",
            fields={
                'date': date_match.group(1),
                'time': time_match.group(1) if time_match else None,
                'action': action,
                'src_ip': src_ip_match.group(1) if src_ip_match else None,
                'dst_ip': dst_ip_match.group(1) if dst_ip_match else None,
                'src_port': int(src_port_match.group(1)) if src_port_match else None,
                'dst_port': int(dst_port_match.group(1)) if dst_port_match else None,
                'protocol': int(proto_match.group(1)) if proto_match else None,
            },
            tags=['firewall', 'fortigate', 'enterprise', 'network']
        )


class CiscoASAParser(Parser):
    """Parser for Cisco ASA Firewall Log"""

    def __init__(self):
        super().__init__("Cisco ASA Firewall Log", LogType.CISCO_ASA)

    def detect(self, line: str) -> bool:
        return '%ASA-' in line

    def parse(self, line: str) -> LogEntry:
        match = re.search(
            r'^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+%ASA-(\d+)-(\d+):\s+access-list\s+(\S+)\s+(denied|permitted)\s+(tcp|udp|icmp)\s+\S+\/(\d+\.\d+\.\d+\.\d+)(?:\((\d+)\))?\s+.*?(\d+\.\d+\.\d+\.\d+)(?:\((\d+)\))?',
            line
        )
        if not match:
            return LogEntry(line, log_type=self.log_type, severity=Severity.INFO, message=line)

        groups = match.groups()
        timestamp, host, severity, msg_id, acl, action, protocol, src_ip, src_port, dst_ip, dst_port = groups

        timestamp_parsed = None
        try:
            timestamp_parsed = datetime.strptime(timestamp, '%b %d %H:%M:%S').replace(year=datetime.now().year).isoformat()
        except:
            pass

        return LogEntry(
            line,
            timestamp=timestamp_parsed,
            log_type=self.log_type,
            severity=Severity.WARNING if action == 'denied' else Severity.INFO,
            source={
                'hostname': host,
                'service': 'cisco_asa',
                'ip': src_ip,
                'port': int(src_port) if src_port else None
            },
            destination={
                'ip': dst_ip,
                'port': int(dst_port) if dst_port else None
            },
            action='allow' if action == 'permitted' else 'deny',
            outcome='success' if action == 'permitted' else 'failure',
            message=f"{action} {protocol} {src_ip} -> {dst_ip}",
            fields={
                'host': host,
                'asa_severity': int(severity),
                'message_id': int(msg_id),
                'acl': acl,
                'action': action,
                'protocol': protocol,
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'src_port': int(src_port) if src_port else None,
                'dst_port': int(dst_port) if dst_port else None,
            },
            tags=['firewall', 'cisco_asa', 'enterprise', 'network']
        )


class CheckPointParser(Parser):
    """Parser for Check Point Firewall Log"""

    def __init__(self):
        super().__init__("Check Point Firewall Log", LogType.CHECKPOINT)

    def detect(self, line: str) -> bool:
        return bool(re.search(r'^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\s+(accept|drop|reject)\s+(TCP|UDP|ICMP)\s+src=', line))

    def parse(self, line: str) -> LogEntry:
        match = re.search(
            r'^(\d{4}-\d{2}-\d{2})\s+(\d{2}:\d{2}:\d{2})\s+(accept|drop|reject)\s+(TCP|UDP|ICMP)\s+src=(\d+\.\d+\.\d+\.\d+)\s+dst=(\d+\.\d+\.\d+\.\d+)\s+rule=(\S+)',
            line
        )
        if not match:
            return LogEntry(line, log_type=self.log_type, severity=Severity.INFO, message=line)

        date, time, action, protocol, src_ip, dst_ip, rule = match.groups()

        timestamp_parsed = None
        try:
            timestamp_parsed = datetime.strptime(f"{date} {time}", '%Y-%m-%d %H:%M:%S').isoformat()
        except:
            pass

        return LogEntry(
            line,
            timestamp=timestamp_parsed,
            log_type=self.log_type,
            severity=Severity.WARNING if action in ['drop', 'reject'] else Severity.INFO,
            source={'service': 'checkpoint', 'ip': src_ip},
            destination={'ip': dst_ip},
            action=action,
            outcome='success' if action == 'accept' else 'failure',
            message=f"{action} {protocol} {src_ip} -> {dst_ip} (rule: {rule})",
            fields={
                'date': date,
                'time': time,
                'action': action,
                'protocol': protocol,
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'rule': rule,
            },
            tags=['firewall', 'checkpoint', 'enterprise', 'network']
        )


class AzureNSGParser(Parser):
    """Parser for Azure NSG Flow Logs"""

    def __init__(self):
        super().__init__("Azure NSG Flow Logs", LogType.AZURE_NSG)

    def detect(self, line: str) -> bool:
        try:
            import json
            j = json.loads(line)
            return bool(j.get('time') and j.get('properties', {}).get('flows'))
        except:
            return False

    def parse(self, line: str) -> LogEntry:
        try:
            import json
            j = json.loads(line)
            if not (j.get('time') and j.get('properties', {}).get('flows')):
                return LogEntry(line, log_type=self.log_type, severity=Severity.INFO, message=line)

            return LogEntry(
                line,
                timestamp=j.get('time'),
                log_type=self.log_type,
                severity=Severity.INFO,
                source={'service': 'azure_nsg'},
                message='Azure NSG Flow Log',
                fields=j,  # Include all JSON fields
                tags=['firewall', 'azure', 'nsg', 'cloud', 'network']
            )
        except:
            return LogEntry(line, log_type=self.log_type, severity=Severity.INFO, message=line)


class GCPVPCParser(Parser):
    """Parser for GCP VPC Firewall Log"""

    def __init__(self):
        super().__init__("GCP VPC Firewall Log", LogType.GCP_VPC)

    def detect(self, line: str) -> bool:
        return bool(re.search(r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\s+(allow|deny)\s+(tcp|udp|icmp)', line))

    def parse(self, line: str) -> LogEntry:
        match = re.search(
            r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)\s+(allow|deny)\s+(tcp|udp|icmp)\s+(\d+\.\d+\.\d+\.\d+):(\d+)\s+(\d+\.\d+\.\d+\.\d+):(\d+)',
            line
        )
        if not match:
            return LogEntry(line, log_type=self.log_type, severity=Severity.INFO, message=line)

        timestamp, action, protocol, src_ip, src_port, dst_ip, dst_port = match.groups()

        return LogEntry(
            line,
            timestamp=timestamp,
            log_type=self.log_type,
            severity=Severity.WARNING if action == 'deny' else Severity.INFO,
            source={'service': 'gcp_vpc', 'ip': src_ip, 'port': int(src_port)},
            destination={'ip': dst_ip, 'port': int(dst_port)},
            action=action,
            outcome='success' if action == 'allow' else 'failure',
            message=f"{action} {protocol} {src_ip}:{src_port} -> {dst_ip}:{dst_port}",
            fields={
                'timestamp': timestamp,
                'action': action,
                'protocol': protocol,
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'src_port': int(src_port),
                'dst_port': int(dst_port),
            },
            tags=['firewall', 'gcp', 'cloud', 'network']
        )


# Export all firewall parsers
PARSERS = [
    IPTablesParser(),
    UFWParser(),
    NFTablesParser(),
    FirewalldParser(),
    WindowsFirewallParser(),
    PaloAltoParser(),
    FortiGateParser(),
    CiscoASAParser(),
    CheckPointParser(),
    AWSVPCFlowParser(),
    AzureNSGParser(),
    GCPVPCParser(),
]