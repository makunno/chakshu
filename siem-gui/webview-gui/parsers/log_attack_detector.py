"""
Log Attack Detector - Log-type-specific attack pattern detection
Python version matching the TypeScript implementation
"""

import re
from typing import Dict, List, Optional, Tuple, Set
from dataclasses import dataclass
from enum import Enum


class AttackType(Enum):
    """Attack types supported by the detector"""
    SQL_INJECTION = "sql_injection"
    XSS_ATTACK = "xss_attack"
    COMMAND_INJECTION = "command_injection"
    PATH_TRAVERSAL = "path_traversal"
    SSRF_ATTACK = "ssrf_attack"
    XXE_ATTACK = "xxe_attack"
    LDAP_INJECTION = "ldap_injection"
    DESERIALIZATION = "deserialization"
    LOG4SHELL = "log4shell"
    PROTOTYPE_POLLUTION = "prototype_pollution"
    FILE_INCLUSION = "file_inclusion"
    WEBSHELL = "webshell"
    BRUTEFORCE = "bruteforce"
    PASSWORD_SPRAY = "password_spray"
    CREDENTIAL_STUFFING = "credential_stuffing"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    LATERAL_MOVEMENT = "lateral_movement"
    ACCOUNT_TAKEOVER = "account_takeover"
    KERBEROASTING = "kerberoasting"
    PASS_THE_HASH = "pass_the_hash"
    PORT_SCAN = "port_scan"
    DDOS = "ddos"
    RECONNAISSANCE = "reconnaissance"
    C2_COMMUNICATION = "c2_communication"
    DATA_EXFILTRATION = "data_exfiltration"
    MALWARE_ACTIVITY = "malware_activity"
    CRYPTOMINING = "cryptomining"
    RANSOMWARE = "ransomware"
    INSIDER_THREAT = "insider_threat"
    SUPPLY_CHAIN = "supply_chain"
    DNS_TUNNELING = "dns_tunneling"
    UNKNOWN = "unknown"


class LogTypeCategory(Enum):
    """Log type categories for attack detection"""
    WEBSERVER = "webserver"
    AUTHENTICATION = "authentication"
    FIREWALL = "firewall"
    DATABASE = "database"
    MAIL = "mail"
    SYSLOG = "syslog"
    CLOUD = "cloud"
    SECURITY = "security"
    GENERIC = "generic"


def get_log_type_category(log_type: str) -> LogTypeCategory:
    """Map detected log type to category"""
    lower_type = log_type.lower()
    
    # Web servers
    if re.search(r'apache|nginx|iis|express|django|flask|fastapi|laravel|rails|gunicorn|uvicorn|node|caddy|haproxy|spring|asp\.net', lower_type):
        return LogTypeCategory.WEBSERVER
    
    # Authentication
    if re.search(r'ssh|auth|login|sshd|windows.*security', lower_type):
        return LogTypeCategory.AUTHENTICATION
    
    # Firewall
    if re.search(r'firewall|iptables|ufw|nftables|palo|fortigate|cisco|checkpoint|aws.*vpc|azure.*nsg|gcp.*vpc', lower_type):
        return LogTypeCategory.FIREWALL
    
    # Database
    if re.search(r'mysql|postgres|oracle|sql.*server|mongodb', lower_type):
        return LogTypeCategory.DATABASE
    
    # Mail
    if re.search(r'postfix|sendmail|exim|dovecot|courier|exchange|smtp|mail', lower_type):
        return LogTypeCategory.MAIL
    
    # Cloud
    if re.search(r'cloudtrail|guardduty|azure.*activity|gcp.*audit|kubernetes|docker', lower_type):
        return LogTypeCategory.CLOUD
    
    # Security tools
    if re.search(r'suricata|zeek|ossec|fail2ban', lower_type):
        return LogTypeCategory.SECURITY
    
    # Syslog/Daemon
    if re.search(r'syslog|systemd|kernel|audit', lower_type):
        return LogTypeCategory.SYSLOG
    
    return LogTypeCategory.GENERIC


@dataclass
class AttackDetection:
    """Attack detection result for a single log entry"""
    attack_type: AttackType
    confidence: float
    mitre_tactics: List[str]
    mitre_techniques: List[str]
    matched_patterns: List[str]


# MITRE ATT&CK mapping
MITRE_MAPPING = {
    AttackType.SQL_INJECTION: {"tactics": ["TA0006"], "techniques": ["T1190"]},
    AttackType.XSS_ATTACK: {"tactics": ["TA0006"], "techniques": ["T1189"]},
    AttackType.COMMAND_INJECTION: {"tactics": ["TA0002"], "techniques": ["T1059"]},
    AttackType.PATH_TRAVERSAL: {"tactics": ["TA0006"], "techniques": ["T1083"]},
    AttackType.SSRF_ATTACK: {"tactics": ["TA0001"], "techniques": ["T1190"]},
    AttackType.XXE_ATTACK: {"tactics": ["TA0001"], "techniques": ["T1059"]},
    AttackType.LDAP_INJECTION: {"tactics": ["TA0006"], "techniques": ["T1213"]},
    AttackType.DESERIALIZATION: {"tactics": ["TA0001"], "techniques": ["T1059"]},
    AttackType.LOG4SHELL: {"tactics": ["TA0001"], "techniques": ["T1190", "T1059"]},
    AttackType.PROTOTYPE_POLLUTION: {"tactics": ["TA0001"], "techniques": ["T1059"]},
    AttackType.FILE_INCLUSION: {"tactics": ["TA0001"], "techniques": ["T1190"]},
    AttackType.WEBSHELL: {"tactics": ["TA0003"], "techniques": ["T1505.003"]},
    AttackType.BRUTEFORCE: {"tactics": ["TA0006"], "techniques": ["T1110"]},
    AttackType.PASSWORD_SPRAY: {"tactics": ["TA0006"], "techniques": ["T1110.003"]},
    AttackType.CREDENTIAL_STUFFING: {"tactics": ["TA0006"], "techniques": ["T1110.004"]},
    AttackType.PRIVILEGE_ESCALATION: {"tactics": ["TA0004"], "techniques": ["T1078"]},
    AttackType.LATERAL_MOVEMENT: {"tactics": ["TA0008"], "techniques": ["T1021"]},
    AttackType.ACCOUNT_TAKEOVER: {"tactics": ["TA0006"], "techniques": ["T1098"]},
    AttackType.KERBEROASTING: {"tactics": ["TA0006"], "techniques": ["T1558.003"]},
    AttackType.PASS_THE_HASH: {"tactics": ["TA0008"], "techniques": ["T1550.002"]},
    AttackType.PORT_SCAN: {"tactics": ["TA0043"], "techniques": ["T1595.001"]},
    AttackType.DDOS: {"tactics": ["TA0040"], "techniques": ["T1498"]},
    AttackType.RECONNAISSANCE: {"tactics": ["TA0043"], "techniques": ["T1595"]},
    AttackType.C2_COMMUNICATION: {"tactics": ["TA0011"], "techniques": ["T1071"]},
    AttackType.DATA_EXFILTRATION: {"tactics": ["TA0010"], "techniques": ["T1041"]},
    AttackType.MALWARE_ACTIVITY: {"tactics": ["TA0002"], "techniques": ["T1204"]},
    AttackType.CRYPTOMINING: {"tactics": ["TA0004"], "techniques": ["T1496"]},
    AttackType.RANSOMWARE: {"tactics": ["TA0040"], "techniques": ["T1486"]},
    AttackType.INSIDER_THREAT: {"tactics": ["TA0004"], "techniques": ["T1078"]},
    AttackType.SUPPLY_CHAIN: {"tactics": ["TA0001"], "techniques": ["T1195"]},
    AttackType.DNS_TUNNELING: {"tactics": ["TA0010"], "techniques": ["T1071.004"]},
}


# Log-type-specific attack patterns organized by category
LOG_TYPE_ATTACK_PATTERNS: Dict[LogTypeCategory, Dict[AttackType, Dict]] = {
    LogTypeCategory.WEBSERVER: {
        AttackType.SQL_INJECTION: {
            "patterns": [
                re.compile(r"('|\"|%27|%22)\s*(OR|AND)\s*('|\"|%27|%22)\s*\d*\s*=\s*('|\"|%27|%22)\s*\d*", re.I),
                re.compile(r"(\bUNION\b.*\bSELECT\b|\bSELECT\b.*\bFROM\b)", re.I),
                re.compile(r";\s*(DROP|DELETE|INSERT|UPDATE|EXEC|EXECUTE)\s+", re.I),
                re.compile(r"(\bWAITFOR\b|\bDELAY\b|\bSLEEP\b|\bBENCHMARK\b)", re.I),
                re.compile(r"(INFORMATION_SCHEMA|sys\.(tables|columns|objects)|pg_catalog)", re.I),
            ],
            "weight": 0.9,
        },
        AttackType.XSS_ATTACK: {
            "patterns": [
                re.compile(r"<script[^>]*>.*?</script>", re.I),
                re.compile(r"javascript:", re.I),
                re.compile(r"on\w+\s*=\s*['\"]*[^'\">\s]+", re.I),
                re.compile(r"<iframe[^>]*src\s*=\s*['\"]*javascript:", re.I),
                re.compile(r"<svg[^>]*onload\s*=", re.I),
                re.compile(r"(document\.(cookie|location|write)|window\.location)", re.I),
                re.compile(r"eval\s*\(|setTimeout\s*\(|setInterval\s*\(", re.I),
            ],
            "weight": 0.85,
        },
        AttackType.COMMAND_INJECTION: {
            "patterns": [
                re.compile(r"[;|`]\s*(cat|ls|pwd|whoami|id|uname|wget|curl|nc|bash|sh|python|perl)\s", re.I),
                re.compile(r"\$\([^)]*\)|`[^`]*`|\$\{[^}]*\}"),
                re.compile(r"(chmod|chown|rm\s+-rf|mkdir|rmdir)\s+", re.I),
                re.compile(r"(/bin/sh|/bin/bash|/bin/python|cmd\.exe|powershell)", re.I),
            ],
            "weight": 0.9,
        },
        AttackType.PATH_TRAVERSAL: {
            "patterns": [
                re.compile(r"\.\.(\/|\\|%2f|%5c|%252f|%255c)", re.I),
                re.compile(r"(%2e%2e|%252e%252e)", re.I),
                re.compile(r"(/etc/passwd|/etc/shadow|/etc/hosts|/proc/self)", re.I),
                re.compile(r"(c:\\windows|c:\\boot\.ini|c:\\system32|c:\\inetpub)", re.I),
            ],
            "weight": 0.8,
        },
        AttackType.SSRF_ATTACK: {
            "patterns": [
                re.compile(r"(169\.254\.169\.254|metadata\.google\.internal|169-254-169-254)", re.I),
                re.compile(r"\?.*(url|uri|path|dest|redirect|next)\s*=\s*https?:", re.I),
                re.compile(r"(file://|gopher://|dict://|ftp://|ldap://)", re.I),
                re.compile(r"(127\.0\.0\.1|localhost|0\.0\.0\.0|\[::\]|0x7f\.)", re.I),
            ],
            "weight": 0.85,
        },
        AttackType.XXE_ATTACK: {
            "patterns": [
                re.compile(r"<!ENTITY\s+[^>]+\s+SYSTEM\s+[\"'][^\"']+[\"']", re.I),
                re.compile(r"<!DOCTYPE\s+[^>]+\s+\[\s*<!ENTITY", re.I),
                re.compile(r"(file://|expect://|php://filter|http://)", re.I),
            ],
            "weight": 0.85,
        },
        AttackType.LOG4SHELL: {
            "patterns": [
                re.compile(r"\$\{jndi:(ldap|ldaps|rmi|dns|iiop)://", re.I),
                re.compile(r"\$\{\$\{[^}]*:-[^}]*\}"),
                re.compile(r"\$\{\s*lower\s*:\s*j\s*\}\s*\{\s*lower\s*:\s*n", re.I),
            ],
            "weight": 0.98,
        },
        AttackType.DESERIALIZATION: {
            "patterns": [
                re.compile(r"(rO0|ysoserial|gadgetchain)", re.I),
                re.compile(r"(\xac\xed\x00\x05|H4sIAAAAAAAA)"),
            ],
            "weight": 0.9,
        },
        AttackType.WEBSHELL: {
            "patterns": [
                re.compile(r"(c99|r57|b374k|wso|weevely|alfa|p0wny|mini.*shell)", re.I),
                re.compile(r"\.(php|asp|aspx|jsp)\?cmd=|\?exec=|\?shell=", re.I),
                re.compile(r"eval\s*\(\s*\$_(GET|POST)|system\s*\(\s*\$|passthru\s*\(\s*\$", re.I),
            ],
            "weight": 0.85,
        },
        AttackType.BRUTEFORCE: {
            "patterns": [
                re.compile(r"(401|403)\s+.*/login|Failed\s+password|Authentication\s+failure", re.I),
            ],
            "weight": 0.6,
        },
        AttackType.RECONNAISSANCE: {
            "patterns": [
                re.compile(r"(/\.env|/config\.json|/\.git/|/\.htaccess|/phpinfo)", re.I),
                re.compile(r"(nikto|sqlmap|nmap|masscan|zgrab|nuclei|dirbuster|gobuster)", re.I),
            ],
            "weight": 0.7,
        },
    },
    
    LogTypeCategory.AUTHENTICATION: {
        AttackType.BRUTEFORCE: {
            "patterns": [
                re.compile(r"Failed\s+password|Authentication\s+failure|Invalid\s+user|Failed\s+login", re.I),
            ],
            "weight": 0.75,
        },
        AttackType.PASSWORD_SPRAY: {
            "patterns": [
                re.compile(r"(Authentication\s+failure|Invalid\s+user|Unknown\s+user)", re.I),
            ],
            "weight": 0.65,
        },
        AttackType.CREDENTIAL_STUFFING: {
            "patterns": [
                re.compile(r"(Account\s+locked|Too\s+many\s+attempts|Rate\s+limit)", re.I),
            ],
            "weight": 0.7,
        },
        AttackType.PRIVILEGE_ESCALATION: {
            "patterns": [
                re.compile(r"(sudo|su\s+-|sudo\s+-i|sudo\s+su|sudo\s+.*ALL)", re.I),
                re.compile(r"(SetUser|Privilege\s+escalation|Admin\s+access)", re.I),
                re.compile(r"(useradd|usermod|passwd\s+root)", re.I),
            ],
            "weight": 0.8,
        },
        AttackType.LATERAL_MOVEMENT: {
            "patterns": [
                re.compile(r"(psexec|wmiexec|smbexec|pass\s+the\s+hash)", re.I),
                re.compile(r"(ssh.*from.*to|scp\s+.*\s+\S+@\S+:\s*)", re.I),
            ],
            "weight": 0.75,
        },
        AttackType.ACCOUNT_TAKEOVER: {
            "patterns": [
                re.compile(r"(impossible\s+travel|unusual\s+location|new\s+device)", re.I),
                re.compile(r"(suspicious\s+login|account.*compromised)", re.I),
            ],
            "weight": 0.75,
        },
        AttackType.KERBEROASTING: {
            "patterns": [
                re.compile(r"(4768.*0x12|4769.*0x17)", re.I),
                re.compile(r"(krbtgt|ticket_granting|AS-REQ|TGS-REQ)", re.I),
            ],
            "weight": 0.8,
        },
        AttackType.PASS_THE_HASH: {
            "patterns": [
                re.compile(r"(NTLM.*hash|pass.the.hash|mimikatz|rubeus)", re.I),
            ],
            "weight": 0.8,
        },
    },
    
    LogTypeCategory.FIREWALL: {
        AttackType.PORT_SCAN: {
            "patterns": [
                re.compile(r"(Connection\s+(refused|timed\s+out)|No\s+route\s+to\s+host)", re.I),
                re.compile(r"(SYN\s+scan|PORT\s+scan|nmap|masscan)", re.I),
                re.compile(r"multiple\s+ports?\s+scanned", re.I),
            ],
            "weight": 0.75,
        },
        AttackType.DDOS: {
            "patterns": [
                re.compile(r"(Connection\s+reset\s+by\s+peer|Too\s+many\s+connections)", re.I),
                re.compile(r"(flood|rate\s+limit\s+exceeded|syn\s+flood)", re.I),
            ],
            "weight": 0.8,
        },
        AttackType.RECONNAISSANCE: {
            "patterns": [
                re.compile(r"(scan|probe|enumerate|discover)", re.I),
            ],
            "weight": 0.65,
        },
        AttackType.C2_COMMUNICATION: {
            "patterns": [
                re.compile(r"(beacon|heartbeat|check-in|command.*control)", re.I),
                re.compile(r"dns\s+tunnel|dga|domain\s+generation", re.I),
            ],
            "weight": 0.7,
        },
        AttackType.DATA_EXFILTRATION: {
            "patterns": [
                re.compile(r"(large\s+data\s+transfer|bulk\s+upload|unusual\s+outbound)", re.I),
            ],
            "weight": 0.7,
        },
        AttackType.LATERAL_MOVEMENT: {
            "patterns": [
                re.compile(r"(internal\s+to\s+internal|east-west\s+traffic)", re.I),
            ],
            "weight": 0.7,
        },
    },
    
    LogTypeCategory.DATABASE: {
        AttackType.SQL_INJECTION: {
            "patterns": [
                re.compile(r"(\bUNION\b.*\bSELECT\b|\bSELECT\b.*\bFROM\b)", re.I),
                re.compile(r";\s*(DROP|DELETE|INSERT|UPDATE|EXEC|EXECUTE)\s+", re.I),
                re.compile(r"(INFORMATION_SCHEMA|sys\.(tables|columns|objects)|pg_catalog)", re.I),
                re.compile(r"(\bWAITFOR\b|\bDELAY\b|\bBENCHMARK\b|\bSLEEP\b)", re.I),
            ],
            "weight": 0.95,
        },
        AttackType.DATA_EXFILTRATION: {
            "patterns": [
                re.compile(r"(SELECT\s+.*\s+INTO\s+OUTFILE|COPY\s+.*\s+TO\s+)", re.I),
                re.compile(r"(bulk\s+select|bcp\s+.*\s+out)", re.I),
            ],
            "weight": 0.8,
        },
        AttackType.PRIVILEGE_ESCALATION: {
            "patterns": [
                re.compile(r"(GRANT\s+ALL|ALTER\s+USER.*WITH\s+ADMIN)", re.I),
                re.compile(r"(CREATE\s+USER|ADD\s+MEMBER\s+TO\s+ROLE)", re.I),
            ],
            "weight": 0.75,
        },
        AttackType.INSIDER_THREAT: {
            "patterns": [
                re.compile(r"(unauthorized.*access|sensitive.*table|customer.*data)", re.I),
            ],
            "weight": 0.7,
        },
    },
    
    LogTypeCategory.MAIL: {
        AttackType.BRUTEFORCE: {
            "patterns": [
                re.compile(r"(authentication\s+failed|login\s+failed|535|530)", re.I),
            ],
            "weight": 0.7,
        },
        AttackType.DATA_EXFILTRATION: {
            "patterns": [
                re.compile(r"(large\s+attachment|bulk\s+email|mass\s+mailing)", re.I),
            ],
            "weight": 0.65,
        },
        AttackType.C2_COMMUNICATION: {
            "patterns": [
                re.compile(r"(suspicious\s+attachment|executable.*email|macro)", re.I),
            ],
            "weight": 0.75,
        },
        AttackType.RECONNAISSANCE: {
            "patterns": [
                re.compile(r"(user\s+enumeration|verify\s+email|rcpt\s+to.*multiple)", re.I),
            ],
            "weight": 0.6,
        },
    },
    
    LogTypeCategory.SYSLOG: {
        AttackType.PRIVILEGE_ESCALATION: {
            "patterns": [
                re.compile(r"(sudo|su\s+-|sudo\s+-i|sudo\s+su)", re.I),
                re.compile(r"(chmod\s+.*\+s|setuid|setgid)", re.I),
            ],
            "weight": 0.8,
        },
        AttackType.MALWARE_ACTIVITY: {
            "patterns": [
                re.compile(r"(virus|trojan|malware|ransomware|backdoor)", re.I),
                re.compile(r"(suspicious\s+process|unusual\s+execution)", re.I),
            ],
            "weight": 0.85,
        },
        AttackType.CRYPTOMINING: {
            "patterns": [
                re.compile(r"(xmrig|minerd|cryptonight|stratum\+tcp)", re.I),
                re.compile(r"(high\s*cpu\s*usage|mining\s*pool)", re.I),
            ],
            "weight": 0.9,
        },
        AttackType.RANSOMWARE: {
            "patterns": [
                re.compile(r"(vssadmin.*delete.*shadows|wmic.*shadowcopy.*delete)", re.I),
                re.compile(r"(bcdedit.*recoveryenabled.*no)", re.I),
                re.compile(r"\.(encrypted|locked|crypto|crypt|enc)\b", re.I),
            ],
            "weight": 0.95,
        },
    },
    
    LogTypeCategory.CLOUD: {
        AttackType.PRIVILEGE_ESCALATION: {
            "patterns": [
                re.compile(r"(AssumeRole|CreateAccessKey|AttachUserPolicy)", re.I),
                re.compile(r"(elevate|escalate|admin.*policy)", re.I),
            ],
            "weight": 0.8,
        },
        AttackType.DATA_EXFILTRATION: {
            "patterns": [
                re.compile(r"(GetObject.*large|Download\s+data|ExportSnapshot)", re.I),
                re.compile(r"(unusual\s+data\s+access|bulk\s+download)", re.I),
            ],
            "weight": 0.75,
        },
        AttackType.ACCOUNT_TAKEOVER: {
            "patterns": [
                re.compile(r"(ConsoleLogin.*suspicious|unusual\s+API\s+calls)", re.I),
                re.compile(r"(impossible\s+travel|unrecognized\s+principal)", re.I),
            ],
            "weight": 0.8,
        },
        AttackType.LATERAL_MOVEMENT: {
            "patterns": [
                re.compile(r"(cross-account|role.*chaining|AssumeRole.*external)", re.I),
            ],
            "weight": 0.75,
        },
        AttackType.RECONNAISSANCE: {
            "patterns": [
                re.compile(r"(ListBuckets|DescribeInstances|ListUsers.*rapid)", re.I),
            ],
            "weight": 0.7,
        },
        AttackType.SUPPLY_CHAIN: {
            "patterns": [
                re.compile(r"(PutBucketPolicy|ModifyLambda|UpdateFunctionCode)", re.I),
            ],
            "weight": 0.8,
        },
    },
    
    LogTypeCategory.SECURITY: {
        AttackType.MALWARE_ACTIVITY: {
            "patterns": [
                re.compile(r"(malware.*detected|virus.*found|trojan)", re.I),
            ],
            "weight": 0.9,
        },
        AttackType.C2_COMMUNICATION: {
            "patterns": [
                re.compile(r"(c2.*detected|command.*control|beacon)", re.I),
            ],
            "weight": 0.85,
        },
        AttackType.PORT_SCAN: {
            "patterns": [
                re.compile(r"(port\s+scan.*detected|scan\s+alert|reconnaissance)", re.I),
            ],
            "weight": 0.8,
        },
        AttackType.BRUTEFORCE: {
            "patterns": [
                re.compile(r"(brute\s+force.*detected|login\s+attack)", re.I),
            ],
            "weight": 0.8,
        },
    },
    
    LogTypeCategory.GENERIC: {
        AttackType.BRUTEFORCE: {
            "patterns": [
                re.compile(r"(Failed\s+password|Authentication\s+failure)", re.I),
            ],
            "weight": 0.5,
        },
        AttackType.MALWARE_ACTIVITY: {
            "patterns": [
                re.compile(r"(virus|trojan|malware)", re.I),
            ],
            "weight": 0.7,
        },
    },
}


class LogAttackDetector:
    """Log-type-specific attack detector"""
    
    def detect_entry_attack(self, message: str, log_type: Optional[str] = None) -> Optional[AttackDetection]:
        """Detect attack patterns in a single log entry based on log type"""
        search_text = message
        
        # Determine log type category
        category = LogTypeCategory.GENERIC
        if log_type:
            category = get_log_type_category(log_type)
        
        # Get patterns for this log type category
        category_patterns = LOG_TYPE_ATTACK_PATTERNS.get(category, LOG_TYPE_ATTACK_PATTERNS[LogTypeCategory.GENERIC])
        
        detections = []
        
        # Check each attack type applicable to this log type
        for attack_type, config in category_patterns.items():
            patterns = config.get("patterns", [])
            weight = config.get("weight", 0.5)
            
            if not patterns:
                continue
            
            match_count = 0
            matched_patterns = []
            
            for pattern in patterns:
                if pattern.search(search_text):
                    match_count += 1
                    matched_patterns.append(pattern.pattern)
            
            if match_count > 0:
                # Calculate confidence based on matches and weight
                confidence = min(weight + (match_count * 0.1), 0.95)
                detections.append({
                    "attack_type": attack_type,
                    "confidence": confidence,
                    "patterns": matched_patterns,
                })
        
        # Return the highest confidence detection
        if not detections:
            return None
        
        detections.sort(key=lambda x: x["confidence"], reverse=True)
        best = detections[0]
        mitre = MITRE_MAPPING.get(best["attack_type"], {"tactics": [], "techniques": []})
        
        return AttackDetection(
            attack_type=best["attack_type"],
            confidence=best["confidence"],
            mitre_tactics=mitre.get("tactics", []),
            mitre_techniques=mitre.get("techniques", []),
            matched_patterns=best["patterns"],
        )
    
    def detect_attacks_in_entries(self, entries: List[Dict], log_type: Optional[str] = None) -> List[Dict]:
        """Detect attacks in multiple entries with log type awareness"""
        results = []
        
        for entry in entries:
            message = entry.get("message", "")
            detection = self.detect_entry_attack(message, log_type or entry.get("log_type"))
            
            if detection and detection.confidence >= 0.3:
                results.append({
                    "entry": entry,
                    "attack": detection,
                })
        
        return results
    
    def get_attack_types_for_log_type(self, log_type: str) -> List[AttackType]:
        """Get available attack types for a log type"""
        category = get_log_type_category(log_type)
        patterns = LOG_TYPE_ATTACK_PATTERNS.get(category, LOG_TYPE_ATTACK_PATTERNS[LogTypeCategory.GENERIC])
        return list(patterns.keys())
    
    def is_attack_type_applicable(self, attack_type: AttackType, log_type: str) -> bool:
        """Check if an attack type is applicable to a log type"""
        category = get_log_type_category(log_type)
        patterns = LOG_TYPE_ATTACK_PATTERNS.get(category, LOG_TYPE_ATTACK_PATTERNS[LogTypeCategory.GENERIC])
        return attack_type in patterns


# Global detector instance
detector = LogAttackDetector()


# Convenience functions for direct use
def detect_entry_attack(message: str, log_type: Optional[str] = None) -> Optional[AttackDetection]:
    """Detect attack patterns in a single log entry"""
    return detector.detect_entry_attack(message, log_type)


def detect_attacks_in_entries(entries: List[Dict], log_type: Optional[str] = None) -> List[Dict]:
    """Detect attacks in multiple entries"""
    return detector.detect_attacks_in_entries(entries, log_type)


def get_attack_types_for_log_type(log_type: str) -> List[AttackType]:
    """Get available attack types for a log type"""
    return detector.get_attack_types_for_log_type(log_type)


def is_attack_type_applicable(attack_type: AttackType, log_type: str) -> bool:
    """Check if an attack type is applicable to a log type"""
    return detector.is_attack_type_applicable(attack_type, log_type)
