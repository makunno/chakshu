"""
Correlation Engine - Link events across multiple log sources
"""

import uuid
from typing import List, Dict, Any
from datetime import datetime
from collections import defaultdict

def correlate_events(all_entries: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Correlate events across different log types based on IP, User, and Time.
    Returns a list of 'Attack Chains' or suspicious event sequences.
    """
    if not all_entries:
        return {"attackChains": [], "summary": {}}
        
    # Sort entries by timestamp
    try:
        sorted_entries = sorted(all_entries, key=lambda x: str(x.get('timestamp', '')))
    except:
        sorted_entries = all_entries
        
    chains = []
    
    # 1. Group by Source IP and User
    by_ip = defaultdict(list)
    by_user = defaultdict(list)
    
    for entry in sorted_entries:
        ip = entry.get('source', {}).get('ip')
        user = entry.get('user', {}).get('name')
        
        if ip and ip != 'LOCAL':
            by_ip[ip].append(entry)
        if user and user.lower() != 'unknown':
            by_user[user.lower()].append(entry)
            
    # 2. Analyze IP-based chains (Multi-stage attacks from same source)
    for ip, entries in by_ip.items():
        attack_types = [e.get('attackType') for e in entries if e.get('attackType') and e.get('attackType') != 'safe']
        anomalies = [e for e in entries if e.get('isAnomaly')]
        
        if len(attack_types) >= 2 or len(anomalies) >= 2 or (attack_types and anomalies):
            chain_id = str(uuid.uuid4())
            unique_types = list(set(attack_types))
            
            chains.append({
                "id": chain_id,
                "type": "ip_correlation",
                "startTime": entries[0].get('timestamp'),
                "endTime": entries[-1].get('timestamp'),
                "attackType": unique_types[0] if unique_types else "behavioral_outlier",
                "stage": "execution" if len(unique_types) > 1 else "reconnaissance",
                "events": entries,
                "sourceIps": [ip],
                "targetUsers": list(set(e.get('user', {}).get('name') for e in entries if e.get('user', {}).get('name'))),
                "prediction": {
                    "confidence": 0.75 + (min(len(entries), 10) * 0.02),
                    "explanation": [f"Source IP {ip} involved in {len(entries)} suspicious events across {len(set(e.get('logType') for e in entries))} services."]
                },
                "mitreTactics": _map_to_mitre(unique_types + (['anomaly'] if anomalies else [])),
                "recommendation": f"Monitor activity from {ip}. High volume of suspicious events detected."
            })

    # 3. Analyze User-based chains (Targeted attacks or compromised accounts)
    for user, entries in by_user.items():
        ips = list(set(e.get('source', {}).get('ip') for e in entries if e.get('source', {}).get('ip')))
        failures = [e for e in entries if e.get('outcome') == 'failure']
        successes = [e for e in entries if e.get('outcome') == 'success']
        
        # Pattern: Multiple IPs targeting one user
        if len(ips) >= 3 and len(failures) >= 5:
            chains.append({
                "id": str(uuid.uuid4()),
                "type": "user_targeting",
                "startTime": entries[0].get('timestamp'),
                "endTime": entries[-1].get('timestamp'),
                "attackType": "distributed_bruteforce",
                "stage": "credential_access",
                "events": entries,
                "sourceIps": ips,
                "targetUsers": [user],
                "prediction": {
                    "confidence": 0.85,
                    "explanation": [f"User '{user}' targeted by {len(ips)} unique IP addresses with multiple failures."]
                },
                "mitreTactics": ["Credential Access"],
                "recommendation": f"Reset password for user '{user}' and enable MFA. Possible distributed brute force."
            })
            
        # Pattern: Compromised Account (Failures followed by success from a new IP)
        if failures and successes:
            fail_ips = set(e.get('source', {}).get('ip') for e in failures)
            succ_ips = set(e.get('source', {}).get('ip') for e in successes)
            # If a success comes from an IP that was failing, or a success after many fails from others
            if any(ip in fail_ips for ip in succ_ips) or (len(failures) > 10 and successes):
                chains.append({
                    "id": str(uuid.uuid4()),
                    "type": "account_compromise",
                    "startTime": entries[0].get('timestamp'),
                    "endTime": entries[-1].get('timestamp'),
                    "attackType": "account_takeover",
                    "stage": "persistence",
                    "events": entries,
                    "sourceIps": list(fail_ips | succ_ips),
                    "targetUsers": [user],
                    "prediction": {
                        "confidence": 0.90,
                        "explanation": [f"Potential account takeover for '{user}'. Observed successful login after multiple failed attempts."]
                    },
                    "mitreTactics": ["Credential Access", "Persistence"],
                    "recommendation": f"IMMEDIATE ACTION: Lock account '{user}'. Evidence of successful login after brute force."
                })

    # 4. Global Timeline Analysis
    timeline = []
    for entry in sorted_entries:
        if entry.get('attackType') and entry.get('attackType') != 'safe' or entry.get('isAnomaly'):
            timeline.append({
                "id": entry.get('id'),
                "timestamp": entry.get('timestamp'),
                "logSource": entry.get('logSource', 'unknown'),
                "eventType": entry.get('attackType') or 'anomaly',
                "severity": entry.get('severity', 'medium'),
                "title": f"Suspicious activity in {entry.get('logType')}",
                "description": entry.get('message', '')[:200],
                "sourceIp": entry.get('source', {}).get('ip'),
                "targetUser": entry.get('user', {}).get('name'),
                "isAnomaly": entry.get('isAnomaly', False),
                "anomalyScore": entry.get('anomalyScore', 0)
            })

    return {
        "success": True,
        "attackChains": chains,
        "timeline": timeline,
        "summary": {
            "totalChains": len(chains),
            "criticalAlerts": len([c for c in chains if c['prediction']['confidence'] > 0.85]),
            "riskScore": min(len(chains) * 15 + (len(timeline) * 2), 100)
        }
    }

def _map_to_mitre(attack_types: List[str]) -> List[str]:
    mapping = {
        "bruteforce": ["Credential Access"],
        "credential_stuffing": ["Credential Access"],
        "sql_injection": ["Initial Access", "Execution"],
        "xss_attack": ["Initial Access"],
        "path_traversal": ["Initial Access", "Exfiltration"],
        "threat_intel": ["Reconnaissance"],
        "anomaly": ["Suspicious Activity"],
        "spam_activity": ["Resource Hijacking"],
        "account_takeover": ["Persistence", "Privilege Escalation"]
    }
    
    tactics = set()
    for at in attack_types:
        if at and at in mapping:
            tactics.update(mapping[at])
            
    return list(tactics) if tactics else ["Unknown"]
