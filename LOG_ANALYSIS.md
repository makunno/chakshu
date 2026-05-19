# Log Format Analysis - Cyber Chakshu SIEM

**Last Updated:** 2026-03-20

---

## Progress Summary

| Category | Total Types | Fixed | Status |
|----------|-------------|-------|--------|
| FTP Logs | 4 | 4 | ✅ Complete |
| Web Server Logs | 9 | 9 | ✅ Complete |
| Database Logs | 7 | 7 | ✅ Complete |
| Firewall Logs | 6 | 6 | ✅ Complete |
| Auth/SSH Logs | 2 | 2 | ✅ Complete |
| Mail Logs | 3 | 3 | ✅ Complete |
| **TOTAL** | **31** | **31** | **100%** |

---

## 1. FTP Logs - ✅ ALL FIXED

### 1.1 vsftpd.log - ✅ FIXED
**Status:** Parser correctly extracts all fields
**Format:** `Jan 14 18:55:21 ftp-prod vsftpd[11119]: [backup_user] OK LOGIN: Client "198.51.100.42"`

**Extracted Fields:**
- timestamp, hostname, pid, username, status, action, client_ip, filename

### 1.2 filezilla.log - ✅ FIXED
**Status:** New parser created
**Format:** `(000001)01/14/2026 18:55:15 - alice (66.249.66.1)> 230 User alice logged in`

**Extracted Fields:**
- connection_id, date, time, username, ip, status_code, message

### 1.3 xferlog.log - ✅ FIXED
**Status:** Parser correctly extracts all 19 fields
**Format:** `Wed Jan 14 18:55:15 2026 25 172.16.5.21 12766578 /home/guest/notes.txt b _ i a guest ftp 0 * c`

**Extracted Fields:**
- weekday, month, day, time, year, transfer_size_kb, remote_host, bytes_sent, filename, file_type, special_action, direction, access_mode, username, service_name, authentication_method, completed, restart_marker, transfer_type

### 1.4 IIS FTP.log - ✅ FIXED
**Status:** Parser correctly extracts all fields
**Format:** `2026-01-14 18:55:07 103.21.244.11 dev01 192.168.1.1 21 PASS - 530 0 0`

**Extracted Fields:**
- date, time, client_ip, username, server_ip, server_port, method, uri_stem, status, sc_bytes, cs_bytes

---

## 2. Web Server Logs - ✅ ALL FIXED

### 2.1 nginx.log - ✅ WORKING
**Format:** `10.0.0.5 - 127.0.0.1 [10/Jan/2026:02:56:02] "POST / HTTP/1.1" 500 708`

### 2.2 apache_access.log - ✅ WORKING
**Format:** `::1 - - [10/Mar/2025:13:31:46 +0530] "GET /DVWA HTTP/1.1" 301 329 "-" "Mozilla/5.0..."`

### 2.3 apache_php.log - ✅ WORKING
**Format:** Same as Apache access log

### 2.4 iis.log - ✅ WORKING
**Format:** `2026-01-10 02:56:02 127.0.0.1 GET /login - 80 - 192.168.1.10 curl/7.68.0 500 0 0 711`

### 2.5 flask.log - ✅ WORKING
**Format:** `PUT /settings 200`

### 2.6 django.log - ✅ WORKING
**Format:** `[10/Jan/2026:02:56:02] "PUT /" 401`

### 2.7 fastapi.json.log - ✅ WORKING
**Format:** `{"time": "2026-01-10T02:56:02.757762", "framework": "FastAPI", "method": "POST", "path": "/login", "status": 201, "latency_ms": 13, "ip": "192.168.1.10"}`

### 2.8 express.json.log - ✅ WORKING
**Format:** `{"time": "2026-01-10T02:56:02.764607", "framework": "Express.js", "method": "GET", "path": "/settings", "status": 201, "latency_ms": 41, "ip": "10.0.0.5"}`

### 2.9 node_morgan.log - ✅ WORKING
**Format:** `GET /settings 401 40ms`

---

## 3. Database Logs - ✅ ALL FIXED

### 3.1 MySQL-Error.log - ✅ FIXED
**Status:** Working correctly
**Format:** `2024-01-01T00:04:43.000Z 89 [ERROR] [MY-001064] [Server] You have an error in your SQL syntax`

**Extracted Fields:**
- timestamp, thread_id, error_level, error_code, component, error_message

### 3.2 MySQL-Slow.log - ✅ FIXED
**Status:** Multi-line parser created
**Format:**
```
# Time: 2024-01-01T00:07:50.000Z
# User@Host: backup_user[backup_user] @ app-server-01 [172.16.0.23]
# Query_time: 158.25 Rows_examined: 6825231
CREATE INDEX idx_payments_id ON payments(id);
```

**Extracted Fields:**
- timestamp, user, db_user, host, ip, query_time, lock_time, rows_examined, rows_sent, sql_statement

### 3.3 PostGre-Error.log - ✅ FIXED
**Status:** Parser correctly handles UTC timezone
**Format:** `2024-01-01 00:03:14.000 UTC [7475] readonly@staging ERROR: 42P01: relation "inventory" does not exist`

**Extracted Fields:**
- timestamp, pid, username, database, level, message

### 3.4 PostGre-Statement.log - ✅ FIXED
**Status:** Parser correctly handles STATEMENT/LOG format
**Format:** `2025-09-15 00:00:49.147 PST [17508] STATEMENT: SELECT ip_address, name FROM staging.payments WHERE id = 8712901;`

**Extracted Fields:**
- timestamp, timezone, pid, log_type, duration_ms, statement

### 3.5 SQLServer-Error.log - ✅ FIXED
**Status:** New parser created
**Format:** `2024-01-01 00:13:27.000 Logon Server Error: 1205, Severity: 13, State: 68. Transaction...`

**Extracted Fields:**
- timestamp, error_number, severity, state, message

### 3.6 Oracle-Listener.log - ✅ FIXED
**Status:** Special nested parser with balanced parentheses handling
**Format:** `01-JAN-2026 00:00:06 * (CONNECT_DATA=(SERVICE_NAME=crmdb)) * (ADDRESS=(PROTOCOL=tcp)(HOST=172.3.232.14)(PORT=12169)) * establish * crmdb * 0`

**Extracted Fields:**
- timestamp, protocol, host, port, service_name, cid_program, cid_host, cid_user, action, service, result

### 3.7 MongoDB-Server.log - ✅ FIXED
**Status:** BSON JSON parser with nested attr extraction
**Format:** `{"t":{"$date":"2024-06-01T00:00:00.135000Z"},"s":"I","c":"NETWORK","msg":"client conn closed","attr":{"remote":"100.65.28.6:46015"}}`

**Extracted Fields:**
- timestamp, severity (I/W/E/F), component, message, remote, connection_id, user, database, command, duration_ms, plan_summary, roles

---

## 4. Firewall Logs - ✅ ALL FIXED

### 4.1 iptables.log - ✅ FIXED
**Status:** Parser correctly extracts all fields
**Format:** `Jan 13 14:54:30 server kernel: IPTABLES-DROP: IN=eth0 OUT= MAC=aa:bb:cc SRC=172.16.0.2 DST=10.0.0.5 PROTO=ICMP SPT=443 DPT=22`

**Extracted Fields:**
- timestamp, hostname, action, in_iface, out_iface, src_ip, dst_ip, protocol, src_port, dst_port

### 4.2 ufw.log - ✅ FIXED
**Status:** Parser correctly extracts all fields
**Format:** `Jan 13 14:54:30 server ufw[1234]: [UFW BLOCK] IN=eth0 OUT= SRC=192.168.1.10 DST=172.16.0.2`

**Extracted Fields:**
- timestamp, hostname, action, in_iface, out_iface, src_ip, dst_ip

### 4.3 windows_firewall.log - ✅ FIXED
**Status:** New parser created
**Format:** `2026-01-13 14:54:30 ALLOW ICMP 127.0.0.1 172.16.0.2 22 443`

**Extracted Fields:**
- timestamp, action, protocol, src_ip, dst_ip, src_port, dst_port

### 4.4 palo_alto.log - ✅ FIXED
**Status:** Parser working
**Format:** `2026/01/13 14:54:30 allow udp 172.16.0.2 172.16.0.2 rule=Block_HTTP`

**Extracted Fields:**
- timestamp, action, protocol, src_ip, dst_ip, rule

### 4.5 fortigate.log - ✅ FIXED
**Status:** Parser working
**Format:** `date=2026-01-13 time=14:54:30 action=allow srcip=127.0.0.1 dstip=10.0.0.5 service=HTTP`

**Extracted Fields:**
- date, time, action, srcip, dstip, service

### 4.6 cisco_asa.log - ✅ FIXED
**Status:** Parser working
**Format:** `Jan 13 14:54:30 firewall %ASA-6-106100: access-list outside_access_in permitted tcp outside/127.0.0.1 to inside/192.168.1.10`

**Extracted Fields:**
- timestamp, action, protocol

---

## 5. Auth/SSH Logs - ✅ ALL FIXED

### 5.1 demo_auth_linux.log (SSH) - ✅ FIXED
**Status:** Accepted and Failed parsers working
**Format:** `Jan 10 09:00:01 web01 sshd[1122]: Accepted password for alice from 192.0.2.10 port 53412 ssh2`

**Extracted Fields:**
- timestamp, hostname, pid, method, user, ip, port

### 5.2 Linux_2k.log (PAM) - ✅ FIXED
**Status:** Parser working
**Format:** `Jun 14 15:16:01 combo sshd(pam_unix)[19939]: authentication failure; logname= uid=0 euid=0 tty=NODEVssh ruser= rhost=218.188.2.4`

---

## 6. Mail Logs - ✅ ALL FIXED

### 6.1 postfix.log - ✅ FIXED
**Status:** Parser working
**Format:** `Jan 13 10:56:03 mailserver postfix/cleanup[5550]: 4C1E538D63: from=<user@example.com>, to=<admin@example.org>, status=bounced`

**Extracted Fields:**
- timestamp, host, service, pid, message

### 6.2 exim.log - ✅ FIXED
**Status:** New parser created
**Format:** `2026-01-13 10:56:03 HHVTKB5I3PCB => user@example.com H=mail.example.com [192.168.1.10]`

**Extracted Fields:**
- timestamp, message_id, direction, recipient, helo, ip, protocol, size

### 6.3 dovecot.log - ✅ FIXED
**Status:** New parser with login/logout support
**Format:** `Jan 13 10:56:03 mailserver dovecot: imap-login: Login: user=<bob>, rip=192.168.1.10`

**Extracted Fields:**
- timestamp, hostname, protocol, login_type, user, remote_ip, local_ip, master_pid, session_id

---

## Special Parser Functions Added

### oracle_listener()
Handles nested CONNECT_DATA and ADDRESS structures with balanced parentheses:
```python
def oracle_listener(line: str) -> Optional[Dict[str, Any]]:
    # Extracts: timestamp, protocol, host, port, service_name, 
    #          cid_program, cid_host, cid_user, action, service, result
```

### mongodb_server()
Handles BSON-like JSON with nested `attr` object:
```python
def mongodb_server(line: str) -> Optional[Dict[str, Any]]:
    # Extracts: timestamp, severity (I/W/E/F), component, message,
    #          remote, connection_id, user, database, command, duration_ms
```

### mysql_slow()
Handles multi-line slow query log blocks:
```python
def mysql_slow(block: str) -> Optional[Dict[str, Any]]:
    # Extracts: timestamp, user, host, ip, query_time, lock_time,
    #          rows_examined, rows_sent, sql_statement
```

### dovecot()
Handles both login and logout events:
```python
def dovecot(line: str) -> Optional[Dict[str, Any]]:
    # Extracts: timestamp, hostname, protocol, login_type, user,
    #          remote_ip, local_ip, master_pid, session_id
```

### exim()
Handles Exim mail transfer logs:
```python
def exim(line: str) -> Optional[Dict[str, Any]]:
    # Extracts: timestamp, message_id, direction, recipient, helo,
    #          ip, protocol, size
```

### windows_firewall()
Handles Windows Firewall CSV format:
```python
def windows_firewall(line: str) -> Optional[Dict[str, Any]]:
    # Extracts: timestamp, action, protocol, src_ip, dst_ip, src_port, dst_port
```

### sqlserver_error()
Handles SQL Server error log format:
```python
def sqlserver_error(line: str) -> Optional[Dict[str, Any]]:
    # Extracts: timestamp, error_number, severity, state, message
```

---

## Implementation Notes

### Nested Field Extraction
For Oracle Listener's nested CONNECT_DATA/ADDRESS:
```python
# Find balanced parentheses until ") * " pattern
m2 = re.match(r'(.*?)\)\s+\*\s+(.*)', content)
```

### BSON Dates in MongoDB
Access via nested dictionary:
```python
timestamp = data.get('t', {}).get('$date', '')
```

### Multi-line Log Handling
MySQL slow query logs span multiple lines - accumulate until complete record.

### Timezone Variations
PostgreSQL logs may have UTC, PST, IST, EST, etc. - captured as separate field.

---

## Files Modified

1. **log_parsers.py** - Added/fixed parsers:
   - `vsftpd()` - Fixed timestamp parsing
   - `filezilla()` - New parser
   - `xferlog()` - Fixed field extraction
   - `iis_ftp()` - Fixed field extraction
   - `postgres_error()` - Added UTC timezone handling
   - `postgres_statement()` - Fixed regex for STATEMENT format
   - `oracle_listener()` - Special nested parser with balanced parens
   - `mongodb_server()` - BSON JSON parser
   - `mongodb_audit()` - New parser
   - `sqlserver_error()` - New parser
   - `sqlserver_audit()` - New parser
   - `sqlserver_transaction()` - New parser
   - `mysql_slow()` - Multi-line parser
   - `dovecot()` - New parser with login/logout support
   - `exim()` - New parser
   - `iptables()` - Fixed regex for actual format
   - `ufw()` - Fixed regex for actual format
   - `windows_firewall()` - New parser

2. **log_detector.py** - Detection patterns unchanged (already working)

---

## Legend

- ✅ **FIXED** - Parser working correctly
- 🔴 **PENDING** - Needs fixing
- ⚠️ **PARTIAL** - Works but missing some fields
- 🆕 **NEW** - Parser didn't exist, was created
