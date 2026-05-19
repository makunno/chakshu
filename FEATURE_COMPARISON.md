# Cyber Chakshu SIEM - Feature Comparison

## Backend Comparison: siem-tool vs siem-gui

### Endpoints

| Endpoint | siem-tool (Cloudflare) | siem-gui (Flask) | Status |
|----------|----------------------|------------------|--------|
| `GET /` | Health check | Health check | ✅ Same |
| `GET /parsers` | 56+ parsers listed | 40+ parsers listed | ⚠️ siem-gui has fewer |
| `POST /parse` | ✅ Full parsing + ML | ✅ Full parsing + ML | ✅ Same |
| `POST /parse/chunked` | ✅ Chunked upload | ✅ Chunked upload | ✅ Same |
| `POST /correlate` | ✅ Multi-log correlation | ✅ Multi-log correlation | ✅ Same |
| `POST /detect` | ✅ Log type detection | ✅ Log type detection | ✅ Same |
| `POST /stream` | ✅ Stream parsing | ✅ Stream parsing | ✅ Same |
| `POST /analyze` | ✅ Dynamic analysis | ✅ Dynamic analysis | ✅ Same |
| `GET /attacks` | ✅ Attack types ref | ✅ Attack types ref | ✅ Same |
| `POST /detect-attack` | ❌ Not present | ✅ Attack detection | ✅ siem-gui only |
| `POST /feedback` | ✅ Feedback submission | ✅ Feedback submission | ✅ Same |
| `POST /feedback/bulk` | ✅ Bulk feedback | ✅ Bulk feedback | ✅ Same |
| `GET /feedback/attack-types` | ✅ Attack types list | ✅ Attack types list | ✅ Same |
| `GET /feedback/stats` | ✅ Feedback stats | ✅ Feedback stats | ✅ Same |
| `POST /feedback/retrain` | ❌ Not present | ✅ Retrain model | ✅ siem-gui only |
| `GET /feedback/versions` | ❌ Not present | ✅ List versions | ✅ siem-gui only |
| `POST /feedback/rollback` | ❌ Not present | ✅ Rollback model | ✅ siem-gui only |

### Supported Log Types

| Category | siem-tool | siem-gui |
|----------|-----------|----------|
| **Web Server** | Apache, Nginx, IIS, Django, Flask, Laravel, Rails, Express, FastAPI, Gunicorn, Uvicorn | Apache, Nginx, IIS, Django, Flask, Express, FastAPI |
| **Database** | MySQL (error, query, slow), PostgreSQL (error, auth, statement), Oracle (alert, listener, audit), SQL Server (error, audit, transaction), MongoDB | MySQL (error, query), PostgreSQL (error, auth, statement), SQL Server, MongoDB, Oracle |
| **Firewall** | iptables, UFW, nftables, firewalld, Windows Firewall, Palo Alto, FortiGate, Cisco ASA, Check Point, AWS VPC Flow, Azure NSG, GCP VPC | iptables, UFW, nftables, Windows Firewall, Palo Alto, FortiGate, Cisco ASA |
| **Mail Server** | Postfix, Sendmail, Exim, Dovecot, Exchange | Postfix, Sendmail, Exim, Dovecot |
| **Auth** | SSH Auth, PAM, sudo, vsftpd, ProFTPD | SSH Auth, PAM |
| **System** | Syslog, Systemd, Kernel, Audit, Package, Cron, Daemon | Syslog, Systemd, Kernel, Audit, Cron |
| **Network** | DNS, DHCP, HTTP proxy, FileZilla, vsftpd, xferlog | FileZilla, vsftpd, xferlog |
| **FTP** | FileZilla, vsftpd, ProFTPD, IIS FTP, pure-ftpd, xferlog | FileZilla, vsftpd, xferlog |

**Total Log Types: siem-tool ~56 | siem-gui ~40**

### ML Features

| Feature | siem-tool | siem-gui |
|---------|-----------|----------|
| **Pattern-based Detection** | ✅ 30+ attack patterns | ✅ 30+ attack patterns |
| **MITRE ATT&CK Mapping** | ✅ 13 tactics, 40+ techniques | ✅ 13 tactics, 40+ techniques |
| **Attack Chains** | ✅ Correlates attacks by IP/time | ✅ Correlates attacks by IP/time |
| **Anomaly Detection** | ⚠️ Feature extraction only | ✅ Isolation Forest |
| **Federated Learning** | ⚠️ Feedback collection only | ✅ Full FL pipeline |
| **Model Retraining** | ❌ Not implemented | ✅ With differential privacy |
| **Model Versioning** | ❌ Not implemented | ✅ Version history & rollback |
| **Pre-trained Model** | ✅ UNSW-NB15 (98.3%) | ✅ UNSW-NB15 (98.3%) |
| **Combined Model** | ✅ 2.38M samples, 15 attack types | ✅ 2.38M samples, 15 attack types |

### Attack Types Detected

| Attack Type | siem-tool | siem-gui |
|-------------|-----------|----------|
| SQL Injection | ✅ | ✅ |
| XSS | ✅ | ✅ |
| Command Injection | ✅ | ✅ |
| Path Traversal | ✅ | ✅ |
| File Inclusion | ✅ | ✅ |
| SSRF | ✅ | ✅ |
| XXE | ✅ | ✅ |
| Log4Shell | ✅ | ✅ |
| Brute Force | ✅ | ✅ |
| Password Spray | ✅ | ✅ |
| Credential Stuffing | ✅ | ✅ |
| MFA Bypass | ✅ | ✅ |
| MFA Fatigue | ✅ | ✅ |
| Session Hijacking | ✅ | ✅ |
| Privilege Escalation | ✅ | ✅ |
| Lateral Movement | ✅ | ✅ |
| Data Exfiltration | ✅ | ✅ |
| Port Scan | ✅ | ✅ |
| DDoS | ✅ | ✅ |
| Reconnaissance | ✅ | ✅ |
| C2 Communication | ✅ | ✅ |
| Malware Activity | ✅ | ✅ |
| Insider Threat | ✅ | ✅ |
| Account Takeover | ✅ | ✅ |
| Kerberoasting | ✅ | ❌ |
| Pass the Hash | ✅ | ❌ |
| Golden Ticket | ✅ | ❌ |
| DNS Tunneling | ✅ | ❌ |
| Cryptomining | ✅ | ❌ |
| Ransomware | ✅ | ❌ |
| Supply Chain | ✅ | ❌ |
| Webshell | ✅ | ❌ |
| Living off the Land | ✅ | ❌ |
| Zero-day Exploit | ✅ | ❌ |
| APT Activity | ✅ | ❌ |
| Prototype Pollution | ✅ | ❌ |

**Total Attack Types: siem-tool 36 | siem-gui 24**

### File Upload Features

| Feature | siem-tool | siem-gui |
|---------|-----------|----------|
| Raw text upload | ✅ | ✅ |
| JSON upload | ✅ | ✅ |
| Multipart form upload | ✅ | ✅ |
| Chunked upload (>100KB) | ✅ | ✅ |
| Multiple files | ✅ | ✅ |
| Force log type | ✅ | ✅ |

## Data Sources for Training

### Downloaded Datasets
- `data/unsw-nb15.csv` - 2.28M samples, 10 attack types (Australian Cyber Security Centre)
- `data/downloaded_datasets/synthetic_logs.csv` - 99K synthetic logs with 7 attack types
- `data/models/attack_detector.pkl` - UNSW-NB15 trained model (130 MB)
- `data/models/attack_detector_combined.pkl` - Combined dataset model (291 MB)

### Available for Download
- **Loghub** (https://zenodo.org/records/8275861) - Apache, BGL, Linux, Mac, OpenSSH, OpenVPN, ProFTPD, Hadoop, Zookeeper, HealthApp, Spark, HDFS
- **CICIDS2017/2018** (https://www.unb.ca/cic/datasets/) - Canadian Institute for Cybersecurity
- **LANL Enterprise** (https://csr.lanl.gov/data/2017/) - 58 days real enterprise data
- **SecRepo** (https://www.secrepo.com/) - Security log samples

## Recommendations

### 1. Add to siem-gui
- [ ] Kerberoasting detection
- [ ] Pass the Hash/Golden Ticket detection
- [ ] DNS Tunneling detection
- [ ] Cryptomining detection
- [ ] Ransomware detection
- [ ] Supply chain attack detection
- [ ] Webshell detection
- [ ] Living off the Land detection
- [ ] Zero-day exploit detection
- [ ] APT activity detection
- [ ] Prototype Pollution detection

### 2. Download Additional Datasets
```bash
# Download Loghub datasets
cd data
python download_datasets.py --loghub-only

# Download CICIDS2017/2018 (manual)
# Visit https://www.unb.ca/cic/datasets/
# Place CSV files in data/downloaded_datasets/cicids2017/

# Retrain with additional data
python train_multi_dataset.py
```

### 3. Deploy Updates
```bash
# Deploy siem-tool (Cloudflare Workers)
cd siem-tool/backend
npm run deploy

# Deploy siem-gui (no deployment needed - runs locally)
# Just restart the Flask server
```

## Conclusion

Both backends have strong feature parity with the following differences:

- **siem-gui** has federated learning features (retraining, versioning, rollback) not in siem-tool
- **siem-tool** has 16 more attack type detections
- **siem-tool** has more parsers (~56 vs ~40)
- **siem-tool** is cloud-ready (Cloudflare Workers), siem-gui is desktop-only (Flask)

For production use, siem-tool is recommended. For on-premise/local analysis, siem-gui provides additional ML pipeline features.
