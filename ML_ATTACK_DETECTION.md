# Cyber Chakshu SIEM - ML Attack Detection Implementation

## Overview
ML-based attack detection has been successfully implemented in both the Python desktop app (`siem-gui/webview-gui`) and the TypeScript Cloudflare Workers backend (`siem-tool/backend`).

## Implementation Summary

### 1. Python Desktop App (siem-gui/webview-gui)

**Files Created/Modified:**

- `ml/train_model.py` - ML training pipeline with Random Forest classifier
  - 8 attack types supported
  - 25 engineered features
  - 6,000 training samples
  - Model saved to `models/attack_classifier.joblib`

- `ml/correlation.py` - Updated with per-entry attack detection
  - `detectEntryAttack()` - Detect attacks in individual entries
  - `detectAttacksInEntries()` - Batch detection
  - MITRE ATT&CK mapping

- `api/app.py` - API integration
  - `/parse` endpoint returns attack data
  - `/detect-attack` endpoint for batch detection
  - Enriches entries with attackType, attackConfidence, mitreTactics, mitreTechniques

- `parsers/webserver.py` - Fixed Apache/Nginx parsers
  - Preserves query strings with spaces (for SQL injection detection)
  - Proper request parsing with rsplit

- `test_logs/` - Test files created
  - apache_normal.log, apache_attacks.log
  - ssh_normal.log, ssh_attacks.log
  - mixed_normal.log, mixed_attacks.log

### 2. TypeScript Cloudflare Backend (siem-tool/backend)

**Files Created/Modified:**

- `ml/entry-classifier.ts` - NEW: Per-entry attack detection
  - Pattern-based detection for 20+ attack types
  - MITRE ATT&CK tactics and techniques mapping
  - Confidence scoring
  - Functions:
    - `detectEntryAttack()` - Single entry detection
    - `detectAttacksInEntries()` - Batch detection
    - `enrichEntryWithAttackDetection()` - Enrich entries
    - `enrichEntriesWithAttacks()` - Batch enrichment

- `ml/index.ts` - Updated exports
  - Added entry-classifier functions

- `ml/classifier.ts` - Updated
  - Added file_inclusion attack type
  - Added attack weights and thresholds

- `ml/types.ts` - Updated
  - Added 'file_inclusion' to AttackType union

- `index.ts` - API integration
  - Updated /parse endpoint to run attack detection
  - Enriches entries with attack data
  - Returns mlAttacks and attackSummary

- `types.ts` - Updated
  - Added attackType, attackConfidence, mitreTactics, mitreTechniques to ParsedLogEntry
  - Added mlAttacks and attackSummary to ParseResponse

## Attack Types Detected

### Web Application Attacks
- SQL Injection (patterns: OR '1'='1, UNION SELECT, DROP TABLE)
- XSS (patterns: <script>, javascript:, onerror=)
- Command Injection (patterns: ; cat, | bash, $(whoami))
- Path Traversal (patterns: ../../etc/passwd, ..%2f)
- SSRF (patterns: metadata.google.internal, file://)
- File Inclusion (patterns: ?page=http://evil.com)
- LDAP Injection
- XXE (XML External Entity)
- Deserialization
- Prototype Pollution

### Exploits
- Log4Shell (CVE-2021-44228)

### Authentication Attacks
- Bruteforce (aggregate analysis)
- Password Spray (aggregate analysis)
- Credential Stuffing

### Infrastructure Attacks
- Port Scan
- DDoS
- Reconnaissance
- Privilege Escalation
- Lateral Movement
- Data Exfiltration

### Advanced Threats
- Malware Activity
- C2 Communication
- DNS Tunneling
- Cryptomining
- Ransomware
- Insider Threat
- Account Takeover
- Kerberoasting
- Pass the Hash
- Golden Ticket

## GUI Integration

### Attack Highlighting
- Attack entries highlighted with red background
- Left border indicator (3px red)
- Attack column shows attack type
- Severity shows warning icon
- Hover for confidence score

### CSS Classes
```css
.attack-row - Red gradient background
.attack-cell - Light red text
.attack-indicator - Warning badge
.attack-type-label - Attack type chip
```

## API Response Format

### Parse Response
```json
{
  "success": true,
  "detectedType": "apache",
  "entries": [
    {
      "id": "...",
      "message": "GET /products.php?id=1' OR '1'='1 200",
      "attackType": "sql_injection",
      "attackConfidence": 0.85,
      "mitreTactics": ["TA0006"],
      "mitreTechniques": ["T1190"]
    }
  ],
  "mlAttacks": [
    {
      "entry": { ... },
      "attack": {
        "attackType": "sql_injection",
        "confidence": 0.85,
        "mitreTactics": ["TA0006"],
        "mitreTechniques": ["T1190"]
      }
    }
  ],
  "attackSummary": {
    "totalAttacks": 5,
    "attackTypes": ["sql_injection", "xss_attack"],
    "uniqueSources": 3,
    "riskScore": 50
  }
}
```

## Test Files

All test files are in `siem-gui/webview-gui/test_logs/`:

1. **apache_normal.log** - 15 normal HTTP requests, 0 attacks expected
2. **apache_attacks.log** - 15 requests with 7 attacks (SQLi, XSS, Command Injection, etc.)
3. **ssh_normal.log** - 15 normal SSH logins, 0 attacks expected
4. **ssh_attacks.log** - SSH bruteforce, 13 attacks expected
5. **mixed_normal.log** - System logs, 0 attacks expected
6. **mixed_attacks.log** - Mixed logs with multiple attack types

## Testing Commands

### Python Backend
```bash
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

### TypeScript Backend (Local)
```bash
cd siem-tool/backend
npm run dev

# Test with curl
curl -X POST http://localhost:8787/parse \
  -H "Content-Type: text/plain" \
  --data-binary @../../siem-gui/webview-gui/test_logs/apache_attacks.log
```

### TypeScript Backend (Deployed)
```bash
curl -X POST https://siem-backend.tanubhavj.workers.dev/parse \
  -H "Content-Type: text/plain" \
  --data-binary @apache_attacks.log
```

## Deployment Status

### Python Desktop App
- ✅ Model trained and saved
- ✅ API endpoints updated
- ✅ Attack detection integrated
- ✅ Test files created

### TypeScript Cloudflare Backend
- ✅ Entry classifier created
- ✅ API endpoint updated
- ✅ Types updated
- ✅ TypeScript compilation passing
- ⏳ Needs deployment to Cloudflare

## Next Steps

1. Deploy TypeScript backend:
   ```bash
   cd siem-tool/backend
   npm run deploy
   ```

2. Test deployed backend with test files

3. Update frontend to display attack data from TypeScript backend

## Model Performance

- **Algorithm:** Random Forest (Python), Pattern-based (TypeScript)
- **Python Accuracy:** 100% on synthetic training data
- **TypeScript Accuracy:** Pattern matching with confidence scoring
- **Features:** 25 engineered features (Python), regex patterns (TypeScript)
- **Confidence Threshold:** 30% minimum for detection

## Files Modified Summary

**Python (siem-gui/webview-gui):**
- ml/train_model.py (31 KB)
- ml/correlation.py (27 KB)
- api/app.py (13 KB)
- parsers/webserver.py
- requirements.txt

**TypeScript (siem-tool/backend):**
- ml/entry-classifier.ts (NEW)
- ml/index.ts
- ml/classifier.ts
- ml/types.ts
- index.ts
- types.ts

**Frontend (siem-tool/frontend):**
- src/App.css
- src/DynamicTable.tsx
- src/types.ts

**Test Files:**
- test_logs/README.md
- test_logs/*.log (6 files)
