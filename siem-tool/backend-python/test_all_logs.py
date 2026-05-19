import os
import requests
import json
from pathlib import Path

test_dir = Path(r"C:\Users\Tanubhav Juneja\Desktop\projects\Cyber Chakshu\siem-test-logs")

results = []

for log_file in sorted(test_dir.rglob("*")):
    if log_file.is_file() and log_file.stat().st_size > 0:
        try:
            with open(log_file, 'rb') as f:
                files = {'file': (log_file.name, f, 'text/plain')}
                resp = requests.post('http://127.0.0.1:8788/parse', files=files, timeout=30)
                data = resp.json()
                
                entry = data.get('entries', [{}])[0] if data.get('entries') else {}
                has_fields = bool(entry.get('fields'))
                fields_keys = list(entry.get('fields', {}).keys())[:5] if has_fields else []
                
                results.append({
                    'file': str(log_file.relative_to(test_dir)),
                    'detected': data.get('detectedType'),
                    'parsed': data.get('parsedLines'),
                    'total': data.get('totalLines'),
                    'has_fields': has_fields,
                    'field_keys': fields_keys
                })
        except Exception as e:
            results.append({
                'file': str(log_file.relative_to(test_dir)),
                'error': str(e)
            })

# Print summary
print("\n=== TEST RESULTS ===\n")
for r in results:
    if 'error' in r:
        print(f"ERROR: {r['file']} - {r['error']}")
    else:
        status = "OK" if r['has_fields'] else "NO FIELDS"
        print(f"{status:12} | {r['detected']:20} | {r['parsed']}/{r['total']:5} | {r['file']}")
        if r['has_fields']:
            print(f"             Fields: {r['field_keys']}")

# Count stats
total = len(results)
with_fields = sum(1 for r in results if r.get('has_fields'))
detected = sum(1 for r in results if r.get('detected') and r['detected'] != 'unknown')

print(f"\n=== SUMMARY ===")
print(f"Total files: {total}")
print(f"With fields: {with_fields}")
print(f"Detected:    {detected}")
