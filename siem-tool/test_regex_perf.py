
import re
import time

# Exim regex from log_parsers.py
EXIM_RE = re.compile(r'^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\s+([A-Z0-9]+)\s+(=>|<=)\s+<?([^>\s]+)>?\s+H=([^[]+)\s+\[([\d.]+)\](?:\s+P=(\w+))?(?:\s+S=(\d+))?')

test_line = "2026-01-13 10:56:03 HHVTKB5I3PCB => user@example.com H=mail.example.com [192.168.1.10] P=esmtp S=1234"

print("Testing Exim regex...")
start = time.time()
for _ in range(10000):
    EXIM_RE.match(test_line)
end = time.time()
print(f"10,000 matches took: {end - start:.4f}s")

# Failing line test
fail_line = "2026-01-13 10:56:03 HHVTKB5I3PCB => user@example.com H=mail.example.com [192.168.1.10] but with extra stuff at end that might cause backtracking"
start = time.time()
for _ in range(10000):
    EXIM_RE.match(fail_line)
end = time.time()
print(f"10,000 failing matches took: {end - start:.4f}s")
