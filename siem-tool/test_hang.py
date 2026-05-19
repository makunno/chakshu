
import os
import sys
import time

# Add backend-python/src to path
sys.path.insert(0, os.path.join(os.getcwd(), "backend-python", "src"))

# Mock ai_client to avoid actual API calls during test if possible, 
# but we want to see if it hangs.
# Actually, let's just see if it's being called.

from parsers import parse_line

test_line = "2026-01-15T16:14:46.806Z	336 Query	SELECT * FROM users WHERE id = 1"

print(f"Testing parse_line with: {test_line}")
start = time.time()
result = parse_line(test_line, "MySQL Query")
end = time.time()

print(f"Result: {result is not None}")
print(f"Time taken: {end - start:.4f}s")

# Test with a line that might fail regex
fail_line = "some weird log line that doesn't match any regex"
print(f"\nTesting parse_line with failing line: {fail_line}")
start = time.time()
result = parse_line(fail_line, "Unknown")
end = time.time()
print(f"Result: {result is not None}")
print(f"Time taken: {end - start:.4f}s")
