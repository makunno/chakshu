import re

line = '192.168.1.1 - - [17/Feb/2026:10:20:30 +0000] "GET /admin HTTP/1.1" 200 1234 "-" "Mozilla/5.0"'
APACHE_RE = re.compile(r'(\S+) - - \[(.*?)\] "(.*?)" (\d+) (\d+)')

match = APACHE_RE.match(line)
print('Match:', match)
if match:
    print('Groups:', match.groups())
