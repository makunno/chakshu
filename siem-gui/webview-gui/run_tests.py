from api.app import app
client = app.test_client()

import os
test_dir = 'test_logs'
print("=" * 60)
print("ML ATTACK DETECTION TEST RESULTS")
print("=" * 60)

for filename in sorted(os.listdir(test_dir)):
    if filename.endswith('.log'):
        with open(os.path.join(test_dir, filename), 'r') as f:
            content = f.read()
        result = client.post('/parse', data=content, content_type='text/plain').get_json()
        total_attacks = result.get("attackSummary", {}).get("totalAttacks", 0)
        print(f'\n{filename}: {total_attacks} attacks detected')
        
        attack_types = {}
        if result.get('mlAttacks'):
            for attack in result['mlAttacks']:
                attack_type = attack['attackType']
                attack_types[attack_type] = attack_types.get(attack_type, 0) + 1
        
        if attack_types:
            print('  Attack types detected:')
            for attack_type, count in sorted(attack_types.items()):
                print(f'    - {attack_type}: {count}')
        else:
            print('  No attacks detected')

print("\n" + "=" * 60)
print("TEST SUMMARY")
print("=" * 60)
print("""
Expected results:
- apache_attacks.log: Should detect SQL injection, XSS, command injection, 
                      directory traversal, file inclusion
- apache_normal.log: Should detect 0 attacks ✓
- ssh_attacks.log: Should detect password_spray/bruteforce
- ssh_normal.log: Should detect 0 attacks ✓
- mixed_attacks.log: Should detect multiple attack types
- mixed_normal.log: Should detect 0 attacks ✓
""")
