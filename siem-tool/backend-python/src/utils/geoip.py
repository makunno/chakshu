"""
GeoIP Utility - Fetch country code from IP address
Uses ip-api.com (free for low volume)
"""

import requests
import functools
import time
from typing import List, Dict

# Simple cache to avoid redundant API calls
@functools.lru_cache(maxsize=1000)
def get_country_code(ip: str) -> str:
    if not ip or ip in ['127.0.0.1', 'localhost', '::1'] or ip.startswith('192.168.') or ip.startswith('10.') or ip.startswith('172.16.'):
        return 'LOCAL'
        
    try:
        # Using ip-api.com (limit: 45 requests per minute)
        response = requests.get(f'http://ip-api.com/json/{ip}?fields=countryCode', timeout=2)
        if response.status_code == 200:
            data = response.json()
            return data.get('countryCode', '??')
        elif response.status_code == 429:
            print(f"GeoIP rate limit exceeded for {ip}")
    except Exception as e:
        print(f"GeoIP lookup failed for {ip}: {e}")
        
    return '??'

def get_country_codes_bulk(ips: List[str]) -> Dict[str, str]:
    """Fetch country codes for multiple IPs using the batch API"""
    if not ips:
        return {}
        
    unique_ips = list(set(ips))
    results = {}
    
    # Filter out local IPs
    to_lookup = []
    for ip in unique_ips:
        if not ip or ip in ['127.0.0.1', 'localhost', '::1'] or ip.startswith('192.168.') or ip.startswith('10.') or ip.startswith('172.16.'):
            results[ip] = 'LOCAL'
        else:
            to_lookup.append(ip)
            
    if not to_lookup:
        return results
        
    # ip-api.com batch limit is 100 per request
    batch_size = 100
    for i in range(0, len(to_lookup), batch_size):
        batch = to_lookup[i:i+batch_size]
        try:
            # Batch endpoint: http://ip-api.com/batch
            response = requests.post(
                'http://ip-api.com/batch?fields=query,countryCode',
                json=[{"query": ip} for ip in batch],
                timeout=5
            )
            if response.status_code == 200:
                data = response.json()
                for item in data:
                    results[item.get('query')] = item.get('countryCode', '??')
            else:
                print(f"GeoIP batch lookup failed: {response.status_code}")
                for ip in batch:
                    results[ip] = '??'
        except Exception as e:
            print(f"GeoIP batch lookup error: {e}")
            for ip in batch:
                results[ip] = '??'
                
        # Small delay between batches if multiple
        if i + batch_size < len(to_lookup):
            time.sleep(1)
            
    return results
