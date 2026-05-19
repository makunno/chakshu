"""
Master Server for Distributed Log Processing
Distributes work across Cloudflare Workers and aggregates results
"""

import requests
import re
from typing import List, Dict, Any, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
import time

# Worker configuration - same as siem-tool/master-worker
WORKERS = [
    {'name': 'siem-worker-1', 'url': 'siem-worker-1.tanubhavj.workers.dev', 'healthy': True},
    {'name': 'siem-worker-2', 'url': 'siem-worker-2.tanubhavj.workers.dev', 'healthy': True},
    {'name': 'siem-worker-3', 'url': 'siem-worker-3.tanubhavj.workers.dev', 'healthy': True},
    {'name': 'siem-worker-4', 'url': 'siem-worker-4.tanubhavj.workers.dev', 'healthy': True},
    {'name': 'siem-worker-5', 'url': 'siem-worker-5.tanubhavj.workers.dev', 'healthy': True},
    {'name': 'siem-worker-6', 'url': 'siem-worker-6.tanubhavj.workers.dev', 'healthy': True},
    {'name': 'siem-worker-7', 'url': 'siem-worker-7.tanubhavj.workers.dev', 'healthy': True},
    {'name': 'siem-worker-8', 'url': 'siem-worker-8.tanubhavj.workers.dev', 'healthy': True},
    {'name': 'siem-worker-9', 'url': 'siem-worker-9.tanubhavj.workers.dev', 'healthy': True},
    {'name': 'siem-worker-10', 'url': 'siem-worker-10.tanubhavj.workers.dev', 'healthy': True},
    {'name': 'siem-worker-11', 'url': 'siem-worker-11.tanubhavj.workers.dev', 'healthy': True},
]

REQUEST_TIMEOUT = 30  # seconds
MAX_RETRIES = 2


def is_new_log_entry(line: str) -> bool:
    """Check if a line is the start of a new log entry"""
    if not line or line.strip() == '':
        return False
    
    # ISO format timestamp
    if re.match(r'^\d{4}[-/]\d{2}[-/]\d{2}[T ]\d{2}:\d{2}:\d{2}', line):
        return True
    
    # Unix timestamp
    if re.match(r'^\d{10,13}(\.\d+)?\s', line):
        return True
    
    # Syslog format
    if re.match(r'^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}', line):
        return True
    
    # Log level indicators
    if re.match(r'^(DEBUG|INFO|WARN|WARNING|ERROR|FATAL|CRITICAL|TRACE)\s*[\[:\-]', line, re.I):
        return True
    
    # Bracketed timestamps
    if re.match(r'^\[\d{4}[-/]\d{2}[-/]\d{2}', line):
        return True
    
    # Apache/Nginx format
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s+\S+\s+\S+\s+\[', line):
        return True
    
    # JSON logs
    if re.match(r'^\{\s*"(timestamp|time|ts|date)"\s*:', line):
        return True
    
    # Windows Event Log (CSV/Text)
    if re.match(r'^\d{4}[-\d\s:]+,(\d+,)?(Information|Warning|Error|Success|Failure|Audit|Info)', line, re.I):
        return True
    
    if line.startswith('TimeCreated,EventID,'):
        return True
    
    return False


def is_continuation_line(line: str) -> bool:
    """Check if a line is a continuation of the previous log entry"""
    if not line:
        return False
    
    # Stack trace lines
    if re.match(r'^\s+(at|File|line|in)\s+', line):
        return True
    
    # Indented continuation
    if re.match(r'^[\t ]{2,}', line):
        return True
    
    # Exception lines
    if re.match(r'^(Caused by|Exception|Traceback|\s+\.{3}\s+\d+ more)', line, re.I):
        return True
    
    # JSON continuation
    if re.match(r'^[\t ]+"', line):
        return True
    
    return False


def group_into_log_entries(lines: List[str]) -> List[str]:
    """Group lines into complete log entries"""
    entries = []
    current_entry = []
    
    for i, line in enumerate(lines):
        next_line = lines[i + 1] if i + 1 < len(lines) else None
        
        # Empty line - separator
        if line.strip() == '':
            if current_entry:
                entries.append('\n'.join(current_entry))
                current_entry = []
            continue
        
        # New log entry
        if is_new_log_entry(line):
            if current_entry:
                entries.append('\n'.join(current_entry))
            current_entry = [line]
        elif is_continuation_line(line) and current_entry:
            current_entry.append(line)
        elif current_entry:
            # Ambiguous - check next line
            if next_line and is_new_log_entry(next_line):
                current_entry.append(line)
                entries.append('\n'.join(current_entry))
                current_entry = []
            else:
                current_entry.append(line)
        else:
            current_entry = [line]
    
    # Don't forget the last entry
    if current_entry:
        entries.append('\n'.join(current_entry))
    
    return entries


def distribute_content(content: str, num_workers: int) -> List[Dict[str, Any]]:
    """Distribute log content across workers"""
    lines = content.split('\n')
    log_entries = group_into_log_entries(lines)
    total_entries = len(log_entries)
    
    print(f"Master: Grouped {len(lines)} lines into {total_entries} complete log entries")
    
    if total_entries == 0:
        return []
    
    entries_per_worker = max(1, (total_entries + num_workers - 1) // num_workers)
    chunks = []
    
    for i in range(num_workers):
        start_entry = i * entries_per_worker
        end_entry = min(start_entry + entries_per_worker, total_entries)
        
        if start_entry >= total_entries:
            break
        
        chunk_entries = log_entries[start_entry:end_entry]
        chunk_content = '\n'.join(chunk_entries)
        
        if chunk_content.strip():
            chunks.append({
                'worker_index': i,
                'content': chunk_content,
                'start_entry': start_entry,
                'end_entry': end_entry,
                'entry_count': len(chunk_entries)
            })
            print(f"Master: Chunk {i}: entries {start_entry}-{end_entry - 1}, {len(chunk_entries)} entries")
    
    return chunks


def process_chunk_with_retry(chunk: Dict, worker: Dict, file_name: str, 
                             total_chunks: int, retry_count: int = 0) -> Dict:
    """Process a chunk on a worker with retry logic"""
    try:
        headers = {
            'Content-Type': 'text/plain',
            'X-Chunk-Index': str(chunk['worker_index']),
            'X-Total-Chunks': str(total_chunks),
            'X-File-Name': file_name,
            'X-Distributed': 'true',
        }
        
        response = requests.post(
            f"https://{worker['url']}/parse",
            data=chunk['content'],
            headers=headers,
            timeout=REQUEST_TIMEOUT
        )
        
        if response.status_code != 200:
            error_text = response.text[:200]
            print(f"Master: Worker {worker['name']} error: HTTP {response.status_code}, {error_text}")
            raise Exception(f"Worker returned {response.status_code}")
        
        result = response.json()
        
        return {
            'worker': worker['name'],
            'chunk_index': chunk['worker_index'],
            'success': True,
            'data': result
        }
        
    except Exception as e:
        if retry_count < MAX_RETRIES:
            print(f"Master: Retrying chunk {chunk['worker_index']} on {worker['name']} "
                  f"(attempt {retry_count + 1}/{MAX_RETRIES})")
            time.sleep(1 * (retry_count + 1))  # Exponential backoff
            return process_chunk_with_retry(chunk, worker, file_name, total_chunks, retry_count + 1)
        
        print(f"Master: Worker {worker['name']} failed after {MAX_RETRIES} retries: {str(e)}")
        return {
            'worker': worker['name'],
            'chunk_index': chunk['worker_index'],
            'success': False,
            'error': str(e)
        }


def merge_results(results: List[Dict]) -> Dict:
    """Merge results from multiple workers"""
    successful_results = [r for r in results if r.get('success') and r.get('data')]
    
    if not successful_results:
        raise Exception('All workers failed to process the file')
    
    base_result = successful_results[0]['data']
    
    # Flatten arrays from all workers
    all_entries = []
    all_alerts = []
    
    for r in successful_results:
        data = r['data']
        if 'entries' in data:
            all_entries.extend(data['entries'])
        if 'alerts' in data:
            all_alerts.extend(data['alerts'])
    
    # Merge stats
    total_lines = 0
    parsed_lines = 0
    failed_lines = 0
    
    for r in successful_results:
        data = r['data']
        total_lines += data.get('totalLines', 0)
        parsed_lines += data.get('parsedLines', 0)
        failed_lines += data.get('failedLines', 0)
    
    success_rate = round(((total_lines - failed_lines) / total_lines * 100), 2) if total_lines > 0 else 0
    
    return {
        'success': True,
        'detectedType': base_result.get('detectedType', 'distributed'),
        'distributed': True,
        'totalLines': total_lines,
        'parsedLines': parsed_lines,
        'failedLines': failed_lines,
        'successRate': success_rate,
        'entries': all_entries,
        'alerts': all_alerts,
        'stats': {
            'totalLines': total_lines,
            'parsedLines': parsed_lines,
            'failedLines': failed_lines,
            'uniqueIPs': len(set(e.get('source', {}).get('ip') for e in all_entries if e.get('source', {}).get('ip'))),
        },
        'distribution': {
            'totalWorkers': len(WORKERS),
            'successful': len(successful_results),
            'failed': len(results) - len(successful_results),
        }
    }


def distribute_and_process(content: str, file_name: str = 'logs.log') -> Dict:
    """Main entry point: distribute file to workers and collect results"""
    print(f"Master: Distributing file {file_name} ({len(content)} bytes) to {len(WORKERS)} workers")
    
    # Split content into chunks
    chunks = distribute_content(content, len(WORKERS))
    
    if not chunks:
        return {'success': False, 'error': 'No content to process'}
    
    print(f"Master: Split into {len(chunks)} chunks")
    
    # Process chunks in parallel
    results = []
    with ThreadPoolExecutor(max_workers=len(chunks)) as executor:
        futures = []
        for i, chunk in enumerate(chunks):
            worker = WORKERS[i % len(WORKERS)]
            future = executor.submit(process_chunk_with_retry, chunk, worker, file_name, len(chunks))
            futures.append(future)
        
        for future in as_completed(futures):
            try:
                result = future.result()
                results.append(result)
            except Exception as e:
                print(f"Master: Future failed: {str(e)}")
                results.append({'success': False, 'error': str(e)})
    
    # Check if any succeeded
    successful = [r for r in results if r.get('success')]
    if not successful:
        return {
            'success': False,
            'error': 'All workers failed to process the file',
            'distribution': {
                'chunks': results,
                'totalWorkers': len(WORKERS),
                'successful': 0,
                'failed': len(results)
            }
        }
    
    # Merge results
    try:
        merged = merge_results(results)
        print(f"Master: Successfully merged results from {len(successful)} workers")
        return merged
    except Exception as e:
        return {
            'success': False,
            'error': f'Failed to merge results: {str(e)}',
            'distribution': {
                'chunks': results,
                'totalWorkers': len(WORKERS),
                'successful': len(successful),
                'failed': len(results) - len(successful)
            }
        }
