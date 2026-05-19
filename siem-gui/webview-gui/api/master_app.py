"""
Master-Slave Flask Server for SIEM Desktop App
Runs on port 5001, distributes work to Cloudflare Workers
"""

from flask import Flask, request, jsonify, send_file, send_from_directory
from flask_cors import CORS
import os
import sys
from pathlib import Path
import requests
import re
from typing import List, Dict, Any
from concurrent.futures import ThreadPoolExecutor, as_completed
import time

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent))
from parsers import auto_parse, detect_log_type, ALL_PARSERS
from detectors.alerts import run_detections, generate_stats

# Determine static folder path (same as app.py)
WEBVIEW_STATIC = Path(__file__).parent.parent / 'static'
FRONTEND_DIST = Path(__file__).parent.parent / 'siem-tool' / 'frontend' / 'dist'

if WEBVIEW_STATIC.exists():
    STATIC_FOLDER = WEBVIEW_STATIC
elif FRONTEND_DIST.exists():
    STATIC_FOLDER = FRONTEND_DIST
else:
    STATIC_FOLDER = WEBVIEW_STATIC

STATIC_FOLDER_STR = str(STATIC_FOLDER)

print(f"Master-Slave Static folder: {STATIC_FOLDER_STR}")

app = Flask(__name__, static_folder=STATIC_FOLDER_STR, static_url_path='/')
CORS(app)

@app.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization,X-Requested-With')
    response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
    return response

@app.route('/parsers', methods=['OPTIONS'])
@app.route('/parse', methods=['OPTIONS'])
@app.route('/correlate', methods=['OPTIONS'])
def handle_options(*args, **kwargs):
    """Handle CORS preflight requests"""
    response = app.make_default_options_response()
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization,X-Requested-With')
    response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
    return response

# Worker configuration - 11 Cloudflare workers
WORKERS = [
    {'name': f'siem-worker-{i}', 'url': f'siem-worker-{i}.tanubhavj.workers.dev', 'healthy': True}
    for i in range(1, 12)
]

REQUEST_TIMEOUT = 30
MAX_RETRIES = 2


def is_new_log_entry(line: str) -> bool:
    """Check if a line is the start of a new log entry"""
    if not line or line.strip() == '':
        return False
    
    patterns = [
        (r'^\d{4}[-/]\d{2}[-/]\d{2}[T ]\d{2}:\d{2}:\d{2}', 'ISO timestamp'),
        (r'^\d{10,13}(\.\d+)?\s', 'Unix timestamp'),
        (r'^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}', 'Syslog'),
        (r'^(DEBUG|INFO|WARN|WARNING|ERROR|FATAL|CRITICAL|TRACE)\s*[\[:\-]', 'Log level', re.I),
        (r'^\[\d{4}[-/]\d{2}[-/]\d{2}', 'Bracketed timestamp'),
        (r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s+\S+\s+\S+\s+\[', 'Apache/Nginx'),
        (r'^\{\s*"(timestamp|time|ts|date)"\s*:', 'JSON log'),
        (r'^\d{4}[-\d\s:]+,(Information|Warning|Error|Success|Failure)', 'Windows Event', re.I),
    ]
    
    for pattern, _, *flags in patterns:
        try:
            if re.match(pattern, line, flags[0] if flags else 0):
                return True
        except:
            if re.match(pattern, line):
                return True
    return False


def is_continuation_line(line: str) -> bool:
    """Check if a line is a continuation of the previous log entry"""
    if not line:
        return False
    if re.match(r'^\s+(at|File|line|in)\s+', line):  # Stack trace
        return True
    if re.match(r'^[\t ]{2,}', line):  # Indented
        return True
    if re.match(r'^(Caused by|Exception|Traceback)', line, re.I):  # Exception
        return True
    return False


def group_into_log_entries(lines: List[str]) -> List[str]:
    """Group lines into complete log entries"""
    entries = []
    current_entry = []
    
    for i, line in enumerate(lines):
        next_line = lines[i + 1] if i + 1 < len(lines) else None
        
        if line.strip() == '':
            if current_entry:
                entries.append('\n'.join(current_entry))
                current_entry = []
            continue
        
        if is_new_log_entry(line):
            if current_entry:
                entries.append('\n'.join(current_entry))
            current_entry = [line]
        elif is_continuation_line(line) and current_entry:
            current_entry.append(line)
        elif current_entry:
            if next_line and is_new_log_entry(next_line):
                current_entry.append(line)
                entries.append('\n'.join(current_entry))
                current_entry = []
            else:
                current_entry.append(line)
        else:
            current_entry = [line]
    
    if current_entry:
        entries.append('\n'.join(current_entry))
    
    return entries


def distribute_content(content: str, num_workers: int) -> List[Dict]:
    """Distribute log content across workers"""
    lines = content.split('\n')
    log_entries = group_into_log_entries(lines)
    total_entries = len(log_entries)
    
    print(f"[MASTER] Grouped {len(lines)} lines into {total_entries} complete log entries")
    
    if total_entries == 0:
        return []
    
    entries_per_worker = max(1, (total_entries + num_workers - 1) // num_workers)
    chunks = []
    
    for i in range(min(num_workers, total_entries)):
        start_entry = i * entries_per_worker
        end_entry = min(start_entry + entries_per_worker, total_entries)
        
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
            print(f"[MASTER] Chunk {i}: entries {start_entry}-{end_entry - 1}")
    
    return chunks


def process_chunk(chunk: Dict, worker: Dict, file_name: str, total_chunks: int, retry_count: int = 0) -> Dict:
    """Process a chunk on a Cloudflare worker with retry"""
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
            print(f"[MASTER] Worker {worker['name']} error: HTTP {response.status_code}")
            raise Exception(f"HTTP {response.status_code}")
        
        return {
            'worker': worker['name'],
            'chunk_index': chunk['worker_index'],
            'success': True,
            'data': response.json()
        }
        
    except Exception as e:
        if retry_count < MAX_RETRIES:
            print(f"[MASTER] Retrying chunk {chunk['worker_index']} on {worker['name']}")
            time.sleep(1 * (retry_count + 1))
            return process_chunk(chunk, worker, file_name, total_chunks, retry_count + 1)
        
        print(f"[MASTER] Worker {worker['name']} failed: {str(e)}")
        return {
            'worker': worker['name'],
            'chunk_index': chunk['worker_index'],
            'success': False,
            'error': str(e)
        }


def merge_results(results: List[Dict]) -> Dict:
    """Merge results from multiple workers"""
    successful = [r for r in results if r.get('success') and r.get('data')]
    
    if not successful:
        raise Exception('All workers failed')
    
    base = successful[0]['data']
    
    all_entries = []
    all_alerts = []
    
    for r in successful:
        data = r['data']
        if 'entries' in data:
            all_entries.extend(data['entries'])
        if 'alerts' in data:
            all_alerts.extend(data['alerts'])
    
    total_lines = sum(r['data'].get('totalLines', 0) for r in successful)
    parsed_lines = sum(r['data'].get('parsedLines', 0) for r in successful)
    failed_lines = sum(r['data'].get('failedLines', 0) for r in successful)
    
    success_rate = round(((total_lines - failed_lines) / total_lines * 100), 2) if total_lines > 0 else 0
    
    return {
        'success': True,
        'detectedType': base.get('detectedType', 'distributed'),
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
            'successful': len(successful),
            'failed': len(results) - len(successful),
        }
    }


@app.route('/')
def index():
    """Serve the React app with API URL injected"""
    try:
        with open(os.path.join(STATIC_FOLDER_STR, 'index.html'), 'r') as f:
            html = f.read()
        
        injected_html = html.replace(
            '</head>',
            '<script>window.FREEKHANA_API_URL="";</script></head>'
        )
        return injected_html
    except Exception as e:
        print(f"Error serving index.html: {e}")
        return send_from_directory(STATIC_FOLDER_STR, 'index.html')


@app.route('/assets/<path:filename>')
def serve_assets(filename):
    """Serve assets from static/assets folder"""
    assets_folder = os.path.join(STATIC_FOLDER_STR, 'assets')
    return send_from_directory(assets_folder, filename)


@app.route('/vite.svg')
def serve_vite_svg():
    """Serve vite.svg from static folder"""
    return send_from_directory(STATIC_FOLDER_STR, 'vite.svg')


@app.route('/<path:path>')
def serve_static(path):
    """Serve static files"""
    static_path = os.path.join(STATIC_FOLDER_STR, path)
    if os.path.isfile(static_path):
        return send_from_directory(STATIC_FOLDER_STR, path)
    return send_from_directory(STATIC_FOLDER_STR, 'index.html')


@app.route('/health')
def health():
    """Health check endpoint"""
    return jsonify({
        'status': 'ok',
        'name': 'Cyber Chakshu SIEM Master-Slave Server',
        'workers': len(WORKERS),
        'mode': 'distributed'
    })


@app.route('/parsers')
def get_parsers():
    """List available parsers"""
    parsers = ALL_PARSERS
    
    categories = {}
    for p in parsers:
        cat = p.get('category', 'general')
        if cat not in categories:
            categories[cat] = []
        categories[cat].append({'name': p['name'], 'logType': p['logType']})
    
    return jsonify({
        'total': len(parsers),
        'categories': categories,
        'all': [{'name': p['name'], 'logType': p['logType']} for p in parsers],
    })


@app.route('/parse', methods=['POST'])
def parse_logs():
    """Main parse endpoint - distributes work to Cloudflare workers"""
    try:
        print(f"[MASTER] Processing /parse request")
        content_type = request.content_type or ''
        content = None
        file_name = 'logs.log'

        if 'multipart/form-data' in content_type:
            if 'file' in request.files:
                file = request.files['file']
                content = file.read().decode('utf-8', errors='ignore')
                file_name = file.filename or 'logs.log'
        elif 'application/json' in content_type:
            data = request.get_json()
            content = data.get('content') or ''
            file_name = data.get('fileName', 'logs.log')
        else:
            content = request.get_data(as_text=True)
            file_name = request.headers.get('X-File-Name', 'logs.log')

        if not content or len(content.strip()) == 0:
            return jsonify({'error': 'No log content provided'}), 400

        print(f"[MASTER] Distributing {len(content)} bytes to {len(WORKERS)} workers")
        
        chunks = distribute_content(content, len(WORKERS))
        if not chunks:
            return jsonify({'success': False, 'error': 'No content to process'}), 400
        
        print(f"[MASTER] Created {len(chunks)} chunks")
        
        results = []
        with ThreadPoolExecutor(max_workers=len(chunks)) as executor:
            futures = []
            for i, chunk in enumerate(chunks):
                worker = WORKERS[i % len(WORKERS)]
                future = executor.submit(process_chunk, chunk, worker, file_name, len(chunks))
                futures.append(future)
            
            for future in as_completed(futures):
                try:
                    results.append(future.result())
                except Exception as e:
                    print(f"[MASTER] Future failed: {str(e)}")
                    results.append({'success': False, 'error': str(e)})
        
        successful = [r for r in results if r.get('success')]
        if not successful:
            return jsonify({
                'success': False,
                'error': 'All workers failed',
                'distribution': {
                    'totalWorkers': len(WORKERS),
                    'successful': 0,
                    'failed': len(results)
                }
            }), 500
        
        merged = merge_results(results)
        print(f"[MASTER] Successfully processed with {len(successful)} workers")
        return jsonify(merged)

    except Exception as e:
        print(f"[MASTER ERROR] {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Failed to process distributed parse',
            'details': str(e)
        }), 500


if __name__ == '__main__':
    print("=" * 60)
    print("Cyber Chakshu SIEM Master-Slave Server")
    print("=" * 60)
    print(f"Workers: {len(WORKERS)}")
    print(f"Port: 5001")
    print("=" * 60)
    app.run(debug=True, host='127.0.0.1', port=5001)
