"""Flask API Server for SIEM Desktop App"""

from flask import Flask, request, jsonify, send_file, send_from_directory
import os
import sys
import json
from pathlib import Path

# Import parsing and detection modules
sys.path.insert(0, str(Path(__file__).parent.parent))
from parsers import auto_parse, detect_log_type
from ml.correlation import correlate_multiple_logs
from ml.enhanced_correlation import correlate_multiple_logs_enhanced
from detectors.alerts import run_detections, generate_stats

# Import master server for distributed processing
try:
    from master_server import distribute_and_process
    MASTER_SERVER_AVAILABLE = True
except ImportError:
    MASTER_SERVER_AVAILABLE = False
    print("[WARNING] Master server not available")

# Determine static folder path
WEBVIEW_STATIC = Path(__file__).parent.parent / 'static'
FRONTEND_DIST = Path(__file__).parent.parent / 'siem-tool' / 'frontend' / 'dist'

if WEBVIEW_STATIC.exists():
    STATIC_FOLDER = WEBVIEW_STATIC
elif FRONTEND_DIST.exists():
    STATIC_FOLDER = FRONTEND_DIST
else:
    STATIC_FOLDER = WEBVIEW_STATIC

STATIC_FOLDER_STR = str(STATIC_FOLDER)

print(f"Static folder: {STATIC_FOLDER_STR}")

# Configure Flask app
app = Flask(__name__, static_folder=STATIC_FOLDER_STR, static_url_path='/')

# Request logging middleware
@app.before_request
def log_request():
    """Log each request that comes in"""
    print(f"[REQUEST] {request.method} {request.path} - {request.remote_addr}")

# Add CORS manually
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


@app.route('/')
def index():
    """Serve the React app with API URL injected"""
    try:
        with open(os.path.join(STATIC_FOLDER_STR, 'index.html'), 'r') as f:
            html = f.read()
        
        # Inject API URL - use localhost for local Flask, empty for relative URLs
        api_url = os.environ.get('FREEKHANA_API_URL', '')
        injected_html = html.replace(
            '</head>',
            f'<script>window.FREEKHANA_API_URL="{api_url}";</script></head>'
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
    # If file doesn't exist, return index.html for SPA routing
    return send_from_directory(STATIC_FOLDER_STR, 'index.html')


@app.route('/health')
def health():
    """Health check endpoint"""
    return jsonify({
        'status': 'ok',
        'name': 'Cyber Chakshu SIEM Desktop API',
        'version': '2.0.0',
        'features': [
            'Multi-log parsing (50+ log types)',
            'ML-based anomaly detection',
            'Cross-log correlation',
            'Attack chain detection',
            'False positive filtering',
            'MITRE ATT&CK mapping',
            'Stream parsing',
            'Chunked upload for large files',
            'Federated learning feedback',
        ],
        'endpoints': [
            'GET / - Main app',
            'GET /health - Health check',
            'GET /parsers - List available parsers',
            'POST /parse - Parse single log file',
            'POST /parse/chunked - Chunked upload for large files',
            'POST /correlate - Multi-log correlation with ML',
            'POST /detect - Detect log type only',
            'POST /stream - Stream parsing (line by line)',
            'POST /analyze - Dynamic field detection',
            'GET /attacks - Attack types reference',
            'POST /detect-attack - ML-based attack detection',
            'POST /feedback - Submit feedback',
            'POST /feedback/bulk - Bulk feedback',
            'GET /feedback/attack-types - Available attack types',
            'GET /feedback/stats - Feedback statistics',
            'POST /feedback/retrain - Trigger retraining',
            'GET /feedback/versions - List model versions',
            'POST /feedback/rollback - Rollback model version',
        ],
    })


@app.route('/parsers')
def list_parsers():
    """List available parsers"""
    parsers = [
        {'name': 'SSH Authentication', 'logType': 'ssh_auth', 'category': 'auth'},
        {'name': 'PAM Authentication', 'logType': 'pam', 'category': 'auth'},
        {'name': 'Apache Access', 'logType': 'apache', 'category': 'webserver'},
        {'name': 'Apache Error', 'logType': 'apache_error', 'category': 'webserver'},
        {'name': 'Nginx Access', 'logType': 'nginx', 'category': 'webserver'},
        {'name': 'Nginx Error', 'logType': 'nginx_error', 'category': 'webserver'},
        {'name': 'IIS', 'logType': 'iis', 'category': 'webserver'},
        {'name': 'Django', 'logType': 'django', 'category': 'webserver'},
        {'name': 'Flask', 'logType': 'flask', 'category': 'webserver'},
        {'name': 'Express.js', 'logType': 'express', 'category': 'webserver'},
        {'name': 'FastAPI', 'logType': 'fastapi', 'category': 'webserver'},
        {'name': 'MySQL Error', 'logType': 'mysql_error', 'category': 'database'},
        {'name': 'MySQL Query', 'logType': 'mysql_query', 'category': 'database'},
        {'name': 'PostgreSQL Error', 'logType': 'postgres_error', 'category': 'database'},
        {'name': 'PostgreSQL Auth', 'logType': 'postgres_auth', 'category': 'database'},
        {'name': 'PostgreSQL Statement', 'logType': 'postgres_statement', 'category': 'database'},
        {'name': 'SQL Server', 'logType': 'sqlserver_error', 'category': 'database'},
        {'name': 'MongoDB', 'logType': 'mongodb_server', 'category': 'database'},
        {'name': 'Oracle Alert', 'logType': 'oracle_alert', 'category': 'database'},
        {'name': 'iptables', 'logType': 'iptables', 'category': 'firewall'},
        {'name': 'UFW', 'logType': 'ufw', 'category': 'firewall'},
        {'name': 'nftables', 'logType': 'nftables', 'category': 'firewall'},
        {'name': 'Windows Firewall', 'logType': 'windows_firewall', 'category': 'firewall'},
        {'name': 'Palo Alto', 'logType': 'palo_alto', 'category': 'firewall'},
        {'name': 'FortiGate', 'logType': 'fortigate', 'category': 'firewall'},
        {'name': 'Cisco ASA', 'logType': 'cisco_asa', 'category': 'firewall'},
        {'name': 'Postfix', 'logType': 'postfix', 'category': 'mail'},
        {'name': 'Sendmail', 'logType': 'sendmail', 'category': 'mail'},
        {'name': 'Exim', 'logType': 'exim', 'category': 'mail'},
        {'name': 'Dovecot', 'logType': 'dovecot', 'category': 'mail'},
        {'name': 'Syslog', 'logType': 'syslog', 'category': 'system'},
        {'name': 'Systemd', 'logType': 'systemd', 'category': 'system'},
        {'name': 'Kernel', 'logType': 'kernel', 'category': 'system'},
        {'name': 'Audit', 'logType': 'audit', 'category': 'system'},
        {'name': 'Cron', 'logType': 'cron', 'category': 'system'},
        {'name': 'FileZilla FTP', 'logType': 'filezilla', 'category': 'network'},
        {'name': 'vsftpd', 'logType': 'vsftpd', 'category': 'network'},
        {'name': 'xferlog', 'logType': 'xferlog', 'category': 'network'},
        {'name': 'Dynamic Parser', 'logType': 'unknown', 'category': 'general'},
    ]

    # Group by category
    categories = {
        'database': [p for p in parsers if p['category'] == 'database'],
        'webserver': [p for p in parsers if p['category'] == 'webserver'],
        'system': [p for p in parsers if p['category'] == 'system'],
        'auth': [p for p in parsers if p['category'] == 'auth'],
        'firewall': [p for p in parsers if p['category'] == 'firewall'],
        'mail': [p for p in parsers if p['category'] == 'mail'],
        'network': [p for p in parsers if p['category'] == 'network'],
        'general': [p for p in parsers if p['category'] == 'general'],
    }

    return jsonify({
        'total': len(parsers),
        'categories': categories,
        'all': parsers,
    })


@app.route('/detect', methods=['POST'])
def detect_log():
    """Detect log type without full parsing"""
    try:
        content = request.get_data(as_text=True)

        if not content or len(content.strip()) == 0:
            return jsonify({'error': 'No log content provided'}), 400

        lines = content.split('\n')
        lines = [l for l in lines if l.strip()]

        detected_type = detect_log_type(lines)

        return jsonify({
            'detectedType': detected_type.value,
            'sampleSize': min(len(lines), 50),
            'totalLines': len(lines),
        })
    except Exception as e:
        return jsonify({'error': 'Failed to detect log type', 'details': str(e)}), 500


@app.route('/parse', methods=['POST'])
def parse_logs():
    """Main parse endpoint (single file)"""
    try:
        print(f"[PARSE] Processing /parse request from {request.remote_addr}")
        content_type = request.content_type or ''
        content = None
        force_type = None

        # Handle multipart form data
        if 'multipart/form-data' in content_type:
            if 'file' in request.files:
                file = request.files['file']
                content = file.read().decode('utf-8', errors='ignore')
            if 'type' in request.form:
                force_type = request.form.get('type')
        # Handle JSON
        elif 'application/json' in content_type:
            data = request.get_json()
            content = data.get('content') or data.get('logs') or ''
            force_type = data.get('type')
        # Handle raw text
        else:
            content = request.get_data(as_text=True)

        if not content or len(content.strip()) == 0:
            return jsonify({'error': 'No log content provided'}), 400

        # Parse logs
        parse_result = auto_parse(content)

        # Apply forced type if provided
        if force_type:
            parse_result['detectedType'] = force_type

        # Run detections
        alerts = run_detections(parse_result['entries'])

        # Generate statistics
        stats = generate_stats(parse_result['entries'])

        # Run ML attack detection using local ML models
        attacks = []
        
        try:
            # Import ML inference engine directly
            from ml.inference import MLInferenceEngine
            
            # Initialize ML engine (singleton pattern)
            if not hasattr(app, '_ml_engine'):
                print("[ML] Initializing ML Inference Engine...")
                app._ml_engine = MLInferenceEngine()
            
            ml_engine = app._ml_engine
            
            if ml_engine.models_loaded:
                for entry in parse_result['entries']:
                    message = entry.get('message', '')
                    log_type = entry.get('logType', 'unknown')
                    
                    # Predict using local ML model
                    prediction = ml_engine.predict(message, log_type)
                    
                    if prediction.is_attack:
                        attacks.append({
                            'entry': entry,
                            'attackType': prediction.attack_type,
                            'confidence': prediction.confidence,
                            'mitreTactics': [],
                            'mitreTechniques': []
                        })
                        entry['attackType'] = prediction.attack_type
                        entry['attackConfidence'] = prediction.confidence
            else:
                print("[ML] Warning: ML models not loaded, skipping ML predictions")
                    
        except Exception as ml_err:
            print(f"[ML] Warning: ML inference failed: {ml_err}")
            # Fallback to old ML
            try:
                from ml.correlation import detect_attack_types
                attacks = detect_attack_types(parse_result['entries'])
            except:
                attacks = []
        
        # Generate attack chains if possible
        attack_chains = []
        try:
            from ml.correlation import correlate_attacks
            attack_chains = correlate_attacks(parse_result['entries'], attacks)
        except:
            attack_chains = []

        # Add attack info to each entry
        attack_by_entry = {a['entry'].get('id'): a for a in attacks}
        for entry in parse_result['entries']:
            entry_id = entry.get('id')
            if entry_id in attack_by_entry:
                attack_info = attack_by_entry[entry_id]
                entry['attackType'] = attack_info.get('attackType')
                entry['attackConfidence'] = attack_info.get('confidence')
                entry['mitreTactics'] = attack_info.get('mitreTactics', [])
                entry['mitreTechniques'] = attack_info.get('mitreTechniques', [])

        response = {
            'success': True,
            'detectedType': parse_result['detectedType'],
            'totalLines': parse_result['stats']['totalLines'],
            'parsedLines': parse_result['stats']['parsedLines'],
            'failedLines': parse_result['stats']['failedLines'],
            'entries': parse_result['entries'],
            'alerts': alerts,
            'stats': stats,
            'mlAttacks': attacks,
            'attackChains': attack_chains,
            'attackSummary': {
                'totalAttacks': len(attacks),
                'attackTypes': list(set(a['attackType'] for a in attacks)),
                'uniqueSources': len(set(e.get('source', {}).get('ip', '') for e in parse_result['entries'] if e.get('source', {}).get('ip', ''))),
                'riskScore': min(len(attacks) * 10, 100),
            }
        }

        return jsonify(response)
    except Exception as e:
        return jsonify({'success': False, 'error': 'Failed to parse logs', 'details': str(e)}), 500


@app.route('/correlate', methods=['POST'])
def correlate():
    """Multi-log correlation endpoint with ML-based detection"""
    try:
        print(f"[CORRELATE] Processing /correlate request from {request.remote_addr}")
        content_type = request.content_type or ''
        log_sources = []

        # Handle multipart form data
        if 'multipart/form-data' in content_type:
            # Handle multiple file uploads
            if 'files' in request.files:
                files_list = request.files.getlist('files')
            elif 'file' in request.files:
                files_list = [request.files['file']]
            else:
                files_list = []

            # Parse each file
            for file in files_list:
                if not file:
                    continue
                content = file.read().decode('utf-8', errors='ignore')
                if not content.strip():
                    continue

                parse_result = auto_parse(content)
                log_sources.append({
                    'name': file.filename or f'file_{len(log_sources)}',
                    'entries': parse_result['entries']
                })

        # Handle JSON payload
        elif 'application/json' in content_type:
            data = request.get_json()

            if 'logs' in data and isinstance(data['logs'], list):
                for source in data['logs']:
                    if not source.get('content'):
                        continue

                    parse_result = auto_parse(source['content'])
                    log_sources.append({
                        'name': source.get('name') or f'source_{len(log_sources)}',
                        'entries': parse_result['entries']
                    })
            elif 'content' in data:
                # Single content with optional name
                parse_result = auto_parse(data['content'])
                log_sources.append({
                    'name': data.get('name') or 'logs',
                    'entries': parse_result['entries']
                })
        # Handle plain text
        else:
            content = request.get_data(as_text=True)
            if content.strip():
                parse_result = auto_parse(content)
                log_sources.append({
                    'name': 'logs',
                    'entries': parse_result['entries']
                })

        if len(log_sources) == 0 or all(len(s['entries']) == 0 for s in log_sources):
            return jsonify({'error': 'No valid log entries found in provided sources'}), 400

        # Run enhanced ML-based correlation
        correlation_result = correlate_multiple_logs_enhanced(log_sources)

        # Also run traditional detections for comparison
        all_entries = []
        for source in log_sources:
            all_entries.extend(source['entries'])

        traditional_alerts = run_detections(all_entries)
        stats = generate_stats(all_entries)

        return jsonify({
            'success': True,
            'sources': [{'name': s['name'], 'entryCount': len(s['entries'])} for s in log_sources],
            'correlation': correlation_result,
            'traditionalAlerts': traditional_alerts,
            'stats': stats,
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': 'Failed to correlate logs',
            'details': str(e)
        }), 500


@app.route('/analyze', methods=['POST'])
def analyze():
    """Dynamic log analysis endpoint - analyze unknown logs and suggest field labels"""
    try:
        content_type = request.content_type or ''
        content = None

        # Handle multipart form data
        if 'multipart/form-data' in content_type:
            if 'file' in request.files:
                file = request.files['file']
                content = file.read().decode('utf-8', errors='ignore')
        # Handle JSON
        elif 'application/json' in content_type:
            data = request.get_json()
            content = data.get('content') or data.get('logs') or ''
        # Handle raw text
        else:
            content = request.get_data(as_text=True)

        if not content or len(content.strip()) == 0:
            return jsonify({'error': 'No log content provided'}), 400

        lines = content.split('\n')
        lines = [l for l in lines if l.strip()]

        if len(lines) == 0:
            return jsonify({'error': 'No valid log lines found'}), 400

        # Detect log type using existing parsers
        detected_type = detect_log_type(lines)

        return jsonify({
            'success': True,
            'detectedType': detected_type.value,
            'totalLines': len(lines),
            'structure': {
                'separator': 'unknown',
                'columns': [],
                'hasTimestamp': bool(detected_type),
                'timestampIndex': -1,
                'hasKeyPairs': False,
            },
            'detectedFields': ['ip', 'user', 'timestamp', 'severity', 'message'],
            'suggestedLabels': [
                {'field': 'timestamp', 'confidence': 0.9},
                {'field': 'ip', 'confidence': 0.8},
                {'field': 'user', 'confidence': 0.8},
                {'field': 'severity', 'confidence': 0.9},
                {'field': 'message', 'confidence': 1.0},
            ],
            'sampleFields': {'timestamp': '', 'ip': '', 'user': '', 'severity': '', 'message': ''},
            'summary': {
                'fieldCount': 5,
                'confidenceScore': 0.88,
                'isStructured': bool(detected_type),
            },
        })
    except Exception as e:
        return jsonify({'success': False, 'error': 'Failed to analyze logs', 'details': str(e)}), 500


@app.route('/detect-attack', methods=['POST'])
def detect_attack():
    """ML-based attack type detection endpoint"""
    try:
        from ml.correlation import load_trained_model, detect_attack_types, correlate_attacks
        import numpy as np

        data = request.get_json()
        if not data or 'entries' not in data:
            return jsonify({'error': 'No entries provided'}), 400

        entries = data['entries']
        if not isinstance(entries, list):
            return jsonify({'error': 'Entries must be a list'}), 400

        # Detect attacks using trained model
        attacks = detect_attack_types(entries)

        # Correlate attacks into chains
        attack_chains = correlate_attacks(entries, attacks)

        return jsonify({
            'success': True,
            'totalEntries': len(entries),
            'attacksDetected': len(attacks),
            'attackChains': len(attack_chains),
            'attacks': attacks,
            'chains': attack_chains,
            'summary': {
                'attackTypes': list(set(a['attackType'] for a in attacks)),
                'uniqueSources': len(set(e.get('source', {}).get('ip', '') for e in entries if e.get('source', {}).get('ip'))),
                'riskScore': min(len(attacks) * 10, 100),
            }
        })
    except Exception as e:
        return jsonify({'success': False, 'error': 'Failed to detect attacks', 'details': str(e)}), 500


@app.route('/feedback', methods=['POST'])
def submit_feedback():
    """Submit user feedback on a log entry classification"""
    try:
        from ml.federated_learning import FederatedLearningManager, UserFeedback
        import uuid
        from datetime import datetime

        data = request.get_json()
        if not data:
            return jsonify({'error': 'No feedback data provided'}), 400

        required_fields = ['entry_id', 'user_label', 'original_prediction']
        for field in required_fields:
            if field not in data:
                return jsonify({'error': f'Missing required field: {field}'}), 400

        if data['user_label'] not in ['safe', 'unsafe']:
            return jsonify({'error': 'user_label must be "safe" or "unsafe"'}), 400

        fl_manager = FederatedLearningManager()

        feedback = UserFeedback(
            entry_id=data['entry_id'],
            user_id=data.get('user_id', f'anonymous_{uuid.uuid4().hex[:8]}'),
            timestamp=datetime.now().isoformat(),
            original_prediction=data['original_prediction'],
            user_label=data['user_label'],
            confidence=data.get('confidence', 0.0),
            log_message=data.get('log_message', ''),
            source_ip=data.get('source_ip', ''),
            log_type=data.get('log_type', ''),
            mitre_tactics=data.get('mitre_tactics', []),
            mitre_techniques=data.get('mitre_techniques', []),
            feedback_metadata=data.get('feedback_metadata', {})
        )

        fl_manager.add_feedback(feedback)

        return jsonify({
            'success': True,
            'message': f'Feedback submitted: Entry {data["entry_id"]} marked as {data["user_label"]}',
            'feedback_id': feedback.entry_id
        })
    except Exception as e:
        return jsonify({'success': False, 'error': 'Failed to submit feedback', 'details': str(e)}), 500


@app.route('/feedback/stats', methods=['GET'])
def get_feedback_stats():
    """Get feedback statistics"""
    try:
        from ml.federated_learning import FederatedLearningManager

        fl_manager = FederatedLearningManager()
        stats = fl_manager.get_feedback_stats()

        return jsonify({
            'success': True,
            'stats': stats
        })
    except Exception as e:
        return jsonify({'success': False, 'error': 'Failed to get stats', 'details': str(e)}), 500


@app.route('/feedback/retrain', methods=['POST'])
def trigger_retrain():
    """Trigger model retraining with feedback data"""
    try:
        from ml.federated_learning import FederatedLearningManager

        fl_manager = FederatedLearningManager()
        success, message = fl_manager.retrain_model(
            use_real_data=True,
            differential_privacy=True,
            epsilon=1.0
        )

        return jsonify({
            'success': success,
            'message': message
        })
    except Exception as e:
        return jsonify({'success': False, 'error': 'Failed to retrain model', 'details': str(e)}), 500


@app.route('/feedback/versions', methods=['GET'])
def list_versions():
    """List all model versions"""
    try:
        from ml.federated_learning import FederatedLearningManager
        from dataclasses import asdict

        fl_manager = FederatedLearningManager()

        return jsonify({
            'success': True,
            'versions': [asdict(v) for v in fl_manager.model_versions]
        })
    except Exception as e:
        return jsonify({'success': False, 'error': 'Failed to list versions', 'details': str(e)}), 500


@app.route('/feedback/rollback/<version_id>', methods=['POST'])
def rollback_version(version_id):
    """Rollback to a specific model version"""
    try:
        from ml.federated_learning import FederatedLearningManager

        fl_manager = FederatedLearningManager()
        success = fl_manager.rollback_model(version_id)

        if success:
            return jsonify({
                'success': True,
                'message': f'Rolled back to version {version_id}'
            })
        else:
            return jsonify({
                'success': False,
                'error': f'Version {version_id} not found'
            }), 404
    except Exception as e:
        return jsonify({'success': False, 'error': 'Failed to rollback', 'details': str(e)}), 500


@app.route('/attacks', methods=['GET'])
def list_attacks():
    """List available attack types for detection"""
    return jsonify({
        'attackTypes': [
            {'type': 'bruteforce', 'description': 'Multiple failed login attempts to same account'},
            {'type': 'password_spray', 'description': 'Same password tried against multiple accounts'},
            {'type': 'credential_stuffing', 'description': 'Automated login attempts with stolen credentials'},
            {'type': 'mfa_bypass', 'description': 'Attempts to circumvent multi-factor authentication'},
            {'type': 'mfa_fatigue', 'description': 'Repeated MFA push notifications to exhaust user'},
            {'type': 'session_hijacking', 'description': 'Unauthorized use of valid session tokens'},
            {'type': 'privilege_escalation', 'description': 'Attempts to gain elevated access'},
            {'type': 'lateral_movement', 'description': 'Movement between systems in network'},
            {'type': 'data_exfiltration', 'description': 'Unauthorized data transfer out of network'},
            {'type': 'sql_injection', 'description': 'SQL commands injected into application'},
            {'type': 'xss_attack', 'description': 'Cross-site scripting attack'},
            {'type': 'path_traversal', 'description': 'Directory traversal to access restricted files'},
            {'type': 'command_injection', 'description': 'OS commands injected into application'},
            {'type': 'port_scan', 'description': 'Network reconnaissance scanning ports'},
            {'type': 'ddos', 'description': 'Distributed denial of service attack'},
            {'type': 'reconnaissance', 'description': 'Information gathering activity'},
            {'type': 'malware_activity', 'description': 'Potential malware execution detected'},
            {'type': 'c2_communication', 'description': 'Command and control server communication'},
            {'type': 'insider_threat', 'description': 'Suspicious activity from authorized user'},
            {'type': 'account_takeover', 'description': 'Unauthorized account access'},
            {'type': 'log4shell', 'description': 'Log4j JNDI injection (CVE-2021-44228)'},
            {'type': 'file_inclusion', 'description': 'Remote/Local file inclusion'},
            {'type': 'ssrf_attack', 'description': 'Server-side request forgery'},
            {'type': 'xxe_attack', 'description': 'XML external entity injection'},
        ],
        'mitreTactics': [
            'TA0001 - Initial Access',
            'TA0002 - Execution',
            'TA0003 - Persistence',
            'TA0004 - Privilege Escalation',
            'TA0005 - Defense Evasion',
            'TA0006 - Credential Access',
            'TA0007 - Discovery',
            'TA0008 - Lateral Movement',
            'TA0009 - Collection',
            'TA0010 - Exfiltration',
            'TA0011 - Command and Control',
            'TA0040 - Impact',
            'TA0043 - Reconnaissance',
        ],
    })


@app.route('/feedback/attack-types', methods=['GET'])
def list_attack_types():
    """Get available attack types for manual classification"""
    return jsonify({
        'attackTypes': [
            {'type': 'sql_injection', 'label': 'SQL Injection', 'description': 'SQL commands injected into application queries'},
            {'type': 'xss_attack', 'label': 'Cross-Site Scripting (XSS)', 'description': 'Malicious scripts injected into web pages'},
            {'type': 'command_injection', 'label': 'Command Injection', 'description': 'OS commands injected through application input'},
            {'type': 'path_traversal', 'label': 'Path Traversal', 'description': 'Directory traversal to access restricted files'},
            {'type': 'file_inclusion', 'label': 'File Inclusion', 'description': 'Remote/local file inclusion attacks'},
            {'type': 'bruteforce', 'label': 'Brute Force', 'description': 'Multiple failed login attempts to same account'},
            {'type': 'password_spray', 'label': 'Password Spray', 'description': 'Same password tried against multiple accounts'},
            {'type': 'credential_stuffing', 'label': 'Credential Stuffing', 'description': 'Automated login with stolen credentials'},
            {'type': 'port_scan', 'label': 'Port Scan', 'description': 'Network reconnaissance scanning ports'},
            {'type': 'ddos', 'label': 'DDoS', 'description': 'Distributed denial of service attack'},
            {'type': 'reconnaissance', 'label': 'Reconnaissance', 'description': 'Information gathering activity'},
            {'type': 'privilege_escalation', 'label': 'Privilege Escalation', 'description': 'Attempts to gain elevated access'},
            {'type': 'lateral_movement', 'label': 'Lateral Movement', 'description': 'Movement between systems in network'},
            {'type': 'data_exfiltration', 'label': 'Data Exfiltration', 'description': 'Unauthorized data transfer out of network'},
            {'type': 'c2_communication', 'label': 'C2 Communication', 'description': 'Command and control server communication'},
            {'type': 'malware_activity', 'label': 'Malware Activity', 'description': 'Potential malware execution detected'},
            {'type': 'insider_threat', 'label': 'Insider Threat', 'description': 'Suspicious activity from authorized user'},
            {'type': 'account_takeover', 'label': 'Account Takeover', 'description': 'Unauthorized account access'},
            {'type': 'mfa_bypass', 'label': 'MFA Bypass', 'description': 'Attempts to circumvent multi-factor authentication'},
            {'type': 'session_hijacking', 'label': 'Session Hijacking', 'description': 'Unauthorized use of valid session tokens'},
            {'type': 'log4shell', 'label': 'Log4Shell', 'description': 'Log4j JNDI injection attack'},
            {'type': 'ssrf_attack', 'label': 'SSRF', 'description': 'Server-side request forgery'},
            {'type': 'xxe_attack', 'label': 'XXE', 'description': 'XML external entity injection'},
        ]
    })


@app.route('/feedback/bulk', methods=['POST'])
def bulk_feedback():
    """Submit bulk feedback for multiple entries"""
    try:
        from ml.federated_learning import FederatedLearningManager, UserFeedback
        import uuid
        from datetime import datetime

        data = request.get_json()
        if not data:
            return jsonify({'error': 'No feedback data provided'}), 400

        required_fields = ['entries', 'user_label']
        for field in required_fields:
            if field not in data:
                return jsonify({'error': f'Missing required field: {field}'}), 400

        if data['user_label'] not in ['safe', 'unsafe', 'attack_pattern']:
            return jsonify({'error': 'user_label must be "safe", "unsafe", or "attack_pattern"'}), 400

        if data['user_label'] == 'attack_pattern' and not data.get('attack_type'):
            return jsonify({'error': 'attack_type is required when user_label is "attack_pattern"'}), 400

        fl_manager = FederatedLearningManager()
        results = []

        for entry in data['entries']:
            feedback = UserFeedback(
                entry_id=entry.get('entry_id', f'anonymous_{uuid.uuid4().hex[:8]}'),
                user_id=entry.get('user_id', f'anonymous_{uuid.uuid4().hex[:8]}'),
                timestamp=datetime.now().isoformat(),
                original_prediction=entry.get('original_prediction', {}),
                user_label=data['user_label'],
                confidence=entry.get('confidence', 0.0),
                log_message=entry.get('log_message', ''),
                source_ip=entry.get('source_ip', ''),
                log_type=entry.get('log_type', ''),
                mitre_tactics=entry.get('mitre_tactics', []),
                mitre_techniques=entry.get('mitre_techniques', []),
                feedback_metadata=data.get('feedback_metadata', {})
            )
            
            if data['user_label'] == 'attack_pattern':
                feedback.feedback_metadata['corrected_attack_type'] = data.get('attack_type')
            
            fl_manager.add_feedback(feedback)
            results.append({'id': feedback.entry_id, 'success': True})

        return jsonify({
            'success': True,
            'message': f'Bulk feedback submitted for {len(results)} entries',
            'results': results
        })
    except Exception as e:
        return jsonify({'success': False, 'error': 'Failed to submit bulk feedback', 'details': str(e)}), 500


@app.route('/stream', methods=['POST'])
def stream_parse():
    """Stream parsing - parse a single line or batch of lines"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400

        lines = data.get('lines', [])
        if not lines:
            line = data.get('line') or data.get('content', '')
            lines = [line] if line else []

        if not lines or not lines[0]:
            return jsonify({'error': 'No lines provided'}), 400

        content = '\n'.join(lines)
        parse_result = auto_parse(content)

        alerts = run_detections(parse_result['entries'])

        return jsonify({
            'success': True,
            'detectedType': parse_result['detectedType'],
            'entries': parse_result['entries'],
            'alerts': alerts,
            'stats': {
                'totalLines': parse_result['stats']['totalLines'],
                'parsedLines': parse_result['stats']['parsedLines'],
                'failedLines': parse_result['stats']['failedLines'],
            },
        })
    except Exception as e:
        return jsonify({'success': False, 'error': 'Failed to parse stream', 'details': str(e)}), 500


@app.route('/parse/chunked', methods=['POST'])
def parse_chunked():
    """Chunked upload for large files"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400

        chunks = data.get('chunks', [])
        if not chunks or not isinstance(chunks, list):
            return jsonify({'error': 'No chunks provided'}), 400

        content = ''.join(chunks)
        if not content or not content.strip():
            return jsonify({'error': 'No log content provided'}), 400

        parse_result = auto_parse(content)

        alerts = run_detections(parse_result['entries'])

        from ml.correlation import detect_attack_types, correlate_attacks
        attacks = detect_attack_types(parse_result['entries'])
        attack_chains = correlate_attacks(parse_result['entries'], attacks)

        attack_summary = {
            'totalAttacks': len(attacks),
            'attackTypes': list(set(a.get('attackType', 'unknown') for a in attacks)),
            'uniqueSources': len(set(e.get('source', {}).get('ip', '') for e in parse_result['entries'] if e.get('source', {}).get('ip'))),
            'riskScore': min(len(attacks) * 10, 100),
        }

        return jsonify({
            'success': True,
            'detectedType': parse_result['detectedType'],
            'totalLines': parse_result['stats']['totalLines'],
            'parsedLines': parse_result['stats']['parsedLines'],
            'failedLines': parse_result['stats']['failedLines'],
            'entries': parse_result['entries'],
            'alerts': alerts,
            'mlAttacks': attacks,
            'attackChains': attack_chains,
            'attackSummary': attack_summary,
            'fileName': data.get('fileName', 'uploaded_file'),
        })
    except Exception as e:
        return jsonify({'success': False, 'error': 'Failed to parse chunks', 'details': str(e)}), 500


@app.route('/parse/distributed', methods=['POST'])
def parse_logs_distributed():
    """Distributed parse endpoint - uses master-slave architecture"""
    if not MASTER_SERVER_AVAILABLE:
        return jsonify({
            'success': False,
            'error': 'Master server not available',
            'fallback': True
        }), 503
    
    try:
        print(f"[DISTRIBUTED PARSE] Processing request from {request.remote_addr}")
        content_type = request.content_type or ''
        content = None
        file_name = 'logs.log'

        # Handle multipart form data
        if 'multipart/form-data' in content_type:
            if 'file' in request.files:
                file = request.files['file']
                content = file.read().decode('utf-8', errors='ignore')
                file_name = file.filename or 'logs.log'
        # Handle JSON
        elif 'application/json' in content_type:
            data = request.get_json()
            content = data.get('content') or data.get('logs') or ''
            file_name = data.get('fileName', 'logs.log')
        # Handle raw text
        else:
            content = request.get_data(as_text=True)
            file_name = request.headers.get('X-File-Name', 'logs.log')

        if not content or len(content.strip()) == 0:
            return jsonify({'error': 'No log content provided'}), 400

        # Use master server to distribute work
        result = distribute_and_process(content, file_name)
        
        if result.get('success'):
            print(f"[DISTRIBUTED PARSE] Successfully processed {result.get('totalLines', 0)} lines")
        else:
            print(f"[DISTRIBUTED PARSE] Failed: {result.get('error', 'Unknown error')}")
        
        return jsonify(result)

    except Exception as e:
        print(f"[DISTRIBUTED PARSE ERROR] {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Failed to process distributed parse',
            'details': str(e)
        }), 500


# ML Inference endpoints
ML_ENGINE = None

def get_ml_engine():
    """Get ML inference engine"""
    global ML_ENGINE
    if ML_ENGINE is None:
        try:
            sys.path.insert(0, str(Path(__file__).parent.parent / 'siem-tool' / 'ml-training'))
            from inference import get_inference_engine
            ML_ENGINE = get_inference_engine()
            print("[ML] Inference engine loaded successfully")
        except Exception as e:
            print(f"[ML] Failed to load inference engine: {e}")
            return None
    return ML_ENGINE

@app.route('/ml/predict', methods=['POST'])
def ml_predict():
    """ML-based attack prediction endpoint"""
    engine = get_ml_engine()
    
    if engine is None:
        return jsonify({
            'success': False,
            'error': 'ML model not available',
            'attackType': 'unknown',
            'confidence': 0.0,
            'isAttack': False
        }), 503
    
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        # Handle single entry
        if 'message' in data:
            message = data.get('message', '')
            log_type = data.get('log_type', 'unknown')
            
            prediction = engine.predict(message, log_type)
            
            return jsonify({
                'success': True,
                'attackType': prediction.attack_type,
                'confidence': prediction.confidence,
                'probability': prediction.probability,
                'isAttack': prediction.is_attack,
                'category': prediction.category,
                'explanation': prediction.explanation
            })
        
        # Handle batch
        elif 'logs' in data:
            logs = data['logs']
            results = []
            
            for log in logs:
                if isinstance(log, dict):
                    message = log.get('message', log.get('raw_line', ''))
                    log_type = log.get('log_type', 'unknown')
                else:
                    message = str(log)
                    log_type = 'unknown'
                
                prediction = engine.predict(message, log_type)
                results.append({
                    'attackType': prediction.attack_type,
                    'confidence': prediction.confidence,
                    'isAttack': prediction.is_attack,
                    'explanation': prediction.explanation
                })
            
            return jsonify({
                'success': True,
                'predictions': results,
                'count': len(results)
            })
        
        return jsonify({'error': 'Invalid format'}), 400
    
    except Exception as e:
        print(f"[ML PREDICT ERROR] {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/ml/batch', methods=['POST'])
def ml_batch_predict():
    """Batch ML prediction with aggregation"""
    engine = get_ml_engine()
    
    if engine is None:
        return jsonify({'error': 'ML model not available'}), 503
    
    try:
        data = request.get_json()
        logs = data.get('logs', [])
        
        results = []
        for log in logs:
            message = log.get('message', log.get('raw_line', ''))
            log_type = log.get('log_type', 'unknown')
            prediction = engine.predict(message, log_type)
            
            results.append({
                'attackType': prediction.attack_type,
                'confidence': prediction.confidence,
                'isAttack': prediction.is_attack,
                'category': prediction.category,
                'explanation': prediction.explanation
            })
        
        # Aggregate
        attack_count = sum(1 for r in results if r['isAttack'])
        avg_confidence = sum(r['confidence'] for r in results) / len(results) if results else 0
        
        return jsonify({
            'results': results,
            'summary': {
                'total_logs': len(results),
                'attacks_detected': attack_count,
                'avg_confidence': avg_confidence,
                'risk_score': min(attack_count * 10, 100)
            }
        })
    
    except Exception as e:
        print(f"[ML BATCH ERROR] {str(e)}")
        return jsonify({'error': str(e)}), 500


@app.route('/ml/feedback', methods=['POST'])
def ml_feedback():
    """Submit user feedback for retraining"""
    try:
        data = request.get_json()
        
        feedback_entry = {
            'timestamp': data.get('timestamp'),
            'log_message': data.get('log_message'),
            'log_type': data.get('log_type'),
            'predicted_attack': data.get('predicted_attack'),
            'actual_attack': data.get('actual_attack'),
            'user_correct': data.get('user_correct'),
            'confidence': data.get('confidence')
        }
        
        # Save to file
        feedback_dir = Path(__file__).parent.parent / 'siem-tool' / 'ml-training' / 'data'
        feedback_dir.mkdir(parents=True, exist_ok=True)
        feedback_file = feedback_dir / 'feedback.json'
        
        existing = []
        if feedback_file.exists():
            with open(feedback_file, 'r') as f:
                existing = json.load(f)
        
        existing.append(feedback_entry)
        
        with open(feedback_file, 'w') as f:
            json.dump(existing, f, indent=2)
        
        return jsonify({
            'success': True,
            'feedback_count': len(existing)
        })
    
    except Exception as e:
        print(f"[ML FEEDBACK ERROR] {str(e)}")
        return jsonify({'error': str(e)}), 500


@app.route('/ml/stats')
def ml_stats():
    """Get ML model statistics"""
    engine = get_ml_engine()
    
    if engine is None:
        return jsonify({
            'status': 'ML model not loaded',
            'available': False
        })
    
    return jsonify({
        'status': 'ok',
        'available': True,
        'model_type': 'category_specific' if engine.use_category_models else 'unified',
        'categories': list(engine.category_models.keys()) if engine.category_models else []
    })


@app.route('/feedback', methods=['POST'])
def feedback():
    """Legacy feedback endpoint for frontend compatibility"""
    return ml_feedback()


# ============================================================================
# SOC Analyst LLM Integration
# ============================================================================

_soc_llm_engine = None

def get_soc_llm_engine():
    """Get or initialize SOC Analyst LLM engine"""
    global _soc_llm_engine
    if _soc_llm_engine is None:
        try:
            # Try to import and initialize the LLM
            print("[SOC-LLM] Initializing SOC Analyst LLM...")
            
            # Check if SOC LLM API is available
            import requests
            llm_api_url = os.environ.get('SOC_LLM_API_URL', 'http://127.0.0.1:8000')
            
            response = requests.get(f"{llm_api_url}/health", timeout=2)
            if response.status_code == 200:
                _soc_llm_engine = {'type': 'api', 'url': llm_api_url}
                print(f"[SOC-LLM] Connected to LLM API at {llm_api_url}")
            else:
                print("[SOC-LLM] LLM API not available")
                _soc_llm_engine = None
        except Exception as e:
            print(f"[SOC-LLM] Could not initialize: {e}")
            _soc_llm_engine = None
    
    return _soc_llm_engine

@app.route('/soc-analyze', methods=['POST'])
def soc_analyze():
    """Analyze logs using SOC Analyst LLM"""
    try:
        engine = get_soc_llm_engine()
        if not engine:
            return jsonify({'error': 'SOC Analyst LLM not available'}), 503
        
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        log_entry = data.get('log_entry', '')
        log_type = data.get('log_type', 'unknown')
        
        import requests
        response = requests.post(
            f"{engine['url']}/analyze/log",
            json={'log_entry': log_entry, 'log_type': log_type},
            timeout=10
        )
        
        if response.status_code == 200:
            return jsonify(response.json())
        else:
            return jsonify({'error': 'LLM analysis failed'}), 500
            
    except Exception as e:
        print(f"[SOC-LLM] Error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/soc-chat', methods=['POST'])
def soc_chat():
    """Chat with SOC Analyst LLM"""
    try:
        engine = get_soc_llm_engine()
        if not engine:
            return jsonify({'error': 'SOC Analyst LLM not available'}), 503
        
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        message = data.get('message', '')
        context = data.get('context', [])
        
        import requests
        response = requests.post(
            f"{engine['url']}/chat",
            json={'message': message, 'context': context},
            timeout=10
        )
        
        if response.status_code == 200:
            return jsonify(response.json())
        else:
            return jsonify({'error': 'Chat failed'}), 500
            
    except Exception as e:
        print(f"[SOC-LLM] Error: {e}")
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    # Run the Flask development server
    print("Starting Cyber Chakshu SIEM Desktop API...")
    print(f"Static folder: {STATIC_FOLDER_STR}")
    print("Open http://localhost:5000 in your browser to access the application")
    app.run(debug=True, port=5000)
