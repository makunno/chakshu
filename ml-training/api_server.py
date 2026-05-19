"""
ML Inference API Server
Provides REST API for attack classification with confidence scores
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
import os
import sys
import json

# Add ml-training to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'ml-training'))

from inference import get_inference_engine, predict_attack

app = Flask(__name__)
CORS(app)

# Initialize inference engine
print("Initializing ML Inference Engine...")
engine = get_inference_engine()
print("ML Engine ready!")

@app.route('/health')
def health():
    return jsonify({
        'status': 'ok',
        'ml_enabled': True,
        'model_type': 'category_specific' if engine.use_category_models else 'unified'
    })

@app.route('/ml/predict', methods=['POST'])
def predict():
    """Predict attack type for log entries"""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        # Handle single entry or batch
        if 'message' in data:
            # Single entry
            result = predict_attack(
                data.get('message', ''),
                data.get('log_type', 'unknown')
            )
            return jsonify(result)
        
        elif 'logs' in data:
            # Batch processing
            logs = data['logs']
            results = []
            for log in logs:
                if isinstance(log, dict):
                    result = predict_attack(
                        log.get('message', log.get('raw_line', '')),
                        log.get('log_type', 'unknown')
                    )
                else:
                    result = predict_attack(str(log), 'unknown')
                results.append(result)
            
            return jsonify({
                'predictions': results,
                'count': len(results)
            })
        
        else:
            return jsonify({'error': 'Invalid format'}), 400
    
    except Exception as e:
        return jsonify({
            'error': 'Prediction failed',
            'details': str(e)
        }), 500

@app.route('/ml/batch', methods=['POST'])
def batch_predict():
    """Batch predict with confidence scores"""
    try:
        data = request.get_json()
        logs = data.get('logs', [])
        
        results = []
        for log in logs:
            message = log.get('message', log.get('raw_line', ''))
            log_type = log.get('log_type', 'unknown')
            
            result = predict_attack(message, log_type)
            results.append({
                'attackType': result['attackType'],
                'confidence': result['confidence'],
                'probability': result['probability'],
                'isAttack': result['isAttack'],
                'category': result['category'],
                'explanation': result['explanation']
            })
        
        # Aggregate results
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
        return jsonify({
            'error': 'Batch prediction failed',
            'details': str(e)
        }), 500

# Feedback endpoint for retraining
feedback_data = []

@app.route('/ml/feedback', methods=['POST'])
def submit_feedback():
    """Submit user feedback for model improvement"""
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
        
        feedback_data.append(feedback_entry)
        
        # Save to file for later retraining
        feedback_file = os.path.join(os.path.dirname(__file__), '..', 'ml-training', 'data', 'feedback.json')
        os.makedirs(os.path.dirname(feedback_file), exist_ok=True)
        
        # Append to existing feedback
        existing = []
        if os.path.exists(feedback_file):
            with open(feedback_file, 'r') as f:
                existing = json.load(f)
        
        existing.append(feedback_entry)
        
        with open(feedback_file, 'w') as f:
            json.dump(existing, f, indent=2)
        
        return jsonify({
            'success': True,
            'feedback_count': len(feedback_data)
        })
    
    except Exception as e:
        return jsonify({
            'error': 'Feedback submission failed',
            'details': str(e)
        }), 500

@app.route('/ml/stats')
def get_stats():
    """Get ML model statistics"""
    return jsonify({
        'models_loaded': {
            'base': engine.base_model is not None,
            'category': engine.category_models is not None,
            'unified': engine.unified_model is not None
        },
        'categories': list(engine.category_models.keys()) if engine.category_models else [],
        'feedback_count': len(feedback_data)
    })

if __name__ == '__main__':
    print("Starting ML Inference API on port 5002...")
    app.run(host='127.0.0.1', port=5002, debug=False)
