#!/usr/bin/env python3
"""
VNC Security Monitor - Main Application
Web dashboard for monitoring VNC security threats
"""

from flask import Flask, render_template, jsonify, request
import json
import threading
import time
import pandas as pd
from datetime import datetime
from threat_detector import VNCThreatDetector
from vnc_simulator import VNCTrafficSimulator
from ml_detector import VNCMLDetector
from data_generator import VNCDataGenerator
import os

app = Flask(__name__)
detector = VNCThreatDetector()
simulator = VNCTrafficSimulator()
ml_detector = VNCMLDetector()
simulator.set_detector(detector)

# Initialize ML model
def initialize_ml_model():
    """Initialize or train the ML model"""
    model_path = 'models/vnc_detector.joblib'
    
    if os.path.exists(model_path):
        print("📥 Loading existing ML model...")
        ml_detector.load_model(model_path)
    else:
        print("🔄 Training new ML model...")
        generator = VNCDataGenerator()
        sessions_df, _, _ = generator.save_datasets()
        ml_detector.train(sessions_df)
        ml_detector.save_model(model_path)
    
    print("✅ ML Detector ready!")

# Initialize on startup
initialize_ml_model()

@app.route('/')
def dashboard():
    """Main dashboard"""
    return render_template('dashboard.html')

@app.route('/api/stats')
def get_stats():
    """Get current security statistics"""
    stats = detector.get_statistics()
    return jsonify(stats)

@app.route('/api/alerts')
def get_alerts():
    """Get recent alerts"""
    alerts = detector.get_recent_alerts(20)
    # Convert datetime objects to strings for JSON serialization
    for alert in alerts:
        alert['timestamp'] = alert['timestamp'].isoformat()
    return jsonify(alerts)

@app.route('/api/simulate/<attack_type>')
def simulate_attack(attack_type):
    """Simulate different types of attacks with ML analysis"""
    if attack_type == 'file_transfer':
        simulator.simulate_file_transfer()
    elif attack_type == 'clipboard':
        simulator.simulate_clipboard_exfiltration()
    elif attack_type == 'database':
        simulator.simulate_database_dump()
    elif attack_type == 'encoded':
        simulator.simulate_encoded_data()
    elif attack_type == 'ml_analysis':
        # Run ML analysis on recent sessions
        _run_ml_analysis()
    
    return jsonify({'status': 'success', 'message': f'{attack_type} attack simulated'})

def _run_ml_analysis():
    """Run ML analysis on simulated session data"""
    # Create a simulated anomalous session
    generator = VNCDataGenerator()
    anomalous_session = generator._generate_anomalous_session("ml-test-001")
    session_df = pd.DataFrame([anomalous_session])
    
    # Predict with ML model
    predictions, scores = ml_detector.predict(session_df)
    
    if predictions[0] == 1:  # Anomaly detected
        explanations = ml_detector.explain_prediction(session_df.iloc[0])
        
        # Create detailed alert
        explanation_text = "; ".join([exp['description'] for exp in explanations[:3]])
        detector._create_alert(
            'HIGH',
            'ML Model Alert: Anomalous Session Detected',
            f'Risk Score: {scores[0]:.2f} - {explanation_text}'
        )

@app.route('/api/start_monitoring')
def start_monitoring():
    """Start the threat detection system"""
    detector.start_monitoring()
    return jsonify({'status': 'started'})

@app.route('/api/stop_monitoring')
def stop_monitoring():
    """Stop the threat detection system"""
    detector.stop_monitoring()
    return jsonify({'status': 'stopped'})

@app.route('/api/traffic_data')
def get_traffic_data():
    """Get traffic data for visualization"""
    bandwidth_data = []
    for entry in detector.bandwidth_history:
        bandwidth_data.append({
            'timestamp': entry['timestamp'].isoformat(),
            'size': entry['size']
        })
    return jsonify(bandwidth_data)

@app.route('/api/ml_insights')
def get_ml_insights():
    """Get ML model insights and feature importance"""
    if ml_detector.feature_importance:
        top_features = sorted(
            ml_detector.feature_importance.items(), 
            key=lambda x: x[1], 
            reverse=True
        )[:10]
        
        return jsonify({
            'top_features': [{'name': name, 'importance': importance} 
                           for name, importance in top_features],
            'model_status': 'trained',
            'total_features': len(ml_detector.feature_importance)
        })
    else:
        return jsonify({
            'top_features': [],
            'model_status': 'not_trained',
            'total_features': 0
        })

@app.route('/api/threat_matrix')
def get_threat_matrix():
    """Get threat scenario matrix data"""
    threat_scenarios = [
        {
            'scenario': 'Large File Transfer',
            'detection_signals': 'Large outbound bytes, clipboard spikes',
            'risk_level': 'HIGH',
            'count': len([a for a in detector.alerts if 'File Transfer' in a.get('title', '')])
        },
        {
            'scenario': 'Screenshot Exfiltration', 
            'detection_signals': 'High frame rate, frequent captures',
            'risk_level': 'MEDIUM',
            'count': len([a for a in detector.alerts if 'Screenshot' in a.get('title', '')])
        },
        {
            'scenario': 'Clipboard Data Theft',
            'detection_signals': 'Large clipboard transfers',
            'risk_level': 'MEDIUM', 
            'count': len([a for a in detector.alerts if 'Clipboard' in a.get('title', '')])
        },
        {
            'scenario': 'Encoded Data Exfiltration',
            'detection_signals': 'Base64/encoded patterns',
            'risk_level': 'HIGH',
            'count': len([a for a in detector.alerts if 'Encoded' in a.get('title', '')])
        }
    ]
    
    return jsonify(threat_scenarios)

@app.route('/api/remediation/<session_id>')
def remediate_session(session_id):
    """Simulate session remediation"""
    action = request.args.get('action', 'terminate')
    
    if action == 'terminate':
        message = f"Session {session_id} terminated"
    elif action == 'block_ip':
        message = f"IP blocked for session {session_id}"
    elif action == 'escalate':
        message = f"Session {session_id} escalated to analyst"
    else:
        message = f"Unknown action for session {session_id}"
    
    # Log remediation action
    detector._create_alert(
        'INFO',
        'Remediation Action Taken',
        message
    )
    
    return jsonify({'status': 'success', 'message': message})

if __name__ == '__main__':
    print("🚀 Starting VNC Security Monitor")
    print("📊 Dashboard will be available at: http://localhost:5000")
    
    # Start the detector automatically
    detector.start_monitoring()
    
    # Start background simulation for demo
    def demo_simulation():
        time.sleep(5)  # Wait for startup
        while True:
            simulator.generate_normal_traffic()
            time.sleep(10)
            # Occasionally simulate attacks for demo
            if time.time() % 30 < 1:  # Every 30 seconds
                simulator.simulate_file_transfer()
            time.sleep(2)
    
    demo_thread = threading.Thread(target=demo_simulation)
    demo_thread.daemon = True
    demo_thread.start()
    
    app.run(debug=True, host='0.0.0.0', port=5000)