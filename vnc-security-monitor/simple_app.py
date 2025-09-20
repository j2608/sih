#!/usr/bin/env python3
"""
VNC Security Monitor - Simplified App for Demo
Minimal version that works even with missing dependencies
"""

from flask import Flask, render_template, jsonify
import json
import threading
import time
from datetime import datetime
import random
import os

app = Flask(__name__)

# Simple in-memory storage
alerts = []
stats = {
    'total_alerts': 0,
    'file_transfers': 0,
    'clipboard_events': 0,
    'high_risk_alerts': 0
}

# Simple threat detector
class SimpleDetector:
    def __init__(self):
        self.running = False
        
    def start_monitoring(self):
        self.running = True
        print("🔍 Simple VNC Detector started")
        
    def create_alert(self, severity, title, description):
        alert = {
            'timestamp': datetime.now().isoformat(),
            'severity': severity,
            'title': title,
            'description': description,
            'id': len(alerts) + 1
        }
        alerts.append(alert)
        stats['total_alerts'] += 1
        if severity == 'HIGH':
            stats['high_risk_alerts'] += 1
        print(f"🚨 {severity} ALERT: {title}")

detector = SimpleDetector()

@app.route('/')
def dashboard():
    """Main dashboard"""
    return render_template('simple_dashboard.html')

@app.route('/api/stats')
def get_stats():
    """Get current statistics"""
    return jsonify(stats)

@app.route('/api/alerts')
def get_alerts():
    """Get recent alerts"""
    return jsonify(alerts[-10:])  # Last 10 alerts

@app.route('/api/simulate/<attack_type>')
def simulate_attack(attack_type):
    """Simulate different attack types"""
    attack_scenarios = {
        'file_transfer': {
            'severity': 'HIGH',
            'title': 'Large File Transfer Detected',
            'description': 'Suspicious file transfer of 50MB detected via VNC clipboard'
        },
        'clipboard': {
            'severity': 'MEDIUM', 
            'title': 'Large Clipboard Transfer',
            'description': 'Clipboard data transfer of 25KB detected'
        },
        'database': {
            'severity': 'HIGH',
            'title': 'Database Content Detected',
            'description': 'SQL dump patterns found in VNC traffic'
        },
        'encoded': {
            'severity': 'MEDIUM',
            'title': 'Encoded Data Transfer',
            'description': 'Base64 encoded data detected in VNC stream'
        }
    }
    
    if attack_type in attack_scenarios:
        scenario = attack_scenarios[attack_type]
        detector.create_alert(scenario['severity'], scenario['title'], scenario['description'])
        
        # Update relevant stats
        if attack_type == 'file_transfer':
            stats['file_transfers'] += 1
        elif attack_type == 'clipboard':
            stats['clipboard_events'] += 1
    
    return jsonify({'status': 'success', 'message': f'{attack_type} attack simulated'})

@app.route('/api/threat_matrix')
def get_threat_matrix():
    """Get threat matrix data"""
    threats = [
        {
            'scenario': 'Large File Transfer',
            'detection_signals': 'High bandwidth, clipboard spikes',
            'risk_level': 'HIGH',
            'count': stats['file_transfers']
        },
        {
            'scenario': 'Clipboard Data Theft',
            'detection_signals': 'Large clipboard transfers',
            'risk_level': 'MEDIUM',
            'count': stats['clipboard_events']
        },
        {
            'scenario': 'Screenshot Exfiltration',
            'detection_signals': 'High frame rate, frequent captures',
            'risk_level': 'MEDIUM',
            'count': random.randint(0, 3)
        },
        {
            'scenario': 'Encoded Data Transfer',
            'detection_signals': 'Base64/encoded patterns',
            'risk_level': 'HIGH',
            'count': random.randint(0, 2)
        }
    ]
    return jsonify(threats)

@app.route('/api/ml_insights')
def get_ml_insights():
    """Get ML insights (simplified)"""
    # Simulate dynamic feature importance based on recent attacks
    base_features = [
        {'name': 'bytes_per_minute', 'importance': 0.25 + random.uniform(-0.05, 0.05)},
        {'name': 'clipboard_events_rate', 'importance': 0.20 + random.uniform(-0.03, 0.03)},
        {'name': 'file_transfer_size', 'importance': 0.18 + random.uniform(-0.02, 0.02)},
        {'name': 'session_duration', 'importance': 0.15 + random.uniform(-0.02, 0.02)},
        {'name': 'frame_rate_spike', 'importance': 0.12 + random.uniform(-0.02, 0.02)},
        {'name': 'unusual_time_access', 'importance': 0.10 + random.uniform(-0.01, 0.01)}
    ]
    
    # Normalize importance values
    total_importance = sum(f['importance'] for f in base_features)
    for feature in base_features:
        feature['importance'] = max(0.01, feature['importance'] / total_importance)
    
    return jsonify({
        'top_features': base_features,
        'model_status': 'active',
        'total_features': 27,
        'model_accuracy': 0.92,
        'last_updated': datetime.now().isoformat()
    })

@app.route('/api/remediation/<session_id>')
def remediate_session(session_id):
    """Simulate remediation action"""
    from flask import request
    action = request.args.get('action', 'terminate')
    
    actions = {
        'terminate': f'Session {session_id} terminated successfully',
        'block_ip': f'IP address blocked for session {session_id}',
        'escalate': f'Session {session_id} escalated to security team'
    }
    
    message = actions.get(action, f'Action {action} applied to {session_id}')
    
    detector.create_alert('INFO', 'Remediation Action', message)
    
    return jsonify({'status': 'success', 'message': message})

if __name__ == '__main__':
    print("🚀 Starting Simple VNC Security Monitor")
    print("📊 Dashboard available at: http://localhost:5000")
    
    detector.start_monitoring()
    
    # Add some demo alerts
    detector.create_alert('INFO', 'System Started', 'VNC Security Monitor is now active')
    
    app.run(debug=True, host='0.0.0.0', port=5000)