#!/usr/bin/env python3
"""
VNC Security Monitor - Integrated Detection System
Combines rule-based detection with ML anomaly detection for comprehensive threat detection
"""

import threading
import time
from datetime import datetime
from collections import deque
import json

from threat_detector import VNCThreatDetector
from ml_detector import MLAnomalyDetector, AdaptiveThreatDetector

class IntegratedVNCSecuritySystem:
    def __init__(self):
        # Initialize detection engines
        self.rule_detector = VNCThreatDetector()
        self.ml_detector = MLAnomalyDetector()
        self.adaptive_detector = AdaptiveThreatDetector()
        
        # System state
        self.running = False
        self.detection_stats = {
            'total_packets': 0,
            'rule_based_alerts': 0,
            'ml_alerts': 0,
            'combined_alerts': 0,
            'false_positives': 0
        }
        
        # Alert correlation
        self.correlated_alerts = deque(maxlen=1000)
        self.alert_correlation_window = 30  # seconds
        
        # Training mode
        self.training_mode = False
        self.training_data = []
        
    def start_system(self):
        """Start the integrated security system"""
        print("🚀 Starting Integrated VNC Security System...")
        
        # Try to load pre-trained ML model
        if self.ml_detector.load_model():
            print("✅ Pre-trained ML model loaded")
        else:
            print("⚠️  No pre-trained model found, will use rule-based detection initially")
        
        # Start detection engines
        self.rule_detector.start_monitoring()
        self.running = True
        
        # Start correlation engine
        self.correlation_thread = threading.Thread(target=self._correlation_loop)
        self.correlation_thread.daemon = True
        self.correlation_thread.start()
        
        print("🛡️  Integrated VNC Security System is now active")
    
    def stop_system(self):
        """Stop the security system"""
        self.running = False
        self.rule_detector.stop_monitoring()
        print("⏹️  Integrated VNC Security System stopped")
    
    def process_vnc_packet(self, packet_data, metadata=None):
        """Process VNC packet through both detection engines"""
        self.detection_stats['total_packets'] += 1
        
        # Rule-based detection
        self.rule_detector.analyze_vnc_packet(packet_data)
        rule_alerts = len(self.rule_detector.alerts)
        
        # ML-based detection
        ml_result = self.ml_detector.detect_anomaly(packet_data, metadata)
        
        # Combine results
        combined_alert = self._correlate_detections(packet_data, ml_result, metadata)
        
        # Store for training if in training mode
        if self.training_mode:
            self.training_data.append((packet_data, metadata))
        
        return combined_alert
    
    def _correlate_detections(self, packet_data, ml_result, metadata):
        """Correlate rule-based and ML detection results"""
        timestamp = datetime.now()
        
        # Get recent rule-based alerts
        recent_rule_alerts = [
            alert for alert in self.rule_detector.alerts
            if (timestamp - alert['timestamp']).seconds < self.alert_correlation_window
        ]
        
        # Determine combined threat level
        combined_risk = self._calculate_combined_risk(ml_result, recent_rule_alerts)
        
        # Create correlated alert if significant threat detected
        if combined_risk['level'] in ['HIGH', 'CRITICAL']:
            alert = {
                'id': len(self.correlated_alerts) + 1,
                'timestamp': timestamp,
                'type': 'CORRELATED_THREAT',
                'severity': combined_risk['level'],
                'confidence': combined_risk['confidence'],
                'packet_size': len(packet_data),
                'ml_score': ml_result['anomaly_score'],
                'rule_triggers': len(recent_rule_alerts),
                'description': combined_risk['description'],
                'recommendations': combined_risk['recommendations']
            }
            
            self.correlated_alerts.append(alert)
            self.detection_stats['combined_alerts'] += 1
            
            print(f"🔥 CORRELATED ALERT [{alert['severity']}]: {alert['description']}")
            return alert
        
        return None
    
    def _calculate_combined_risk(self, ml_result, rule_alerts):
        """Calculate combined risk level from multiple detection sources"""
        risk_score = 0
        confidence = 0
        triggers = []
        
        # ML contribution
        if ml_result['is_anomaly']:
            ml_weight = abs(ml_result['anomaly_score']) * 0.4
            risk_score += ml_weight
            confidence += ml_result['confidence'] * 0.6
            triggers.append(f"ML anomaly (score: {ml_result['anomaly_score']:.3f})")
        
        # Rule-based contribution
        if rule_alerts:
            rule_weight = min(len(rule_alerts) * 0.3, 0.6)
            risk_score += rule_weight
            confidence += 0.8 * (len(rule_alerts) / 5)  # Max 5 alerts for full confidence
            
            high_severity_alerts = [a for a in rule_alerts if a['severity'] == 'HIGH']
            if high_severity_alerts:
                risk_score += 0.3
                triggers.append(f"{len(high_severity_alerts)} high-severity rule alerts")
        
        # Determine final risk level
        if risk_score > 0.8:
            level = 'CRITICAL'
        elif risk_score > 0.6:
            level = 'HIGH'
        elif risk_score > 0.4:
            level = 'MEDIUM'
        else:
            level = 'LOW'
        
        # Generate recommendations
        recommendations = self._generate_recommendations(ml_result, rule_alerts, level)
        
        return {
            'level': level,
            'confidence': min(confidence, 1.0),
            'score': risk_score,
            'description': f"Combined threat detected: {', '.join(triggers)}",
            'recommendations': recommendations
        }
    
    def _generate_recommendations(self, ml_result, rule_alerts, risk_level):
        """Generate security recommendations based on detected threats"""
        recommendations = []
        
        if risk_level in ['HIGH', 'CRITICAL']:
            recommendations.append("🚨 Immediately investigate VNC session")
            recommendations.append("🔒 Consider terminating suspicious VNC connection")
            recommendations.append("📊 Review user activity logs")
        
        if ml_result['is_anomaly']:
            if ml_result['features'].get('has_file_signature'):
                recommendations.append("📁 Block file transfers through VNC")
            if ml_result['features'].get('entropy', 0) > 7:
                recommendations.append("🔐 Investigate potential encrypted data transfer")
        
        if rule_alerts:
            for alert in rule_alerts:
                if 'File Transfer' in alert['title']:
                    recommendations.append("📤 Enable file transfer logging")
                elif 'Clipboard' in alert['title']:
                    recommendations.append("📋 Disable clipboard sharing")
                elif 'Bandwidth' in alert['title']:
                    recommendations.append("🌐 Implement bandwidth throttling")
        
        if not recommendations:
            recommendations.append("👀 Continue monitoring for suspicious activity")
        
        return recommendations
    
    def _correlation_loop(self):
        """Background loop for alert correlation and cleanup"""
        while self.running:
            # Clean up old alerts
            current_time = datetime.now()
            
            # Remove old rule alerts
            self.rule_detector.alerts = deque([
                alert for alert in self.rule_detector.alerts
                if (current_time - alert['timestamp']).seconds < 3600  # Keep 1 hour
            ], maxlen=1000)
            
            # Update statistics
            self.detection_stats['rule_based_alerts'] = len(self.rule_detector.alerts)
            self.detection_stats['ml_alerts'] = len(self.ml_detector.alerts)
            
            time.sleep(60)  # Run every minute
    
    def train_ml_model(self):
        """Train ML model with collected data"""
        if not self.training_data:
            print("❌ No training data available")
            return False
        
        print(f"🎓 Training ML model with {len(self.training_data)} samples...")
        self.ml_detector.train_model(self.training_data)
        
        # Clear training data to save memory
        self.training_data = []
        return True
    
    def enable_training_mode(self):
        """Enable training mode to collect data"""
        self.training_mode = True
        print("📚 Training mode enabled - collecting data for ML model")
    
    def disable_training_mode(self):
        """Disable training mode"""
        self.training_mode = False
        print("📚 Training mode disabled")
    
    def process_user_feedback(self, alert_id, is_true_positive):
        """Process user feedback for adaptive learning"""
        self.adaptive_detector.process_feedback(alert_id, is_true_positive)
        
        if not is_true_positive:
            self.detection_stats['false_positives'] += 1
    
    def get_system_status(self):
        """Get comprehensive system status"""
        return {
            'running': self.running,
            'training_mode': self.training_mode,
            'ml_model_trained': self.ml_detector.trained,
            'detection_stats': self.detection_stats,
            'recent_alerts': list(self.correlated_alerts)[-10:],
            'ml_stats': self.ml_detector.get_model_stats(),
            'rule_stats': self.rule_detector.get_statistics(),
            'detection_accuracy': self.adaptive_detector.get_detection_accuracy()
        }
    
    def export_threat_intelligence(self):
        """Export threat intelligence data"""
        intelligence = {
            'timestamp': datetime.now().isoformat(),
            'system_stats': self.get_system_status(),
            'threat_patterns': self._extract_threat_patterns(),
            'recommendations': self._generate_system_recommendations()
        }
        
        return intelligence
    
    def _extract_threat_patterns(self):
        """Extract common threat patterns from alerts"""
        patterns = {}
        
        # Analyze correlated alerts
        for alert in self.correlated_alerts:
            pattern_key = f"{alert['type']}_{alert['severity']}"
            if pattern_key not in patterns:
                patterns[pattern_key] = {
                    'count': 0,
                    'avg_confidence': 0,
                    'common_features': []
                }
            patterns[pattern_key]['count'] += 1
            patterns[pattern_key]['avg_confidence'] += alert['confidence']
        
        # Calculate averages
        for pattern in patterns.values():
            if pattern['count'] > 0:
                pattern['avg_confidence'] /= pattern['count']
        
        return patterns
    
    def _generate_system_recommendations(self):
        """Generate system-wide security recommendations"""
        recommendations = []
        
        stats = self.detection_stats
        
        if stats['false_positives'] > stats['combined_alerts'] * 0.3:
            recommendations.append("🎯 Tune detection thresholds to reduce false positives")
        
        if not self.ml_detector.trained:
            recommendations.append("🤖 Train ML model with more data for better detection")
        
        if stats['combined_alerts'] > 50:
            recommendations.append("🔧 Consider implementing automated response actions")
        
        return recommendations

# Example usage and testing
if __name__ == "__main__":
    # Initialize system
    security_system = IntegratedVNCSecuritySystem()
    
    # Start monitoring
    security_system.start_system()
    
    # Enable training mode for initial data collection
    security_system.enable_training_mode()
    
    # Simulate some VNC traffic for testing
    test_packets = [
        b"VNC_FRAME_UPDATE" + b"A" * 1000,  # Normal frame update
        b"FILE_TRANSFER" + b"B" * 50000,    # Large file transfer
        b"CLIPBOARD_DATA" + b"sensitive_data" * 100,  # Clipboard data
        b"\x89\x50\x4E\x47" + b"C" * 10000  # PNG file signature
    ]
    
    print("\n🧪 Testing with simulated VNC packets...")
    for i, packet in enumerate(test_packets):
        print(f"\nProcessing packet {i+1}...")
        result = security_system.process_vnc_packet(packet, {
            'session_duration': 300,
            'activity_level': 0.7,
            'bandwidth_spike': len(packet) > 10000
        })
        
        if result:
            print(f"Alert generated: {result['description']}")
    
    # Train ML model with collected data
    time.sleep(2)
    security_system.disable_training_mode()
    security_system.train_ml_model()
    
    # Show system status
    print("\n📊 System Status:")
    status = security_system.get_system_status()
    print(json.dumps(status, indent=2, default=str))
    
    # Stop system
    time.sleep(1)
    security_system.stop_system()