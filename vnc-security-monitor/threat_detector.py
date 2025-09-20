#!/usr/bin/env python3
"""
VNC Security Monitor - Threat Detection Engine
Detects data exfiltration patterns in VNC traffic
"""

import time
import threading
import json
from datetime import datetime
from collections import defaultdict, deque
import hashlib

class VNCThreatDetector:
    def __init__(self):
        self.alerts = deque(maxlen=1000)
        self.traffic_stats = defaultdict(int)
        self.file_transfers = []
        self.clipboard_events = []
        self.bandwidth_history = deque(maxlen=100)
        self.running = False
        
    def start_monitoring(self):
        """Start the threat detection engine"""
        self.running = True
        self.monitor_thread = threading.Thread(target=self._monitor_loop)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()
        print("🔍 VNC Threat Detector started")
        
    def stop_monitoring(self):
        """Stop the threat detection engine"""
        self.running = False
        print("⏹️  VNC Threat Detector stopped")
        
    def _monitor_loop(self):
        """Main monitoring loop"""
        while self.running:
            self._analyze_traffic()
            self._check_anomalies()
            time.sleep(1)
            
    def analyze_vnc_packet(self, packet_data):
        """Analyze individual VNC packet for threats"""
        timestamp = datetime.now()
        packet_size = len(packet_data)
        
        # Update bandwidth tracking
        self.bandwidth_history.append({
            'timestamp': timestamp,
            'size': packet_size
        })
        
        # Detect file transfer patterns
        if self._is_file_transfer(packet_data):
            self._handle_file_transfer(packet_data, timestamp)
            
        # Detect clipboard operations
        if self._is_clipboard_operation(packet_data):
            self._handle_clipboard_event(packet_data, timestamp)
            
        # Check for suspicious patterns
        self._check_suspicious_patterns(packet_data, timestamp)
        
    def _is_file_transfer(self, data):
        """Detect file transfer patterns in VNC data"""
        # Look for common file transfer signatures
        file_signatures = [
            b'Content-Type: application/octet-stream',
            b'filename=',
            b'PUT /upload',
            b'POST /file'
        ]
        return any(sig in data for sig in file_signatures)
        
    def _is_clipboard_operation(self, data):
        """Detect clipboard operations"""
        clipboard_patterns = [
            b'\x03\x00\x00\x00',  # VNC clipboard message
            b'clipboard',
            b'copy',
            b'paste'
        ]
        return any(pattern in data.lower() for pattern in clipboard_patterns)
        
    def _handle_file_transfer(self, data, timestamp):
        """Handle detected file transfer"""
        file_hash = hashlib.md5(data).hexdigest()[:8]
        transfer = {
            'timestamp': timestamp,
            'size': len(data),
            'hash': file_hash,
            'risk_level': self._calculate_risk_level(len(data))
        }
        self.file_transfers.append(transfer)
        
        # Generate alert for large transfers
        if len(data) > 1024 * 1024:  # 1MB threshold
            self._create_alert(
                'HIGH',
                'Large File Transfer Detected',
                f'File transfer of {len(data)/1024/1024:.2f}MB detected'
            )
            
    def _handle_clipboard_event(self, data, timestamp):
        """Handle clipboard events"""
        event = {
            'timestamp': timestamp,
            'size': len(data),
            'content_preview': str(data[:50]) + '...' if len(data) > 50 else str(data)
        }
        self.clipboard_events.append(event)
        
        # Alert on large clipboard data
        if len(data) > 10000:  # 10KB threshold
            self._create_alert(
                'MEDIUM',
                'Large Clipboard Transfer',
                f'Clipboard data of {len(data)} bytes detected'
            )
            
    def _check_suspicious_patterns(self, data, timestamp):
        """Check for various suspicious patterns"""
        # Check for encoded data (base64, hex)
        if self._contains_encoded_data(data):
            self._create_alert(
                'MEDIUM',
                'Encoded Data Detected',
                'Potentially encoded data in VNC stream'
            )
            
        # Check for database dumps
        if b'INSERT INTO' in data or b'CREATE TABLE' in data:
            self._create_alert(
                'HIGH',
                'Database Content Detected',
                'Potential database dump in VNC traffic'
            )
            
    def _contains_encoded_data(self, data):
        """Check if data contains encoded content"""
        # Simple heuristic for base64
        try:
            import base64
            decoded = base64.b64decode(data[:100])
            return len(decoded) > 10
        except:
            return False
            
    def _calculate_risk_level(self, size):
        """Calculate risk level based on transfer size"""
        if size > 10 * 1024 * 1024:  # 10MB
            return 'HIGH'
        elif size > 1024 * 1024:  # 1MB
            return 'MEDIUM'
        else:
            return 'LOW'
            
    def _create_alert(self, severity, title, description):
        """Create a security alert"""
        alert = {
            'timestamp': datetime.now(),
            'severity': severity,
            'title': title,
            'description': description,
            'id': len(self.alerts) + 1
        }
        self.alerts.append(alert)
        print(f"🚨 {severity} ALERT: {title} - {description}")
        
    def _analyze_traffic(self):
        """Analyze overall traffic patterns"""
        if len(self.bandwidth_history) < 10:
            return
            
        # Calculate bandwidth anomalies
        recent_sizes = [entry['size'] for entry in list(self.bandwidth_history)[-10:]]
        avg_size = sum(recent_sizes) / len(recent_sizes)
        
        if avg_size > 100000:  # 100KB average
            self._create_alert(
                'MEDIUM',
                'High Bandwidth Usage',
                f'Average packet size: {avg_size/1024:.2f}KB'
            )
            
    def _check_anomalies(self):
        """Check for behavioral anomalies"""
        # Check for rapid file transfers
        recent_transfers = [t for t in self.file_transfers 
                          if (datetime.now() - t['timestamp']).seconds < 60]
        
        if len(recent_transfers) > 5:
            self._create_alert(
                'HIGH',
                'Rapid File Transfer Activity',
                f'{len(recent_transfers)} transfers in last minute'
            )
            
    def get_statistics(self):
        """Get current security statistics"""
        return {
            'total_alerts': len(self.alerts),
            'file_transfers': len(self.file_transfers),
            'clipboard_events': len(self.clipboard_events),
            'current_bandwidth': len(self.bandwidth_history),
            'high_risk_alerts': len([a for a in self.alerts if a['severity'] == 'HIGH']),
            'medium_risk_alerts': len([a for a in self.alerts if a['severity'] == 'MEDIUM'])
        }
        
    def get_recent_alerts(self, limit=10):
        """Get recent security alerts"""
        return list(self.alerts)[-limit:]