#!/usr/bin/env python3
"""
VNC Traffic Simulator - For demonstration purposes
Simulates various VNC traffic patterns and attacks
"""

import random
import time
import base64
from threat_detector import VNCThreatDetector

class VNCTrafficSimulator:
    def __init__(self):
        self.detector = None
        
    def set_detector(self, detector):
        """Set the threat detector instance"""
        self.detector = detector
        
    def generate_normal_traffic(self):
        """Generate normal VNC traffic"""
        if not self.detector:
            return
            
        # Simulate normal screen updates
        normal_packets = [
            b'\x00\x00\x00\x00\x00\x00\x00\x00',  # Screen update
            b'\x01\x00\x00\x00\x00\x00\x00\x00',  # Mouse movement
            b'\x02\x00\x00\x00\x00\x00\x00\x00',  # Keyboard input
        ]
        
        packet = random.choice(normal_packets)
        packet += b'x' * random.randint(50, 500)  # Add random data
        self.detector.analyze_vnc_packet(packet)
        
    def simulate_file_transfer(self):
        """Simulate a file transfer attack"""
        if not self.detector:
            return
            
        print("🎭 Simulating file transfer attack...")
        
        # Simulate large file transfer
        file_data = b'Content-Type: application/octet-stream\r\n'
        file_data += b'filename=sensitive_data.pdf\r\n'
        file_data += b'x' * (2 * 1024 * 1024)  # 2MB file
        
        self.detector.analyze_vnc_packet(file_data)
        
    def simulate_clipboard_exfiltration(self):
        """Simulate clipboard-based data exfiltration"""
        if not self.detector:
            return
            
        print("🎭 Simulating clipboard exfiltration...")
        
        # Simulate large clipboard data
        clipboard_data = b'\x03\x00\x00\x00'  # VNC clipboard message
        clipboard_data += b'CONFIDENTIAL: Employee Database\n'
        clipboard_data += b'John Doe, SSN: 123-45-6789, Salary: $75000\n' * 100
        
        self.detector.analyze_vnc_packet(clipboard_data)
        
    def simulate_database_dump(self):
        """Simulate database dump exfiltration"""
        if not self.detector:
            return
            
        print("🎭 Simulating database dump...")
        
        # Simulate SQL dump
        sql_data = b'-- Database Dump\n'
        sql_data += b'CREATE TABLE users (id INT, name VARCHAR(50), email VARCHAR(100));\n'
        sql_data += b'INSERT INTO users VALUES (1, "John Doe", "john@company.com");\n' * 50
        
        self.detector.analyze_vnc_packet(sql_data)
        
    def simulate_encoded_data(self):
        """Simulate encoded data exfiltration"""
        if not self.detector:
            return
            
        print("🎭 Simulating encoded data transfer...")
        
        # Create base64 encoded data
        secret_data = "This is confidential company information that should not be leaked"
        encoded_data = base64.b64encode(secret_data.encode())
        
        packet = b'data:text/plain;base64,' + encoded_data
        self.detector.analyze_vnc_packet(packet)
        
    def simulate_bandwidth_spike(self):
        """Simulate sudden bandwidth spike"""
        if not self.detector:
            return
            
        print("🎭 Simulating bandwidth spike...")
        
        # Send multiple large packets quickly
        for _ in range(10):
            large_packet = b'x' * (500 * 1024)  # 500KB packets
            self.detector.analyze_vnc_packet(large_packet)
            time.sleep(0.1)

# Global instance for the app to use
simulator_instance = VNCTrafficSimulator()

def get_simulator():
    return simulator_instance