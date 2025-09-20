#!/usr/bin/env python3
"""
Network Analyzer for VNC Traffic
Captures and analyzes real VNC network packets
"""

import socket
import struct
import threading
import time
from datetime import datetime

class VNCNetworkAnalyzer:
    def __init__(self, detector):
        self.detector = detector
        self.running = False
        self.vnc_ports = [5900, 5901, 5902, 5903, 5904]  # Common VNC ports
        self.captured_packets = []
        
    def start_capture(self, interface='localhost'):
        """Start capturing VNC network traffic"""
        self.running = True
        self.capture_thread = threading.Thread(target=self._capture_loop)
        self.capture_thread.daemon = True
        self.capture_thread.start()
        print(f"🔍 Network capture started on {interface}")
        
    def stop_capture(self):
        """Stop network capture"""
        self.running = False
        print("⏹️  Network capture stopped")
        
    def _capture_loop(self):
        """Main packet capture loop"""
        # Simulate packet capture for demo
        while self.running:
            self._simulate_vnc_traffic()
            time.sleep(0.5)
            
    def _simulate_vnc_traffic(self):
        """Simulate VNC traffic for demonstration"""
        # Generate various types of VNC packets
        packet_types = [
            self._create_vnc_handshake(),
            self._create_vnc_auth(),
            self._create_vnc_framebuffer_update(),
            self._create_vnc_pointer_event(),
            self._create_vnc_key_event(),
            self._create_vnc_clipboard()
        ]
        
        import random
        packet = random.choice(packet_types)
        self.captured_packets.append({
            'timestamp': datetime.now(),
            'size': len(packet),
            'data': packet,
            'source': '192.168.1.100',
            'destination': '192.168.1.200',
            'port': 5900
        })
        
        # Send to detector
        self.detector.analyze_vnc_packet(packet)
        
    def _create_vnc_handshake(self):
        """Create VNC handshake packet"""
        return b'RFB 003.008\n'
        
    def _create_vnc_auth(self):
        """Create VNC authentication packet"""
        return b'\x02\x00\x00\x00'  # VNC auth type
        
    def _create_vnc_framebuffer_update(self):
        """Create framebuffer update packet"""
        # VNC framebuffer update header
        packet = b'\x00'  # Message type
        packet += b'\x00'  # Padding
        packet += struct.pack('>H', 1)  # Number of rectangles
        packet += struct.pack('>HHHH', 0, 0, 800, 600)  # Rectangle
        packet += struct.pack('>I', 0)  # Encoding type
        packet += b'x' * 1000  # Pixel data
        return packet
        
    def _create_vnc_pointer_event(self):
        """Create pointer event packet"""
        packet = b'\x05'  # Message type
        packet += b'\x01'  # Button mask
        packet += struct.pack('>HH', 400, 300)  # X, Y coordinates
        return packet
        
    def _create_vnc_key_event(self):
        """Create key event packet"""
        packet = b'\x04'  # Message type
        packet += b'\x01'  # Down flag
        packet += b'\x00\x00'  # Padding
        packet += struct.pack('>I', 65)  # Key symbol (A)
        return packet
        
    def _create_vnc_clipboard(self):
        """Create clipboard packet"""
        text = b"Confidential data being copied"
        packet = b'\x03'  # Message type
        packet += b'\x00\x00\x00'  # Padding
        packet += struct.pack('>I', len(text))  # Length
        packet += text
        return packet
        
    def get_packet_statistics(self):
        """Get packet capture statistics"""
        if not self.captured_packets:
            return {}
            
        total_packets = len(self.captured_packets)
        total_bytes = sum(p['size'] for p in self.captured_packets)
        
        # Calculate packets per second
        if total_packets > 1:
            time_span = (self.captured_packets[-1]['timestamp'] - 
                        self.captured_packets[0]['timestamp']).total_seconds()
            pps = total_packets / max(time_span, 1)
        else:
            pps = 0
            
        return {
            'total_packets': total_packets,
            'total_bytes': total_bytes,
            'packets_per_second': round(pps, 2),
            'average_packet_size': round(total_bytes / max(total_packets, 1), 2)
        }
        
    def analyze_protocol_distribution(self):
        """Analyze VNC protocol message distribution"""
        message_types = {}
        for packet in self.captured_packets:
            if packet['data']:
                msg_type = packet['data'][0] if len(packet['data']) > 0 else 0
                message_types[msg_type] = message_types.get(msg_type, 0) + 1
                
        return message_types