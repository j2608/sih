#!/usr/bin/env python3
"""
VNC Monitor - Network traffic analysis for VNC connections
"""

import socket
import struct
import threading
import time
from scapy import all as scapy
import logging

class VNCMonitor:
    def __init__(self):
        self.monitoring = False
        self.vnc_ports = [5900, 5901, 5902, 5903]  # Common VNC ports
        self.connections = {}
        self.packet_buffer = []
        
    def start_monitoring(self, host='localhost', port=5900):
        """Start monitoring VNC traffic"""
        self.monitoring = True
        self.target_host = host
        self.target_port = port
        
        # Start packet capture thread
        capture_thread = threading.Thread(target=self._capture_packets, daemon=True)
        capture_thread.start()
        
        # Start VNC protocol analysis thread
        analysis_thread = threading.Thread(target=self._analyze_vnc_traffic, daemon=True)
        analysis_thread.start()
        
        logging.info(f"Started monitoring VNC traffic on {host}:{port}")
    
    def stop_monitoring(self):
        """Stop monitoring"""
        self.monitoring = False
        logging.info("Stopped VNC monitoring")
    
    def _capture_packets(self):
        """Capture network packets using scapy"""
        try:
            # Filter for VNC traffic (ports 5900-5910)
            filter_str = f"tcp and (port {self.target_port} or portrange 5900-5910)"
            
            def packet_handler(packet):
                if self.monitoring:
                    self._process_packet(packet)
            
            # Start packet capture
            scapy.sniff(filter=filter_str, prn=packet_handler, store=0)
            
        except Exception as e:
            logging.error(f"Packet capture error: {e}")
    
    def _process_packet(self, packet):
        """Process captured VNC packets"""
        try:
            if packet.haslayer(scapy.TCP):
                tcp_layer = packet[scapy.TCP]
                
                # Check if it's VNC traffic
                if tcp_layer.dport in self.vnc_ports or tcp_layer.sport in self.vnc_ports:
                    connection_key = f"{packet[scapy.IP].src}:{tcp_layer.sport}->{packet[scapy.IP].dst}:{tcp_layer.dport}"
                    
                    # Store packet info
                    packet_info = {
                        'timestamp': time.time(),
                        'src_ip': packet[scapy.IP].src,
                        'dst_ip': packet[scapy.IP].dst,
                        'src_port': tcp_layer.sport,
                        'dst_port': tcp_layer.dport,
                        'payload_size': len(packet[scapy.TCP].payload),
                        'flags': tcp_layer.flags,
                        'payload': bytes(packet[scapy.TCP].payload) if packet[scapy.TCP].payload else b''
                    }
                    
                    self.packet_buffer.append(packet_info)
                    
                    # Maintain connection state
                    if connection_key not in self.connections:
                        self.connections[connection_key] = {
                            'established': time.time(),
                            'bytes_transferred': 0,
                            'packets': 0,
                            'last_activity': time.time()
                        }
                    
                    self.connections[connection_key]['bytes_transferred'] += packet_info['payload_size']
                    self.connections[connection_key]['packets'] += 1
                    self.connections[connection_key]['last_activity'] = time.time()
                    
        except Exception as e:
            logging.error(f"Packet processing error: {e}")
    
    def _analyze_vnc_traffic(self):
        """Analyze VNC protocol messages"""
        while self.monitoring:
            try:
                if self.packet_buffer:
                    packet = self.packet_buffer.pop(0)
                    self._analyze_vnc_message(packet)
                else:
                    time.sleep(0.1)
            except Exception as e:
                logging.error(f"VNC analysis error: {e}")
    
    def _analyze_vnc_message(self, packet):
        """Analyze VNC RFB protocol messages"""
        payload = packet['payload']
        
        if len(payload) < 1:
            return
        
        try:
            # VNC RFB Protocol Analysis
            message_type = payload[0] if payload else 0
            
            # Client-to-Server messages
            if packet['dst_port'] in self.vnc_ports:
                self._analyze_client_message(message_type, payload, packet)
            
            # Server-to-Client messages  
            elif packet['src_port'] in self.vnc_ports:
                self._analyze_server_message(message_type, payload, packet)
                
        except Exception as e:
            logging.error(f"VNC message analysis error: {e}")
    
    def _analyze_client_message(self, msg_type, payload, packet):
        """Analyze client-to-server VNC messages"""
        # VNC Client message types
        if msg_type == 0:  # SetPixelFormat
            pass
        elif msg_type == 2:  # SetEncodings
            pass
        elif msg_type == 3:  # FramebufferUpdateRequest
            pass
        elif msg_type == 4:  # KeyEvent
            self._detect_key_logging(payload, packet)
        elif msg_type == 5:  # PointerEvent
            pass
        elif msg_type == 6:  # ClientCutText (Clipboard)
            self._detect_clipboard_exfiltration(payload, packet)
    
    def _analyze_server_message(self, msg_type, payload, packet):
        """Analyze server-to-client VNC messages"""
        # VNC Server message types
        if msg_type == 0:  # FramebufferUpdate
            self._detect_screen_scraping(payload, packet)
        elif msg_type == 1:  # SetColourMapEntries
            pass
        elif msg_type == 2:  # Bell
            pass
        elif msg_type == 3:  # ServerCutText (Clipboard)
            self._detect_clipboard_exfiltration(payload, packet)
    
    def _detect_clipboard_exfiltration(self, payload, packet):
        """Detect clipboard-based data exfiltration"""
        if len(payload) > 8:  # Minimum clipboard message size
            try:
                # Extract clipboard text length (bytes 4-7)
                text_length = struct.unpack('>I', payload[4:8])[0]
                
                if text_length > 100:  # Suspicious large clipboard data
                    logging.warning(f"Large clipboard transfer detected: {text_length} bytes from {packet['src_ip']}")
                    return {
                        'type': 'clipboard_exfiltration',
                        'size': text_length,
                        'source': packet['src_ip'],
                        'timestamp': packet['timestamp']
                    }
            except:
                pass
        return None
    
    def _detect_screen_scraping(self, payload, packet):
        """Detect excessive screen capture/scraping"""
        connection_key = f"{packet['src_ip']}:{packet['src_port']}"
        
        if connection_key in self.connections:
            conn = self.connections[connection_key]
            
            # Check for high frequency screen updates
            current_time = time.time()
            if current_time - conn.get('last_screen_update', 0) < 0.1:  # < 100ms between updates
                conn['screen_update_frequency'] = conn.get('screen_update_frequency', 0) + 1
                
                if conn['screen_update_frequency'] > 50:  # More than 50 rapid updates
                    logging.warning(f"Potential screen scraping detected from {packet['src_ip']}")
                    return {
                        'type': 'screen_scraping',
                        'frequency': conn['screen_update_frequency'],
                        'source': packet['src_ip'],
                        'timestamp': packet['timestamp']
                    }
            
            conn['last_screen_update'] = current_time
        
        return None
    
    def _detect_key_logging(self, payload, packet):
        """Detect suspicious key logging patterns"""
        if len(payload) >= 8:
            # VNC KeyEvent: [type][down-flag][padding][key]
            key_code = struct.unpack('>I', payload[4:8])[0]
            
            # Log key events for pattern analysis
            connection_key = f"{packet['src_ip']}:{packet['src_port']}"
            if connection_key not in self.connections:
                self.connections[connection_key] = {}
            
            if 'key_events' not in self.connections[connection_key]:
                self.connections[connection_key]['key_events'] = []
            
            self.connections[connection_key]['key_events'].append({
                'key_code': key_code,
                'timestamp': packet['timestamp']
            })
            
            # Keep only recent key events
            recent_keys = [k for k in self.connections[connection_key]['key_events'] 
                          if packet['timestamp'] - k['timestamp'] < 60]  # Last 60 seconds
            self.connections[connection_key]['key_events'] = recent_keys
            
            # Detect rapid typing (potential automated data entry)
            if len(recent_keys) > 100:  # More than 100 keys in 60 seconds
                logging.warning(f"Rapid key input detected from {packet['src_ip']}")
                return {
                    'type': 'rapid_key_input',
                    'key_count': len(recent_keys),
                    'source': packet['src_ip'],
                    'timestamp': packet['timestamp']
                }
        
        return None
    
    def get_connection_stats(self):
        """Get current connection statistics"""
        return {
            'active_connections': len(self.connections),
            'total_bytes': sum(conn['bytes_transferred'] for conn in self.connections.values()),
            'total_packets': sum(conn['packets'] for conn in self.connections.values())
        }