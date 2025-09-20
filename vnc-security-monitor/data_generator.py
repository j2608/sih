#!/usr/bin/env python3
"""
Synthetic Data Generator for VNC Security Training
Generates realistic session logs, network flows, and host telemetry
"""

import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import random
import json
from faker import Faker

fake = Faker()

class VNCDataGenerator:
    def __init__(self, seed=42):
        np.random.seed(seed)
        random.seed(seed)
        Faker.seed(seed)
        
    def generate_session_logs(self, n_sessions=1000, anomaly_rate=0.15):
        """Generate synthetic VNC session logs with anomalies"""
        sessions = []
        n_anomalies = int(n_sessions * anomaly_rate)
        
        # Generate normal sessions
        for i in range(n_sessions - n_anomalies):
            session = self._generate_normal_session(f"sess-{i:04d}")
            sessions.append(session)
            
        # Generate anomalous sessions
        for i in range(n_anomalies):
            session = self._generate_anomalous_session(f"sess-{n_sessions-n_anomalies+i:04d}")
            sessions.append(session)
            
        return pd.DataFrame(sessions)
    
    def _generate_normal_session(self, session_id):
        """Generate a normal VNC session"""
        start_time = fake.date_time_between(start_date='-30d', end_date='now')
        duration = max(60, int(np.random.normal(1800, 600)))  # 30min avg, 10min std
        end_time = start_time + timedelta(seconds=duration)
        
        # Normal traffic patterns
        bytes_out = max(1000, int(np.random.lognormal(13, 1)))  # ~1MB average
        bytes_in = bytes_out * np.random.uniform(0.8, 1.2)
        
        return {
            'session_id': session_id,
            'user_id': fake.user_name(),
            'device_id': f"dev-{random.randint(1, 50)}",
            'src_ip': fake.ipv4_private(),
            'dst_ip': fake.ipv4(),
            'src_geo': fake.country(),
            'dst_geo': fake.country(),
            'start_ts': start_time.isoformat(),
            'end_ts': end_time.isoformat(),
            'duration_seconds': duration,
            'total_bytes_in': int(bytes_in),
            'total_bytes_out': bytes_out,
            'avg_bytes_per_sec_out': bytes_out / duration,
            'num_clipboard_events': np.random.poisson(0.5),
            'total_clipboard_bytes': np.random.exponential(2048),
            'num_screenshot_events': np.random.poisson(1),
            'avg_frame_rate': np.random.uniform(3, 8),
            'num_file_transfer_events': np.random.poisson(0.2),
            'total_files_transferred': np.random.poisson(0.3),
            'total_files_size_bytes': np.random.exponential(50000),
            'processes_spawned_count': np.random.poisson(2),
            'auth_method': np.random.choice(['password', 'kerberos', 'mfa'], p=[0.6, 0.3, 0.1]),
            'device_trust_score': np.random.beta(8, 2),  # Skewed toward high trust
            'is_encrypted': np.random.choice([True, False], p=[0.8, 0.2]),
            'label': 'normal'
        }
    
    def _generate_anomalous_session(self, session_id):
        """Generate an anomalous VNC session based on threat scenarios"""
        attack_type = np.random.choice([
            'large_file_exfil',
            'screenshot_exfil', 
            'keylogging',
            'tunnel_exfil',
            'steganographic',
            'credential_reuse',
            'insider_threat'
        ])
        
        base_session = self._generate_normal_session(session_id)
        base_session['label'] = 'anomalous'
        
        if attack_type == 'large_file_exfil':
            # Large file transfer via clipboard/drag-drop
            base_session['total_bytes_out'] *= 50  # 50x normal traffic
            base_session['num_clipboard_events'] = np.random.randint(10, 50)
            base_session['total_clipboard_bytes'] = np.random.randint(10**7, 10**8)
            base_session['num_file_transfer_events'] = np.random.randint(3, 15)
            base_session['total_files_size_bytes'] = base_session['total_clipboard_bytes']
            base_session['avg_bytes_per_sec_out'] = base_session['total_bytes_out'] / base_session['duration_seconds']
            
        elif attack_type == 'screenshot_exfil':
            # High frequency screenshots
            base_session['num_screenshot_events'] = np.random.randint(50, 200)
            base_session['avg_frame_rate'] = np.random.uniform(15, 30)  # High frame rate
            base_session['total_bytes_out'] *= 10
            
        elif attack_type == 'keylogging':
            # Suspicious keyboard patterns
            base_session['num_clipboard_events'] = np.random.randint(20, 100)
            base_session['total_clipboard_bytes'] = np.random.randint(10000, 100000)
            
        elif attack_type == 'tunnel_exfil':
            # Port forwarding/tunneling
            base_session['processes_spawned_count'] = np.random.randint(10, 30)
            base_session['total_bytes_out'] *= 20
            
        elif attack_type == 'credential_reuse':
            # Suspicious access patterns
            base_session['device_trust_score'] = np.random.uniform(0.1, 0.4)  # Low trust
            base_session['auth_method'] = 'password'  # Weak auth
            # Unusual time (2-6 AM)
            start_hour = np.random.randint(2, 6)
            base_session['start_ts'] = fake.date_time_between(start_date='-7d', end_date='now').replace(hour=start_hour).isoformat()
            
        elif attack_type == 'insider_threat':
            # Legitimate user, suspicious activity
            base_session['total_bytes_out'] *= 30
            base_session['num_file_transfer_events'] = np.random.randint(5, 20)
            base_session['total_files_size_bytes'] = base_session['total_bytes_out'] * 0.8
            
        return base_session
    
    def generate_network_flows(self, sessions_df):
        """Generate network flow records for sessions"""
        flows = []
        
        for _, session in sessions_df.iterrows():
            n_flows = np.random.randint(1, 10)  # Multiple flows per session
            
            for i in range(n_flows):
                flow = {
                    'flow_id': f"{session['session_id']}-flow-{i}",
                    'session_id': session['session_id'],
                    'src_ip': session['src_ip'],
                    'dst_ip': session['dst_ip'],
                    'src_port': np.random.randint(1024, 65535),
                    'dst_port': 5900 + np.random.randint(0, 5),  # VNC ports
                    'protocol': 'TCP',
                    'start_ts': session['start_ts'],
                    'end_ts': session['end_ts'],
                    'bytes_sent': session['total_bytes_out'] // n_flows,
                    'bytes_received': session['total_bytes_in'] // n_flows,
                    'packets_sent': np.random.randint(100, 10000),
                    'packets_received': np.random.randint(50, 5000),
                    'flow_direction': 'egress',
                    'app_protocol': 'VNC',
                    'entropy_score': np.random.uniform(0.3, 0.95)
                }
                flows.append(flow)
                
        return pd.DataFrame(flows)
    
    def generate_host_telemetry(self, sessions_df):
        """Generate host telemetry events"""
        events = []
        
        for _, session in sessions_df.iterrows():
            n_events = np.random.randint(5, 50)  # Events per session
            
            for i in range(n_events):
                event_time = datetime.fromisoformat(session['start_ts']) + timedelta(
                    seconds=np.random.randint(0, session['duration_seconds'])
                )
                
                # Correlate with session anomalies
                is_anomalous = session['label'] == 'anomalous'
                
                event = {
                    'event_id': f"{session['session_id']}-evt-{i}",
                    'session_id': session['session_id'],
                    'ts': event_time.isoformat(),
                    'host_cpu_percent': np.random.uniform(1, 15) * (3 if is_anomalous else 1),
                    'host_mem_percent': np.random.uniform(20, 60),
                    'disk_read_bytes': np.random.exponential(10000) * (10 if is_anomalous else 1),
                    'disk_write_bytes': np.random.exponential(5000),
                    'clipboard_event': np.random.choice([True, False], p=[0.3, 0.7] if is_anomalous else [0.05, 0.95]),
                    'clipboard_bytes': np.random.exponential(1000) * (50 if is_anomalous else 1),
                    'file_opened': f"/masked/file_{np.random.randint(1, 1000)}.dat",
                    'file_read_bytes': np.random.exponential(50000) * (20 if is_anomalous else 1),
                    'file_write_bytes': np.random.exponential(10000),
                    'new_process': np.random.choice(['explorer.exe', 'notepad.exe', 'cmd.exe', 'powershell.exe']),
                    'browser_upload_event': np.random.choice([True, False], p=[0.2, 0.8] if is_anomalous else [0.01, 0.99]),
                    'screenshot_taken': np.random.choice([True, False], p=[0.4, 0.6] if is_anomalous else [0.02, 0.98]),
                    'watermark_present': np.random.choice([True, False], p=[0.1, 0.9]),
                    'label': session['label']
                }
                events.append(event)
                
        return pd.DataFrame(events)
    
    def save_datasets(self, output_dir='data'):
        """Generate and save all datasets"""
        import os
        os.makedirs(output_dir, exist_ok=True)
        
        print("🔄 Generating synthetic VNC security datasets...")
        
        # Generate session logs
        sessions_df = self.generate_session_logs(1000, 0.15)
        sessions_df.to_csv(f'{output_dir}/session_logs.csv', index=False)
        print(f"✅ Generated {len(sessions_df)} session logs")
        
        # Generate network flows
        flows_df = self.generate_network_flows(sessions_df)
        flows_df.to_csv(f'{output_dir}/network_flows.csv', index=False)
        print(f"✅ Generated {len(flows_df)} network flow records")
        
        # Generate host telemetry
        telemetry_df = self.generate_host_telemetry(sessions_df)
        telemetry_df.to_csv(f'{output_dir}/host_telemetry.csv', index=False)
        print(f"✅ Generated {len(telemetry_df)} host telemetry events")
        
        # Generate summary stats
        stats = {
            'total_sessions': len(sessions_df),
            'normal_sessions': len(sessions_df[sessions_df['label'] == 'normal']),
            'anomalous_sessions': len(sessions_df[sessions_df['label'] == 'anomalous']),
            'anomaly_rate': len(sessions_df[sessions_df['label'] == 'anomalous']) / len(sessions_df),
            'total_flows': len(flows_df),
            'total_events': len(telemetry_df)
        }
        
        with open(f'{output_dir}/dataset_stats.json', 'w') as f:
            json.dump(stats, f, indent=2)
            
        print(f"📊 Dataset statistics saved to {output_dir}/dataset_stats.json")
        return sessions_df, flows_df, telemetry_df

if __name__ == "__main__":
    generator = VNCDataGenerator()
    generator.save_datasets()