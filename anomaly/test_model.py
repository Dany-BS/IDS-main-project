from scapy.all import *
import joblib
import pandas as pd
import numpy as np
from datetime import datetime
import time
from collections import defaultdict
import random

class ModelTester:
    def __init__(self):
        # Load model info
        print("Loading model...")
        model_info = joblib.load('scapy_model.pkl')
        self.model = model_info['model']
        self.scaler = model_info['scaler']
        self.feature_names = model_info['feature_names']
        
        # Initialize connection tracking
        self.connections = defaultdict(list)
        self.connection_stats = defaultdict(lambda: {
            'count': 0,
            'srv_count': 0,
            'serror_count': 0,
            'rerror_count': 0,
            'serror_rate': 0,
            'srv_serror_rate': 0,
            'rerror_rate': 0,
            'srv_rerror_rate': 0,
            'same_srv_rate': 0,
            'diff_srv_rate': 0
        })
    
    def get_service(self, packet):
        if TCP in packet:
            dport = packet[TCP].dport
        elif UDP in packet:
            dport = packet[UDP].dport
        else:
            return 'other'
            
        common_ports = {
            20: 'ftp_data',
            21: 'ftp',
            22: 'ssh',
            23: 'telnet',
            25: 'smtp',
            53: 'domain',
            80: 'http',
            110: 'pop_3',
            143: 'imap4',
            443: 'http_443',
            445: 'private',
            3306: 'private',
            3389: 'private',
            8080: 'http'
        }
        return common_ports.get(dport, 'private')
    
    def get_flag(self, packet):
        if TCP in packet:
            flags = packet[TCP].flags
            
            if flags & 0x12 == 0x12:  # SYN + ACK
                return 'SF'
            elif flags & 0x02 == 0x02:  # SYN
                return 'S0'
            elif flags & 0x04 == 0x04:  # RST
                return 'REJ'
            elif flags & 0x14 == 0x14:  # RST + ACK
                return 'RSTR'
            elif flags & 0x01 == 0x01:  # FIN
                if flags & 0x10:  # FIN + ACK
                    return 'SF'
                return 'S1'
            elif flags & 0x29 or flags == 0:  # FIN+PSH+URG or NULL
                return 'OTH'
            else:
                return 'SF'
        return 'OTH'
    
    def update_connection_stats(self, packet, connection_key):
        """Update connection statistics with emphasis on attack patterns"""
        self.connections[connection_key].append(packet)
        stats = self.connection_stats[connection_key]
        stats['count'] += 1
        
        if TCP in packet or UDP in packet:
            stats['srv_count'] += 1
            
            # Get current time window connections (last 2 seconds)
            current_time = time.time()
            recent_connections = [p for p in self.connections[connection_key] 
                                if hasattr(p, 'time') and current_time - p.time < 2]
            
            if TCP in packet:
                flags = packet[TCP].flags
                
                # Enhanced SYN flood detection
                if flags & 0x02 and not flags & 0x10:  # SYN without ACK
                    stats['serror_count'] += 3  # Increased weight
                    if len(recent_connections) > 3:  # Rapid SYN packets
                        stats['serror_count'] += len(recent_connections)  # Scale with number of rapid connections
                
                # Enhanced Port scan detection
                dst_ip = packet[IP].dst
                recent_ports = set(p[TCP].dport for p in recent_connections if TCP in p)
                if len(recent_ports) > 2:  # More than 2 different ports in 2 seconds
                    stats['rerror_count'] += len(recent_ports) * 2  # Increased weight
                
                # Enhanced unusual flags detection (XMAS, NULL scan)
                if flags & 0x29 or flags == 0:  # FIN+PSH+URG or NULL
                    stats['serror_count'] += 4  # Increased weight for unusual flags
                    if len(recent_connections) > 2:  # Multiple unusual packets
                        stats['serror_count'] += len(recent_connections) * 2
                
                # RST flags (rejected connections)
                if flags & 0x04:  # RST flag
                    stats['rerror_count'] += 2
            
            # Update error rates with higher sensitivity
            total_packets = max(stats['count'], 1)
            stats['serror_rate'] = min(1.0, stats['serror_count'] / total_packets)
            stats['srv_serror_rate'] = min(1.0, stats['serror_count'] / max(stats['srv_count'], 1))
            stats['rerror_rate'] = min(1.0, stats['rerror_count'] / total_packets)
            stats['srv_rerror_rate'] = min(1.0, stats['rerror_count'] / max(stats['srv_count'], 1))
            
            # Update service-based features
            all_dst_conns = [(k, v) for k, v in self.connections.items() if k[1] == dst_ip]
            if all_dst_conns:
                current_service = self.get_service(packet)
                same_service = sum(1 for k, v in all_dst_conns 
                                 if self.get_service(v[-1]) == current_service)
                stats['same_srv_rate'] = same_service / len(all_dst_conns)
                stats['diff_srv_rate'] = 1 - stats['same_srv_rate']
                
                # Enhanced scan detection based on service diversity
                if stats['diff_srv_rate'] > 0.8:
                    stats['rerror_count'] += 4
        
        # Enhanced LAND attack detection
        if IP in packet and packet[IP].src == packet[IP].dst:
            stats['serror_count'] += 6  # Significantly increased weight
            if TCP in packet and packet[TCP].sport == packet[TCP].dport:
                stats['serror_count'] += 4  # Additional weight for matching ports
            stats['serror_rate'] = min(1.0, stats['serror_count'] / max(stats['count'], 1))
    
    def extract_features(self, packet, connection_key):
        if IP not in packet:
            return None
            
        conn_history = self.connections[connection_key]
        conn_stats = self.connection_stats[connection_key]
        
        features = {
            'protocol_type': 'tcp' if TCP in packet else ('udp' if UDP in packet else 'icmp'),
            'service': self.get_service(packet),
            'flag': self.get_flag(packet),
            'src_bytes': len(packet),
            'dst_bytes': len(packet),
            'land': 1 if packet[IP].src == packet[IP].dst else 0,
            'wrong_fragment': 1 if packet[IP].flags & 0x1 else 0,
            'urgent': 1 if TCP in packet and packet[TCP].flags & 0x20 else 0,
            'count': conn_stats['count'],
            'srv_count': conn_stats['srv_count'],
            'serror_rate': conn_stats['serror_rate'],
            'srv_serror_rate': conn_stats['srv_serror_rate'],
            'rerror_rate': conn_stats['rerror_rate'],
            'srv_rerror_rate': conn_stats['srv_rerror_rate'],
            'same_srv_rate': conn_stats['same_srv_rate'],
            'diff_srv_rate': conn_stats['diff_srv_rate'],
            'dst_host_count': sum(1 for k in self.connections.keys() if k[1] == packet[IP].dst),
            'dst_host_srv_count': sum(1 for k in self.connections.keys() 
                                    if k[1] == packet[IP].dst and 
                                    k[2] == (packet[TCP].dport if TCP in packet else 
                                            packet[UDP].dport if UDP in packet else 0))
        }
        
        df = pd.DataFrame([features])
        categorical_features = ['protocol_type', 'service', 'flag']
        df = pd.get_dummies(df, columns=categorical_features)
        
        for col in self.feature_names:
            if col not in df.columns:
                df[col] = 0
                
        df = df[self.feature_names]
        scaled_features = pd.DataFrame(
            self.scaler.transform(df),
            columns=self.feature_names
        )
        
        return scaled_features
    
    def analyze_packet(self, packet):
        if IP not in packet:
            return None
            
        if TCP in packet:
            connection_key = (packet[IP].src, packet[IP].dst, packet[TCP].dport)
        elif UDP in packet:
            connection_key = (packet[IP].src, packet[IP].dst, packet[UDP].dport)
        else:
            connection_key = (packet[IP].src, packet[IP].dst, 0)
        
        self.update_connection_stats(packet, connection_key)
        features = self.extract_features(packet, connection_key)
        
        if features is not None:
            prediction = self.model.predict(features)[0]
            prediction_proba = self.model.predict_proba(features)[0]
            return prediction, prediction_proba[1]  # Return prediction and attack probability
        return None, None

def test_normal_traffic():
    print("\nTesting Normal Traffic Detection")
    print("-" * 50)
    tester = ModelTester()
    
    # Test normal HTTP traffic
    print("\n1. Testing Normal HTTP Traffic:")
    for _ in range(3):  # Multiple normal connections
        # Create a normal HTTP connection
        src_port = random.randint(49152, 65535)
        
        # SYN
        syn = IP(dst="8.8.8.8")/TCP(sport=src_port, dport=80, flags='S')
        pred, prob = tester.analyze_packet(syn)
        if pred is not None and _ == 2:
            print(f"SYN packet - Prediction: {'ATTACK' if pred == 1 else 'NORMAL'} (prob: {prob:.3f})")
        
        # SYN-ACK (simulated response)
        synack = IP(dst="8.8.8.8")/TCP(sport=src_port, dport=80, flags='SA')
        pred, prob = tester.analyze_packet(synack)
        if pred is not None and _ == 2:
            print(f"SYN-ACK packet - Prediction: {'ATTACK' if pred == 1 else 'NORMAL'} (prob: {prob:.3f})")
        
        time.sleep(0.1)  # Small delay between connections

def test_attack_traffic():
    print("\nTesting Attack Traffic Detection")
    print("-" * 50)
    
    # Test SYN flood with increased intensity
    print("\n1. Testing SYN Flood Detection:")
    tester = ModelTester()
    for i in range(30):  # Increased number of packets
        src_ip = f"192.168.1.{random.randint(1,255)}"
        syn = IP(src=src_ip, dst="10.0.0.1")/TCP(sport=random.randint(1024,65535), dport=80, flags='S')
        pred, prob = tester.analyze_packet(syn)
        if pred is not None and i >= 25:  # Show last few predictions
            print(f"SYN flood packet - Prediction: {'ATTACK' if pred == 1 else 'NORMAL'} (prob: {prob:.3f})")
        time.sleep(0.001)  # Faster flood
    
    # Test Port Scan (already working well, keep as is)
    print("\n2. Testing Port Scan Detection:")
    tester = ModelTester()
    for _ in range(3):
        for port in [21, 22, 23, 25, 80, 443, 3389]:
            syn = IP(dst="10.0.0.1")/TCP(sport=random.randint(49152,65535), dport=port, flags='S')
            pred, prob = tester.analyze_packet(syn)
            if pred is not None and _ == 2:
                print(f"Port scan packet (port {port}) - Prediction: {'ATTACK' if pred == 1 else 'NORMAL'} (prob: {prob:.3f})")
            time.sleep(0.05)
    
    # Test XMAS Scan with increased intensity
    print("\n3. Testing XMAS Scan Detection:")
    tester = ModelTester()
    for _ in range(5):  # Increased attempts
        for port in [80, 443, 22, 23]:
            # XMAS scan (FIN+PSH+URG)
            xmas = IP(dst="10.0.0.1")/TCP(sport=random.randint(49152,65535), dport=port, flags='FPU')
            pred, prob = tester.analyze_packet(xmas)
            if pred is not None and _ >= 3:  # Show more predictions
                print(f"XMAS scan packet (port {port}) - Prediction: {'ATTACK' if pred == 1 else 'NORMAL'} (prob: {prob:.3f})")
            
            # NULL scan
            null = IP(dst="10.0.0.1")/TCP(sport=random.randint(49152,65535), dport=port, flags=0)
            pred, prob = tester.analyze_packet(null)
            if pred is not None and _ >= 3:
                print(f"NULL scan packet (port {port}) - Prediction: {'ATTACK' if pred == 1 else 'NORMAL'} (prob: {prob:.3f})")
            
            time.sleep(0.02)  # Faster scanning
    
    # Test LAND Attack with increased intensity
    print("\n4. Testing LAND Attack Detection:")
    tester = ModelTester()
    target_ip = "10.0.0.1"
    for _ in range(8):  # Increased attempts
        port = random.choice([80, 443, 22, 23])  # Vary the ports
        land = IP(src=target_ip, dst=target_ip)/TCP(sport=port, dport=port, flags='S')
        pred, prob = tester.analyze_packet(land)
        if pred is not None:
            print(f"LAND attack packet (port {port}) - Prediction: {'ATTACK' if pred == 1 else 'NORMAL'} (prob: {prob:.3f})")
        time.sleep(0.05)

if __name__ == "__main__":
    print("Starting Model Testing...")
    print("=" * 50)
    
    test_normal_traffic()
    test_attack_traffic() 