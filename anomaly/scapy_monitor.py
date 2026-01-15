import tkinter as tk
from tkinter import ttk, scrolledtext
import joblib
import pandas as pd
import numpy as np
from scapy.all import sniff, IP, TCP, UDP
import threading
from datetime import datetime
from collections import defaultdict
import time

class NetworkMonitor:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Traffic Anomaly Detector")
        self.root.geometry("800x600")
        
        # Load model info
        print("Loading model information...")
        model_info = joblib.load('scapy_model.pkl')
        self.model = model_info['model']
        self.scaler = model_info['scaler']
        self.feature_names = model_info['feature_names']
        print(f"Model loaded with {len(self.feature_names)} features")
        print("Feature names:", self.feature_names)
        
        # Initialize connection tracking
        self.connections = defaultdict(list)  # (src_ip, dst_ip, dst_port) -> [packets]
        self.connection_stats = defaultdict(lambda: {
            'count': 0,
            'srv_count': 0,
            'serror_count': 0,
            'rerror_count': 0
        })
        
        self.packet_count = 0
        self.is_capturing = False
        self.setup_gui()
    
    def setup_gui(self):
        # Control Frame
        control_frame = ttk.Frame(self.root)
        control_frame.pack(padx=10, pady=5, fill="x")
        
        self.start_button = ttk.Button(control_frame, text="Start Capture", command=self.start_capture)
        self.start_button.pack(side="left", padx=5)
        
        self.stop_button = ttk.Button(control_frame, text="Stop Capture", command=self.stop_capture, state="disabled")
        self.stop_button.pack(side="left", padx=5)
        
        # Statistics Frame
        stats_frame = ttk.LabelFrame(self.root, text="Statistics")
        stats_frame.pack(padx=10, pady=5, fill="x")
        
        self.stats_label = ttk.Label(stats_frame, text="Packets Captured: 0")
        self.stats_label.pack(padx=5, pady=5)
        
        # Log Frame
        log_frame = ttk.LabelFrame(self.root, text="Packet Log")
        log_frame.pack(padx=10, pady=5, fill="both", expand=True)
        
        self.log_area = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD)
        self.log_area.pack(padx=5, pady=5, fill="both", expand=True)
    
    def get_service(self, packet):
        """Map ports to the expected service values from training data"""
        if TCP in packet:
            dport = packet[TCP].dport
        elif UDP in packet:
            dport = packet[UDP].dport
        else:
            return 'other'
            
        # Map ports to services as per training data
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
            1433: 'private',
            3306: 'private',
            3389: 'private',
            8080: 'http'
        }
        return common_ports.get(dport, 'private')  # Use 'private' as default
    
    def get_flag(self, packet):
        """Map TCP flags to the expected flag values from training data"""
        if TCP in packet:
            flags = packet[TCP].flags
            
            # SYN-ACK: Normal established connection
            if flags & 0x12 == 0x12:  # SYN + ACK
                return 'SF'
                
            # SYN only: Connection attempt
            elif flags & 0x02 == 0x02:  # SYN
                return 'S0'
                
            # RST: Connection rejected
            elif flags & 0x04 == 0x04:  # RST
                return 'REJ'
                
            # RST-ACK: Connection reset
            elif flags & 0x14 == 0x14:  # RST + ACK
                return 'RSTR'
                
            # FIN: Connection closing
            elif flags & 0x01 == 0x01:  # FIN
                if flags & 0x10:  # FIN + ACK
                    return 'SF'
                return 'S1'
                
            # Unusual combinations (XMAS, NULL scan, etc.)
            elif flags & 0x29 or flags == 0:  # FIN+PSH+URG or NULL
                return 'OTH'
                
            # Default for other combinations
            else:
                return 'SF'  # Assume normal traffic for unknown combinations
        return 'OTH'  # Non-TCP packets
    
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
                
                # SYN flood detection (many SYN packets without completion)
                if flags & 0x02 and not flags & 0x10:  # SYN without ACK
                    stats['serror_count'] += 1
                    if len(recent_connections) > 3:  # Rapid SYN packets
                        stats['serror_count'] += 2
                
                # Port scan detection (multiple ports in short time)
                dst_ip = packet[IP].dst
                recent_ports = set(p[TCP].dport for p in recent_connections if TCP in p)
                if len(recent_ports) > 2:  # More than 2 different ports in 2 seconds
                    stats['rerror_count'] += len(recent_ports)
                
                # Unusual flags (XMAS, NULL scan)
                if flags & 0x29 or flags == 0:  # FIN+PSH+URG or NULL
                    stats['serror_count'] += 2
                
                # RST flags (rejected connections)
                if flags & 0x04:  # RST flag
                    stats['rerror_count'] += 1
            
            # Update error rates
            stats['serror_rate'] = stats['serror_count'] / max(stats['count'], 1)
            stats['srv_serror_rate'] = stats['serror_count'] / max(stats['srv_count'], 1)
            stats['rerror_rate'] = stats['rerror_count'] / max(stats['count'], 1)
            stats['srv_rerror_rate'] = stats['rerror_count'] / max(stats['srv_count'], 1)
            
            # Update service-based features
            all_dst_conns = [(k, v) for k, v in self.connections.items() if k[1] == dst_ip]
            if all_dst_conns:
                current_service = self.get_service(packet)
                same_service = sum(1 for k, v in all_dst_conns 
                                 if self.get_service(v[-1]) == current_service)
                stats['same_srv_rate'] = same_service / len(all_dst_conns)
                stats['diff_srv_rate'] = 1 - stats['same_srv_rate']
                
                # High rate of different services indicates potential scan
                if stats['diff_srv_rate'] > 0.8:
                    stats['rerror_count'] += 2
        
        # LAND attack detection
        if IP in packet and packet[IP].src == packet[IP].dst:
            stats['serror_count'] += 3
            stats['serror_rate'] = stats['serror_count'] / max(stats['count'], 1)
            
    def extract_features(self, packet, connection_key):
        if IP not in packet:
            return None
            
        conn_history = self.connections[connection_key]
        conn_stats = self.connection_stats[connection_key]
        
        # Calculate time-window based features
        current_time = time.time()
        recent_connections = [p for p in conn_history 
                            if hasattr(p, 'time') and current_time - p.time < 2]
        
        # Basic features
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
            'same_srv_rate': conn_stats.get('same_srv_rate', 0),
            'diff_srv_rate': conn_stats.get('diff_srv_rate', 0),
            'dst_host_count': sum(1 for k in self.connections.keys() if k[1] == packet[IP].dst),
            'dst_host_srv_count': sum(1 for k in self.connections.keys() 
                                    if k[1] == packet[IP].dst and 
                                    k[2] == (packet[TCP].dport if TCP in packet else 
                                            packet[UDP].dport if UDP in packet else 0))
        }
        
        # Debug print
        print("\nExtracted features:")
        for k, v in features.items():
            print(f"{k}: {v}")
        
        # Convert to DataFrame and handle categorical variables
        df = pd.DataFrame([features])
        categorical_features = ['protocol_type', 'service', 'flag']
        df = pd.get_dummies(df, columns=categorical_features)
        
        # Debug print
        print("\nAfter one-hot encoding:")
        print("Columns:", df.columns.tolist())
        
        # Ensure all feature columns exist
        for col in self.feature_names:
            if col not in df.columns:
                df[col] = 0
                print(f"Added missing column: {col}")
        
        # Reorder columns to match training data
        df = df[self.feature_names]
        
        # Scale features
        scaled_features = pd.DataFrame(
            self.scaler.transform(df),
            columns=self.feature_names
        )
        
        # Debug print
        print("\nFinal feature values:")
        print(scaled_features.iloc[0])
        
        return scaled_features
    
    def analyze_packet(self, packet):
        if IP not in packet:
            return
        
        # Create connection key
        if TCP in packet:
            connection_key = (packet[IP].src, packet[IP].dst, packet[TCP].dport)
        elif UDP in packet:
            connection_key = (packet[IP].src, packet[IP].dst, packet[UDP].dport)
        else:
            connection_key = (packet[IP].src, packet[IP].dst, 0)
        
        # Update connection statistics
        self.update_connection_stats(packet, connection_key)
        
        # Extract features
        features = self.extract_features(packet, connection_key)
        if features is not None:
            # Make prediction
            prediction = self.model.predict(features)[0]
            prediction_proba = self.model.predict_proba(features)[0]
            
            # Log result
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            protocol = 'TCP' if TCP in packet else ('UDP' if UDP in packet else 'Other')
            flags = packet[TCP].flags if TCP in packet else "N/A"
            result = "ATTACK" if prediction == 1 else "NORMAL"
            
            # Debug print
            print(f"\nPrediction probabilities: Normal: {prediction_proba[0]:.3f}, Attack: {prediction_proba[1]:.3f}")
            
            log_message = f"[{timestamp}] {protocol} {src_ip} → {dst_ip} Flags: {flags} : {result} (Attack prob: {prediction_proba[1]:.3f})\n"
            self.log_area.insert(tk.END, log_message)
            self.log_area.see(tk.END)
            
            self.packet_count += 1
            self.stats_label.config(text=f"Packets Captured: {self.packet_count}")
    
    def packet_callback(self, packet):
        if not self.is_capturing:
            return
        self.root.after(0, self.analyze_packet, packet)
    
    def start_capture(self):
        self.is_capturing = True
        self.start_button.config(state="disabled")
        self.stop_button.config(state="normal")
        
        # Start packet capture in a separate thread
        self.capture_thread = threading.Thread(target=self.capture_packets)
        self.capture_thread.daemon = True
        self.capture_thread.start()
    
    def capture_packets(self):
        sniff(prn=self.packet_callback, store=0)
    
    def stop_capture(self):
        self.is_capturing = False
        self.start_button.config(state="normal")
        self.stop_button.config(state="disabled")

if __name__ == "__main__":
    root = tk.Tk()
    app = NetworkMonitor(root)
    root.mainloop() 