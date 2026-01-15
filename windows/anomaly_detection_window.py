import customtkinter as ctk
from tkinter import scrolledtext, END
import joblib
import pandas as pd
import numpy as np
from scapy.all import sniff, IP, TCP, UDP
import threading
from datetime import datetime
from collections import defaultdict
import time
import os
import os.path

class AnomalyDetectionWindow(ctk.CTkFrame):
    def __init__(self, master):
        super().__init__(master)
        self.master = master
        
        # Initialize network monitoring variables
        self.packet_count = 0
        self.alert_count = 0  # Add alert counter
        self.is_capturing = False
        
        # Make sure we have access to the shared resource monitor
        if not hasattr(self.master, 'resource_monitor'):
            print("Warning: resource_monitor not found in master")
            self.master.resource_monitor = {'alerts': [], 'logs': []}
        
        # Initialize connection tracking
        self.connections = defaultdict(list)
        self.connection_stats = defaultdict(lambda: {
            'count': 0,
            'srv_count': 0,
            'serror_count': 0,
            'rerror_count': 0
        })
        
        # Load model info
        print("Loading model information...")
        try:
            model_path = os.path.join(os.path.dirname(__file__), '..', 'anomaly', 'scapy_model.pkl')
            model_info = joblib.load(model_path)
            self.model = model_info['model']
            self.scaler = model_info['scaler']
            self.feature_names = model_info['feature_names']
            self.model_loaded = True
            print(f"Model loaded with {len(self.feature_names)} features")
            print("Feature names:", self.feature_names)
        except Exception as e:
            print(f"Error loading model: {e}")
            self.model = None
            self.scaler = None
            self.feature_names = None
            self.model_loaded = False
        
        self.setup_ui()
        # Pack the main frame
        self.pack(fill="both", expand=True)
        self.configure(fg_color=("gray95", "gray10"))

    def setup_ui(self):
        # Main container
        self.main_container = ctk.CTkFrame(self)
        self.main_container.pack(padx=20, pady=20, fill="both", expand=True)
        
        # Header Frame with Title and Back Button
        header_frame = ctk.CTkFrame(self.main_container)
        header_frame.pack(padx=10, pady=(0, 10), fill="x")
        
        # Back Button
        back_button = ctk.CTkButton(
            header_frame,
            text="← Back",
            command=self.master.show_home_window,
            width=100,
            height=32,
            font=ctk.CTkFont(size=14)
        )
        back_button.pack(side="left", padx=10, pady=10)
        
        title_label = ctk.CTkLabel(
            header_frame, 
            text="Network Traffic Anomaly Detector",
            font=ctk.CTkFont(size=24, weight="bold")
        )
        title_label.pack(pady=10)
        
        # Control Frame
        control_frame = ctk.CTkFrame(self.main_container)
        control_frame.pack(padx=10, pady=5, fill="x")
        
        self.start_button = ctk.CTkButton(
            control_frame,
            text="Start Capture",
            command=self.start_capture,
            width=120,
            height=32,
            font=ctk.CTkFont(size=14)
        )
        self.start_button.pack(side="left", padx=5)
        
        self.stop_button = ctk.CTkButton(
            control_frame,
            text="Stop Capture",
            command=self.stop_capture,
            width=120,
            height=32,
            state="disabled",
            font=ctk.CTkFont(size=14)
        )
        self.stop_button.pack(side="left", padx=5)
        
        # Add Save Logs Button
        self.save_logs_button = ctk.CTkButton(
            control_frame,
            text="Save Logs",
            command=self.save_logs,
            width=120,
            height=32,
            font=ctk.CTkFont(size=14)
        )
        self.save_logs_button.pack(side="left", padx=5)
        
        # Statistics Frame
        stats_frame = ctk.CTkFrame(self.main_container)
        stats_frame.pack(padx=10, pady=10, fill="x")
        
        stats_title = ctk.CTkLabel(
            stats_frame,
            text="Statistics",
            font=ctk.CTkFont(size=16, weight="bold")
        )
        stats_title.pack(padx=5, pady=5)
        
        self.stats_label = ctk.CTkLabel(
            stats_frame,
            text="Packets Captured: 0",
            font=ctk.CTkFont(size=14)
        )
        self.stats_label.pack(padx=5, pady=5)
        
        # Add Alert Counter Label
        self.alert_label = ctk.CTkLabel(
            stats_frame,
            text="Alerts : 0",
            font=ctk.CTkFont(size=14),
            text_color="red"
        )
        self.alert_label.pack(padx=5, pady=5)
        
        # Log Frame
        log_frame = ctk.CTkFrame(self.main_container)
        log_frame.pack(padx=10, pady=10, fill="both", expand=True)
        
        log_title = ctk.CTkLabel(
            log_frame,
            text="Packet Log",
            font=ctk.CTkFont(size=16, weight="bold")
        )
        log_title.pack(padx=5, pady=5)
        
        # Custom styling for the log area
        self.log_area = scrolledtext.ScrolledText(
            log_frame,
            wrap="word",
            font=("Consolas", 11),
            bg="#2b2b2b",
            fg="#ffffff",
            insertbackground="#ffffff"
        )
        self.log_area.pack(padx=10, pady=10, fill="both", expand=True)

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
        return common_ports.get(dport, 'private')

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
            # Unusual combinations
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
                
                # SYN flood detection
                if flags & 0x02 and not flags & 0x10:
                    stats['serror_count'] += 1
                    if len(recent_connections) > 3:
                        stats['serror_count'] += 2
                
                # Port scan detection
                dst_ip = packet[IP].dst
                recent_ports = set(p[TCP].dport for p in recent_connections if TCP in p)
                if len(recent_ports) > 2:
                    stats['rerror_count'] += len(recent_ports)
                
                # Unusual flags
                if flags & 0x29 or flags == 0:
                    stats['serror_count'] += 2
                
                # RST flags
                if flags & 0x04:
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
            'serror_rate': conn_stats.get('serror_rate', 0),
            'srv_serror_rate': conn_stats.get('srv_serror_rate', 0),
            'rerror_rate': conn_stats.get('rerror_rate', 0),
            'srv_rerror_rate': conn_stats.get('srv_rerror_rate', 0),
            'same_srv_rate': conn_stats.get('same_srv_rate', 0),
            'diff_srv_rate': conn_stats.get('diff_srv_rate', 0),
            'dst_host_count': sum(1 for k in self.connections.keys() if k[1] == packet[IP].dst),
            'dst_host_srv_count': sum(1 for k in self.connections.keys() 
                                    if k[1] == packet[IP].dst and 
                                    k[2] == (packet[TCP].dport if TCP in packet else 
                                            packet[UDP].dport if UDP in packet else 0))
        }
        
        # Convert to DataFrame and handle categorical variables
        df = pd.DataFrame([features])
        categorical_features = ['protocol_type', 'service', 'flag']
        df = pd.get_dummies(df, columns=categorical_features)
        
        # Ensure all feature columns exist
        for col in self.feature_names:
            if col not in df.columns:
                df[col] = 0
        
        # Reorder columns to match training data
        df = df[self.feature_names]
        
        # Scale features
        scaled_features = pd.DataFrame(
            self.scaler.transform(df),
            columns=self.feature_names
        )
        
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
            
            # Get TCP flags
            if TCP in packet:
                flags = ""
                if packet[TCP].flags & 0x01:  # FIN
                    flags += "F"
                if packet[TCP].flags & 0x02:  # SYN
                    flags += "S"
                if packet[TCP].flags & 0x04:  # RST
                    flags += "R"
                if packet[TCP].flags & 0x08:  # PSH
                    flags += "P"
                if packet[TCP].flags & 0x10:  # ACK
                    flags += "A"
                if packet[TCP].flags & 0x20:  # URG
                    flags += "U"
                if not flags:
                    flags = "0"
            else:
                flags = "N/A"
            
            attack_prob = prediction_proba[1]
            result = "ATTACK" if attack_prob > 0.7 else "NORMAL"
            
            # Format log message
            log_message = f"[{timestamp}] {protocol} {src_ip} → {dst_ip} Flags: {flags} : {result} (Attack prob: {attack_prob:.3f})\n"
            
            # Color-code based on probability and update alert count
            if attack_prob > 0.7:
                self.log_area.tag_config(f"color_{self.packet_count}", foreground="#ff6b6b")  # Red for high probability attack
                self.alert_count += 1  # Increment alert counter
                self.alert_label.configure(text=f"Alerts (Prob > 0.7): {self.alert_count}")  # Update alert label
                
                # Add to centralized alerts and logs system
                alert_data = {
                    "time": timestamp,
                    "source": "Anomaly",  # Mark this as an anomaly alert
                    "priority": "High" if attack_prob > 0.85 else "Medium",
                    "process_name": f"{protocol} Traffic",
                    "details": f"Potential attack from {src_ip} to {dst_ip} (Probability: {attack_prob:.3f}) - Flags: {flags}"
                }
                
                # Make sure the alerts list exists
                if not hasattr(self.master, 'resource_monitor'):
                    print("Warning: resource_monitor not found in master")
                    self.master.resource_monitor = ResourceMonitor()
                    
                if not hasattr(self.master.resource_monitor, 'alerts'):
                    self.master.resource_monitor.alerts = []
                    
                self.master.resource_monitor.alerts.append(alert_data)
                
                # Also add to logs
                log_data = {
                    "timestamp": timestamp,
                    "source": "Anomaly",
                    "event": f"Network anomaly detected: {src_ip} → {dst_ip}",
                    "severity": "High" if attack_prob > 0.85 else "Medium",
                    "status": "Alert",
                    "action": "Logged",
                    "user": "System"
                }
                
                if not hasattr(self.master.resource_monitor, 'logs'):
                    self.master.resource_monitor.logs = []
                    
                self.master.resource_monitor.logs.append(log_data)
                
                # Save to disk
                try:
                    self.master.resource_monitor.save_alerts_and_logs()
                except Exception as e:
                    print(f"Error saving alerts and logs: {e}")
                    
                # Also save to anomaly_detection log (only save attacks)
                try:
                    self.save_to_anomaly_log(timestamp, protocol, src_ip, dst_ip, flags, attack_prob)
                except Exception as e:
                    print(f"Error saving to anomaly log: {e}")
                
                # Notify any open alerts or logs window to refresh
                self.trigger_alerts_refresh()
                
                # Add message to log area
                self.log_area.insert(END, log_message, f"color_{self.packet_count}")
                self.log_area.see(END)
            else:
                self.log_area.tag_config(f"color_{self.packet_count}", foreground="#69db7c")  # Green for normal/low probability
                # Add message to log area for normal packets but don't save to file
                self.log_area.insert(END, log_message, f"color_{self.packet_count}")
                self.log_area.see(END)
            
            self.packet_count += 1
            self.stats_label.configure(text=f"Packets Captured: {self.packet_count}")

    def packet_callback(self, packet):
        if not self.is_capturing:
            return
        self.after(0, self.analyze_packet, packet)

    def start_capture(self):
        self.is_capturing = True
        self.start_button.configure(state="disabled")
        self.stop_button.configure(state="normal")
        
        # Start packet capture in a separate thread
        self.capture_thread = threading.Thread(target=self.capture_packets)
        self.capture_thread.daemon = True
        self.capture_thread.start()

    def capture_packets(self):
        sniff(prn=self.packet_callback, store=0)

    def stop_capture(self):
        self.is_capturing = False
        self.start_button.configure(state="normal")
        self.stop_button.configure(state="disabled")
        
        # Reset counters when stopping capture
        self.packet_count = 0
        self.alert_count = 0
        self.stats_label.configure(text=f"Packets Captured: {self.packet_count}")
        self.alert_label.configure(text=f"Alerts (Prob > 0.7): {self.alert_count}") 

    def save_logs(self):
        """Save the current logs to a file with date-based naming"""
        try:
            # Create logs directory if it doesn't exist
            logs_dir = os.path.join(os.path.dirname(__file__), '..', 'logs')
            os.makedirs(logs_dir, exist_ok=True)
            
            # Generate filename with current date
            current_date = datetime.now().strftime("%Y-%m-%d")
            filename = f"anomaly_detection_{current_date}.log"
            filepath = os.path.join(logs_dir, filename)
            
            # Get all text from the log area
            log_content = self.log_area.get("1.0", END)
            
            # Add header with timestamp
            header = f"=== Anomaly Detection Log - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ===\n"
            header += f"Total Packets: {self.packet_count}\n"
            header += f"Total Alerts: {self.alert_count}\n"
            header += "=" * 50 + "\n\n"
            
            # Write to file
            with open(filepath, 'a', encoding='utf-8') as f:
                f.write(header)
                f.write(log_content)
            
            # Show success message in the log area
            success_msg = f"\n[System] Logs saved successfully to {filename}\n"
            self.log_area.insert(END, success_msg)
            self.log_area.see(END)
            
        except Exception as e:
            error_msg = f"\n[System] Error saving logs: {str(e)}\n"
            self.log_area.insert(END, error_msg)
            self.log_area.see(END)

    def save_to_anomaly_log(self, timestamp, protocol, src_ip, dst_ip, flags, attack_prob):
        """Save anomaly detection to a separate log file"""
        import os
        from datetime import datetime
        
        # Create logs directory if it doesn't exist
        logs_dir = os.path.join(os.path.dirname(__file__), '..', 'logs')
        os.makedirs(logs_dir, exist_ok=True)
        
        # Generate filename with current date
        current_date = datetime.now().strftime("%Y-%m-%d")
        filename = f"anomaly_detection_{current_date}.log"
        filepath = os.path.join(logs_dir, filename)
        
        # Format the log entry
        log_entry = f"[{timestamp}] {protocol} {src_ip} → {dst_ip} Flags: {flags} : ATTACK (Attack prob: {attack_prob:.3f})\n"
        
        # Write to file
        with open(filepath, 'a', encoding='utf-8') as f:
            f.write(log_entry) 

    def trigger_alerts_refresh(self):
        """Trigger refresh in any open alerts or logs window"""
        try:
            from windows.alerts_window import AlertsWindow
            from windows.logs_window import LogsWindow
            
            # Check if the current window in main app is alerts or logs
            if hasattr(self.master, 'current_window'):
                if isinstance(self.master.current_window, AlertsWindow):
                    self.master.current_window.refresh_alerts()
                elif isinstance(self.master.current_window, LogsWindow):
                    self.master.current_window.refresh_logs()
        except Exception as e:
            print(f"Error triggering alerts refresh: {e}") 