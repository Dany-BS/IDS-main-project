import customtkinter as ctk
from datetime import datetime
import scapy.all as scapy
import pandas as pd
import threading
import os
import json
from tkinter import messagebox
import re

class SignatureWindow(ctk.CTkFrame):
    def __init__(self, master):
        super().__init__(master)
        self.title = "Signature-Based Intrusion Detection"
        self.master = master
        
        # Make sure we have access to the shared resource monitor
        if not hasattr(self.master, 'resource_monitor'):
            print("Warning: resource_monitor not found in master")
            self.master.resource_monitor = {'alerts': [], 'logs': []}
        
        # Initialize variables
        self.load_signatures()
        self.alerts_log = []
        self.sniffing = False
        
        # Initialize attack detection variables
        self.syn_flood_count = 0
        self.port_scan_tracker = {}  # Format: {'ip': {'ports': set(), 'last_time': timestamp}}
        self.port_scan_window = 5  # Time window in seconds
        
        # Initialize connection trackers
        self.connection_trackers = {}  # Format: {'ip': {'service': count, 'last_time': timestamp}}
        self.icmp_tracker = {}  # Format: {'ip': {'count': int, 'last_time': timestamp}}
        
        # Load Snort rules
        self.snort_rules = self.load_snort_rules()
        
        # Create UI
        self.create_ui()

    def load_signatures(self):
        """Load and process the KDDTrain+ dataset"""
        try:
            # Check if file exists
            if not os.path.exists("KDDTrain+.txt"):
                self.signature_chunks = []
                return

            # Define column names for KDDTrain+ dataset
            cols = ['duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes', 
                   'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'logged_in',
                   'num_compromised', 'root_shell', 'su_attempted', 'num_root', 'num_file_creations',
                   'num_shells', 'num_access_files', 'num_outbound_cmds', 'is_host_login',
                   'is_guest_login', 'count', 'srv_count', 'serror_rate', 'srv_serror_rate',
                   'rerror_rate', 'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate',
                   'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count',
                   'dst_host_same_srv_rate', 'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
                   'dst_host_srv_diff_host_rate', 'dst_host_serror_rate', 'dst_host_srv_serror_rate',
                   'dst_host_rerror_rate', 'dst_host_srv_rerror_rate', 'class']
            
            # Read the entire dataset
            self.full_dataset = pd.read_csv("KDDTrain+.txt", names=cols)
            
            # Split into chunks for memory efficiency
            chunk_size = 10000
            self.signature_chunks = [self.full_dataset[i:i + chunk_size] for i in range(0, len(self.full_dataset), chunk_size)]
            
            # Create attack type mappings
            self.attack_types = self.full_dataset['class'].unique()
            
        except Exception as e:
            self.signature_chunks = []

    def create_ui(self):
        # Navigation frame at the top
        nav_frame = ctk.CTkFrame(self)
        nav_frame.pack(fill="x", padx=20, pady=10)

        # Back button
        self.back_button = ctk.CTkButton(
            nav_frame, 
            text="← Back",
            command=self.master.go_back,
            width=100
        )
        self.back_button.pack(side="left", padx=10)

        # Home button
        self.home_button = ctk.CTkButton(
            nav_frame, 
            text="🏠 Home",
            command=self.master.show_home_window,
            width=100
        )
        self.home_button.pack(side="left", padx=10)

        # Add spacing at the top
        top_spacing = ctk.CTkFrame(self, height=20)
        top_spacing.pack()

        # Header label with larger font and bold
        self.header_label = ctk.CTkLabel(
            self, 
            text="Signature-Based Intrusion Detection System", 
            font=("Arial Bold", 24)
        )
        self.header_label.pack(pady=20)

        # Add a separator line
        separator = ctk.CTkFrame(self, height=2, fg_color="gray50")
        separator.pack(fill="x", padx=20, pady=10)

        # Create a frame for column headers
        header_frame = ctk.CTkFrame(self)
        header_frame.pack(pady=(20, 0), padx=20, fill="x")

        # Column headers with adjusted widths
        header_widths = {
            "Timestamp": 120,
            "Event Type": 100,
            "Protocol": 10,
            "Source IP:Port": 120,
            "Destination IP:Port": 210
        }

        for header, width in header_widths.items():
            ctk.CTkLabel(header_frame, text=header, width=width).pack(side="left", padx=5)

        # Alert log display with increased width
        self.alert_textbox = ctk.CTkTextbox(self, width=900, height=300)
        self.alert_textbox.pack(pady=5, padx=20, fill="x")

        # Create a frame for control buttons
        button_frame = ctk.CTkFrame(self)
        button_frame.pack(pady=10)

        # Control Buttons
        self.start_button = ctk.CTkButton(button_frame, text="Start Detection", command=self.start_detection, width=150)
        self.start_button.pack(side="left", padx=20)

        self.stop_button = ctk.CTkButton(button_frame, text="Stop Detection", command=self.stop_detection, width=150)
        self.stop_button.pack(side="left", padx=20)

        self.save_button = ctk.CTkButton(button_frame, text="Save Log", command=self.save_log, width=150)
        self.save_button.pack(side="left", padx=20)

        # Create a tag for red color in the log area
        self.alert_textbox.tag_config("red_alert", foreground="#ff6b6b")

    def start_detection(self):
        """Start packet capture in a separate thread"""
        if not self.sniffing:
            self.sniffing = True
            self.capture_thread = threading.Thread(target=self.capture_packets)
            self.capture_thread.daemon = True
            self.capture_thread.start()
            self.start_button.configure(state="disabled")
            self.stop_button.configure(state="normal")
            self.alert_textbox.insert("1.0", "Starting packet capture...\n")

    def stop_detection(self):
        """Stop packet capture"""
        self.sniffing = False
        self.start_button.configure(state="normal")
        self.stop_button.configure(state="disabled")
        self.alert_textbox.insert("1.0", "Stopping packet capture...\n")

    def capture_packets(self):
        """Capture packets using scapy"""
        try:
            scapy.sniff(
                prn=self.process_packet,
                store=False,
                filter="ip",
                iface=None,
                stop_filter=lambda x: not self.sniffing
            )
        except Exception as e:
            print(f"Error in packet capture: {e}")
            self.alert_textbox.insert("1.0", f"Error in packet capture: {e}\n")

    def process_packet(self, packet):
        """Process each captured packet and check against signatures"""
        try:
            if not self.sniffing:
                return

            if packet.haslayer(scapy.IP):
                # Extract packet features
                features = self.extract_packet_features(packet)
                
                # Check against signatures (pass the packet for Snort rules)
                is_malicious, attack_type = self.check_signatures(features, packet)
                
                # Log packet info
                timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                src_ip = packet[scapy.IP].src
                dst_ip = packet[scapy.IP].dst
                protocol = features['protocol_type']
                
                # Format ports
                src_port = dst_port = "N/A"
                if packet.haslayer(scapy.TCP):
                    src_port = packet[scapy.TCP].sport
                    dst_port = packet[scapy.TCP].dport
                elif packet.haslayer(scapy.UDP):
                    src_port = packet[scapy.UDP].sport
                    dst_port = packet[scapy.UDP].dport
                
                # Create log entry
                log_entry = {
                    "timestamp": timestamp,
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "protocol": protocol,
                    "src_port": src_port,
                    "dst_port": dst_port,
                    "status": "ALERT" if is_malicious else "NORMAL",
                    "attack_type": attack_type if is_malicious else "none"
                }
                
                # Format display message with attack type if malicious
                if is_malicious:
                    msg = f"{timestamp} [⚠️ ALERT - {attack_type}] {protocol} {src_ip}:{src_port} -> {dst_ip}:{dst_port}\n"
                    self.alerts_log.append(log_entry)
                    
                    # Create an alert to be sent to the centralized system
                    alert = {
                        "timestamp": timestamp,
                        "alert_type": attack_type,
                        "protocol": protocol,
                        "src_ip": src_ip,
                        "src_port": src_port,
                        "dst_ip": dst_ip,
                        "dst_port": dst_port,
                        "message": f"{attack_type} attack detected"
                    }
                    
                    # Save to log file and centralized system
                    self.save_to_log_file(log_entry)
                    self.save_alert(alert)
                    
                    # Add to UI (this is only for this window's display)
                    self.after(10, lambda: self.alert_textbox.insert("1.0", msg, "red_alert"))
                else:
                    msg = f"{timestamp} [NORMAL] {protocol} {src_ip}:{src_port} -> {dst_ip}:{dst_port}\n"
                    self.after(10, lambda: self.alert_textbox.insert("1.0", msg))
                
        except Exception as e:
            print(f"Error processing packet: {e}")

    def extract_packet_features(self, packet):
        """Extract relevant features from packet for signature matching"""
        def get_service(packet):
            if packet.haslayer(scapy.TCP):
                port = packet[scapy.TCP].dport
                common_services = {
                    80: 'http',
                    443: 'https',
                    21: 'ftp_data',
                    22: 'ssh',
                    23: 'telnet',
                    25: 'smtp',
                    53: 'domain_u',
                    110: 'pop_3',
                    143: 'imap4'
                }
                return common_services.get(port, 'private')
            return 'other'

        def get_tcp_flags(packet):
            if packet.haslayer(scapy.TCP):
                flags = packet[scapy.TCP].flags
                if flags & 0x02:  # SYN
                    return 'S0'
                elif flags & 0x10:  # ACK
                    return 'SF'
                elif flags & 0x01:  # FIN
                    return 'RSTO'
                elif flags & 0x04:  # RST
                    return 'RSTR'
            return 'OTH'

        # Get source and destination ports
        src_port = dst_port = 0
        if packet.haslayer(scapy.TCP):
            src_port = packet[scapy.TCP].sport
            dst_port = packet[scapy.TCP].dport
        elif packet.haslayer(scapy.UDP):
            src_port = packet[scapy.UDP].sport
            dst_port = packet[scapy.UDP].dport

        # Check for broadcast/multicast for Smurf attack detection
        dst_ip = packet[scapy.IP].dst
        is_broadcast = (
            dst_ip == "255.255.255.255" or  # Broadcast
            dst_ip.startswith("224.") or    # Multicast
            dst_ip.endswith(".255")         # Subnet broadcast
        )

        features = {
            'protocol_type': 'tcp' if packet.haslayer(scapy.TCP) else 'udp' if packet.haslayer(scapy.UDP) else 'icmp',
            'service': get_service(packet),
            'flag': get_tcp_flags(packet),
            'src_bytes': len(packet) if packet.haslayer(scapy.IP) else 0,
            'dst_bytes': len(packet[scapy.IP].payload) if packet.haslayer(scapy.IP) else 0,
            'land': 1 if packet.haslayer(scapy.IP) and packet[scapy.IP].src == packet[scapy.IP].dst else 0,
            'wrong_fragment': 1 if packet.haslayer(scapy.IP) and packet[scapy.IP].frag != 0 else 0,
            'urgent': 1 if packet.haslayer(scapy.TCP) and packet[scapy.TCP].flags & 0x20 else 0,
            # Add additional features for attack detection
            'src_ip': packet[scapy.IP].src,
            'dst_ip': packet[scapy.IP].dst,
            'src_port': src_port,
            'dst_port': dst_port,
            'is_broadcast': 1 if is_broadcast else 0
        }
        return features

    def check_snort_rules(self, packet, features):
        """Check packet against Snort rules"""
        if not packet:
            return False, 'none'

        for rule in self.snort_rules:
            if not self._match_protocol(rule['protocol'], features['protocol_type']):
                continue

            # Check ports if specified
            if not self._match_ports(rule, features):
                continue

            # Check content if packet has payload
            if packet.haslayer(scapy.Raw):
                payload = str(packet[scapy.Raw].load)
                if 'options' in rule and 'content' in rule['options']:
                    for pattern in rule['options']['content']:
                        # Remove pipe-enclosed hex values for now
                        pattern = re.sub(r'\|[0-9A-Fa-f\s]+\|', '', pattern)
                        if pattern and pattern.encode('utf-8', errors='ignore').decode() in payload:
                            return True, rule['options'].get('msg', 'snort_match')

            # Check for specific backdoor ports
            if (rule['options'].get('classtype') == 'trojan-activity' and 
                features['dst_port'] in [20034, 31337, 1234, 4444, 666, 5401, 5402]):
                return True, rule['options'].get('msg', 'backdoor_activity')

        return False, 'none'

    def _match_protocol(self, rule_proto, packet_proto):
        """Match protocol between rule and packet"""
        if rule_proto == 'ip':
            return True
        return rule_proto == packet_proto

    def _match_ports(self, rule, features):
        """Match ports between rule and packet"""
        if rule['src_port'] == 'any' and rule['dst_port'] == 'any':
            return True

        # Handle port ranges
        def parse_port(port_str):
            if port_str == 'any':
                return None
            if ':' in port_str:
                start, end = map(int, port_str.split(':'))
                return range(start, end + 1)
            return [int(port_str)]

        src_ports = parse_port(rule['src_port'])
        dst_ports = parse_port(rule['dst_port'])

        if src_ports and features['src_port'] not in src_ports:
            return False
        if dst_ports and features['dst_port'] not in dst_ports:
            return False

        return True

    def check_signatures(self, features, packet=None):
        """Check packet features against known signatures"""
        if not self.signature_chunks:
            return False, 'none'
            
        current_time = datetime.now().timestamp()
        src_ip = features['src_ip']

        # Check Snort-style rules first if packet is available
        if packet and packet.haslayer(scapy.Raw):
            is_malicious, attack_type = self.check_snort_rules(packet, features)
            if is_malicious:
                return True, attack_type

        # 1. Neptune Attack (SYN Flood) Detection
        if features['protocol_type'] == 'tcp' and features['flag'] == 'S0':
            self.syn_flood_count += 1
            if self.syn_flood_count > 10:
                self.syn_flood_count = 0
                return True, 'neptune'
        else:
            self.syn_flood_count = max(0, self.syn_flood_count - 1)

        # 2. Land Attack Detection
        if features['protocol_type'] == 'tcp' and features['flag'] == 'S0':
            src_ip = features['src_ip']
            dst_ip = features['dst_ip']
            src_port = features['src_port']
            dst_port = features['dst_port']
            
            # Check if source and destination are same
            is_same_endpoint = (src_ip == dst_ip and src_port == dst_port)
            
            # Check if it's not a legitimate loopback or local communication
            is_valid_ip = all(
                # Exclude common legitimate cases
                not src_ip.startswith(prefix) for prefix in [
                    '0.',        # Unspecified
                    '127.',      # Loopback
                    '169.254.',  # Link-local
                    '224.',      # Multicast
                    '255.',      # Broadcast
                ]
            )
            
            if is_same_endpoint and is_valid_ip:
                return True, 'land'

        # 3. Smurf Attack Detection
        if features['protocol_type'] == 'icmp':
            dst_ip = features['dst_ip']
            is_broadcast = (
                dst_ip == "255.255.255.255" or
                dst_ip.startswith("224.") or
                dst_ip.endswith(".255") or
                features['is_broadcast'] == 1
            )
            large_packet = features['src_bytes'] > 500
            
            if is_broadcast or large_packet:
                return True, 'smurf'

        # 4. Port Scan Detection
        if features['protocol_type'] == 'tcp' and features['flag'] == 'S0':
            if src_ip not in self.port_scan_tracker:
                self.port_scan_tracker[src_ip] = {
                    'ports': set(),
                    'last_time': current_time,
                    'count': 0,
                    'start_time': current_time
                }
            
            tracker = self.port_scan_tracker[src_ip]
            
            # Reset if too much time has passed
            if (current_time - tracker['last_time']) > self.port_scan_window:
                tracker['ports'] = set()
                tracker['count'] = 0
                tracker['start_time'] = current_time
            
            # Only track if scanning different ports
            if features['dst_port'] not in tracker['ports']:
                tracker['ports'].add(features['dst_port'])
                tracker['count'] += 1
            
            tracker['last_time'] = current_time
            
            # Calculate rate of unique port connections
            time_window = current_time - tracker['start_time']
            if time_window > 0:
                scan_rate = len(tracker['ports']) / time_window
                
                # Alert if: more than 8 unique ports in 5 seconds window
                # or more than 15 connection attempts
                if (scan_rate > 1.6 and len(tracker['ports']) >= 8) or tracker['count'] >= 15:
                    self.port_scan_tracker[src_ip] = {
                        'ports': set(),
                        'last_time': current_time,
                        'count': 0,
                        'start_time': current_time
                    }
                    return True, 'portscan'

        # 5. Back Door Detection
        if (features['protocol_type'] == 'tcp' and 
            features['dst_port'] in [20034, 31337, 1234, 4444] and
            features['flag'] == 'S0'):
            return True, 'backdoor'

        # 6. Buffer Overflow Detection
        if features['src_bytes'] > 4096:
            return True, 'buffer_overflow'

        # 7. FTP Write Detection
        if (features['protocol_type'] == 'tcp' and 
            features['service'] == 'ftp_data' and 
            features['dst_port'] == 21):
            return True, 'ftp_write'

        # 8. Guess Password Detection
        if (features['protocol_type'] == 'tcp' and 
            features['service'] in ['ftp_data', 'ssh', 'telnet', 'pop_3', 'imap4'] and
            features['flag'] == 'S0'):
            
            service = features['service']
            if src_ip not in self.connection_trackers:
                self.connection_trackers[src_ip] = {'last_time': current_time, 'services': {}}
            
            tracker = self.connection_trackers[src_ip]
            if (current_time - tracker['last_time']) > 60:  # Reset after 60 seconds
                tracker['services'] = {}
            
            tracker['services'][service] = tracker['services'].get(service, 0) + 1
            tracker['last_time'] = current_time
            
            if tracker['services'].get(service, 0) > 5:
                tracker['services'][service] = 0
                return True, 'guess_passwd'

        # 9. IPSweep Detection
        if features['protocol_type'] == 'icmp':
            if src_ip not in self.icmp_tracker:
                self.icmp_tracker[src_ip] = {
                    'count': 0,
                    'last_time': current_time,
                    'targets': set(),
                    'start_time': current_time
                }
            
            tracker = self.icmp_tracker[src_ip]
            
            # Reset after timeout
            if (current_time - tracker['last_time']) > 5:
                tracker['count'] = 0
                tracker['targets'] = set()
                tracker['start_time'] = current_time
            
            # Only count unique targets
            if features['dst_ip'] not in tracker['targets']:
                tracker['targets'].add(features['dst_ip'])
                tracker['count'] += 1
            
            tracker['last_time'] = current_time
            
            # Calculate ping rate
            time_window = current_time - tracker['start_time']
            if time_window > 0:
                ping_rate = len(tracker['targets']) / time_window
                
                # Alert if: more than 5 unique targets in 5 seconds
                # and rate is higher than 1 target per second
                if len(tracker['targets']) >= 5 and ping_rate > 1:
                    tracker['count'] = 0
                    tracker['targets'] = set()
                    tracker['start_time'] = current_time
                    return True, 'ipsweep'

        # 10. Warezmaster Detection
        if (features['protocol_type'] == 'tcp' and
            features['service'] == 'ftp_data' and
            features['dst_port'] == 21 and
            features['src_bytes'] > 2048):
            return True, 'warezmaster'

        # Clean up old entries
        self._cleanup_trackers(current_time)

        # 11. Check against dataset patterns
        for chunk in self.signature_chunks:
            base_conditions = (
                (chunk['protocol_type'] == features['protocol_type']) &
                (
                    (chunk['service'] == features['service']) |
                    (chunk['service'] == 'private') |
                    (features['service'] == 'private')
                )
            )

            if features['protocol_type'] == 'tcp':
                base_conditions = base_conditions & (
                    (chunk['flag'] == features['flag']) |
                    (chunk['flag'].isin(['S0', 'SF', 'RSTO', 'RSTR']))
                )

            byte_conditions = (
                (abs(chunk['src_bytes'] - features['src_bytes']) < 500) |
                (abs(chunk['dst_bytes'] - features['dst_bytes']) < 500)
            )

            matches = chunk[base_conditions & byte_conditions]
            
            if len(matches) > 0:
                attack_counts = matches['class'].value_counts()
                if len(attack_counts) > 0:
                    most_common_attack = attack_counts.index[0]
                    if most_common_attack != 'normal':
                        return True, most_common_attack.replace('.', '')
        
        return False, 'none'

    def _cleanup_trackers(self, current_time):
        """Clean up old entries from all trackers"""
        # Clean port scan tracker
        self.port_scan_tracker = {
            ip: data for ip, data in self.port_scan_tracker.items()
            if (current_time - data['last_time']) <= self.port_scan_window
        }
        
        # Clean connection tracker
        self.connection_trackers = {
            ip: data for ip, data in self.connection_trackers.items()
            if (current_time - data['last_time']) <= 60
        }
        
        # Clean ICMP tracker
        self.icmp_tracker = {
            ip: data for ip, data in self.icmp_tracker.items()
            if (current_time - data['last_time']) <= 5
        }

    def save_to_log_file(self, log_entry):
        """Save alert to a single log file"""
        try:
            # Create logs directory if it doesn't exist
            logs_dir = "logs"
            os.makedirs(logs_dir, exist_ok=True)

            # Use a single log file with date in name
            current_date = datetime.now().strftime('%Y%m%d')
            log_file = os.path.join(logs_dir, f"signature_alerts_{current_date}.log")
            
            # Format the log message
            log_message = (f"{log_entry['timestamp']} [ALERT - {log_entry['attack_type']}] "
                         f"{log_entry['protocol']} {log_entry['src_ip']}:{log_entry['src_port']} -> "
                         f"{log_entry['dst_ip']}:{log_entry['dst_port']}\n")
            
            # Append to the log file
            with open(log_file, 'a') as f:
                f.write(log_message)
                
        except Exception:
            pass  # Silently handle errors

    def save_alert(self, alert):
        """Save an alert to the log and to the central resource monitor"""
        try:
            # First, save to the local log
            log_entry = {
                "timestamp": alert.get("timestamp", datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
                "message": alert.get("message", "Unknown alert"),
                "alert_type": alert.get("alert_type", "Unknown"),
                "protocol": alert.get("protocol", "Unknown"),
                "src_ip": alert.get("src_ip", "Unknown"),
                "dst_ip": alert.get("dst_ip", "Unknown"),
                "details": alert.get("details", "No details available")
            }
            
            self.save_to_log_file(log_entry)
            
            # Make sure resource_monitor exists in master
            if not hasattr(self.master, 'resource_monitor'):
                print("Warning: resource_monitor not found in master")
                from utils.resource_monitor import ResourceMonitor
                self.master.resource_monitor = ResourceMonitor()
                
            # Then, also add to centralized alerts system
            timestamp = alert.get("timestamp", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
            alert_data = {
                "time": timestamp,
                "source": "Signature",  # Mark this as a signature-based alert
                "priority": "High",
                "process_name": f"{alert.get('protocol', 'Network')} Traffic",
                "details": f"{alert.get('alert_type', 'Attack')} detected: {alert.get('src_ip', 'Unknown')} → {alert.get('dst_ip', 'Unknown')} - {alert.get('message', '')}"
            }
            self.master.resource_monitor.alerts.append(alert_data)
            
            # Also add to logs
            log_data = {
                "timestamp": timestamp,
                "source": "Signature",
                "event": alert.get("message", "Signature match detected"),
                "severity": "High",
                "status": "Alert",
                "action": "Logged",
                "user": "System"
            }
            self.master.resource_monitor.logs.append(log_data)
            
            # Save to disk
            self.master.resource_monitor.save_alerts_and_logs()
            
            # Notify any open alerts or logs window to refresh
            self.trigger_alerts_refresh()
            
            return True
        except Exception as e:
            print(f"Error saving alert: {e}")
            return False

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

    def save_log(self):
        """Save current session alerts to a file (for manual saving)"""
        try:
            if not self.alerts_log:
                messagebox.showinfo("No Alerts", "No alerts to save.")
                return

            # Create logs directory if it doesn't exist
            logs_dir = "logs"
            os.makedirs(logs_dir, exist_ok=True)

            # Generate filename with timestamp for session log
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = os.path.join(logs_dir, f"session_alerts_{timestamp}.txt")
            
            with open(filename, 'w') as f:
                for alert in reversed(self.alerts_log):
                    f.write(f"{alert['timestamp']} [ALERT - {alert['attack_type']}] {alert['protocol']} "
                           f"{alert['src_ip']}:{alert['src_port']} -> {alert['dst_ip']}:{alert['dst_port']}\n")
            
            messagebox.showinfo("Success", f"Session log saved successfully to:\n{filename}")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save log: {str(e)}")

    def load_snort_rules(self):
        """Load Snort rules from the rules file"""
        rules = []
        try:
            with open("snort3-community.rules", "r") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        # Parse rule components
                        rule = self.parse_snort_rule(line)
                        if rule:
                            rules.append(rule)
        except Exception as e:
            pass  # Silently handle errors
        return rules

    def parse_snort_rule(self, rule_text):
        """Parse a Snort rule into components"""
        try:
            # Basic rule components
            parts = rule_text.split(" ( ")
            if len(parts) < 2:
                return None

            header = parts[0].split()
            if len(header) < 7:
                return None

            # Parse header
            action = header[0]  # alert, log, etc.
            protocol = header[1]  # tcp, udp, icmp
            src_net = header[2]
            src_port = header[3]
            direction = header[4]  # ->
            dst_net = header[5]
            dst_port = header[6]

            # Parse options
            options_text = " ( " + parts[1]
            options = {}
            
            # Extract msg
            msg_match = re.search(r'msg:"([^"]+)"', options_text)
            if msg_match:
                options['msg'] = msg_match.group(1)

            # Extract content patterns
            content_patterns = re.findall(r'content:"([^"]+)"', options_text)
            if content_patterns:
                options['content'] = content_patterns

            # Extract flow
            flow_match = re.search(r'flow:([^;]+)', options_text)
            if flow_match:
                options['flow'] = flow_match.group(1).split(',')

            # Extract classtype
            classtype_match = re.search(r'classtype:([^;]+)', options_text)
            if classtype_match:
                options['classtype'] = classtype_match.group(1)

            return {
                'action': action,
                'protocol': protocol,
                'src_net': src_net,
                'src_port': src_port,
                'dst_net': dst_net,
                'dst_port': dst_port,
                'options': options
            }
        except Exception:
            return None 

    def some_method_where_alert_is_logged(self, attack_type, protocol, src_ip, src_port, dst_ip, dst_port):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"{timestamp} [⚠️ ALERT - {attack_type}] {protocol} {src_ip}:{src_port} -> {dst_ip}:{dst_port}\n"
        
        # Insert the log entry with the red_alert tag
        self.alert_textbox.insert(END, log_entry, "red_alert")
        self.alert_textbox.see(END) 