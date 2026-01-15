import psutil
import GPUtil
from datetime import datetime
import json

class ResourceMonitor:
    def __init__(self):
        # Define resource limits (in percentage)
        self.resource_limits = self.load_resource_limits()
        self.process_whitelist = self.load_process_whitelist()
        
        # Initialize alerts and logs
        self.MAX_ENTRIES = 25  # Maximum number of alerts and logs to keep
        self.alerts = []
        self.logs = []
        self.load_alerts_and_logs()
        
        # Add process alert tracking
        self.process_alert_history = {}  # To track when alerts were last generated
        self.ALERT_COOLDOWN = 300  # 5 minutes in seconds
        
        print("\n=== Resource Monitor Initialized ===")
        print(f"Resource Limits: {self.resource_limits}")
        print(f"Whitelisted Processes: {self.process_whitelist}")

    def load_resource_limits(self):
        try:
            with open('resource_limits.txt', 'r') as f:
                limits = {}
                for line in f:
                    resource, limit = line.strip().split(',')
                    limits[resource] = float(limit)
                return limits
        except FileNotFoundError:
            return {'cpu': 50, 'memory': 70}

    def load_process_whitelist(self):
        try:
            whitelist = []
            with open('process_whitelist.txt', 'r') as f:
                for line in f:
                    process = line.strip()
                    if process:
                        whitelist.append(process)
            return whitelist
        except FileNotFoundError:
            default_whitelist = [
                "chrome.exe",
                "code.exe",
                "python.exe",
                "explorer.exe",
                "discord.exe",
                "whatsapp.exe"
            ]
            with open('process_whitelist.txt', 'w') as f:
                for process in default_whitelist:
                    f.write(f"{process}\n")
            return default_whitelist

    def load_alerts_and_logs(self):
        """Load alerts and logs from separate files"""
        # Load alerts
        try:
            with open('alerts.json', 'r') as f:
                data = json.load(f)
                self.alerts = data.get('alerts', [])[:self.MAX_ENTRIES]
                print("Successfully loaded existing alerts")
        except FileNotFoundError:
            print("No existing alerts file found, creating new one")
            self.alerts = []
            self.save_alerts()
        except json.JSONDecodeError:
            print("Error reading alerts file, creating new one")
            self.alerts = []
            self.save_alerts()

        # Load logs
        try:
            with open('logs.json', 'r') as f:
                data = json.load(f)
                self.logs = data.get('logs', [])[:self.MAX_ENTRIES]
                print("Successfully loaded existing logs")
        except FileNotFoundError:
            print("No existing logs file found, creating new one")
            self.logs = []
            self.save_logs()
        except json.JSONDecodeError:
            print("Error reading logs file, creating new one")
            self.logs = []
            self.save_logs()
            
        # Import logs from signature and anomaly detection files
        self.import_external_logs()

    def import_external_logs(self):
        """Import logs from signature and anomaly detection files in the logs directory"""
        try:
            import os
            import glob
            
            # Make sure logs directory exists
            if not os.path.exists('logs'):
                print("No logs directory found")
                return
                
            # Get the most recent signature alert log
            signature_logs = glob.glob('logs/signature_alerts_*.log')
            if signature_logs:
                # Sort by modification time (newest first)
                latest_signature_log = max(signature_logs, key=os.path.getmtime)
                print(f"Importing signature alerts from {latest_signature_log}")
                self.import_signature_log(latest_signature_log)
                
            # Get the most recent anomaly detection log
            anomaly_logs = glob.glob('logs/anomaly_detection_*.log')
            if anomaly_logs:
                latest_anomaly_log = max(anomaly_logs, key=os.path.getmtime)
                print(f"Importing anomaly alerts from {latest_anomaly_log}")
                self.import_anomaly_log(latest_anomaly_log)
                
        except Exception as e:
            print(f"Error importing external logs: {e}")
            
    def import_signature_log(self, log_file):
        """Import signature alerts from log file"""
        try:
            with open(log_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                        
                    # Parse signature alert line
                    # Format: 2025-04-05 22:40:44 [ALERT - backdoor] tcp 192.168.1.35:33871 -> 8.8.8.8:4444
                    try:
                        # Split timestamp and rest of alert
                        parts = line.split('[ALERT - ', 1)
                        if len(parts) < 2:
                            continue
                            
                        timestamp = parts[0].strip()
                        alert_parts = parts[1].split(']', 1)
                        if len(alert_parts) < 2:
                            continue
                            
                        alert_type = alert_parts[0].strip()
                        connection_info = alert_parts[1].strip()
                        
                        # Parse protocol and connection details
                        conn_parts = connection_info.split()
                        if len(conn_parts) < 3:
                            continue
                            
                        protocol = conn_parts[0]
                        src = conn_parts[1].split(':')[0] if ':' in conn_parts[1] else conn_parts[1]
                        dst = conn_parts[3].split(':')[0] if ':' in conn_parts[3] else conn_parts[3]
                        
                        # Create alert
                        alert_data = {
                            "time": timestamp,
                            "source": "Signature",
                            "priority": "High",
                            "process_name": f"{protocol.upper()} Traffic",
                            "details": f"{alert_type} attack detected: {src} → {dst}"
                        }
                        
                        # Check if this alert already exists to avoid duplicates
                        duplicate = False
                        for existing_alert in self.alerts:
                            if (existing_alert.get("time") == timestamp and 
                                existing_alert.get("source") == "Signature" and
                                existing_alert.get("details") == alert_data["details"]):
                                duplicate = True
                                break
                                
                        if not duplicate:
                            # Add alert and log
                            self.alerts.append(alert_data)
                            
                            log_data = {
                                "timestamp": timestamp,
                                "source": "Signature",
                                "event": f"{alert_type} attack detected",
                                "severity": "High",
                                "status": "Alert",
                                "action": "Logged",
                                "user": "System"
                            }
                            self.logs.append(log_data)
                            
                    except Exception as e:
                        print(f"Error parsing signature log line: {e}")
                        continue
                        
        except Exception as e:
            print(f"Error reading signature log file: {e}")
            
    def import_anomaly_log(self, log_file):
        """Import anomaly detection alerts from log file"""
        try:
            with open(log_file, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if not line or "ATTACK" not in line:
                        continue
                        
                    # Parse anomaly alert line
                    # Format: [2025-04-05 23:00:27] TCP 192.168.1.35 → 192.168.1.1 Flags: FSRPU : ATTACK (Attack prob: 0.720)
                    try:
                        # Extract timestamp
                        if line.startswith('['):
                            timestamp_end = line.find(']')
                            if timestamp_end == -1:
                                continue
                                
                            timestamp = line[1:timestamp_end]
                            remaining = line[timestamp_end+1:].strip()
                        else:
                            continue
                            
                        # Extract protocol
                        protocol_end = remaining.find(' ')
                        if protocol_end == -1:
                            continue
                            
                        protocol = remaining[:protocol_end]
                        
                        # Extract attack probability
                        prob_start = line.find('Attack prob:')
                        if prob_start == -1:
                            prob = "Unknown"
                        else:
                            prob_text = line[prob_start:].split(')', 1)[0]
                            prob = prob_text.replace('Attack prob:', '').strip()
                        
                        # Create alert
                        alert_data = {
                            "time": timestamp,
                            "source": "Anomaly",
                            "priority": "High",
                            "process_name": f"{protocol} Traffic",
                            "details": f"Network anomaly detected (Probability: {prob})"
                        }
                        
                        # Check if this alert already exists to avoid duplicates
                        duplicate = False
                        for existing_alert in self.alerts:
                            if (existing_alert.get("time") == timestamp and 
                                existing_alert.get("source") == "Anomaly" and
                                prob in existing_alert.get("details", "")):
                                duplicate = True
                                break
                                
                        if not duplicate:
                            # Add alert and log
                            self.alerts.append(alert_data)
                            
                            log_data = {
                                "timestamp": timestamp,
                                "source": "Anomaly",
                                "event": f"Network anomaly detected (probability: {prob})",
                                "severity": "High",
                                "status": "Alert",
                                "action": "Logged",
                                "user": "System"
                            }
                            self.logs.append(log_data)
                            
                    except Exception as e:
                        print(f"Error parsing anomaly log line '{line}': {e}")
                        continue
                        
        except Exception as e:
            print(f"Error reading anomaly log file: {e}")

    def save_alerts(self):
        """Save alerts to a separate file"""
        try:
            with open('alerts.json', 'w') as f:
                json.dump({'alerts': self.alerts}, f, indent=2)
            print("Successfully saved alerts")
        except Exception as e:
            print(f"Error saving alerts: {e}")

    def save_logs(self):
        """Save logs to a separate file"""
        try:
            with open('logs.json', 'w') as f:
                json.dump({'logs': self.logs}, f, indent=2)
            print("Successfully saved logs")
        except Exception as e:
            print(f"Error saving logs: {e}")

    def save_alerts_and_logs(self):
        """Save both alerts and logs to their respective files"""
        self.save_alerts()
        self.save_logs()

    def get_system_resources(self):
        """Get accurate system resource usage"""
        try:
            # CPU Usage (average across all cores)
            cpu_percent = psutil.cpu_percent(interval=1)
            
            # Memory Usage
            memory = psutil.virtual_memory()
            memory_total = memory.total / (1024 ** 3)  # Convert to GB
            memory_used = (memory.total - memory.available) / (1024 ** 3)
            memory_percent = memory.percent
            
            # Disk Usage
            disk_info = {}
            for partition in psutil.disk_partitions():
                if partition.fstype:
                    usage = psutil.disk_usage(partition.mountpoint)
                    disk_info[partition.device] = {
                        'total': usage.total / (1024 ** 3),  # GB
                        'used': usage.used / (1024 ** 3),    # GB
                        'free': usage.free / (1024 ** 3),    # GB
                        'percent': usage.percent
                    }
            
            # Network Usage
            net_io = psutil.net_io_counters()
            network_info = {
                'bytes_sent': net_io.bytes_sent,
                'bytes_recv': net_io.bytes_recv
            }
            
            return {
                'cpu': {
                    'percent': cpu_percent,
                    'cores': psutil.cpu_count(),
                    'physical_cores': psutil.cpu_count(logical=False)
                },
                'memory': {
                    'total': memory_total,
                    'used': memory_used,
                    'percent': memory_percent,
                    'available': memory.available / (1024 ** 3)
                },
                'disk': disk_info,
                'network': network_info
            }
        except Exception as e:
            print(f"Error getting system resources: {e}")
            return None

    def check_resources(self):
        """Check system resources and processes, return any alerts"""
        alerts = []
        current_time = datetime.now()
        print("\n=== Checking System Resources ===")
        
        # Get system memory info for percentage calculations
        system_memory = psutil.virtual_memory()
        total_memory = system_memory.total
        
        # Track processes exceeding limits
        problematic_processes = []
        
        # Check all running processes
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_info']):
            try:
                # Get process info
                proc_info = proc.info
                proc_name = proc_info['name'].lower()
                
                # Calculate process resource usage
                cpu_percent = proc_info['cpu_percent'] / psutil.cpu_count()
                memory_percent = (proc_info['memory_info'].rss / total_memory) * 100
                
                # Check if process exceeds limits
                if (cpu_percent > self.resource_limits['cpu'] or 
                    memory_percent > self.resource_limits['memory']):
                    
                    # Only add to problematic processes if not in whitelist
                    if proc_name not in [p.lower() for p in self.process_whitelist]:
                        # Check if we should generate an alert for this process
                        should_alert = True
                        if proc_name in self.process_alert_history:
                            last_alert_time = self.process_alert_history[proc_name]
                            time_diff = (current_time - last_alert_time).total_seconds()
                            if time_diff < self.ALERT_COOLDOWN:
                                should_alert = False
                                print(f"\nSkipping alert for {proc_name} - cooldown active "
                                      f"({int(self.ALERT_COOLDOWN - time_diff)} seconds remaining)")
                        
                        if should_alert:
                            print(f"\n!!! Resource Limit Exceeded by {proc_name} !!!")
                            print(f"  CPU: {cpu_percent:.1f}% (Limit: {self.resource_limits['cpu']}%)")
                            print(f"  Memory: {memory_percent:.1f}% (Limit: {self.resource_limits['memory']}%)")
                            
                            problematic_processes.append({
                                'name': proc_name,
                                'pid': proc_info['pid'],
                                'cpu': cpu_percent,
                                'memory': memory_percent
                            })
                            # Update the alert history
                            self.process_alert_history[proc_name] = current_time
                
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess) as e:
                print(f"Error accessing process: {e}")
                continue
        
        # Clean up old entries from process_alert_history
        current_processes = [p.info['name'].lower() for p in psutil.process_iter(['name'])]
        self.process_alert_history = {
            proc: time 
            for proc, time in self.process_alert_history.items() 
            if proc in current_processes
        }
        
        # Generate alerts for problematic processes
        for proc in problematic_processes:
            alert = self.create_process_alert(proc)
            if alert:
                alerts.append(alert)
        
        return alerts

    def create_process_alert(self, process):
        """Create an alert for a problematic process"""
        current_time = datetime.now()
        
        # Check for recent duplicate alerts
        for existing_alert in self.alerts[:5]:  # Check last 5 alerts
            if (existing_alert["process_name"] == process['name'] and
                existing_alert["message"] == f"Process {process['name']} exceeded resource limits"):
                print(f"\n=== Skipping Duplicate Alert for {process['name']} ===")
                return None
        
        # Create detailed message
        details = (
            f"Process Name: {process['name']}\n"
            f"PID: {process['pid']}\n"
            f"CPU Usage: {process['cpu']:.1f}% (Limit: {self.resource_limits['cpu']}%)\n"
            f"Memory Usage: {process['memory']:.1f}% (Limit: {self.resource_limits['memory']}%)"
        )
        
        alert = {
            "priority": "High",
            "message": f"Process {process['name']} exceeded resource limits",
            "details": details,
            "time": current_time.strftime("%Y-%m-%d %H:%M:%S"),  # Use full date-time format
            "process_name": process['name'],
            "source": "System"  # Explicitly set source for system alerts
        }
        
        # Add to alerts list and maintain max size
        self.alerts.insert(0, alert)
        if len(self.alerts) > self.MAX_ENTRIES:
            self.alerts = self.alerts[:self.MAX_ENTRIES]
        # Save alerts immediately
        self.save_alerts()
        
        # Create log entry
        log_entry = {
            "timestamp": current_time.strftime("%Y-%m-%d %H:%M:%S"),
            "source": "System",  # Explicitly set source for system logs
            "event": f"Resource limit exceeded by {process['name']}",
            "severity": "High",
            "status": "Alert",
            "action": "Process Monitoring",
            "user": "system",
            "process": process['name']
        }
        
        # Add to logs list and maintain max size
        self.logs.insert(0, log_entry)
        if len(self.logs) > self.MAX_ENTRIES:
            self.logs = self.logs[:self.MAX_ENTRIES]
        # Save logs immediately
        self.save_logs()
        
        # Notify main app to refresh alerts and logs windows if open
        self.trigger_alerts_refresh()
        
        print(f"\n=== Alert Generated ===")
        print(f"Time: {alert['time']}")
        print(f"Process: {process['name']}")
        print(f"Details:\n{details}")
        
        return alert
        
    def trigger_alerts_refresh(self):
        """Trigger refresh in main app's alerts/logs windows if they're open"""
        try:
            # This may be called from a background thread, so we need to be careful
            import __main__
            if hasattr(__main__, 'app'):
                current_window = __main__.app.current_window
                window_class_name = current_window.__class__.__name__
                if window_class_name == 'AlertsWindow':
                    current_window.refresh_alerts()
                elif window_class_name == 'LogsWindow':
                    current_window.refresh_logs()
        except Exception as e:
            print(f"Error notifying alerts refresh: {e}") 