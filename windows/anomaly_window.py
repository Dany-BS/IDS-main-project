import customtkinter as ctk
from datetime import datetime
from ..utils.scapy_monitor import ScapyMonitor  # Import your scapy monitor class
from tkinter import scrolledtext, END

class AnomalyWindow(ctk.CTkFrame):
    def __init__(self, master):
        super().__init__(master)
        self.master = master
        self.resource_monitor = self.master.resource_monitor
        self.scapy_monitor = ScapyMonitor()  # Initialize your scapy monitor
        self.packet_count = 0
        self.alert_count = 0
        
        # Make sure we have access to the shared resource monitor
        if not hasattr(self.master, 'resource_monitor'):
            print("Warning: resource_monitor not found in master")
            self.master.resource_monitor = {'alerts': [], 'logs': []}
            self.resource_monitor = self.master.resource_monitor
        
        self.setup_ui()
        # Pack the main frame
        self.pack(fill="both", expand=True)
        self.configure(fg_color=("gray95", "gray10"))

    def setup_ui(self):
        # Create main container
        main_container = ctk.CTkFrame(self)
        main_container.pack(fill="both", expand=True)

        # Create sidebar
        sidebar = ctk.CTkFrame(main_container, width=250, fg_color=("#2B2B2B", "#1A1A1A"))
        sidebar.pack(side="left", fill="y", padx=0, pady=0)
        sidebar.pack_propagate(False)

        # App logo and title container
        title_container = ctk.CTkFrame(sidebar, fg_color="transparent", height=120)
        title_container.pack(fill="x", pady=(20, 10))
        title_container.pack_propagate(False)

        # App title with modern styling
        ctk.CTkLabel(
            title_container,
            text="IDS",
            font=("Helvetica", 32, "bold"),
            text_color=("#3a7ebf", "#1f538d")
        ).pack(pady=(20, 0))
        
        ctk.CTkLabel(
            title_container,
            text="Dashboard",
            font=("Helvetica", 16),
            text_color="gray70"
        ).pack()

        # Navigation buttons with Anomaly Detection active
        buttons = [
            ("🏠 Dashboard", self.master.show_home_window, False),
            ("🖥️ System", self.master.show_system_window, False),
            ("🚨 Alerts", self.master.show_alerts_window, False),
            ("📝 Logs", self.master.show_logs_window, False),
            ("📂 File Management", self.master.show_file_management_window, False),
            ("💾 External Device", self.master.show_external_device_window, False),
            ("🔍 Anomaly Detection", self.master.show_anomaly_window, True),
            ("⚙️ Admin", self.master.show_admin_window, False),
            ("📋 Signature", self.master.show_signature_window, False),
        ]

        nav_frame = ctk.CTkFrame(sidebar, fg_color="transparent")
        nav_frame.pack(fill="both", expand=True, padx=10, pady=5)

        for text, command, is_active in buttons:
            btn_frame = ctk.CTkFrame(nav_frame, fg_color="transparent")
            btn_frame.pack(fill="x", pady=2)
            
            btn = ctk.CTkButton(
                btn_frame,
                text=text,
                command=command,
                width=200,
                height=40,
                fg_color=("#3a7ebf", "#1f538d") if is_active else "transparent",
                text_color="white" if is_active else ("gray10", "gray90"),
                hover_color=("#325882", "#14375e"),
                corner_radius=8,
                anchor="w",
                font=("Helvetica", 14)
            )
            btn.pack(fill="x")

        # Bottom section with logout and back buttons
        bottom_frame = ctk.CTkFrame(sidebar, fg_color=("gray90", "gray20"), height=80)
        bottom_frame.pack(fill="x", side="bottom", pady=15, padx=15)
        bottom_frame.pack_propagate(False)

        btn_frame = ctk.CTkFrame(bottom_frame, fg_color="transparent")
        btn_frame.pack(expand=True)

        # Back button
        back_btn = ctk.CTkButton(
            btn_frame,
            text="↩️ Back",
            command=self.master.go_back,
            width=90,
            height=32,
            fg_color=("#3a7ebf", "#1f538d"),
            hover_color=("#325882", "#14375e"),
            corner_radius=8,
            font=("Helvetica", 12)
        )
        back_btn.pack(side="left", padx=5)

        # Logout button
        logout_btn = ctk.CTkButton(
            btn_frame,
            text="🚪 Logout",
            command=self.master.show_login_window,
            width=90,
            height=32,
            fg_color="#D35B58",
            hover_color="#C04A47",
            corner_radius=8,
            font=("Helvetica", 12)
        )
        logout_btn.pack(side="left", padx=5)

        # Content Area (right side)
        content_area = ctk.CTkFrame(main_container)
        content_area.pack(side="right", fill="both", expand=True, padx=20, pady=20)

        # Title and Controls Section
        header_frame = ctk.CTkFrame(content_area, fg_color="transparent")
        header_frame.pack(fill="x", pady=(0, 20))

        ctk.CTkLabel(
            header_frame,
            text="Network Anomaly Detection",
            font=("Helvetica", 24, "bold")
        ).pack(side="left")

        # Control buttons
        controls_frame = ctk.CTkFrame(header_frame, fg_color="transparent")
        controls_frame.pack(side="right")

        self.start_button = ctk.CTkButton(
            controls_frame,
            text="Start Monitoring",
            command=self.start_monitoring,
            width=150,
            height=35,
            fg_color=("#3a7ebf", "#1f538d"),
            hover_color=("#325882", "#14375e")
        )
        self.start_button.pack(side="left", padx=5)

        self.stop_button = ctk.CTkButton(
            controls_frame,
            text="Stop Monitoring",
            command=self.stop_monitoring,
            width=150,
            height=35,
            fg_color="gray30",
            hover_color="gray40",
            state="disabled"
        )
        self.stop_button.pack(side="left", padx=5)

        # Statistics Frame
        stats_frame = ctk.CTkFrame(content_area)
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
            text="Alerts: 0",
            font=ctk.CTkFont(size=14),
            text_color="red"
        )
        self.alert_label.pack(padx=5, pady=5)
        
        # Log Frame
        log_frame = ctk.CTkFrame(content_area)
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

    def start_monitoring(self):
        self.start_button.configure(state="disabled")
        self.stop_button.configure(state="normal")
        self.scapy_monitor.start_capture(self.update_ui)

    def stop_monitoring(self):
        self.stop_button.configure(state="disabled")
        self.start_button.configure(state="normal")
        self.scapy_monitor.stop_capture()

    def update_ui(self, stats, packet_info, alerts):
        # Update packet count
        self.packet_count += 1
        self.stats_label.configure(text=f"Packets Captured: {self.packet_count}")

        # Add new packet to log
        if packet_info:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            log_message = f"[{timestamp}] {packet_info['protocol']} {packet_info['src']} → {packet_info['dst']} ({packet_info['length']} bytes)\n"
            self.log_area.insert(END, log_message)
            self.log_area.see(END)

        # Update alert count and add alerts
        if alerts:
            self.alert_count += len(alerts)
            self.alert_label.configure(text=f"Alerts: {self.alert_count}")
            
            for alert in alerts:
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                alert_message = f"[{timestamp}] ALERT: {alert['message']}\n"
                self.log_area.insert(END, alert_message, "alert")
                self.log_area.tag_config("alert", foreground="red")
                self.log_area.see(END)
                
                # Add to centralized alerts system
                alert_data = {
                    "time": timestamp,
                    "source": "Anomaly",  # Mark this as an anomaly alert
                    "priority": "High",
                    "process_name": f"{alert.get('protocol', 'Network')} Traffic",
                    "details": alert['message']
                }
                
                # Make sure the alerts list exists
                if not hasattr(self.master, 'resource_monitor'):
                    print("Warning: resource_monitor not found in master")
                    from utils.resource_monitor import ResourceMonitor
                    self.master.resource_monitor = ResourceMonitor()
                    
                if not hasattr(self.master.resource_monitor, 'alerts'):
                    self.master.resource_monitor.alerts = []
                    
                self.master.resource_monitor.alerts.append(alert_data)
                
                # Also add to logs
                log_data = {
                    "timestamp": timestamp,
                    "source": "Anomaly",
                    "event": alert['message'],
                    "severity": "High",
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
                
                # Also save to anomaly log file
                try:
                    self.save_to_anomaly_log(timestamp, alert)
                except Exception as e:
                    print(f"Error saving to anomaly log: {e}")
                    
                # Notify any open alerts or logs window to refresh
                self.trigger_alerts_refresh()
                
    def save_to_anomaly_log(self, timestamp, alert):
        """Save anomaly alert to a separate log file"""
        import os
        from datetime import datetime
        
        # Create logs directory if it doesn't exist
        logs_dir = os.path.join(os.path.dirname(__file__), '..', 'logs')
        os.makedirs(logs_dir, exist_ok=True)
        
        # Generate filename with current date
        current_date = datetime.now().strftime("%Y-%m-%d")
        filename = f"anomaly_detection_{current_date}.log"
        filepath = os.path.join(logs_dir, filename)
        
        # Format the log entry with focus on attack type rather than IPs
        protocol = alert.get('protocol', 'UNKNOWN')
        alert_message = alert.get('message', 'Unknown attack')
        
        # Simplified log entry format focusing on attack probability
        log_entry = f"[{timestamp}] {protocol} Traffic : ATTACK (Alert: {alert_message})\n"
        
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

    def on_close(self):
        self.stop_monitoring() 