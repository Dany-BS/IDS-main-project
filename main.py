import os
import sys
from datetime import datetime
import tkinter as tk
from tkinter import messagebox

# Get the absolute path of the project root directory
project_root = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, project_root)

import customtkinter as ctk
from windows.home_window import HomeWindow
from windows.login_window import LoginWindow
from windows.system_window import SystemWindow
from windows.alerts_window import AlertsWindow
from windows.logs_window import LogsWindow
from windows.admin_window import AdminWindow
from windows.signature_window import SignatureWindow
from windows.file_management_window import FileManagementWindow
from windows.external_device_window import ExternalDeviceWindow
from windows.anomaly_detection_window import AnomalyDetectionWindow
from utils.resource_monitor import ResourceMonitor

class MainApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        # Window setup
        self.title("Intrusion Detection System")
        self.geometry("1024x720")
        
        # Global appearance settings
        ctk.set_appearance_mode("Dark")
        ctk.set_default_color_theme("dark-blue")
        
        # Set project root for resource paths
        self.project_root = project_root
        self.data_dir = os.path.join(self.project_root, 'data')
        self.utils_dir = os.path.join(self.project_root, 'utils')
        self.windows_dir = os.path.join(self.project_root, 'windows')
        
        # Create data directory if it doesn't exist
        os.makedirs(self.data_dir, exist_ok=True)
        
        # Initialize resource monitor at startup
        self.resource_monitor = ResourceMonitor()
        self._monitoring_job = None  # Track monitoring job
        
        # Add page history
        self.page_history = []
        self.current_page = None

        # Show login window first
        self.current_window = None
        self.show_login_window()

    def start_monitoring(self):
        """Start monitoring system resources"""
        if not self._monitoring_job:  # Only start if not already running
            self.check_resources()

    def stop_monitoring(self):
        """Stop the monitoring process"""
        if self._monitoring_job:
            self.after_cancel(self._monitoring_job)
            self._monitoring_job = None

    def check_resources(self):
        """Check for new alerts periodically"""
        alerts = self.resource_monitor.check_resources()
        if alerts and self.current_window:
            # If we're on the alerts window, refresh it
            if isinstance(self.current_window, AlertsWindow):
                self.current_window.refresh_alerts()
        
        # Schedule next check and store the job id
        self._monitoring_job = self.after(2000, self.check_resources)

    def navigate_to(self, window_class):
        """Navigate to a new page and store history"""
        if self.current_window:
            self.page_history.append(type(self.current_window))
        self.clear_current_window()
        
        # Make sure resource_monitor exists
        if not hasattr(self, 'resource_monitor') or not self.resource_monitor:
            self.resource_monitor = ResourceMonitor()
            
        # Create new window and ensure it has the resource_monitor
        self.current_window = window_class(self)
        
        # Explicitly set resource_monitor on the window instance
        setattr(self.current_window, 'resource_monitor', self.resource_monitor)
        
        self.current_window.pack(fill="both", expand=True)

    def go_back(self):
        """Navigate to previous page"""
        if self.page_history:
            previous_window = self.page_history.pop()
            self.clear_current_window()
            
            # Make sure resource_monitor exists
            if not hasattr(self, 'resource_monitor') or not self.resource_monitor:
                self.resource_monitor = ResourceMonitor()
                
            # Create the previous window and ensure it has the resource_monitor
            self.current_window = previous_window(self)
            
            # Explicitly set resource_monitor on the window instance
            setattr(self.current_window, 'resource_monitor', self.resource_monitor)
            
            self.current_window.pack(fill="both", expand=True)

    def show_login_window(self):
        """Show login window and stop monitoring"""
        self.stop_monitoring()  # Stop monitoring when showing login
        if self.current_window:
            self.current_window.destroy()
            
        # Make sure resource_monitor exists
        if not hasattr(self, 'resource_monitor') or not self.resource_monitor:
            self.resource_monitor = ResourceMonitor()
            
        self.current_window = LoginWindow(self)
        
        # Explicitly set resource_monitor on the window instance
        setattr(self.current_window, 'resource_monitor', self.resource_monitor)
        
        self.current_window.pack(expand=True, fill="both")

    def show_system_window(self):
        self.navigate_to(SystemWindow)

    def show_alerts_window(self):
        self.navigate_to(AlertsWindow)

    def show_logs_window(self):
        self.navigate_to(LogsWindow)

    def show_admin_window(self):
        self.navigate_to(AdminWindow)

    def show_home_window(self):
        """Show home window and start monitoring"""
        if self.current_window:
            self.current_window.destroy()
        
        # Make sure resource_monitor exists
        if not hasattr(self, 'resource_monitor') or not self.resource_monitor:
            self.resource_monitor = ResourceMonitor()
            
        self.current_window = HomeWindow(self)
        
        # Explicitly set resource_monitor on the window instance
        setattr(self.current_window, 'resource_monitor', self.resource_monitor)
        
        self.current_window.pack(expand=True, fill="both")
        self.start_monitoring()  # Start monitoring after successful login

    def show_signature_window(self):
        self.navigate_to(SignatureWindow)

    def show_file_management_window(self):
        """Show file management window"""
        self.navigate_to(FileManagementWindow)

    def show_external_device_window(self):
        """Show external device window"""
        self.navigate_to(ExternalDeviceWindow)

    def show_anomaly_detection_window(self):
        """Show anomaly detection window"""
        self.navigate_to(AnomalyDetectionWindow)

    def clear_current_window(self):
        if self.current_window:
            self.current_window.destroy()

    def logout(self):
        """Handle logout by stopping monitoring and showing login window"""
        self.stop_monitoring()  # Stop monitoring on logout
        self.show_login_window()

    def on_closing(self):
        """Handle application closing"""
        self.stop_monitoring()  # Ensure monitoring is stopped
        self.quit()

    # Add a debug method to generate test alerts 
    def generate_test_alerts(self):
        """Generate test alerts of different types for debugging"""
        # Make sure resource_monitor exists
        if not hasattr(self, 'resource_monitor') or not self.resource_monitor:
            self.resource_monitor = ResourceMonitor()
        
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # System resource alert
        system_alert = {
            "time": current_time,
            "source": "System",
            "priority": "High",
            "process_name": "test_process.exe",
            "details": "Test system resource alert"
        }
        self.resource_monitor.alerts.append(system_alert)
        
        # Signature alert
        signature_alert = {
            "time": current_time,
            "source": "Signature",
            "priority": "Medium",
            "process_name": "TCP Traffic",
            "details": "Test signature-based alert"
        }
        self.resource_monitor.alerts.append(signature_alert)
        
        # Anomaly alert
        anomaly_alert = {
            "time": current_time,
            "source": "Anomaly",
            "priority": "High",
            "process_name": "UDP Traffic",
            "details": "Test anomaly detection alert"
        }
        self.resource_monitor.alerts.append(anomaly_alert)
        
        # Add corresponding logs
        system_log = {
            "timestamp": current_time,
            "source": "System",
            "event": "Test system resource event",
            "severity": "High",
            "status": "Alert",
            "action": "Logged",
            "user": "System"
        }
        self.resource_monitor.logs.append(system_log)
        
        signature_log = {
            "timestamp": current_time,
            "source": "Signature",
            "event": "Test signature detection event",
            "severity": "Medium",
            "status": "Alert",
            "action": "Logged",
            "user": "System"
        }
        self.resource_monitor.logs.append(signature_log)
        
        anomaly_log = {
            "timestamp": current_time,
            "source": "Anomaly",
            "event": "Test anomaly detection event",
            "severity": "High",
            "status": "Alert",
            "action": "Logged",
            "user": "System"
        }
        self.resource_monitor.logs.append(anomaly_log)
        
        print("Test alerts and logs generated")
        
        # If on alerts or logs window, refresh the display
        if isinstance(self.current_window, AlertsWindow):
            self.current_window.refresh_alerts()
        elif isinstance(self.current_window, LogsWindow):
            self.current_window.refresh_logs()
        
        # Save the alerts and logs to disk
        self.resource_monitor.save_alerts_and_logs()
        
    def refresh_external_logs(self):
        """Refresh alerts and logs from external files"""
        if not hasattr(self, 'resource_monitor') or not self.resource_monitor:
            return
            
        # Import logs from external files
        self.resource_monitor.import_external_logs()
        
        # Refresh the display if on alerts or logs window
        if isinstance(self.current_window, AlertsWindow):
            self.current_window.refresh_alerts()
        elif isinstance(self.current_window, LogsWindow):
            self.current_window.refresh_logs()
            
        print("External logs refreshed")

if __name__ == "__main__":
    try:
        app = MainApp()
        # Store app reference for global access without depending on module name
        import __main__
        __main__.app = app
        app.show_login_window()
        app.mainloop()
    except Exception as e:
        messagebox.showerror("Error", f"Application error: {e}")
        import traceback
        traceback.print_exc()