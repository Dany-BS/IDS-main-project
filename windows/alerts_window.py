import customtkinter as ctk
from datetime import datetime, timedelta
from tkcalendar import DateEntry
import tkinter as tk

class AlertsWindow(ctk.CTkFrame):
    def __init__(self, master):
        super().__init__(master)
        self.master = master
        # Use the shared resource monitor from the main app
        self.resource_monitor = self.master.resource_monitor
        
        # Initialize filters
        self.source_filter = "All"
        self.start_date = (datetime.now() - timedelta(days=30)).strftime("%Y-%m-%d")
        self.end_date = datetime.now().strftime("%Y-%m-%d")
        
        # For tracking when alerts were last refreshed
        self.last_alert_count = 0
        self.last_refresh_time = datetime.now()
        
        self.setup_ui()
        # Start automatic refresh timer
        self.start_auto_refresh()

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

        # Clock section
        clock_container = ctk.CTkFrame(sidebar, fg_color=("gray90", "gray20"), corner_radius=10, height=80)
        clock_container.pack(fill="x", padx=15, pady=15)
        clock_container.pack_propagate(False)

        self.time_label = ctk.CTkLabel(
            clock_container,
            text=datetime.now().strftime("%I:%M:%S %p\n%B %d, %Y"),
            font=("Roboto", 18, "bold"),
            text_color=("#3a7ebf", "#1f538d")
        )
        self.time_label.pack(expand=True)
        self.update_time()

        # Navigation section title
        nav_title = ctk.CTkFrame(sidebar, fg_color="transparent", height=40)
        nav_title.pack(fill="x", padx=15, pady=(20, 10))
        
        ctk.CTkLabel(
            nav_title,
            text="NAVIGATION",
            font=("Helvetica", 12),
            text_color="gray60"
        ).pack(side="left")

        # Navigation buttons - Note Alerts is active
        buttons = [
            ("🏠 Dashboard", self.master.show_home_window, False),
            ("🖥️ System", self.master.show_system_window, False),
            ("🚨 Alerts", self.master.show_alerts_window, True),  # Active
            ("📝 Logs", self.master.show_logs_window, False),
            ("📂 File Management", self.master.show_file_management_window, False),
            ("💾 External Device", self.master.show_external_device_window, False),
            ("🔍 Anomaly Detection", self.master.show_anomaly_detection_window, False),
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

        # Main content area
        content_area = ctk.CTkFrame(main_container)
        content_area.pack(side="right", fill="both", expand=True, padx=10, pady=10)

        # Title and refresh button
        header_frame = ctk.CTkFrame(content_area, fg_color="transparent")
        header_frame.pack(fill="x", pady=(0, 10))

        ctk.CTkLabel(
            header_frame,
            text="System Alerts",
            font=("Helvetica", 24, "bold")
        ).pack(side="left")

        # Add buttons container for multiple buttons
        buttons_frame = ctk.CTkFrame(header_frame, fg_color="transparent")
        buttons_frame.pack(side="right")
        
        # Add external logs refresh button
        ext_refresh_btn = ctk.CTkButton(
            buttons_frame,
            text="Import External Logs",
            command=self.master.refresh_external_logs,
            width=150
        )
        ext_refresh_btn.pack(side="left", padx=(0, 10))

        # Regular refresh button
        refresh_btn = ctk.CTkButton(
            buttons_frame,
            text="Refresh",
            command=self.refresh_alerts,
            width=100
        )
        refresh_btn.pack(side="left")
        
        # Add filter section
        filter_frame = ctk.CTkFrame(content_area)
        filter_frame.pack(fill="x", pady=10)
        
        # Source filter
        source_label = ctk.CTkLabel(
            filter_frame,
            text="Source:",
            font=("Helvetica", 12, "bold")
        )
        source_label.pack(side="left", padx=(10, 5))
        
        # Source dropdown
        self.source_var = ctk.StringVar(value="All")
        source_options = ["All", "System", "Signature", "Anomaly"]
        source_dropdown = ctk.CTkOptionMenu(
            filter_frame,
            values=source_options,
            variable=self.source_var,
            command=self.on_source_change,
            width=120
        )
        source_dropdown.pack(side="left", padx=5)
        
        # Date filters
        date_label = ctk.CTkLabel(
            filter_frame,
            text="Date Range:",
            font=("Helvetica", 12, "bold")
        )
        date_label.pack(side="left", padx=(20, 5))
        
        # Start date
        start_date_frame = ctk.CTkFrame(filter_frame)
        start_date_frame.pack(side="left", padx=5)
        
        self.start_date_entry = DateEntry(
            start_date_frame,
            width=10,
            background='darkblue',
            foreground='white',
            borderwidth=2,
            date_pattern='yyyy-mm-dd',
            selectbackground='darkblue'
        )
        self.start_date_entry.pack(padx=5, pady=5)
        self.start_date_entry.set_date(datetime.now() - timedelta(days=30))
        
        # End date
        end_date_frame = ctk.CTkFrame(filter_frame)
        end_date_frame.pack(side="left", padx=5)
        
        self.end_date_entry = DateEntry(
            end_date_frame,
            width=10,
            background='darkblue',
            foreground='white',
            borderwidth=2,
            date_pattern='yyyy-mm-dd',
            selectbackground='darkblue'
        )
        self.end_date_entry.pack(padx=5, pady=5)
        self.end_date_entry.set_date(datetime.now())
        
        # Apply filters button
        apply_btn = ctk.CTkButton(
            filter_frame,
            text="Apply Filters",
            command=self.apply_filters,
            width=100
        )
        apply_btn.pack(side="right", padx=10)

        # Create scrollable frame for alerts
        self.alerts_scroll_frame = ctk.CTkScrollableFrame(content_area)
        self.alerts_scroll_frame.pack(fill="both", expand=True, padx=5, pady=5)

        # Create alerts table inside scrollable frame
        self.setup_alerts_table(self.alerts_scroll_frame)
        
    def on_source_change(self, value):
        self.source_filter = value
    
    def apply_filters(self):
        """Apply the selected filters to the alerts view"""
        self.start_date = self.start_date_entry.get_date().strftime("%Y-%m-%d")
        self.end_date = self.end_date_entry.get_date().strftime("%Y-%m-%d")
        self.refresh_alerts()

    def setup_alerts_table(self, parent):
        if hasattr(self, 'table_frame'):
            self.table_frame.destroy()

        # Create table container
        self.table_frame = ctk.CTkFrame(parent)
        self.table_frame.pack(fill="both", expand=True)

        # Configure grid weights
        self.table_frame.grid_columnconfigure(0, weight=1)  # Time
        self.table_frame.grid_columnconfigure(1, weight=1)  # Source
        self.table_frame.grid_columnconfigure(2, weight=1)  # Priority
        self.table_frame.grid_columnconfigure(3, weight=2)  # Process
        self.table_frame.grid_columnconfigure(4, weight=3)  # Details

        # Headers
        headers = ["Time", "Source", "Priority", "Process", "Details"]
        header_bg = "gray25"
        
        for col, header in enumerate(headers):
            header_label = ctk.CTkLabel(
                self.table_frame,
                text=header,
                font=("Helvetica", 12, "bold"),
                fg_color=header_bg,
                corner_radius=6
            )
            header_label.grid(row=0, column=col, sticky="nsew", padx=2, pady=2)

        # Filter alerts based on criteria
        filtered_alerts = self.get_filtered_alerts()
        
        if not filtered_alerts:
            no_alerts_label = ctk.CTkLabel(
                self.table_frame,
                text="No alerts found",
                font=("Helvetica", 12)
            )
            no_alerts_label.grid(row=1, column=0, columnspan=5, pady=20)
            return

        # Add alerts
        for row, alert in enumerate(filtered_alerts, start=1):
            row_bg = "gray17" if row % 2 == 0 else "gray20"
            
            # Time
            time_label = ctk.CTkLabel(
                self.table_frame,
                text=alert["time"],
                font=("Helvetica", 12),
                fg_color=row_bg,
                corner_radius=6
            )
            time_label.grid(row=row, column=0, sticky="nsew", padx=2, pady=2)
            
            # Source
            source_label = ctk.CTkLabel(
                self.table_frame,
                text=alert.get("source", "System"),
                font=("Helvetica", 12),
                fg_color=row_bg,
                corner_radius=6
            )
            source_label.grid(row=row, column=1, sticky="nsew", padx=2, pady=2)

            # Priority
            priority_color = "#FF4444" if alert["priority"] == "High" else "#FFA500"
            priority_label = ctk.CTkLabel(
                self.table_frame,
                text=alert["priority"],
                text_color=priority_color,
                font=("Helvetica", 12),
                fg_color=row_bg,
                corner_radius=6
            )
            priority_label.grid(row=row, column=2, sticky="nsew", padx=2, pady=2)

            # Process
            process_label = ctk.CTkLabel(
                self.table_frame,
                text=alert["process_name"],
                font=("Helvetica", 12),
                fg_color=row_bg,
                corner_radius=6
            )
            process_label.grid(row=row, column=3, sticky="nsew", padx=2, pady=2)

            # Details
            details_frame = ctk.CTkFrame(self.table_frame, fg_color=row_bg)
            details_frame.grid(row=row, column=4, sticky="nsew", padx=2, pady=2)
            details_frame.grid_columnconfigure(0, weight=1)

            details_text = alert["details"].replace('\n', ' | ')
            details_label = ctk.CTkLabel(
                details_frame,
                text=details_text,
                font=("Helvetica", 12),
                wraplength=400,  # Adjust based on your needs
                justify="left"
            )
            details_label.grid(row=0, column=0, sticky="w", padx=5, pady=5)
    
    def get_filtered_alerts(self):
        """Filter alerts based on source and date range"""
        filtered_alerts = []
        
        start_date = datetime.strptime(self.start_date, "%Y-%m-%d")
        end_date = datetime.strptime(self.end_date, "%Y-%m-%d") + timedelta(days=1)  # Include end date
        
        for alert in self.resource_monitor.alerts:
            # Parse the alert time
            try:
                # Try full date-time format first
                if "time" in alert:
                    time_str = alert["time"]
                    # Check if time already includes date
                    if " " in time_str:  # Has space, likely full datetime
                        alert_time = datetime.strptime(time_str, "%Y-%m-%d %H:%M:%S")
                    else:  # Time only, assume current date
                        today = datetime.now().strftime("%Y-%m-%d")
                        alert_time = datetime.strptime(f"{today} {time_str}", "%Y-%m-%d %H:%M:%S")
                else:
                    # Skip alerts without time
                    continue
            except ValueError:
                print(f"Warning: Could not parse time format in alert: {alert.get('time', 'No time')}")
                # Assume current time if we can't parse it
                alert_time = datetime.now()
            
            # Check if date is in range
            if not (start_date <= alert_time <= end_date):
                continue
            
            # Check source filter
            alert_source = alert.get("source", "System")
            if self.source_filter != "All" and alert_source != self.source_filter:
                continue
            
            # For Anomaly alerts, simplify the details to focus on attack probability
            if alert_source == "Anomaly":
                details = alert.get("details", "")
                # Extract probability if it exists
                if "Probability:" in details:
                    prob_start = details.find("Probability:")
                    prob_end = details.find(")", prob_start) if ")" in details[prob_start:] else len(details)
                    probability = details[prob_start:prob_end+1]
                    # Create simplified details without IP addresses
                    simplified_details = f"Network anomaly detected ({probability})"
                    # Create a copy of the alert with simplified details
                    alert_copy = alert.copy()
                    alert_copy["details"] = simplified_details
                    filtered_alerts.append(alert_copy)
                else:
                    filtered_alerts.append(alert)
            else:
                filtered_alerts.append(alert)
        
        # Sort alerts by time, most recent first
        try:
            filtered_alerts.sort(key=lambda x: datetime.strptime(x["time"], "%Y-%m-%d %H:%M:%S") if " " in x["time"] else datetime.now(), reverse=True)
        except (ValueError, KeyError) as e:
            print(f"Warning: Could not sort alerts by time: {e}")
            
        return filtered_alerts

    def refresh_alerts(self):
        """Refresh the alerts table display"""
        self.setup_alerts_table(self.alerts_scroll_frame)

    def on_close(self):
        # Cleanup code here
        pass

    def update_time(self):
        current_time = datetime.now().strftime("%I:%M:%S %p\n%B %d, %Y")
        self.time_label.configure(text=current_time)
        self.after(1000, self.update_time)

    def start_auto_refresh(self):
        """Start automatic refresh timer to check for new alerts"""
        self.check_for_new_alerts()
        # Schedule next check in 2 seconds
        self.after(2000, self.start_auto_refresh)
        
    def check_for_new_alerts(self):
        """Check if there are new alerts and refresh the display if needed"""
        current_count = len(self.resource_monitor.alerts)
        current_time = datetime.now()
        
        # Check if alerts count has changed or if it's been more than 10 seconds since last refresh
        time_diff = (current_time - self.last_refresh_time).total_seconds()
        if current_count != self.last_alert_count or time_diff > 10:
            self.refresh_alerts()
            self.last_alert_count = current_count
            self.last_refresh_time = current_time 