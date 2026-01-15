import customtkinter as ctk
from datetime import datetime, timedelta
from tkcalendar import DateEntry
import tkinter as tk

class LogsWindow(ctk.CTkFrame):
    def __init__(self, master):
        super().__init__(master)
        self.master = master
        self.resource_monitor = self.master.resource_monitor
        
        # Initialize filters
        self.source_filter = "All"
        self.start_date = (datetime.now() - timedelta(days=30)).strftime("%Y-%m-%d")
        self.end_date = datetime.now().strftime("%Y-%m-%d")
        
        # For tracking when logs were last refreshed
        self.last_log_count = 0
        self.last_refresh_time = datetime.now()
        
        self.setup_ui()
        # Start automatic refresh timer
        self.start_auto_refresh()

    def setup_ui(self):
        # Create main container
        main_container = ctk.CTkFrame(self)
        main_container.pack(fill="both", expand=True)

        # Create sidebar with new style
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

        # Navigation buttons
        buttons = [
            ("🏠 Dashboard", self.master.show_home_window, False),
            ("🖥️ System", self.master.show_system_window, False),
            ("🚨 Alerts", self.master.show_alerts_window, False),
            ("📝 Logs", self.master.show_logs_window, True),  # Active
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
            text="System Logs",
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
            command=self.refresh_logs,
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

        # Create logs table
        self.setup_logs_table(content_area)
        
    def on_source_change(self, value):
        self.source_filter = value
    
    def apply_filters(self):
        """Apply the selected filters to the logs view"""
        self.start_date = self.start_date_entry.get_date().strftime("%Y-%m-%d")
        self.end_date = self.end_date_entry.get_date().strftime("%Y-%m-%d")
        self.refresh_logs()

    def setup_logs_table(self, content_area=None):
        if hasattr(self, 'table_frame'):
            self.table_frame.destroy()

        if content_area is None:
            content_area = self.winfo_children()[0].winfo_children()[-1]  # Get the content area

        self.table_frame = ctk.CTkFrame(content_area)
        self.table_frame.pack(fill="both", expand=True, padx=10, pady=10)

        # Configure grid columns with weights
        self.table_frame.grid_columnconfigure(0, weight=2)  # Time
        self.table_frame.grid_columnconfigure(1, weight=1)  # Source
        self.table_frame.grid_columnconfigure(2, weight=3)  # Event
        self.table_frame.grid_columnconfigure(3, weight=1)  # Severity
        self.table_frame.grid_columnconfigure(4, weight=1)  # Status
        self.table_frame.grid_columnconfigure(5, weight=2)  # Action
        self.table_frame.grid_columnconfigure(6, weight=1)  # User

        # Headers
        headers = ["Time", "Source", "Event", "Severity", "Status", "Action", "User"]
        header_frame = ctk.CTkFrame(self.table_frame, fg_color="gray25")
        header_frame.grid(row=0, column=0, columnspan=7, sticky="ew")

        for col, header in enumerate(headers):
            header_label = ctk.CTkLabel(
                header_frame,
                text=header,
                font=("Helvetica", 12, "bold"),
                padx=10,
                pady=5
            )
            header_label.grid(row=0, column=col, sticky="ew")
            header_frame.grid_columnconfigure(col, weight=1)

        # Create scrollable frame for logs
        logs_container = ctk.CTkScrollableFrame(self.table_frame)
        logs_container.grid(row=1, column=0, columnspan=7, sticky="nsew", pady=(0, 5))
        self.table_frame.grid_rowconfigure(1, weight=1)

        # Configure grid columns in logs container
        for i, w in enumerate([2, 1, 3, 1, 1, 2, 1]):  # Match the weights above
            logs_container.grid_columnconfigure(i, weight=w)

        # Get filtered logs
        filtered_logs = self.get_filtered_logs()
        
        # Logs
        if not filtered_logs:
            no_logs_label = ctk.CTkLabel(
                logs_container,
                text="No logs found",
                font=("Helvetica", 12)
            )
            no_logs_label.grid(row=0, column=0, columnspan=7, pady=20)
            return

        for i, log in enumerate(filtered_logs):
            row_color = "gray17" if i % 2 == 0 else "gray20"
            
            # Time
            ctk.CTkLabel(
                logs_container,
                text=log["timestamp"],
                font=("Helvetica", 12),
                fg_color=row_color,
                corner_radius=5,
                padx=10,
                pady=5
            ).grid(row=i, column=0, sticky="ew", padx=2, pady=1)

            # Source
            ctk.CTkLabel(
                logs_container,
                text=log.get("source", "System"),
                font=("Helvetica", 12),
                fg_color=row_color,
                corner_radius=5,
                padx=10,
                pady=5
            ).grid(row=i, column=1, sticky="ew", padx=2, pady=1)
            
            # Event
            event_label = ctk.CTkLabel(
                logs_container,
                text=log["event"],
                font=("Helvetica", 12),
                fg_color=row_color,
                corner_radius=5,
                padx=10,
                pady=5,
                justify="left",
                wraplength=300  # Prevent long events from expanding the column
            )
            event_label.grid(row=i, column=2, sticky="ew", padx=2, pady=1)

            # Severity
            severity_color = "#FF4444" if log["severity"] == "High" else "#FFA500"
            ctk.CTkLabel(
                logs_container,
                text=log["severity"],
                text_color=severity_color,
                font=("Helvetica", 12),
                fg_color=row_color,
                corner_radius=5,
                padx=10,
                pady=5
            ).grid(row=i, column=3, sticky="ew", padx=2, pady=1)

            # Status
            status_color = {
                "Alert": "#FF4444",
                "Warning": "#FFA500",
                "Info": "#00CC00"
            }.get(log["status"], None)
            
            ctk.CTkLabel(
                logs_container,
                text=log["status"],
                text_color=status_color,
                font=("Helvetica", 12),
                fg_color=row_color,
                corner_radius=5,
                padx=10,
                pady=5
            ).grid(row=i, column=4, sticky="ew", padx=2, pady=1)

            # Action
            ctk.CTkLabel(
                logs_container,
                text=log["action"],
                font=("Helvetica", 12),
                fg_color=row_color,
                corner_radius=5,
                padx=10,
                pady=5
            ).grid(row=i, column=5, sticky="ew", padx=2, pady=1)

            # User
            ctk.CTkLabel(
                logs_container,
                text=log["user"],
                font=("Helvetica", 12),
                fg_color=row_color,
                corner_radius=5,
                padx=10,
                pady=5
            ).grid(row=i, column=6, sticky="ew", padx=2, pady=1)
    
    def get_filtered_logs(self):
        """Filter logs based on source and date range"""
        filtered_logs = []
        
        start_date = datetime.strptime(self.start_date, "%Y-%m-%d")
        end_date = datetime.strptime(self.end_date, "%Y-%m-%d") + timedelta(days=1)  # Include end date
        
        for log in self.resource_monitor.logs:
            # Parse the log timestamp
            try:
                log_time = datetime.strptime(log["timestamp"], "%Y-%m-%d %H:%M:%S")
            except ValueError:
                # Skip logs with invalid timestamp format
                print(f"Warning: Could not parse timestamp in log: {log.get('timestamp', 'No time')}")
                continue
            
            # Check if date is in range
            if not (start_date <= log_time <= end_date):
                continue
            
            # Check source filter
            log_source = log.get("source", "System")
            if self.source_filter != "All" and log_source != self.source_filter:
                continue
            
            # For Anomaly logs, simplify the event description to focus on attack probability
            if log_source == "Anomaly" and "probability" in log.get("event", ""):
                event = log.get("event", "")
                # Create a copy of the log with simplified event
                log_copy = log.copy()
                # Remove any IP addresses from the event
                if "detected" in event:
                    # Keep just the probability part
                    simplified_event = "Network anomaly detected " + event[event.find("("):]
                    log_copy["event"] = simplified_event
                filtered_logs.append(log_copy)
            else:
                filtered_logs.append(log)
        
        # Sort logs by timestamp, most recent first
        try:
            filtered_logs.sort(key=lambda x: datetime.strptime(x["timestamp"], "%Y-%m-%d %H:%M:%S"), reverse=True)
        except (ValueError, KeyError) as e:
            print(f"Warning: Could not sort logs by timestamp: {e}")
            
        return filtered_logs

    def refresh_logs(self):
        self.setup_logs_table()

    def on_close(self):
        # Cleanup code here
        pass

    def update_time(self):
        current_time = datetime.now().strftime("%I:%M:%S %p\n%B %d, %Y")
        self.time_label.configure(text=current_time)
        self.after(1000, self.update_time)

    def start_auto_refresh(self):
        """Start automatic refresh timer to check for new logs"""
        self.check_for_new_logs()
        # Schedule next check in 2 seconds
        self.after(2000, self.start_auto_refresh)
        
    def check_for_new_logs(self):
        """Check if there are new logs and refresh the display if needed"""
        current_count = len(self.resource_monitor.logs)
        current_time = datetime.now()
        
        # Check if logs count has changed or if it's been more than 10 seconds since last refresh
        time_diff = (current_time - self.last_refresh_time).total_seconds()
        if current_count != self.last_log_count or time_diff > 10:
            self.refresh_logs()
            self.last_log_count = current_count
            self.last_refresh_time = current_time 