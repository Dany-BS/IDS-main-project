import customtkinter as ctk
import psutil
from datetime import datetime

class HomeWindow(ctk.CTkFrame):
    def __init__(self, master):
        super().__init__(master)
        self.master = master
        # Use the shared resource monitor from the main app
        self.resource_monitor = self.master.resource_monitor
        
        self.setup_ui()
        self.start_monitoring()

    def setup_ui(self):
        # Create main container
        main_container = ctk.CTkFrame(self)
        main_container.pack(fill="both", expand=True)

        # Create sidebar
        self.setup_sidebar(main_container)

        # Main content area
        content_area = ctk.CTkFrame(main_container)
        content_area.pack(side="right", fill="both", expand=True, padx=10, pady=10)

        # Welcome section
        self.setup_welcome_section(content_area)

        # Stats Overview
        self.setup_stats_overview(content_area)

        # Create grid for dashboard cards
        grid_frame = ctk.CTkFrame(content_area, fg_color="transparent")
        grid_frame.pack(fill="both", expand=True, padx=15, pady=15)
        
        # Configure grid with better spacing
        grid_frame.grid_columnconfigure((0, 1), weight=1, uniform="column")
        grid_frame.grid_rowconfigure((0, 1), weight=1, uniform="row")

        # Dashboard Cards
        self.setup_system_card(grid_frame, 0, 0)
        self.setup_alerts_card(grid_frame, 0, 1)
        self.setup_logs_card(grid_frame, 1, 0)
        self.setup_status_card(grid_frame, 1, 1)

    def setup_sidebar(self, parent):
        sidebar = ctk.CTkFrame(parent, width=250, fg_color=("#2B2B2B", "#1A1A1A"))
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
            text="",
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
            ("🏠 Dashboard", self.master.show_home_window, True),
            ("🖥️ System", self.master.show_system_window, False),
            ("🚨 Alerts", self.master.show_alerts_window, False),
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

    def setup_welcome_section(self, parent):
        welcome_frame = ctk.CTkFrame(parent, fg_color="transparent")
        welcome_frame.pack(fill="x", padx=20, pady=(10, 25))

        # Welcome message with improved styling
        welcome_container = ctk.CTkFrame(welcome_frame, fg_color=("gray95", "gray20"), corner_radius=15)
        welcome_container.pack(fill="x", padx=5, pady=5)
        
        welcome_row = ctk.CTkFrame(welcome_container, fg_color="transparent")
        welcome_row.pack(fill="x", padx=20, pady=15)
        
        ctk.CTkLabel(
            welcome_row,
            text="Welcome to IDS Dashboard",
            font=("Helvetica", 26, "bold"),
        ).pack(side="left", anchor="w")
        
        # Add test button (for debugging only)
        test_btn = ctk.CTkButton(
            welcome_row,
            text="Generate Test Alerts",
            command=self.master.generate_test_alerts,
            width=150,
            height=32,
            fg_color="#3a7ebf",
            hover_color="#325882",
            corner_radius=8,
            font=("Helvetica", 12)
        )
        test_btn.pack(side="right", padx=5)

    def setup_stats_overview(self, parent):
        stats_frame = ctk.CTkFrame(parent, fg_color="transparent")
        stats_frame.pack(fill="x", padx=20, pady=(0, 25))

        # Quick stats in a row with improved styling
        stats = [
            ("🔍 System Status", "Active", "#00CC00", self.master.show_system_window),
            ("⚠️ Active Alerts", f"{len(self.resource_monitor.alerts)}", "#FFA500", self.master.show_alerts_window),
            ("📊 CPU Usage", "0%", None, self.master.show_system_window),
            ("💾 Memory Usage", "0%", None, self.master.show_system_window)
        ]

        for title, value, color, command in stats:
            stat_box = ctk.CTkFrame(stats_frame, corner_radius=15, fg_color=("gray95", "gray20"))
            stat_box.pack(side="left", expand=True, fill="both", padx=5, pady=5)

            # Title and View Details button container
            header_frame = ctk.CTkFrame(stat_box, fg_color="transparent")
            header_frame.pack(fill="x", padx=15, pady=(15, 5))

            ctk.CTkLabel(
                header_frame,
                text=title,
                font=("Helvetica", 14, "bold")
            ).pack(side="left")

            view_btn = ctk.CTkButton(
                header_frame,
                text="View →",
                command=command,
                width=70,
                height=28,
                font=("Helvetica", 12),
                fg_color=("#3a7ebf", "#1f538d"),
                hover_color=("#325882", "#14375e"),
                corner_radius=8
            )
            view_btn.pack(side="right")

            label = ctk.CTkLabel(
                stat_box,
                text=value,
                font=("Helvetica", 20, "bold"),
                text_color=color if color else ("gray20", "gray90")
            )
            label.pack(pady=(5, 15))

            if title == "📊 CPU Usage":
                self.cpu_stat_label = label
            elif title == "💾 Memory Usage":
                self.memory_stat_label = label

    def update_time(self):
        current_time = datetime.now().strftime("%I:%M:%S %p\n%B %d, %Y")
        self.time_label.configure(text=current_time)
        self.after(1000, self.update_time)

    def create_card(self, parent, title):
        """Helper function to create consistent card frames with improved styling"""
        card = ctk.CTkFrame(parent, corner_radius=15, fg_color=("gray95", "gray20"))
        
        # Title with separator
        title_frame = ctk.CTkFrame(card, fg_color="transparent")
        title_frame.pack(fill="x", padx=15, pady=(15, 5))
        
        ctk.CTkLabel(
            title_frame,
            text=title,
            font=("Helvetica", 16, "bold")
        ).pack(side="left")
        
        # Add subtle separator
        separator = ctk.CTkFrame(card, height=2, fg_color=("gray85", "gray30"))
        separator.pack(fill="x", padx=15, pady=(5, 0))
        
        return card

    def setup_system_card(self, parent, row, col):
        card = self.create_card(parent, "System Resources")
        card.grid(row=row, column=col, padx=5, pady=5, sticky="nsew")

        # Add View Details button
        view_btn = ctk.CTkButton(
            card,
            text="View Details",
            command=self.master.show_system_window,
            width=100,
            height=30,
            font=("Helvetica", 12),
            fg_color="transparent",
            hover_color=("gray70", "gray30")
        )
        view_btn.pack(anchor="e", padx=10)

        # CPU Usage
        cpu_frame = ctk.CTkFrame(card, fg_color="transparent")
        cpu_frame.pack(fill="x", padx=10, pady=5)
        
        self.cpu_info_label = ctk.CTkLabel(
            cpu_frame, 
            text="CPU Usage:", 
            font=("Helvetica", 12)
        )
        self.cpu_info_label.pack(side="left")
        
        self.cpu_label = ctk.CTkLabel(
            cpu_frame, 
            text="0%", 
            font=("Helvetica", 12)
        )
        self.cpu_label.pack(side="right")
        
        self.cpu_progress = ctk.CTkProgressBar(card)
        self.cpu_progress.pack(fill="x", padx=10, pady=(0, 10))
        self.cpu_progress.set(0)

        # Memory Usage
        mem_frame = ctk.CTkFrame(card, fg_color="transparent")
        mem_frame.pack(fill="x", padx=10, pady=5)
        
        self.memory_info_label = ctk.CTkLabel(
            mem_frame, 
            text="Memory Usage:", 
            font=("Helvetica", 12)
        )
        self.memory_info_label.pack(side="left")
        
        self.memory_label = ctk.CTkLabel(
            mem_frame, 
            text="0 GB / 0 GB (0%)", 
            font=("Helvetica", 12)
        )
        self.memory_label.pack(side="right")
        
        self.memory_progress = ctk.CTkProgressBar(card)
        self.memory_progress.pack(fill="x", padx=10, pady=(0, 10))
        self.memory_progress.set(0)

    def setup_alerts_card(self, parent, row, col):
        card = self.create_card(parent, "Recent Alerts")
        card.grid(row=row, column=col, padx=5, pady=5, sticky="nsew")

        # Header with count and view button
        header_frame = ctk.CTkFrame(card, fg_color="transparent")
        header_frame.pack(fill="x", padx=10, pady=(0, 10))

        alert_count = len(self.resource_monitor.alerts)
        count_label = ctk.CTkLabel(
            header_frame,
            text=f"Total Alerts: {alert_count}",
            font=("Helvetica", 12),
            text_color="gray60"
        )
        count_label.pack(side="left")

        view_btn = ctk.CTkButton(
            header_frame,
            text="View All",
            command=self.master.show_alerts_window,
            width=80,
            height=28,
            font=("Helvetica", 12),
            fg_color="transparent",
            hover_color=("gray70", "gray30")
        )
        view_btn.pack(side="right")

        # Create scrollable frame for alerts
        alerts_frame = ctk.CTkScrollableFrame(card, height=150)
        alerts_frame.pack(fill="x", padx=10, pady=5)

        # Show last 5 alerts
        alerts = self.resource_monitor.alerts[:5]

        if not alerts:
            ctk.CTkLabel(
                alerts_frame,
                text="No recent alerts",
                font=("Helvetica", 12),
                text_color="gray60"
            ).pack(pady=10)
        else:
            for alert in alerts:
                alert_frame = ctk.CTkFrame(alerts_frame, fg_color=("gray95", "gray25"))
                alert_frame.pack(fill="x", pady=3, padx=2)
                
                alert_content = ctk.CTkFrame(alert_frame, fg_color="transparent")
                alert_content.pack(fill="x", padx=8, pady=5)
                
                ctk.CTkLabel(
                    alert_content,
                    text="🚨",
                    font=("Helvetica", 14)
                ).pack(side="left", padx=(0, 5))
                
                ctk.CTkLabel(
                    alert_content,
                    text=alert['message'],
                    font=("Helvetica", 12),
                    justify="left"
                ).pack(side="left", fill="x", expand=True)
                
                ctk.CTkLabel(
                    alert_content,
                    text=alert['time'],
                    font=("Helvetica", 11),
                    text_color="gray60"
                ).pack(side="right", padx=(10, 0))

    def setup_logs_card(self, parent, row, col):
        card = self.create_card(parent, "Recent Logs")
        card.grid(row=row, column=col, padx=5, pady=5, sticky="nsew")

        # Header with count and view button
        header_frame = ctk.CTkFrame(card, fg_color="transparent")
        header_frame.pack(fill="x", padx=10, pady=(0, 10))

        log_count = len(self.resource_monitor.logs)
        count_label = ctk.CTkLabel(
            header_frame,
            text=f"Total Logs: {log_count}",
            font=("Helvetica", 12),
            text_color="gray60"
        )
        count_label.pack(side="left")

        view_btn = ctk.CTkButton(
            header_frame,
            text="View All",
            command=self.master.show_logs_window,
            width=80,
            height=28,
            font=("Helvetica", 12),
            fg_color="transparent",
            hover_color=("gray70", "gray30")
        )
        view_btn.pack(side="right")

        # Create scrollable frame for logs
        logs_frame = ctk.CTkScrollableFrame(card, height=150)
        logs_frame.pack(fill="x", padx=10, pady=5)

        # Show last 5 logs
        logs = self.resource_monitor.logs[:5]
        if not logs:
            ctk.CTkLabel(
                logs_frame,
                text="No recent logs",
                font=("Helvetica", 12),
                text_color="gray60"
            ).pack(pady=10)
        else:
            for log in logs:
                log_frame = ctk.CTkFrame(logs_frame, fg_color=("gray95", "gray25"))
                log_frame.pack(fill="x", pady=3, padx=2)
                
                log_content = ctk.CTkFrame(log_frame, fg_color="transparent")
                log_content.pack(fill="x", padx=8, pady=5)
                
                ctk.CTkLabel(
                    log_content,
                    text="📝",
                    font=("Helvetica", 14)
                ).pack(side="left", padx=(0, 5))
                
                ctk.CTkLabel(
                    log_content,
                    text=log['event'],
                    font=("Helvetica", 12),
                    justify="left"
                ).pack(side="left", fill="x", expand=True)
                
                ctk.CTkLabel(
                    log_content,
                    text=log['timestamp'],
                    font=("Helvetica", 11),
                    text_color="gray60"
                ).pack(side="right", padx=(10, 0))

    def setup_status_card(self, parent, row, col):
        card = self.create_card(parent, "System Status")
        card.grid(row=row, column=col, padx=5, pady=5, sticky="nsew")

        # Status header with view button
        header_frame = ctk.CTkFrame(card, fg_color="transparent")
        header_frame.pack(fill="x", padx=10, pady=(0, 10))

        status_label = ctk.CTkLabel(
            header_frame,
            text="Current Status: Active",
            font=("Helvetica", 12),
            text_color="#00CC00"
        )
        status_label.pack(side="left")

        view_btn = ctk.CTkButton(
            header_frame,
            text="View Details",
            command=self.master.show_admin_window,
            width=80,
            height=28,
            font=("Helvetica", 12),
            fg_color="transparent",
            hover_color=("gray70", "gray30")
        )
        view_btn.pack(side="right")

        # Resource Limits section
        limits_frame = ctk.CTkFrame(card, fg_color=("gray95", "gray25"))
        limits_frame.pack(fill="x", padx=10, pady=5)
        
        limits_header = ctk.CTkLabel(
            limits_frame,
            text="Resource Limits",
            font=("Helvetica", 14, "bold")
        )
        limits_header.pack(anchor="w", pady=5, padx=10)

        # CPU Limit with progress bar
        cpu_limit = self.resource_monitor.resource_limits.get('cpu', 50)
        cpu_frame = ctk.CTkFrame(limits_frame, fg_color="transparent")
        cpu_frame.pack(fill="x", padx=10, pady=2)
        
        ctk.CTkLabel(
            cpu_frame,
            text="CPU Limit",
            font=("Helvetica", 12)
        ).pack(side="left")
        
        ctk.CTkLabel(
            cpu_frame,
            text=f"{cpu_limit}%",
            font=("Helvetica", 12, "bold"),
            text_color=("gray60")
        ).pack(side="right")

        # Memory Limit with progress bar
        memory_limit = self.resource_monitor.resource_limits.get('memory', 70)
        memory_frame = ctk.CTkFrame(limits_frame, fg_color="transparent")
        memory_frame.pack(fill="x", padx=10, pady=(2, 10))
        
        ctk.CTkLabel(
            memory_frame,
            text="Memory Limit",
            font=("Helvetica", 12)
        ).pack(side="left")
        
        ctk.CTkLabel(
            memory_frame,
            text=f"{memory_limit}%",
            font=("Helvetica", 12, "bold"),
            text_color=("gray60")
        ).pack(side="right")

        # Whitelist section
        whitelist_frame = ctk.CTkFrame(card, fg_color=("gray95", "gray25"))
        whitelist_frame.pack(fill="x", padx=10, pady=5)
        
        whitelist_header = ctk.CTkLabel(
            whitelist_frame,
            text="Whitelisted Processes",
            font=("Helvetica", 14, "bold")
        )
        whitelist_header.pack(anchor="w", pady=5, padx=10)
        
        count = len(self.resource_monitor.process_whitelist)
        count_frame = ctk.CTkFrame(whitelist_frame, fg_color="transparent")
        count_frame.pack(fill="x", padx=10, pady=(2, 10))
        
        ctk.CTkLabel(
            count_frame,
            text="Total Processes",
            font=("Helvetica", 12)
        ).pack(side="left")
        
        ctk.CTkLabel(
            count_frame,
            text=str(count),
            font=("Helvetica", 12, "bold"),
            text_color=("gray60")
        ).pack(side="right")

    def start_monitoring(self):
        self.update_resources()

    def update_resources(self):
        try:
            # Get accurate system resources
            resources = self.resource_monitor.get_system_resources()
            if resources:
                # Update CPU
                cpu_percent = resources['cpu']['percent']
                cores = resources['cpu']['cores']
                self.cpu_progress.set(cpu_percent / 100)
                self.cpu_label.configure(text=f"{cpu_percent:.1f}%")
                self.cpu_stat_label.configure(text=f"{cpu_percent:.1f}%")
                self.cpu_info_label.configure(
                    text=f"CPU Usage ({cores} logical cores):"
                )
                
                # Update Memory
                mem = resources['memory']
                total_gb = mem['total']
                used_gb = mem['used']
                percent = mem['percent']
                
                self.memory_progress.set(percent / 100)
                self.memory_label.configure(
                    text=f"{used_gb:.1f} GB / {total_gb:.1f} GB ({percent:.1f}%)"
                )
                self.memory_stat_label.configure(text=f"{percent:.1f}%")
                
        except Exception as e:
            print(f"Error updating dashboard resources: {e}")
        
        if self.winfo_exists():
            self.after(1000, self.update_resources)

    def on_close(self):
        # Cleanup code here
        pass 