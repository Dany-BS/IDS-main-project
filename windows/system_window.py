import customtkinter as ctk
import psutil
from datetime import datetime

class SystemWindow(ctk.CTkFrame):
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
            ("🖥️ System", self.master.show_system_window, True),  # Active
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

        # Main content area
        content_area = ctk.CTkFrame(main_container)
        content_area.pack(side="right", fill="both", expand=True, padx=10, pady=10)

        # Title in content area
        ctk.CTkLabel(
            content_area,
            text="System Resources",
            font=("Helvetica", 24, "bold")
        ).pack(pady=10, padx=10, anchor="w")

        # Scrollable content frame
        self.content_frame = ctk.CTkScrollableFrame(content_area)
        self.content_frame.pack(fill="both", expand=True, padx=10, pady=10)

        # CPU Usage
        self.setup_cpu_frame()
        
        # Memory Usage
        self.setup_memory_frame()
        
        # Disk Usage
        self.setup_disk_frame()
        
        # Network Usage
        self.setup_network_frame()

    def setup_cpu_frame(self):
        cpu_frame = ctk.CTkFrame(self.content_frame)
        cpu_frame.pack(fill="x", pady=5)
        
        ctk.CTkLabel(cpu_frame, text="CPU Usage", font=("Helvetica", 16, "bold")).pack()
        
        self.cpu_progress = ctk.CTkProgressBar(cpu_frame)
        self.cpu_progress.pack(fill="x", padx=20, pady=5)
        
        self.cpu_label = ctk.CTkLabel(cpu_frame, text="0%")
        self.cpu_label.pack()

    def setup_memory_frame(self):
        memory_frame = ctk.CTkFrame(self.content_frame)
        memory_frame.pack(fill="x", pady=5)
        
        ctk.CTkLabel(memory_frame, text="Memory Usage", font=("Helvetica", 16, "bold")).pack()
        
        self.memory_progress = ctk.CTkProgressBar(memory_frame)
        self.memory_progress.pack(fill="x", padx=20, pady=5)
        
        self.memory_label = ctk.CTkLabel(memory_frame, text="0 GB / 0 GB (0%)")
        self.memory_label.pack()

    def setup_disk_frame(self):
        disk_frame = ctk.CTkFrame(self.content_frame)
        disk_frame.pack(fill="x", pady=5)
        
        ctk.CTkLabel(disk_frame, text="Disk Usage", font=("Helvetica", 16, "bold")).pack()
        
        self.disk_frames = {}
        for partition in psutil.disk_partitions():
            if partition.fstype:
                partition_frame = ctk.CTkFrame(disk_frame)
                partition_frame.pack(fill="x", padx=20, pady=5)
                
                ctk.CTkLabel(
                    partition_frame, 
                    text=f"Drive {partition.device}",
                    font=("Helvetica", 12)
                ).pack(anchor="w")
                
                progress = ctk.CTkProgressBar(partition_frame)
                progress.pack(fill="x", pady=2)
                
                label = ctk.CTkLabel(partition_frame, text="0 GB / 0 GB (0%)")
                label.pack()
                
                self.disk_frames[partition.device] = (progress, label)

    def setup_network_frame(self):
        network_frame = ctk.CTkFrame(self.content_frame)
        network_frame.pack(fill="x", pady=5)
        
        ctk.CTkLabel(network_frame, text="Network Usage", font=("Helvetica", 16, "bold")).pack()
        
        self.network_frames = {}
        self.prev_net_io = psutil.net_io_counters(pernic=True)
        
        for interface in self.prev_net_io.keys():
            interface_frame = ctk.CTkFrame(network_frame)
            interface_frame.pack(fill="x", padx=20, pady=5)
            
            ctk.CTkLabel(
                interface_frame,
                text=f"Interface: {interface}",
                font=("Helvetica", 12)
            ).pack(anchor="w")
            
            label = ctk.CTkLabel(interface_frame, text="↑0 B/s  ↓0 B/s")
            label.pack()
            
            self.network_frames[interface] = label

    def start_monitoring(self):
        self.update_resources()

    def update_resources(self):
        try:
            # Update CPU
            cpu_percent = psutil.cpu_percent()
            self.cpu_progress.set(cpu_percent / 100)
            self.cpu_label.configure(text=f"{cpu_percent:.1f}%")
            
            # Update Memory
            memory = psutil.virtual_memory()
            self.memory_progress.set(memory.percent / 100)
            total_gb = memory.total / (1024**3)
            used_gb = memory.used / (1024**3)
            self.memory_label.configure(
                text=f"{used_gb:.1f} GB / {total_gb:.1f} GB ({memory.percent:.1f}%)"
            )
            
            # Update Disk
            for partition in psutil.disk_partitions():
                if partition.fstype and partition.device in self.disk_frames:
                    try:
                        usage = psutil.disk_usage(partition.mountpoint)
                        progress, label = self.disk_frames[partition.device]
                        
                        progress.set(usage.percent / 100)
                        total_gb = usage.total / (1024**3)
                        used_gb = usage.used / (1024**3)
                        label.configure(
                            text=f"{used_gb:.1f} GB / {total_gb:.1f} GB ({usage.percent:.1f}%)"
                        )
                    except Exception:
                        continue
            
            # Update Network
            current_net_io = psutil.net_io_counters(pernic=True)
            for interface, stats in current_net_io.items():
                if interface in self.network_frames and interface in self.prev_net_io:
                    bytes_sent = stats.bytes_sent - self.prev_net_io[interface].bytes_sent
                    bytes_recv = stats.bytes_recv - self.prev_net_io[interface].bytes_recv
                    
                    upload_speed = self.format_bytes(bytes_sent) + "/s"
                    download_speed = self.format_bytes(bytes_recv) + "/s"
                    
                    self.network_frames[interface].configure(
                        text=f"↑{upload_speed}  ↓{download_speed}"
                    )
            
            self.prev_net_io = current_net_io
            
        except Exception as e:
            print(f"Error updating resources: {e}")
        
        # Schedule next update if window still exists
        if self.winfo_exists():
            self.after(1000, self.update_resources)

    def format_bytes(self, bytes):
        """Format bytes to human readable format."""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if bytes < 1024:
                return f"{bytes:.1f} {unit}"
            bytes /= 1024
        return f"{bytes:.1f} TB"

    def on_close(self):
        # Cleanup code here
        pass 

    def update_time(self):
        current_time = datetime.now().strftime("%I:%M:%S %p\n%B %d, %Y")
        self.time_label.configure(text=current_time)
        self.after(1000, self.update_time) 