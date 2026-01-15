import scapy.all as scapy
import pandas as pd
import customtkinter as ctk
from tkinter import messagebox
from datetime import datetime
import threading

class SignatureBasedDetectionApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Signature-Based Intrusion Detection")
        self.geometry("1200x600")

        # Load dataset
        self.dataset = pd.read_csv("Train_data.csv")
        self.alerts_log = []  # Store alerts
        self.sniffing = False  # Control flag for sniffing

        # UI components
        self.create_ui()

    def create_ui(self):
        # Header label
        self.header_label = ctk.CTkLabel(self, text="Signature-Based Intrusion Detection", font=("Arial", 20))
        self.header_label.pack(pady=10)

        # Create a frame for column headers
        header_frame = ctk.CTkFrame(self)
        header_frame.pack(pady=(5, 0), padx=20, fill="x")

        # Column headers with adjusted widths
        header_widths = {
            "Timestamp": 150,
            "Event Type": 100,
            "Protocol": 100,
            "Source IP:Port": 200,
            "Destination IP:Port": 200
        }

        for header, width in header_widths.items():
            ctk.CTkLabel(header_frame, text=header, width=width).pack(side="left", padx=5)

        # Alert log display with increased width
        self.alert_textbox = ctk.CTkTextbox(self, width=800, height=300)
        self.alert_textbox.pack(pady=5, padx=20, fill="x")

        # Create a frame for buttons
        button_frame = ctk.CTkFrame(self)
        button_frame.pack(pady=10)

        # Buttons
        self.start_button = ctk.CTkButton(button_frame, text="Start Detection", command=self.start_detection, width=150)
        self.start_button.pack(side="left", padx=20)

        self.stop_button = ctk.CTkButton(button_frame, text="Stop Detection", command=self.stop_detection, width=150)
        self.stop_button.pack(side="left", padx=20)

        self.save_button = ctk.CTkButton(button_frame, text="Save Log", command=self.save_log, width=150)
        self.save_button.pack(side="left", padx=20)

    def start_detection(self):
        if not self.sniffing:
            self.sniffing = True
            # messagebox.showinfo("Detection Started", "Packet monitoring has started.")
            sniff_thread = threading.Thread(target=self.sniff_packets, daemon=True)
            sniff_thread.start()
        else:
            messagebox.showinfo("Already Running", "Packet monitoring is already running.")

    def stop_detection(self):
        if self.sniffing:
            self.sniffing = False
            messagebox.showinfo("Detection Stopped", "Packet monitoring has been stopped.")
        else:
            messagebox.showinfo("Not Running", "Packet monitoring is not currently running.")

    def sniff_packets(self):
        while self.sniffing:
            scapy.sniff(prn=self.process_packet, store=False, count=1)

    def process_packet(self, packet):
        if not self.sniffing:
            return

        if packet.haslayer(scapy.IP):
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            protocol = packet[scapy.IP].proto
            src_ip = packet[scapy.IP].src
            dst_ip = packet[scapy.IP].dst

            # Map protocol number to name
            protocol_map = {6: "tcp", 17: "udp", 1: "icmp"}
            protocol_type = protocol_map.get(protocol, "unknown")

            # Extract ports if TCP or UDP
            src_port = dst_port = 0  # Default values
            if protocol in [6, 17]:  # TCP or UDP
                if packet.haslayer(scapy.TCP) or packet.haslayer(scapy.UDP):
                    src_port = packet.sport
                    dst_port = packet.dport

            # Adjusted column widths to match headers
            packet_info = f"{timestamp:<25} {'PACKET':<15} {protocol_type:<15} {f'{src_ip}:{src_port}':<25} {f'{dst_ip}:{dst_port}':<25}\n"
            
            self.alert_textbox.insert("1.0", packet_info)

            # Check for intrusion
            src_bytes = len(packet[scapy.IP].payload)
            dst_bytes = len(packet[scapy.IP].payload.original) if hasattr(packet[scapy.IP].payload, 'original') else 0

            match = self.dataset[
                (self.dataset['protocol_type'] == protocol_type) &
                (self.dataset['src_bytes'] == src_bytes) &
                (self.dataset['dst_bytes'] == dst_bytes) &
                (self.dataset['src_port'] == src_port) &
                (self.dataset['dst_port'] == dst_port)
            ]
            if not match.empty:
                alert_info = f"{timestamp:<25} {'⚠️ ALERT':<15} {protocol_type:<15} {f'{src_ip}:{src_port}':<25} {f'{dst_ip}:{dst_port}':<25}\n"
                self.alert_textbox.insert("1.0", alert_info)
                self.alerts_log.append(alert_info)

    def save_log(self):
        if not self.alerts_log:
            messagebox.showinfo("No Alerts", "No alerts to save.")
            return

        log_filename = f"alerts_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        with open(log_filename, "w") as log_file:
            log_file.write("\n".join(self.alerts_log))

        messagebox.showinfo("Log Saved", f"Alert log saved as {log_filename}.")

if __name__ == "__main__":
    app = SignatureBasedDetectionApp()
    app.mainloop()
