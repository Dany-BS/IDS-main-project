                                PROJECT OVERVIEW: iNTRUSION DETECTION SYSTEM (IDS)
1. Project Function: 
This project is a Python-based Intrusion Detection System (IDS) designed to monitor network traffic, system resources, and external devices. It features a graphical user interface (GUI) and utilizes machine learning for anomaly detection.

2. Technology Stack: 
Language: Python
GUI Framework: CustomTkinter
Network Analysis: Scapy
Machine Learning: Scikit-learn (RandomForest/IsolationForest implied by serialized models)
Data Handling: Pandas, Numpy
System Monitoring: psutil, WMI
Driver: Npcap (Required for Windows packet capture)
3. Project Structure: 
Entry Points
run_ids.bat
: The primary startup script. It checks for administrative privileges, verifies Python installation, checks dependencies (installing missing ones), validates Npcap installation, and finally launches 
main.py
.
main.py
: The main Python application entry point. It initializes the 
MainApp
 class (CustomTkinter), sets up the resource monitor, and launches the login window.
Key Directories
windows/: Contains the GUI screens and logic.
LoginWindow, HomeWindow, SystemWindow, AlertsWindow, LogsWindow, AdminWindow, SignatureWindow, AnomalyDetectionWindow.
anomaly/
: Contains the Machine Learning components.
scapy_model.pkl
: The trained ML model.
scapy_monitor.py
 / 
scapy_monitor_custom.py
: Scripts for capturing and analyzing network packets.
train_scapy_model.py
: Script to train the intrusion detection model.
utils/: Utility scripts.
resource_monitor.py
: Back-end logic for monitoring system stats and managing alerts.
usb_whitelist.py
: Logic for managing authorized USB devices.
config/, data/, 
logs/
: Directories for configuration, persistent data, and application logs.
4. Key Features: 
Real-time Monitoring: Network traffic and system resource usage.
Anomaly Detection: Uses ML models to identify suspicious network patterns.
Signature-Based Detection: Traditional rule-based detection (references to 
snort3-community.rules
).
Alert System: Generates and displays alerts for suspicious activities.
User Management: Admin interface and login system.
External Device Monitoring: Tracks USB device connections.
5. Execution: 
To run the application, execute 
run_ids.bat
 as Administrator. It handles the environment setup and launching of the application.
